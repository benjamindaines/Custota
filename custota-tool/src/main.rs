/*
 * SPDX-FileCopyrightText: 2023-2025 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap, HashSet},
    ffi::{OsStr, OsString},
    fmt::{self, Write as _},
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
//    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use avbroot::{
    cli::args::LogFormat,
    crypto::{self, PassphraseSource, RsaSigningKey, SignatureAlgorithm},
    format::{ota, payload::PayloadHeader, zip},
    protobuf::build::tools::releasetools::ota_metadata::OtaType,
    stream::{self, HashingReader},
};
use clap::{Parser, Subcommand, ValueEnum};
use cms::{
    builder::{SignedDataBuilder, SignerInfoBuilder},
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::ContentInfo,
    signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier},
};
use const_oid::ObjectIdentifier;
use hex::FromHexError;
use rawzip::{CompressionMethod, ZipArchiveWriter};
use ring::digest::Digest;
use rsa::{
    RsaPrivateKey,
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    signature::Verifier,
};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use sha2::{Sha256, Sha512};
use tempfile::TempDir;
use tracing::{Level, info, warn};
use x509_cert::{
    Certificate,
    der::{Any, Decode, Encode, Tag, asn1::OctetStringRef},
    spki::AlgorithmIdentifierOwned,
};

const CSIG_EXT: &str = ".csig";
const RULES_EXT: &str = ".p7m";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PropertyFile {
    name: String,
    offset: u64,
    size: u64,
    digest: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
struct VbmetaDigest(#[serde(with = "hex")] [u8; 32]);

impl fmt::Debug for VbmetaDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VbmetaDigest")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl fmt::Display for VbmetaDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for VbmetaDigest {
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut result = Self([0u8; 32]);
        hex::decode_to_slice(s, &mut result.0)?;
        Ok(result)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CsigInfo {
    version: CsigVersion,
    files: Vec<PropertyFile>,
    // Version 2 only.
    #[serde(skip_serializing_if = "Option::is_none")]
    vbmeta_digest: Option<VbmetaDigest>,
    /// UTC epoch seconds of this build, read from `.timestamp`. Signed (unlike the
    /// descriptor's copy) so the updater can trust it for the rules window and
    /// cross-check it against the descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LocationInfo {
    location_ota: String,
    location_csig: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct UpdateInfo {
    version: u8,
    /// UTC timestamp (seconds since the Unix epoch) of when this update info
    /// file was last written. Refreshed on every write by `gen-update-info`.
    /// `#[serde(default)]` keeps older files that predate this field readable.
    #[serde(default)]
    timestamp: i64,
    full: Option<LocationInfo>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    incremental: HashMap<String, LocationInfo>,
}

#[derive(Clone, Debug)]
struct WebUrlOrRelativePath(String);

impl FromStr for WebUrlOrRelativePath {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.contains(':') {
            if Path::new(s).is_absolute() {
                bail!("Not a relative path: {s:?}");
            }
        } else if !s.starts_with("http://") && !s.starts_with("https://") {
            bail!("Only http:// and https:// URLs are supported: {s:?}");
        }

        Ok(Self(s.to_owned()))
    }
}

#[derive(Clone, Copy, Debug, ValueEnum, Deserialize_repr, Serialize_repr)]
#[repr(u8)]
enum CsigVersion {
    #[value(name = "1")]
    Version1 = 1,
    #[value(name = "2")]
    Version2 = 2,
}

/// The lane a rule belongs to. Serialized as a lowercase string in the canonical
/// JSON the device parses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
enum Action {
    /// Back up before the OS/user clears the app; never uninstall.
    Capture,
    /// Eligible for pre-reboot uninstall (subject to the device's system-app +
    /// signature gates), unioned with the hard-coded floor.
    Conflict,
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Action::Capture => "capture",
            Action::Conflict => "conflict",
        }
    }

    /// Parse the author-facing action string, failing loudly on anything that
    /// isn't a known lane (so a typo like `conlict` is a hard error, not a
    /// silently-dropped rule).
    fn parse(s: &str) -> Result<Self> {
        match s {
            "capture" => Ok(Action::Capture),
            "conflict" => Ok(Action::Conflict),
            other => bail!("Unknown action {other:?} (expected \"capture\" or \"conflict\")"),
        }
    }
}

/// A single emitted rule. This is the on-wire shape the device parses; a typed
/// `Vec<Rule>` serialized through serde is also the fix for the old "updater
/// expected an array but got hand-built JSON" bug.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Rule {
    package: String,
    action: Action,
    /// UTC epoch seconds of the build this rule was introduced with. The updater
    /// only runs rules whose timestamp is `<=` the destination build it is moving
    /// to, so rules for builds beyond the destination (e.g. a pre-release branch)
    /// are ignored on a stable install.
    timestamp: i64,
    /// If true, the rule fires only on the update that crosses its timestamp (a
    /// one-time migration). If false, it fires on every update once that build has
    /// been reached (a standing rule).
    oneshot: bool,
}

/// The signed rules document: canonical JSON wrapped in the same CMS envelope
/// used for csig files.
#[derive(Clone, Debug, Serialize)]
struct RulesFile {
    version: u8,
    rules: Vec<Rule>,
}

/// Author-facing TOML shape. Provenance lives in `#` comments (stripped for free
/// by the TOML parser) and/or any extra keys such as `reason = "..."`, which
/// serde ignores and which therefore never reach the emitted JSON.
#[derive(Debug, Deserialize)]
struct RulesToml {
    #[serde(default)]
    rule: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    package: String,
    action: String,
    /// Optional. Omit it (or set `timestamp = ""` / `timestamp = "auto"`) to have
    /// the signer stamp it from the build's `.timestamp` file. An explicit integer
    /// back-dates the rule to a specific build.
    timestamp: Option<TimestampField>,
    /// Optional, defaults to false (a standing rule that fires on every update once
    /// its build is reached). Set true for a one-time migration.
    #[serde(default)]
    oneshot: bool,
}

/// A `timestamp` value in the source TOML: either an explicit epoch (integer) or a
/// string sentinel (`""` or `"auto"`) meaning "fill from the build's .timestamp".
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TimestampField {
    Epoch(i64),
    Text(String),
}

/// View the contents of a csig file.
#[derive(Debug, Parser)]
struct ShowCsig {
    /// Input path for csig file.
    #[arg(short, long, value_parser)]
    input: PathBuf,

    /// Path to certificate for verifying csig.
    #[arg(short, long, value_parser)]
    cert: Option<PathBuf>,

    /// Show the raw JSON contents of csig data.
    ///
    /// This is useful when programmatically parsing the output.
    #[arg(short, long)]
    raw: bool,
}

/// Generate a csig file for an OTA zip.
///
/// The csig file contains the signature for the metadata portions of the OTA zip. This allows
/// Custota to read metadata from the OTA in a secure way without downloading the entire zip.
#[derive(Debug, Parser)]
struct GenerateCsig {
    /// Input path for OTA zip file.
    #[arg(short, long, value_parser)]
    input: PathBuf,

    /// Output path for csig file.
    ///
    /// Defaults to <OTA zip>.csig.
    #[arg(short, long, value_parser)]
    output: Option<PathBuf>,

    /// Path to private key for signing csig.
    #[arg(short, long, value_parser)]
    key: PathBuf,

    /// Environment variable containing the private key passphrase.
    #[arg(long, value_parser, group = "passphrase")]
    passphrase_env_var: Option<OsString>,

    /// Text file containing the private key passphrase.
    #[arg(long, value_parser, group = "passphrase")]
    passphrase_file: Option<PathBuf>,

    /// Path to certificate for signing csig.
    #[arg(short, long, value_parser)]
    cert: PathBuf,

    /// Path to certificate for verifying OTA.
    ///
    /// This is used to verify the signature of the OTA zip file. If this option is omitted, it
    /// defaults to the value of -c/--cert.
    #[arg(short = 'C', long)]
    cert_verify: Option<PathBuf>,

    /// csig file format version.
    ///
    /// csig version 1 is supported by all versions of Custota. Version 2 is
    /// supported since version 5.0 of Custota and adds support for storing the
    /// vbmeta digest to allow detecting updates when the OS version does not
    /// change.
    #[arg(long, value_enum, default_value_t = CsigVersion::Version2)]
    csig_version: CsigVersion,
}

/// Generate or update an update info file.
///
/// The update info file contains the relative path or full URL to the OTA zip and the csig file.
/// This command only updates the required fields in the file and leaves other fields untouched.
#[derive(Debug, Parser)]
struct GenerateUpdateInfo {
    /// Relative path or URL to the OTA zip.
    ///
    /// Custota will take the URL of the update info file and use this field to compute the full URL
    /// to the OTA zip. This can be set to a relative path if the OTA is stored in the same
    /// directory tree as the update info file. Otherwise, it can be set to an actual URL, allowing
    /// the OTA zip to be hosted on a different domain.
    #[arg(short, long)]
    location: WebUrlOrRelativePath,

    /// Relative path or URL to the csig file.
    ///
    /// Defaults to <location>.csig.
    #[arg(short, long)]
    csig_location: Option<WebUrlOrRelativePath>,

    /// Path to update info file.
    #[arg(short, long, value_parser)]
    file: PathBuf,

    /// Source vbmeta digest for an incremental OTA.
    #[arg(short, long, value_name = "SHA256", value_parser)]
    inc_vbmeta_digest: Option<VbmetaDigest>,
}

/// Generate a module for system CA certificates.
///
/// The module will install a set of certificates into the system CA trust store.
#[derive(Debug, Parser)]
struct GenerateCertModule {
    /// Output path for module zip.
    #[arg(short, long, value_parser)]
    output: PathBuf,

    /// Path to certificate.
    #[arg(value_parser, num_args = 1)]
    cert: Vec<PathBuf>,
}

/// Sign a remote rules file.
///
/// Parses a hand-edited `rules.toml`, validates it, serializes the rules as
/// canonical JSON, and wraps them in the same CMS envelope used for csig files.
/// The signing key is the bespoke BenOS rules key, independent of the OTA and
/// platform keys.
#[derive(Debug, Parser)]
struct SignRules {
    /// Input path for the rules TOML file.
    #[arg(short, long, value_parser)]
    input: PathBuf,

    /// Output path for the signed rules file.
    ///
    /// Defaults to <input>.p7m.
    #[arg(short, long, value_parser)]
    output: Option<PathBuf>,

    /// Path to private key for signing the rules.
    #[arg(short, long, value_parser)]
    key: PathBuf,

    /// Environment variable containing the private key passphrase.
    #[arg(long, value_parser, group = "passphrase")]
    passphrase_env_var: Option<OsString>,

    /// Text file containing the private key passphrase.
    #[arg(long, value_parser, group = "passphrase")]
    passphrase_file: Option<PathBuf>,

    /// Path to certificate for signing the rules.
    #[arg(short, long, value_parser)]
    cert: PathBuf,
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Subcommand)]
enum Command {
    ShowCsig(ShowCsig),
    GenCsig(GenerateCsig),
    GenUpdateInfo(GenerateUpdateInfo),
    GenCertModule(GenerateCertModule),
    SignRules(SignRules),
}

#[derive(Debug, Parser)]
#[command(version = env!("GIT_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Lowest log message severity to output.
    #[arg(long, global = true, value_name = "LEVEL", default_value_t = Level::INFO)]
    log_level: Level,

    /// Output format for log messages.
    #[arg(long, global = true, value_name = "FORMAT", default_value_t)]
    log_format: LogFormat,
}

/// Compute the SHA256 digest of a section of a file.
fn hash_section(
    mut reader: impl Read + Seek,
    offset: u64,
    size: u64,
    cancel_signal: &AtomicBool,
) -> Result<Digest> {
    reader.seek(SeekFrom::Start(offset))?;

    let mut hashing_reader =
        HashingReader::new(reader, ring::digest::Context::new(&ring::digest::SHA256));

    stream::copy_n(&mut hashing_reader, io::sink(), size, cancel_signal)?;

    let (_, context) = hashing_reader.finish();

    Ok(context.finish())
}

/// Verify the CMS signature against the specified data. Only SHA256 and SHA512
/// are supported for both the signed attributes digest and the content digest.
fn verify_cms_signature(
    signed_data: &SignedData,
    econtent_type: ObjectIdentifier,
    econtent_data: &[u8],
    cert: &Certificate,
) -> Result<()> {
    let public_key = crypto::get_public_key(cert)?;

    for signer_info in signed_data.signer_infos.0.iter() {
        let signature = Signature::try_from(signer_info.signature.as_bytes())?;
        let Some(signed_attrs) = &signer_info.signed_attrs else {
            continue;
        };
        let signed_attrs_der = signed_attrs.to_der()?;

        let (sig_algo, result) = match signer_info.digest_alg.oid {
            const_oid::db::rfc5912::ID_SHA_256 => (
                SignatureAlgorithm::Sha256WithRsa,
                VerifyingKey::<Sha256>::new(public_key.clone())
                    .verify(&signed_attrs_der, &signature),
            ),
            const_oid::db::rfc5912::ID_SHA_512 => (
                SignatureAlgorithm::Sha512WithRsa,
                VerifyingKey::<Sha512>::new(public_key.clone())
                    .verify(&signed_attrs_der, &signature),
            ),
            _ => continue,
        };

        if result.is_err() {
            continue;
        }

        // At this point, the signature of the signed attributes is verified and
        // we know we're looking at the correct signer info. All further issues
        // are treated as errors.

        let econtent_type_attr = signed_attrs
            .iter()
            .find(|a| a.oid == const_oid::db::rfc5911::ID_CONTENT_TYPE)
            .ok_or_else(|| {
                anyhow!(
                    "Signed attribute not found: {}",
                    const_oid::db::rfc5911::ID_CONTENT_TYPE,
                )
            })?;

        if econtent_type_attr.values.len() != 1 {
            bail!("Expected exactly one signed attribute value: {econtent_type_attr:?}");
        }

        let econtent_type_expected = econtent_type_attr
            .values
            .get(0)
            .unwrap()
            .decode_as::<ObjectIdentifier>()?;

        if econtent_type != econtent_type_expected {
            bail!(
                "Content type does not match signed attribute: {econtent_type} != {econtent_type_expected}"
            );
        }

        let econtent_digest_attr = signed_attrs
            .iter()
            .find(|a| a.oid == const_oid::db::rfc5911::ID_MESSAGE_DIGEST)
            .ok_or_else(|| {
                anyhow!(
                    "Signed attribute not found: {}",
                    const_oid::db::rfc5911::ID_MESSAGE_DIGEST,
                )
            })?;

        if econtent_digest_attr.values.len() != 1 {
            bail!("Expected exactly one signed attribute value: {econtent_digest_attr:?}");
        }

        let econtent_digest_expected = econtent_digest_attr
            .values
            .get(0)
            .unwrap()
            .decode_as::<OctetStringRef>()?;

        let econtent_digest = sig_algo.hash(econtent_data);

        if econtent_digest != econtent_digest_expected.as_bytes() {
            bail!(
                "Content digest does not match signed attribute: {} != {}",
                hex::encode(econtent_digest),
                hex::encode(econtent_digest_expected),
            );
        }

        return Ok(());
    }

    bail!("None of the CMS signatures match the specified certificate");
}

/// Return the encapsulated content in a CMS signature, optionally verifying the
/// signature first.
fn get_cms_inline(ci: &ContentInfo, cert: Option<&Certificate>) -> Result<Vec<u8>> {
    if ci.content_type != const_oid::db::rfc5911::ID_SIGNED_DATA {
        bail!(
            "Invalid content type: {} != {}",
            ci.content_type,
            const_oid::db::rfc5911::ID_SIGNED_DATA,
        );
    }

    let signed_data = ci.content.decode_as::<SignedData>()?;

    let econtent_type = signed_data.encap_content_info.econtent_type;
    if econtent_type != const_oid::db::rfc5911::ID_DATA {
        bail!(
            "Invalid encapsulated content type: {econtent_type} != {}",
            const_oid::db::rfc5911::ID_DATA,
        );
    }

    let Some(econtent) = &signed_data.encap_content_info.econtent else {
        bail!("CMS signature has no encapsulated content");
    };
    let econtent_data = econtent.decode_as::<OctetStringRef>()?;

    if let Some(cert) = cert {
        verify_cms_signature(&signed_data, econtent_type, econtent_data.as_bytes(), cert)?;
    } else {
        warn!("Skipping signature verification");
    }

    Ok(econtent_data.as_bytes().to_vec())
}

/// Create a CMS signature with the specified encapsulated content.
fn sign_cms_inline(key: &RsaPrivateKey, cert: &Certificate, data: &[u8]) -> Result<ContentInfo> {
    let content = EncapsulatedContentInfo {
        econtent_type: const_oid::db::rfc5911::ID_DATA,
        econtent: Some(Any::new(
            Tag::OctetString,
            OctetStringRef::new(data)?.as_bytes(),
        )?),
    };

    let signer = SigningKey::<Sha256>::new(key.clone());
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: None,
    };

    let si_builder = SignerInfoBuilder::new(
        &signer,
        SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        }),
        digest_algorithm.clone(),
        &content,
        None,
    )
    .map_err(|e| anyhow!("Failed to create SignerInfoBuilder: {e}"))?;

    let sd = SignedDataBuilder::new(&content)
        .add_digest_algorithm(digest_algorithm)
        .map_err(|e| anyhow!("Failed to add digest algorithm: {e}"))?
        .add_certificate(CertificateChoices::Certificate(cert.clone()))
        .map_err(|e| anyhow!("Failed to add certificate: {e}"))?
        .add_signer_info(si_builder)
        .map_err(|e| anyhow!("Failed to add signer info: {e}"))?
        .build()
        .map_err(|e| anyhow!("Failed to build SignedData: {e}"))?;

    Ok(sd)
}

fn compute_vbmeta_digest(
    raw_reader: File,
    offset: u64,
    size: u64,
    header: &PayloadHeader,
    cancel_signal: &AtomicBool,
) -> Result<[u8; 32]> {
    info!("Computing vbmeta digest...");

    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
    let unique_images = header
        .manifest
        .partitions
        .iter()
        .map(|p| &p.partition_name)
        .cloned()
        .collect::<BTreeSet<_>>();

    avbroot::cli::ota::extract_payload(
        &raw_reader,
        temp_dir.path(),
        offset,
        size,
        header,
        &unique_images,
        cancel_signal,
    )?;

    avbroot::cli::avb::compute_digest(temp_dir.path(), "vbmeta", cancel_signal)
}

fn subcommand_show_csig(args: &ShowCsig) -> Result<()> {
    let signing_cert = args
        .cert
        .as_ref()
        .map(|p| {
            crypto::read_pem_cert_file(p)
                .with_context(|| anyhow!("Failed to load certificate: {p:?}"))
        })
        .transpose()?;

    let csig_raw =
        fs::read(&args.input).with_context(|| format!("Failed to read file: {:?}", args.input))?;
    let csig_ci = ContentInfo::from_der(&csig_raw)
        .with_context(|| format!("Failed to parse CMS data: {:?}", args.input))?;

    let csig_json = get_cms_inline(&csig_ci, signing_cert.as_ref())?;

    if args.raw {
        io::stdout().write_all(&csig_json)?;
    } else {
        let csig: CsigInfo = serde_json::from_slice(&csig_json)?;
        println!("{csig:#?}");
    }

    Ok(())
}

fn subcommand_gen_csig(args: &GenerateCsig, cancel_signal: &AtomicBool) -> Result<()> {
    let passphrase_source = if let Some(v) = &args.passphrase_env_var {
        PassphraseSource::EnvVar(v.clone())
    } else if let Some(p) = &args.passphrase_file {
        PassphraseSource::File(p.clone())
    } else {
        PassphraseSource::Prompt(format!("Enter passphrase for {:?}: ", args.key))
    };

    let signing_private_key = crypto::read_pem_key_file(&args.key, &passphrase_source)
        .with_context(|| anyhow!("Failed to load key: {:?}", args.key))?;
    let signing_cert = crypto::read_pem_cert_file(&args.cert)
        .with_context(|| anyhow!("Failed to load certificate: {:?}", args.cert))?;

    if !crypto::cert_matches_key(
        &signing_cert,
        &RsaSigningKey::Internal(signing_private_key.clone()),
    )? {
        bail!(
            "Private key {:?} does not match certificate {:?}",
            args.key,
            args.cert,
        );
    }

    let (verify_cert_path, verify_cert) = match &args.cert_verify {
        Some(c) => {
            let cert = crypto::read_pem_cert_file(c)
                .with_context(|| anyhow!("Failed to load certificate: {c:?}"))?;
            (c, Cow::Owned(cert))
        }
        None => (&args.cert, Cow::Borrowed(&signing_cert)),
    };

    let mut reader = File::open(&args.input)
        .map(BufReader::new)
        .with_context(|| anyhow!("Failed to open for reading: {:?}", args.input))?;

    info!("Verifying OTA signature...");
    let ota_sig = ota::parse_ota_sig(&mut reader).context("Failed to parse OTA signature")?;
    ota_sig
        .verify_ota(&mut reader, cancel_signal)
        .context("Failed to verify OTA against embedded certificate")?;

    let (metadata, ota_cert, header, _) = ota::parse_zip_ota_info(&mut reader)
        .with_context(|| anyhow!("Failed to parse OTA info from zip"))?;
    if ota_cert != ota_sig.cert {
        bail!(
            "{} does not match CMS embedded certificate",
            ota::PATH_OTACERT,
        );
    } else if ota_sig.cert != *verify_cert {
        bail!("OTA has a valid signature, but was not signed with: {verify_cert_path:?}");
    }

    ota::verify_metadata(&mut reader, &metadata, header.blob_offset)
        .with_context(|| anyhow!("Failed to verify OTA metadata offsets"))?;

    if metadata.r#type() != OtaType::Ab {
        bail!("Not an A/B OTA");
    } else if metadata.wipe {
        bail!("OTA unconditionally wipes userdata partition");
    } else if metadata.downgrade || metadata.spl_downgrade {
        bail!("Downgrades are not supported");
    }

    let device_name = metadata
        .precondition
        .as_ref()
        .map(|s| &s.device)
        .and_then(|d| d.first())
        .ok_or_else(|| anyhow!("Preconditions do not list a device name"))?;
    if Path::new(device_name).file_name() != Some(OsStr::new(&device_name)) {
        bail!("Invalid device name: {device_name:?}");
    }

    let postcondition = metadata
        .postcondition
        .as_ref()
        .ok_or_else(|| anyhow!("Postconditions are missing"))?;

    if postcondition.build.is_empty() {
        bail!("Postconditions do not list any fingerprints");
    }

    info!("Device name: {device_name}");
    info!("Fingerprints:");
    for fingerprint in &postcondition.build {
        info!("- {fingerprint}");
    }
    info!("Security patch: {}", postcondition.security_patch_level);

    let pfs_raw = metadata
        .property_files
        .get(ota::PF_NAME)
        .ok_or_else(|| anyhow!("Missing property files: {}", ota::PF_NAME))?;
    let pfs = ota::parse_property_files(pfs_raw)
        .with_context(|| anyhow!("Failed to parse property files: {}", ota::PF_NAME))?;
    let file_size = reader.seek(SeekFrom::End(0))?;

    let (pf_payload_offset, pf_payload_size) = pfs
        .iter()
        .find(|pf| pf.name() == ota::PATH_PAYLOAD)
        .ok_or_else(|| anyhow!("Missing property files entry: {}", ota::PATH_PAYLOAD))
        .map(|pf| (pf.offset, pf.size))?;

    let invalid_pfs = pfs
        .iter()
        .filter(|p| p.offset + p.size > file_size)
        .collect::<Vec<_>>();

    if !invalid_pfs.is_empty() {
        bail!("Property file ranges not in bounds: {:?}", invalid_pfs);
    }

    let digested_pfs = pfs
        .into_iter()
        .map(|pf| {
            hash_section(&mut reader, pf.offset, pf.size, cancel_signal).map(|d| PropertyFile {
                name: pf.name().to_owned(),
                offset: pf.offset,
                size: pf.size,
                digest: Some(hex::encode(d)),
            })
        })
        .collect::<Result<_>>()?;

    let raw_reader = reader.into_inner();
    let vbmeta_digest = match args.csig_version {
        CsigVersion::Version1 => None,
        CsigVersion::Version2 => {
            if header.is_full_ota() {
                let digest = compute_vbmeta_digest(
                    raw_reader,
                    pf_payload_offset,
                    pf_payload_size,
                    &header,
                    cancel_signal,
                )?;

                info!("vbmeta digest: {}", hex::encode(digest));

                Some(VbmetaDigest(digest))
            } else {
                info!("Skipping vbmeta digest for incremental OTA");

                None
            }
        }
    };

    let csig_info = CsigInfo {
        version: args.csig_version,
        files: digested_pfs,
        vbmeta_digest,
        timestamp: read_dot_timestamp()?,
    };
    let csig_info_raw = serde_json::to_string(&csig_info)?;

    let csig_signature = sign_cms_inline(
        &signing_private_key,
        &signing_cert,
        csig_info_raw.as_bytes(),
    )?;
    let csig_signature_der = csig_signature.to_der()?;

    let output = args.output.as_ref().map_or_else(
        || {
            let mut s = args.input.clone().into_os_string();
            s.push(CSIG_EXT);
            Cow::Owned(PathBuf::from(s))
        },
        Cow::Borrowed,
    );

    fs::write(output.as_ref(), csig_signature_der)
        .with_context(|| anyhow!("Failed to create file: {output:?}"))?;

    info!("Wrote: {output:?}");

    Ok(())
}

fn subcommand_gen_update_info(args: &GenerateUpdateInfo) -> Result<()> {
    let csig_location = args.csig_location.as_ref().map_or_else(
        || Cow::Owned(format!("{}{CSIG_EXT}", args.location.0)),
        |l| Cow::Borrowed(&l.0),
    );

    let mut options = OpenOptions::new();
    options.read(true).write(true);

    let (mut file, mut update_info, created) = match options.open(&args.file) {
        Ok(f) => {
            let mut reader = BufReader::new(f);
            let update_info: UpdateInfo = serde_json::from_reader(&mut reader)
                .with_context(|| anyhow!("Failed to parse JSON: {:?}", args.file))?;

            (reader.into_inner(), update_info, false)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let f = options
                .clone()
                .create(true)
                .open(&args.file)
                .with_context(|| anyhow!("Failed to create: {:?}", args.file))?;

            (f, UpdateInfo::default(), true)
        }
        Err(e) => {
            return Err(e).with_context(|| anyhow!("Failed to open: {:?}", args.file));
        }
    };

    update_info.version = 2;

    // Refresh the UTC timestamp (seconds since the Unix epoch) on every write so
    // it always reflects when this update info file was last (re)generated. The
    // updater app compares this against the running ROM's `ro.benos_timestamp`.
   // update_info.timestamp = SystemTime::now()
    
    update_info.timestamp = fs::read_to_string(".timestamp")?
        .trim()
        .parse::<i64>()?;
    
//        .duration_since(UNIX_EPOCH)
//        .context("System time is before the Unix epoch")?
//        .as_secs() as i64;

    let location_info = LocationInfo {
        location_ota: args.location.0.clone(),
        location_csig: csig_location.into_owned(),
    };

    if let Some(vbmeta_digest) = &args.inc_vbmeta_digest {
        update_info
            .incremental
            .insert(vbmeta_digest.to_string(), location_info);
    } else {
        update_info.full = Some(location_info);
    }

    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;

    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &update_info)?;

    if created {
        info!("Created: {:?}", args.file);
    } else {
        info!("Updated: {:?}", args.file);
    }

    Ok(())
}

/// Loosely validate an Android package name so obvious typos and garbage fail at
/// author time rather than silently shipping. Requires at least two dot-separated
/// segments, each starting with a letter or underscore and otherwise alphanumeric
/// or underscore.
fn is_valid_package_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    let segments: Vec<&str> = name.split('.').collect();
    if segments.len() < 2 {
        return false;
    }

    segments.iter().all(|seg| {
        let mut chars = seg.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// Validate the parsed TOML and build a canonical, deduplicated, sorted
/// `Vec<Rule>`. Hard errors on unknown actions and malformed package names;
/// warns (but continues) on exact duplicates and on a package straddling both
/// lanes.
/// Read the build's UTC epoch-seconds timestamp from the `.timestamp` file, used to
/// stamp rules that don't carry an explicit timestamp. Returns None if the file is
/// absent; errors if it is present but unparseable.
fn read_dot_timestamp() -> Result<Option<i64>> {
    match fs::read_to_string(".timestamp") {
        Ok(s) => Ok(Some(
            s.trim()
                .parse::<i64>()
                .context("Invalid .timestamp contents (expected an integer epoch)")?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::Error::from(e).context("Failed to read .timestamp")),
    }
}

/// Resolve a rule's timestamp: an explicit epoch is used as-is; an omitted value or
/// the string sentinels "" / "auto" are filled from the build's `.timestamp`.
fn resolve_timestamp(
    package: &str,
    field: &Option<TimestampField>,
    default_timestamp: Option<i64>,
) -> Result<i64> {
    let autofill = || {
        default_timestamp.ok_or_else(|| {
            anyhow!(
                "Rule for {package:?} needs an autofilled timestamp but no .timestamp \
                 file was found; add `timestamp = <epoch>` or create a .timestamp file"
            )
        })
    };

    let ts = match field {
        None => autofill()?,
        Some(TimestampField::Epoch(n)) => *n,
        Some(TimestampField::Text(s)) => {
            let s = s.trim();
            if s.is_empty() || s.eq_ignore_ascii_case("auto") {
                autofill()?
            } else {
                s.parse::<i64>()
                    .with_context(|| anyhow!("Rule for {package:?} has an invalid timestamp {s:?}"))?
            }
        }
    };

    if ts < 0 {
        bail!("Rule for {package:?} has a negative timestamp: {ts}");
    }

    Ok(ts)
}

fn validate_and_build_rules(
    toml_doc: &RulesToml,
    default_timestamp: Option<i64>,
) -> Result<Vec<Rule>> {
    let mut rules = Vec::with_capacity(toml_doc.rule.len());
    let mut seen: HashSet<(String, Action)> = HashSet::new();
    let mut capture_pkgs: HashSet<&str> = HashSet::new();
    let mut conflict_pkgs: HashSet<&str> = HashSet::new();

    for raw in &toml_doc.rule {
        let action = Action::parse(&raw.action)
            .with_context(|| anyhow!("Invalid rule for package {:?}", raw.package))?;

        if !is_valid_package_name(&raw.package) {
            bail!("Malformed package name: {:?}", raw.package);
        }

        let timestamp = resolve_timestamp(&raw.package, &raw.timestamp, default_timestamp)?;

        if !seen.insert((raw.package.clone(), action)) {
            warn!(
                "Ignoring duplicate rule: {} ({})",
                raw.package,
                action.as_str(),
            );
            continue;
        }

        match action {
            Action::Capture => {
                capture_pkgs.insert(raw.package.as_str());
            }
            Action::Conflict => {
                conflict_pkgs.insert(raw.package.as_str());
            }
        }

        rules.push(Rule {
            package: raw.package.clone(),
            action,
            timestamp,
            oneshot: raw.oneshot,
        });
    }

    for pkg in capture_pkgs.intersection(&conflict_pkgs) {
        warn!("Package {pkg:?} appears in both the capture and conflict lanes");
    }

    // Canonical ordering: deterministic output regardless of source ordering, so
    // the signed artifact is reproducible and diffable.
    rules.sort();

    Ok(rules)
}

fn subcommand_sign_rules(args: &SignRules) -> Result<()> {
    let passphrase_source = if let Some(v) = &args.passphrase_env_var {
        PassphraseSource::EnvVar(v.clone())
    } else if let Some(p) = &args.passphrase_file {
        PassphraseSource::File(p.clone())
    } else {
        PassphraseSource::Prompt(format!("Enter passphrase for {:?}: ", args.key))
    };

    let signing_private_key = crypto::read_pem_key_file(&args.key, &passphrase_source)
        .with_context(|| anyhow!("Failed to load key: {:?}", args.key))?;
    let signing_cert = crypto::read_pem_cert_file(&args.cert)
        .with_context(|| anyhow!("Failed to load certificate: {:?}", args.cert))?;

    if !crypto::cert_matches_key(
        &signing_cert,
        &RsaSigningKey::Internal(signing_private_key.clone()),
    )? {
        bail!(
            "Private key {:?} does not match certificate {:?}",
            args.key,
            args.cert,
        );
    }

    let toml_raw = fs::read_to_string(&args.input)
        .with_context(|| anyhow!("Failed to read rules file: {:?}", args.input))?;
    let toml_doc: RulesToml = toml::from_str(&toml_raw)
        .with_context(|| anyhow!("Failed to parse rules TOML: {:?}", args.input))?;

    let default_timestamp = read_dot_timestamp()?;
    let rules = validate_and_build_rules(&toml_doc, default_timestamp)
        .with_context(|| anyhow!("Rules validation failed: {:?}", args.input))?;

    let capture_count = rules.iter().filter(|r| r.action == Action::Capture).count();
    let conflict_count = rules.len() - capture_count;
    info!(
        "Validated {} rule(s): {capture_count} capture, {conflict_count} conflict",
        rules.len(),
    );

    let rules_file = RulesFile { version: 1, rules };

    // Canonical JSON from a typed value (no hand-built JSON).
    let rules_json = serde_json::to_vec(&rules_file)?;

    let signature = sign_cms_inline(&signing_private_key, &signing_cert, &rules_json)?;
    let signature_der = signature.to_der()?;

    let output = args.output.as_ref().map_or_else(
        || {
            let mut s = args.input.clone().into_os_string();
            s.push(RULES_EXT);
            Cow::Owned(PathBuf::from(s))
        },
        Cow::Borrowed,
    );

    fs::write(output.as_ref(), signature_der)
        .with_context(|| anyhow!("Failed to create file: {output:?}"))?;

    info!("Wrote: {output:?}");

    Ok(())
}

fn subcommand_gen_cert_module(args: &GenerateCertModule) -> Result<()> {
    if args.cert.is_empty() {
        bail!("No certificates specified");
    }

    let mut certs = vec![];
    let mut seen = HashSet::new();

    for path in &args.cert {
        let cert = crypto::read_pem_cert_file(path)
            .with_context(|| format!("Failed to load cert: {path:?}"))?;

        let mut subject_der = vec![];
        cert.tbs_certificate
            .subject
            .encode_to_vec(&mut subject_der)?;

        // Android uses openssl's X509_NAME_hash_old per:
        // https://android.googlesource.com/platform/system/ca-certificates/+/refs/tags/android-14.0.0_r29/README.cacerts
        let subject_md5 = md5::compute(subject_der);
        let subject_hash = u32::from_le_bytes(subject_md5.0[0..4].try_into().unwrap());

        if !seen.insert(subject_hash) {
            warn!("Skipping duplicate cert: {path:?}");
            continue;
        }

        certs.push((subject_hash, cert));
    }

    let mut archive = File::create(&args.output)
        .map(BufWriter::new)
        .map(ZipArchiveWriter::new)
        .with_context(|| format!("Failed to open for writing: {:?}", args.output))?;

    let mut description = "Certs: ".to_owned();
    for (i, (hash, _)) in certs.iter().enumerate() {
        if i > 0 {
            write!(&mut description, ", ")?;
        }
        write!(&mut description, "{hash:08x}")?;
    }
    description.push('\n');

    fn add_file(
        zip_writer: &mut ZipArchiveWriter<impl Write>,
        name: &str,
        data_fn: impl Fn(&mut dyn Write) -> Result<()>,
    ) -> Result<()> {
        let compression_method = CompressionMethod::Deflate;

        let (entry_writer, data_config) = zip_writer
            .new_file(name)
            .compression_method(compression_method)
            .start()?;
        let compressed_writer = zip::compressed_writer(entry_writer, compression_method)?;
        let mut data_writer = data_config.wrap(compressed_writer);

        data_fn(&mut data_writer)?;

        data_writer
            .finish()
            .and_then(|(w, d)| w.finish()?.finish(d))?;

        Ok(())
    }

    add_file(&mut archive, "module.prop", |w| {
        w.write_all(include_bytes!("../system-ca-certs/module.prop"))?;
        w.write_all(description.as_bytes())?;
        Ok(())
    })?;

    add_file(&mut archive, "post-fs-data.sh", |w| {
        w.write_all(include_bytes!("../system-ca-certs/post-fs-data.sh"))?;
        Ok(())
    })?;

    add_file(
        &mut archive,
        "META-INF/com/google/android/update-binary",
        |w| {
            w.write_all(include_bytes!("../system-ca-certs/update-binary"))?;
            Ok(())
        },
    )?;

    add_file(
        &mut archive,
        "META-INF/com/google/android/updater-script",
        |w| {
            w.write_all(include_bytes!("../system-ca-certs/updater-script"))?;
            Ok(())
        },
    )?;

    for (hash, cert) in certs {
        let name = format!("cacerts/{hash:08x}.0");
        add_file(&mut archive, &name, |w| {
            crypto::write_pem_cert(Path::new(&name), w, &cert)?;
            Ok(())
        })?;
    }

    archive.finish()?.flush()?;

    Ok(())
}

fn main() -> Result<()> {
    // Set up a cancel signal so we can properly clean up any temporary files.
    let cancel_signal = Arc::new(AtomicBool::new(false));
    {
        let signal = cancel_signal.clone();

        ctrlc::set_handler(move || {
            signal.store(true, Ordering::SeqCst);
        })
        .expect("Failed to set signal handler");
    }

    let args = Cli::parse();

    avbroot::cli::args::init_logging(args.log_level, args.log_format);

    match args.command {
        Command::ShowCsig(args) => subcommand_show_csig(&args),
        Command::GenCsig(args) => subcommand_gen_csig(&args, &cancel_signal),
        Command::GenUpdateInfo(args) => subcommand_gen_update_info(&args),
        Command::GenCertModule(args) => subcommand_gen_cert_module(&args),
        Command::SignRules(args) => subcommand_sign_rules(&args),
    }
}
