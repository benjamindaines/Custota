/*
 * SPDX-FileCopyrightText: 2023-2025 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(ExperimentalStdlibApi::class, ExperimentalSerializationApi::class)

package com.chiller3.custota.updater

import android.annotation.SuppressLint
import android.content.ContentResolver
import android.content.Context
import android.net.Network
import android.net.Uri
import android.os.Build
import android.os.IUpdateEngine
import android.os.IUpdateEngineCallback
import android.os.Parcelable
import android.os.PowerManager
import android.ota.OtaPackageMetadata.OtaMetadata
import android.system.ErrnoException
import android.system.OsConstants
import android.util.Log
import androidx.documentfile.provider.DocumentFile
import com.chiller3.custota.BuildConfig
import com.chiller3.custota.Preferences
import com.chiller3.custota.extension.findCause
import com.chiller3.custota.extension.findNestedFile
import com.chiller3.custota.extension.toSingleLineString
import com.chiller3.custota.ui.Markdown
import com.chiller3.custota.wrapper.ServiceManagerProxy
import com.chiller3.custota.wrapper.SystemPropertiesProxy
import kotlinx.parcelize.Parcelize
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.math.roundToInt
import androidx.core.net.toUri
import com.chiller3.custota.backup.NeoBackupEngine

class UpdaterThread(
    private val context: Context,
    private val network: Network?,
    private val action: Action,
    private val listener: UpdaterThreadListener,
) : Thread() {
    private val updateEngine = IUpdateEngine.Stub.asInterface(
        ServiceManagerProxy.getServiceOrThrow("android.os.UpdateEngineService"))

    private val prefs = Preferences(context)
    // NOTE: This is not implemented.
    private val authorization: String? = null

    private var logcatProcess: Process? = null
        
    private val backupEngine = NeoBackupEngine(context)
    
    // If we crash and restart while paused, the user will need to pause and unpause to resume
    // because update_engine does not report the pause state.
    var isPaused: Boolean = false
        get() = synchronized(this) { field }
        set(value) {
            synchronized(this) {
                Log.d(TAG, "Updating pause state: $value")
                if (value) {
                    updateEngine.suspend()
                } else {
                    updateEngine.resume()
                }
                field = value
            }
        }

    private val engineStatusLock = ReentrantLock()
    private val engineStatusCondition = engineStatusLock.newCondition()
    private var engineStatus = -1
    private val engineErrorLock = ReentrantLock()
    private val engineErrorCondition = engineErrorLock.newCondition()
    private var engineError = -1

    private enum class EngineWatchType {
        GENERIC,
        MERGE,
    }

    private inner class EngineCallback(private val watchType: EngineWatchType) :
        IUpdateEngineCallback.Stub() {
        override fun onStatusUpdate(status: Int, percentage: Float) {
            val statusMsg = UpdateEngineStatus.toString(status)
            Log.d(TAG, "$watchType :: onStatusUpdate($statusMsg, ${percentage * 100}%)")

            when (watchType) {
                EngineWatchType.GENERIC -> {
                    engineStatusLock.withLock {
                        engineStatus = status
                        engineStatusCondition.signalAll()
                    }
                }
                EngineWatchType.MERGE -> {
                    // The merge callback is purely for progress monitoring. We don't make any
                    // decisions based on the status here. Completion updates happen in the generic
                    // callback for merges anyway.
                }
            }

            val max = 100
            val current = (percentage * 100).roundToInt()

            when (status) {
                UpdateEngineStatus.DOWNLOADING -> ProgressType.UPDATE
                UpdateEngineStatus.VERIFYING -> ProgressType.VERIFY
                UpdateEngineStatus.FINALIZING -> ProgressType.FINALIZE
                // This does not include intermediate progress updates for EngineWatchType.GENERIC.
                UpdateEngineStatus.CLEANUP_PREVIOUS_UPDATE -> ProgressType.CLEANUP
                else -> null
            }?.let {
                listener.onUpdateProgress(this@UpdaterThread, it, current, max)
            }
        }

        override fun onPayloadApplicationComplete(errorCode: Int) {
            val errorMsg = UpdateEngineError.toString(errorCode)
            Log.d(TAG, "$watchType :: onPayloadApplicationComplete($errorMsg)")

            when (watchType) {
                EngineWatchType.GENERIC -> {
                    engineErrorLock.withLock {
                        engineError = errorCode
                        engineErrorCondition.signalAll()
                    }
                }
                EngineWatchType.MERGE -> {
                    // Merge callbacks are one-shot.
                    mergeCallback = null
                }
            }
        }
    }

    private var genericCallback: EngineCallback? = null
    private var mergeCallback: EngineCallback? = null

    private enum class NetworkPinningState {
        NOT_ATTEMPTED,
        ALLOWED,
        DENIED,
    }

    private var networkPinningState = NetworkPinningState.NOT_ATTEMPTED

    init {
        EngineCallback(EngineWatchType.GENERIC).let {
            updateEngine.bind(it)
            genericCallback = it
        }

        // This cannot be unbound. The callback is removed from update_engine only when the merge
        // operation finishes or the binder client process dies.
        EngineCallback(EngineWatchType.MERGE).let {
            // We set mergeCallback first because calling cleanupSuccessfulUpdate() may result in a
            // synchronous call to onPayloadApplicationComplete(), which clears the callback.
            mergeCallback = it
            try {
                updateEngine.cleanupSuccessfulUpdate(it)
            } catch (e: Exception) {
                mergeCallback = null
                throw e
            }
        }
    }

    protected fun finalize() {
        // In case the thread is somehow not started
        unbind()
    }

    private fun unbind() {
        synchronized(this) {
            genericCallback?.let {
                updateEngine.unbind(it)
            }

            mergeCallback?.let {
                throw IllegalStateException("Unbinding while merge is ongoing")
            }
        }
    }

    private fun waitForStatus(block: (Int) -> Boolean): Int {
        engineStatusLock.withLock {
            while (!block(engineStatus)) {
                engineStatusCondition.await()
            }
            return engineStatus
        }
    }

    private fun waitForError(block: (Int) -> Boolean): Int {
        engineErrorLock.withLock {
            while (!block(engineError)) {
                engineErrorCondition.await()
            }
            return engineError
        }
    }

    fun cancel() {
        updateEngine.cancel()
    }

    /**
     * Compute [str] relative to [base].
     *
     * [base] must refer to a directory. For HTTP(S) URIs, a trailing slash is appended if there
     * isn't one already.
     *
     * For local SAF URIs, [str] must be a (potentially nested) child of [base]. For HTTP(S) URIs,
     * [str] can be a relative path, absolute path, or absolute HTTP(S) URI.
     */
    private fun resolveUri(base: Uri, str: String): Uri {
        if (base.scheme == ContentResolver.SCHEME_CONTENT) {
            val file = DocumentFile.fromTreeUri(context, base)
                ?: throw IOException("Failed to open tree from: $base")
            // This is safe because SAF does not allow '..'
            val components = str.split('/')

            val child = file.findNestedFile(components)
                ?: throw IOException("Failed to find $str inside ${file.uri}")

            return child.uri
        } else {
            val raw = buildString {
                append(base)
                if (!endsWith('/')) {
                    append('/')
                }
            }

            val resolved = URI(raw).resolve(str).toString().toUri()
            if (resolved.scheme != "http" && resolved.scheme != "https") {
                throw IllegalStateException("$str resolves to unsupported protocol")
            }

            return resolved
        }
    }

    private fun openUrlOnce(url: URL, canPin: Boolean): HttpURLConnection {
        if (network == null) {
            throw IllegalStateException("Network is required, but no network object available")
        }

        val c = if (canPin) {
            Log.i(TAG, "Using pinned network: $network")
            network.openConnection(url) as HttpURLConnection
        } else {
            Log.i(TAG, "Not using pinned network")
            url.openConnection() as HttpURLConnection
        }

        c.connectTimeout = TIMEOUT_MS
        c.readTimeout = TIMEOUT_MS
        c.setRequestProperty("User-Agent", USER_AGENT)
        if (authorization != null) {
            c.setRequestProperty("Authorization", authorization)
        }
        return c
    }

    /**
     * Open a connection to the URL and pass the connection to the block.
     *
     * If the block throws an exception indicating the Android's Network API is broken and the user
     * allows disabling network pinning, then block is called again with a new connection that does
     * not use network pinning. The network pinning state is cached for future calls.
     */
    private fun <R> openUrl(url: URL, block: (HttpURLConnection) -> R): R =
        when (networkPinningState) {
            NetworkPinningState.NOT_ATTEMPTED -> {
                // If we get any other exception, we can still assume that the API works.
                var newState = NetworkPinningState.ALLOWED

                try {
                    block(openUrlOnce(url, true))
                } catch (e: IOException) {
                    if (e.findCause(ErrnoException::class.java)?.errno == OsConstants.EPERM) {
                        Log.w(TAG, "Network pinning is broken", e)

                        if (prefs.pinNetworkId) {
                            throw BrokenNetworkApiException("Blocked from using Network API", e)
                        }

                        Log.i(TAG, "Disabling network pinning is permitted by user")
                        newState = NetworkPinningState.DENIED
                        block(openUrlOnce(url, false))
                    } else {
                        throw e
                    }
                } finally {
                    networkPinningState = newState
                }
            }
            NetworkPinningState.ALLOWED -> block(openUrlOnce(url, true))
            NetworkPinningState.DENIED -> block(openUrlOnce(url, false))
        }

    /** Fetch and parse update info JSON file. */
    private fun fetchUpdateInfo(uri: Uri): UpdateInfo {
        val stream = if (uri.scheme == ContentResolver.SCHEME_CONTENT) {
            context.contentResolver.openInputStream(uri)
                ?: throw IOException("Failed to open: $uri")
        } else {
            openUrl(URL(uri.toString())) { it.inputStream }
        }

        val updateInfo: UpdateInfo = stream.use { JSON_FORMAT.decodeFromStream(it) }
        Log.d(TAG, "Update info: $updateInfo")

        if (updateInfo.version != 2) {
            throw BadFormatException("Only UpdateInfo version 2 is supported")
        }

        return updateInfo
    }

    /**
     * Fetch a property file entry from the OTA zip. For HTTP and HTTPS, the server must support
     * byte ranges. If the server returns too few or too many bytes, then the download will fail.
     *
     * @param output Not closed by this function
     */
    private fun fetchPropertyFile(uri: Uri, pf: PropertyFile, output: OutputStream) {
        val stream = if (uri.scheme == ContentResolver.SCHEME_CONTENT) {
            val pfd = context.contentResolver.openFileDescriptor(uri, "r")
                ?: throw IOException("Failed to open: $uri")

            PartialFdInputStream(pfd, pf.offset, pf.size)
        } else {
            val range = "${pf.offset}-${pf.offset + pf.size - 1}"

            val connection = openUrl(URL(uri.toString())) {
                it.apply {
                    setRequestProperty("Range", "bytes=$range")
                    connect()
                }
            }

            if (connection.responseCode / 100 != 2) {
                throw IOException("Got ${connection.responseCode} (${connection.responseMessage}) for $uri")
            }

            val responseRange = connection.getHeaderField("Content-Range")
                ?: throw IOException("Server does not support byte ranges")

            if (responseRange.split('/').firstOrNull() != "bytes $range") {
                throw IOException("Response range ($responseRange) does not match request ($range)")
            }

            if (connection.contentLengthLong != pf.size) {
                throw IOException("Expected ${pf.size} bytes, but Content-Length is ${connection.contentLengthLong}")
            }

            connection.inputStream
        }

        val md = MessageDigest.getInstance("SHA-256")

        stream.use { input ->
            val buf = ByteArray(16384)
            var downloaded = 0L

            while (downloaded < pf.size) {
                val toRead = java.lang.Long.min(buf.size.toLong(), pf.size - downloaded).toInt()
                val n = input.read(buf, 0, toRead)
                if (n <= 0) {
                    break
                }

                md.update(buf, 0, n)
                output.write(buf, 0, n)
                downloaded += n.toLong()
            }

            if (downloaded != pf.size) {
                throw IOException("Unexpected EOF after downloading $downloaded bytes (expected ${pf.size} bytes)")
            } else if (input.read() != -1) {
                throw IOException("Server returned more data than expected (expected ${pf.size} bytes)")
            }
        }

        val sha256 = md.digest().toHexString()

        if (!pf.digest.equals(sha256, true)) {
            throw IOException("Expected sha256 ${pf.digest}, but have $sha256")
        }
    }

    /**
     * Parse key/value pairs from properties-style files.
     *
     * The OTA property files format has equals-delimited key/value pairs, one on each line.
     * Extraneous newlines, comments, and duplicate keys are not allowed.
     */
    private fun parseKeyValuePairs(data: String): Map<String, String> {
        val result = hashMapOf<String, String>()

        for (line in data.lineSequence()) {
            if (line.isEmpty()) {
                continue
            }

            val pieces = line.split("=", limit = 2)
            if (pieces.size != 2) {
                throw BadFormatException("Invalid property file line: $line")
            } else if (pieces[0] in result) {
                throw BadFormatException("Duplicate property file key: ${pieces[0]}")
            }

            result[pieces[0]] = pieces[1]
        }

        return result
    }

    /** Parse property file entries from the relevant OTA metadata file value. */
    private fun parsePropertyFiles(value: String): List<PropertyFile> {
        val result = mutableListOf<PropertyFile>()

        for (segment in value.splitToSequence(',')) {
            // Trimmed because the last item will have padding
            val pieces = segment.trimEnd().split(':')
            if (pieces.size != 3) {
                throw BadFormatException("Invalid property files segment: $segment")
            }

            val name = pieces[0]
            val offset = pieces[1].toLongOrNull()
                ?: throw BadFormatException("Invalid property files entry offset: ${pieces[1]}")
            val size = pieces[2].toLongOrNull()
                ?: throw BadFormatException("Invalid property files entry size: ${pieces[2]}")

            result.add(PropertyFile(name, offset, size, null))
        }

        return result
    }

    /** Fetch and parse key/value pairs file. */
    private fun fetchKeyValueFile(uri: Uri, pf: PropertyFile): Map<String, String> {
        val outputStream = ByteArrayOutputStream()
        fetchPropertyFile(uri, pf, outputStream)

        return parseKeyValuePairs(outputStream.toString(Charsets.UTF_8))
    }

    /** Fetch and verify signature of the csig file. */
    private fun downloadAndCheckCsig(uri: Uri): CsigInfo {
        val stream = if (uri.scheme == ContentResolver.SCHEME_CONTENT) {
            context.contentResolver.openInputStream(uri)
                ?: throw IOException("Failed to open: $uri")
        } else {
            openUrl(URL(uri.toString())) { it.inputStream }
        }

        val csigRaw = stream.use { it.readBytes() }
        val csigCms = CMSSignedData(csigRaw)

        // Verify the signature against both the system OTA certificates and the custom certificates
        // installed by the user. The custom certificates cannot be used for verifying the payload.
        val csigCert = (OtaPaths.otaCerts + prefs.csigCerts).find { cert ->
            csigCms.signerInfos.any { signerInfo ->
                signerInfo.verify(JcaSimpleSignerInfoVerifierBuilder().build(cert))
            }
        } ?: throw ValidationException("csig is not signed by a trusted key")
        Log.d(TAG, "csig is signed by: $csigCert")

        val csigInfoRaw = String(csigCms.signedContent.content as ByteArray)
        val csigInfo: CsigInfo = JSON_FORMAT.decodeFromString(csigInfoRaw)
        Log.d(TAG, "csig info: $csigInfo")

        // The only difference in version 2 is the introduction of the vbmeta_digest field.
        if (csigInfo.version != 1 && csigInfo.version != 2) {
            throw BadFormatException("Only CsigInfo versions 1 and 2 are supported")
        }

        return csigInfo
    }

    /**
     * Fetch the signed remote rules file, CMS-verify it against the pinned BenOS
     * rules key, extract the JSON, and partition it into the capture and conflict
     * lanes.
     *
     * Fail closed: any failure — unreachable, malformed, unverified, or no pinned
     * key — returns [ResolvedRules.EMPTY], so the conflict lane falls back to the
     * hard-coded [PackageConflictConfig] floor and the capture lane is empty. The
     * device never acts on an unsigned or unverified rules blob.
     */
    private fun fetchAndPartitionRules(romTimestamp: Long?, otaTimestamp: Long?): ResolvedRules {
        return try {
            val publicKey = RulesConfig.publicKey
                ?: throw ValidationException("No pinned BenOS rules key available")

            val rulesRaw = openUrl(URL(RulesConfig.RULES_URL)) { it.inputStream }
                .use { it.readBytes() }

            val cms = CMSSignedData(rulesRaw)

            // Verify against the pinned key only — never against any certificate
            // that may be carried inside the blob.
            val verified = cms.signerInfos.any { signerInfo ->
                try {
                    signerInfo.verify(JcaSimpleSignerInfoVerifierBuilder().build(publicKey))
                } catch (e: Exception) {
                    false
                }
            }
            if (!verified) {
                throw ValidationException("Rules file is not signed by the pinned BenOS rules key")
            }

            val json = String(cms.signedContent.content as ByteArray, Charsets.UTF_8)
            val rulesFile: RulesFile = JSON_FORMAT.decodeFromString(json)

            if (rulesFile.version != 1) {
                throw BadFormatException("Only rules version 1 is supported")
            }

            val capture = mutableListOf<String>()
            val conflict = mutableListOf<String>()
            for (rule in rulesFile.rules) {
                if (!ruleInEffect(rule, romTimestamp, otaTimestamp)) {
                    continue
                }
                when (rule.action) {
                    "capture" -> capture.add(rule.pkg)
                    "conflict" -> conflict.add(rule.pkg)
                    else -> Log.w(TAG, "Ignoring rule with unknown action: ${rule.action}")
                }
            }

            Log.d(TAG, "Rules: ${capture.size} capture, ${conflict.size} conflict")
            ResolvedRules(capture.distinct(), conflict.distinct())
        } catch (e: Exception) {
            Log.w(TAG, "Rules unavailable; failing closed to the hard-coded floor", e)
            ResolvedRules.EMPTY
        }
    }

    /**
     * Decide whether a rule applies to the update currently being installed, given
     * the running ROM's build timestamp [romTimestamp] (`ro.benos_timestamp`) and
     * the destination build's timestamp [otaTimestamp] (`updateInfo.timestamp`). All
     * three are UTC epoch seconds derived from the same build-time value.
     *
     *  - Out of scope (rule timestamp > destination): skipped, so rules belonging to
     *    builds beyond the destination — e.g. a pre-release branch published in the
     *    same rules file — never run on a stable install.
     *  - oneshot: fires only on the update that crosses its timestamp, i.e.
     *    `romTimestamp < ruleTs <= otaTimestamp`, so it runs exactly once — even if
     *    the build that introduced it was skipped over in a single larger jump.
     *  - standing (oneshot = false): fires on every update once in scope.
     *
     * A rule without a timestamp (or when a timestamp is unavailable) falls back to
     * firing — prior ungated behavior — rather than being silently dropped.
     */
    private fun ruleInEffect(rule: RuleEntry, romTimestamp: Long?, otaTimestamp: Long?): Boolean {
        val ruleTs = rule.timestamp ?: return true

        // Stop at the destination: ignore rules from builds beyond where we're going.
        if (otaTimestamp != null && ruleTs > otaTimestamp) {
            return false
        }

        return if (rule.oneshot) {
            // Fire only while crossing the rule's build; once the running ROM has
            // reached or passed it, never fire again.
            romTimestamp == null || romTimestamp < ruleTs
        } else {
            true
        }
    }

    /** Fetch the OTA metadata and validate that the update is valid for the current system. */
    private fun fetchAndCheckMetadata(
        uri: Uri,
        pf: PropertyFile,
        csigInfo: CsigInfo,
    ): OtaMetadata {
        val outputStream = ByteArrayOutputStream()
        fetchPropertyFile(uri, pf, outputStream)

        val metadata = OtaMetadata.newBuilder().mergeFrom(outputStream.toByteArray()).build()
        Log.d(TAG, "OTA metadata: $metadata")

        // Required
        val preDevices = metadata.precondition.deviceList
        val postSecurityPatchLevel = metadata.postcondition.securityPatchLevel
        val postTimestamp = metadata.postcondition.timestamp * 1000

        val securityPatch = getSecurityPatch()

        if (metadata.type != OtaMetadata.OtaType.AB) {
            throw ValidationException("Not an A/B OTA package")
        } else if (!preDevices.contains(Build.DEVICE)) {
            throw ValidationException("Mismatched device ID: " +
                    "current=${Build.DEVICE}, ota=$preDevices")
        } else if (postSecurityPatchLevel < securityPatch) {
            throw ValidationException("Downgrading to older security patch is not allowed: " +
                    "current=$securityPatch, ota=$postSecurityPatchLevel")
        } else if (postTimestamp < Build.TIME) {
            throw ValidationException("Downgrading to older timestamp is not allowed: " +
                    "current=${Build.TIME}, ota=$postTimestamp")
        }

        // Optional
        val preBuildIncremental = metadata.precondition.buildIncremental
        val preBuilds = metadata.precondition.buildList

        if (preBuildIncremental.isNotEmpty() && preBuildIncremental != Build.VERSION.INCREMENTAL) {
            throw ValidationException("Mismatched incremental version: " +
                    "current=${Build.VERSION.INCREMENTAL}, ota=$preBuildIncremental")
        } else if (preBuilds.isNotEmpty() && !preBuilds.contains(Build.FINGERPRINT)) {
            throw ValidationException("Mismatched fingerprint: " +
                    "current=${Build.FINGERPRINT}, ota=$preBuilds")
        }

        // Property files
        val propertyFilesRaw = metadata.getPropertyFilesOrThrow("ota-property-files")
        val propertyFiles = parsePropertyFiles(propertyFilesRaw)

        val invalidPropertyFiles = csigInfo.files.zip(propertyFiles)
            .filter { !it.first.equalsWithoutDigest(it.second) }

        if (invalidPropertyFiles.isNotEmpty()) {
            throw ValidationException(
                "csig files do not match metadata property files: $invalidPropertyFiles")
        }

        return metadata
    }

    /**
     * Fetch the payload metadata (protobuf in headers) and verify that the payload is valid for
     * this device.
     *
     * At a minimum, update_engine checks that the list of partitions in the OTA match the device.
     */
    @SuppressLint("SetWorldReadable")
    private fun fetchAndCheckPayloadMetadata(uri: Uri, pf: PropertyFile) {
        val file = File(OtaPaths.OTA_PACKAGE_DIR, OtaPaths.PAYLOAD_METADATA_NAME)

        try {
            file.outputStream().use { out ->
                fetchPropertyFile(uri, pf, out)
            }
            file.setReadable(true, false)

            updateEngine.verifyPayloadApplicable(file.absolutePath)
        } finally {
            file.delete()
        }
    }

    /** Download dm-verity care map from [OtaPaths.OTA_PACKAGE_DIR]. */
    private fun deleteCareMap(): Boolean {
        val file = File(OtaPaths.OTA_PACKAGE_DIR, OtaPaths.CARE_MAP_NAME)

        return file.delete().also {
            Log.d(TAG, "Delete $file result: $it")
        }
    }

    /**
     * Download the dm-verity care map to [OtaPaths.OTA_PACKAGE_DIR].
     *
     * Returns the path to the written file.
     */
    @SuppressLint("SetWorldReadable")
    private fun downloadCareMap(uri: Uri, pf: PropertyFile): File {
        val file = File(OtaPaths.OTA_PACKAGE_DIR, OtaPaths.CARE_MAP_NAME)

        // If Custota is reinstalled before the file is cleaned up, it will be owned by a different
        // UID and cannot be written to.
        file.delete()

        try {
            file.outputStream().use { out ->
                fetchPropertyFile(uri, pf, out)
            }
            file.setReadable(true, false)
        } catch (e: Exception) {
            file.delete()
            throw e
        }

        return file
    }

    /** Synchronously check for updates. */
    private fun checkForUpdates(): CheckUpdateResult {
        val baseUri = prefs.effectiveOtaSource ?: throw IllegalStateException("No URI configured")
        val updateInfoUri = resolveUri(baseUri, "${Build.DEVICE}.json")
        Log.d(TAG, "Update info URI: $updateInfoUri")

        val updateInfo = try {
            fetchUpdateInfo(updateInfoUri)
        } catch (e: Exception) {
            throw IOException("Failed to download update info", e)
        }

        val vbmetaDigest = SystemPropertiesProxy.get(PROP_VBMETA_DIGEST)
        Log.d(TAG, "Current vbmeta digest: $vbmetaDigest")

        // Running ROM's build timestamp (UTC seconds since the Unix epoch), read
        // once and reused by both the update-info gate and the update-message gate
        // below. Null when the property is unset or non-numeric, in which case
        // neither gate applies and prior behavior is preserved.
        val romTimestamp = SystemPropertiesProxy.get(PROP_BENOS_TIMESTAMP).toLongOrNull()
        Log.d(TAG, "Current ROM timestamp: $romTimestamp")

        val locationInfo = updateInfo.incremental[vbmetaDigest] ?: updateInfo.full
        val isIncremental = locationInfo !== updateInfo.full
        Log.d(TAG, "OTA is incremental: $isIncremental")

        val otaUri = resolveUri(baseUri, locationInfo.locationOta)
        Log.d(TAG, "OTA URI: $otaUri")
        val csigUri = resolveUri(baseUri, locationInfo.locationCsig)
        Log.d(TAG, "csig URI: $csigUri")

        val csigInfo = downloadAndCheckCsig(csigUri)

        val pfMetadata = csigInfo.getOrThrow(OtaPaths.METADATA_NAME)
        val metadata = fetchAndCheckMetadata(otaUri, pfMetadata, csigInfo)

        // The signed csig and the (unsigned) descriptor both carry this build's
        // timestamp; require them to agree. The rules window and the up-to-date /
        // no-downgrade gate both key off this value, so anchoring it to the signed
        // csig means the unsigned descriptor can't be tampered with undetected.
        if (csigInfo.timestamp != null && updateInfo.timestamp != null &&
            csigInfo.timestamp != updateInfo.timestamp) {
            throw ValidationException(
                "csig timestamp (${csigInfo.timestamp}) does not match descriptor " +
                    "timestamp (${updateInfo.timestamp})")
        }

        if (metadata.postcondition.buildList.isEmpty()) {
            throw ValidationException("Metadata postcondition lists no fingerprints")
        }
        val fingerprints = metadata.postcondition.buildList
        var updateAvailable = isIncremental || !fingerprints.contains(Build.FINGERPRINT)

        // We allow "upgrading" to the same version if the vbmeta digest differs. This happens, for
        // example, if a newer version of Magisk was used when patching an OTA with the same OS
        // version as what is currently running.
        if (!updateAvailable && csigInfo.vbmetaDigest != null) {
            Log.d(TAG, "OTA vbmeta digest: ${csigInfo.vbmetaDigest}")
            updateAvailable = csigInfo.vbmetaDigest != vbmetaDigest
        }
        // Pull the signed remote rules each update check and partition them into the
        // capture and conflict lanes, gated by the timestamp window between the
        // running ROM and the destination build. The destination comes from the
        // signed csig (falling back to the descriptor only if an older csig lacks
        // it). Fail-closed to empty (-> floor).
        val rules = fetchAndPartitionRules(romTimestamp, csigInfo.timestamp ?: updateInfo.timestamp)
        
        // If the running ROM's build timestamp is newer than the timestamp of the
        // published OTA, the device is already up to date and must not "update" to
        // an older build. Both values are UTC timestamps in seconds since the Unix
        // epoch. The gate is only applied when both values are present and
        // parseable; otherwise the prior behavior is preserved unchanged.
        val otaTimestamp = updateInfo.timestamp
        if (updateAvailable && romTimestamp != null && otaTimestamp != null) {
            Log.d(TAG, "ROM timestamp: $romTimestamp, OTA timestamp: $otaTimestamp")
            if (romTimestamp > otaTimestamp) {
                Log.w(TAG, "ROM timestamp is newer than OTA; treating as up to date")
                updateAvailable = false
            }
        }

        if (!updateAvailable) {
            Log.w(TAG, "Already up to date")

            if (prefs.allowReinstall) {
                Log.w(TAG, "Reinstalling at user's request")
                updateAvailable = true
            }
        }
    
    
        // Best-effort fetch of an optional message to show the user before installing. The file is
        // a Markdown document sitting alongside the device JSON. If it is absent, there is simply
        // no message. The file may also carry a hidden timestamp marker (see
        // Markdown.extractTimestamp): it is always stripped from the displayed text, and if the
        // running ROM is newer than the message's timestamp, the message is treated as stale and
        // suppressed (mirroring the update-info gate above).
        val message = try {
            val messageUri = resolveUri(baseUri, "${Build.DEVICE}.md")
            Log.d(TAG, "Update message URI: $messageUri")
            val rawMessage = fetchUpdateMessage(messageUri)

            if (rawMessage == null) {
                null
            } else {
                val (messageTimestamp, cleanedMessage) = Markdown.extractTimestamp(rawMessage)
                Log.d(TAG, "Update message timestamp: $messageTimestamp")

                if (messageTimestamp != null && romTimestamp != null &&
                    romTimestamp > messageTimestamp) {
                    Log.w(TAG, "ROM timestamp is newer than update message; hiding message")
                    null
                } else {
                    cleanedMessage.trim().ifEmpty { null }
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "No update message available", e)
            null
        }

        return CheckUpdateResult(
            updateAvailable,
            fingerprints,
            otaUri,
            csigInfo,
            message,
            rules,
        )
    }

    /**
     * Fetch the optional Markdown update message. Returns null (rather than throwing) when the file
     * is missing or empty, so its absence never interferes with the update.
     */
    private fun fetchUpdateMessage(uri: Uri): String? {
        val text = if (uri.scheme == ContentResolver.SCHEME_CONTENT) {
            context.contentResolver.openInputStream(uri)?.use {
                it.readBytes().toString(Charsets.UTF_8)
            }
        } else {
            openUrl(URL(uri.toString())) { connection ->
                connection.connect()
                when {
                    connection.responseCode == HttpURLConnection.HTTP_NOT_FOUND -> null
                    connection.responseCode / 100 != 2 -> {
                        Log.d(TAG, "No message: HTTP ${connection.responseCode} for $uri")
                        null
                    }
                    else -> connection.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
                }
            }
        }

        return text?.trim()?.ifEmpty { null }
    }

    /** Asynchronously trigger the update_engine payload application. */
    private fun startInstallation(otaUri: Uri, csigInfo: CsigInfo) {
        val pfPayload = csigInfo.getOrThrow(OtaPaths.PAYLOAD_NAME)
        val pfPayloadMetadata = csigInfo.getOrThrow(OtaPaths.PAYLOAD_METADATA_NAME)
        val pfPayloadProperties = csigInfo.getOrThrow(OtaPaths.PAYLOAD_PROPERTIES_NAME)
        val pfCareMap = csigInfo.get(OtaPaths.CARE_MAP_NAME)

        Log.i(TAG, "Downloading payload metadata and checking compatibility")

        fetchAndCheckPayloadMetadata(otaUri, pfPayloadMetadata)

        Log.i(TAG, "Downloading dm-verity care map file")

        if (pfCareMap != null) {
            downloadCareMap(otaUri, pfCareMap)
        } else {
            Log.w(TAG, "OTA package does not have a dm-verity care map")
        }

        Log.i(TAG, "Downloading payload properties file")

        val payloadProperties = fetchKeyValueFile(otaUri, pfPayloadProperties)

        Log.i(TAG, "Passing payload information to update_engine")

        val engineProperties = HashMap(payloadProperties).apply {
            if (otaUri.scheme != ContentResolver.SCHEME_CONTENT) {
                when (networkPinningState) {
                    NetworkPinningState.NOT_ATTEMPTED -> throw IllegalStateException(
                        "Another network connection should have already been attempted once",
                    )
                    NetworkPinningState.ALLOWED -> {
                        Log.i(TAG, "Passing network to update_engine: $network")
                        put("NETWORK_ID", network!!.networkHandle.toString())
                    }
                    NetworkPinningState.DENIED -> Log.i(TAG, "Not passing network to update_engine")
                }

                put("USER_AGENT", USER_AGENT_UPDATE_ENGINE)

                if (authorization != null) {
                    Log.i(TAG, "Passing authorization header to update_engine")
                    put("AUTHORIZATION", authorization)
                }
            }

            if (prefs.skipPostInstall) {
                put("RUN_POST_INSTALL", "0")
            }
        }

        val enginePropertiesArray = engineProperties.map { "${it.key}=${it.value}" }.toTypedArray()

        if (otaUri.scheme == ContentResolver.SCHEME_CONTENT) {
            val pfd = context.contentResolver.openFileDescriptor(otaUri, "r")
                ?: throw IOException("Failed to open: $otaUri")

            pfd.use {
                updateEngine.applyPayloadFd(
                    it,
                    pfPayload.offset,
                    pfPayload.size,
                    enginePropertiesArray,
                )
            }
        } else {
            updateEngine.applyPayload(
                otaUri.toString(),
                pfPayload.offset,
                pfPayload.size,
                engineProperties.map { "${it.key}=${it.value}" }.toTypedArray(),
            )
        }
    }

    private fun startLogcat() {
        assert(logcatProcess == null) { "logcat already started" }

        val externalFilesDir = context.getExternalFilesDir(null)
        if (externalFilesDir == null) {
            Log.w(TAG, "External files directory is null (direct boot?)")
            return
        }

        Log.d(TAG, "Starting log file (${BuildConfig.VERSION_NAME})")

        val logcatFile = File(externalFilesDir, "${action.name.lowercase()}.log")
        logcatProcess = ProcessBuilder("logcat", "*:V")
            // This is better than -f because the logcat implementation calls fflush() when the
            // output stream is stdout.
            .redirectOutput(logcatFile)
            .redirectErrorStream(true)
            .start()
    }

    private fun stopLogcat() {
        val logcatProcess = logcatProcess
        if (logcatProcess == null) {
            Log.i(TAG, "logcat not started")
            return
        }

        try {
            Log.d(TAG, "Stopping log file")

            // Give logcat a bit of time to flush the output. It does not have any special
            // handling to flush buffers when interrupted.
            sleep(1000)

            logcatProcess.destroy()
        } finally {
            logcatProcess.waitFor()
        }
    }

    /**
     * Remove user-installed apps that would conflict with same-named system apps shipped by the
     * OTA. This is invoked once the engine has reached [UpdateEngineStatus.UPDATED_NEED_REBOOT] and
     * before the user is prompted to reboot, so it runs while still booted on the old slot where a
     * conflicting app is still an ordinary user package and can be cleanly uninstalled.
     *
     * Failures here must never block or fail the (already successful) update flow, so all errors
     * are caught and logged.
     */
    /**
     * Unstage a freshly-applied update so the device boots the old slot again, and
     * return the engine status once it has left [UpdateEngineStatus.UPDATED_NEED_REBOOT].
     * This is the single revert primitive shared by the [Action.REVERT] flow and
     * the post-update conflict guard.
     */
    private fun revertStagedUpdate(): Int {
        Log.d(TAG, "Reverting staged update via engine reset")
        updateEngine.resetStatus()
        return waitForStatus { it != UpdateEngineStatus.UPDATED_NEED_REBOOT }
    }

    /**
     * Capture and conflict handling, run once the engine has staged the new slot
     * and before the user is prompted to reboot (still booted on the old slot, so
     * a conflicting app is still an ordinary user package that can be cleanly
     * uninstalled).
     *
     * Capture lane: back up every package the rules mark `capture`. These are
     * never uninstalled, so a backup failure is logged and we continue.
     *
     * Conflict lane: the hard-coded floor unioned with the rules' `conflict`
     * packages, each gated by the resolver's system-app + signature checks. Every
     * conflict is backed up immediately before it is uninstalled; if the backup
     * fails, the app is left in place. A shared [captureOnce] set ensures an app in
     * both lanes is backed up exactly once.
     *
     * Returns the conflicts that could NOT be removed ("blockers"). A non-empty
     * result tells the caller to revert the staged update, because a leftover
     * conflicting app would bootloop the new slot. Removed apps were backed up
     * first, so after a revert the user can restore them with the bundled NeoBackup.
     */
    private fun resolvePackageConflicts(rules: ResolvedRules): List<String> {
        val captureOnce = mutableSetOf<String>()

        // Capture lane. backup() never throws (it returns null on failure), so a
        // failure is just logged; it never blocks the update.
        for (pkg in rules.captureList) {
            if (pkg in captureOnce) {
                continue
            }
            if (backupEngine.backup(pkg) != null) {
                captureOnce.add(pkg)
            } else {
                Log.w(TAG, "Capture-lane backup failed for $pkg; continuing")
            }
        }

        // Conflict lane.
        return try {
            val conflictPackages =
                (PackageConflictConfig.PACKAGE_NAMES + rules.conflictExtra).distinct()

            val result = PackageConflictResolver(context).resolveConflicts(
                conflictPackages,
            ) onBeforeUninstall@{ pkg ->
                if (pkg in captureOnce) {
                    // Already backed up this cycle (capture lane or an earlier conflict).
                    return@onBeforeUninstall true
                }
                val backedUp = backupEngine.backup(pkg) != null
                if (backedUp) {
                    captureOnce.add(pkg)
                } else {
                    Log.w(TAG, "Backup before uninstall failed for $pkg; will not uninstall")
                }
                backedUp
            }

            if (result.removed.isNotEmpty()) {
                Log.i(TAG, "Removed conflicting packages before reboot: ${result.removed}")
            }
            if (result.blockers.isNotEmpty()) {
                Log.w(TAG, "Conflicting packages that could not be removed: ${result.blockers}")
            }
            result.blockers
        } catch (e: Exception) {
            Log.w(TAG, "Package conflict resolution failed", e)
            // Could not complete resolution; treat the configured conflict set as
            // unresolved so the update is reverted rather than risking a bootloop.
            (PackageConflictConfig.PACKAGE_NAMES + rules.conflictExtra).distinct()
        }
    }

    @SuppressLint("WakelockTimeout")
    override fun run() {
        startLogcat()

        val pm = context.getSystemService(PowerManager::class.java)
        val wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, TAG)

        try {
            wakeLock.acquire()

            Log.d(TAG, "Action: $action")

            Log.d(TAG, "Waiting for initial engine status")
            val status = waitForStatus { it != -1 }
            val statusStr = UpdateEngineStatus.toString(status)
            Log.d(TAG, "Initial status: $statusStr")

            if (action == Action.REVERT) {
                if (status != UpdateEngineStatus.UPDATED_NEED_REBOOT) {
                    throw IllegalStateException("Cannot revert while in state: $statusStr")
                }

                val newStatus = revertStagedUpdate()
                val newStatusStr = UpdateEngineStatus.toString(newStatus)
                Log.d(TAG, "New status after revert: $newStatusStr")

                if (newStatus == UpdateEngineStatus.IDLE) {
                    listener.onUpdateResult(this, UpdateReverted)
                } else {
                    listener.onUpdateResult(this, UpdateFailed(newStatusStr))
                }
            } else if (status == UpdateEngineStatus.UPDATED_NEED_REBOOT) {
                // The update already completed in a previous run; backup and
                // conflict resolution ran then. Nothing to do but remind the user.

                // Resend success notification to remind the user to reboot. We can't perform any
                // further operations besides reverting.
                listener.onUpdateResult(this, UpdateNeedReboot)
            } else {
		var rules: ResolvedRules = ResolvedRules.EMPTY
                if (status == UpdateEngineStatus.IDLE) {
                    if (action == Action.MONITOR) {
                        // Nothing to do.
                        listener.onUpdateResult(this, NothingToMonitor)
                        return
                    }

                    Log.d(TAG, "Starting new update because engine is idle")

                    listener.onUpdateProgress(this, ProgressType.CHECK, 0, 0)

                    val checkUpdateResult = checkForUpdates()

                    if (!checkUpdateResult.updateAvailable) {
                        // Update not needed.
                        listener.onUpdateResult(this, UpdateUnnecessary)
                        return
                    } else if (action == Action.CHECK ||
                        (action == Action.INSTALL && checkUpdateResult.message != null)) {
                        // Alert that an update is available, attaching the message if present. When
                        // a message exists, this branch also fires for automatic installation
                        // (Action.INSTALL), overriding it so the user must acknowledge the message
                        // first (via the notification -> full-screen message -> Action.INSTALL_CONFIRMED).
                        listener.onUpdateResult(this,
                            UpdateAvailable(checkUpdateResult.fingerprints, checkUpdateResult.message))
                        return
                    }

                    // We immediately switch to the update state here instead of waiting until
                    // update_engine begins installation. For incremental OTAs, the payload metadata
                    // check for verifying source partition digests can take a while and the status
                    // should not be "checking for updates".
                    listener.onUpdateProgress(this, ProgressType.UPDATE, 0, 0)

		   // backupEngine.backup("com.google.android.apps.messaging")
                   
		    rules = checkUpdateResult.rules
                 
                    startInstallation(
                        checkUpdateResult.otaUri,
                        checkUpdateResult.csigInfo,
                    )

                } else {
                    Log.w(TAG, "Monitoring existing update because engine is not idle")
                }

                val error = waitForError { it != -1 }
                val errorStr = UpdateEngineError.toString(error)
                Log.d(TAG, "Update engine result: $errorStr")

                if (UpdateEngineError.isUpdateSucceeded(error)) {
                    if (status == UpdateEngineStatus.CLEANUP_PREVIOUS_UPDATE) {
                        deleteCareMap()

                        Log.d(TAG, "Successfully cleaned up upgrade")
                        listener.onUpdateResult(this, UpdateCleanedUp)
                    } else {
                        Log.d(TAG, "Successfully completed upgrade")

                        // The new slot is staged and the engine is now pending reboot. We are
                        // still booted on the old slot, so any conflicting user-installed app is
                        // still an ordinary /data/app package that can be cleanly uninstalled
                        // here, before the user is prompted to reboot into the new slot.
                        //
                        // If any conflict cannot be safely removed, the new slot would bootloop
                        // on the leftover app until the OS fell back to the old slot, so we
                        // unstage (revert) the update and report which packages blocked it rather
                        // than letting the user reboot into a broken slot.
                        val conflictBlockers = resolvePackageConflicts(rules)
                        if (conflictBlockers.isNotEmpty()) {
                            Log.w(TAG, "Unremovable conflicting packages; reverting staged " +
                                    "update: $conflictBlockers")
                            revertStagedUpdate()
                            listener.onUpdateResult(this, UpdateFailedConflicts(conflictBlockers))
                        } else {
                            // The custom OTA source is a one-shot: reset it to the default
                            // (disabled) after a successful update.
                            prefs.allowCustomOtaSource = false
                            listener.onUpdateResult(this, UpdateSucceeded)
                        }
                    }
                } else if (error == UpdateEngineError.USER_CANCELED) {
                    deleteCareMap()

                    Log.w(TAG, "User cancelled upgrade")
                    listener.onUpdateResult(this, UpdateCancelled)
                } else {
                    throw Exception(errorStr)
                }
            }
        } catch (e: Exception) {
            deleteCareMap()

            Log.e(TAG, "Failed to install update", e)

            if (e.findCause(BrokenNetworkApiException::class.java) != null) {
                listener.onUpdateResult(this, BrokenNetworkApi)
            } else {
                listener.onUpdateResult(this, UpdateFailed(e.toSingleLineString()))
            }
        } finally {
            wakeLock.release()
            unbind()

            try {
                stopLogcat()
            } catch (e: Exception) {
                Log.w(TAG, "Failed to dump logcat", e)
            }
        }
    }

    class BadFormatException(msg: String, cause: Throwable? = null)
        : Exception(msg, cause)

    class ValidationException(msg: String, cause: Throwable? = null)
        : Exception(msg, cause)

    class BrokenNetworkApiException(msg: String, cause: Throwable? = null)
        : Exception(msg, cause)

    private data class CheckUpdateResult(
        val updateAvailable: Boolean,
        val fingerprints: List<String>,
        val otaUri: Uri,
        val csigInfo: CsigInfo,
        val message: String?,
        val rules: ResolvedRules,
    )

    /** One entry of the signed rules file. */
    @Serializable
    private data class RuleEntry(
        @SerialName("package")
        val pkg: String,
        val action: String,
        val timestamp: Long? = null,
        val oneshot: Boolean = false,
    )

    /** The signed rules document (canonical JSON inside the CMS envelope). */
    @Serializable
    private data class RulesFile(
        val version: Int,
        val rules: List<RuleEntry> = emptyList(),
    )

    /** Rules partitioned into the two lanes the device acts on. */
    private data class ResolvedRules(
        val captureList: List<String>,
        val conflictExtra: List<String>,
    ) {
        companion object {
            val EMPTY = ResolvedRules(emptyList(), emptyList())
        }
    }

    @Serializable
    private data class PropertyFile(
        val name: String,
        val offset: Long,
        val size: Long,
        val digest: String?,
    ) {
        fun equalsWithoutDigest(other: PropertyFile) =
            name == other.name && offset == other.offset && size == other.size
    }

    @Serializable
    private data class CsigInfo(
        val version: Int,
        val files: List<PropertyFile>,
        @SerialName("vbmeta_digest")
        val vbmetaDigest: String? = null,
        val timestamp: Long? = null,
    ) {
        init {
            if (version == 1) {
                require(vbmetaDigest == null) { "vbmeta_digest is not supported in csig version 1" }
            }
        }

        fun get(name: String) = files.find { it.name == name }

        fun getOrThrow(name: String) = get(name)
            ?: throw ValidationException("Missing property files entry: $name")
    }

    @Serializable
    private data class LocationInfo(
        @SerialName("location_ota")
        val locationOta: String,
        @SerialName("location_csig")
        val locationCsig: String,
    )

    @Serializable
    private data class UpdateInfo(
        val version: Int,
        val full: LocationInfo,
        val incremental: Map<String, LocationInfo> = emptyMap(),
        val timestamp: Long? = null,
    )

    @Parcelize
    enum class Action : Parcelable {
        MONITOR,
        CHECK,
        INSTALL,
        REVERT,

        /**
         * Like [INSTALL], but the user has already acknowledged the update message, so the message
         * gate in [run] is bypassed. Scheduled by [UpdateMessageActivity].
         */
        INSTALL_CONFIRMED;

        val requiresNetwork: Boolean
            get() = this == CHECK || this == INSTALL || this == INSTALL_CONFIRMED

        val performsLargeDownloads: Boolean
            get() = this == INSTALL || this == INSTALL_CONFIRMED

        val usesSignificantBattery: Boolean
            get() = this == INSTALL || this == INSTALL_CONFIRMED
    }

    sealed interface Result

    data object NothingToMonitor : Result

    data class UpdateAvailable(val fingerprints: List<String>, val message: String?) : Result

    data object UpdateUnnecessary : Result

    data object UpdateSucceeded : Result

    data object UpdateCleanedUp : Result

    /** Update succeeded in a previous updater run. */
    data object UpdateNeedReboot : Result

    data object UpdateReverted : Result

    data object UpdateCancelled : Result

    data class UpdateFailed(val errorMsg: String) : Result

    /** Update was reverted because conflicting packages could not be removed. */
    data class UpdateFailedConflicts(val packages: List<String>) : Result

    data object BrokenNetworkApi : Result

    enum class ProgressType {
        CHECK,
        UPDATE,
        VERIFY,
        FINALIZE,
        CLEANUP;

        val isActionable: Boolean
            get() = this == UPDATE || this == VERIFY || this == FINALIZE
    }

    interface UpdaterThreadListener {
        fun onUpdateResult(thread: UpdaterThread, result: Result)

        fun onUpdateProgress(thread: UpdaterThread, type: ProgressType, current: Int, max: Int)
    }

    companion object {
        private val TAG = UpdaterThread::class.java.simpleName

        private const val USER_AGENT = "${BuildConfig.APPLICATION_ID}/${BuildConfig.VERSION_NAME}"
        private val USER_AGENT_UPDATE_ENGINE = "$USER_AGENT update_engine/${Build.VERSION.SDK_INT}"

        private const val TIMEOUT_MS = 30_000

        const val PROP_SECURITY_PATCH = "ro.build.version.security_patch"
        const val PROP_VBMETA_DIGEST = "ro.boot.vbmeta.digest"

        // ROM build timestamp (UTC, seconds since the Unix epoch). Compared
        // against UpdateInfo.timestamp to detect when the running OS is already
        // newer than the published OTA.
        const val PROP_BENOS_TIMESTAMP = "ro.benos_timestamp"

        private val JSON_FORMAT = Json { ignoreUnknownKeys = true }

        /**
         * Get the OS security patch level.
         *
         * CalyxOS lies about the value when queried from [Build.VERSION.SECURITY_PATCH]. This will
         * return the property value of [PROP_SECURITY_PATCH] and log a warning if the OS lies.
         */
        @SuppressLint("PrivateApi")
        private fun getSecurityPatch(): String {
            val reportedPatch = Build.VERSION.SECURITY_PATCH
            val actualPatch = try {
                val systemProperties = Class.forName("android.os.SystemProperties")
                val get = systemProperties.getDeclaredMethod("get", String::class.java)
                get.invoke(null, PROP_SECURITY_PATCH) as String
            } catch (e: Exception) {
                Log.w(TAG, "Failed to query $PROP_SECURITY_PATCH property", e)
                null
            }

            if (reportedPatch != actualPatch) {
                Log.w(TAG, "OS lies about security patch: reported=$reportedPatch, actual=$actualPatch")
            }

            return actualPatch ?: reportedPatch
        }
    }
}
