/*
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * NeoBackup wire-format definitions, ported verbatim from Neo-Backup so that
 * archives produced by the updater are byte-format-compatible with the
 * standalone Neo-Backup app's restore path.
 *
 * IMPORTANT: The field names, defaults, date pattern, directory/file naming and
 * the kotlinx Json configuration below MUST stay in lock-step with the version
 * of Neo-Backup your users restore with. The values here match Neo-Backup
 * 8.3.x (backupVersionCode = MAJOR*1000 + MINOR = 8003).
 */
package com.chiller3.custota.backup

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

object NeoBackupFormat {

    // --- versioning ------------------------------------------------------
    // Neo-Backup: backupVersionCode = BuildConfig.MAJOR * 1000 + BuildConfig.MINOR
    // 8.3.x -> 8 * 1000 + 3 = 8003. Keep this <= the MAJOR*1000+MINOR of the
    // Neo-Backup build your users run, or restore may reject the props file.
    const val BACKUP_VERSION_CODE = 8003

    // --- date/time -------------------------------------------------------
    // Neo-Backup FILE_DATE_TIME_MS_PATTERN
    const val FILE_DATE_TIME_MS_PATTERN = "yyyy-MM-dd-HH-mm-ss-SSS"
    val BACKUP_DATE_TIME_FORMATTER: DateTimeFormatter =
        DateTimeFormatter.ofPattern(FILE_DATE_TIME_MS_PATTERN)
    // DATE_TIME_AS_VERSION_CODE_PATTERN, used only when a package has versionCode 0
    val DATE_TIME_AS_VERSION_CODE_FORMATTER: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyMMddHH")

    // --- per-data-type archive base names (Neo-Backup BaseAppAction) ------
    const val BACKUP_DIR_DATA = "data"
    const val BACKUP_DIR_DEVICE_PROTECTED_FILES = "device_protected_files"
    const val BACKUP_DIR_EXTERNAL_FILES = "external_files"
    const val BACKUP_DIR_OBB_FILES = "obb_files"
    const val BACKUP_DIR_MEDIA_FILES = "media_files"

    // --- properties file naming ------------------------------------------
    const val PROP_NAME = "properties"
    // When propertiesInDir is used (default we emit), the props file lives
    // inside the instance dir with this fixed name.
    const val BACKUP_INSTANCE_PROPERTIES_INDIR = "backup.$PROP_NAME"

    /** Instance directory name, e.g. "2026-06-22-13-04-55-123-user_0". */
    fun backupInstanceDir(dateTimeStr: String, profileId: Int) =
        "$dateTimeStr-user_$profileId"

    /**
     * Neo-Backup BaseAppAction.getBackupArchiveFilename. Produces e.g.
     * "data.tar.zst" or "data.tar.zst.enc".
     */
    fun backupArchiveFilename(
        what: String,
        isCompressed: Boolean,
        compressionType: String?,
        isEncrypted: Boolean,
    ): String {
        val ext = buildString {
            if (isCompressed) {
                append(
                    when (compressionType) {
                        null, "no" -> ""
                        "gz" -> ".gz"
                        "zst" -> ".zst"
                        else -> ".gz"
                    }
                )
            }
            if (isEncrypted) append(".enc")
        }
        return "$what.tar$ext"
    }

    // --- kotlinx Json: must match Neo-Backup NeoApp.JsonDefault ------------
    // Neo-Backup decodes with JsonDefault (no ignoreUnknownKeys, encodeDefaults
    // = false). We therefore only emit the Backup data class with identical
    // field names/defaults; do not add extra keys.
    @OptIn(ExperimentalSerializationApi::class)
    val JSON: Json = Json {
        // default: encodeDefaults = false, ignoreUnknownKeys = false
    }

    /**
     * Neo-Backup LocalDateTimeSerializer encodes LocalDateTime via its default
     * ISO-8601 toString()/parse(), as a JSON string.
     */
    object LocalDateTimeSerializer : KSerializer<LocalDateTime> {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("LocalDateTime", PrimitiveKind.STRING)

        override fun serialize(encoder: Encoder, value: LocalDateTime) =
            encoder.encodeString(value.toString())

        override fun deserialize(decoder: Decoder): LocalDateTime =
            LocalDateTime.parse(decoder.decodeString())
    }
}


@Serializable
data class NeoBackupProps @OptIn(ExperimentalSerializationApi::class) constructor(
    val backupVersionCode: Int = NeoBackupFormat.BACKUP_VERSION_CODE,
    val packageName: String,
    val packageLabel: String,
    val versionName: String? = "-",
    val versionCode: Int = 0,
    val profileId: Int = 0,
    val sourceDir: String? = null,
    val splitSourceDirs: Array<String> = arrayOf(),
    val isSystem: Boolean = false,
    @Serializable(with = NeoBackupFormat.LocalDateTimeSerializer::class)
    val backupDate: LocalDateTime,
    val hasApk: Boolean = false,
    val hasAppData: Boolean = false,
    val hasDevicesProtectedData: Boolean = false,
    val hasExternalData: Boolean = false,
    val hasObbData: Boolean = false,
    val hasMediaData: Boolean = false,
    val compressionType: String? = null,
    val cipherType: String? = null,
    val iv: ByteArray? = byteArrayOf(),
    val cpuArch: String?,
    val permissions: List<String> = listOf(),
    val size: Long = 0,
    val note: String = "",
    val persistent: Boolean = false,
) {
    fun toSerialized(): String = NeoBackupFormat.JSON.encodeToString(serializer(), this)

    // data class equals/hashCode on arrays is reference based; provide content
    // based ones to avoid surprises if these are ever compared.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is NeoBackupProps) return false
        return packageName == other.packageName && backupDate == other.backupDate
    }

    override fun hashCode(): Int = 31 * packageName.hashCode() + backupDate.hashCode()
}
