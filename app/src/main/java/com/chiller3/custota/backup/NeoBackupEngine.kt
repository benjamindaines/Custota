/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * NeoBackupEngine: produces Neo-Backup-compatible backups for a single package
 * without root, using benbackupd for privileged reads. The on-disk result is a
 * standard Neo-Backup instance directory that the user's Neo-Backup app can
 * restore directly.
 *
 * Layout produced (non-flat, properties-in-dir):
 *   <BACKUP_ROOT>/<pkg>/<yyyy-MM-dd-HH-mm-ss-SSS>-user_<id>/
 *       base.apk, split_*.apk            (if BACKUP_APK)
 *       data.tar.zst[.enc]               (if app data present)
 *       device_protected_files.tar...    (if present)
 *       external_files.tar...            (if present)
 *       obb_files.tar...                 (if present)
 *       media_files.tar...               (if present)
 *       backup.properties                (Neo-Backup JSON schema)
 */
package com.chiller3.custota.backup

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.util.Log
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import org.apache.commons.compress.archivers.tar.TarConstants
import java.io.File
import java.io.OutputStream
import java.time.LocalDateTime
import java.util.Date
import com.chiller3.custota.updater.PackageConflictConfig

class NeoBackupEngine(
    private val context: Context,
    private val fs: PrivilegedFs = PrivilegedFs(),
) {
    private val pm = context.packageManager

    // mode type masks, identical to Neo-Backup TarUtils
    private val DIR_MASK = 0b0_000_100_000_000_000_000   // 040000 S_IFDIR
    private val FILE_MASK = 0b0_001_000_000_000_000_000  // 0100000 S_IFREG
    private val FIFO_MASK = 0b0_000_001_000_000_000_000  // 010000 S_IFIFO
    private val LINK_MASK = 0b0_001_010_000_000_000_000  // 0120000 S_IFLNK

  
    fun backup(packageName: String, userId: Int = BackupConfig.USER_ID): File? {
        return try {
            val appInfo = pm.getApplicationInfo(packageName, 0)
            val pkgInfo = pm.getPackageInfo(packageName, 0)

            val now = LocalDateTime.now()
            val dateStr = NeoBackupFormat.BACKUP_DATE_TIME_FORMATTER.format(now)
            val instanceName = NeoBackupFormat.backupInstanceDir(dateStr, userId)

            val pkgDir = File(BackupConfig.BACKUP_ROOT, packageName)
            val instanceDir = File(pkgDir, instanceName)
            if (!instanceDir.mkdirs() && !instanceDir.isDirectory) {
                Log.e(TAG, "Could not create $instanceDir")
                return null
            }

            val iv = BackupCrypto.initIv()
            val salt = BackupConfig.ENCRYPTION_SALT ?: BackupCrypto.FALLBACK_SALT

            var hasApk = false
            var hasData = false
            var hasDe = false
            var hasExt = false
            var hasObb = false
            var hasMedia = false

            if (BackupConfig.BACKUP_APK) {
                hasApk = backupApks(appInfo, instanceDir)
            }
            if (BackupConfig.BACKUP_DATA) {
                hasData = backupTree(
                    NeoBackupFormat.BACKUP_DIR_DATA,
                    "/data/user/$userId/$packageName", instanceDir, iv, salt, topLevel = true,
                )
            }
            if (BackupConfig.BACKUP_DEVICE_PROTECTED_DATA) {
                hasDe = backupTree(
                    NeoBackupFormat.BACKUP_DIR_DEVICE_PROTECTED_FILES,
                    "/data/user_de/$userId/$packageName", instanceDir, iv, salt, topLevel = true,
                )
            }
            if (BackupConfig.BACKUP_EXTERNAL_DATA) {
                hasExt = backupTree(
                    NeoBackupFormat.BACKUP_DIR_EXTERNAL_FILES,
                    "/storage/emulated/$userId/Android/data/$packageName", instanceDir, iv, salt,
                )
            }
            if (BackupConfig.BACKUP_OBB) {
                hasObb = backupTree(
                    NeoBackupFormat.BACKUP_DIR_OBB_FILES,
                    "/storage/emulated/$userId/Android/obb/$packageName", instanceDir, iv, salt,
                )
            }
            if (BackupConfig.BACKUP_MEDIA) {
                hasMedia = backupTree(
                    NeoBackupFormat.BACKUP_DIR_MEDIA_FILES,
                    "/storage/emulated/$userId/Android/media/$packageName", instanceDir, iv, salt,
                )
            }

            val size = instanceDir.listFiles()?.sumOf { it.length() } ?: 0L

            val props = NeoBackupProps(
                packageName = packageName,
                packageLabel = pm.getApplicationLabel(appInfo).toString(),
                versionName = pkgInfo.versionName ?: "-",
                versionCode = pkgInfo.longVersionCode.toInt(),
                profileId = userId,
                sourceDir = appInfo.sourceDir,
                splitSourceDirs = appInfo.splitSourceDirs ?: arrayOf(),
                isSystem = packageName in PackageConflictConfig.IS_SYSTEM || (appInfo.flags and
                        (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0,
                backupDate = now,
                hasApk = hasApk,
                hasAppData = hasData,
                hasDevicesProtectedData = hasDe,
                hasExternalData = hasExt,
                hasObbData = hasObb,
                hasMediaData = hasMedia,
                compressionType = if (BackupConfig.COMPRESS) BackupConfig.COMPRESSION_TYPE else null,
                cipherType = if (BackupConfig.ENCRYPT) BackupCrypto.CIPHER_ALGORITHM else null,
                iv = iv,
                cpuArch = android.os.Build.SUPPORTED_ABIS.firstOrNull(),
                permissions = (pkgInfo.requestedPermissions?.toList() ?: emptyList()).sorted(),
                size = size,
            )

//            File(instanceDir, NeoBackupFormat.BACKUP_INSTANCE_PROPERTIES_INDIR)
            val propsFile = File(pkgDir, "$instanceName.properties")
            propsFile.writeText(props.toSerialized())

            Log.i(TAG, "Backed up $packageName -> $instanceDir (${size} bytes)")
            instanceDir
        } catch (e: PackageManager.NameNotFoundException) {
            Log.w(TAG, "$packageName not installed; nothing to back up")
            null
        } catch (e: Throwable) {
            Log.e(TAG, "Backup of $packageName failed", e)
            null
        }
    }

    private fun backupApks(appInfo: ApplicationInfo, instanceDir: File): Boolean {
        val sourceDir = appInfo.sourceDir ?: return false
        if (!sourceDir.startsWith("/data/")) {
            Log.i(TAG, "Preinstalled APK survives the OTA; skipping capture ($sourceDir)")
            return false  
        }
        val apks = buildList { add(sourceDir); appInfo.splitSourceDirs?.forEach { add(it) } }
        var any = false
        for (apk in apks) {
            try {
                File(instanceDir, File(apk).name).outputStream().use { fs.readFile(apk, it) }
                any = true
            } catch (e: Throwable) {
                Log.w(TAG, "Skipping APK $apk: ${e.message}")
            }
        }
        return any
    }


    /**
    private fun backupApks(appInfo: ApplicationInfo, instanceDir: File): Boolean {
        val apks = buildList {
            appInfo.sourceDir?.let { add(it) }
            appInfo.splitSourceDirs?.forEach { add(it) }
        }
        if (apks.isEmpty()) return false
        for (apk in apks) {
            val name = File(apk).name
            File(instanceDir, name).outputStream().use { out ->
                fs.readFile(apk, out)
            }
        }
        return true
    }
    */

    /**
     * Tar up [sourcePath]'s contents into <type>.tar[.zst][.enc] in [instanceDir].
     * Returns false if the source is absent/empty.
     */
    private fun backupTree(
        type: String,
        sourcePath: String,
        instanceDir: File,
        iv: ByteArray,
        salt: ByteArray,
        topLevel: Boolean = false,
    ): Boolean {
        val nodes = try {
            fs.list(sourcePath)
        } catch (e: Throwable) {
            Log.d(TAG, "No $type at $sourcePath (${e.message})")
            return false
        }
        val filtered = applyExclusions(nodes, topLevel)
        if (filtered.isEmpty()) {
            Log.d(TAG, "Nothing to back up for $type")
            return false
        }

        val filename = NeoBackupFormat.backupArchiveFilename(
            type, BackupConfig.COMPRESS, BackupConfig.COMPRESSION_TYPE, BackupConfig.ENCRYPT,
        )
        val outFile = File(instanceDir, filename)
	return try {
		val nodes = fs.list(sourcePath)
		val filtered = applyExclusions(nodes, topLevel)
		if (filtered.isEmpty()) return false
        	outFile.outputStream().use { rawOut ->
            	    val wrapped: OutputStream = BackupCrypto.wrapArchiveStream(
                	rawOut,
               		compress = BackupConfig.COMPRESS,
                	compressionType = BackupConfig.COMPRESSION_TYPE,
                	compressionLevel = BackupConfig.COMPRESSION_LEVEL,
                	encrypt = BackupConfig.ENCRYPT,
                	password = BackupConfig.ENCRYPTION_PASSWORD.ifEmpty { null },
                	salt = salt,
                	iv = iv,
            	)
                TarArchiveOutputStream(wrapped).use { tar ->
                    tar.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX)
                    writeEntries(tar, sourcePath, filtered)
                }
            }
            true
        } catch (e: Throwable) {
		Log.w(TAG, "Tree $type at $sourcePath failed: ${e.message}")
		false
	  }
    }

    /** Mirrors Neo-Backup TarUtils.suAddFiles, sourcing bytes from benbackupd. */
    private fun writeEntries(tar: TarArchiveOutputStream, sourcePath: String, nodes: List<PrivilegedFs.Node>) {
        for (node in nodes) {
            val name = node.relPath
            when (node.type) {
                PrivilegedFs.NodeType.REGULAR -> {
                    val entry = TarArchiveEntry(name)
                    entry.size = node.size
                    entry.setNames(node.uid.toString(), node.gid.toString())
                    entry.mode = FILE_MASK or node.mode
                    entry.setModTime(Date(node.mtimeSec * 1000))
                    tar.putArchiveEntry(entry)
                    try {
                        fs.readFile("$sourcePath/$name", tar)
                    } finally {
                        tar.closeArchiveEntry()
                    }
                }
                PrivilegedFs.NodeType.DIRECTORY -> {
                    val entry = TarArchiveEntry(name, TarConstants.LF_DIR)
                    entry.setNames(node.uid.toString(), node.gid.toString())
                    entry.mode = DIR_MASK or node.mode
                    tar.putArchiveEntry(entry)
                    tar.closeArchiveEntry()
                }
                PrivilegedFs.NodeType.SYMLINK -> {
                    val entry = TarArchiveEntry(name, TarConstants.LF_SYMLINK)
                    entry.linkName = node.linkTarget
                    entry.setNames(node.uid.toString(), node.gid.toString())
                    entry.mode = LINK_MASK or node.mode
                    tar.putArchiveEntry(entry)
                    tar.closeArchiveEntry()
                }
                PrivilegedFs.NodeType.FIFO -> {
                    val entry = TarArchiveEntry(name, TarConstants.LF_FIFO)
                    entry.setNames(node.uid.toString(), node.gid.toString())
                    entry.mode = FIFO_MASK or node.mode
                    tar.putArchiveEntry(entry)
                    tar.closeArchiveEntry()
                }
            }
        }
    }

    /**
     * Drop excluded top-level dirs (and their whole subtree) plus excluded
     * basenames anywhere. relPath has no leading "./" and uses "/" separators.
     */
    private fun applyExclusions(nodes: List<PrivilegedFs.Node>, topLevel: Boolean): List<PrivilegedFs.Node> {
        val excludedPrefixes = ArrayList<String>()
        if (topLevel) {
            for (n in nodes) {
                if (!n.relPath.contains('/') && n.relPath in BackupConfig.TOP_LEVEL_EXCLUDED_DIRS) {
                    excludedPrefixes.add(n.relPath + "/")
                }
            }
        }
        return nodes.filter { n ->
            val base = n.relPath.substringAfterLast('/')
            if (base in BackupConfig.EXCLUDED_NAMES_ANYWHERE) return@filter false
            if (topLevel && !n.relPath.contains('/') &&
                n.relPath in BackupConfig.TOP_LEVEL_EXCLUDED_DIRS) return@filter false
            if (excludedPrefixes.any { n.relPath.startsWith(it) }) return@filter false
            true
        }
    }

    companion object {
        private const val TAG = "NeoBackupEngine"
    }
}
