/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Build-time configuration for the embedded NeoBackup-compatible backup that
 * runs before conflict uninstalls. No UI; edit values here.
 */
package com.chiller3.custota.backup

object BackupConfig {

    
    const val BACKUP_ROOT = "/storage/emulated/0/NeoBackup"

    const val USER_ID = 0

    // --- what to capture -------------------------------------------------
    const val BACKUP_APK = true
    const val BACKUP_DATA = true                 // /data/user/<id>/<pkg>
    const val BACKUP_DEVICE_PROTECTED_DATA = true// /data/user_de/<id>/<pkg>
    const val BACKUP_EXTERNAL_DATA = true        // Android/data/<pkg>
    const val BACKUP_OBB = true                  // Android/obb/<pkg>
    const val BACKUP_MEDIA = true                // Android/media/<pkg>

    // --- compression (matches Neo-Backup) --------------------------------
    const val COMPRESS = true
    const val COMPRESSION_TYPE = "gz"           // "zst" | "gz" | "no" NOTE: zst is broken currently 
    const val COMPRESSION_LEVEL = 3              // Neo-Backup default-ish

    // --- exclusions (match / slightly tighten Neo-Backup) ----------------
    const val BACKUP_CACHE = false               // false => exclude cache/code_cache
    const val BACKUP_NO_BACKUP = false           // false => exclude no_backup
    val TOP_LEVEL_EXCLUDED_DIRS: List<String>
        get() = buildList {
            add("lib")                           // arch-specific, never restore
            if (!BACKUP_NO_BACKUP) add("no_backup")
            if (!BACKUP_CACHE) { add("cache"); add("code_cache") }
        }
    val EXCLUDED_NAMES_ANYWHERE: List<String> = listOf(
        "com.google.android.gms.appid.xml",
        "com.machiav3lli.backup.xml",
        "trash",
        ".thumbnails",
    )

    // Realistically, don't use this
    const val ENCRYPT = false
    const val ENCRYPTION_PASSWORD = ""           // must equal user's Neo-Backup password
    // null => use Neo-Backup FALLBACK_SALT ("oandbackupx")
    val ENCRYPTION_SALT: ByteArray? = null
}
