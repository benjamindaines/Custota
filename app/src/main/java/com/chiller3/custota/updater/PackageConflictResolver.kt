/*
 * SPDX-FileCopyrightText: 2026 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.updater

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.IntentSender
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.content.pm.VersionedPackage
import android.util.Log
import androidx.core.content.ContextCompat
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import android.Manifest
import android.os.Process

/**
 * Removes user-installed apps that would collide with a same-named system app being introduced by
 * an OTA, but only when the installed copy is signed with a *different* key than the platform.
 */
class PackageConflictResolver(private val context: Context) {
    private val packageManager = context.packageManager

 
    /**
     * Evaluate each candidate package and uninstall the ones that are genuine
     * conflicts (installed, non-system, untrusted signature). A non-null
     * [onBeforeUninstall] is invoked immediately before each uninstall; returning
     * false (e.g. because a pre-uninstall backup could not be made) leaves the app
     * in place.
     *
     * Returns the packages actually removed and the "blockers": conflicts that
     * were NOT removed, whether because the hook declined or the uninstall failed.
     * The caller uses a non-empty blocker list to revert a staged update, since a
     * leftover conflicting app would bootloop the new slot.
     */
    @JvmOverloads
    fun resolveConflicts(
        packageNames: List<String> = PackageConflictConfig.PACKAGE_NAMES,
        onBeforeUninstall: ((String) -> Boolean)? = null,
    ): ConflictResult {
        if (packageNames.isEmpty()) {
            Log.d(TAG, "No packages configured for conflict resolution")
            return ConflictResult(emptyList(), emptyList())
        }

        val trustedCerts = collectTrustedCertificates()
        if (trustedCerts.rawCerts.isEmpty() && trustedCerts.sha256Digests.isEmpty()) {
            // Fail safe: if we cannot determine any trusted certificate, do nothing
            // rather than risk uninstalling a legitimately-signed app.
            Log.w(TAG, "No trusted certificates available; skipping conflict resolution")
            return ConflictResult(emptyList(), emptyList())
        }

        val removed = mutableListOf<String>()
        val blockers = mutableListOf<String>()

        for (packageName in packageNames) {
            try {
                if (!shouldUninstall(packageName, trustedCerts)) {
                    continue
                }

                // Back up before removing. If the hook declines (e.g. the backup
                // could not be made), leave the app in place; it becomes a blocker.
                if (onBeforeUninstall != null && !onBeforeUninstall(packageName)) {
                    Log.w(TAG, "Not uninstalling $packageName: pre-uninstall backup failed")
                    blockers.add(packageName)
                    continue
                }

                if (uninstall(packageName)) {
                    removed.add(packageName)
                } else {
                    Log.w(TAG, "Failed to uninstall conflicting package: $packageName")
                    blockers.add(packageName)
                }
            } catch (e: Exception) {
                // A package we could not even evaluate is treated as a blocker so the
                // update is reverted rather than risking a leftover conflict.
                Log.w(TAG, "Error while evaluating $packageName for conflict resolution", e)
                blockers.add(packageName)
            }
        }

        Log.d(TAG, "Conflict resolution removed=$removed blockers=$blockers")
        return ConflictResult(removed, blockers)
    }

    /** Result of [resolveConflicts]: packages removed, and conflicts left in place. */
    data class ConflictResult(
        val removed: List<String>,
        val blockers: List<String>,
    )

    private fun shouldUninstall(packageName: String, trustedCerts: TrustedCertificates): Boolean {
        val appInfo = try {
            packageManager.getApplicationInfo(packageName, 0)
        } catch (e: PackageManager.NameNotFoundException) {
            Log.d(TAG, "$packageName is not installed; nothing to do")
            return false
        }

        val isSystem = (appInfo.flags and
            (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
        if (isSystem) {
            Log.d(TAG, "$packageName is a system app; leaving untouched")
            return false
        }

        if (isSignedByTrustedCertificate(packageName, trustedCerts)) {
            Log.d(TAG, "$packageName is signed by a trusted certificate; leaving untouched")
            return false
        }

        Log.i(TAG, "$packageName is a user app with a mismatched signature; will uninstall")
        return true
    }

    private fun isSignedByTrustedCertificate(
        packageName: String,
        trustedCerts: TrustedCertificates,
    ): Boolean {
        for (cert in trustedCerts.rawCerts) {
            if (packageManager.hasSigningCertificate(
                    packageName, cert, PackageManager.CERT_INPUT_RAW_X509)) {
                return true
            }
        }

        if (trustedCerts.sha256Digests.isNotEmpty()) {
            for (digest in signingCertSha256Digests(packageName)) {
                if (trustedCerts.sha256Digests.contains(digest)) {
                    return true
                }
            }
        }

        return false
    }

    private fun collectTrustedCertificates(): TrustedCertificates {
        val rawCerts = mutableListOf<ByteArray>()

        try {
            signaturesOf(context.packageName).forEach { rawCerts.add(it.toByteArray()) }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to read this app's own signing certificate", e)
        }

        val digests = PackageConflictConfig.ADDITIONAL_TRUSTED_CERT_SHA256
            .map { it.lowercase().replace(":", "").trim() }
            .filter { it.isNotEmpty() }
            .toSet()

        return TrustedCertificates(rawCerts, digests)
    }

    private fun signingCertSha256Digests(packageName: String): List<String> {
        return try {
            signaturesOf(packageName).map { sha256Hex(it.toByteArray()) }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to read signing certificate for $packageName", e)
            emptyList()
        }
    }

    @SuppressLint("PackageManagerGetSignatures")
    private fun signaturesOf(packageName: String): Array<Signature> {
        val info = packageManager.getPackageInfo(
            packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val signingInfo = info.signingInfo ?: return emptyArray()
        val signatures = if (signingInfo.hasMultipleSigners()) {
            signingInfo.apkContentsSigners
        } else {
            // History includes the current cert plus any earlier certs in the rotation lineage.
            signingInfo.signingCertificateHistory
        }
        return signatures ?: emptyArray()
    }
    
    private fun uninstall(packageName: String): Boolean {
        val installer = packageManager.packageInstaller
        val latch = CountDownLatch(1)
        var status = PackageInstaller.STATUS_FAILURE
        var message: String? = null

        val action = "$ACTION_UNINSTALL_RESULT.$packageName"
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, intent: Intent?) {
                status = intent?.getIntExtra(
                    PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
                    ?: PackageInstaller.STATUS_FAILURE
                message = intent?.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
                latch.countDown()
            }
        }

        ContextCompat.registerReceiver(
            context, receiver, IntentFilter(action), ContextCompat.RECEIVER_NOT_EXPORTED)

        try {
            val intent = Intent(action).setPackage(context.packageName)
            val pendingIntent = PendingIntent.getBroadcast(
                context,
                packageName.hashCode(),
                intent,
                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )

            Log.i(TAG, "Uninstalling $packageName")

            installer.uninstall(packageName, pendingIntent.intentSender)
            
            if (!latch.await(UNINSTALL_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                Log.w(TAG, "Timed out waiting for uninstall of $packageName")
                return false
            }

            return when (status) {
                PackageInstaller.STATUS_SUCCESS -> {
                    Log.i(TAG, "Uninstalled $packageName")
                    true
                }
                PackageInstaller.STATUS_PENDING_USER_ACTION -> {

                    Log.w(TAG, "Uninstall of $packageName requires user action; skipping")
                    false
                }
                else -> {
                    Log.w(TAG, "Failed to uninstall $packageName: status=$status, message=$message")
                    false
                }
            }
        } finally {
            try {
                context.unregisterReceiver(receiver)
            } catch (e: IllegalArgumentException) {
                // Already unregistered; ignore.
            }
        }
    }

    private data class TrustedCertificates(
        val rawCerts: List<ByteArray>,
        val sha256Digests: Set<String>,
    )

/*   
    private fun uninstallAllUsers(
        installer: PackageInstaller,
        packageName: String,
        sender: IntentSender,
    ): Boolean {
        return try {
            val versioned = VersionedPackage(packageName, PACKAGE_VERSION_CODE_HIGHEST)
            Log.i(TAG, "uid=${Process.myUid()} pkg=${context.packageName} " +
            "DELETE=${context.checkSelfPermission(Manifest.permission.DELETE_PACKAGES)} " +
            "IAUF=${context.checkSelfPermission("android.permission.INTERACT_ACROSS_USERS_FULL")}")
            val method = PackageInstaller::class.java.getMethod(
                "uninstall",
                VersionedPackage::class.java,
                Int::class.javaPrimitiveType,
                IntentSender::class.java,
            )
            method.invoke(installer, versioned, DELETE_ALL_USERS, sender)
            Log.d(TAG, "Requested all-users uninstall of $packageName")
            true
	   } catch (e: Throwable) {
	    Log.w(TAG, "All-users uninstall threw: ${e.javaClass.name}: ${e.message}", e)
	    false
	}
/**        } catch (e: Throwable) {
            Log.w(TAG, "All-users uninstall unavailable for $packageName; " +
                "falling back to single-user", e)
            false
        }*/
    }
*/
    companion object {
        private val TAG = PackageConflictResolver::class.java.simpleName

        private const val ACTION_UNINSTALL_RESULT =
            "com.chiller3.custota.updater.UNINSTALL_RESULT"

        private const val UNINSTALL_TIMEOUT_SECONDS = 60L

        /** Value of the hidden `PackageManager.DELETE_ALL_USERS` flag. */
        private const val DELETE_ALL_USERS = 0x00000002

        /** Value of the hidden `PackageManager.VERSION_CODE_HIGHEST` constant. */
        private const val PACKAGE_VERSION_CODE_HIGHEST = -1L

        private fun sha256Hex(data: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(data)
            return digest.joinToString("") { "%02x".format(it) }
        }
    }
}
