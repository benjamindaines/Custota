/*
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * AES/GCM + PBKDF2 stream encryption ported verbatim from Neo-Backup CryptoUtils
 * plus the compression wrapping from BackupAppAction.createArchiveFile, so the
 * envelope on disk is bit-identical to what Neo-Backup writes and can be
 * decrypted/decompressed by the Neo-Backup restore path.
 *
 * Stream nesting (outermost write -> file):
 *   Tar -> (zstd|gzip) -> (AES/GCM CipherOutputStream) -> file
 * i.e. on disk = encrypt(compress(tar)). Restore reverses it.
 */
package com.chiller3.custota.backup

import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream
import org.apache.commons.compress.compressors.gzip.GzipParameters
import org.apache.commons.compress.compressors.zstandard.ZstdCompressorOutputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

object BackupCrypto {

    // --- Neo-Backup CryptoUtils constants (do not change) ----------------
    private const val DEFAULT_SECRET_KEY_FACTORY_ALGORITHM = "PBKDF2withHmacSHA256"
    const val CIPHER_ALGORITHM = "AES/GCM/NoPadding"
    private const val ITERATION_COUNT = 2020
    private const val KEY_LENGTH = 256

    /** Neo-Backup FALLBACK_SALT, used when the user set no custom salt. */
    val FALLBACK_SALT: ByteArray = "oandbackupx".toByteArray(StandardCharsets.UTF_8)

    /** Random IV, one per archive, stored in backup.properties (as Neo-Backup does). */
    fun initIv(): ByteArray {
        val blockSize = Cipher.getInstance(CIPHER_ALGORITHM).blockSize
        return Random.nextBytes(blockSize)
    }

    private fun keyFromPassword(password: String, salt: ByteArray): SecretKey {
        val factory = SecretKeyFactory.getInstance(DEFAULT_SECRET_KEY_FACTORY_ALGORITHM)
        val spec = PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH)
        val keyBytes = factory.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, CIPHER_ALGORITHM.split("/")[0])
    }

    /** Wrap [out] so writes are AES/GCM encrypted, matching Neo-Backup. */
    fun encryptStream(out: OutputStream, password: String, salt: ByteArray, iv: ByteArray): CipherOutputStream {
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, keyFromPassword(password, salt), IvParameterSpec(iv))
        return CipherOutputStream(out, cipher)
    }

   
    fun wrapArchiveStream(
        fileOut: OutputStream,
        compress: Boolean,
        compressionType: String,     // "zst" | "gz" | "no"
        compressionLevel: Int,
        encrypt: Boolean,
        password: String?,
        salt: ByteArray,
        iv: ByteArray,
    ): OutputStream {
        var out: OutputStream = fileOut

        // 1) encryption is the innermost wrapper (closest to the file)
        if (encrypt) {
            requireNotNull(password) { "Encryption requested but no password configured" }
            require(password.isNotEmpty()) { "Encryption password is empty" }
            out = encryptStream(out, password, salt, iv)
        }

        // 2) compression wraps the (maybe-encrypting) stream
        if (compress) {
            out = when (compressionType) {
                "no" -> out
                "gz" -> {
                    val p = GzipParameters().apply { setCompressionLevel(compressionLevel) }
                    GzipCompressorOutputStream(out, p)
                }
            //    "zst" -> ZstdCompressorOutputStream.builder()
            //        .setOutputStream(out)
            //        .setLevel(compressionLevel)
            //        .get()
                else -> throw UnsupportedOperationException("Unsupported compression: $compressionType")
            }
        }
        return out
    }
}
