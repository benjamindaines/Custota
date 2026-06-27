/*
 * SPDX-FileCopyrightText: 2026 Ben Daines
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.updater

import android.util.Base64
import android.util.Log
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec

object RulesConfig {
    
    const val RULES_URL = "https://ota.dgsd.ph/rules.toml.p7m"

    private const val SPKI_DER_BASE64 =
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwfEgC0+dPuSwdDs+KWov" +
        "LdnlBruKH9FsGW3hLjET7UnJdZ79cB4dUP0vmy38RdkeglSjngQ/sD8YZlqu7DO" +
        "lSd8/mUk7XLBa0XIB4cRqLj3pD6CCP9gMcb/ArwulobAHp4QDnvTdeDMV2GKht0" +
        "+/X1BrEmcMoGcYuco7XLFlXC/7JgjOArXUxE7wuJvTpH8BEw+ArDTH0ugcfkyL+" +
        "izSlIwzXvzYnZTFUopHTFtae04gLIgJtho5nW1558dRVEzPkBjjiTIKzJrRo548" +
        "CrE4/nmRdEGieHD57QExCrTMqO9SDSA0baEoP71/DuosWx9/DzPDIc47uYGHaJd" +
        "NRBF16tXgRhE7vgl5Ex585/Rye3+B1OmMycLk+RjQCuLWM6NDv+7o9ir1ziq5vl" +
        "TLaaUyfAQv5tUDeocC22nJ4apev0N2659UB+Nzti8R78rDfP0StaaxtU7nhys36" +
        "YfNnFUhz0zVEolNZPS2eVdd89BoNKxdQ/3SQHUD+u7uE1z1zxkgUi5C0G/z+i4N" +
        "2coiKeoe9ZS0C71IW1afDPn9R4W0LBNf2A0i6iUFYa3/vq5J4f+GlMUvI0tExFs" +
        "sEN1hWoUqDGcbT0KHaD6VnyVrs8pbFxomtCvVGlHedO/gPtkjrEKkut0TYGyHGP" +
        "DU2L1yqjHy9NDrgZCWF0gmz/5ynfbaW/8CAwEAAQ=="

    private const val SPKI_SHA256 =
        "05f5bf36ac9cc233496b88568e7e87981590e2aaeefe6bf396eb85d3f51c6e9a"

    val publicKey: PublicKey? by lazy { loadPinnedKey() }

    private fun loadPinnedKey(): PublicKey? {
        return try {
            val spki = Base64.decode(SPKI_DER_BASE64, Base64.DEFAULT)

            val actual = MessageDigest.getInstance("SHA-256").digest(spki)
                .joinToString("") { "%02x".format(it) }
            if (!actual.equals(SPKI_SHA256, ignoreCase = true)) {
                Log.e(TAG, "Embedded rules key does not match its pin; refusing to trust it")
                return null
            }

            KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(spki))
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load embedded rules key", e)
            null
        }
    }

    private val TAG = RulesConfig::class.java.simpleName
}
