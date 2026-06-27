/*
 * SPDX-FileCopyrightText: 2026 Andrew Gunnerson
 * SPDX-License-Identifier: GPL-3.0-only
 */

package com.chiller3.custota.updater

/**
 * Build-time configuration for pre-reboot package conflict resolution.
 *
 * This is the only file that normally needs editing to enable the feature.
 */
object PackageConflictConfig {
    val PACKAGE_NAMES: List<String> = listOf(
	"com.q25.keymapperbootfix",
        "com.blackberry.keyboard",
        "tech.shroyer.q25trackpadcustomizer",
        "com.duc1607.resolutionchanger",
        "com.duc1607.q25led",
	"com.rifsxd.ksunext",
	"tafsan.utgyzt.uynwdw",
    )

    val ADDITIONAL_TRUSTED_CERT_SHA256: List<String> = listOf(
        // "aa:bb:cc:dd:...",
    )

    val IS_SYSTEM: List<String> = listOf(
	"com.q25.keymapperbootfix",
        "com.blackberry.keyboard",
        "tech.shroyer.q25trackpadcustomizer",
        "com.duc1607.resolutionchanger",
        "com.duc1607.q25led",
    )
	
}
