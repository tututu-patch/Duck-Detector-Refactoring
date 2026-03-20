package com.eltavine.duckdetector.core.packagevisibility

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

enum class InstalledPackageVisibility {
    UNKNOWN,
    FULL,
    RESTRICTED,
}

object InstalledPackageVisibilityChecker {

    const val FULL_VISIBILITY_MINIMUM_COUNT = 10
    const val SUSPICIOUSLY_LOW_VISIBLE_PACKAGE_COUNT = 60

    fun detect(
        context: Context,
        installedPackageCount: Int,
    ): InstalledPackageVisibility {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return InstalledPackageVisibility.FULL
        }
        return if (installedPackageCount > FULL_VISIBILITY_MINIMUM_COUNT) {
            InstalledPackageVisibility.FULL
        } else {
            InstalledPackageVisibility.RESTRICTED
        }
    }

    fun hasSuspiciouslyLowInventory(
        visibility: InstalledPackageVisibility,
        installedPackageCount: Int,
        sdkInt: Int = Build.VERSION.SDK_INT,
    ): Boolean {
        if (sdkInt < Build.VERSION_CODES.R) {
            return false
        }
        return visibility == InstalledPackageVisibility.FULL &&
                installedPackageCount < SUSPICIOUSLY_LOW_VISIBLE_PACKAGE_COUNT
    }

    @Suppress("DEPRECATION")
    fun getInstalledPackages(context: Context): Set<String> {
        return runCatching {
            val applications = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong()),
                )
            } else {
                context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
            }
            applications.mapTo(linkedSetOf()) { it.packageName }
        }.getOrDefault(emptySet())
    }
}
