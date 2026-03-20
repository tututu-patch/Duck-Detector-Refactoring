package com.eltavine.duckdetector.features.dangerousapps.data.repository

import android.content.Context
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibilityChecker
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility

object PackageVisibilityChecker {

    fun detect(
        context: Context,
        installedPackageCount: Int,
    ): DangerousPackageVisibility {
        return when (InstalledPackageVisibilityChecker.detect(context, installedPackageCount)) {
            InstalledPackageVisibility.FULL -> DangerousPackageVisibility.FULL
            InstalledPackageVisibility.RESTRICTED -> DangerousPackageVisibility.RESTRICTED
            InstalledPackageVisibility.UNKNOWN -> DangerousPackageVisibility.UNKNOWN
        }
    }

    fun getInstalledPackages(context: Context): Set<String> {
        return InstalledPackageVisibilityChecker.getInstalledPackages(context)
    }

    fun hasSuspiciouslyLowInventory(
        packageVisibility: DangerousPackageVisibility,
        installedPackageCount: Int,
    ): Boolean {
        val visibility = when (packageVisibility) {
            DangerousPackageVisibility.FULL -> InstalledPackageVisibility.FULL
            DangerousPackageVisibility.RESTRICTED -> InstalledPackageVisibility.RESTRICTED
            DangerousPackageVisibility.UNKNOWN -> InstalledPackageVisibility.UNKNOWN
        }
        return InstalledPackageVisibilityChecker.hasSuspiciouslyLowInventory(
            visibility = visibility,
            installedPackageCount = installedPackageCount,
        )
    }
}
