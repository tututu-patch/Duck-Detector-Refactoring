package com.eltavine.duckdetector.core.packagevisibility

import android.os.Build
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InstalledPackageVisibilityCheckerTest {

    @Test
    fun `full inventory below sixty is suspicious on android r and newer`() {
        assertTrue(
            InstalledPackageVisibilityChecker.hasSuspiciouslyLowInventory(
                visibility = InstalledPackageVisibility.FULL,
                installedPackageCount = 43,
                sdkInt = Build.VERSION_CODES.R,
            ),
        )
    }

    @Test
    fun `restricted inventory or pre-r does not trigger low-count warning`() {
        assertFalse(
            InstalledPackageVisibilityChecker.hasSuspiciouslyLowInventory(
                visibility = InstalledPackageVisibility.RESTRICTED,
                installedPackageCount = 43,
                sdkInt = Build.VERSION_CODES.UPSIDE_DOWN_CAKE,
            ),
        )
        assertFalse(
            InstalledPackageVisibilityChecker.hasSuspiciouslyLowInventory(
                visibility = InstalledPackageVisibility.FULL,
                installedPackageCount = 43,
                sdkInt = Build.VERSION_CODES.Q,
            ),
        )
    }
}
