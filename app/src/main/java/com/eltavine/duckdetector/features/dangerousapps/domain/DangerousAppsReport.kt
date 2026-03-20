package com.eltavine.duckdetector.features.dangerousapps.domain

enum class DangerousAppsStage {
    LOADING,
    READY,
    FAILED,
}

enum class DangerousPackageVisibility {
    UNKNOWN,
    FULL,
    RESTRICTED,
}

enum class DangerousDetectionMethodKind(
    val label: String,
) {
    PACKAGE_MANAGER("PackageManager"),
    DIRECTORY_LISTING("Android/data Directory Listing"),
    ZWC_BYPASS("Android/data ZWC Bypass"),
    IGNORABLE_CODEPOINT_BYPASS("Android/data Ignorable CodePoint Bypass"),
    FUSE_STAT("FUSE stat"),
    NATIVE_DATA_STAT("Native /data/data stat"),
    SPECIAL_PATH("Special path"),
    SCENE_LOOPBACK("Scene loopback"),
    THANOX_IPC("IPC Probe (DROPBOX_SERVICE)"),
    ACCESSIBILITY_SERVICE("Accessibility Service"),
}

data class DangerousAppTarget(
    val packageName: String,
    val appName: String,
    val category: DangerousAppCategory,
)

data class DangerousDetectionMethod(
    val kind: DangerousDetectionMethodKind,
    val detail: String? = null,
    val hmaEligible: Boolean = true,
) {
    val displayText: String
        get() = detail ?: kind.label
}

data class DangerousAppFinding(
    val target: DangerousAppTarget,
    val methods: List<DangerousDetectionMethod>,
)

data class DangerousAppsReport(
    val stage: DangerousAppsStage,
    val packageVisibility: DangerousPackageVisibility,
    val packageManagerVisibleCount: Int,
    val suspiciousLowPmInventory: Boolean,
    val targets: List<DangerousAppTarget>,
    val findings: List<DangerousAppFinding>,
    val hiddenFromPackageManager: List<DangerousAppFinding>,
    val probesRan: List<DangerousDetectionMethodKind>,
    val issues: List<String> = emptyList(),
) {
    val detectedCount: Int
        get() = findings.size

    val hiddenCount: Int
        get() = hiddenFromPackageManager.size

    companion object {
        fun loading(targets: List<DangerousAppTarget>): DangerousAppsReport {
            return DangerousAppsReport(
                stage = DangerousAppsStage.LOADING,
                packageVisibility = DangerousPackageVisibility.UNKNOWN,
                packageManagerVisibleCount = 0,
                suspiciousLowPmInventory = false,
                targets = targets,
                findings = emptyList(),
                hiddenFromPackageManager = emptyList(),
                probesRan = emptyList(),
            )
        }

        fun failed(
            targets: List<DangerousAppTarget>,
            message: String,
        ): DangerousAppsReport {
            return DangerousAppsReport(
                stage = DangerousAppsStage.FAILED,
                packageVisibility = DangerousPackageVisibility.UNKNOWN,
                packageManagerVisibleCount = 0,
                suspiciousLowPmInventory = false,
                targets = targets,
                findings = emptyList(),
                hiddenFromPackageManager = emptyList(),
                probesRan = emptyList(),
                issues = listOf(message),
            )
        }
    }
}
