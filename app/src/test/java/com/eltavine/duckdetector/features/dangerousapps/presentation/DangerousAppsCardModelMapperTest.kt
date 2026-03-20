package com.eltavine.duckdetector.features.dangerousapps.presentation

import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.features.dangerousapps.data.rules.DangerousAppsCatalog
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsReport
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsStage
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DangerousAppsCardModelMapperTest {

    private val mapper = DangerousAppsCardModelMapper()

    @Test
    fun `suspiciously low pm inventory becomes warning and mentions hma whitelist`() {
        val model = mapper.map(
            DangerousAppsReport(
                stage = DangerousAppsStage.READY,
                packageVisibility = DangerousPackageVisibility.FULL,
                packageManagerVisibleCount = 43,
                suspiciousLowPmInventory = true,
                targets = DangerousAppsCatalog.targets,
                findings = emptyList(),
                hiddenFromPackageManager = emptyList(),
                probesRan = emptyList(),
                issues = listOf(
                    "PackageManager returned only 43 visible packages despite a full inventory result. This can happen under HMA-style whitelist filtering.",
                ),
            ),
        )

        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertEquals("Package inventory unusually small", model.verdict)
        assertTrue(model.summary.contains("HMA-style whitelist filtering"))
        assertTrue(model.subtitle.contains("43 visible"))
        assertTrue(
            model.headerFacts.any { fact ->
                fact.label == "PM" &&
                        fact.status.severity == DetectionSeverity.WARNING &&
                        fact.value.contains("43")
            },
        )
    }
}
