package com.eltavine.duckdetector.features.licenses.data

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AboutLibrariesJsonOverridesTest {
    @Test
    fun apply_rewritesSoterLicenseMetadata() {
        val input = """
            {
              "libraries": [
                {
                  "uniqueId": "com.github.Tencent.soter:soter-wrapper",
                  "name": "Tencent/soter",
                  "description": "Original",
                  "website": "https://github.com/Tencent/soter",
                  "licenses": ["other"]
                }
              ],
              "licenses": {
                "BSD-3-Clause": {
                  "name": "BSD 3-Clause"
                }
              }
            }
        """.trimIndent()

        val updated = JSONObject(AboutLibrariesJsonOverrides.apply(input))
        val library = updated.getJSONArray("libraries").getJSONObject(0)

        assertEquals("Tencent Soter", library.getString("name"))
        assertEquals(
            "https://github.com/Tencent/soter/blob/master/LICENSE",
            library.getString("website"),
        )
        assertEquals("BSD-3-Clause", library.getJSONArray("licenses").getString(0))
        assertTrue(library.getString("description").contains("BSD 3-Clause"))
    }
}
