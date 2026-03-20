package com.eltavine.duckdetector.features.licenses.data

import org.json.JSONArray
import org.json.JSONObject

object AboutLibrariesJsonOverrides {
    private const val SOTER_UNIQUE_ID = "com.github.Tencent.soter:soter-wrapper"
    private const val SOTER_LICENSE_PAGE =
        "https://github.com/Tencent/soter/blob/master/LICENSE"
    private const val SOTER_LICENSE_ID = "BSD-3-Clause"

    fun apply(rawJson: String): String {
        val root = runCatching { JSONObject(rawJson) }.getOrElse { return rawJson }
        val libraries = root.optJSONArray("libraries") ?: return rawJson
        var mutated = false

        for (index in 0 until libraries.length()) {
            val library = libraries.optJSONObject(index) ?: continue
            if (library.optString("uniqueId") != SOTER_UNIQUE_ID) {
                continue
            }

            library.put("name", "Tencent Soter")
            library.put(
                "description",
                "Upstream LICENSE states Tencent Soter source and binary releases are under the BSD 3-Clause License.",
            )
            library.put("website", SOTER_LICENSE_PAGE)
            library.put("licenses", JSONArray().put(SOTER_LICENSE_ID))
            mutated = true
        }

        return if (mutated) root.toString() else rawJson
    }
}
