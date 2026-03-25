package com.eltavine.duckdetector.core.ui.presentation

fun formatBuildTimeUtc(raw: String): String {
    if (raw.length != 14 || raw.any { !it.isDigit() }) {
        return raw
    }
    return buildString {
        append(raw.substring(0, 4))
        append('-')
        append(raw.substring(4, 6))
        append('-')
        append(raw.substring(6, 8))
        append(' ')
        append(raw.substring(8, 10))
        append(':')
        append(raw.substring(10, 12))
        append(':')
        append(raw.substring(12, 14))
    }
}
