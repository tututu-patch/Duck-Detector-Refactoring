package com.eltavine.duckdetector.features.settings.ui.model

data class SettingsUiState(
    val isCrlNetworkingEnabled: Boolean,
    val versionName: String,
    val versionCode: Int,
    val buildTimeUtc: String,
    val buildHash: String,
)
