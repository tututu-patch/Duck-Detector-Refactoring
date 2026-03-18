package com.eltavine.duckdetector.features.kernelcheck.data.native

data class KernelCheckNativeSnapshot(
    val available: Boolean = false,
    val procVersion: String = "",
    val procCmdline: String = "",
    val suspiciousCmdline: Boolean = false,
    val buildTimeMismatch: Boolean = false,
    val kptrExposed: Boolean = false,
    val findings: List<String> = emptyList(),
)
