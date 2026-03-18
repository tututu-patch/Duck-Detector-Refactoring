package com.eltavine.duckdetector.features.kernelcheck.data.native

class KernelCheckNativeBridge {

    fun collectSnapshot(
        systemBuildTime: Long,
    ): KernelCheckNativeSnapshot {
        return runCatching {
            parse(nativeCollectSnapshot(systemBuildTime))
        }.getOrDefault(KernelCheckNativeSnapshot())
    }

    internal fun parse(
        raw: String,
    ): KernelCheckNativeSnapshot {
        if (raw.isBlank()) {
            return KernelCheckNativeSnapshot()
        }

        val entries = raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && it.contains('=') }
            .map { it.substringBefore('=') to it.substringAfter('=') }
            .toList()

        return KernelCheckNativeSnapshot(
            available = entries.firstOrNull { it.first == "AVAILABLE" }?.second != "0",
            procVersion = entries.firstOrNull { it.first == "PROC_VERSION" }?.second?.decodeValue()
                .orEmpty(),
            procCmdline = entries.firstOrNull { it.first == "PROC_CMDLINE" }?.second?.decodeValue()
                .orEmpty(),
            suspiciousCmdline = entries.firstOrNull { it.first == "CMDLINE" }?.second == "1",
            buildTimeMismatch = entries.firstOrNull { it.first == "BUILD_TIME" }?.second == "1",
            kptrExposed = entries.firstOrNull { it.first == "KPTR" }?.second == "1",
            findings = entries.filter { it.first == "FINDING" }.map { it.second.decodeValue() },
        )
    }

    private fun String.decodeValue(): String {
        return replace("\\n", "\n")
            .replace("\\r", "\r")
    }

    private external fun nativeCollectSnapshot(systemBuildTime: Long): String

    companion object {
        init {
            runCatching { System.loadLibrary("duckdetector") }
        }
    }
}
