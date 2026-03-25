package com.eltavine.duckdetector.features.dangerousapps.data.probes

import java.io.File

data class OpenApkFdPackageProbeResult(
    val matchedPathsByPackage: Map<String, List<String>>,
    val available: Boolean,
) {
    val detectedPackages: Set<String>
        get() = matchedPathsByPackage.keys
}

class OpenApkFdPackageProbe(
    private val procFdPath: String = PROC_FD_PATH,
) {

    fun run(
        targetPackages: Set<String>,
    ): OpenApkFdPackageProbeResult {
        return evaluate(
            fdTargets = readFdTargets(procFdPath),
            targetPackages = targetPackages,
        )
    }

    internal fun evaluate(
        fdTargets: List<String>?,
        targetPackages: Set<String>,
    ): OpenApkFdPackageProbeResult {
        if (fdTargets == null) {
            return OpenApkFdPackageProbeResult(
                matchedPathsByPackage = emptyMap(),
                available = false,
            )
        }

        val targetsByLower = targetPackages.associateBy { it.lowercase() }
        val matchedPaths = linkedMapOf<String, LinkedHashSet<String>>()

        fdTargets
            .asSequence()
            .map { it.trim().replace('\\', '/') }
            .filter { it.isNotEmpty() }
            .filter(::looksLikeApkPath)
            .forEach { target ->
                val parentDirectory = target.parentDirectoryName() ?: return@forEach
                targetsByLower.forEach { (packageLower, packageName) ->
                    if (!matchesPackageDirectory(parentDirectory, packageLower)) {
                        return@forEach
                    }
                    matchedPaths.getOrPut(packageName) { linkedSetOf() }.add(target)
                }
            }

        return OpenApkFdPackageProbeResult(
            matchedPathsByPackage = matchedPaths.mapValues { (_, paths) -> paths.toList() },
            available = true,
        )
    }

    private fun readFdTargets(
        directoryPath: String,
    ): List<String>? {
        val directory = File(directoryPath)
        if (!directory.exists() || !directory.isDirectory) {
            return null
        }

        return runCatching {
            directory.listFiles()
                ?.mapNotNull { file ->
                    runCatching { file.canonicalPath }.getOrNull()
                }
                .orEmpty()
        }.getOrNull()
    }

    private fun looksLikeApkPath(
        path: String,
    ): Boolean = path.lowercase().endsWith(".apk")

    private fun matchesPackageDirectory(
        parentDirectory: String,
        packageLower: String,
    ): Boolean {
        val lowerParent = parentDirectory.lowercase()
        return lowerParent == packageLower ||
                lowerParent.startsWith("$packageLower-") ||
                lowerParent.startsWith("$packageLower==")
    }

    private fun String.parentDirectoryName(): String? {
        val lastSlash = lastIndexOf('/')
        if (lastSlash <= 0) {
            return null
        }
        val parentPath = substring(0, lastSlash)
        val parentSlash = parentPath.lastIndexOf('/')
        return if (parentSlash >= 0) {
            parentPath.substring(parentSlash + 1)
        } else {
            parentPath
        }.takeIf { it.isNotBlank() }
    }

    private companion object {
        private const val PROC_FD_PATH = "/proc/self/fd"
    }
}
