/*
 * NOIR — Android leak audit
 * Copyright (c) 2026 Verlintas
 * SPDX-License-Identifier: MIT
 */
package app.noir.android

import android.content.Context
import android.os.Build
import app.noir.core.Advisor
import app.noir.core.AppEntry
import app.noir.core.Classifier
import app.noir.core.Device
import app.noir.core.Report
import app.noir.core.ReportMeta
import app.noir.core.Rules
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class AndroidScanResult(
    val apps: List<AppEntry>,
    val recommendations: List<app.noir.core.Recommendation>,
    val json: String,
    val markdown: String,
    val errors: List<String>,
    val packageCount: Int,
    val networkCount: Int
)

/** First mobile scanner: Root shell inventory plus local APK inspection. */
class AndroidScanner(
    private val context: Context,
    private val progress: (done: Int, total: Int, packageName: String) -> Unit = { _, _, _ -> }
) {

    private val shell = RootShell()
    private val workDir = File(context.cacheDir, "noir-scan")

    fun scan(): AndroidScanResult {
        val root = shell.check()
        require(root.ok && ROOT_ID.containsMatchIn(root.output)) {
            "Root access was not granted. NOIR Android requires a working su provider.\n${root.output.trim()}"
        }

        workDir.deleteRecursively()
        workDir.mkdirs()

        val packagePaths = parsePackagePaths(shell.exec("pm list packages -f").output)
        val packageMeta = RootDumpsys.parse(shell.exec("dumpsys package", timeoutSeconds = 300).output)
        val networkPackages = packageMeta
            .filter { (pkg, meta) -> "INTERNET" in meta.permissions && pkg in packagePaths }
            .toList()
            .sortedBy { it.first }

        val splitPaths = fetchSplitPaths(networkPackages.map { it.first })
        val errors = ArrayList<String>()
        val apps = ArrayList<AppEntry>(networkPackages.size)

        networkPackages.forEachIndexed { index, (pkg, meta) ->
            val apkPaths = splitPaths[pkg].orEmpty().ifEmpty { listOf(packagePaths.getValue(pkg)) }.distinct()
            val endpoints = LinkedHashSet<String>()
            var manifest: ManifestSummary? = null

            apkPaths.forEachIndexed { apkIndex, source ->
                val local = File(workDir, "${index}_$apkIndex.apk")
                val copy = copyFromDevice(source, local)
                if (!copy.ok || !local.isFile) {
                    errors += "$pkg: cannot read $source (${copy.output.trim()})"
                    return@forEachIndexed
                }
                try {
                    endpoints += AndroidApkScan.urls(local)
                    if (manifest == null) manifest = AndroidManifestScan.analyze(local)
                } catch (error: Exception) {
                    errors += "$pkg: ${error.message ?: error.javaClass.simpleName}"
                } finally {
                    local.delete()
                }
            }

            val permissions = meta.permissions.filter { it in Rules.SENSITIVE }.sorted()
            val urls = endpoints.toList().sorted()
            val system = meta.isSystem
            apps += AppEntry(
                pkg = pkg,
                uid = meta.appId,
                isSystem = system,
                debuggable = meta.debuggable,
                installer = meta.installer,
                permissions = permissions,
                endpoints = urls,
                score = Rules.score(permissions, urls, system, meta.debuggable),
                category = Classifier.category(pkg, urls, permissions, system),
                vendor = Classifier.vendor(pkg, urls),
                sharedUid = meta.sharedUser,
                exportedWithoutPermission = manifest?.exportedWithoutPermission ?: 0,
                cleartext = manifest?.cleartext,
                allowBackup = manifest?.allowBackup,
                targetSdk = manifest?.targetSdk
            )
            progress(index + 1, networkPackages.size, pkg)
        }

        val sorted = apps.sortedWith(compareByDescending<AppEntry> { it.score }.thenBy { it.pkg })
        val recommendations = Advisor.advise(sorted)
        val device = Device(
            serial = "local-root",
            state = "device",
            model = Build.MODEL ?: "Android",
            product = Build.PRODUCT ?: ""
        )
        val meta = ReportMeta(
            tool = "NOIR Android 0.1.0",
            host = "Android ${Build.VERSION.RELEASE} / ${Build.MANUFACTURER}",
            android = Build.VERSION.RELEASE ?: "unknown",
            sdk = Build.VERSION.SDK_INT.toString(),
            build = Build.DISPLAY ?: Build.ID ?: "unknown",
            fingerprint = Build.FINGERPRINT ?: "unknown",
            user = "0",
            generatedAt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date())
        )

        return AndroidScanResult(
            apps = sorted,
            recommendations = recommendations,
            json = Report.json(device, sorted, recommendations, meta),
            markdown = Report.markdown(device, sorted, recommendations, meta),
            errors = errors,
            packageCount = packageMeta.size,
            networkCount = networkPackages.size
        )
    }

    private fun parsePackagePaths(output: String): Map<String, String> = buildMap {
        output.lineSequence().forEach { line ->
            if (!line.startsWith("package:")) return@forEach
            val body = line.removePrefix("package:")
            val split = body.lastIndexOf('=')
            if (split <= 0) return@forEach
            val path = body.substring(0, split)
            val pkg = body.substring(split + 1).trim()
            if (pkg.isNotEmpty()) put(pkg, path)
        }
    }

    private fun fetchSplitPaths(packages: List<String>): Map<String, List<String>> {
        if (packages.isEmpty()) return emptyMap()
        val command = packages.joinToString("\n") { pkg ->
            "echo PKG:${RootShell.quote(pkg)}; pm path ${RootShell.quote(pkg)}"
        }
        val output = shell.exec(command, timeoutSeconds = 300).output
        val result = LinkedHashMap<String, MutableList<String>>()
        var current: String? = null
        output.lineSequence().forEach { line ->
            when {
                line.startsWith("PKG:") -> {
                    val pkg = line.removePrefix("PKG:").trim()
                    current = pkg.takeIf { PACKAGE_NAME.matches(it) }
                }
                line.startsWith("package:") && current != null ->
                    result.getOrPut(current!!) { mutableListOf() } += line.removePrefix("package:").trim()
            }
        }
        return result
    }

    private fun copyFromDevice(source: String, destination: File): ShellResult {
        val command = "cat ${RootShell.quote(source)} > ${RootShell.quote(destination.absolutePath)} && chmod 644 ${RootShell.quote(destination.absolutePath)}"
        return shell.exec(command, timeoutSeconds = 300)
    }

    companion object {
        private val ROOT_ID = Regex("uid=0(?:\\(root\\))?")
        private val PACKAGE_NAME = Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+")
    }
}
