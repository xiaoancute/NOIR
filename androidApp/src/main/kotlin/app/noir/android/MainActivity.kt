/*
 * NOIR — Android leak audit
 * Copyright (c) 2026 Verlintas
 * SPDX-License-Identifier: MIT
 */
package app.noir.android

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import java.io.OutputStreamWriter

class MainActivity : Activity() {

    private lateinit var rootState: TextView
    private lateinit var status: TextView
    private lateinit var progress: ProgressBar
    private lateinit var output: TextView
    private lateinit var scanButton: Button
    private lateinit var exportButton: Button

    private var latest: AndroidScanResult? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildView())
        checkRoot()
    }

    private fun buildView(): View {
        val density = resources.displayMetrics.density
        fun dp(value: Int): Int = (value * density).toInt()

        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(18), dp(18), dp(18))
            setBackgroundColor(Color.rgb(8, 8, 10))
        }

        val title = TextView(this).apply {
            text = "NOIR  /  ROOT STATIC AUDIT"
            textSize = 20f
            setTextColor(Color.rgb(34, 211, 238))
            typeface = android.graphics.Typeface.MONOSPACE
        }
        page.addView(title, LinearLayout.LayoutParams(-1, -2))

        rootState = TextView(this).apply {
            text = "root: checking..."
            textSize = 13f
            setTextColor(Color.LTGRAY)
            typeface = android.graphics.Typeface.MONOSPACE
            setPadding(0, dp(8), 0, dp(4))
        }
        page.addView(rootState, LinearLayout.LayoutParams(-1, -2))

        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        scanButton = Button(this).apply {
            text = "SCAN DEVICE"
            setOnClickListener { startScan() }
        }
        exportButton = Button(this).apply {
            text = "EXPORT JSON"
            isEnabled = false
            setOnClickListener { exportJson() }
        }
        actions.addView(scanButton, LinearLayout.LayoutParams(0, -2, 1f))
        actions.addView(exportButton, LinearLayout.LayoutParams(0, -2, 1f).apply {
            leftMargin = dp(8)
        })
        page.addView(actions, LinearLayout.LayoutParams(-1, -2))

        progress = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = 100
            visibility = View.GONE
        }
        page.addView(progress, LinearLayout.LayoutParams(-1, dp(4)).apply {
            topMargin = dp(10)
        })

        status = TextView(this).apply {
            text = "ready"
            textSize = 12f
            setTextColor(Color.GRAY)
            typeface = android.graphics.Typeface.MONOSPACE
            setPadding(0, dp(8), 0, dp(8))
        }
        page.addView(status, LinearLayout.LayoutParams(-1, -2))

        output = TextView(this).apply {
            text = "Root is required. NOIR reads installed APKs locally and does not upload scan results."
            textSize = 12f
            setTextColor(Color.rgb(220, 220, 225))
            typeface = android.graphics.Typeface.MONOSPACE
            setTextIsSelectable(true)
            setPadding(dp(12), dp(12), dp(12), dp(12))
        }
        val scroll = ScrollView(this).apply {
            isFillViewport = true
            addView(output, ScrollView.LayoutParams(-1, -2))
        }
        page.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        return page
    }

    private fun checkRoot() {
        Thread {
            val result = RootShell().check()
            runOnUiThread {
                if (result.ok && result.output.contains("uid=0")) {
                    rootState.text = "root: granted"
                    rootState.setTextColor(Color.rgb(52, 211, 153))
                    status.text = "ready to scan all packages with INTERNET"
                } else {
                    rootState.text = "root: unavailable"
                    rootState.setTextColor(Color.rgb(248, 113, 113))
                    status.text = "grant NOIR root access in Magisk / KernelSU and retry"
                }
            }
        }.start()
    }

    private fun startScan() {
        scanButton.isEnabled = false
        exportButton.isEnabled = false
        progress.visibility = View.VISIBLE
        progress.progress = 0
        status.text = "starting root scan..."
        output.text = "Reading dumpsys package and APK paths..."

        Thread {
            try {
                val result = AndroidScanner(this) { done, total, pkg ->
                    runOnUiThread {
                        progress.max = total.coerceAtLeast(1)
                        progress.progress = done
                        status.text = "scanning $done/$total  $pkg"
                    }
                }.scan()
                latest = result
                runOnUiThread {
                    progress.visibility = View.GONE
                    scanButton.isEnabled = true
                    exportButton.isEnabled = true
                    status.text = "scan complete: ${result.networkCount} network apps"
                    output.text = render(result)
                }
            } catch (error: Exception) {
                runOnUiThread {
                    progress.visibility = View.GONE
                    scanButton.isEnabled = true
                    status.text = "scan failed"
                    output.text = error.message ?: error.javaClass.simpleName
                }
            }
        }.start()
    }

    private fun render(result: AndroidScanResult): String = buildString {
        appendLine("NOIR Android 0.1.0")
        appendLine("packages: ${result.packageCount}  network: ${result.networkCount}  findings: ${result.apps.count { it.score > 0 }}")
        appendLine("recommendations: ${result.recommendations.size}")
        appendLine()
        appendLine("TOP FINDINGS")
        appendLine("────────────────────────────────────────────────────────")

        result.apps.asSequence()
            .filter { it.score > 0 || it.endpoints.isNotEmpty() }
            .take(60)
            .forEachIndexed { index, app ->
                appendLine("${(index + 1).toString().padStart(2)}  ${app.score.toString().padStart(2)}  ${app.pkg}")
                appendLine("    ${app.category.label}  ${app.vendor ?: "unknown"}  uid=${app.uid}")
                if (app.permissions.isNotEmpty()) appendLine("    permissions: ${app.permissions.joinToString(", ")}")
                if (app.endpoints.isNotEmpty()) appendLine("    endpoints: ${app.endpoints.take(8).joinToString(", ")}")
                if (app.exportedWithoutPermission > 0 || app.cleartext == true) {
                    appendLine("    manifest: exported-without-permission=${app.exportedWithoutPermission} cleartext=${app.cleartext}")
                }
                appendLine()
            }

        if (result.errors.isNotEmpty()) {
            appendLine("ERRORS (${result.errors.size})")
            result.errors.take(30).forEach { appendLine("- $it") }
        }
        appendLine()
        appendLine("Full report is available through EXPORT JSON.")
    }

    private fun exportJson() {
        if (latest == null) return
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/json"
            putExtra(Intent.EXTRA_TITLE, "noir-report.json")
        }
        startActivityForResult(intent, EXPORT_JSON)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != EXPORT_JSON || resultCode != RESULT_OK || data?.data == null) return
        val report = latest ?: return
        contentResolver.openOutputStream(data.data!!)?.use { stream ->
            OutputStreamWriter(stream, Charsets.UTF_8).use { it.write(report.json) }
        }
        status.text = "JSON report exported"
    }

    companion object {
        private const val EXPORT_JSON = 41
    }
}
