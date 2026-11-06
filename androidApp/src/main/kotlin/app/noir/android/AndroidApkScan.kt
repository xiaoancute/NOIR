/*
 * NOIR — Android leak audit
 * Copyright (c) 2026 Verlintas
 * SPDX-License-Identifier: MIT
 */
package app.noir.android

import java.io.File
import java.util.zip.ZipFile

/** APK reader used after RootShell copies a protected device APK into app storage. */
object AndroidApkScan {

    private val url = Regex("https?://[A-Za-z0-9._~:/?#@!&()*+,;=%-]{4,300}")

    fun urls(apk: File, limit: Int = 300): List<String> {
        val found = LinkedHashSet<String>()
        ZipFile(apk).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements() && found.size < limit) {
                val entry = entries.nextElement()
                if (!entry.name.matches(Regex("classes[0-9]*\\.dex"))) continue
                if (entry.size <= 0 || entry.size > 96L * 1024 * 1024) continue
                zip.getInputStream(entry).use { scan(it.readBytes(), found, limit) }
            }
        }
        return found.toList()
    }

    private fun scan(bytes: ByteArray, found: MutableSet<String>, limit: Int) {
        var index = 0
        while (index < bytes.size - 8 && found.size < limit) {
            if (bytes[index] != 'h'.code.toByte()) {
                index++
                continue
            }

            var end = index
            while (end < bytes.size && end - index < 320) {
                val value = bytes[end].toInt() and 0xFF
                if (value <= 32 || value >= 127) break
                end++
            }
            if (end - index > 8) {
                val text = String(bytes, index, end - index, Charsets.US_ASCII)
                url.findAll(text).forEach { found += it.value }
            }
            index = if (end > index) end else index + 1
        }
    }
}
