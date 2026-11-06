/*
 * NOIR — Android leak audit
 * Copyright (c) 2026 Verlintas
 * SPDX-License-Identifier: MIT
 */
package app.noir.android

import java.io.File
import java.util.zip.ZipFile

data class ManifestSummary(
    val exportedWithoutPermission: Int = 0,
    val cleartext: Boolean? = null,
    val allowBackup: Boolean? = null,
    val debuggable: Boolean? = null,
    val targetSdk: String? = null
)

/** Reads only the manifest facts useful to the first mobile report. */
object AndroidManifestScan {

    private val componentNames = setOf("activity", "activity-alias", "service", "receiver", "provider")

    fun analyze(apk: File): ManifestSummary? = runCatching {
        val bytes = ZipFile(apk).use { zip ->
            val entry = zip.getEntry("AndroidManifest.xml") ?: return null
            zip.getInputStream(entry).use { it.readBytes() }
        }
        val nodes = Axml.parse(bytes)
        if (nodes.isEmpty()) return null
        val application = nodes.firstOrNull { it.depth == 1 && it.name == "application" }
        val sdk = nodes.firstOrNull { it.name == "uses-sdk" }

        var exportedWithoutPermission = 0
        nodes.forEachIndexed { index, node ->
            if (node.depth != 2 || node.name !in componentNames) return@forEachIndexed
            var hasIntentFilter = false
            var cursor = index + 1
            while (cursor < nodes.size && nodes[cursor].depth > node.depth) {
                if (nodes[cursor].name == "intent-filter") {
                    hasIntentFilter = true
                    break
                }
                cursor++
            }
            val exported = when (node.attrs["exported"]) {
                "true" -> true
                "false" -> false
                else -> hasIntentFilter
            }
            if (exported && node.attrs["permission"].isNullOrBlank()) exportedWithoutPermission++
        }

        ManifestSummary(
            exportedWithoutPermission = exportedWithoutPermission,
            cleartext = application?.attrs?.get("usesCleartextTraffic").toBooleanValue(),
            allowBackup = application?.attrs?.get("allowBackup").toBooleanValue(),
            debuggable = application?.attrs?.get("debuggable").toBooleanValue(),
            targetSdk = sdk?.attrs?.get("targetSdkVersion")
        )
    }.getOrNull()

    private fun String?.toBooleanValue(): Boolean? = when (this) {
        "true" -> true
        "false" -> false
        else -> null
    }

    private object Axml {
        data class Node(val name: String, val attrs: Map<String, String?>, val depth: Int)

        fun parse(bytes: ByteArray): List<Node> {
            if (bytes.size < 8) return emptyList()
            var strings = emptyList<String>()
            val nodes = ArrayList<Node>()
            var depth = 0
            var offset = 8
            while (offset + 8 <= bytes.size) {
                val type = u16(bytes, offset)
                val headerSize = u16(bytes, offset + 2)
                val size = u32(bytes, offset + 4)
                if (size <= 0 || offset + size > bytes.size || size < 8) break
                when (type) {
                    0x0001 -> strings = stringPool(bytes, offset)
                    0x0102 -> startElement(bytes, offset, headerSize, strings, depth)?.let { nodes += it; depth++ }
                    0x0103 -> if (depth > 0) depth--
                }
                offset += size
            }
            return nodes
        }

        private fun startElement(bytes: ByteArray, offset: Int, headerSize: Int, strings: List<String>, depth: Int): Node? {
            if (offset + 36 > bytes.size) return null
            val nameIndex = u32(bytes, offset + 20)
            val attrStart = u16(bytes, offset + 24)
            val attrSize = u16(bytes, offset + 26)
            val attrCount = u16(bytes, offset + 28)
            if (attrSize < 20) return null
            val attrs = LinkedHashMap<String, String?>()
            var attr = offset + headerSize + attrStart
            repeat(attrCount) {
                if (attr + 20 > bytes.size) return@repeat
                val attrName = u32(bytes, attr + 4)
                val rawValue = u32(bytes, attr + 8)
                val dataType = bytes[attr + 15].toInt() and 0xFF
                val data = u32(bytes, attr + 16)
                val key = strings.getOrNull(attrName).orEmpty()
                if (key.isNotEmpty()) {
                    attrs[key] = when (dataType) {
                        0x03 -> strings.getOrNull(data)
                        0x12 -> if (data != 0) "true" else "false"
                        0x10, 0x11 -> data.toString()
                        else -> strings.getOrNull(rawValue)
                    }
                }
                attr += attrSize
            }
            return Node(strings.getOrNull(nameIndex).orEmpty(), attrs, depth)
        }

        private fun stringPool(bytes: ByteArray, offset: Int): List<String> {
            if (offset + 28 > bytes.size) return emptyList()
            val count = u32(bytes, offset + 8)
            val flags = u32(bytes, offset + 16)
            val stringsStart = offset + u32(bytes, offset + 20)
            if (count <= 0 || count > 1_000_000) return emptyList()
            val utf8 = flags and 0x100 != 0
            return (0 until count).map { index ->
                val entry = stringsStart + u32(bytes, offset + 28 + index * 4)
                if (utf8) readUtf8(bytes, entry) else readUtf16(bytes, entry)
            }
        }

        private fun readUtf8(bytes: ByteArray, start: Int): String {
            var p = start
            if (p + 2 > bytes.size) return ""
            var skip = bytes[p].toInt() and 0xFF
            p++
            if (skip and 0x80 != 0) {
                if (p >= bytes.size) return ""
                skip = ((skip and 0x7F) shl 8) or (bytes[p].toInt() and 0xFF)
                p++
            }
            var length = bytes[p].toInt() and 0xFF
            p++
            if (length and 0x80 != 0) {
                if (p >= bytes.size) return ""
                length = ((length and 0x7F) shl 8) or (bytes[p].toInt() and 0xFF)
                p++
            }
            return if (length >= 0 && p + length <= bytes.size) String(bytes, p, length, Charsets.UTF_8) else ""
        }

        private fun readUtf16(bytes: ByteArray, start: Int): String {
            var p = start
            if (p + 2 > bytes.size) return ""
            var length = u16(bytes, p)
            p += 2
            if (length and 0x8000 != 0) {
                if (p + 2 > bytes.size) return ""
                length = ((length and 0x7FFF) shl 16) or u16(bytes, p)
                p += 2
            }
            val size = length * 2
            return if (size >= 0 && p + size <= bytes.size) String(bytes, p, size, Charsets.UTF_16LE) else ""
        }

        private fun u16(bytes: ByteArray, offset: Int): Int =
            (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)

        private fun u32(bytes: ByteArray, offset: Int): Int =
            (bytes[offset].toInt() and 0xFF) or
                ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
                ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
                ((bytes[offset + 3].toInt() and 0xFF) shl 24)
    }
}
