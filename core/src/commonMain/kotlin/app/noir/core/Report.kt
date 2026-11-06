/*
 * NOIR — Android leak audit
 * Copyright (c) 2026 Verlintas
 * SPDX-License-Identifier: MIT
 */
package app.noir.core

/** Renders scan results as portable JSON and human-readable Markdown. */
object Report {

    fun json(
        device: Device,
        apps: List<AppEntry>,
        recommendations: List<Recommendation> = emptyList(),
        meta: ReportMeta = ReportMeta()
    ): String {
        val sb = StringBuilder()
        sb.append("{\n")
        sb.append("  \"environment\": {\n")
        sb.append("    \"tool\": \"").append(esc(meta.tool)).append("\",\n")
        sb.append("    \"host\": \"").append(esc(meta.host)).append("\",\n")
        sb.append("    \"android\": \"").append(esc(meta.android)).append("\",\n")
        sb.append("    \"sdk\": \"").append(esc(meta.sdk)).append("\",\n")
        sb.append("    \"build\": \"").append(esc(meta.build)).append("\",\n")
        sb.append("    \"fingerprint\": \"").append(esc(meta.fingerprint)).append("\",\n")
        sb.append("    \"user\": \"").append(esc(meta.user)).append("\",\n")
        sb.append("    \"generatedAt\": \"").append(esc(meta.generatedAt)).append("\"\n")
        sb.append("  },\n")
        sb.append("  \"device\": {\"serial\": \"").append(esc(device.serial))
            .append("\", \"model\": \"").append(esc(device.model)).append("\"},\n")
        sb.append("  \"apps\": [\n")
        apps.forEachIndexed { i, a ->
            sb.append("    {\n")
            sb.append("      \"package\": \"").append(esc(a.pkg)).append("\",\n")
            sb.append("      \"uid\": \"").append(esc(a.uid)).append("\",\n")
            sb.append("      \"system\": ").append(a.isSystem).append(",\n")
            sb.append("      \"debuggable\": ").append(a.debuggable).append(",\n")
            sb.append("      \"installer\": ").append(a.installer?.let { "\"${esc(it)}\"" } ?: "null").append(",\n")
            sb.append("      \"category\": \"").append(esc(a.category.label)).append("\",\n")
            sb.append("      \"vendor\": ").append(a.vendor?.let { "\"${esc(it)}\"" } ?: "null").append(",\n")
            sb.append("      \"sharedUid\": ").append(a.sharedUid?.let { "\"${esc(it)}\"" } ?: "null").append(",\n")
            sb.append("      \"exportedWithoutPermission\": ").append(a.exportedWithoutPermission).append(",\n")
            sb.append("      \"cleartext\": ").append(a.cleartext?.toString() ?: "null").append(",\n")
            sb.append("      \"allowBackup\": ").append(a.allowBackup?.toString() ?: "null").append(",\n")
            sb.append("      \"targetSdk\": ").append(a.targetSdk?.let { "\"${esc(it)}\"" } ?: "null").append(",\n")
            sb.append("      \"dataTypes\": ").append(array(a.dataTypes.map { it.label })).append(",\n")
            sb.append("      \"leaks\": ").append(leaksJson(a)).append(",\n")
            sb.append("      \"score\": ").append(a.score).append(",\n")
            sb.append("      \"permissions\": ").append(array(a.permissions)).append(",\n")
            sb.append("      \"endpoints\": ").append(array(a.endpoints)).append("\n")
            sb.append("    }").append(if (i == apps.lastIndex) "" else ",").append("\n")
        }
        sb.append("  ],\n")
        sb.append("  \"recommendations\": [\n")
        recommendations.forEachIndexed { i, r ->
            sb.append("    {\n")
            sb.append("      \"package\": \"").append(esc(r.pkg)).append("\",\n")
            sb.append("      \"action\": \"").append(esc(r.action.label)).append("\",\n")
            sb.append("      \"risk\": \"").append(esc(r.risk)).append("\",\n")
            sb.append("      \"reason\": \"").append(esc(r.reason)).append("\",\n")
            sb.append("      \"autoSafe\": ").append(r.autoSafe).append("\n")
            sb.append("    }").append(if (i == recommendations.lastIndex) "" else ",").append("\n")
        }
        sb.append("  ]\n}\n")
        return sb.toString()
    }

    fun markdown(
        device: Device,
        apps: List<AppEntry>,
        recommendations: List<Recommendation> = emptyList(),
        meta: ReportMeta = ReportMeta()
    ): String {
        val sb = StringBuilder()
        sb.append("# NOIR report\n\n")
        sb.append("- tool: ").append(meta.tool).append("\n")
        sb.append("- host: ").append(meta.host).append("\n")
        sb.append("- device: `").append(device.model).append("` (`").append(device.serial).append("`)\n")
        sb.append("- android: ").append(meta.android).append(" (SDK ").append(meta.sdk).append(")\n")
        sb.append("- build: ").append(meta.build).append("\n")
        sb.append("- fingerprint: ").append(meta.fingerprint).append("\n")
        sb.append("- user: ").append(meta.user).append("\n")
        sb.append("- generated: ").append(meta.generatedAt).append("\n")
        sb.append("- apps flagged: ").append(apps.size).append("\n")
        sb.append("- recommendations: ").append(recommendations.size).append("\n\n")

        sb.append("## Overview\n\n")
        sb.append("| score | package | category | vendor | system | perms | upload | cmd |\n")
        sb.append("|---:|---|---|---|:---:|---:|---:|---:|\n")
        apps.forEach { a ->
            sb.append("| ").append(a.score)
                .append(" | `").append(a.pkg).append("`")
                .append(" | ").append(a.category.label)
                .append(" | ").append(a.vendor ?: "—")
                .append(" | ").append(if (a.isSystem) "yes" else "no")
                .append(" | ").append(a.permissions.size)
                .append(" | ").append(a.uploadEndpoints.size)
                .append(" | ").append(a.commandEndpoints.size)
                .append(" |\n")
        }

        if (recommendations.isNotEmpty()) {
            sb.append("\n## Recommended actions\n\n")
            sb.append("| risk | action | package | why |\n")
            sb.append("|:---:|---|---|---|\n")
            recommendations.forEach { r ->
                sb.append("| ").append(r.risk)
                    .append(" | ").append(r.action.label)
                    .append(" | `").append(r.pkg).append("`")
                    .append(" | ").append(r.reason)
                    .append(" |\n")
            }
        }

        val sharedGroups = apps.filter { it.sharedUid != null }
            .groupBy { it.sharedUid!! }
            .filterValues { it.size > 1 }
        if (sharedGroups.isNotEmpty()) {
            sb.append("\n## Shared UIDs\n\n")
            sb.append("Packages below share one Linux uid, so they effectively hold the *union* of\n")
            sb.append("their permissions. A privileged component can borrow another's grants.\n\n")
            sharedGroups.toList().sortedByDescending { it.second.size }.forEach { (uid, group) ->
                sb.append("- **").append(uid).append("** — ").append(group.size).append(" packages: ")
                sb.append(group.joinToString(", ") { "`${it.pkg}`" }).append("\n")
            }
        }

        sb.append("\n## Details\n")
        apps.forEach { a ->
            sb.append("\n### ").append(a.pkg).append("  (").append(a.score).append(")\n\n")
            sb.append("- uid: ").append(a.uid)
            sb.append(" · system: ").append(a.isSystem)
            sb.append(" · debuggable: ").append(a.debuggable)
            sb.append(" · installer: ").append(a.installer ?: "unknown")
            sb.append(" · category: ").append(a.category.label)
            sb.append(" · vendor: ").append(a.vendor ?: "unknown")
            sb.append(" · shared uid: ").append(a.sharedUid ?: "—").append("\n")
            sb.append("- manifest: exported without permission=").append(a.exportedWithoutPermission)
                .append(" · cleartext=").append(a.cleartext ?: "unknown")
                .append(" · backup=").append(a.allowBackup ?: "unknown")
                .append(" · targetSdk=").append(a.targetSdk ?: "unknown").append("\n")
            if (a.dataTypes.isNotEmpty()) {
                sb.append("- data: ").append(a.dataTypes.joinToString(", ") { it.label }).append("\n")
            }
            if (a.leaks.isNotEmpty()) {
                sb.append("- leak paths:\n")
                a.leaks.forEach { (data, hosts) ->
                    sb.append("  - ").append(data.label).append(" → ").append(hosts.joinToString(", ")).append("\n")
                }
            }
            if (a.permissions.isNotEmpty()) {
                sb.append("- permissions: ").append(a.permissions.joinToString(", ")).append("\n")
            }
            if (a.endpoints.isNotEmpty()) {
                sb.append("- endpoints:\n")
                a.endpoints.take(25).forEach { sb.append("  - `").append(it).append("`\n") }
            }
        }
        return sb.toString()
    }

    private fun leaksJson(app: AppEntry): String {
        if (app.leaks.isEmpty()) return "{}"
        return app.leaks.entries.joinToString(prefix = "{", postfix = "}") { (data, hosts) ->
            "\"${esc(data.label)}\":" + array(hosts)
        }
    }

    private fun array(items: List<String>): String =
        items.joinToString(prefix = "[", postfix = "]") { "\"${esc(it)}\"" }

    private fun esc(s: String): String {
        val sb = StringBuilder(s.length + 8)
        for (c in s) {
            when (c) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (c < ' ') sb.append("\\u").append(c.code.toString(16).padStart(4, '0')) else sb.append(c)
            }
        }
        return sb.toString()
    }
}
