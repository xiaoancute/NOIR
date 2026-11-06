/*
 * NOIR — Android leak audit
 * Copyright (c) 2026 Verlintas
 * SPDX-License-Identifier: MIT
 */
package app.noir.android

/** Small parser for the package and granted-permission facts emitted by dumpsys. */
data class RootPackageMeta(
    val flags: String,
    val appId: String,
    val installer: String?,
    val permissions: Set<String>,
    val sharedUser: String? = null
) {
    val isSystem: Boolean get() = flags.contains("SYSTEM")
    val debuggable: Boolean get() = flags.contains("DEBUGGABLE")
}

object RootDumpsys {

    private val packageHeader = Regex("^  Package \\[([^\\]]+)]")
    private val sharedUser = Regex("^sharedUser=SharedUserSetting\\{[0-9a-f]+ ([^/]+)/")
    private val sharedHeader = Regex("^  SharedUser \\[([^\\]]+)]")
    private val packageSetting = Regex("PackageSetting\\{[0-9a-f]+ ([^/]+)/")
    private val granted = Regex("^android\\.permission\\.([A-Z0-9_]+): granted=true(?:[,;].*)?$")

    fun parse(text: String): Map<String, RootPackageMeta> {
        val packages = LinkedHashMap<String, MutablePackage>()
        val sharedPackages = HashMap<String, MutableList<String>>()
        val sharedPermissions = HashMap<String, MutableSet<String>>()
        val sharedAppIds = HashMap<String, String>()

        var current: MutablePackage? = null
        var currentShared: String? = null
        var inSharedSection = false

        text.lineSequence().forEach { line ->
            if (line.startsWith("Shared users:")) {
                inSharedSection = true
                current = null
                currentShared = null
                return@forEach
            }

            if (!inSharedSection) {
                val header = packageHeader.find(line)
                if (header != null) {
                    current = packages.getOrPut(header.groupValues[1]) { MutablePackage() }
                    return@forEach
                }

                val entry = current ?: return@forEach
                val value = line.trim()
                when {
                    value.startsWith("appId=") && entry.appId.isEmpty() ->
                        entry.appId = value.removePrefix("appId=")
                    value.startsWith("flags=[") && entry.flags.isEmpty() -> entry.flags = value
                    value.startsWith("installerPackageName=") && entry.installer == null -> {
                        val installer = value.removePrefix("installerPackageName=")
                        entry.installer = installer.takeUnless { it == "null" }
                    }
                    value.startsWith("sharedUser=") && entry.sharedUser == null ->
                        entry.sharedUser = sharedUser.find(value)?.groupValues?.get(1)
                    else -> granted.find(value)?.let { entry.permissions += it.groupValues[1] }
                }
            } else {
                val header = sharedHeader.find(line)
                if (header != null) {
                    currentShared = header.groupValues[1]
                    sharedPackages.getOrPut(currentShared!!) { mutableListOf() }
                    sharedPermissions.getOrPut(currentShared!!) { mutableSetOf() }
                    return@forEach
                }

                val shared = currentShared ?: return@forEach
                val value = line.trim()
                if (value.startsWith("appId=")) {
                    sharedAppIds[shared] = value.removePrefix("appId=")
                } else {
                    packageSetting.find(value)?.let { sharedPackages.getValue(shared) += it.groupValues[1] }
                    granted.find(value)?.let { sharedPermissions.getValue(shared) += it.groupValues[1] }
                }
            }
        }

        sharedPackages.forEach { (shared, names) ->
            val permissions = sharedPermissions[shared].orEmpty()
            val appId = sharedAppIds[shared]
            names.forEach { pkg ->
                val entry = packages.getOrPut(pkg) { MutablePackage() }
                entry.permissions += permissions
                if (entry.appId.isEmpty() && appId != null) entry.appId = appId
                if (entry.flags.isEmpty() && appId == "1000") entry.flags = "SYSTEM"
            }
        }

        return packages.mapValues { (_, value) ->
            RootPackageMeta(
                flags = value.flags,
                appId = value.appId,
                installer = value.installer,
                permissions = value.permissions,
                sharedUser = value.sharedUser
            )
        }
    }

    private class MutablePackage {
        var flags: String = ""
        var appId: String = ""
        var installer: String? = null
        var sharedUser: String? = null
        val permissions: MutableSet<String> = HashSet()
    }
}
