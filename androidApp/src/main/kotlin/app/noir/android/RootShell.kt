/*
 * NOIR — Android leak audit
 * Copyright (c) 2026 Verlintas
 * SPDX-License-Identifier: MIT
 */
package app.noir.android

import java.util.concurrent.TimeUnit

data class ShellResult(val exitCode: Int, val output: String) {
    val ok: Boolean get() = exitCode == 0
}

/** Runs commands through the device's Root manager instead of a host adb binary. */
class RootShell {

    fun check(): ShellResult = exec("id")

    fun exec(command: String, timeoutSeconds: Long = 180): ShellResult {
        val process = try {
            ProcessBuilder("su", "-c", command)
                .redirectErrorStream(true)
                .start()
        } catch (error: Exception) {
            return ShellResult(-1, error.message ?: error.javaClass.simpleName)
        }

        val output = process.inputStream.bufferedReader().use { it.readText() }
        val finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForcibly()
            return ShellResult(-1, "$output\ncommand timed out")
        }
        return ShellResult(process.exitValue(), output)
    }

    companion object {
        /** Single-quote a value before embedding it in the root shell command. */
        fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
    }
}
