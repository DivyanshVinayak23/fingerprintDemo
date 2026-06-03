package com.example.fingerprintdemo

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

/**
 * Detects approximate last factory reset time using multiple artifact sources.
 *
 * Sources (in order of reliability/priority):
 * 1. /data/misc/bootstat/factory_reset          — file mtime (Android 11+, needs full FS)
 * 2. SystemProperties: ro.build.date.utc        — via getprop, no root needed
 * 3. suggestions.xml                            — Pixel/AOSP devices (needs full FS)
 * 4. setup_wizard_info.xml                      — Android 11+, Pixel (needs full FS)
 * 5. /efs/recovery/history                      — Samsung only (needs full FS)
 *
 * Note: Most sources require a full filesystem extraction or root access.
 * The getprop-based approach (source 2) is the only one accessible at runtime
 * without root. The rest are included for forensic/offline analysis scenarios.
 */
object FactoryResetDetector {

    private const val TAG = "FactoryResetDetector"

    data class FactoryResetResult(
        val estimatedResetTime: Long?,        // Unix epoch millis, null if not found
        val source: String,                   // Which artifact provided the result
        val confidence: Confidence,
        val allResults: List<ResetCandidate>  // All detected candidates for corroboration
    )

    data class ResetCandidate(
        val timestampMillis: Long,
        val source: String,
        val confidence: Confidence,
        val notes: String = ""
    )

    enum class Confidence { HIGH, MEDIUM, LOW }

    // -------------------------------------------------------------------------
    // Main entry point
    // -------------------------------------------------------------------------

    @JvmStatic
    fun detect(context: Context): FactoryResetResult {
        val candidates = mutableListOf<ResetCandidate>()

        tryBootstatFactoryReset()?.let { candidates.add(it) }
        tryGetpropFactoryReset()?.let  { candidates.add(it) }
        trySuggestionsXml(context)?.let { candidates.add(it) }
        trySetupWizardInfoXml(context)?.let { candidates.add(it) }
        trySamsungRecoveryHistory()?.let { candidates.add(it) }

        if (candidates.isEmpty()) {
            return FactoryResetResult(
                estimatedResetTime = null,
                source = "none",
                confidence = Confidence.LOW,
                allResults = emptyList()
            )
        }

        // Sort by confidence priority then pick the best
        val best = candidates.sortedWith(
            compareBy({ confidenceRank(it.confidence) }, { it.timestampMillis })
        ).first()

        return FactoryResetResult(
            estimatedResetTime = best.timestampMillis,
            source = best.source,
            confidence = best.confidence,
            allResults = candidates.sortedByDescending { it.timestampMillis }
        )
    }

    // -------------------------------------------------------------------------
    // Source 1: /data/misc/bootstat/factory_reset  (Android 11+)
    // The file is empty but its last-modified time reflects the wipe time.
    // Available in full filesystem extraction; persistent across reboots.
    // -------------------------------------------------------------------------

    private fun tryBootstatFactoryReset(): ResetCandidate? {
        return try {
            val file = File("/data/misc/bootstat/factory_reset")
            if (!file.exists()) return null

            val mtime = file.lastModified()
            if (mtime == 0L) return null

            Log.d(TAG, "bootstat/factory_reset mtime: $mtime")
            ResetCandidate(
                timestampMillis = mtime,
                source = "bootstat/factory_reset",
                confidence = Confidence.HIGH,
                notes = "File mtime from /data/misc/bootstat/factory_reset (Android 11+)"
            )
        } catch (e: Exception) {
            Log.w(TAG, "bootstat check failed: ${e.message}")
            null
        }
    }

    // -------------------------------------------------------------------------
    // Source 2: SystemProperties — ro.boottime.factory_reset
    // Accessible via reflection without root. Returns Unix epoch seconds.
    // May roll off after 3+ reboots on Pixel (more on Samsung).
    // -------------------------------------------------------------------------

    private fun tryGetpropFactoryReset(): ResetCandidate? {
        return try {
            // ro.boottime.factory_reset is set from persistent_properties
            val value = getSystemProperty("ro.boottime.factory_reset")
                        ?: getSystemProperty("persist.sys.factory_reset_time")

            if (value.isNullOrBlank() || value == "0") return null

            // Value is nanoseconds since boot for ro.boottime.*, convert carefully
            // For the factory_reset variant it's stored as Unix epoch seconds
            val epochSeconds = value.toLongOrNull() ?: return null
            val millis = if (epochSeconds > 1_000_000_000_000L) {
                epochSeconds / 1_000_000  // nanoseconds → millis
            } else {
                epochSeconds * 1000L       // seconds → millis
            }

            Log.d(TAG, "getprop factory_reset: $millis")
            ResetCandidate(
                timestampMillis = millis,
                source = "getprop:ro.boottime.factory_reset",
                confidence = Confidence.MEDIUM,
                notes = "May roll off after 3+ reboots"
            )
        } catch (e: Exception) {
            Log.w(TAG, "getprop check failed: ${e.message}")
            null
        }
    }

    // -------------------------------------------------------------------------
    // Source 3: suggestions.xml — DEFERRED_SETUP_setup_time
    // Location: /data/data/com.google.android.settings.intelligence/shared_prefs/
    // Android 10 & 11, Pixel/AOSP only (not Samsung). Needs full FS access.
    // -------------------------------------------------------------------------

    private fun trySuggestionsXml(context: Context): ResetCandidate? {
        val paths = listOf(
            "/data/data/com.google.android.settings.intelligence/shared_prefs/suggestions.xml",
            "/data/user/0/com.google.android.settings.intelligence/shared_prefs/suggestions.xml"
        )

        for (path in paths) {
            try {
                val file = File(path)
                if (!file.exists()) continue

                val content = file.readText()

                // Extract DEFERRED_SETUP_setup_time value
                val deferredRegex = Regex(
                    """name="com\.android\.settings\.suggested\.category\.DEFERRED_SETUP_setup_time"\s+value="(\d+)""""
                )
                val fingerprintRegex = Regex(
                    """name="com\.android\.settings/com\.android\.settings\.biometrics\.fingerprint\.FingerprintEnrollSuggestionActivity_setup_time"\s+value="(\d+)""""
                )

                val match = deferredRegex.find(content) ?: fingerprintRegex.find(content)
                val ts = match?.groupValues?.get(1)?.toLongOrNull() ?: continue

                Log.d(TAG, "suggestions.xml setup_time: $ts")
                return ResetCandidate(
                    timestampMillis = ts,
                    source = "suggestions.xml",
                    confidence = Confidence.HIGH,
                    notes = "DEFERRED_SETUP_setup_time from Google Settings Intelligence"
                )
            } catch (e: Exception) {
                Log.w(TAG, "suggestions.xml check failed at $path: ${e.message}")
            }
        }
        return null
    }

    // -------------------------------------------------------------------------
    // Source 4: setup_wizard_info.xml — suw_finished_time_ms
    // Same directory as suggestions.xml. Android 11+ only, Pixel/AOSP.
    // Needs full FS access.
    // -------------------------------------------------------------------------

    private fun trySetupWizardInfoXml(context: Context): ResetCandidate? {
        val paths = listOf(
            "/data/data/com.google.android.settings.intelligence/shared_prefs/setup_wizard_info.xml",
            "/data/user/0/com.google.android.settings.intelligence/shared_prefs/setup_wizard_info.xml"
        )

        for (path in paths) {
            try {
                val file = File(path)
                if (!file.exists()) continue

                val content = file.readText()
                val regex = Regex("""name="suw_finished_time_ms"\s+value="(\d+)"""")
                val ts = regex.find(content)?.groupValues?.get(1)?.toLongOrNull() ?: continue

                Log.d(TAG, "setup_wizard_info.xml suw_finished_time_ms: $ts")
                return ResetCandidate(
                    timestampMillis = ts,
                    source = "setup_wizard_info.xml",
                    confidence = Confidence.HIGH,
                    notes = "suw_finished_time_ms — Android 11+, Pixel/AOSP only"
                )
            } catch (e: Exception) {
                Log.w(TAG, "setup_wizard_info.xml check failed: ${e.message}")
            }
        }
        return null
    }

    // -------------------------------------------------------------------------
    // Source 5: /efs/recovery/history — Samsung exclusive
    // Contains a full wipe history persistent across OS upgrades.
    // Format: lines containing "--wipe_data" with a preceding timestamp line.
    // -------------------------------------------------------------------------

    private fun trySamsungRecoveryHistory(): ResetCandidate? {
        return try {
            val file = File("/efs/recovery/history")
            if (!file.exists()) return null

            val lines = file.readLines()
            val timestamps = mutableListOf<Long>()

            // Lines before "--wipe_data" contain a date in format: "YYYY/MM/DD HH:MM:SS"
            val dateFormat = SimpleDateFormat("yyyy/MM/dd HH:mm:ss", Locale.US).apply {
                timeZone = TimeZone.getTimeZone("UTC")
            }

            lines.forEachIndexed { index, line ->
                if (line.contains("--wipe_data") && index > 0) {
                    // The timestamp line is a few lines before; scan back
                    for (offset in 1..3) {
                        val candidate = lines.getOrNull(index - offset) ?: continue
                        try {
                            val ts = dateFormat.parse(candidate.trim())?.time
                            if (ts != null) {
                                timestamps.add(ts)
                                return@forEachIndexed
                            }
                        } catch (_: Exception) {}
                    }
                }
            }

            if (timestamps.isEmpty()) return null

            val latest = timestamps.maxOrNull() ?: return null
            Log.d(TAG, "Samsung recovery/history latest wipe: $latest")
            ResetCandidate(
                timestampMillis = latest,
                source = "Samsung:/efs/recovery/history",
                confidence = Confidence.HIGH,
                notes = "Samsung exclusive. History persists across Android upgrades. Found ${timestamps.size} wipe event(s)."
            )
        } catch (e: Exception) {
            Log.w(TAG, "Samsung recovery/history check failed: ${e.message}")
            null
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun getSystemProperty(key: String): String? {
        return try {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            (method.invoke(null, key) as? String)?.takeIf { it.isNotBlank() }
        } catch (e: Exception) {
            null
        }
    }

    private fun confidenceRank(c: Confidence): Int = when (c) {
        Confidence.HIGH   -> 0
        Confidence.MEDIUM -> 1
        Confidence.LOW    -> 2
    }

    // -------------------------------------------------------------------------
    // Convenience: formatted summary string for logging / fingerprint output
    // -------------------------------------------------------------------------

    fun summary(context: Context): String {
        val result = detect(context)
        val sb = StringBuilder()
        sb.appendLine("=== Factory Reset Detection ===")

        if (result.estimatedResetTime == null) {
            sb.appendLine("No factory reset time detected.")
        } else {
            val date = Date(result.estimatedResetTime)
            sb.appendLine("Best estimate : $date")
            sb.appendLine("Source        : ${result.source}")
            sb.appendLine("Confidence    : ${result.confidence}")
        }

        if (result.allResults.size > 1) {
            sb.appendLine("\nAll candidates:")
            result.allResults.forEach {
                sb.appendLine("  [${it.confidence}] ${Date(it.timestampMillis)} — ${it.source}")
                if (it.notes.isNotBlank()) sb.appendLine("         ${it.notes}")
            }
        }
        return sb.toString()
    }
}
