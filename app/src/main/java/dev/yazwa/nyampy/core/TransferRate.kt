package dev.yazwa.nyampy.core

import java.util.Locale
import kotlin.math.ceil

/**
 * A byte rate the way the stats screen writes it: 730 B/s, 12.4 KB/s, 3.1 MB/s. SI
 * units on purpose - the app counts the same way everywhere - and the decimal
 * separator follows the locale, so Russian reads 12,4 MB/s.
 */
internal fun formatRate(bytesPerSecond: Long): String = formatBytes(bytesPerSecond) + "/s"

private fun formatBytes(bytes: Long): String {
    val value = bytes.toDouble()
    return when {
        bytes >= 999_999_999 -> trimDecimal(value / 1e9) + " GB"
        bytes >= 999_999 -> trimDecimal(value / 1e6) + " MB"
        bytes >= 999 -> trimDecimal(value / 1e3) + " KB"
        else -> "$bytes B"
    }
}

/** One decimal below ten, none above it: 3.1 MB, 12 MB. */
private fun trimDecimal(value: Double): String =
    if (value < 10.0) String.format(Locale.getDefault(), "%.1f", value)
    else ceil(value).toInt().toString()
