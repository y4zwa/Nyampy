package dev.yazwa.nyampy.data

import android.content.Context
import java.io.IOException
import java.io.InputStream
import java.util.Locale

/**
 * The `.dat` databases that ship inside the APK, and the categories they carry.
 *
 * The panel rules travel as mihomo rules now, so nothing is downloaded any more: a
 * category the shipped files lack is dropped by the writer, not fetched. This object
 * only reads what is already there.
 */
internal object GeodataFiles {
    const val MAX_BYTES = 64L * 1024 * 1024

    @Volatile
    private var supportedCache: Pair<Set<String>, Set<String>>? = null

    /**
     * The categories the APK's own .dat files actually carry, upper-cased: geosite and
     * geoip. The config writer uses them to drop panel rules the core would fail to
     * parse: mihomo refuses an unknown GEOSITE/GEOIP category instead of ignoring it,
     * and one bad rule takes the whole tunnel down. Cached after the first read.
     */
    fun supported(context: Context): Pair<Set<String>, Set<String>> {
        supportedCache?.let { return it }
        return synchronized(this) {
            supportedCache ?: run {
                val geosite = runCatching {
                    context.assets.open("geosite.dat").use(::categories)
                }.getOrDefault(emptySet())
                val geoip = runCatching {
                    context.assets.open("geoip.dat").use(::categories)
                }.getOrDefault(emptySet())
                (geosite to geoip).also { supportedCache = it }
            }
        }
    }

    fun categories(source: InputStream): Set<String> {
        val input = source.buffered()
        val result = mutableSetOf<String>()
        var total = 0L
        var entries = 0
        while (true) {
            val tag = varint(input, eof = true) ?: break
            require(++entries <= 100_000) { "Too many geodata categories" }
            require(tag == 10L) { "Invalid geodata container" }
            val length = varint(input)!!
            require(length in 1..MAX_BYTES && total + length <= MAX_BYTES) { "Geodata size limit" }
            total += length
            val entry = LimitedInput(input, length)
            var name: String? = null
            while (entry.remaining > 0) {
                val field = varint(entry)!!
                require(field shr 3 > 0) { "Invalid geodata field" }
                when ((field and 7).toInt()) {
                    0 -> varint(entry)
                    1 -> skip(entry, 8)
                    2 -> {
                        val size = varint(entry)!!
                        require(size <= entry.remaining) { "Truncated geodata" }
                        if (field shr 3 == 1L) {
                            require(size in 1..256) { "Invalid category" }
                            val bytes = ByteArray(size.toInt())
                            for (index in bytes.indices) bytes[index] = entry.read().also { require(it >= 0) }.toByte()
                            name = bytes.toString(Charsets.UTF_8).uppercase(Locale.ROOT)
                        } else skip(entry, size)
                    }
                    5 -> skip(entry, 4)
                    else -> throw IOException("Invalid geodata wire type")
                }
            }
            require(!name.isNullOrBlank()) { "Missing geodata category" }
            result.add(name)
        }
        require(result.isNotEmpty()) { "Empty geodata" }
        return result
    }

    private fun varint(input: InputStream, eof: Boolean = false): Long? {
        var value = 0L
        for (shift in 0..63 step 7) {
            val next = input.read()
            if (next < 0) { if (shift == 0 && eof) return null; throw IOException("Truncated geodata") }
            if (shift == 63 && next > 1) throw IOException("Invalid varint")
            value = value or ((next and 127).toLong() shl shift)
            if (next and 128 == 0) return value.also { require(it >= 0) }
        }
        throw IOException("Invalid varint")
    }

    private fun skip(input: InputStream, length: Long) {
        require(length >= 0)
        var remaining = length
        while (remaining > 0) {
            val skipped = input.skip(remaining)
            if (skipped > 0) remaining -= skipped
            else { if (input.read() < 0) throw IOException("Truncated geodata"); remaining-- }
        }
    }

    private class LimitedInput(private val source: InputStream, var remaining: Long) : InputStream() {
        override fun read(): Int {
            if (remaining == 0L) return -1
            return source.read().also { if (it < 0) throw IOException("Truncated geodata"); remaining-- }
        }

        override fun skip(n: Long): Long = source.skip(minOf(n, remaining)).also { remaining -= it }
    }
}
