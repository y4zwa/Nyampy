package slop.miho.chumpy.sub

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/**
 * The metadata panels attach to a subscription response — Hiddify's dialect, which is the
 * de-facto standard: traffic counters in `subscription-userinfo`, the display name in
 * `profile-title` (plain or base64-prefixed), a filename hint in `content-disposition`,
 * the refresh hint in `profile-update-interval`, the card's avatar URL in
 * `profile-logo`, and — on Happ panels — the routing
 * profile in `routing`, whose `Geoipurl`/`Geositeurl` name the provider's geodata.
 */
data class SubscriptionMetadata(
    val title: String? = null,
    val uploadBytes: Long = 0,
    val downloadBytes: Long = 0,
    val totalBytes: Long = 0,
    val expireEpochSeconds: Long = 0,
    val updateIntervalHours: Int? = null,
    val geodataSources: String = "",
    val routingProfileUrl: String? = null,
    /** The panel's `profile-logo`: a URL the card's avatar is downloaded from. */
    val logoUrl: String? = null,
    val supportUrl: String? = null,
    val webPageUrl: String? = null,
    val announcement: String? = null,
)

object SubscriptionHeaders {
    private val bodyKeys = setOf(
        "subscription-userinfo", "profile-title", "profile-update-interval",
        "routing", "autorouting", "profile-logo", "support-url", "profile-web-page-url", "announce",
    )

    internal fun bodyParameter(line: String): Pair<String, String>? {
        val comment = line.trimStart()
        if (!comment.startsWith('#')) return null
        val separator = comment.indexOf(':')
        if (separator < 0) return null
        val key = comment.substring(1, separator).trim().lowercase()
        if (key !in bodyKeys) return null
        return key to comment.substring(separator + 1).trim()
    }

    internal fun parseResponse(headers: Map<String, List<String>>, text: String): SubscriptionMetadata {
        val parameters = mutableMapOf<String, List<String>>()
        text.lineSequence().forEach { line ->
            bodyParameter(line)?.let { (key, value) ->
                if (value.isNotBlank()) parameters.putIfAbsent(key, listOf(value))
            }
        }
        headers.forEach { (key, values) ->
            if (values.firstOrNull()?.isNotBlank() == true) parameters[key.lowercase()] = values
        }
        return parse(parameters)
    }

    internal fun webUrl(value: String): String? {
        val url = value.trim().takeIf { it.length <= 8192 }?.toHttpUrlOrNull() ?: return null
        return url.takeIf { it.username.isEmpty() && it.password.isEmpty() }?.toString()
    }

    private fun announcement(value: String): String? {
        val trimmed = value.trim()
        val text = if (trimmed.startsWith("base64:", ignoreCase = true)) {
            LinkUtils.decodeBase64(trimmed.substringAfter(':')) ?: return null
        } else trimmed
        return text.trim().take(4096).takeIf { it.isNotBlank() }
    }

    /** Parses the interesting headers out of a response's header map. */
    fun parse(headers: Map<String, List<String>>): SubscriptionMetadata {
        fun first(name: String): String? = headers.entries
            .firstOrNull { it.key.equals(name, ignoreCase = true) }
            ?.value?.firstOrNull()?.takeIf { it.isNotBlank() }

        var meta = SubscriptionMetadata()
        first("subscription-userinfo")?.let {
            val counters = parseUserinfo(it)
            meta = meta.copy(
                uploadBytes = counters.uploadBytes,
                downloadBytes = counters.downloadBytes,
                totalBytes = counters.totalBytes,
                expireEpochSeconds = counters.expireEpochSeconds,
            )
        }
        first("profile-title")?.let { parseTitle(it)?.let { title -> meta = meta.copy(title = title) } }
        first("content-disposition")?.let { meta = meta.copy(title = meta.title ?: parseFilename(it)) }
        first("profile-update-interval")?.let { parseUpdateInterval(it)?.let { h -> meta = meta.copy(updateIntervalHours = h) } }
        val routing = first("routing")
        val remoteRouting = first("autorouting")?.let(GeodataSources::remoteProfileUrl)
            ?: routing?.let(GeodataSources::remoteProfileUrl)
        meta = meta.copy(
            geodataSources = routing?.let(GeodataSources::fromHappHeader).orEmpty(),
            routingProfileUrl = remoteRouting,
        )
        first("profile-logo")?.let { meta = meta.copy(logoUrl = it) }
        return meta.copy(
            supportUrl = first("support-url")?.let(::webUrl),
            webPageUrl = first("profile-web-page-url")?.let(::webUrl),
            announcement = first("announce")?.let(::announcement),
        )
    }

    /** "upload=123; download=456; total=789; expire=1700000000" → its four numbers. */
    fun parseUserinfo(value: String): SubscriptionMetadata {
        var upload = 0L
        var download = 0L
        var total = 0L
        var expire = 0L
        value.split(';').forEach { part ->
            val idx = part.indexOf('=')
            if (idx <= 0) return@forEach
            val key = part.substring(0, idx).trim().lowercase()
            val number = part.substring(idx + 1).trim().toLongOrNull() ?: return@forEach
            when (key) {
                "upload" -> upload = number
                "download" -> download = number
                "total" -> total = number
                "expire" -> expire = number
            }
        }
        return SubscriptionMetadata(uploadBytes = upload, downloadBytes = download, totalBytes = total, expireEpochSeconds = expire)
    }

    /** Plain text, or "base64:…" encoded; both are in the wild. */
    fun parseTitle(value: String): String? {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) return null
        if (trimmed.startsWith("base64:", ignoreCase = true)) {
            LinkUtils.decodeBase64(trimmed.substringAfter(':'))?.takeIf { it.isNotBlank() }?.let { return it.trim() }
            return null
        }
        // URLEncoded titles are common too.
        return LinkUtils.decodeURIComponent(trimmed).takeIf { it.isNotBlank() }
    }

    /** "attachment; filename=Name.txt" → "Name". */
    fun parseFilename(value: String): String? {
        val match = "filename\\*?=\"?([^\";]+)\"?".toRegex().find(value) ?: return null
        val name = match.groupValues[1].trim()
        return name.removeSuffix(".txt").removeSuffix(".list").takeIf { it.isNotEmpty() }
    }

    /** Hours, as the header carries it. */
    fun parseUpdateInterval(value: String): Int? =
        value.trim().substringBefore(';').toDoubleOrNull()?.let { hours ->
            if (hours > 0) hours.toInt().coerceAtLeast(1) else null
        }
}
