package dev.yazwa.nyampy.sub

import kotlinx.serialization.json.*

/**
 * The geodata sources a subscription names: which databases its routing needs and where
 * the provider's own copies can be downloaded from. The sources travel as a small JSON
 * object — logical database name to URL — both from a raw config's `geodata` block and
 * from a Happ panel's routing header.
 */
internal object GeodataSources {
    /** A routing header longer than this is junk; no real profile comes close. */
    private const val MAX_HAPP_HEADER_CHARS = 256 * 1024
    private const val HAPP_ONADD_PREFIX = "happ://routing/onadd/"
    private const val HAPP_ADD_PREFIX = "happ://routing/add/"
    private val routingPrefixes = listOf(
        HAPP_ONADD_PREFIX, HAPP_ADD_PREFIX,
        "incy://routing/onadd/", "incy://routing/add/",
        "://routing/onadd/", "://routing/add/",
    )
    fun fromRoutingBody(body: String): String = runCatching {
        val text = body.trim().removePrefix("\uFEFF")
        val prefix = routingPrefixes.firstOrNull { text.startsWith(it, ignoreCase = true) }
        val payload = if (prefix != null) LinkUtils.decodeURIComponent(text.substring(prefix.length)) else text
        val decoded = if (payload.startsWith("{")) payload else LinkUtils.decodeBase64(payload) ?: return@runCatching ""
        val config = json.parseToJsonElement(decoded) as? JsonObject ?: return@runCatching ""
        val sources = linkedMapOf<String, String>()
        listOf("geoipurl" to "geoip.dat", "geositeurl" to "geosite.dat").forEach { (key, file) ->
            config.stringIgnoreCase(key)?.trim()?.takeIf { SubscriptionHeaders.webUrl(it) != null }
                ?.let { sources[file] = it }
        }
        encode(sources)
    }.getOrDefault("")


    private val json = Json { ignoreUnknownKeys = true }
    private val filename = Regex("[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\\.dat")

    fun validFilename(name: String): Boolean = filename.matches(name) && !name.contains("..")

    /**
     * Extracts the database URLs from a Happ routing header — `happ://routing/onadd/<data>`
     * or the older `happ://routing/add/<data>`, where `<data>` is the base64 of a Happ
     * routing profile (the base64 may itself be URL-encoded).
     *
     * Only `Geoipurl`/`Geositeurl` are consumed, case-insensitively: they name the
     * provider's geoip.dat and geosite.dat. The rest of the profile — DirectSites,
     * ProxySites and the routing itself — is intentionally ignored; the rules already
     * arrive in the config body. A malformed, oversized or URL-less header returns "".
     *
     * The header is only sent while the Happ spoof is enabled (the default; see
     * [HappSpoof] and [dev.yazwa.nyampy.data.SettingsStore]).
     */
    fun fromHappHeader(header: String): String = runCatching {
        val value = header.trim()
        if (value.length > MAX_HAPP_HEADER_CHARS) return@runCatching ""
        fromRoutingBody(value)
    }.getOrDefault("")

    /** Panels spell the keys both ways, so the lookup ignores case. */
    private fun JsonObject.stringIgnoreCase(key: String): String? =
        entries.firstOrNull { it.key.equals(key, ignoreCase = true) }?.value
            ?.let { (it as? JsonPrimitive)?.takeIf { value -> value.isString }?.content }

    /**
     * The union of two source sets. `overrides` wins per database key — the config body's
     * own source beats the header's — and a malformed side is skipped rather than thrown,
     * since this sits on the subscription import path.
     */
    fun merge(defaults: String, overrides: String): String = merge(parseSafely(defaults), overrides)

    fun merge(defaults: Map<String, String>, overrides: String): String =
        encode(defaults + parseSafely(overrides))

    /** [parse] without the throw: a broken header or body source becomes no sources. */
    internal fun parseSafely(sources: String): Map<String, String> =
        runCatching { parse(sources) }.getOrDefault(emptyMap())

    private fun encode(sources: Map<String, String>): String =
        if (sources.isEmpty()) "" else JsonObject(sources.mapValues { JsonPrimitive(it.value) }).toString()

    fun fromConfig(config: JsonObject): String {
        val sources = linkedMapOf<String, JsonElement>()
        (config["geodata"] as? JsonObject)?.get("assets")?.let { assets ->
            (assets as? JsonArray)?.filterIsInstance<JsonObject>()?.forEach { entry ->
                val name = (entry["file"] as? JsonPrimitive)?.contentOrNull.orEmpty()
                val url = (entry["url"] as? JsonPrimitive)?.contentOrNull.orEmpty()
                if (validFilename(name) && url.isNotBlank()) sources[name] = JsonPrimitive(url)
            }
        }
        (config["geox-url"] as? JsonObject)?.let { urls ->
            listOf("geoip", "geosite").forEach { key ->
                (urls[key] as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() }?.let { sources.putIfAbsent("$key.dat", JsonPrimitive(it)) }
            }
        }
        return if (sources.isEmpty()) "" else JsonObject(sources).toString()
    }

    fun parse(sources: String): Map<String, String> = if (sources.isBlank()) emptyMap() else {
        val entries = json.parseToJsonElement(sources) as? JsonObject ?: error("Invalid geodata sources")
        entries.mapValues { (_, value) -> (value as? JsonPrimitive)?.contentOrNull ?: error("Invalid geodata URL") }
            .also { require(it.keys.all(::validFilename)) { "Invalid geodata filename" } }
    }

}
