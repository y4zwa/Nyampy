package dev.yazwa.nyampy.sub

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import dev.yazwa.nyampy.db.ProfileEntity
import dev.yazwa.nyampy.db.ProfileType
import dev.yazwa.nyampy.db.computeLinkKey

/**
 * The Clash YAML subscription dialect: a `proxies:` list of proxy maps, the format panels
 * serve to Clash-flavoured clients. Supported inline rules are converted to Xray rules.
 *
 * The YAML is read by a deliberately small block parser (mappings, sequences, quoted
 * scalars, flow lists, comments, and the anchors/aliases/merge keys generators lean on
 * to keep a big config short) — the subset clash proxy lists actually use. Null means
 * "not this dialect".
 */
object ClashYamlParser {
    private val PROXIES_KEY = Regex("""(?m)^[ \t]*(?:proxies|"proxies"|'proxies')[ \t]*:""")

    private val httpFields = setOf(
        "name", "type", "server", "port", "username", "password", "headers",
        "tls", "sni", "servername", "skip-cert-verify", "alpn", "udp",
    )

    /** The profiles found in the `proxies:` list, deduplicated; null when it is not one. */
    fun parse(body: String): List<ProfileEntity>? {
        if (!PROXIES_KEY.containsMatchIn(body)) return null
        val root = runCatching { MiniYaml.parse(body.trim().removePrefix("\uFEFF")) as? Map<*, *> }.getOrNull() ?: return null
        @Suppress("UNCHECKED_CAST")
        val proxies = root["proxies"] as? List<Any?> ?: return null
        val profiles = proxies.mapNotNull { entry ->
            (entry as? Map<*, *>)?.let(::proxyToProfile)
        }
        if (profiles.isEmpty()) return null
        val rules = ClashRouting.parse(root, profiles.map { it.remarks }.toSet())
        return profiles.distinctBy { it.computeLinkKey() }.map { it.copy(routingRules = rules) }
    }

    /** One clash proxy map as a profile draft; null when its endpoint does not hold together. */
    private fun proxyToProfile(proxy: Map<*, *>): ProfileEntity? {
        val type = when ((proxy["type"] as? String)?.lowercase()) {
            "vless" -> ProfileType.VLESS
            "vmess" -> ProfileType.VMESS
            "trojan" -> ProfileType.TROJAN
            "ss", "shadowsocks" -> ProfileType.SHADOWSOCKS
            "socks5", "socks" -> ProfileType.SOCKS
            "http" -> ProfileType.HTTP
            "hysteria2", "hy2" -> ProfileType.HYSTERIA2
            "tuic" -> ProfileType.TUIC
            "anytls" -> ProfileType.ANYTLS
            "snell" -> ProfileType.SNELL
            "mieru" -> ProfileType.MIERU
            "sudoku" -> ProfileType.SUDOKU
            "shadowquic" -> ProfileType.SHADOWQUIC
            "trusttunnel" -> ProfileType.TRUSTTUNNEL
            "wireguard" -> ProfileType.WIREGUARD
            // mihomo's own WARP dialect: WireGuard over HTTP/2 or QUIC, with an EC
            // keypair instead of a Curve25519 one. Clash never had it, panels do.
            "masque" -> ProfileType.MASQUE
            else -> return null
        }
        val server = proxy["server"] as? String ?: return null
        val port = (proxy["port"] as? String)?.toIntOrNull() ?: return null
        if (server.isBlank() || port !in 1..65535) return null

        var profile = ProfileEntity(id = "", subscriptionId = null, type = type).copy(
            remarks = (proxy["name"] as? String).orEmpty(),
            server = server,
            serverPort = port,
        )
        when (type) {
            ProfileType.VLESS -> profile = profile.copy(
                password = proxy["uuid"] as? String ?: return null,
                method = "none",
                flow = (proxy["flow"] as? String).orEmpty(),
            )

            ProfileType.VMESS -> profile = profile.copy(
                password = proxy["uuid"] as? String ?: return null,
                method = (proxy["cipher"] as? String) ?: "auto",
            )

            ProfileType.TROJAN -> profile = profile.copy(
                password = proxy["password"] as? String ?: return null,
            )

            ProfileType.SHADOWSOCKS -> profile = profile.copy(
                method = (proxy["cipher"] as? String).orEmpty(),
                password = (proxy["password"] as? String).orEmpty(),
            )

            ProfileType.SOCKS, ProfileType.HTTP -> profile = profile.copy(
                username = (proxy["username"] as? String).orEmpty(),
                password = (proxy["password"] as? String).orEmpty(),
            )

            ProfileType.HYSTERIA2 -> profile = profile.copy(
                password = proxy["password"] as? String ?: return null,
                obfsPassword = (proxy["obfs-password"] as? String).orEmpty(),
                portHopping = (proxy["ports"] as? String).orEmpty(),
                portHoppingInterval = (proxy["hop-interval"] as? String).orEmpty(),
                hysteriaUpMbps = (proxy["up"] as? String)?.toIntOrNull()?.takeIf { it > 0 },
                hysteriaDownMbps = (proxy["down"] as? String)?.toIntOrNull()?.takeIf { it > 0 },
            )

            ProfileType.TUIC -> profile = profile.copy(
                // TUIC authenticates with a UUID and password; panels spell the UUID
                // either as "uuid" (mihomo) or "username" (some sing-box exports).
                username = (proxy["uuid"] as? String) ?: (proxy["username"] as? String) ?: return null,
                password = proxy["password"] as? String ?: return null,
            )

            ProfileType.ANYTLS -> profile = profile.copy(
                password = proxy["password"] as? String ?: return null,
            )

            ProfileType.SNELL -> profile = profile.copy(
                password = proxy["psk"] as? String ?: return null,
            )

            ProfileType.MIERU -> profile = profile.copy(
                username = proxy["username"] as? String ?: return null,
                password = proxy["password"] as? String ?: return null,
            )

            ProfileType.SUDOKU -> profile = profile.copy(
                password = proxy["key"] as? String ?: return null,
            )

            ProfileType.SHADOWQUIC -> profile = profile.copy(
                username = proxy["username"] as? String ?: return null,
                password = proxy["password"] as? String ?: return null,
            )

            ProfileType.TRUSTTUNNEL -> profile = profile.copy(
                username = proxy["username"] as? String ?: return null,
                password = proxy["password"] as? String ?: return null,
            )

            ProfileType.WIREGUARD -> {
                val privateKey = proxy["private-key"] as? String ?: return null
                val peerKey = proxy["public-key"] as? String ?: return null
                if (privateKey.isBlank() || peerKey.isBlank()) return null
                profile = profile.copy(
                    wgSecretKey = privateKey,
                    publicKey = peerKey,
                    wgPresharedKey = (proxy["pre-shared-key"] as? String).orEmpty(),
                    wgLocalAddress = stringOrList(proxy["ip"]).ifEmpty { "172.16.0.2/32" },
                    wgMtu = (proxy["mtu"] as? String)?.toIntOrNull() ?: 1420,
                    wgReserved = stringOrList(proxy["reserved"]),
                    wgKeepalive = (proxy["persistent-keepalive"] as? String)?.toIntOrNull() ?: 0,
                    wgAmnezia = (proxy["amnezia-wg-option"] as? Map<*, *>)?.let { toJson(it).toString() }.orEmpty(),
                )
            }

            // MASQUE is the core's own shape already: an EC keypair, a SNI and a
            // transport. Nothing to fold into a column — the whole map rides along in
            // extraOptions and the writer hands it to the core as it came.
            ProfileType.MASQUE -> {
                if ((proxy["private-key"] as? String).isNullOrBlank() ||
                    (proxy["public-key"] as? String).isNullOrBlank()
                ) {
                    return null
                }
            }

            else -> return null
        }

        when (type) {
            ProfileType.VLESS, ProfileType.VMESS, ProfileType.TROJAN, ProfileType.HYSTERIA2,
            ProfileType.TUIC, ProfileType.ANYTLS, ProfileType.SNELL, ProfileType.MIERU,
            ProfileType.SUDOKU, ProfileType.SHADOWQUIC, ProfileType.TRUSTTUNNEL ->
                if (profile.password.isBlank()) return null
            ProfileType.SHADOWSOCKS ->
                if (profile.method.isBlank() || profile.password.isEmpty()) return null
            else -> Unit
        }

        if (type == ProfileType.HTTP) {
            val headers = proxy["headers"]
            if (headers != null && headers != "" && headers != "{}" && headers != emptyMap<Any, Any>()) return null
            if (proxy.keys.any { it !in httpFields }) return null
            val tls = (proxy["tls"] as? String)?.lowercase()
            if (proxy["tls"] != null && tls !in setOf("true", "false")) return null
            val skipVerification = (proxy["skip-cert-verify"] as? String)?.lowercase()
            if (proxy["skip-cert-verify"] != null && skipVerification != "false") return null
            if (profile.username.isEmpty() && profile.password.isNotEmpty()) return null
        }
        val reality = proxy["reality-opts"] as? Map<*, *>
        var result = profile.copy(
            network = when {
                type == ProfileType.HYSTERIA2 -> "hysteria"
                type == ProfileType.WIREGUARD -> "tcp"
                // MASQUE's transport is the core's own key, and it defaults to QUIC.
                type == ProfileType.MASQUE ->
                    ((proxy["network"] as? String) ?: "quic").lowercase()
                type == ProfileType.MIERU ->
                    ((proxy["transport"] as? String) ?: "TCP").lowercase()
                else -> when (val net = proxy["network"] as? String) {
                    "ws", "websocket", "grpc", "httpupgrade", "kcp", "mkcp", "xhttp", "splithttp" -> net
                    "h2", "http" -> "http"
                    null, "", "tcp" -> "tcp"
                    else -> return null
                }
            },
            security = when {
                reality != null -> "reality"
                type == ProfileType.HYSTERIA2 || type == ProfileType.TROJAN ||
                    type == ProfileType.TUIC || type == ProfileType.ANYTLS ||
                    type == ProfileType.TRUSTTUNNEL -> "tls"
                (proxy["tls"] as? String).equals("true", ignoreCase = true) -> "tls"
                else -> ""
            },
            sni = (proxy["servername"] as? String) ?: (proxy["sni"] as? String) ?: "",
            fingerprint = (proxy["client-fingerprint"] as? String).orEmpty(),
            alpn = (proxy["alpn"] as? List<*>)?.joinToString(",") { it.toString() } ?: "",
            allowInsecure = (proxy["skip-cert-verify"] as? String).equals("true", ignoreCase = true),
            // REALITY's public key shares its column with a WireGuard peer's: only a
            // document that actually carries REALITY may overwrite what the branch
            // above wrote, or a WireGuard import would lose its key.
            publicKey = if (reality != null) (reality["public-key"] as? String).orEmpty() else profile.publicKey,
            shortId = (reality?.get("short-id") as? String).orEmpty(),
            extraOptions = proxyExtraOptions(proxy),
        )

        when (result.network) {
            "ws", "websocket" -> (proxy["ws-opts"] as? Map<*, *>)?.let { ws ->
                result = result.copy(
                    path = (ws["path"] as? String).orEmpty(),
                    host = hostOf(ws["headers"]),
                )
            }

            "grpc" -> (proxy["grpc-opts"] as? Map<*, *>)?.let { grpc ->
                result = result.copy(serviceName = (grpc["grpc-service-name"] as? String).orEmpty())
            }

            "xhttp", "splithttp" -> (proxy["xhttp-opts"] as? Map<*, *>)?.let { xhttp ->
                result = result.copy(
                    path = (xhttp["path"] as? String).orEmpty(),
                    mode = (xhttp["mode"] as? String).orEmpty(),
                    host = hostOf(xhttp["headers"]),
                )
            }
        }
        return result
    }

    /** The Host header, which clash writes as a scalar, a list or a one-key map. */
    private fun hostOf(headers: Any?): String = when (headers) {
        null -> ""
        is Map<*, *> -> (headers["Host"] ?: headers["host"])?.let(::hostOf) ?: ""
        is List<*> -> headers.joinToString(",") { it.toString() }
        else -> headers.toString()
    }

    /** A scalar or a flow/block list, flattened the way Clash expects it. */
    private fun stringOrList(value: Any?): String = when (value) {
        null -> ""
        is List<*> -> value.joinToString(",") { it.toString() }
        else -> value.toString()
    }

    /** Every key the entry carried, minus the four the columns own. */
    private fun proxyExtraOptions(proxy: Map<*, *>): String {
        val map = LinkedHashMap<String, JsonElement>()
        for ((key, value) in proxy) {
            val name = key as? String ?: continue
            if (name in setOf("name", "type", "server", "port") || value == null) continue
            map[name] = toJson(value)
        }
        return JsonObject(map).toString()
    }

    private fun toJson(value: Any?): JsonElement = when (value) {
        null -> JsonPrimitive("")
        is Map<*, *> -> JsonObject(
            value.entries.mapNotNull { (key, item) ->
                (key as? String)?.takeIf { item != null }?.let { it to toJson(item) }
            }.toMap(),
        )
        is List<*> -> JsonArray(value.map(::toJson))
        else -> JsonPrimitive(value.toString())
    }
}

/**
 * The block-YAML subset clash proxy lists use: mappings and sequences nested by
 * indentation, quoted and plain scalars, flow lists, comments, anchors and merge keys.
 * A `- key: value` item opens a map whose first line is the content at the column it
 * starts on.
 *
 * Anchors are what a generator writes to keep a hundred-node config short: a shared
 * block is defined once as `name: &anchor` and every node pulls it in with `<<: *anchor`
 * (YAML's merge key) or repeats a single value with `*anchor`. The values are resolved
 * as the document is read, the way a real loader would, and the map's own keys win.
 */
private object MiniYaml {
    private class Line(val indent: Int, val text: String)

    fun parse(body: String): Any? {
        val lines = body.lines().mapNotNull(::strip).filterNot { it.text == "---" || it.text == "..." }
        if (lines.isEmpty()) return null
        require(lines.all { it.indent <= 128 }) { "YAML nesting is too deep" }
        val cursor = Cursor(lines, 0)
        return block(cursor, lines.first().indent)
    }

    /** Blank and comment-only lines vanish; the rest keep their indent. */
    private fun strip(raw: String): Line? {
        val indent = raw.indexOfFirst { !it.isWhitespace() }
        if (indent < 0) return null
        val text = stripComment(raw.substring(indent).trimEnd())
        if (text.isBlank()) return null
        return Line(indent, text)
    }

    /** A `#` outside quotes starts a comment — but only at line start or after a space. */
    private fun stripComment(text: String): String {
        var quote: Char? = null
        var index = 0
        while (index < text.length) {
            val char = text[index]
            if (quote != null) {
                if (quote == '"' && char == '\\') { index += 2; continue }
                if (char == quote) {
                    if (quote == '\'' && text.getOrNull(index + 1) == '\'') { index += 2; continue }
                    quote = null
                }
            } else when {
                char == '\'' || char == '"' -> quote = char
                char == '#' && (index == 0 || text[index - 1].isWhitespace()) -> return text.substring(0, index).trimEnd()
            }
            index++
        }
        return text
    }

    private class Cursor(val lines: List<Line>, var index: Int) {
        /** Every `&anchor` read so far; an alias can only point backwards, as in YAML. */
        val anchors = HashMap<String, Any?>()
        fun peek(): Line? = lines.getOrNull(index)
    }

    private fun isSeqItem(text: String): Boolean = text == "-" || text.startsWith("- ")

    private fun block(cursor: Cursor, indent: Int): Any? =
        if (isSeqItem(cursor.lines[cursor.index].text)) sequence(cursor, indent) else mapping(cursor, indent)

    private fun sequence(cursor: Cursor, indent: Int): List<Any?> {
        val items = mutableListOf<Any?>()
        while (true) {
            val line = cursor.peek() ?: break
            if (line.indent != indent || !isSeqItem(line.text)) break
            if (line.text == "-") {
                cursor.index++
                items += cursor.peek()?.takeIf { it.indent > indent }?.let { block(cursor, it.indent) }
            } else {
                val content = line.text.removePrefix("- ")
                if (content.startsWith("{") && content.endsWith("}")) {
                    cursor.index++
                    items += scalar(content, cursor.anchors)
                } else if (keyValue(content) != null) {
                    // The map opens mid-line, at the column the content starts on; the
                    // whole item line is spent as that opening.
                    cursor.index++
                    val virtual = Line(line.indent + line.text.length - content.length, content)
                    items += mapping(cursor, virtual.indent, virtual)
                } else {
                    cursor.index++
                    items += scalar(content, cursor.anchors)
                }
            }
        }
        return items
    }

    /** A block mapping at [indent]; [first] is a virtual opening line from a sequence item. */
    private fun mapping(cursor: Cursor, indent: Int, first: Line? = null): LinkedHashMap<String, Any?> {
        val map = LinkedHashMap<String, Any?>()
        val merged = ArrayList<Map<*, *>>()
        var current = first
        while (true) {
            val line = current ?: cursor.peek()?.takeIf { it.indent == indent } ?: break
            if (current == null && isSeqItem(line.text)) break
            val entry = keyValue(line.text) ?: break
            if (current == null) cursor.index++
            current = null
            val (key, valueText) = entry
            val anchor = anchorOf(valueText)
            val value = when {
                // A child block below, or a sequence written at the key's own indent.
                anchor == null && valueText.isEmpty() -> child(cursor, indent)
                anchor == null -> scalar(valueText, cursor.anchors)
                anchor.second.isEmpty() -> child(cursor, indent)
                else -> scalar(anchor.second, cursor.anchors)
            }
            if (anchor != null) cursor.anchors[anchor.first] = value
            if (key == "<<") merged += mapsOf(value) else map[key] = value
        }
        // YAML's merge key: the map's own keys win, and an earlier source wins over a
        // later one — which is how `<<: *common` plus a `port:` line ends up as a node.
        for (source in merged) {
            for ((key, value) in source) {
                val name = key as? String ?: continue
                if (name !in map) map[name] = value
            }
        }
        return map
    }

    /** The value under a key that carried none of its own: a block, a flush sequence or null. */
    private fun child(cursor: Cursor, indent: Int): Any? {
        val next = cursor.peek()
        return when {
            next == null -> null
            next.indent > indent -> block(cursor, next.indent)
            next.indent == indent && isSeqItem(next.text) -> sequence(cursor, indent)
            else -> null
        }
    }

    /**
     * A `&anchor` prefix: its name, and whatever follows it — either the value itself
     * or nothing, the child block carrying it.
     */
    private fun anchorOf(text: String): Pair<String, String>? {
        if (!text.startsWith("&")) return null
        val space = text.indexOfFirst { it.isWhitespace() }
        return if (space < 0) {
            text.substring(1) to ""
        } else {
            text.substring(1, space) to text.substring(space + 1).trim()
        }
    }

    /** What a merge key points at: one map, or a flow list of them. */
    private fun mapsOf(value: Any?): List<Map<*, *>> = when (value) {
        is Map<*, *> -> listOf(value)
        is List<*> -> value.filterIsInstance<Map<*, *>>()
        else -> emptyList()
    }

    /** `key: value` — the first colon outside quotes that ends the key. */
    private fun keyValue(text: String): Pair<String, String>? {
        val index = delimiter(text, ':')
        if (index < 0) return null
        val rest = text.substring(index + 1)
        if (rest.isNotEmpty() && !rest.first().isWhitespace()) return null
        return unquote(text.substring(0, index).trim()) to rest.trim()
    }

    private fun scalar(text: String, anchors: Map<String, Any?>): Any {
        if (text.startsWith("*")) return anchors[text.substring(1)] ?: text
        if (text.startsWith("[") && text.endsWith("]")) {
            return splitFlow(text.substring(1, text.length - 1)).filter { it.isNotBlank() }
                .map { scalar(it.trim(), anchors) }
        }
        if (text.startsWith("{") && text.endsWith("}")) {
            return splitFlow(text.substring(1, text.length - 1)).filter { it.isNotBlank() }.associate { entry ->
                val colon = delimiter(entry, ':')
                require(colon >= 0) { "Invalid YAML mapping" }
                unquote(entry.substring(0, colon).trim()) to scalar(entry.substring(colon + 1).trim(), anchors)
            }
        }
        return unquote(text)
    }

    private fun splitFlow(text: String): List<String> {
        var start = 0
        return (delimiters(text, ',') + text.length).map { index ->
            text.substring(start, index).also { start = index + 1 }
        }
    }

    private fun delimiter(text: String, target: Char): Int = delimiters(text, target).firstOrNull() ?: -1

    private fun delimiters(text: String, target: Char): List<Int> {
        val positions = mutableListOf<Int>()
        var quote: Char? = null
        var depth = 0
        var index = 0
        while (index < text.length) {
            val char = text[index]
            if (quote != null) {
                if (quote == '"' && char == '\\') { index += 2; continue }
                if (char == quote) {
                    if (quote == '\'' && text.getOrNull(index + 1) == '\'') { index += 2; continue }
                    quote = null
                }
            } else when {
                char == '\'' || char == '"' -> quote = char
                char == '[' || char == '{' -> depth++
                char == ']' || char == '}' -> depth--
                char == target && depth == 0 -> positions.add(index)
            }
            require(depth in 0..64) { "YAML nesting is too deep" }
            index++
        }
        require(quote == null && depth == 0) { "Unterminated YAML value" }
        return positions
    }

    private fun unquote(text: String): String = when {
        text.length >= 2 && text.startsWith("'") && text.endsWith("'") ->
            text.substring(1, text.length - 1).replace("''", "'")
        text.length >= 2 && text.startsWith("\"") && text.endsWith("\"") ->
            kotlinx.serialization.json.Json.parseToJsonElement(text).let {
                (it as kotlinx.serialization.json.JsonPrimitive).content
            }
        else -> text
    }
}
