package slop.miho.chumpy.sub

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import slop.miho.chumpy.db.ProfileEntity
import slop.miho.chumpy.db.ProfileType
import slop.miho.chumpy.sub.LinkUtils.decodeURIComponent
import slop.miho.chumpy.sub.LinkUtils.fixIllegalUrl
import slop.miho.chumpy.sub.LinkUtils.idnHost
import slop.miho.chumpy.sub.LinkUtils.ipv6Brackets
import slop.miho.chumpy.sub.LinkUtils.parsePort
import slop.miho.chumpy.sub.LinkUtils.queryParams
import java.net.URI

/**
 * Parsers for share links: vmess://, vless://, trojan://, ss://, socks://, hysteria2://,
 * wireguard:// and .conf file bodies. Ported from v2rayNG's fmt/ package (Apache-2.0).
 *
 * A parser returns a draft [ProfileEntity] with an empty id and no subscription; the
 * repository stamps identity and ownership on insert. Null means "not a link of mine".
 */
object LinkParsers {
    private const val TLS = "tls"
    private const val REALITY = "reality"
    private const val DEFAULT_VMESS_SECURITY = "auto"
    private const val DEFAULT_WG_ADDRESS = "172.16.0.2/32"
    private const val DEFAULT_WG_MTU = 1420

    /** Panels' JSON is not always quoted by the book; this one forgives. */
    private val lenientJson = Json { ignoreUnknownKeys = true; isLenient = true }

    /** Dispatches on the scheme; accepts trimmed lines with surrounding junk spaces. */
    fun parse(link: String): ProfileEntity? {
        val raw = link.trim().removePrefix("\uFEFF").trim()
        val schemeEnd = raw.indexOf("://")
        if (schemeEnd <= 0) return null
        val trimmed = raw.substring(0, schemeEnd).lowercase() + raw.substring(schemeEnd)
        val parsed = when {
            trimmed.startsWith("vmess://", ignoreCase = true) -> parseVmess(trimmed)
            trimmed.startsWith("vless://", ignoreCase = true) -> parseVless(trimmed)
            trimmed.startsWith("trojan://", ignoreCase = true) -> parseTrojan(trimmed)
            trimmed.startsWith("ss://", ignoreCase = true) -> parseShadowsocks(trimmed)
            trimmed.startsWith("socks://", ignoreCase = true) ||
                trimmed.startsWith("socks5://", ignoreCase = true) -> parseSocks(trimmed)
            trimmed.startsWith("hy2://", ignoreCase = true) ||
                trimmed.startsWith("hysteria2://", ignoreCase = true) -> parseHysteria2(trimmed)
            trimmed.startsWith("wireguard://", ignoreCase = true) ||
                trimmed.startsWith("wg://", ignoreCase = true) -> parseWireguardUri(trimmed)
            trimmed.startsWith("tuic://", ignoreCase = true) -> parseTuic(trimmed)
            trimmed.startsWith("anytls://", ignoreCase = true) -> parseAnytls(trimmed)
            trimmed.startsWith("snell://", ignoreCase = true) -> parseSnell(trimmed)
            trimmed.startsWith("mieru://", ignoreCase = true) -> parseMieru(trimmed)
            trimmed.startsWith("sudoku://", ignoreCase = true) -> parseSudoku(trimmed)
            trimmed.startsWith("shadowquic://", ignoreCase = true) -> parseShadowQuic(trimmed)
            trimmed.startsWith("trusttunnel://", ignoreCase = true) -> parseTrustTunnel(trimmed)
            else -> null
        }
        // The link itself rides along, verbatim — the row's copy gives it back the
        // way it came in, and everything that parses through here is a link by
        // definition. Configs and balancers arrive by other doors, carrying none.
        return parsed?.takeIf {
            it.server.isNotBlank() && it.serverPort in 1..65535 && when (it.type) {
                ProfileType.VMESS, ProfileType.VLESS, ProfileType.TROJAN -> it.password.isNotBlank()
                ProfileType.WIREGUARD -> it.wgSecretKey.isNotBlank() && it.publicKey.isNotBlank()
                ProfileType.SHADOWSOCKS -> it.method.isNotBlank() && it.password.isNotEmpty()
                ProfileType.TUIC, ProfileType.ANYTLS, ProfileType.SNELL, ProfileType.MIERU,
                ProfileType.SUDOKU, ProfileType.SHADOWQUIC, ProfileType.TRUSTTUNNEL ->
                    it.password.isNotBlank()
                else -> true
            }
        }
            ?.copy(sourceLink = raw)
    }

    internal fun parseHttpProxy(line: String): ProfileEntity? {
        val raw = line.trim()
        val https = raw.startsWith("https://", ignoreCase = true)
        if (!https && !raw.startsWith("http://", ignoreCase = true)) return null
        val uri = parseUri(raw) ?: return null
        if (uri.idnHost.isEmpty() || uri.port !in 1..65535 ||
            uri.rawPath.orEmpty() !in setOf("", "/") || uri.rawQuery != null
        ) return null
        val credentials = uri.rawUserInfo.orEmpty()
        val username = decodeURIComponent(credentials.substringBefore(':'))
        val password = decodeURIComponent(credentials.substringAfter(':', ""))
        if (username.isEmpty() && password.isNotEmpty()) return null
        return draft(ProfileType.HTTP).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = uri.port,
            username = username,
            password = password,
            security = if (https) TLS else "",
            sourceLink = raw,
        )
    }

    /** A WireGuard .conf file body (the tunnel-migration import path). */
    fun parseWireguardConf(text: String): ProfileEntity? {
        val interfaceParams = mutableMapOf<String, String>()
        val peerParams = mutableMapOf<String, String>()
        var section: String? = null
        var peers = 0
        text.lines().forEach { line ->
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
            when {
                trimmed.startsWith("[Interface]", ignoreCase = true) -> section = "interface"
                trimmed.startsWith("[Peer]", ignoreCase = true) -> {
                    if (++peers > 1) return null
                    section = "peer"
                }
                trimmed.startsWith("[") -> section = null
                section != null -> {
                    val idx = trimmed.indexOf('=')
                    if (idx > 0) {
                        val params = if (section == "interface") interfaceParams else peerParams
                        params[trimmed.substring(0, idx).trim().lowercase()] = trimmed.substring(idx + 1).trim()
                    }
                }
            }
        }
        val endpoint = peerParams["endpoint"].orEmpty()
        if (endpoint.isEmpty() || interfaceParams["privatekey"].isNullOrEmpty() ||
            peerParams["publickey"].isNullOrEmpty()) return null
        val endpointHost: String
        val endpointPort: Int
        val colon = endpoint.lastIndexOf(':')
        if (colon > 0) {
            endpointHost = endpoint.substring(0, colon).removeSurrounding("[", "]")
            endpointPort = parsePort(endpoint.substring(colon + 1))
        } else {
            endpointHost = endpoint
            endpointPort = 0
        }
        if (endpointHost.isBlank() || endpointPort !in 1..65535) return null
        return draft(ProfileType.WIREGUARD).copy(
            server = endpointHost,
            serverPort = endpointPort,
            remarks = "",
            wgSecretKey = interfaceParams["privatekey"].orEmpty(),
            wgLocalAddress = interfaceParams["address"] ?: DEFAULT_WG_ADDRESS,
            wgMtu = interfaceParams["mtu"]?.toIntOrNull() ?: DEFAULT_WG_MTU,
            publicKey = peerParams["publickey"].orEmpty(),
            wgPresharedKey = peerParams["presharedkey"].orEmpty(),
            wgReserved = peerParams["reserved"] ?: "",
            wgKeepalive = peerParams["persistentkeepalive"]?.trim()?.toIntOrNull() ?: 0,
            wgAmnezia = amneziaOptions(interfaceParams),
            // The .conf's own resolvers, carried the way a Clash proxy map carries them:
            // the writer hands them to the core instead of silently substituting DoH.
            extraOptions = wireguardDnsOptions(interfaceParams["dns"]),
        )
    }

    /** A [Interface] DNS line as the extraOptions JSON the config writer reads. */
    private fun wireguardDnsOptions(value: String?): String {
        val servers = value.orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }
        if (servers.isEmpty()) return ""
        return JsonObject(mapOf("dns" to JsonArray(servers.map(::JsonPrimitive)))).toString()
    }

    /** The v3.1-only keys: their presence marks the whole block as version 3. */
    private val AMNEZIA_V3_KEYS = setOf(
        "headerprotectionkey", "contentpaddingaddition", "rekeyaftertime", "rekeytimeout",
        "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts", "randomtrailers",
        "disablecookies",
    )

    /**
     * The AmneziaWG knobs a .conf carries, rendered as the JSON object the config writer
     * hands to the core's `amnezia-wg-option`. Empty for a plain WireGuard conf.
     *
     * Keys are the conf file's own names in lowercase; the emitted names are the core's.
     * AmneziaWG 3.1 adds the header protection key, content padding, rekey timers and the
     * two on/off switches, and the core wants the version stated explicitly for them.
     */
    private fun amneziaOptions(params: Map<String, String>): String {
        val options = LinkedHashMap<String, kotlinx.serialization.json.JsonElement>()

        fun number(source: String, target: String = source) {
            params[source]?.trim()?.toIntOrNull()?.let { options[target] = JsonPrimitive(it) }
        }

        fun text(source: String, target: String = source) {
            params[source]?.trim()?.takeIf { it.isNotEmpty() }?.let { options[target] = JsonPrimitive(it) }
        }

        fun flag(source: String, target: String) {
            when (params[source]?.trim()?.lowercase()) {
                "on", "true", "yes", "1" -> options[target] = JsonPrimitive(true)
                "off", "false", "no", "0" -> options[target] = JsonPrimitive(false)
            }
        }

        val version = when {
            params.keys.any { it in AMNEZIA_V3_KEYS } -> 3
            params.containsKey("jc") || params.containsKey("jmin") || params.containsKey("s1") -> 1
            else -> 0
        }
        if (version == 0) return ""
        options["version"] = JsonPrimitive(version)
        number("jc")
        number("jmin")
        number("jmax")
        number("s1")
        number("s2")
        number("s3")
        number("s4")
        text("h1")
        text("h2")
        text("h3")
        text("h4")
        text("headerprotectionkey", "header-protection-key")
        text("i1")
        text("i2")
        text("i3")
        text("i4")
        text("i5")
        text("contentpaddingaddition", "content-padding-addition")
        text("rekeyaftertime", "rekey-after-time")
        text("rekeytimeout", "rekey-timeout")
        text("rejectaftertime", "reject-after-time")
        text("keepalivetimeout", "keepalive-timeout")
        text("maxhandshakeattempts", "max-handshake-attempts")
        flag("randomtrailers", "random-trailers")
        flag("disablecookies", "disable-cookies")
        return kotlinx.serialization.json.JsonObject(options).toString()
    }
    private fun draft(type: ProfileType): ProfileEntity =
        ProfileEntity(id = "", subscriptionId = null, type = type)

    // ------------------------------------------------------------------ vmess

    private fun parseVmess(str: String): ProfileEntity? {
        // The modern "standard" vmess URI carries a query string; the classic QR-code form
        // is base64 of a JSON blob. kotlinx.serialization (not org.json) keeps this
        // JVM-testable; lenient because panels' JSON is not always quoted by the book.
        if (str.substringAfter("vmess://").substringBefore('#').contains('@')) return parseVmessUri(str)

        val json = LinkUtils.decode(str.removePrefix("vmess://"))
        if (json.isEmpty()) return null
        val qr = try {
            lenientJson.parseToJsonElement(json).jsonObject
        } catch (_: Exception) {
            return null
        }
        fun field(name: String): String = (qr[name] as? JsonPrimitive)?.content ?: ""
        val add = field("add")
        val id = field("id")
        val net = field("net")
        if (add.isEmpty() || id.isEmpty()) return null

        val profile = draft(ProfileType.VMESS).copy(
            remarks = field("ps"),
            server = add,
            serverPort = parsePort(field("port")),
            password = id,
            method = field("scy").ifEmpty { DEFAULT_VMESS_SECURITY },
            network = net.ifEmpty { "tcp" },
            headerType = field("type"),
            host = field("host"),
            path = field("path"),
            security = field("tls").let { if (it == TLS) it else "" },
            sni = field("sni"),
            alpn = field("alpn"),
            fingerprint = field("fp"),
            allowInsecure = field("insecure") == "1",
        )
        val withTransport = when (profile.network) {
            "kcp", "mkcp" -> profile.copy(seed = field("path"))
            "grpc" -> profile.copy(mode = field("type"), serviceName = field("path"), authority = field("host"))
            else -> profile
        }
        return withTransport
    }

    private fun parseVmessUri(str: String): ProfileEntity? {
        val uri = parseUri(str) ?: return null
        val profile = draft(ProfileType.VMESS).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = uri.port,
            password = uri.userInfo.orEmpty(),
            method = DEFAULT_VMESS_SECURITY,
        )
        return applyQueryParams(profile, queryParams(uri))
    }

    // ------------------------------------------------------------------ vless

    private fun parseVless(str: String): ProfileEntity? {
        val uri = parseUri(str) ?: return null
        val profile = draft(ProfileType.VLESS).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = uri.port,
            password = uri.userInfo.orEmpty(),
            method = queryParams(uri)["encryption"] ?: "none",
        )
        return applyQueryParams(profile, queryParams(uri))
    }

    // ------------------------------------------------------------------ trojan

    private fun parseTrojan(str: String): ProfileEntity? {
        val uri = parseUri(str) ?: return null
        val profile = draft(ProfileType.TROJAN).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = uri.port,
            password = uri.userInfo.orEmpty(),
        )
        return if (uri.rawQuery.isNullOrEmpty()) {
            profile.copy(network = "tcp", security = TLS)
        } else {
            applyQueryParams(profile, queryParams(uri)).copy(security = queryParams(uri)["security"] ?: TLS)
        }
    }

    // ------------------------------------------------------------------ shadowsocks

    private fun parseShadowsocks(str: String): ProfileEntity? =
        parseShadowsocksSip002(str) ?: parseShadowsocksLegacy(str)

    private fun parseShadowsocksSip002(str: String): ProfileEntity? {
        val uri = parseUri(str) ?: return null
        if (uri.idnHost.isEmpty() || uri.port <= 0) return null
        val userInfo = uri.rawUserInfo?.takeIf { it.isNotEmpty() } ?: return null
        val parts = if (':' in userInfo) {
            userInfo.split(':', limit = 2).map(LinkUtils::decodeURIComponent)
        } else {
            LinkUtils.decode(decodeURIComponent(userInfo)).split(':', limit = 2)
        }
        if (parts.size != 2 || parts.first().isBlank()) return null
        var profile = draft(ProfileType.SHADOWSOCKS).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = uri.port,
            method = parts.first().lowercase(),
            password = parts.last(),
        )
        // SIP003 plugins (simple-obfs, shadow-tls, v2ray-plugin, …) ride through
        // verbatim: the emitter hands plugin/plugin-opts to the core untouched.
        val plugin = queryParams(uri)["plugin"].orEmpty()
        if (plugin.isNotEmpty()) {
            val parts = plugin.split(';')
            val opts = LinkedHashMap<String, JsonElement>()
            parts.drop(1).forEach { pair ->
                val idx = pair.indexOf('=')
                if (idx > 0) opts[pair.substring(0, idx).trim()] = JsonPrimitive(pair.substring(idx + 1))
            }
            val extras = LinkedHashMap<String, JsonElement>()
            extras["plugin"] = JsonPrimitive(parts.first().trim())
            if (opts.isNotEmpty()) extras["plugin-opts"] = JsonObject(opts)
            profile = profile.copy(extraOptions = JsonObject(extras).toString())
        }
        return profile
    }

    private fun parseShadowsocksLegacy(str: String): ProfileEntity? {
        var body = str.removePrefix("ss://")
        val hashIdx = body.indexOf('#')
        var remarks = ""
        if (hashIdx > 0) {
            remarks = decodeURIComponent(body.substring(hashIdx + 1))
            body = body.substring(0, hashIdx)
        }
        // Either the whole body is base64, or only the method:password half before "@".
        val atIdx = body.indexOf('@')
        body = if (atIdx > 0) {
            LinkUtils.decode(body.substring(0, atIdx)) + body.substring(atIdx)
        } else {
            LinkUtils.decode(body)
        }
        val match = "^(.+?):(.*)@(.+?):(\\d+)/?$".toRegex().matchEntire(body) ?: return null
        return draft(ProfileType.SHADOWSOCKS).copy(
            remarks = remarks,
            server = match.groupValues[3].removeSurrounding("[", "]"),
            serverPort = parsePort(match.groupValues[4]),
            password = match.groupValues[2],
            method = match.groupValues[1].lowercase(),
        )
    }

    // ------------------------------------------------------------------ socks

    private fun parseSocks(str: String): ProfileEntity? {
        val uri = parseUri(str) ?: return null
        if (uri.idnHost.isEmpty() || uri.port <= 0) return null
        val profile = draft(ProfileType.SOCKS).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = uri.port,
        )
        val userInfo = uri.rawUserInfo.orEmpty()
        return if (userInfo.contains(":")) {
            profile.copy(username = decodeURIComponent(userInfo.substringBefore(":")),
                password = decodeURIComponent(userInfo.substringAfter(":")))
        } else {
            profile
        }
    }

    // ------------------------------------------------------------------ hysteria2

    private fun parseHysteria2(str: String): ProfileEntity? {
        val uri = parseUri(str) ?: return null
        val profile = draft(ProfileType.HYSTERIA2).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = if (uri.port == -1) 443 else uri.port,
            password = uri.userInfo.orEmpty(),
            security = TLS,
            network = "hysteria",
        )
        if (uri.rawQuery.isNullOrEmpty()) return profile
        val query = queryParams(uri)
        return applyQueryParams(profile, query).copy(
            network = "hysteria",
            security = query["security"] ?: TLS,
            obfsPassword = query["obfs-password"].orEmpty(),
            portHopping = query["mport"].orEmpty(),
            portHoppingInterval = query["mportinterval"].orEmpty(),
        )
    }

    // ------------------------------------------------------------------ tuic

    private fun parseTuic(str: String): ProfileEntity? {
        val uri = parseUri(str) ?: return null
        val (uuid, password) = credentialPair(uri) ?: return null
        val query = queryParams(uri)
        return draft(ProfileType.TUIC).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = uri.port,
            username = uuid,
            password = password,
            sni = query["sni"].orEmpty(),
            alpn = query["alpn"].orEmpty(),
            allowInsecure = insecureFlag(query),
            fingerprint = (query["fp"] ?: query["fingerprint"]).orEmpty(),
            extraOptions = queryExtras(
                query,
                setOf("sni", "alpn", "fp", "fingerprint", "allow_insecure", "allowInsecure", "insecure"),
                // The TUIC link spec spells this one differently from the core's option.
                mapOf("congestion_control" to "congestion-controller"),
            ),
        )
    }

    // ------------------------------------------------------------------ anytls

    private fun parseAnytls(str: String): ProfileEntity? {
        val uri = parseUri(str) ?: return null
        val password = decodeURIComponent(uri.rawUserInfo.orEmpty())
        if (password.isEmpty()) return null
        val query = queryParams(uri)
        return draft(ProfileType.ANYTLS).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = uri.port,
            password = password,
            sni = query["sni"].orEmpty(),
            alpn = query["alpn"].orEmpty(),
            allowInsecure = insecureFlag(query),
            fingerprint = (query["fp"] ?: query["fingerprint"]).orEmpty(),
            extraOptions = queryExtras(
                query,
                setOf("sni", "alpn", "fp", "fingerprint", "allow_insecure", "allowInsecure", "insecure"),
            ),
        )
    }

    // ------------------------------------------------------------------ snell

    private fun parseSnell(str: String): ProfileEntity? {
        val uri = parseUri(str) ?: return null
        val psk = decodeURIComponent(uri.rawUserInfo.orEmpty())
        if (psk.isEmpty()) return null
        val query = queryParams(uri)
        val extras = LinkedHashMap<String, JsonElement>()
        query["version"]?.let { extras["version"] = JsonPrimitive(it) }
        val obfs = query["obfs"].orEmpty()
        if (obfs.isNotEmpty()) {
            val opts = LinkedHashMap<String, JsonElement>()
            opts["mode"] = JsonPrimitive(obfs)
            query["obfs-host"]?.let { opts["host"] = JsonPrimitive(it) }
            extras["obfs-opts"] = JsonObject(opts)
        }
        return draft(ProfileType.SNELL).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = uri.port,
            password = psk,
            extraOptions = JsonObject(extras).toString(),
        )
    }

    // ------------------------------------------------------------------ mieru

    private fun parseMieru(str: String): ProfileEntity? {
        val uri = parseUri(str) ?: return null
        val (username, password) = credentialPair(uri) ?: return null
        val query = queryParams(uri)
        val transport = (query["transport"] ?: "TCP").lowercase()
        return draft(ProfileType.MIERU).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = uri.port,
            username = username,
            password = password,
            network = transport,
            extraOptions = queryExtras(
                query,
                setOf("transport", "sni", "alpn", "allow_insecure", "allowInsecure", "insecure"),
            ),
        )
    }

    // ------------------------------------------------------------------ sudoku

    private fun parseSudoku(str: String): ProfileEntity? {
        val uri = parseUri(str) ?: return null
        val key = decodeURIComponent(uri.rawUserInfo.orEmpty())
        if (key.isEmpty()) return null
        val query = queryParams(uri)
        return draft(ProfileType.SUDOKU).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = uri.port,
            password = key,
            extraOptions = queryExtras(query, emptySet()),
        )
    }

    // -------------------------------------------------------------- shadowquic

    private fun parseShadowQuic(str: String): ProfileEntity? {
        val uri = parseUri(str) ?: return null
        val (username, password) = credentialPair(uri) ?: return null
        val query = queryParams(uri)
        return draft(ProfileType.SHADOWQUIC).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = uri.port,
            username = username,
            password = password,
            sni = query["sni"].orEmpty(),
            alpn = query["alpn"].orEmpty(),
            extraOptions = queryExtras(query, setOf("sni", "alpn")),
        )
    }

    // -------------------------------------------------------------- trusttunnel

    private fun parseTrustTunnel(str: String): ProfileEntity? {
        val uri = parseUri(str) ?: return null
        val (username, password) = credentialPair(uri) ?: return null
        val query = queryParams(uri)
        return draft(ProfileType.TRUSTTUNNEL).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = uri.port,
            username = username,
            password = password,
            sni = query["sni"].orEmpty(),
            alpn = query["alpn"].orEmpty(),
            allowInsecure = insecureFlag(query),
            fingerprint = (query["fp"] ?: query["fingerprint"]).orEmpty(),
            extraOptions = queryExtras(
                query,
                setOf("sni", "alpn", "fp", "fingerprint", "allow_insecure", "allowInsecure", "insecure"),
            ),
        )
    }

    /** userinfo split as name:password, percent-decoded; null when the colon is absent. */
    private fun credentialPair(uri: URI): Pair<String, String>? {
        val raw = uri.rawUserInfo.orEmpty()
        if (':' !in raw) return null
        val name = decodeURIComponent(raw.substringBefore(':'))
        val password = decodeURIComponent(raw.substringAfter(':'))
        if (name.isEmpty() || password.isEmpty()) return null
        return name to password
    }

    private fun insecureFlag(query: Map<String, String>): Boolean =
        listOf("insecure", "allow_insecure", "allowInsecure").any {
            query[it].equals("1", ignoreCase = true) || query[it].equals("true", ignoreCase = true)
        }

    /** The query string minus the keys the typed columns already own, as JSON. */
    private fun queryExtras(
        query: Map<String, String>,
        excluded: Set<String>,
        rename: Map<String, String> = emptyMap(),
    ): String {
        val extras = LinkedHashMap<String, JsonElement>()
        query.forEach { (key, value) ->
            if (key !in excluded && value.isNotEmpty()) {
                extras[rename[key] ?: key] = JsonPrimitive(value)
            }
        }
        return if (extras.isEmpty()) "" else JsonObject(extras).toString()
    }

    // ------------------------------------------------------------------ wireguard

    private fun parseWireguardUri(str: String): ProfileEntity? {
        val uri = parseUri(str) ?: return null
        if (uri.rawQuery.isNullOrEmpty()) return null
        val query = queryParams(uri)
        return draft(ProfileType.WIREGUARD).copy(
            remarks = fragmentOf(uri),
            server = uri.idnHost,
            serverPort = uri.port,
            wgSecretKey = uri.userInfo.orEmpty(),
            wgLocalAddress = query["address"] ?: DEFAULT_WG_ADDRESS,
            publicKey = query["publickey"].orEmpty(),
            wgPresharedKey = query["presharedkey"].orEmpty(),
            wgMtu = query["mtu"]?.toIntOrNull() ?: DEFAULT_WG_MTU,
            wgReserved = query["reserved"] ?: "0,0,0",
            wgKeepalive = (query["keepalive"] ?: query["persistentkeepalive"])
                ?.trim()?.toIntOrNull() ?: 0,
        )
    }

    // ------------------------------------------------------------------ shared

    /** Fills the transport/security fields shared by every scheme-with-query format. */
    private fun applyQueryParams(profile: ProfileEntity, query: Map<String, String>): ProfileEntity {
        var result = profile.copy(
            network = query["type"] ?: "tcp",
            headerType = query["headerType"].orEmpty(),
            host = query["host"].orEmpty(),
            path = query["path"].orEmpty(),
            seed = query["seed"].orEmpty(),
            mode = query["mode"].orEmpty(),
            serviceName = query["serviceName"].orEmpty(),
            authority = query["authority"].orEmpty(),
            xhttpExtra = query["extra"],
        )
        val security = query["security"]
        result = result.copy(security = if (security == TLS || security == REALITY) security else "")
        val insecureKeys = listOf("insecure", "allowInsecure", "allow_insecure")
        result = result.copy(
            allowInsecure = insecureKeys.any { query[it] == "1" },
            sni = query["sni"].orEmpty(),
            fingerprint = query["fp"].orEmpty(),
            alpn = query["alpn"].orEmpty(),
            publicKey = query["pbk"].orEmpty(),
            shortId = query["sid"].orEmpty(),
            spiderX = query["spx"].orEmpty(),
            flow = query["flow"].orEmpty(),
        )
        return result
    }

    private fun fragmentOf(uri: URI): String = decodeURIComponent(uri.rawFragment.orEmpty())

    private fun parseUri(str: String): URI? = try {
        URI(fixIllegalUrl(str))
    } catch (_: Exception) {
        null
    }

    /** The endpoint in host:port form, IPv6 bracketed — the shape configs want. */
    fun endpointOf(profile: ProfileEntity): String =
        "${ipv6Brackets(profile.server)}:${profile.serverPort}"
}
