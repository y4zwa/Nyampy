package dev.yazwa.nyampy.mihomo

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import dev.yazwa.nyampy.db.ProfileEntity
import dev.yazwa.nyampy.db.ProfileType
import java.util.Locale
import kotlin.math.roundToLong

/**
 * Routing intent of a session: everything through the tunnel, or everything but the
 * region's own sites and addresses. The region list mirrors the old Xray builder's
 * presets (hiddify's ir/cn/ru/af/id/tr/br), now expressed as mihomo GEOSITE/GEOIP rules.
 */
enum class RoutingMode(val region: String?) {
    GLOBAL(null),
    BYPASS_RU("ru"),
    BYPASS_CN("cn"),
    BYPASS_IR("ir"),
    BYPASS_AF("af"),
    BYPASS_ID("id"),
    BYPASS_TR("tr"),
    BYPASS_BR("br"),
}

/**
 * Renders the mihomo document the core runs. The TUN and its DNS hijack are attached by
 * the bridge (the device itself is owned by the VpnService); everything that describes
 * *where* traffic goes lives here.
 *
 * The shape mirrors the old Xray builder: one proxy (or the balancer's members), a
 * "PROXY" selector over it, a direct matcher, a reject matcher, and a catch-all.
 */
object ClashConfig {
    /** The group the rules point at. Proxy entries are named "node*" so they never clash. */
    const val PROXY_GROUP = "PROXY"
    const val DIRECT_TAG = "DIRECT"
    const val REJECT_TAG = "REJECT"

    const val DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"

    /**
     * The TUN the VpnService establishes: 172.19.0.1/30, IPv4 only — the service builds
     * no IPv6 address, so the core must not claim one either. mihomo takes the addresses
     * as a comma-separated list of prefixes.
     *
     * IPv6 was carried here until 2026-11-19: apps that latch onto the second family —
     * the Google app above all — resolved AAAA, hung on those destinations and declared
     * themselves offline while the browser quietly fell back to v4.
     */
    const val GATEWAY = "172.19.0.1/30"
    const val DNS_HIJACK = "any"
    const val TUN_MTU = 1500

    /** What a trusted CA starts with; the bridge keeps only strings that look like this. */
    const val CERTIFICATE_PEM = "-----BEGIN CERTIFICATE-----"

    private const val PROBE_INTERVAL = 300

    fun buildFull(
        profile: ProfileEntity,
        mode: RoutingMode,
        members: List<ProfileEntity> = emptyList(),
        testUrl: String = DEFAULT_TEST_URL,
        knownGeoSite: Set<String>? = null,
        knownGeoIp: Set<String>? = null,
        // No default: the inbound is a free proxy on loopback, so every caller names
        // its own port and password rather than inheriting a shared one.
        localProxy: LocalProxy,
    ): String {
        require(profile.type != ProfileType.BALANCER || members.isNotEmpty()) {
            "Balancer has no usable servers"
        }
        val balanced = profile.type == ProfileType.BALANCER
        val strategy = profile.balancerStrategy.ifEmpty { "random" }

        val y = Yaml()
        y.key(0, "mixed-port", localProxy.port.toString())
        y.items(0, "authentication", listOf(quote(localProxy.authentication)))
        y.key(0, "allow-lan", "false")
        y.key(0, "mode", "rule")
        y.key(0, "log-level", "info")
        y.key(0, "ipv6", "false")
        y.key(0, "unified-delay", "true")
        y.key(0, "tcp-concurrent", "true")
        // The core lives in its own process and the app package is excluded from the VPN:
        // process matching has nothing to look at and only costs startup time.
        y.key(0, "find-process-mode", "\"off\"")
        // The .dat files ship inside the APK; geodata-mode makes the core read them instead
        // of downloading a MaxMind DB on first start (and lets GEOIP rules use .dat-only
        // categories such as private).
        y.key(0, "geodata-mode", "true")
        y.key(0, "geo-auto-update", "false")
        y.block(0, "profile") {
            y.key(2, "store-selected", "false")
            y.key(2, "store-fake-ip", "true")
        }
        y.block(0, "sniffer") {
            y.key(2, "enable", "true")
            y.key(2, "force-dns-mapping", "true")
            y.key(2, "parse-pure-ip", "true")
            y.key(2, "override-destination", "false")
            y.block(2, "sniff") {
                y.key(4, "HTTP", "{}")
                y.key(4, "TLS", "{}")
                y.key(4, "QUIC", "{}")
            }
            y.items(2, "skip-domain", listOf("+.apple.com", "+.push.apple.com").map(::quote))
        }
        y.block(0, "dns") {
            y.key(2, "enable", "true")
            y.key(2, "ipv6", "false")
            y.key(2, "enhanced-mode", "fake-ip")
            y.key(2, "fake-ip-range", "198.18.0.1/16")
            y.items(2, "fake-ip-filter", listOf("*.lan", "+.local", "localhost.ptlogin2.qq.com").map(::quote))
            // The device's own resolvers also bootstrap the DoH endpoints and the proxy
            // server's name: with Cloudflare throttled, DoH alone never gets an answer.
            // "system" is fed by the bridge (SetSystemDNS) on every network change, so the
            // document does not have to be rebuilt when the tunnel changes networks.
            y.items(2, "default-nameserver", listOf("1.1.1.1", "8.8.8.8"))
            y.items(2, "nameserver", listOf("https://1.1.1.1/dns-query", "https://dns.google/dns-query"))
            y.items(2, "proxy-server-nameserver", listOf("https://1.1.1.1/dns-query", "system"))
            // DoH knows nothing about the LAN's own zones, and it is a lottery in regions
            // where it is throttled: private names and the bypass region go to the device's
            // resolvers instead, the same ones the phone used before the tunnel.
            y.block(2, "nameserver-policy") {
                dnsPolicy(mode).forEach { (domain, servers) ->
                    y.items(4, quote(domain), servers.map(::quote))
                }
            }
        }

        emitTrust(y, profile)

        // ---------------------------------------------------------------- proxies
        y.raw(0, "proxies:")
        if (balanced) {
            members.forEachIndexed { index, member -> emitProxy(y, member, nodeName(index)) }
        } else {
            emitProxy(y, profile, nodeName(0))
        }

        // ----------------------------------------------------------- proxy groups
        y.raw(0, "proxy-groups:")
        y.item(2, "name: $PROXY_GROUP")
        if (balanced) {
            val groupType = strategyGroup(strategy)
            y.key(4, "type", groupType)
            // mihomo's load-balance defaults to consistent hashing (sticky per destination),
            // not the even spread Xray's roundrobin/random promised: name the strategy.
            if (groupType == "load-balance") y.key(4, "strategy", "round-robin")
            y.key(4, "url", quote(testUrl))
            y.key(4, "interval", PROBE_INTERVAL.toString())
            // Probes only while the group is in use: a pool of any size would otherwise
            // wake the radio every five minutes per member, for as long as the app runs.
            y.key(4, "lazy", "true")
            y.key(4, "tolerance", "50")
            y.items(4, "proxies", (members.indices).map { quote(nodeName(it)) })
        } else {
            y.key(4, "type", "select")
            y.items(4, "proxies", listOf(quote(nodeName(0)), DIRECT_TAG))
        }

        // ------------------------------------------------------------------ rules
        y.raw(0, "rules:")
        mode.region?.let { region ->
            when (region) {
                "ru" -> y.item(2, "GEOSITE,category-ru,$DIRECT_TAG")
                "ir" -> y.item(2, "GEOSITE,category-ir,$DIRECT_TAG")
                "cn" -> y.item(2, "GEOSITE,cn,$DIRECT_TAG")
            }
            // No leading dot: mihomo's DomainSuffix prepends the dot itself, so ".ru"
            // would look for "..ru" and never match.
            y.item(2, "DOMAIN-SUFFIX,$region,$DIRECT_TAG")
            y.item(2, "GEOIP,$region,$DIRECT_TAG")
        }
        // QUIC is left alone on purpose. Rejecting UDP/443 used to keep the session on
        // TCP, but a hard reject is what a browser reads as a broken QUIC handshake: it
        // then shows ERR_QUIC_PROTOCOL_ERROR instead of quietly falling back — Google
        // Search and the Google app were the first places that surfaced it. The sniffer
        // carries QUIC (`sniff.QUIC` above), so HTTP/3 still gets its domain routing.
        // "lan" is the core's own short-circuit — it matches every private range before any
        // database is touched. "private" is a .dat-only category and never matches in mmdb
        // mode, which would send the whole LAN through the server.
        y.item(2, "GEOIP,lan,$DIRECT_TAG,no-resolve")
        y.item(2, "GEOSITE,private,$DIRECT_TAG")
        // The panel's own routing, next to ours: bypass lists, ad and QUIC blocks, BT
        // direct — the intent the imported config carried, expressed as Clash rules.
        panelRules(profile.routingRules, PROXY_GROUP, knownGeoSite, knownGeoIp).forEach { y.item(2, it) }
        y.item(2, "MATCH,$PROXY_GROUP")
        return y.toString()
    }

    /**
     * A subscription imported from sing-box may trust a provider's own CA. mihomo has
     * no per-proxy trust store for a server chain: the global pool is the only place,
     * and the bridge keeps that block to PEM certificates alone (the rest of the
     * document's TLS section stays denied).
     */
    private fun emitTrust(y: Yaml, profile: ProfileEntity) {
        profile.tlsTrustCertificate?.trim()?.takeIf { it.startsWith(CERTIFICATE_PEM) }?.let { certificate ->
            y.block(0, "tls") {
                y.items(2, "custom-certifactes", listOf(quote(certificate)))
            }
        }
    }

    /** The one-proxy document the bridge loads for a delay measurement. */
    fun buildTest(profile: ProfileEntity, testUrl: String = DEFAULT_TEST_URL): String {
        val y = Yaml()
        y.key(0, "mode", "rule")
        y.key(0, "log-level", "warning")
        y.key(0, "ipv6", "false")
        emitTrust(y, profile)
        y.raw(0, "proxies:")
        emitProxy(y, profile, nodeName(0))
        y.raw(0, "proxy-groups:")
        y.item(2, "name: $PROXY_GROUP")
        y.key(4, "type", "url-test")
        y.key(4, "url", quote(testUrl))
        y.key(4, "interval", PROBE_INTERVAL.toString())
        y.items(4, "proxies", listOf(quote(nodeName(0))))
        y.raw(0, "rules:")
        y.item(2, "MATCH,$PROXY_GROUP")
        return y.toString()
    }

    private fun nodeName(index: Int) = if (index == 0) "node" else "node-$index"

    // ------------------------------------------------------------------- panel

    /** The parser for the panel's carried routing rules; malformed ones are skipped. */
    private val lenientJson = Json { ignoreUnknownKeys = true; isLenient = true }

    /**
     * The panel's own Xray rules, rewritten as Clash lines: bypass lists, ad and QUIC
     * blocks, BT direct — the routing the imported config came with. Targets are mapped
     * onto this session's tags, the way the Xray build did.
     */
    private fun panelRules(
        rulesJson: String,
        fallthrough: String,
        knownGeoSite: Set<String>?,
        knownGeoIp: Set<String>?,
    ): List<String> {
        if (rulesJson.isBlank()) return emptyList()
        val rules = try {
            lenientJson.parseToJsonElement(rulesJson) as? JsonArray
        } catch (_: Exception) {
            null
        } ?: return emptyList()

        val out = mutableListOf<String>()
        for (element in rules) {
            val rule = element as? JsonObject ?: continue
            // BitTorrent sniffing has no Clash counterpart: turn it into nothing rather
            // than a catch-all.
            if (rule.containsKey("protocol")) continue
            val target = targetOf(rule, fallthrough) ?: continue

            // A matcher the panel wrote but the core cannot parse drops the whole rule:
            // emitting its address half alone would quietly widen what it matches.
            val port = when (val raw = (rule["port"] as? JsonPrimitive)?.contentOrNull) {
                null -> null
                else -> portToken(raw) ?: continue
            }
            val network = when (val raw = (rule["network"] as? JsonPrimitive)?.contentOrNull) {
                null -> null
                else -> {
                    val protocols = raw.split(',')
                        .map { it.trim().lowercase() }
                        .filter { it == "tcp" || it == "udp" }
                    when {
                        protocols.isEmpty() -> continue
                        // "tcp,udp" is the panel's catch-all, not a matcher.
                        protocols.size == 2 -> null
                        else -> protocols.first()
                    }
                }
            }

            val sourcePort = when (val raw = (rule["sourcePort"] as? JsonPrimitive)?.contentOrNull) {
                null -> null
                else -> portToken(raw) ?: continue
            }

            val rawDomains = strings(rule["domain"])
            val rawIps = strings(rule["ip"])
            val rawSources = strings(rule["source"])
            val domains = rawDomains.mapNotNull { domainRule(it, knownGeoSite) }
            val ips = rawIps.mapNotNull { ipRule(it, knownGeoIp) }
            val sources = rawSources.mapNotNull { sourceRule(it, knownGeoIp) }
            if (domains.isEmpty() && ips.isEmpty() && sources.isEmpty()) continue
            // An AND rule that lost one of its halves would match more than the panel
            // asked for; the whole rule goes instead.
            val present = listOf(rawDomains, rawIps, rawSources).count { it.isNotEmpty() }
            if (present > 1 && listOf(domains, ips, sources).count { it.isNotEmpty() } < present) continue

            // One kind of matcher: the values are alternatives, so each gets its own
            // rule — that also lets an address rule keep its no-resolve option. Two
            // kinds at once are Xray's AND, and are written as one nested rule.
            val groups = listOf(domains, ips, sources).filter { it.isNotEmpty() }
            if (groups.size == 1) {
                for (primary in groups.first()) {
                    val conditions = mutableListOf(primary)
                    if (port != null) conditions += "DST-PORT,$port"
                    if (sourcePort != null) conditions += "SRC-PORT,$sourcePort"
                    if (network != null) conditions += "NETWORK,$network"
                    out += if (conditions.size == 1) {
                        // A lone address/country matcher needs no DNS for the
                        // destination; the option belongs after the target, never
                        // before it. AND rules cannot carry it per-condition.
                        val noResolve = primary.startsWith("IP-CIDR,") || primary.startsWith("GEOIP,")
                        "$primary,$target" + if (noResolve) ",no-resolve" else ""
                    } else {
                        "AND,(" + conditions.joinToString(",") { "($it)" } + "),$target"
                    }
                }
            } else {
                val conditions = mutableListOf<String>()
                groups.forEach { group ->
                    if (group.size == 1) conditions += group.first()
                    else conditions += "OR,(" + group.joinToString(",") { "($it)" } + ")"
                }
                if (port != null) conditions += "DST-PORT,$port"
                if (sourcePort != null) conditions += "SRC-PORT,$sourcePort"
                if (network != null) conditions += "NETWORK,$network"
                out += "AND,(" + conditions.joinToString(",") { "($it)" } + "),$target"
            }
        }
        return out
    }

    private fun strings(element: JsonElement?): List<String> = when (element) {
        null, is JsonNull -> emptyList()
        is JsonPrimitive -> listOfNotNull(element.contentOrNull)
        is JsonArray -> element.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
        else -> emptyList()
    }

    private fun domainRule(raw: String, knownGeoSite: Set<String>?): String? {
        val value = ruleToken(raw) ?: return null
        // Xray's external geodata (ext:file:category) has no mihomo counterpart: a
        // DOMAIN-SUFFIX with "ext:" in it would never match.
        if (value.isEmpty() || value.startsWith("ext:")) return null
        return when {
            value.startsWith("geosite:") -> {
                val name = value.removePrefix("geosite:")
                // "!" is Xray's negation; the core has no such category and refuses the
                // whole document over it, so the rule goes instead.
                if (name.startsWith("!")) return null
                val category = name.substringBefore('@').trim().uppercase(Locale.ROOT)
                if (category.isEmpty() || (knownGeoSite != null && category !in knownGeoSite)) null
                else "GEOSITE,$name"
            }
            value.startsWith("domain:") -> "DOMAIN-SUFFIX," + value.removePrefix("domain:")
            value.startsWith("full:") -> "DOMAIN," + value.removePrefix("full:")
            value.startsWith("regexp:") -> value.removePrefix("regexp:")
                .takeIf(::safeRegex)?.let { "DOMAIN-REGEX," + it }
            value.startsWith("keyword:") -> "DOMAIN-KEYWORD," + value.removePrefix("keyword:")
            else -> "DOMAIN-SUFFIX," + value
        }
    }

    private fun ipRule(raw: String, knownGeoIp: Set<String>?): String? {
        val value = ruleToken(raw) ?: return null
        if (value.isEmpty() || value.startsWith("ext:")) return null
        if (value.startsWith("geoip:")) {
            val name = value.removePrefix("geoip:")
            // "!" is Xray's negation; the core has no such category and refuses the
            // whole document over it, so the rule goes instead.
            if (name.startsWith("!")) return null
            val country = name.trim().uppercase(Locale.ROOT)
            // "lan" is the core's own private-range short-circuit, not a .dat category.
            return if (country.isEmpty() || (country != "LAN" && knownGeoIp != null && country !in knownGeoIp)) {
                null
            } else {
                "GEOIP,$name"
            }
        }
        // Xray accepts a bare address here; IP-CIDR does not — netip.ParsePrefix would
        // reject the whole document. A missing mask is a host, /32 or /128.
        //
        // The option list comes after the target, so "IP-CIDR,1.2.3.4,no-resolve" would
        // name a proxy called "no-resolve"; the rule is left without one, which is the
        // default resolution behaviour anyway.
        if (!isNumericAddress(value)) return null
        return "IP-CIDR," + withHostPrefix(value)
    }

    private fun sourceRule(raw: String, knownGeoIp: Set<String>?): String? {
        val value = ruleToken(raw) ?: return null
        if (value.isEmpty() || value.startsWith("ext:")) return null
        if (value.startsWith("geoip:")) {
            val name = value.removePrefix("geoip:")
            // Same negation story as GEOIP: no "!" category exists in the core.
            if (name.startsWith("!")) return null
            val country = name.trim().uppercase(Locale.ROOT)
            return if (country.isEmpty() || (country != "LAN" && knownGeoIp != null && country !in knownGeoIp)) {
                null
            } else {
                "SRC-GEOIP,$name"
            }
        }
        if (!isNumericAddress(value)) return null
        return "SRC-IP-CIDR," + withHostPrefix(value)
    }

    private fun withHostPrefix(value: String): String = when {
        value.contains('/') -> value
        value.contains(':') -> "$value/128"
        else -> "$value/32"
    }

    /**
     * A panel value as a rule token, or null when it cannot be one.
     *
     * Rule lines are written verbatim — no quoting saves them — so a value carrying
     * anything YAML reads as a line break (CR, NEL, LS, PS) would end the line and
     * hand the rest of the document to whoever wrote the subscription. Everything else
     * the rule syntax itself rejects is dropped too: one bad rule fails the whole
     * document in mihomo, and a tunnel that will not start is its own kind of damage.
     */
    private fun ruleToken(raw: String): String? {
        val value = raw.trim()
        if (value.isEmpty()) return null
        if (value.any { it.isISOControl() || it == '\u2028' || it == '\u2029' }) return null
        if (value.any { it == ',' || it.isWhitespace() }) return null
        return value
    }

    /**
     * A port matcher as the core writes it: "80", "80/443", "1-1024". Xray and links
     * spell the list with commas, but a comma is the core's field separator - only the
     * first port would reach `NewPort`, the rest would be read as a target or a dropped
     * parameter. Each segment must be a real port or a real range, because the parser
     * rejects the whole document over "80,,443" or "80-90-100".
     */
    private fun portToken(raw: String): String? {
        val value = raw.trim()
        if (value.isEmpty()) return null
        if (value.any { it.isISOControl() || it == '\u2028' || it == '\u2029' || it.isWhitespace() }) return null
        val segments = value.split(',')
        if (segments.size > MAX_PORT_RANGES) return null
        val normalized = ArrayList<String>(segments.size)
        for (segment in segments) {
            if (segment.isEmpty()) return null
            val range = segment.split('-', limit = 2)
            val start = range[0].toIntOrNull() ?: return null
            if (start !in 1..65535) return null
            if (range.size == 2) {
                val end = range[1].toIntOrNull() ?: return null
                if (end !in start..65535) return null
                normalized += "$start-$end"
            } else {
                normalized += start.toString()
            }
        }
        return normalized.joinToString("/")
    }

    /** `utils.NewUnsignedRanges` refuses a rule with more segments than this. */
    private const val MAX_PORT_RANGES = 28

    /**
     * A regex the core can compile. mihomo builds its DOMAIN-REGEX rules with Go's RE2,
     * which rejects the lookarounds, backreferences, atomic groups, possessive
     * quantifiers and Perl-only escapes Java accepts - one rejected pattern fails the
     * entire config. The patterns the panels actually ship are plain domain matches.
     */
    private fun safeRegex(pattern: String): Boolean {
        if (pattern.isEmpty() || pattern.length > 4096) return false
        if (UNSUPPORTED_REGEX.any { pattern.contains(it) }) return false
        if (BACK_REFERENCE.containsMatchIn(pattern)) return false
        return runCatching { Regex(pattern) }.isSuccess
    }

    private val UNSUPPORTED_REGEX = listOf(
        "(?=", "(?!", "(?<=", "(?<!", "(?>", "(?(", "++", "*+", "?+", "\\k<",
        "\\Q", "\\E", "\\G", "\\R", "\\X", "\\h", "\\Z", "\\p{Is",
    )
    private val BACK_REFERENCE = Regex("\\\\[1-9]")

    /**
     * mihomo's Hysteria2 `hop-interval` is a number (or a range) of seconds, not a Go
     * duration: "30s" makes `utils.NewUnsignedRange` reject the whole outbound. Links
     * and panels spell it both ways, so durations are converted; a value the core would
     * reject is dropped and the core's 30-second default stands.
     */
    private fun hopInterval(raw: String): String? {
        val value = raw.trim()
        if (value.isEmpty()) return null
        if (value.matches(HOP_SECONDS)) return value
        val match = HOP_DURATION.matchEntire(value) ?: return null
        val amount = match.groupValues[1].toDoubleOrNull() ?: return null
        val factor = when (match.groupValues[2]) {
            "ms" -> 0.001
            "s" -> 1.0
            "m" -> 60.0
            else -> 3600.0
        }
        return (amount * factor).roundToLong().coerceAtLeast(1).toString()
    }

    private val HOP_SECONDS = Regex("\\d+(?:-\\d+)?")
    private val HOP_DURATION = Regex("^(\\d+(?:\\.\\d+)?)(ms|s|m|h)$")

    /**
     * Whether a bare matcher really is an address. mihomo parses `IP-CIDR` with
     * `netip.ParsePrefix`, which rejects the whole document over one bad rule, so
     * "999.999.999.999" must never reach it: a shape check alone is not enough.
     */
    private fun isNumericAddress(value: String): Boolean {
        val address = value.substringBefore('/')
        val prefix = value.substringAfter('/', "")
        val v6 = ':' in address
        if (prefix.isNotEmpty()) {
            val bits = prefix.toIntOrNull() ?: return false
            if (bits !in 0..(if (v6) 128 else 32)) return false
            if (prefix.length > 1 && prefix.startsWith('0')) return false
        }
        return if (v6) isIpv6(address) else isIpv4(address)
    }

    private fun isIpv4(value: String): Boolean {
        val parts = value.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all { it in '0'..'9' } &&
                (part.length == 1 || !part.startsWith('0')) && part.toInt() <= 255
        }
    }

    private fun isIpv6(value: String): Boolean {
        if (value.isEmpty()) return false
        val halves = value.split("::")
        if (halves.size > 2) return false
        fun groups(part: String): List<String> = if (part.isEmpty()) emptyList() else part.split(':')
        val head = groups(halves[0])
        var tail = groups(if (halves.size == 2) halves[1] else "")
        // The tail may end with an embedded IPv4 address ("::ffff:1.2.3.4"), which
        // counts as two groups.
        val embeddedV4 = tail.isNotEmpty() && '.' in tail.last()
        if (embeddedV4) {
            if (!isIpv4(tail.last())) return false
            tail = tail.dropLast(1)
        }
        fun validGroup(group: String) =
            group.length in 1..4 && group.all { it in '0'..'9' || it.lowercaseChar() in 'a'..'f' }
        if (!head.all(::validGroup) || !tail.all(::validGroup)) return false
        val count = head.size + tail.size + if (embeddedV4) 2 else 0
        return if (halves.size == 2) count <= 7 else count == 8
    }

    /** The Xray tag the rule pointed at, mapped onto this session's target. */
    private fun targetOf(rule: JsonObject, fallthrough: String): String? {
        val tag = ((rule["outboundTag"] ?: rule["balancerTag"]) as? JsonPrimitive)
            ?.contentOrNull?.trim()?.lowercase() ?: return fallthrough
        return when (tag) {
            "direct", "freedom", "bypass" -> DIRECT_TAG
            "block", "blackhole" -> REJECT_TAG
            else -> fallthrough
        }
    }

    private fun strategyGroup(strategy: String): String = when (strategy.lowercase()) {
        // A select group has no controller here and would stay pinned to its first member
        // forever; Xray's random had no mihomo twin, round-robin is the closest honest
        // answer to both.
        "roundrobin", "random" -> "load-balance"
        "leastping", "leastload" -> "url-test"
        else -> "load-balance"
    }

    /**
     * The names the device's own resolver answers for: the private zones every home and
     * office network keeps inside, plus the bypass region's own suffix, whose sites are
     * meant to travel direct and whose DNS is often the only one that answers locally.
     */
    private fun dnsPolicy(mode: RoutingMode): Map<String, List<String>> {
        val system = listOf("system")
        val policy = linkedMapOf<String, List<String>>()
        PRIVATE_ZONES.forEach { policy[it] = system }
        mode.region?.let { region ->
            policy["+.$region"] = system
            when (region) {
                "ru" -> policy["geosite:category-ru"] = system
                "ir" -> policy["geosite:category-ir"] = system
                "cn" -> policy["geosite:cn"] = system
            }
        }
        return policy
    }

    private val PRIVATE_ZONES = listOf("+.lan", "+.local", "+.home.arpa", "localhost")

    // ------------------------------------------------------------------ proxies

    private fun emitProxy(y: Yaml, profile: ProfileEntity, tag: String) {
        y.item(2, "name: ${quote(tag)}")
        y.key(4, "type", quote(proxyType(profile.type)))
        y.key(4, "server", quote(profile.server))
        y.key(4, "port", profile.serverPort.toString())
        // Every type carries the flag: mihomo refuses UDP — DNS included — through a
        // proxy that has not declared support for it. A panel that says `udp: false`
        // knows its server, unless the protocol is UDP by nature.
        val udp = when (profile.type) {
            ProfileType.WIREGUARD, ProfileType.HYSTERIA2, ProfileType.TUIC,
            ProfileType.SHADOWQUIC, ProfileType.MASQUE -> true
            else -> extraFlag(profile, "udp") ?: true
        }
        y.key(4, "udp", udp.toString())
        // Everything the typed columns do not cover: plugins, obfs, ECH, mux, sudoku
        // tables, snell version — whatever the panel's YAML carried.
        emitExtras(y, profile, handledKeys(profile.type))

        when (profile.type) {
            ProfileType.VMESS -> {
                y.key(4, "uuid", quote(profile.password))
                // Rows imported before the column existed kept the panel's value in
                // extraOptions; keep honouring it until the next refresh rewrites them.
                val alterId = profile.alterId.takeIf { it > 0 }
                    ?: (extraObject(profile)?.get("alterId") as? JsonPrimitive)?.contentOrNull?.toIntOrNull()
                    ?: 0
                y.key(4, "alterId", alterId.toString())
                y.key(4, "cipher", quote(profile.method.ifEmpty { "auto" }))
                emitTransport(y, profile, alwaysNetwork = true)
                emitTls(y, profile)
            }

            ProfileType.VLESS -> {
                y.key(4, "uuid", quote(profile.password))
                if (profile.flow.isNotEmpty()) y.key(4, "flow", quote(profile.flow))
                if (profile.method.isNotEmpty() && !profile.method.equals("none", true)) {
                    // mihomo only speaks plain VLESS; a non-"none" encryption is a server quirk.
                    y.key(4, "encryption", quote(profile.method))
                }
                emitTransport(y, profile, alwaysNetwork = false)
                emitTls(y, profile)
            }

            ProfileType.TROJAN -> {
                y.key(4, "password", quote(profile.password))
                emitTransport(y, profile, alwaysNetwork = false)
                emitTls(y, profile, defaultTls = true, sniKey = "sni")
            }

            ProfileType.SHADOWSOCKS -> {
                y.key(4, "cipher", quote(profile.method))
                y.key(4, "password", quote(profile.password))
            }

            ProfileType.SOCKS -> {
                if (profile.username.isNotEmpty()) y.key(4, "username", quote(profile.username))
                if (profile.password.isNotEmpty()) y.key(4, "password", quote(profile.password))
            }

            ProfileType.HTTP -> {
                if (profile.username.isNotEmpty()) y.key(4, "username", quote(profile.username))
                if (profile.password.isNotEmpty()) y.key(4, "password", quote(profile.password))
                // `fingerprint` on an HTTP outbound is a certificate pin, not the
                // browser fingerprint a link's `fp` carries; the typed column is a
                // browser value, so it stays out.
                emitTls(y, profile, sniKey = "sni", alpnSupported = false, fingerprintKey = "")
            }

            ProfileType.WIREGUARD -> {
                y.key(4, "private-key", quote(profile.wgSecretKey))
                y.key(4, "public-key", quote(profile.publicKey))
                if (profile.wgPresharedKey.isNotEmpty()) y.key(4, "pre-shared-key", quote(profile.wgPresharedKey))
                val (ipv4, ipv6) = wireguardAddresses(profile)
                y.key(4, "ip", quote(ipv4 ?: "10.0.0.2/32"))
                if (ipv6 != null) y.key(4, "ipv6", quote(ipv6))
                y.key(4, "mtu", (if (profile.wgMtu > 0) profile.wgMtu else 1420).toString())
                reservedOf(profile)?.let { y.key(4, "reserved", it) }
                if (profile.wgKeepalive > 0) y.key(4, "persistent-keepalive", profile.wgKeepalive.toString())
                y.key(4, "remote-dns-resolve", "true")
                y.items(4, "dns", wireguardDns(profile).map(::quote))
                emitAmnezia(y, profile)
            }

            ProfileType.HYSTERIA2 -> {
                y.key(4, "password", quote(profile.password))
                if (profile.sni.isNotEmpty()) y.key(4, "sni", quote(profile.sni))
                y.key(4, "skip-cert-verify", profile.allowInsecure.toString())
                y.items(4, "alpn", listOf("h3"))
                // Hysteria2's `fingerprint` is a certificate pin, not a browser
                // fingerprint: a link's `fp=qq` here is hex-decoded and fails the whole
                // outbound. mihomo's Hysteria2 has no uTLS option, so it stays out.
                if (profile.obfsPassword.isNotEmpty()) {
                    y.key(4, "obfs", "salamander")
                    y.key(4, "obfs-password", quote(profile.obfsPassword))
                }
                profile.hysteriaUpMbps?.let { y.key(4, "up", it.toString()) }
                profile.hysteriaDownMbps?.let { y.key(4, "down", it.toString()) }
                if (profile.portHopping.isNotEmpty()) y.key(4, "ports", quote(profile.portHopping))
                hopInterval(profile.portHoppingInterval)?.let { y.key(4, "hop-interval", quote(it)) }
            }

            ProfileType.TUIC -> {
                y.key(4, "uuid", quote(profile.username))
                y.key(4, "password", quote(profile.password))
                // TUIC's `fingerprint` is a certificate pin; a link's `fp` is a browser
                // fingerprint and has no field here. The pin from a panel stays in
                // extraOptions and passes through untouched.
                emitTls(y, profile, sniKey = "sni", tlsFlag = false, fingerprintKey = "")
            }

            ProfileType.ANYTLS -> {
                y.key(4, "password", quote(profile.password))
                emitTls(y, profile, sniKey = "sni", tlsFlag = false)
            }

            ProfileType.SNELL -> {
                y.key(4, "psk", quote(profile.password))
            }

            ProfileType.MIERU -> {
                y.key(4, "username", quote(profile.username))
                y.key(4, "password", quote(profile.password))
                y.key(4, "transport", quote(profile.network.ifEmpty { "tcp" }.uppercase()))
            }

            ProfileType.SUDOKU -> {
                y.key(4, "key", quote(profile.password))
            }

            ProfileType.SHADOWQUIC -> {
                y.key(4, "username", quote(profile.username))
                y.key(4, "password", quote(profile.password))
                // ShadowQuic has no uTLS fingerprint option; an unknown key is noise.
                emitTls(y, profile, sniKey = "sni", tlsFlag = false, fingerprintKey = "")
            }

            ProfileType.TRUSTTUNNEL -> {
                y.key(4, "username", quote(profile.username))
                y.key(4, "password", quote(profile.password))
                emitTls(y, profile, sniKey = "sni", tlsFlag = false)
            }

            // MASQUE is the core's own dialect, and the panel's map is already in it:
            // the keypair, the SNI and the transport ride along in extraOptions and are
            // written there untouched. Nothing here has a column of its own.
            ProfileType.MASQUE -> Unit

            ProfileType.BALANCER -> error("a balancer is not an outbound")
        }
    }

    private fun proxyType(type: ProfileType): String = when (type) {
        ProfileType.VMESS -> "vmess"
        ProfileType.VLESS -> "vless"
        ProfileType.TROJAN -> "trojan"
        ProfileType.SHADOWSOCKS -> "ss"
        ProfileType.SOCKS -> "socks5"
        ProfileType.HTTP -> "http"
        ProfileType.WIREGUARD -> "wireguard"
        ProfileType.HYSTERIA2 -> "hysteria2"
        ProfileType.TUIC -> "tuic"
        ProfileType.ANYTLS -> "anytls"
        ProfileType.SNELL -> "snell"
        ProfileType.MIERU -> "mieru"
        ProfileType.SUDOKU -> "sudoku"
        ProfileType.SHADOWQUIC -> "shadowquic"
        ProfileType.TRUSTTUNNEL -> "trusttunnel"
        ProfileType.MASQUE -> "masque"
        ProfileType.BALANCER -> error("a balancer is not an outbound")
    }

    /**
     * The tunnel's own addresses, split the way the core wants them: `ip` and `ipv6` are
     * separate keys, and the first of each family wins. A Clash-imported profile keeps
     * its v6 in extraOptions, a .conf's Address line carries both comma-separated.
     */
    private fun wireguardAddresses(profile: ProfileEntity): Pair<String?, String?> {
        val declared = profile.wgLocalAddress.split(',').map { it.trim() }.filter { it.isNotEmpty() } +
            extraStrings(profile, "ipv6")
        val v4 = declared.firstOrNull { it.contains('.') && !it.contains(':') }
        val v6 = declared.firstOrNull { it.contains(':') }
        return (v4?.let { withHostPrefix(it) }) to (v6?.let { withHostPrefix(it) })
    }

    private fun wireguardDns(profile: ProfileEntity): List<String> =
        extraStrings(profile, "dns").ifEmpty { listOf("1.1.1.1", "8.8.8.8") }

    /** A string list out of [ProfileEntity.extraOptions]; empty when the key is absent. */
    private fun extraStrings(profile: ProfileEntity, key: String): List<String> {
        if (profile.extraOptions.isBlank()) return emptyList()
        val element = runCatching {
            (Json.parseToJsonElement(profile.extraOptions) as? JsonObject)?.get(key)
        }.getOrNull() ?: return emptyList()
        return when (element) {
            is JsonArray -> element.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            is JsonPrimitive -> listOfNotNull(element.contentOrNull)
            else -> emptyList()
        }.filter { it.isNotBlank() }
            .map { it.trim() }
    }

    private fun reservedOf(profile: ProfileEntity): String? {
        val bytes = profile.wgReserved.split(',').mapNotNull { it.trim().toIntOrNull() }
        return if (bytes.size == 3) "[${bytes.joinToString(", ")}]" else null
    }

    /**
     * The AmneziaWG block: the obfuscation knobs the profile came with, straight into the
     * core's `amnezia-wg-option`. Strings are quoted — the i1..i5 patterns carry angle
     * brackets and spaces, and a bare scalar would break the document.
     */
    private fun emitAmnezia(y: Yaml, profile: ProfileEntity) {
        val raw = profile.wgAmnezia
        if (raw.isBlank()) return
        val options = runCatching { Json.parseToJsonElement(raw) as? JsonObject }.getOrNull() ?: return
        if (options.isEmpty()) return
        y.block(4, "amnezia-wg-option") {
            options.forEach { (key, value) ->
                val primitive = value as? JsonPrimitive ?: return@forEach
                val text = booleanLiteral(key, primitive)
                    ?: if (primitive.isString) quote(primitive.content) else primitive.content
                y.key(6, quote(key), text)
            }
        }
    }

    // ----------------------------------------------------------- extra options

    /**
     * What the typed emitter writes for a protocol. Everything else in
     * [ProfileEntity.extraOptions] is passed through as-is, so a panel's plugin,
     * obfs, ECH, mux and quic knobs survive without a column each.
     */
    private fun handledKeys(type: ProfileType): Set<String> {
        val common = setOf("udp", "name", "type", "server", "port")
        val tls = setOf("tls", "servername", "sni", "skip-cert-verify", "client-fingerprint", "alpn")
        return common + when (type) {
            ProfileType.VMESS -> setOf(
                "uuid", "alterId", "cipher", "network", "ws-opts", "grpc-opts", "xhttp-opts", "reality-opts",
                "http-opts", "h2-opts", "mkcp-opts",
            ) + tls
            ProfileType.VLESS -> setOf(
                "uuid", "flow", "encryption", "network", "ws-opts", "grpc-opts", "xhttp-opts", "reality-opts",
                "http-opts", "h2-opts",
            ) + tls
            ProfileType.TROJAN -> setOf("password", "network", "ws-opts", "grpc-opts", "reality-opts") + tls
            ProfileType.SHADOWSOCKS -> setOf("cipher", "password")
            ProfileType.SOCKS -> setOf("username", "password")
            ProfileType.HTTP -> setOf("username", "password") + tls
            ProfileType.WIREGUARD -> setOf(
                "private-key", "public-key", "pre-shared-key", "ip", "ipv6", "mtu", "reserved",
                "persistent-keepalive", "remote-dns-resolve", "dns", "amnezia-wg-option",
            )
            ProfileType.HYSTERIA2 -> setOf(
                "password", "obfs", "obfs-password", "ports", "up", "down", "hop-interval",
            ) + tls
            ProfileType.TUIC -> setOf("uuid", "password") + tls
            ProfileType.ANYTLS -> setOf("password") + tls
            ProfileType.SNELL -> setOf("psk")
            ProfileType.MIERU -> setOf("username", "password", "transport")
            ProfileType.SUDOKU -> setOf("key")
            ProfileType.SHADOWQUIC -> setOf("username", "password") + tls
            ProfileType.TRUSTTUNNEL -> setOf("username", "password") + tls
            // Every other key is the core's own vocabulary: pass the map through.
            ProfileType.MASQUE -> common
            ProfileType.BALANCER -> emptySet()
        }
    }

    private fun emitExtras(y: Yaml, profile: ProfileEntity, handled: Set<String>) {
        val options = extraObject(profile) ?: return
        options.forEach { (key, value) ->
            // A chained dialer points at another proxy tag; the document has one node,
            // so the reference could only fail the whole config.
            if (key == "dialer-proxy") return@forEach
            if (key !in handled) emitJsonValue(y, 4, key, value)
        }
    }

    /** The profile's extra options as a map, or null when it carries none. */
    private fun extraObject(profile: ProfileEntity): JsonObject? {
        if (profile.extraOptions.isBlank()) return null
        return runCatching {
            Json.parseToJsonElement(profile.extraOptions) as? JsonObject
        }.getOrNull()
    }

    /** A boolean the profile's panel set in its extra options, or null when absent. */
    private fun extraFlag(profile: ProfileEntity, key: String): Boolean? {
        val value = extraObject(profile)?.get(key) as? JsonPrimitive ?: return null
        if (value.isString) {
            return when (value.content.trim().lowercase(Locale.ROOT)) {
                "true", "1", "yes", "on" -> true
                "false", "0", "no", "off" -> false
                else -> null
            }
        }
        return value.content.toBooleanStrictOrNull()
    }

    /**
     * The option keys mihomo types as booleans, across every outbound and its plugin
     * options. Link query strings and panel YAML often spell them "true"/"1"; the
     * core's decoder accepts a YAML boolean and nothing else, and one string there
     * fails the whole document.
     */
    private val booleanOptions = setOf(
        "udp", "tfo", "mptcp", "xudp", "packet-addr", "tls", "skip-cert-verify",
        "reduce-rtt", "disable-sni", "udp-over-stream", "zero-rtt", "disable-mtu-discovery",
        "http-mask", "http-mask-tls", "enable-pure-downlink",
        "enabled", "enable", "disabled", "disable", "insecure",
        "disable-reuse", "quic", "health-check", "remote-dns-resolve", "fast-open",
        "reuse", "random-trailers", "disable-cookies", "udp-over-tcp",
        "no-grpc-header", "x-padding-obfs-mode", "global-padding", "authenticated-length",
        "v2ray-http-upgrade", "v2ray-http-upgrade-fast-open", "congestion",
        // Plugin options (the core decodes plugin-opts a second time, same rules).
        "mux", "nocomp", "acknodelay", "force-tls12",
        // Rarer outbounds the core also knows; a panel may still carry their flags.
        "connection-ready", "connection-recall-exit", "dhcp", "encrypted-hello",
        "ephemeral", "forward", "h2-do-not-wait-for-download-finish", "low-bandwidth",
        "only-tcp", "padding", "sequence-watermarking-enabled", "statistic",
        "support-x25519mlkem768", "accept-dns", "accept-routes", "exit-node-allow-lan-access",
        "disable-kcp-input", "disable-p2p", "disable-quic-input", "enable-encryption",
        "enable-exit-node", "enable-kcp-proxy", "enable-quic-proxy", "latency-first",
        "no-listener", "private-mode", "secure-mode",
    )

    /** "true"/"1" (and friends) on a boolean option as the literal the core parses. */
    private fun booleanLiteral(key: String, value: JsonPrimitive): String? {
        if (!value.isString) return null
        if (key.lowercase(Locale.ROOT).replace('_', '-') !in booleanOptions) return null
        return when (value.content.trim().lowercase(Locale.ROOT)) {
            "true", "1", "yes", "on" -> "true"
            "false", "0", "no", "off" -> "false"
            else -> null
        }
    }

    private fun emitJsonValue(y: Yaml, indent: Int, key: String, value: JsonElement) {
        // The panel decides the key's spelling, not us: a colon or a newline in it must not
        // end the line or start a new mapping.
        val name = quote(key)
        when (value) {
            is JsonObject -> if (value.isEmpty()) y.key(indent, name, "{}") else y.block(indent, name) {
                value.forEach { (childKey, child) -> emitJsonValue(y, indent + 2, childKey, child) }
            }
            is JsonArray -> y.key(indent, name, value.toString())
            is JsonPrimitive -> y.key(
                indent,
                name,
                booleanLiteral(key, value) ?: if (value.isString) quote(value.content) else value.content,
            )
        }
    }

    // ---------------------------------------------------------------- stream

    private fun emitTransport(y: Yaml, profile: ProfileEntity, alwaysNetwork: Boolean) {
        when (profile.network.ifEmpty { "tcp" }) {
            "ws", "websocket" -> {
                y.key(4, "network", "ws")
                emitWsOpts(y, profile)
            }

            "httpupgrade" -> {
                // mihomo has no httpupgrade transport of its own: it is a WebSocket
                // handshake with the upgrade flag set.
                y.key(4, "network", "ws")
                emitWsOpts(y, profile, httpUpgrade = true)
            }

            "grpc" -> {
                y.key(4, "network", "grpc")
                emitGrpcOpts(y, profile)
            }

            "xhttp", "splithttp" -> {
                y.key(4, "network", "xhttp")
                emitXhttpOpts(y, profile)
            }

            "kcp", "mkcp" -> {
                if (profile.type == ProfileType.VMESS) {
                    y.key(4, "network", "mkcp")
                    emitKcpOpts(y, profile)
                } else if (alwaysNetwork) {
                    y.key(4, "network", "tcp")
                }
            }

            "http" -> if (profile.type == ProfileType.VMESS || profile.type == ProfileType.VLESS) {
                y.key(4, "network", "http")
                emitHttpOpts(y, profile)
            } else if (alwaysNetwork) {
                y.key(4, "network", "tcp")
            }

            "h2" -> if (profile.type == ProfileType.VMESS || profile.type == ProfileType.VLESS) {
                y.key(4, "network", "h2")
                emitH2Opts(y, profile)
            } else if (alwaysNetwork) {
                y.key(4, "network", "tcp")
            }

            // Xray's TCP-with-HTTP-header obfuscation is mihomo's HTTP transport.
            "tcp" -> if (profile.headerType.equals("http", ignoreCase = true) &&
                (profile.type == ProfileType.VMESS || profile.type == ProfileType.VLESS)
            ) {
                y.key(4, "network", "http")
                emitHttpOpts(y, profile)
            } else if (alwaysNetwork) {
                y.key(4, "network", "tcp")
            }

            else -> if (alwaysNetwork) y.key(4, "network", "tcp")
        }
    }

    /** The option map a panel's Clash entry carried, or null when it had none. */
    private fun panelObject(profile: ProfileEntity, key: String): JsonObject? =
        extraObject(profile)?.get(key) as? JsonObject

    /** The first string of a scalar-or-list value, as Clash writes hosts and paths. */
    private fun firstString(value: JsonElement?): String? = when (value) {
        is JsonPrimitive -> value.contentOrNull?.takeIf { it.isNotEmpty() }
        is JsonArray -> (value.firstOrNull() as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotEmpty() }
        else -> null
    }

    /**
     * A WebSocket/XHTTP header, whose core type is a plain string. A panel that wrote
     * the value as a list gets its first entry; the array itself would fail decoding.
     */
    private fun emitHeader(y: Yaml, indent: Int, key: String, value: JsonElement) {
        val text = firstString(value) ?: return
        y.key(indent, quote(key), quote(text))
    }

    /** An HTTP transport header: the core's type is a list, even for one value. */
    private fun emitHttpHeader(y: Yaml, indent: Int, key: String, value: JsonElement) {
        when (value) {
            is JsonArray -> y.items(
                indent,
                quote(key),
                value.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }.map(::quote),
            )
            is JsonPrimitive -> if (value.contentOrNull?.isNotEmpty() == true) {
                y.items(indent, quote(key), listOf(quote(value.content)))
            }
            else -> Unit
        }
    }

    private fun emitWsOpts(y: Yaml, profile: ProfileEntity, httpUpgrade: Boolean = false) {
        val panel = panelObject(profile, "ws-opts")
        val path = profile.path.ifEmpty { panel?.primitive("path") ?: "/" }
        val panelHeaders = panel?.get("headers") as? JsonObject
        y.block(4, "ws-opts") {
            y.key(6, "path", quote(path))
            if (profile.host.isNotEmpty() || panelHeaders?.isNotEmpty() == true) {
                y.block(6, "headers") {
                    if (profile.host.isNotEmpty()) y.key(8, "Host", quote(profile.host))
                    panelHeaders?.forEach { (key, value) ->
                        // The typed host wins; a panel that kept it only in its map
                        // still gets it through.
                        if (!key.equals("Host", ignoreCase = true) || profile.host.isEmpty()) {
                            emitHeader(y, 8, key, value)
                        }
                    }
                }
            }
            if (httpUpgrade) y.key(6, "v2ray-http-upgrade", "true")
            panel?.forEach { (key, value) ->
                // path/headers are written from the typed columns above; with an
                // httpupgrade transport the flag is already true. A plain ws entry
                // may carry the flag itself — that is the Clash way of saying it.
                if (key in setOf("path", "headers")) return@forEach
                if (httpUpgrade && key == "v2ray-http-upgrade") return@forEach
                emitJsonValue(y, 6, key, value)
            }
        }
    }

    private fun emitGrpcOpts(y: Yaml, profile: ProfileEntity) {
        val panel = panelObject(profile, "grpc-opts")
        val service = profile.serviceName.ifEmpty { panel?.primitive("grpc-service-name").orEmpty() }
        y.block(4, "grpc-opts") {
            y.key(6, "grpc-service-name", quote(service))
            panel?.forEach { (key, value) ->
                if (key != "grpc-service-name") emitJsonValue(y, 6, key, value)
            }
        }
    }

    private fun emitHttpOpts(y: Yaml, profile: ProfileEntity) {
        val panel = panelObject(profile, "http-opts")
        val path = profile.path.ifEmpty { firstString(panel?.get("path")) ?: "/" }
        val panelHeaders = panel?.get("headers") as? JsonObject
        val host = profile.host.ifEmpty {
            panelHeaders?.entries?.firstOrNull { it.key.equals("Host", ignoreCase = true) }
                ?.value?.let(::firstString).orEmpty()
        }
        y.block(4, "http-opts") {
            y.items(6, "path", listOf(quote(path)))
            if (host.isNotEmpty() || panelHeaders?.isNotEmpty() == true) {
                y.block(6, "headers") {
                    if (host.isNotEmpty()) y.items(8, "Host", listOf(quote(host)))
                    panelHeaders?.forEach { (key, value) ->
                        if (!key.equals("Host", ignoreCase = true) || host.isEmpty()) {
                            emitHttpHeader(y, 8, key, value)
                        }
                    }
                }
            }
            panel?.forEach { (key, value) ->
                if (key !in setOf("path", "headers")) emitJsonValue(y, 6, key, value)
            }
        }
    }

    private fun emitH2Opts(y: Yaml, profile: ProfileEntity) {
        val panel = panelObject(profile, "h2-opts")
        val host = profile.host.ifEmpty { firstString(panel?.get("host")).orEmpty() }
        val path = profile.path.ifEmpty { panel?.primitive("path") ?: "/" }
        y.block(4, "h2-opts") {
            if (host.isNotEmpty()) y.items(6, "host", listOf(quote(host)))
            y.key(6, "path", quote(path))
            panel?.forEach { (key, value) ->
                if (key !in setOf("host", "path")) emitJsonValue(y, 6, key, value)
            }
        }
    }

    private fun emitKcpOpts(y: Yaml, profile: ProfileEntity) {
        val panel = panelObject(profile, "mkcp-opts")
        y.block(4, "mkcp-opts") {
            if (profile.seed.isNotEmpty()) y.key(6, "seed", quote(profile.seed))
            if (profile.headerType.isNotEmpty()) y.key(6, "header", quote(profile.headerType))
            panel?.forEach { (key, value) ->
                val overridden = (key == "seed" && profile.seed.isNotEmpty()) ||
                    (key == "header" && profile.headerType.isNotEmpty())
                if (!overridden) emitJsonValue(y, 6, key, value)
            }
        }
    }

    private fun emitXhttpOpts(y: Yaml, profile: ProfileEntity) {
        val panel = panelObject(profile, "xhttp-opts")
        val extra = xhttpExtra(profile) ?: (panel?.get("extra") as? JsonObject)
        val path = profile.path.ifEmpty { panel?.primitive("path") ?: "/" }
        val mode = profile.mode.ifEmpty { panel?.primitive("mode") ?: "auto" }
        val panelHeaders = panel?.get("headers") as? JsonObject
        val extraHeaders = extra?.get("headers") as? JsonObject
        y.block(4, "xhttp-opts") {
            y.key(6, "path", quote(path))
            y.key(6, "mode", quote(mode))
            if (profile.host.isNotEmpty() || panelHeaders?.isNotEmpty() == true || extraHeaders?.isNotEmpty() == true) {
                y.block(6, "headers") {
                    if (profile.host.isNotEmpty()) y.key(8, "Host", quote(profile.host))
                    panelHeaders?.forEach { (key, value) ->
                        if (!key.equals("Host", ignoreCase = true) || profile.host.isEmpty()) {
                            emitHeader(y, 8, key, value)
                        }
                    }
                    extraHeaders?.forEach { (key, value) ->
                        // The typed host wins; a link that kept it only in `extra` still
                        // gets it through.
                        if (!key.equals("Host", ignoreCase = true) || profile.host.isEmpty()) {
                            emitHeader(y, 8, key, value)
                        }
                    }
                }
            }
            // The panel's own xhttp options ride as they came (the core's spelling),
            // while path/mode/headers above stay the typed values.
            val written = mutableSetOf("path", "mode", "headers", "extra")
            panel?.forEach { (key, value) ->
                if (key !in written) {
                    // The core refuses a split download in stream-one mode; the
                    // setting goes rather than the whole outbound.
                    if (key == "download-settings" && mode.equals("stream-one", ignoreCase = true)) {
                        return@forEach
                    }
                    emitJsonValue(y, 6, key, value)
                    written += normalizedKey(key)
                }
            }
            // The share link's `extra` and a panel's xhttp settings ride here: same
            // values, Xray's camelCase turned into the kebab-case the core reads.
            extra?.forEach { (key, value) ->
                val target = kebabKey(key)
                val normalized = normalizedKey(target)
                when {
                    key in setOf("path", "mode", "headers") -> Unit
                    normalized in written -> Unit
                    target == "download-settings" -> {
                        // mihomo refuses the whole outbound when a split download is
                        // asked for in stream-one mode ("xhttp mode \"stream-one\"
                        // cannot be used with download-settings"), so the setting goes
                        // rather than the tunnel.
                        if (mode.equals("stream-one", ignoreCase = true)) return@forEach
                        val settings = value as? JsonObject ?: return@forEach
                        if (settings.isEmpty()) return@forEach
                        // A panel in the core's own spelling already: nothing to
                        // translate, the tree goes through as it came.
                        if (settings.isXrayDownloadTree()) emitDownloadSettings(y, 6, settings)
                        else emitJsonValue(y, 6, "download-settings", kebabTree(settings))
                        written += normalized
                    }
                    else -> {
                        emitJsonValue(y, 6, target, kebabTree(value))
                        written += normalized
                    }
                }
            }
        }
    }

    private fun normalizedKey(key: String): String =
        key.lowercase(Locale.ROOT).replace('_', '-')

    /** The Xray-style extra object of an XHTTP profile; null when absent or malformed. */
    private fun xhttpExtra(profile: ProfileEntity): JsonObject? {
        val raw = profile.xhttpExtra ?: return null
        if (raw.isBlank()) return null
        return runCatching {
            Json.parseToJsonElement(raw) as? JsonObject
        }.getOrNull()
    }

    /**
     * The Xray `downloadSettings` tree, rewritten as the flat object mihomo reads.
     *
     * The core's `XHTTPDownloadSettings` has no `address`, `security`, `tlsSettings`,
     * `realitySettings` or `xhttpSettings`: the server sits next to `tls`, the TLS flags
     * next to `path`, and REALITY keeps its own block. This mirrors the core's own
     * share-link converter (`common/convert/v.go`); a blanket kebab-case pass would hand
     * it keys it never reads, and the split download would go quiet.
     *
     * Nothing is written when there is nothing to translate: an empty block would only
     * arm the same settings without a value.
     */
    private fun emitDownloadSettings(y: Yaml, indent: Int, ds: JsonObject) {
        val scalars = linkedMapOf<String, String>()
        ds.primitive("address")?.takeIf { it.isNotEmpty() }?.let { scalars["server"] = quote(it) }
        ds.primitive("port")?.toIntOrNull()?.let { scalars["port"] = it.toString() }

        val security = ds.primitive("security")?.lowercase(Locale.ROOT)
        val tls = security == "tls" || security == "reality"
        val tlsSettings = ds["tlsSettings"] as? JsonObject
        val alpn = if (tls) {
            (tlsSettings?.get("alpn") as? JsonArray)
                ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull?.takeIf { value -> value.isNotEmpty() } }
                ?.takeIf { it.isNotEmpty() }
        } else null
        if (tls) {
            scalars["tls"] = "true"
            tlsSettings?.primitive("serverName")?.takeIf { it.isNotEmpty() }?.let { scalars["servername"] = quote(it) }
            tlsSettings?.primitive("fingerprint")?.takeIf { it.isNotEmpty() }?.let { scalars["client-fingerprint"] = quote(it) }
            if (tlsSettings?.flag("allowInsecure") == true) scalars["skip-cert-verify"] = "true"
        }

        val reality = ds["realitySettings"] as? JsonObject
        val realityOpts = linkedMapOf<String, String>()
        if (tls && security == "reality") {
            reality?.primitive("publicKey")?.takeIf { it.isNotEmpty() }?.let { realityOpts["public-key"] = quote(it) }
            reality?.primitive("shortId")?.takeIf { it.isNotEmpty() }?.let { realityOpts["short-id"] = quote(it) }
        }

        val xhttp = ds["xhttpSettings"] as? JsonObject
        xhttp?.primitive("path")?.takeIf { it.isNotEmpty() }?.let { scalars["path"] = quote(it) }
        xhttp?.primitive("host")?.takeIf { it.isNotEmpty() }?.let { scalars["host"] = quote(it) }
        val headers = (xhttp?.get("headers") as? JsonObject)?.takeIf { it.isNotEmpty() }
        val xmux = ((xhttp?.get("extra") as? JsonObject)?.get("xmux") as? JsonObject)?.takeIf { it.isNotEmpty() }

        if (scalars.isEmpty() && alpn == null && headers == null && realityOpts.isEmpty() && xmux == null) return

        y.block(indent, "download-settings") {
            scalars.forEach { (key, value) -> y.key(indent + 2, key, value) }
            alpn?.let { y.items(indent + 2, "alpn", it.map(::quote)) }
            if (realityOpts.isNotEmpty()) {
                y.block(indent + 2, "reality-opts") {
                    realityOpts.forEach { (key, value) -> y.key(indent + 4, key, value) }
                }
            }
            headers?.let {
                y.block(indent + 2, "headers") {
                    it.forEach { (key, value) -> emitJsonValue(y, indent + 4, key, value) }
                }
            }
            // xmux inside the download's xhttp settings is the same reuse-settings the
            // root extra carries.
            xmux?.let {
                y.block(indent + 2, "reuse-settings") {
                    val tree = kebabTree(it) as JsonObject
                    tree.forEach { (key, value) -> emitJsonValue(y, indent + 4, key, value) }
                }
            }
        }
    }

    /** The string a JSON leaf carries; numbers lose nothing a proxy option needs. */
    private fun JsonObject.primitive(key: String): String? =
        (this[key] as? JsonPrimitive)?.contentOrNull?.trim()

    /** A JSON boolean, spelled the way a leaf may spell it. */
    private fun JsonObject.flag(key: String): Boolean =
        (this[key] as? JsonPrimitive)?.contentOrNull?.toBooleanStrictOrNull() == true

    /**
     * Whether a `downloadSettings` object is Xray's tree rather than the core's flat
     * object: only the tree has the fields the translation consumes.
     */
    private fun JsonObject.isXrayDownloadTree(): Boolean =
        listOf("address", "security", "tlsSettings", "realitySettings", "xhttpSettings")
            .any { containsKey(it) }

    private val camelBoundary = Regex("([a-z0-9])([A-Z])")
    private val acronymBoundary = Regex("([A-Z]+)([A-Z][a-z])")

    /** Xray spells its XHTTP knobs camelCase; mihomo's proxy tags are kebab-case. */
    private fun kebabKey(key: String): String {
        when (key.lowercase(Locale.ROOT)) {
            "xmux" -> return "reuse-settings"
            // The core spells the session family without the "ID": a blanket kebab pass
            // would hand it session-id-placement, a key it never reads.
            "sessionidplacement" -> return "session-placement"
            "sessionidkey" -> return "session-key"
            "sessionidtable" -> return "session-table"
            "sessionidlength" -> return "session-length"
        }
        return key
            .replace(acronymBoundary, "$1-$2")
            .replace(camelBoundary, "$1-$2")
            .lowercase(Locale.ROOT)
    }

    /** A nested extra object gets the same key treatment, leaf values pass through. */
    private fun kebabTree(value: JsonElement): JsonElement = when (value) {
        is JsonObject -> JsonObject(
            value.entries.associate { (key, child) -> kebabKey(key) to kebabTree(child) },
        )
        is JsonArray -> JsonArray(value.map(::kebabTree))
        else -> value
    }

    private fun emitTls(
        y: Yaml,
        profile: ProfileEntity,
        defaultTls: Boolean = false,
        sniKey: String = "servername",
        alpnSupported: Boolean = true,
        tlsFlag: Boolean = true,
        fingerprintKey: String = "client-fingerprint",
    ) {
        val alpn = profile.alpn.split(',').map { it.trim() }.filter { it.isNotEmpty() }
        when (profile.security) {
            "tls" -> {
                if (tlsFlag) y.key(4, "tls", "true")
                if (profile.sni.isNotEmpty()) y.key(4, sniKey, quote(profile.sni))
                if (profile.allowInsecure) y.key(4, "skip-cert-verify", "true")
                if (fingerprintKey.isNotEmpty() && profile.fingerprint.isNotEmpty()) {
                    y.key(4, fingerprintKey, quote(profile.fingerprint))
                }
                if (alpnSupported && alpn.isNotEmpty()) y.items(4, "alpn", alpn.map(::quote))
            }

            "reality" -> {
                if (tlsFlag) y.key(4, "tls", "true")
                if (profile.sni.isNotEmpty()) y.key(4, sniKey, quote(profile.sni))
                if (fingerprintKey.isNotEmpty() && profile.fingerprint.isNotEmpty()) {
                    y.key(4, fingerprintKey, quote(profile.fingerprint))
                }
                if (alpnSupported && alpn.isNotEmpty()) y.items(4, "alpn", alpn.map(::quote))
                // An empty key is no REALITY at all: writing the block would make the
                // core reject the whole document, so the profile falls back to TLS.
                if (profile.publicKey.isNotEmpty()) {
                    y.block(4, "reality-opts") {
                        y.key(6, "public-key", quote(profile.publicKey))
                        if (profile.shortId.isNotEmpty()) y.key(6, "short-id", quote(profile.shortId))
                    }
                }
            }

            else -> if (defaultTls) {
                // Trojan is TLS by definition: an empty security field means the defaults.
                if (tlsFlag) y.key(4, "tls", "true")
                if (profile.sni.isNotEmpty()) y.key(4, sniKey, quote(profile.sni))
                if (profile.allowInsecure) y.key(4, "skip-cert-verify", "true")
            }
        }
    }
}

/**
 * A tiny line-based YAML writer: the document is flat enough that a full emitter would be
 * more machinery than the job needs. Leaf values go through [quote]; rule lines and list
 * items are written verbatim by design.
 */
internal class Yaml {
    private val sb = StringBuilder()

    fun key(indent: Int, name: String, value: String) {
        sb.append(" ".repeat(indent)).append(name).append(": ").append(value).append('\n')
    }

    fun raw(indent: Int, text: String) {
        sb.append(" ".repeat(indent)).append(text).append('\n')
    }

    /** A sequence item at [indent]: the first line of a map entry, or a bare scalar. */
    fun item(indent: Int, text: String) {
        sb.append(" ".repeat(indent)).append("- ").append(text).append('\n')
    }

    fun block(indent: Int, name: String, body: () -> Unit) {
        sb.append(" ".repeat(indent)).append(name).append(":\n")
        body()
    }

    fun items(indent: Int, name: String, values: List<String>) {
        sb.append(" ".repeat(indent)).append(name).append(":\n")
        values.forEach { sb.append(" ".repeat(indent + 2)).append("- ").append(it).append('\n') }
    }

    override fun toString(): String = sb.toString()
}

internal fun quote(value: String): String {
    // Always quoted. A bare YAML scalar has its own type rules (0x1234 is the integer
    // 4660, .inf is a float, 1_000 is 1000) and its own line rules — a lone CR, NEL, LS
    // or PS ends the line and lets the rest of the value become document structure.
    // Some of these values come from a subscription, that is, from someone else. The
    // document is a couple of kilobytes: there is nothing to save on the quotes.
    val escaped = buildString(value.length + 8) {
        value.forEach { ch ->
            when {
                ch == '\\' -> append("\\\\")
                ch == '"' -> append("\\\"")
                ch == '\n' -> append("\\n")
                ch == '\r' -> append("\\r")
                ch == '\t' -> append("\\t")
                ch.isISOControl() || ch == '\u2028' || ch == '\u2029' ->
                    append("\\u%04x".format(ch.code))
                else -> append(ch)
            }
        }
    }
    return "\"$escaped\""
}
