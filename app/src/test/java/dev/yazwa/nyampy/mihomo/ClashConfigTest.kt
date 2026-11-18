package dev.yazwa.nyampy.mihomo

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import dev.yazwa.nyampy.db.ProfileEntity
import dev.yazwa.nyampy.db.ProfileType
import dev.yazwa.nyampy.mihomo.LocalProxy

/**
 * The pieces of the document that are easy to get silently wrong: the geodata mode the
 * shipped .dat files need, the LAN short-circuit, the balancer strategy, panel rules
 * and the WireGuard address split.
 */
class ClashConfigTest {
    /**
     * The writer takes the loopback inbound from its caller now, so the tests name one
     * place and every document gets the same: only the dedicated test below cares which
     * port and password those are.
     */
    private fun build(
        profile: ProfileEntity,
        mode: RoutingMode,
        members: List<ProfileEntity> = emptyList(),
        knownGeoSite: Set<String>? = null,
        knownGeoIp: Set<String>? = null,
        localProxy: LocalProxy = LocalProxy(10808, "nyampy", "nyampy"),
    ) = ClashConfig.buildFull(
        profile, mode,
        members = members, knownGeoSite = knownGeoSite, knownGeoIp = knownGeoIp,
        localProxy = localProxy,
    )

    private fun vless(name: String = "node") = ProfileEntity(
        id = "", subscriptionId = null, type = ProfileType.VLESS,
        remarks = name, server = "a.example.com", serverPort = 443,
        password = "00000000-1111-2222-3333-444444444444",
    )

    @Test
    fun `geodata mode matches the files that ship in the apk`() {
        val yaml = build(vless(), RoutingMode.GLOBAL)
        assertTrue(yaml.contains("geodata-mode: true"))
    }

    @Test
    fun `private ranges are matched by the lan short-circuit`() {
        val yaml = build(vless(), RoutingMode.GLOBAL)
        assertTrue(yaml.contains("GEOIP,lan,DIRECT,no-resolve"))
        assertFalse(yaml.contains("GEOIP,private"))
    }

    @Test
    fun `the local inbound is authenticated and uses the chosen port`() {
        val proxy = LocalProxy(23456, "nyampy", "deadbeef")
        val yaml = build(vless(), RoutingMode.GLOBAL, localProxy = proxy)
        assertTrue(yaml.contains("mixed-port: 23456"))
        assertTrue(yaml.contains("allow-lan: false"))
        assertTrue(yaml.contains("authentication:"))
        assertTrue(yaml.contains("- \"nyampy:deadbeef\""))
    }

    @Test
    fun `the bypass region suffix carries no leading dot`() {
        val yaml = build(vless(), RoutingMode.BYPASS_RU)
        assertTrue(yaml.contains("DOMAIN-SUFFIX,ru,DIRECT"))
        assertFalse(yaml.contains("DOMAIN-SUFFIX,.ru"))
    }

    @Test
    fun `panel categories the shipped dat does not carry are dropped`() {
        val profile = vless().copy(
            routingRules = """[
                {"outboundTag":"direct","domain":["geosite:youtube","geosite:category-ru","geosite:ext:site.dat:foo"]},
                {"outboundTag":"direct","ip":["geoip:us","geoip:ru","geoip:lan"]}
            ]""",
        )
        val yaml = build(
            profile,
            RoutingMode.GLOBAL,
            knownGeoSite = setOf("CATEGORY-RU"),
            knownGeoIp = setOf("RU"),
        )
        assertTrue(yaml.contains("GEOSITE,category-ru,DIRECT"))
        assertTrue(yaml.contains("GEOIP,ru,DIRECT"))
        assertTrue(yaml.contains("GEOIP,lan,DIRECT"))
        assertFalse(yaml.contains("GEOSITE,youtube"))
        assertFalse(yaml.contains("GEOIP,us"))
        assertFalse(yaml.contains("ext:"))
    }

    @Test
    fun `xhttp extra reaches the document in the core's spelling`() {
        val profile = vless().copy(
            network = "xhttp",
            path = "/x",
            mode = "packet-up",
            host = "",
            xhttpExtra = """{"scMaxEachPostBytes":1000000,"noGRPCHeader":true,"headers":{"Host":"cdn.example.com"},"xmux":{"maxConcurrency":"16-32"}}""",
        )
        val yaml = build(profile, RoutingMode.GLOBAL)
        assertTrue(yaml.contains("Host: cdn.example.com"))
        assertTrue(yaml.contains("sc-max-each-post-bytes: 1000000"))
        assertTrue(yaml.contains("no-grpc-header: true"))
        assertTrue(yaml.contains("reuse-settings:"))
        assertTrue(yaml.contains("max-concurrency: 16-32"))
        assertFalse(yaml.contains("scMaxEachPostBytes"))
    }

    @Test
    fun `xhttp split download is rewritten the way the core reads it`() {
        val profile = vless().copy(
            network = "xhttp",
            path = "/x",
            mode = "packet-up",
            xhttpExtra = """{"downloadSettings":{
                "address":"dl.example.com","port":"8443","security":"reality",
                "tlsSettings":{"serverName":"dl.example.com","fingerprint":"chrome","alpn":["h2"],"allowInsecure":true},
                "realitySettings":{"publicKey":"pk","shortId":"ab"},
                "xhttpSettings":{"path":"/d","host":"dl.example.com","headers":{"X-Test":"1"},
                    "extra":{"xmux":{"maxConcurrency":"4-8"}}}}}""",
        )
        val yaml = build(profile, RoutingMode.GLOBAL)
        assertTrue(yaml.contains("download-settings:"))
        assertTrue(yaml.contains("server: dl.example.com"))
        assertTrue(yaml.contains("port: 8443"))
        assertTrue(yaml.contains("tls: true"))
        assertTrue(yaml.contains("servername: dl.example.com"))
        assertTrue(yaml.contains("client-fingerprint: chrome"))
        assertTrue(yaml.contains("skip-cert-verify: true"))
        assertTrue(yaml.contains("- h2"))
        assertTrue(yaml.contains("public-key: pk"))
        assertTrue(yaml.contains("short-id: ab"))
        assertTrue(yaml.contains("path: /d"))
        assertTrue(yaml.contains("host: dl.example.com"))
        assertTrue(yaml.contains("max-concurrency: 4-8"))
        // The Xray spelling of the tree has no reader in the core.
        assertFalse(yaml.contains("address:"))
        assertFalse(yaml.contains("security:"))
        assertFalse(yaml.contains("tls-settings"))
        assertFalse(yaml.contains("reality-settings"))
        assertFalse(yaml.contains("xhttp-settings"))
    }

    @Test
    fun `a split download already in the core's spelling is passed through`() {
        val profile = vless().copy(
            network = "xhttp",
            xhttpExtra = """{"downloadSettings":{"server":"dl.example.com","port":8443,"tls":true}}""",
        )
        val yaml = build(profile, RoutingMode.GLOBAL)
        assertTrue(yaml.contains("download-settings:"))
        assertTrue(yaml.contains("server: dl.example.com"))
        assertTrue(yaml.contains("tls: true"))
        assertFalse(yaml.contains("address:"))
    }

    @Test
    fun `split download is dropped where the core refuses it`() {
        val profile = vless().copy(
            network = "xhttp",
            mode = "stream-one",
            xhttpExtra = """{"downloadSettings":{"address":"dl.example.com","port":8443}}""",
        )
        val yaml = build(profile, RoutingMode.GLOBAL)
        assertFalse(yaml.contains("download-settings"))
    }

    @Test
    fun `the session knobs lose the id the core never reads`() {
        val profile = vless().copy(
            network = "xhttp",
            xhttpExtra = """{"sessionIDPlacement":"header","sessionIDKey":"X-S","sessionIDLength":16}""",
        )
        val yaml = build(profile, RoutingMode.GLOBAL)
        assertTrue(yaml.contains("session-placement: header"))
        assertTrue(yaml.contains("session-key: X-S"))
        assertTrue(yaml.contains("session-length: 16"))
        assertFalse(yaml.contains("session-id-"))
    }

    @Test
    fun `private zones and the bypass region use the system resolver`() {
        val yaml = build(vless(), RoutingMode.BYPASS_RU)
        assertTrue(yaml.contains("nameserver-policy:"))
        assertTrue(yaml.contains("+.lan"))
        assertTrue(yaml.contains("GEOSITE,category-ru,DIRECT"))
        assertTrue(yaml.contains("geosite:category-ru"))
        assertTrue(yaml.contains("- system"))
    }

    @Test
    fun `the system resolver is named, not an address baked at build time`() {
        val yaml = build(vless(), RoutingMode.GLOBAL)
        assertTrue(yaml.contains("nameserver-policy:"))
        assertFalse(yaml.contains("192.168."))
    }

    @Test
    fun `a balancer spreads instead of pinning to its first member`() {
        val balancer = ProfileEntity(
            id = "", subscriptionId = null, type = ProfileType.BALANCER,
            remarks = "pool", balancerStrategy = "random",
        )
        val yaml = build(
            balancer, RoutingMode.GLOBAL, members = listOf(vless("a"), vless("b")),
        )
        assertTrue(yaml.contains("type: load-balance"))
        assertTrue(yaml.contains("strategy: round-robin"))
    }

    @Test
    fun `least ping stays a url test`() {
        val balancer = ProfileEntity(
            id = "", subscriptionId = null, type = ProfileType.BALANCER,
            remarks = "pool", balancerStrategy = "leastping",
        )
        val yaml = build(
            balancer, RoutingMode.GLOBAL, members = listOf(vless("a"), vless("b")),
        )
        assertTrue(yaml.contains("type: url-test"))
    }

    @Test
    fun `panel ip rules get a mask and the target before any option`() {
        val profile = vless().copy(
            routingRules = """[{"outboundTag":"direct","ip":["1.2.3.4","2001:db8::1"]}]""",
        )
        val yaml = build(profile, RoutingMode.GLOBAL)
        assertTrue(yaml.contains("IP-CIDR,1.2.3.4/32,DIRECT,no-resolve"))
        assertTrue(yaml.contains("IP-CIDR,2001:db8::1/128,DIRECT,no-resolve"))
        assertFalse(yaml.contains("no-resolve,DIRECT"))
    }

    @Test
    fun `wireguard keeps both address families and its own dns`() {
        val profile = ProfileEntity(
            id = "", subscriptionId = null, type = ProfileType.WIREGUARD,
            remarks = "wg", server = "wg.example.com", serverPort = 51820,
            wgSecretKey = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            publicKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
            wgLocalAddress = "10.0.0.2/32, fd00::2/128",
            wgKeepalive = 25,
            extraOptions = """{"dns":["9.9.9.9"]}""",
        )
        val yaml = build(profile, RoutingMode.GLOBAL)
        assertTrue(yaml.contains("ip: 10.0.0.2/32"))
        assertTrue(yaml.contains("fd00::2/128"))
        assertTrue(yaml.contains("persistent-keepalive: 25"))
        assertTrue(yaml.contains("- 9.9.9.9"))
    }

    @Test
    fun `panel keys are quoted too`() {
        val profile = vless().copy(extraOptions = """{"x:y":"value"}""")
        val yaml = build(profile, RoutingMode.GLOBAL)
        assertTrue(yaml.contains("\"x:y\": value"))
    }
}
