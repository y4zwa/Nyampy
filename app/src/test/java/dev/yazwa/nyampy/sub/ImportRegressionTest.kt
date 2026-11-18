package dev.yazwa.nyampy.sub

import dev.yazwa.nyampy.TEST_LOCAL_PROXY
import dev.yazwa.nyampy.mihomo.ClashConfig
import dev.yazwa.nyampy.mihomo.RoutingMode
import org.junit.Assert.*
import org.junit.Test

class ImportRegressionTest {
    private val link = "vless://test@example.com:443?security=tls#Name"

    @Test
    fun `wrapped base64 subscription imports and deduplicates profiles`() {
        val encoded = LinkUtils.encodeBase64("$link\n$link").chunked(16).joinToString("\r\n")
        val profiles = SubscriptionParser.parse(encoded)
        assertEquals(1, profiles.size)
        assertEquals("example.com", profiles.single().server)
    }

    @Test
    fun `base64 nested URL is recognized`() {
        assertEquals("https://example.com/sub", SubscriptionParser.isNestedSubscriptionUrl(
            LinkUtils.encodeBase64("https://example.com/sub"),
        ))
    }

    @Test
    fun `scheme is case insensitive and fragment is decoded exactly once`() {
        val profile = LinkParsers.parse("VMESS://" + LinkUtils.encodeBase64(
            """{"add":"example.com","port":"443","id":"test","ps":"name"}""",
        ))
        assertNotNull(profile)
        assertEquals("literal%20name", LinkParsers.parse(link.substringBefore('#') + "#literal%2520name")!!.remarks)
    }

    @Test
    fun `invalid endpoints are rejected and a plain vless URI can be imported`() {
        assertNull(LinkParsers.parse("vless://test@:443?security=tls"))
        assertNull(LinkParsers.parse("vless://test@example.com:65536?security=tls"))
        assertNull(LinkParsers.parse("vless://test@example.com?security=tls"))
        assertNotNull(LinkParsers.parse("vless://test@example.com:443"))
    }

    @Test
    fun `vmess URI works with one query parameter or none`() {
        assertEquals("ws", LinkParsers.parse("vmess://test@example.com:443?type=ws")!!.network)
        assertEquals("test", LinkParsers.parse("vmess://test@example.com:443")!!.password)
    }

    @Test
    fun `hysteria transport stays canonical when query parameters are present`() {
        assertEquals("hysteria", LinkParsers.parse("hy2://test@example.com?sni=example.com")!!.network)
        assertNull(LinkParsers.parse("ss://invalid@example.com:443"))
    }

    @Test
    fun `raw websocket config preserves host header`() {
        val profile = ConfigParser.parse("""{
            "outbounds":[{"protocol":"vless","settings":{"vnext":[{
                "address":"example.com","port":443,"users":[{"id":"test"}]
            }]},"streamSettings":{"network":"ws","wsSettings":{
                "path":"/socket","headers":{"Host":"front.example.com"}
            }}}]
        }""")!!.single()
        assertEquals("front.example.com", profile.host)
        assertEquals("/socket", profile.path)
    }

    @Test fun `encoded SOCKS components retain their boundaries`() {
        val profile = LinkParsers.parse("socks://user%3Aname:pa%3Ass@example.com:1080")!!
        assertEquals("user:name", profile.username)
        assertEquals("pa:ss", profile.password)
    }

    @Test fun `missing mandatory credentials are rejected`() {
        assertNull(LinkParsers.parse("vless://example.com:443?security=tls"))
        assertNull(LinkParsers.parse("wg://private@example.com:443?address=10.0.0.2/32"))
        assertNull(LinkParsers.parse("trojan://example.com:443"))
        assertNotNull(LinkParsers.parse("socks://example.com:1080"))
    }

    @Test fun `flow YAML and quoted passwords preserve content`() {
        val flow = "proxies:\n  - {name: Test, type: trojan, server: example.com, port: 443, password: 'it''s, a password'}"
        assertEquals("it's, a password", SubscriptionParser.parse(flow).single().password)
        val escaped = "proxies:\n  - name: Test\n    type: trojan\n    server: example.com\n    port: 443\n    password: \"a\\u003Ab\\n\" # note"
        assertEquals("a:b\n", SubscriptionParser.parse(escaped).single().password)
    }

    @Test fun `BOM does not change JSON import`() {
        val raw = """{"outbounds":[{"protocol":"socks","settings":{"address":"example.com","port":1080}}]}"""
        assertEquals(SubscriptionParser.parse(raw), SubscriptionParser.parse("\uFEFF" + raw))
    }

    @Test fun `custom outbound tags retain block and direct semantics`() {
        fun parse(protocol: String) = ConfigParser.parse("""{
            "outbounds":[{"tag":"proxy","protocol":"socks","settings":{"address":"example.com","port":1080}},
            {"tag":"custom-target","protocol":"$protocol"}],
            "routing":{"rules":[{"type":"field","domain":["domain:example.net"],"outboundTag":"custom-target"}]}
        }""")!!.single()
        // The panel's rule, rewritten as a Clash line and aimed at the session's target.
        assertTrue(ClashConfig.buildFull(parse("blackhole"), RoutingMode.GLOBAL, localProxy = TEST_LOCAL_PROXY)
            .contains("DOMAIN-SUFFIX,example.net,REJECT"))
        assertTrue(ClashConfig.buildFull(parse("freedom"), RoutingMode.GLOBAL, localProxy = TEST_LOCAL_PROXY)
            .contains("DOMAIN-SUFFIX,example.net,DIRECT"))
    }

    @Test fun `WireGuard config rejects multiple peers and keeps the one`() {
        val text = "[Interface]\nPrivateKey = private\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = public\nEndpoint = example.com:443\n"
        assertNull(LinkParsers.parseWireguardConf(text + "[Peer]\nPublicKey = other\nEndpoint = other.example:443\n"))
        val profile = LinkParsers.parseWireguardConf(text)!!
        assertEquals("example.com", profile.server)
        assertEquals(443, profile.serverPort)
        assertEquals("public", profile.publicKey)
        assertEquals("private", profile.wgSecretKey)
    }

    @Test fun `AmneziaWG 3_1 conf reaches the core's option block`() {
        val text = """
            [Interface]
            PrivateKey = priv
            Address = 10.0.0.2/32
            MTU = 1280
            Jc = 5
            Jmin = 100
            Jmax = 700
            S1 = 32
            H1 = 1
            I1 = <b 0xc30000000108><r 8>
            HeaderProtectionKey = key=
            ContentPaddingAddition = 16-64
            RekeyAfterTime = 110-130
            RandomTrailers = on
            DisableCookies = on

            [Peer]
            PublicKey = pub
            Endpoint = example.com:51830
            PersistentKeepalive = 25
        """.trimIndent()
        val profile = LinkParsers.parseWireguardConf(text)!!
        assertEquals(25, profile.wgKeepalive)
        assertTrue(profile.wgAmnezia, profile.wgAmnezia.contains("\"version\":3"))
        assertTrue(profile.wgAmnezia, profile.wgAmnezia.contains("header-protection-key"))
        assertTrue(profile.wgAmnezia, profile.wgAmnezia.contains("random-trailers"))

        val yaml = ClashConfig.buildFull(profile, RoutingMode.GLOBAL, localProxy = TEST_LOCAL_PROXY)
        assertTrue(yaml, yaml.contains("amnezia-wg-option:"))
        assertTrue(yaml, yaml.contains("persistent-keepalive: 25"))
        assertTrue(yaml, yaml.contains("""header-protection-key":"""))
        assertTrue(yaml, yaml.contains("""i1":"""))
    }

}
