package dev.yazwa.nyampy.sub

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import dev.yazwa.nyampy.db.ProfileType
import org.junit.Assert.assertTrue
import dev.yazwa.nyampy.TEST_LOCAL_PROXY
import dev.yazwa.nyampy.mihomo.ClashConfig
import dev.yazwa.nyampy.mihomo.RoutingMode

class Hysteria2ConfigParserTest {
    private fun config(version: Int = 2, auth: String = "\"auth\": \"test-password\"") = """
        {
          "remarks": "Test Hysteria2",
          "outbounds": [{
            "tag": "proxy",
            "protocol": "hysteria",
            "settings": {"address": "hy.example.com", "port": 443, "version": $version},
            "streamSettings": {
              "network": "hysteria",
              "hysteriaSettings": {"version": $version${if (auth.isNotEmpty()) ", $auth" else ""}},
              "security": "tls",
              "tlsSettings": {"serverName": "sni.example.com", "alpn": ["h3"], "fingerprint": "chrome"}
            }
          }, {"tag": "direct", "protocol": "freedom"}]
        }
    """.trimIndent()

    @Test
    fun `a JSON subscription preserves hysteria2 endpoint authentication and TLS`() {
        val profile = SubscriptionParser.parse("[${config()}]").single()
        assertEquals(ProfileType.HYSTERIA2, profile.type)
        assertEquals("Test Hysteria2", profile.remarks)
        assertEquals("hy.example.com", profile.server)
        assertEquals(443, profile.serverPort)
        assertEquals("test-password", profile.password)
        assertEquals("hysteria", profile.network)
        assertEquals("tls", profile.security)
        assertEquals("sni.example.com", profile.sni)
        assertEquals("h3", profile.alpn)
        assertEquals("chrome", profile.fingerprint)

        // The document the core now runs: the same credentials and TLS fields, spelled
        // the Clash way.
        val yaml = ClashConfig.buildFull(profile, RoutingMode.GLOBAL, localProxy = TEST_LOCAL_PROXY)
        assertTrue(yaml, yaml.contains("type: hysteria2"))
        assertTrue(yaml, yaml.contains("password: test-password"))
        assertTrue(yaml, yaml.contains("sni: sni.example.com"))
        assertTrue(yaml, yaml.contains("alpn:"))
    }

    @Test
    fun `hysteria v1 is not imported as hysteria2`() {
        assertNull(ConfigParser.parse(config(version = 1)))
    }

    @Test
    fun `a hysteria2 outbound without authentication is skipped`() {
        assertNull(ConfigParser.parse(config(auth = "")))
    }

    @Test
    fun `hysteria2 YAML preserves TLS obfuscation and port hopping`() {
        val profile = SubscriptionParser.parse("""
            proxies:
              - name: Test
                type: hysteria2
                server: hy.example.com
                port: 443
                password: test-password
                sni: sni.example.com
                obfs: salamander
                obfs-password: test-mask
                ports: 20000-20100
                hop-interval: 30
                skip-cert-verify: true
        """.trimIndent()).single()
        assertEquals(ProfileType.HYSTERIA2, profile.type)
        assertEquals("hysteria", profile.network)
        assertEquals("tls", profile.security)
        assertEquals("test-password", profile.password)
        assertEquals("test-mask", profile.obfsPassword)
        assertEquals("20000-20100", profile.portHopping)
        assertEquals("30", profile.portHoppingInterval)
        assertEquals(true, profile.allowInsecure)
    }

    @Test
    fun `hysteria2 links use port 443 when omitted`() {
        assertEquals(443, LinkParsers.parse("hy2://test@hy.example.com?sni=sni.example.com")!!.serverPort)
    }
}
