package slop.miho.chumpy.sub

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import slop.miho.chumpy.db.ProfileType
import slop.miho.chumpy.mihomo.ClashConfig
import slop.miho.chumpy.mihomo.RoutingMode
import java.io.File

/**
 * The whole protocol matrix the VPS test instance serves: every entry has to survive
 * the Clash YAML reader and the config writer. The written documents are what the
 * external core is pointed at by the protocol harness.
 */
class ProtocolMatrixTest {
    private fun matrix(): String =
        javaClass.classLoader!!.getResourceAsStream("protocol-matrix.yaml")!!
            .bufferedReader().readText()

    @Test
    fun `every protocol in the matrix parses into its own type`() {
        val profiles = ClashYamlParser.parse(matrix())
        assertNotNull(profiles)
        assertEquals(profiles!!.map { it.remarks }.toString(), 29, profiles.size)
        val byType = profiles.groupingBy { it.type }.eachCount()
        assertEquals(4, byType[ProfileType.SHADOWSOCKS])
        assertEquals(4, byType[ProfileType.VMESS])
        assertEquals(4, byType[ProfileType.VLESS])
        assertEquals(3, byType[ProfileType.TROJAN])
        assertEquals(2, byType[ProfileType.HYSTERIA2])
        assertEquals(2, byType[ProfileType.MIERU])
        assertEquals(2, byType[ProfileType.SNELL])
        assertEquals(2, byType[ProfileType.HTTP])
        assertEquals(1, byType[ProfileType.TUIC])
        assertEquals(1, byType[ProfileType.ANYTLS])
        assertEquals(1, byType[ProfileType.SUDOKU])
        assertEquals(1, byType[ProfileType.SHADOWQUIC])
        assertEquals(1, byType[ProfileType.TRUSTTUNNEL])
        assertEquals(1, byType[ProfileType.SOCKS])
    }

    /**
     * The shape checks only; the real "the core can run it" pass is the Go test in
     * nyampy-core (config_test.go), which feeds these documents to config.ParseRawConfig.
     */
    @Test
    fun `every matrix entry renders a complete document`() {
        val out = File("build/protocol-configs")
        out.mkdirs()
        out.listFiles()?.forEach { it.delete() }
        val profiles = ClashYamlParser.parse(matrix())!!
        profiles.forEachIndexed { index, profile ->
            val yaml = ClashConfig.buildFull(profile, RoutingMode.GLOBAL)
            assertTrue("${profile.remarks}: no proxy block", yaml.contains("proxies:"))
            assertTrue("${profile.remarks}: no match rule", yaml.contains("MATCH,PROXY"))
            val name = "%02d-%s.yaml".format(
                index,
                profile.remarks.replace(Regex("[^A-Za-z0-9]+"), "-").trim('-'),
            )
            File(out, name).writeText(yaml)
        }
        assertEquals(29, out.listFiles()!!.size)
    }

    @Test
    fun `share links for the newer protocols parse`() {
        val cases = mapOf(
            "tuic://00000000-1111-2222-3333-444444444444:pass@t.example.com:443?congestion_control=bbr&alpn=h3&sni=t.example.com#tuic" to ProfileType.TUIC,
            "anytls://pass@a.example.com:443?sni=a.example.com&insecure=1#anytls" to ProfileType.ANYTLS,
            "snell://psk@h.example.com:443?version=4&obfs=http&obfs-host=cdn.example.com#snell" to ProfileType.SNELL,
            "mieru://user:pass@m.example.com:443?transport=TCP#mieru" to ProfileType.MIERU,
            "sudoku://key@d.example.com:443#sudoku" to ProfileType.SUDOKU,
            "shadowquic://user:pass@q.example.com:443?sni=q.example.com&alpn=h3#shadowquic" to ProfileType.SHADOWQUIC,
            "trusttunnel://user:pass@tt.example.com:443?sni=tt.example.com#trusttunnel" to ProfileType.TRUSTTUNNEL,
        )
        cases.forEach { (link, type) ->
            val profile = LinkParsers.parse(link)
            assertNotNull("did not parse: $link", profile)
            assertEquals(link, type, profile!!.type)
            assertEquals("example.com", profile.server.substringAfter('.'))
            assertEquals(443, profile.serverPort)
        }
        val tuic = LinkParsers.parse(cases.keys.first())!!
        assertEquals("00000000-1111-2222-3333-444444444444", tuic.username)
        assertEquals("pass", tuic.password)
        assertTrue(tuic.extraOptions.contains("congestion-control") || tuic.extraOptions.contains("congestion_control"))
        val snell = LinkParsers.parse("snell://psk@h.example.com:443?version=4&obfs=http&obfs-host=cdn.example.com#snell")!!
        assertTrue(snell.extraOptions.contains("obfs-opts"))
    }
}


