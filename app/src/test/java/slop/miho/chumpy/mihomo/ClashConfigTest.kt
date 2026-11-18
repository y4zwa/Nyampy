package slop.miho.chumpy.mihomo

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import slop.miho.chumpy.db.ProfileEntity
import slop.miho.chumpy.db.ProfileType

/**
 * The pieces of the document that are easy to get silently wrong: the geodata mode the
 * shipped .dat files need, the LAN short-circuit, the balancer strategy, panel rules
 * and the WireGuard address split.
 */
class ClashConfigTest {
    private fun vless(name: String = "node") = ProfileEntity(
        id = "", subscriptionId = null, type = ProfileType.VLESS,
        remarks = name, server = "a.example.com", serverPort = 443,
        password = "00000000-1111-2222-3333-444444444444",
    )

    @Test
    fun `geodata mode matches the files that ship in the apk`() {
        val yaml = ClashConfig.buildFull(vless(), RoutingMode.GLOBAL)
        assertTrue(yaml.contains("geodata-mode: true"))
    }

    @Test
    fun `private ranges are matched by the lan short-circuit`() {
        val yaml = ClashConfig.buildFull(vless(), RoutingMode.GLOBAL)
        assertTrue(yaml.contains("GEOIP,lan,DIRECT,no-resolve"))
        assertFalse(yaml.contains("GEOIP,private"))
    }

    @Test
    fun `the device resolvers answer for private zones and the bypass region`() {
        val yaml = ClashConfig.buildFull(
            vless(), RoutingMode.BYPASS_RU, systemDns = listOf("192.168.1.1"),
        )
        assertTrue(yaml.contains("nameserver-policy:"))
        assertTrue(yaml.contains("+.lan"))
        assertTrue(yaml.contains("GEOSITE,category-ru,DIRECT"))
        assertTrue(yaml.contains("geosite:category-ru"))
    }

    @Test
    fun `without device resolvers no policy is invented`() {
        val yaml = ClashConfig.buildFull(vless(), RoutingMode.GLOBAL)
        assertFalse(yaml.contains("nameserver-policy:"))
    }

    @Test
    fun `a balancer spreads instead of pinning to its first member`() {
        val balancer = ProfileEntity(
            id = "", subscriptionId = null, type = ProfileType.BALANCER,
            remarks = "pool", balancerStrategy = "random",
        )
        val yaml = ClashConfig.buildFull(
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
        val yaml = ClashConfig.buildFull(
            balancer, RoutingMode.GLOBAL, members = listOf(vless("a"), vless("b")),
        )
        assertTrue(yaml.contains("type: url-test"))
    }

    @Test
    fun `panel ip rules get a mask and the target before any option`() {
        val profile = vless().copy(
            routingRules = """[{"outboundTag":"direct","ip":["1.2.3.4","2001:db8::1"]}]""",
        )
        val yaml = ClashConfig.buildFull(profile, RoutingMode.GLOBAL)
        assertTrue(yaml.contains("IP-CIDR,1.2.3.4/32,DIRECT"))
        assertTrue(yaml.contains("IP-CIDR,2001:db8::1/128,DIRECT"))
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
        val yaml = ClashConfig.buildFull(profile, RoutingMode.GLOBAL)
        assertTrue(yaml.contains("ip: 10.0.0.2/32"))
        assertTrue(yaml.contains("fd00::2/128"))
        assertTrue(yaml.contains("persistent-keepalive: 25"))
        assertTrue(yaml.contains("- 9.9.9.9"))
    }

    @Test
    fun `panel keys are quoted too`() {
        val profile = vless().copy(extraOptions = """{"x:y":"value"}""")
        val yaml = ClashConfig.buildFull(profile, RoutingMode.GLOBAL)
        assertTrue(yaml.contains("\"x:y\": value"))
    }
}
