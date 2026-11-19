package dev.yazwa.nyampy.sub

import dev.yazwa.nyampy.db.ProfileType
import dev.yazwa.nyampy.db.computeLinkKey
import dev.yazwa.nyampy.mihomo.ClashConfig
import dev.yazwa.nyampy.mihomo.LocalProxy
import dev.yazwa.nyampy.mihomo.RoutingMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The WARP group's rows: what the generator makes of an account, and what the writer
 * makes of them. The account below is the API's own answer shape, with the keys made up.
 */
class WarpGeneratorTest {
    private val account = WarpAccount(
        privateKey = "cHJpdmF0ZS1rZXktMzItYnl0ZXMtbG9uZy0hLS0tLS0tLS0=",
        publicKey = "cHVibGljLWtleS0zMi1ieXRlcy1sb25nLSEtLS0tLS0tLS0=",
        peerPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        ipv4 = "172.16.0.2",
        ipv6 = "2606:4700:110:8a18:40cc:d39f:8bdf:d66c",
        jc = 5,
        jmin = 23,
        jmax = 71,
        i1 = WarpClient.DEFAULT_I1,
    )

    @Test
    fun `a row per endpoint, one device behind them all`() {
        val profiles = WarpGenerator.build(account)
        assertEquals(WarpGenerator.ENDPOINTS.size, profiles.size)
        assertTrue(profiles.all { it.type == ProfileType.WIREGUARD })
        assertTrue(profiles.all { it.wgSecretKey == account.privateKey })
        assertTrue(profiles.all { it.publicKey == account.peerPublicKey })
        assertTrue(profiles.all { it.wgLocalAddress == account.ipv4 })
        assertTrue(profiles.all { it.wgMtu == 1280 })
        assertTrue(profiles.all { it.wgKeepalive == 25 })
        assertTrue(profiles.all { it.remarks.startsWith("WARP · ") })
        // One row per endpoint, and every row its own identity: a regeneration must not
        // shuffle the list, and two endpoints must not collapse into one row.
        assertEquals(profiles.size, profiles.map { it.computeLinkKey() }.distinct().size)
        assertTrue(profiles.any { it.server == "engage.cloudflareclient.com" })
        assertTrue(profiles.any { it.remarks == "WARP · engage:2408" })
    }

    @Test
    fun `the writer hands the core both families and the junk`() {
        val profile = WarpGenerator.build(account).first { it.server == "162.159.192.1" }
        val yaml = ClashConfig.buildFull(
            profile, RoutingMode.GLOBAL,
            localProxy = LocalProxy(7899, "nyampy", "test"),
        )
        assertTrue(yaml.contains("""type: "wireguard""""))
        assertTrue(yaml.contains("""ip: "172.16.0.2/32""""))
        assertTrue(yaml.contains("""ipv6: "2606:4700:110:8a18:40cc:d39f:8bdf:d66c/128""""))
        assertTrue(yaml.contains("mtu: 1280"))
        assertTrue(yaml.contains("persistent-keepalive: 25"))
        assertTrue(yaml.contains("amnezia-wg-option:"))
        assertTrue(yaml.contains("\"jc\": 5"))
        assertTrue(yaml.contains("\"jmin\": 23"))
        assertTrue(yaml.contains("\"jmax\": 71"))
        // The far end is plain WireGuard: the header types stay the standard ones and
        // the padding sizes stay zero, or Cloudflare drops every packet.
        assertTrue(yaml.contains("\"s1\": 0"))
        assertTrue(yaml.contains("\"s2\": 0"))
        assertTrue(yaml.contains("\"h1\": 1"))
        assertTrue(yaml.contains("\"h4\": 4"))
        assertTrue(yaml.contains("\"i1\": \"<r 2><b 0x8580"))
        assertTrue(yaml.contains("""- "1.1.1.1""""))
    }

    @Test
    fun `the registration answer parses into an account`() {
        // Shape of the API's answer, values made up.
        val body = """
            {
              "id": "245e4fdc-fb0b-47e4-8af2-9e71acf35236",
              "token": "tok",
              "config": {
                "client_id": "2MY9",
                "peers": [{"public_key": "peer-key"}],
                "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110::1"}}
              }
            }
        """.trimIndent()
        val registration = WarpClient.parseRegistration(body, "priv", "pub")
        assertEquals("peer-key", registration.peerPublicKey)
        assertEquals("172.16.0.2", registration.ipv4)
        assertEquals("2606:4700:110::1", registration.ipv6)
        val account = registration.account(WarpClient.Junk(5, 20, 60))
        assertEquals(5, account.jc)
        assertEquals(20, account.jmin)
        assertEquals(60, account.jmax)
        assertEquals(WarpClient.DEFAULT_I1, account.i1)
    }

    @Test
    fun `an answer without a peer key is refused`() {
        val body = """{"id":"x","token":"t","config":{"peers":[],"interface":{"addresses":{"v4":"172.16.0.2"}}}}"""
        try {
            WarpClient.parseRegistration(body, "priv", "pub")
            throw AssertionError("a registration without a peer key must not parse")
        } catch (_: IllegalArgumentException) {
            // expected: require() in parseRegistration
        }
    }

    @Test
    fun `the account file round-trips`() {
        val file = File(System.getProperty("java.io.tmpdir"), "nyampy-warp-account-test.json")
        file.delete()
        val store = WarpAccountStore(file)
        store.save(account)
        assertEquals(account, store.load())
        store.clear()
        assertEquals(null, store.load())
    }
}
