package dev.yazwa.nyampy.sub

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import dev.yazwa.nyampy.db.ProfileType

/**
 * The Clash YAML dialect, exercised on the shapes panels actually serve: the vless
 * reality/tcp, grpc+alpn and ws entries panel-style bodies carry, a quoted name, the
 * vmess/trojan/ss forms, and the verdicts that keep other dialects out of it.
 */
class ClashYamlParserTest {
    private val realityEntry = """
            - name: '🇩🇪  Германия #3'
              type: vless
              server: 1.2.3.4
              port: 443
              uuid: 00000000-1111-2222-3333-444444444444
              network: tcp
              udp: true
              tls: true
              servername: pl4.example.org
              client-fingerprint: edge
              reality-opts:
                public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                short-id: 0000000000000000
              flow: xtls-rprx-vision
    """.trimIndent()

    @Test
    fun `a vless reality entry parses`() {
        val profiles = ClashYamlParser.parse("proxies:\n$realityEntry\n")
        assertNotNull(profiles)
        val p = profiles!!.single()
        assertEquals(ProfileType.VLESS, p.type)
        assertEquals("🇩🇪  Германия #3", p.remarks)
        assertEquals("1.2.3.4", p.server)
        assertEquals(443, p.serverPort)
        assertEquals("00000000-1111-2222-3333-444444444444", p.password)
        assertEquals("xtls-rprx-vision", p.flow)
        assertEquals("reality", p.security)
        assertEquals("pl4.example.org", p.sni)
        assertEquals("edge", p.fingerprint)
        assertEquals("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", p.publicKey)
        assertEquals("0000000000000000", p.shortId)
    }

    @Test
    fun `a grpc entry with a block alpn parses`() {
        val yaml = """
            proxies:
            - name: '🇺🇸  США | Gemini'
              type: vless
              server: 1.2.3.6
              port: 443
              uuid: 9a14cdc4-9ef2-4f79-87ab-76206a11b1ea
              network: grpc
              tls: true
              servername: us4.example.org
              client-fingerprint: chrome
              grpc-opts:
                grpc-service-name: content.v1.Feed
              alpn:
              - h2
        """.trimIndent()
        val p = ClashYamlParser.parse(yaml)!!.single()
        assertEquals("🇺🇸  США | Gemini", p.remarks)
        assertEquals("grpc", p.network)
        assertEquals("content.v1.Feed", p.serviceName)
        assertEquals("tls", p.security)
        assertEquals("us4.example.org", p.sni)
        assertEquals("h2", p.alpn)
    }

    @Test
    fun `a ws entry with an indented ws-opts map parses`() {
        val yaml = """
            proxies:
            - name: 🇸🇪  Швеция #2
              type: vless
              server: 1.2.3.7
              port: 443
              uuid: 9a14cdc4-9ef2-4f79-87ab-76206a11b1ea
              network: ws
              tls: true
              servername: se4.example.org
              ws-opts:
                path: /api-se4
                headers:
                  Host: cdn.example.com
        """.trimIndent()
        val p = ClashYamlParser.parse(yaml)!!.single()
        assertEquals("ws", p.network)
        assertEquals("/api-se4", p.path)
        assertEquals("cdn.example.com", p.host)
    }

    @Test
    fun `vmess trojan and ss entries parse`() {
        val yaml = """
            proxies:
            - name: vm
              type: vmess
              server: v.example.com
              port: 8443
              uuid: b831381d-6324-4d53-ad4f-8cda48b30811
              alterId: 0
              cipher: auto
              network: ws
              ws-opts:
                path: /ws
            - name: tj
              type: trojan
              server: t.example.com
              port: 443
              password: trojanpass
              sni: t.example.com
              skip-cert-verify: true
            - name: ss
              type: ss
              server: s.example.com
              port: 8388
              cipher: aes-256-gcm
              password: sspass
        """.trimIndent()
        val profiles = ClashYamlParser.parse(yaml)!!
        assertEquals(3, profiles.size)
        val vm = profiles[0]
        assertEquals(ProfileType.VMESS, vm.type)
        assertEquals("b831381d-6324-4d53-ad4f-8cda48b30811", vm.password)
        assertEquals("auto", vm.method)
        assertEquals("ws", vm.network)
        assertEquals("/ws", vm.path)
        val tj = profiles[1]
        assertEquals(ProfileType.TROJAN, tj.type)
        assertEquals("trojanpass", tj.password)
        assertEquals("t.example.com", tj.sni)
        assertTrue(tj.allowInsecure)
        val ss = profiles[2]
        assertEquals(ProfileType.SHADOWSOCKS, ss.type)
        assertEquals("aes-256-gcm", ss.method)
        assertEquals("sspass", ss.password)
    }

    @Test
    fun `unknown types are skipped and other dialects stay out`() {
        // A supported entry next to an unsupported one: only the supported survives.
        val mixed = "proxies:\n$realityEntry\n" + """
            - name: hy
              type: unsupported-protocol
              server: h.example.com
              port: 443
              password: hy
        """.trimIndent() + "\n"
        assertEquals(1, ClashYamlParser.parse(mixed)!!.size)

        assertNull(ClashYamlParser.parse("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443#x"))
        assertNull(ClashYamlParser.parse("[Interface]\nPrivateKey = x\n"))
    }

    @Test
    fun `anchors aliases and merge keys resolve into nodes`() {
        // The shape a WARP generator writes: one shared block, one alias per node.
        val yaml = """
            warp-common: &warp-common
              type: wireguard
              private-key: cHJpdmF0ZS1rZXk=
              public-key: cHVibGljLWtleQ==
              ip: 172.16.0.2
              reserved: [225, 139, 2]
              mtu: 1280
              dns: [1.1.1.1]
              amnezia-wg-option: &amnezia
                jc: 4
                i1: <b 0x0102>
            i1-default: &i1-default <b 0xc1>
            proxies:
            - name: nl
              <<: *warp-common
              server: nl.example.org
              port: 4500
            - name: de
              <<: *warp-common
              server: de.example.org
              port: 500
              mtu: 1300
            - name: aliased
              <<: *warp-common
              server: al.example.org
              port: 2408
              amnezia-wg-option:
                jc: 4
                i1: *i1-default
        """.trimIndent()
        val profiles = ClashYamlParser.parse(yaml)!!
        assertEquals(3, profiles.size)
        val nl = profiles[0]
        assertEquals(ProfileType.WIREGUARD, nl.type)
        assertEquals("cHJpdmF0ZS1rZXk=", nl.wgSecretKey)
        assertEquals("cHVibGljLWtleQ==", nl.publicKey)
        assertEquals("225,139,2", nl.wgReserved)
        assertEquals(1280, nl.wgMtu)
        assertEquals("""{"jc":"4","i1":"<b 0x0102>"}""", nl.wgAmnezia)
        // The node's own key beats the block it merged in…
        assertEquals(1300, profiles[1].wgMtu)
        // …and an alias inside a nested map keeps the value it pointed at.
        assertEquals("""{"jc":"4","i1":"<b 0xc1>"}""", profiles[2].wgAmnezia)
    }

    @Test
    fun `a masque entry keeps the core's own keys`() {
        val yaml = """
            proxies:
            - name: mq
              type: masque
              server: 162.159.198.2
              port: 443
              sni: 4pda.to
              private-key: MHcCAQEEI
              public-key: MFkwEwYHKoZIzj0CAQYI
              network: h2
        """.trimIndent()
        val p = ClashYamlParser.parse(yaml)!!.single()
        assertEquals(ProfileType.MASQUE, p.type)
        assertEquals("h2", p.network)
        assertTrue(p.extraOptions.contains("\"sni\":\"4pda.to\""))
        assertTrue(p.extraOptions.contains("\"private-key\":\"MHcCAQEEI\""))

        // Without the keypair there is no tunnel: the entry is not worth a row.
        assertNull(ClashYamlParser.parse("proxies:\n- name: mq\n  type: masque\n  server: 1.2.3.4\n  port: 443\n"))
    }

    @Test
    fun `SubscriptionParser hands clash yaml through`() {
        // ws paths and server names carry no "://", so the body reaches the reader raw.
        val yaml = "proxies:\n$realityEntry\nproxy-groups:\n- name: PROXY\n  type: select\nrules:\n- MATCH,PROXY\n"
        val profiles = SubscriptionParser.parse(yaml)
        assertEquals(1, profiles.size)
        assertEquals("🇩🇪  Германия #3", profiles.single().remarks)
    }

    @Test
    fun `boolean options stay strings for the writer to coerce, and h2 keeps its network`() {
        val yaml = """
            proxies:
            - name: t
              type: tuic
              server: t.example.com
              port: 443
              uuid: 00000000-1111-2222-3333-444444444444
              password: x
              udp: false
              reduce-rtt: true
            - name: h
              type: vless
              server: h.example.com
              port: 443
              uuid: 00000000-1111-2222-3333-444444444444
              network: h2
        """.trimIndent()
        val profiles = ClashYamlParser.parse(yaml)!!
        val tuic = profiles.first { it.type == ProfileType.TUIC }
        // extraOptions keeps the text (the link key hashes it); the writer turns the
        // known boolean keys into YAML booleans, which is what the core decodes.
        assertTrue(tuic.extraOptions.contains("\"udp\":\"false\""))
        assertTrue(tuic.extraOptions.contains("\"reduce-rtt\":\"true\""))
        // h2 and http are different transports; collapsing them breaks the handshake.
        assertEquals("h2", profiles.first { it.type == ProfileType.VLESS }.network)
    }
}
