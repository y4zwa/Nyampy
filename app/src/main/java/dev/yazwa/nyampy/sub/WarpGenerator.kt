package dev.yazwa.nyampy.sub

import dev.yazwa.nyampy.db.ProfileEntity
import dev.yazwa.nyampy.db.ProfileType
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.JsonArray

/**
 * The rows a WARP account turns into: one profile per Cloudflare endpoint, the way the
 * panels' own WARP configs list them. The account is one device — every row shares its
 * keys and its addresses — so the rows differ only in where they dial, which is exactly
 * what makes one of them better than another from a given network.
 *
 * The endpoint list is warpscout's own pools, narrowed to one address per pool: those
 * whole /24s answer, and a dozen rows is a list a person can look at. The ports are the
 * four Cloudflare serves everywhere; 2408 first, as the one that works most often.
 */
object WarpGenerator {
    internal data class Endpoint(val host: String, val port: Int)

    internal val ENDPOINTS = listOf(
        Endpoint("engage.cloudflareclient.com", 2408),
        Endpoint("162.159.192.1", 2408),
        Endpoint("162.159.195.1", 2408),
        Endpoint("188.114.96.1", 2408),
        Endpoint("188.114.97.1", 500),
        Endpoint("188.114.98.1", 4500),
        Endpoint("188.114.99.1", 1701),
        Endpoint("8.6.112.1", 2408),
        Endpoint("8.34.70.1", 500),
        Endpoint("8.34.146.1", 4500),
        Endpoint("8.35.211.1", 1701),
        Endpoint("8.39.125.1", 2408),
        Endpoint("8.39.204.1", 500),
        Endpoint("8.47.69.1", 2408),
    )

    /** The DNS the tunnel resolves through: Cloudflare's own, as the panels ship it. */
    private val DNS = listOf("1.1.1.1", "1.0.0.1")

    private const val MTU = 1280

    /** A quarter-hour of idle traffic keeps the mapping alive across CGNAT. */
    private const val KEEPALIVE = 25

    internal fun build(account: WarpAccount, endpoints: List<Endpoint> = ENDPOINTS): List<ProfileEntity> {
        val extras = buildJsonObject {
            if (account.ipv6.isNotBlank()) put("ipv6", JsonPrimitive(account.ipv6))
            put("dns", JsonArray(DNS.map(::JsonPrimitive)))
        }.toString()
        val amnezia = amnezia(account).toString()
        return endpoints.map { endpoint ->
            ProfileEntity(
                id = "",
                subscriptionId = null,
                type = ProfileType.WIREGUARD,
                remarks = "WARP · ${label(endpoint)}",
                server = endpoint.host,
                serverPort = endpoint.port,
                network = "tcp",
                wgSecretKey = account.privateKey,
                publicKey = account.peerPublicKey,
                wgLocalAddress = account.ipv4,
                wgMtu = MTU,
                wgKeepalive = KEEPALIVE,
                wgAmnezia = amnezia,
                extraOptions = extras,
            )
        }
    }

    /**
     * The AmneziaWG block the core reads. Header types and padding stay at the plain
     * WireGuard values — Cloudflare is the far end, and only the junk before the
     * handshake and the decoy first packet are invisible to it.
     */
    internal fun amnezia(account: WarpAccount): JsonObject = buildJsonObject {
        put("jc", JsonPrimitive(account.jc))
        put("jmin", JsonPrimitive(account.jmin))
        put("jmax", JsonPrimitive(account.jmax))
        put("s1", JsonPrimitive(0))
        put("s2", JsonPrimitive(0))
        put("h1", JsonPrimitive(1))
        put("h2", JsonPrimitive(2))
        put("h3", JsonPrimitive(3))
        put("h4", JsonPrimitive(4))
        if (account.i1.isNotBlank()) put("i1", JsonPrimitive(account.i1))
    }

    private fun label(endpoint: Endpoint): String {
        val host = if (endpoint.host == "engage.cloudflareclient.com") "engage" else endpoint.host
        return "$host:${endpoint.port}"
    }
}
