package dev.yazwa.nyampy.sub

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * WARP registration: Cloudflare's own API, the way the Android client enrols a device.
 *
 * Two calls. The first mints the device around our public key and answers with the
 * tunnel's addresses and the peer's key; the second turns the tunnel on — an account
 * that was never switched on answers the handshake with silence, so skipping it is the
 * difference between a working profile and a dead one.
 *
 * The API is reachable from the home network directly (checked 2026-11-19), which is
 * why there is no relay here yet; if it ever starts being filtered, the call sites are
 * one function wide.
 */
object WarpClient {
    private const val REG_URL = "https://api.devices.cloudflare.com/v0a4005/reg"
    private const val CLIENT_VERSION = "a-6.11-2223"
    private const val USER_AGENT = "okhttp/3.12.1"

    private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()

    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .writeTimeout(20, TimeUnit.SECONDS)
        .build()

    private val random = SecureRandom()

    /**
     * The obfuscation the profiles of this account are born with. Only the junk before
     * the handshake and the decoy first packet are free to move: the far end is plain
     * WireGuard, so the header types stay 1..4 and the padding sizes stay zero — a
     * "proper" AmneziaWG 3.1 set would make Cloudflare drop every packet.
     */
    internal const val DEFAULT_I1 =
        "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"

    suspend fun register(): Result<WarpAccount> = withContext(Dispatchers.IO) {
        runCatching {
            val privateKey = ByteArray(32).also(random::nextBytes)
            val privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey)
            val publicKeyBase64 = Base64.getEncoder().encodeToString(X25519.publicKey(privateKey))

            val minted = parseRegistration(
                post(REG_URL, """{"key":"$publicKeyBase64"}""", token = null),
                privateKeyBase64,
                publicKeyBase64,
            )
            // The account exists but is not switched on: without this PATCH the peer
            // answers the handshake with silence.
            patch("$REG_URL/${minted.id}", minted.token)
            minted.account(junk())
        }
    }

    /** The registration's own answer, before the junk and the token are dropped. */
    internal data class Registration(
        val id: String,
        val token: String,
        val privateKey: String,
        val publicKey: String,
        val peerPublicKey: String,
        val ipv4: String,
        val ipv6: String,
    ) {
        fun account(junk: Junk): WarpAccount = WarpAccount(
            privateKey = privateKey,
            publicKey = publicKey,
            peerPublicKey = peerPublicKey,
            ipv4 = ipv4,
            ipv6 = ipv6,
            jc = junk.jc,
            jmin = junk.jmin,
            jmax = junk.jmax,
            i1 = DEFAULT_I1,
        )
    }

    internal data class Junk(val jc: Int, val jmin: Int, val jmax: Int)

    /** The ranges warpscout measured as broadly working: few packets, small sizes. */
    internal fun junk(): Junk {
        val jc = 4 + random.nextInt(3) // 4..6
        val jmin = 10 + random.nextInt(41) // 10..50
        val jmax = jmin + 20 + random.nextInt(81) // +20..100
        return Junk(jc, jmin, jmax)
    }

    internal fun parseRegistration(body: String, privateKey: String, publicKey: String): Registration {
        val root = Json.parseToJsonElement(body) as? JsonObject
            ?: error("WARP registration answered something that is not a JSON object")
        val id = (root["id"] as? JsonPrimitive)?.contentOrNull.orEmpty()
        val token = (root["token"] as? JsonPrimitive)?.contentOrNull.orEmpty()
        val config = root["config"] as? JsonObject
        val peer = (config?.get("peers") as? JsonArray)?.firstOrNull() as? JsonObject
        val peerKey = (peer?.get("public_key") as? JsonPrimitive)?.contentOrNull.orEmpty()
        val addresses = ((config?.get("interface") as? JsonObject)?.get("addresses") as? JsonObject)
        val ipv4 = (addresses?.get("v4") as? JsonPrimitive)?.contentOrNull.orEmpty()
        val ipv6 = (addresses?.get("v6") as? JsonPrimitive)?.contentOrNull.orEmpty()
        require(id.isNotBlank() && token.isNotBlank()) { "WARP registration returned no id or token" }
        require(peerKey.isNotBlank()) { "WARP registration returned no peer public key" }
        require(ipv4.isNotBlank()) { "WARP registration returned no tunnel address" }
        return Registration(id, token, privateKey, publicKey, peerKey, ipv4, ipv6)
    }

    private fun post(url: String, body: String, token: String?): String =
        request(url, body, token, "POST")

    private fun patch(url: String, token: String): String =
        request(url, """{"warp_enabled":true}""", token, "PATCH")

    private fun request(url: String, body: String, token: String?, method: String): String {
        val builder = Request.Builder()
            .url(url)
            .header("User-Agent", USER_AGENT)
            .header("CF-Client-Version", CLIENT_VERSION)
            .header("Content-Type", "application/json")
            .method(method, body.toRequestBody(JSON_MEDIA))
        if (token != null) builder.header("Authorization", "Bearer $token")
        client.newCall(builder.build()).execute().use { response ->
            val text = response.body.string()
            check(response.isSuccessful) { "WARP API answered ${response.code}: ${text.take(200)}" }
            return text
        }
    }
}
