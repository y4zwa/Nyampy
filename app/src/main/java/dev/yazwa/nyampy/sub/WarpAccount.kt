package dev.yazwa.nyampy.sub

import android.content.Context
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import java.io.File

/**
 * One registered WARP device, plus the AmneziaWG obfuscation it was generated with.
 * The API hands out the tunnel's own addresses and the peer key; the private key is
 * ours, generated before the call and never sent anywhere in full — only its public
 * half goes up.
 *
 * The junk parameters live here because they are per-device, not per-endpoint: every
 * profile of the group reuses them, so a regeneration keeps the same rows (and their
 * measured pings) instead of minting new identities.
 */
data class WarpAccount(
    val privateKey: String,
    val publicKey: String,
    val peerPublicKey: String,
    val ipv4: String,
    val ipv6: String,
    val jc: Int,
    val jmin: Int,
    val jmax: Int,
    val i1: String,
)

/** The account file: one JSON object under the app's own files directory. */
class WarpAccountStore(private val file: File) {
    constructor(context: Context) : this(File(context.filesDir, "warp-account.json"))

    fun load(): WarpAccount? {
        if (!file.isFile) return null
        return runCatching { parse(file.readText()) }.getOrNull()
    }

    fun save(account: WarpAccount) {
        val json = buildJsonObject {
            put("private_key", JsonPrimitive(account.privateKey))
            put("public_key", JsonPrimitive(account.publicKey))
            put("peer_public_key", JsonPrimitive(account.peerPublicKey))
            put("ipv4", JsonPrimitive(account.ipv4))
            put("ipv6", JsonPrimitive(account.ipv6))
            put("jc", JsonPrimitive(account.jc))
            put("jmin", JsonPrimitive(account.jmin))
            put("jmax", JsonPrimitive(account.jmax))
            put("i1", JsonPrimitive(account.i1))
        }.toString()
        // Written through a temporary file: a torn account file would cost a new
        // registration, and the API is not something to hit twice for a crash.
        val temp = File(file.parentFile, "${file.name}.tmp")
        temp.writeText(json)
        if (!temp.renameTo(file)) {
            file.writeText(json)
            temp.delete()
        }
    }

    fun clear() {
        file.delete()
    }

    internal fun parse(body: String): WarpAccount? {
        val root = runCatching { Json.parseToJsonElement(body) as? JsonObject }.getOrNull() ?: return null
        fun text(key: String): String = (root[key] as? JsonPrimitive)?.contentOrNull.orEmpty()
        fun number(key: String, fallback: Int): Int =
            (root[key] as? JsonPrimitive)?.intOrNull ?: fallback
        val account = WarpAccount(
            privateKey = text("private_key"),
            publicKey = text("public_key"),
            peerPublicKey = text("peer_public_key"),
            ipv4 = text("ipv4"),
            ipv6 = text("ipv6"),
            jc = number("jc", 0),
            jmin = number("jmin", 0),
            jmax = number("jmax", 0),
            i1 = text("i1"),
        )
        return account.takeIf {
            it.privateKey.isNotBlank() && it.peerPublicKey.isNotBlank() && it.ipv4.isNotBlank()
        }
    }
}
