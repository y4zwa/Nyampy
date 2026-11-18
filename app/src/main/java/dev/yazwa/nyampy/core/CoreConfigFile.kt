package dev.yazwa.nyampy.core

import android.content.Context
import dev.yazwa.nyampy.data.AtomicSnapshot
import dev.yazwa.nyampy.mihomo.LocalProxy
import dev.yazwa.nyampy.ui.components.splitLeadingFlag
import dev.yazwa.nyampy.ui.components.splitLeadingPrideFlag
import java.io.File

/**
 * The config hand-off between the two processes: the UI process (which owns the profile
 * database) renders the full mihomo YAML document and writes it here, and the ":core"
 * process reads it whenever it brings the tunnel up — on a user connect, on an Always-on
 * restart, or on a QS tile toggle. Plain files, written atomically, read on demand: no
 * Room access from the core process, ever.
 *
 * The legacy file is still named config.json; its content has been YAML since the move
 * to mihomo.
 */
object CoreConfigFile {
    private const val DIR = "core"
    private const val CONFIG = "config.json"
    private const val PROFILE = "profile.txt"
    private const val SUBSCRIPTION = "subscription.txt"

    private fun dir(context: Context): File = File(context.filesDir, DIR).also { it.mkdirs() }

    data class Snapshot(
        val config: String,
        val profileName: String?,
        val subscriptionName: String?,
        val profileId: String? = null,
        val subscriptionId: String? = null,
        val server: String? = null,
        val localProxy: LocalProxy? = null,
    )

    private var cachedKey: String? = null
    private var cachedSnapshot: Snapshot? = null

    @Synchronized
    fun snapshot(context: Context): Snapshot? = runCatching { readSnapshot(context) }.getOrNull()

    private fun readSnapshot(context: Context): Snapshot? {
        val directory = dir(context)
        val bundle = File(directory, "session.json")
        if (bundle.exists()) return runCatching {
            val attributes = java.nio.file.Files.readAttributes(bundle.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java)
            val key = "${bundle.absolutePath}:${attributes.fileKey()}:${attributes.size()}:${attributes.lastModifiedTime()}"
            if (cachedKey == key) return cachedSnapshot
            val json = org.json.JSONObject(AtomicSnapshot.read(bundle) ?: return null)
            val config = json.getString("config")
            if (config.isBlank()) {
                cachedKey = key
                cachedSnapshot = null
                return null
            }
            fun field(key: String) = json.optString(key).takeIf { it.isNotEmpty() }
            Snapshot(
                config, field("profile"), field("subscription"), field("profileId"),
                field("subscriptionId"), field("server"), proxyOf(json),
            ).also {
                cachedKey = key
                cachedSnapshot = it
            }
        }.getOrNull()
        val config = AtomicSnapshot.read(File(directory, CONFIG))?.takeIf { it.isNotBlank() } ?: return null
        return Snapshot(config, AtomicSnapshot.read(File(directory, PROFILE)),
            AtomicSnapshot.read(File(directory, SUBSCRIPTION)))
    }

    private fun proxyOf(json: org.json.JSONObject): LocalProxy? {
        val port = json.optInt("proxyPort", 0)
        val username = json.optString("proxyUser")
        val password = json.optString("proxyPassword")
        return if (port in 1..65535 && username.isNotEmpty() && password.isNotEmpty()) {
            LocalProxy(port, username, password)
        } else {
            null
        }
    }

    /** The loopback proxy of the last written document; null before the first connect. */
    fun localProxy(context: Context): LocalProxy? = snapshot(context)?.localProxy

    fun readConfig(context: Context): String? = snapshot(context)?.config
    fun readProfileName(context: Context): String? = snapshot(context)?.let { saved ->
        saved.profileName?.trim()?.takeIf {
            it.isNotEmpty() && !(dev.yazwa.nyampy.data.SettingsStore.tileSettings(context).maskAddresses && it == saved.server)
        }
    }
    fun readSubscriptionName(context: Context): String? = snapshot(context)?.subscriptionName?.trim()?.takeIf { it.isNotEmpty() }
    fun has(context: Context): Boolean = snapshot(context) != null

    @Synchronized
    fun write(context: Context, configJson: String, profileName: String?, subscriptionName: String?,
        profileId: String? = null, subscriptionId: String? = null, server: String? = null,
        localProxy: LocalProxy? = null) {
        cachedKey = null
        val json = org.json.JSONObject().put("config", configJson)
            .put("profile", profileName.orEmpty()).put("subscription", subscriptionName.orEmpty())
            .put("profileId", profileId.orEmpty()).put("subscriptionId", subscriptionId.orEmpty())
            .put("server", server.orEmpty())
            .put("proxyPort", localProxy?.port ?: 0)
            .put("proxyUser", localProxy?.username.orEmpty())
            .put("proxyPassword", localProxy?.password.orEmpty())
        AtomicSnapshot.write(File(dir(context), "session.json"), json.toString())
    }

    @Synchronized
    fun clear(context: Context) {
        val directory = dir(context)
        cachedKey = null
        cachedSnapshot = null
        AtomicSnapshot.write(File(directory, "session.json"), org.json.JSONObject().put("config", "").toString())
        listOf(CONFIG, PROFILE, SUBSCRIPTION).forEach { File(directory, it).delete() }
    }

}

/** The profile name the way the server list shows it: the leading flag lifted off —
 *  the pride emoji first, then the country's — the same pair of splits the rows do,
 *  leaving the name that reads beside the row's flag. */
internal fun stripFlag(name: String): String {
    val afterPride = splitLeadingPrideFlag(name).second
    return splitLeadingFlag(afterPride).second.trim()
}
