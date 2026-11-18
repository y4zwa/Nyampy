package dev.yazwa.nyampy

import android.app.Application
import android.app.NotificationManager
import android.os.Build
import dev.yazwa.nyampy.core.TunnelClient
import dev.yazwa.nyampy.core.MihomoCore
import java.io.File

class NyampyApp : Application() {
    override fun onCreate() {
        super.onCreate()
        if (currentProcessName().endsWith(":core")) {
            // The ":core" process can be started by the system alone (Always-on VPN, the
            // QS tile, or a bound-only measurement), so the core is initialised here rather
            // than on the first command. The UI process never loads it.
            MihomoCore.init(this)
        } else {
            // The main process owns the profile database and the subscription machinery
            // on top of it; the ":core" process never opens either.
            Graph.init(this)
            // One shot per install, in the process the UI lives in: the channels the app
            // created before the rename are never posted to again, and Android keeps the
            // settings entries alive for as long as the ids exist.
            retireLegacyNotificationChannels()
            // The UI process's one tunnel link, bound for the whole process lifetime: every
            // screen can watch the tunnel state — the offline grayscale theme among them —
            // without a view model of its own. The main view model keeps driving connect and
            // disconnect over this same link.
            tunnelClient = TunnelClient(this).also { it.bind() }
        }
    }

    /**
     * Deletes the notification channels of the pre-rename builds — `chumpy-core`,
     * `chumpy-alerts`, `chumpy-updates` — once. Their settings entries would otherwise
     * sit in the system's list of this app forever; the ids the app writes now are the
     * `nyampy-*` ones, so nothing races. A channel that is not there is a no-op.
     */
    private fun retireLegacyNotificationChannels() {
        val prefs = getSharedPreferences(MIGRATIONS_PREFS, MODE_PRIVATE)
        if (prefs.getBoolean(LEGACY_CHANNELS_DONE, false)) return
        // minSdk is 26: the notification channel API is always there.
        getSystemService(NotificationManager::class.java)?.let { manager ->
            LEGACY_CHANNELS.forEach { id ->
                runCatching { manager.deleteNotificationChannel(id) }
            }
        }
        prefs.edit().putBoolean(LEGACY_CHANNELS_DONE, true).apply()
    }

    private fun currentProcessName(): String =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            getProcessName()
        } else {
            File("/proc/self/cmdline").readText().trimEnd('\u0000')
        }

    companion object {
        private const val MIGRATIONS_PREFS = "nyampy-migrations"
        private const val LEGACY_CHANNELS_DONE = "chumpy-notification-channels-retired"

        /** The channel ids every build before the rename used. */
        private val LEGACY_CHANNELS = listOf("chumpy-core", "chumpy-alerts", "chumpy-updates")

        /** The UI process's shared tunnel link; the ":core" process never initializes it. */
        lateinit var tunnelClient: TunnelClient
            private set
    }
}
