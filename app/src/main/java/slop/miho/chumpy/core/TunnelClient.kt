package slop.miho.chumpy.core

import android.content.ComponentName
import android.app.Application
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.RemoteException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * UI-process side of the AIDL link to [ChumpyVpnService]. Connect and disconnect travel as
 * service commands (the VPN must be started, not merely bound); the binder carries status
 * callbacks, traffic counters and delay measurements.
 */
class TunnelClient(context: Context) {
    internal companion object {
        const val MAX_PARALLEL_DELAY_TESTS = 25
    }

    private val context: Application = context.applicationContext as Application
    private val _status = MutableStateFlow(TunnelStatus())
    val status: StateFlow<TunnelStatus> = _status.asStateFlow()

    @Volatile
    private var service: ITunnelService? = null
    private var bound = false

    private val callback = object : ITunnelCallback.Stub() {
        override fun onStateChanged(state: Int, error: String?) {
            _status.value = TunnelStatus(TunnelState.fromOrdinal(state), error)
        }
    }

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            val remote = ITunnelService.Stub.asInterface(binder)
            service = remote
            call(remote) { it.registerCallback(callback) }
        }

        override fun onServiceDisconnected(name: ComponentName) {
            // ":core" died; BIND_AUTO_CREATE brings it back and we reconnect automatically.
            service = null
            _status.value = TunnelStatus()
        }
    }

    fun bind() {
        if (bound) return
        bound = context.bindService(
            Intent(context, ChumpyVpnService::class.java),
            connection,
            Context.BIND_AUTO_CREATE,
        )
    }

    fun unbind() {
        if (!bound) return
        service?.let { remote -> call(remote) { it.unregisterCallback(callback) } }
        context.unbindService(connection)
        service = null
        bound = false
    }

    /**
     * Connect (or reload, if already up) using the config the caller just wrote with
     * [CoreConfigFile]. The caller must hold the VPN consent already.
     */
    fun connect() = ChumpyVpnService.startConnect(context)

    fun disconnect() = ChumpyVpnService.startDisconnect(context)

    /** Wall-clock millis of the last transition to UP, or null while not bound. */
    fun connectedAtMillis(): Long? {
        val remote = service ?: return null
        return try {
            remote.connectedAtMillis()
        } catch (_: RemoteException) {
            null
        }
    }

    fun trafficBytes(): LongArray? {
        val remote = service ?: return null
        return try {
            remote.trafficBytes()
        } catch (_: RemoteException) {
            null
        }
    }

    /**
     * A real delay measurement through [configJson], performed by a one-off core instance
     * in the ":core" process. Null when unreachable.
     */
    suspend fun measureDelay(configJson: String, testUrl: String): Long? {
        val remote = service ?: return null
        val binder = remote.asBinder()
        val result = CompletableDeferred<Long?>()
        val deathRecipient = IBinder.DeathRecipient { result.complete(null) }
        val callback = object : IDelayResult.Stub() {
            override fun onResult(delayMillis: Long) {
                result.complete(delayMillis.takeIf { it >= 0 })
            }
        }
        return try {
            binder.linkToDeath(deathRecipient, 0)
            try {
                remote.measureDelay(configJson, testUrl, callback)
                // Keep the caller's permit until the native request actually finishes.
                withContext(NonCancellable) { result.await() }
            } finally {
                binder.unlinkToDeath(deathRecipient, 0)
            }
        } catch (_: RemoteException) {
            null
        }
    }

    /**
     * Delay through the *running* tunnel (the probe path for Home's ping chip and the
     * stats screen's loss buckets). Null while not bound or the core is down.
     */
    fun measureLiveDelay(testUrl: String): Long? {
        val remote = service ?: return null
        return try {
            remote.measureLiveDelay(testUrl).takeIf { it >= 0 }
        } catch (_: RemoteException) {
            null
        }
    }

    /** The Xray core version, or null while the core process is unreachable. */
    fun coreVersion(): String? {
        val remote = service ?: return null
        return try {
            remote.coreVersion()
        } catch (_: RemoteException) {
            null
        }
    }

    /** The core's captured log tail, or null while the core process is unreachable. */
    fun coreLogs(): String? {
        val remote = service ?: return null
        return try {
            remote.coreLogs()
        } catch (_: RemoteException) {
            null
        }
    }

    private fun call(remote: ITunnelService, action: (ITunnelService) -> Unit) {
        try {
            action(remote)
        } catch (_: RemoteException) {
            // onServiceDisconnected will follow.
        }
    }
}
