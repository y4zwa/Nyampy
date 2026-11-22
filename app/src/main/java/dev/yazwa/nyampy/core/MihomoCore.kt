package dev.yazwa.nyampy.core

import android.content.Context
import android.net.ConnectivityManager
import android.os.ParcelFileDescriptor
import android.os.RemoteCallbackList
import android.os.RemoteException
import android.os.SystemClock
import android.util.Log
import androidx.core.content.edit
import nyampycore.Nyampycore
import java.io.File
import java.net.Inet4Address
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import dev.yazwa.nyampy.data.AtomicSnapshot
import dev.yazwa.nyampy.data.DailyTrafficStore
import dev.yazwa.nyampy.mihomo.ClashConfig

/**
 * Owner of the mihomo core (the gomobile bindings built from MetaCubeX/mihomo). Lives only in
 * the ":core" process, which stays alive while the VPN is up, independently of the UI.
 *
 * mihomo keeps its state in the process, not in a controller object: configure once, attach
 * the TUN handed over by [NyampyVpnService], then read the counters. Every call that touches
 * the core runs on one worker thread, the same discipline the Xray controller had.
 */
object MihomoCore {
    private const val TAG = "Nyampy/MihomoCore"

    /** How long a stop may take before the engine process is reaped. */
    private const val STOP_GRACE_MILLIS = 5_000L

    /** Where the geo databases and the generated config live. */
    private const val WORK_DIR = "mihomo"

    /** The geo files as mihomo wants them: capitalised, in its own home directory. */
    private const val GEOSITE = "GeoSite.dat"
    private const val GEOIP = "GeoIP.dat"

    /** The document's single-proxy name and the probe budget. */
    private const val LIVE_PROXY_NAME = "node"
    private const val PROBE_TIMEOUT_MS = 5000

    private const val LOG_CAPACITY = 1000
    private const val LOG_MAX_CHARS = 48 * 1024
    private var logChars = 0

    private lateinit var appContext: Context

    private val worker = Executors.newSingleThreadExecutor { Thread(it, "mihomo-worker") }

    private val initLatch = CountDownLatch(1)

    @Volatile
    private var initFailed: String? = null

    /** Whether the core is running (config applied and TUN attached). */
    @Volatile
    var isRunning: Boolean = false
        private set

    private val callbacks = RemoteCallbackList<ITunnelCallback>()

    @Volatile
    private var status = TunnelStatus()

    @Volatile
    private var connectedAtMillis = 0L

    private val logRing = ArrayDeque<String>(LOG_CAPACITY)

    /**
     * The app's own lines and the core's: the core's ring is what a rejected document
     * writes its reason to, and it was collected but never read. The two rings carry
     * different messages, so they simply follow each other.
     */
    fun coreLogs(): String {
        val local = synchronized(logRing) { logRing.joinToString("\n") }
        val core = runCatching { Nyampycore.logs() }.getOrNull().orEmpty()
        return when {
            core.isBlank() -> local
            local.isBlank() -> core
            else -> local + "\n" + core
        }
    }

    fun recordTunnelFailure(stage: String, error: Exception) {
        log(Log.ERROR, stage, error)
    }

    private fun log(level: Int, message: String, error: Exception? = null) {
        val line = when (level) {
            Log.ERROR -> "E/"
            Log.WARN -> "W/"
            else -> "I/"
        } + message.take(2048) + (error?.let { ": ${it.message.orEmpty().take(1024)}" } ?: "")
        synchronized(logRing) {
            while (logRing.isNotEmpty() && (logRing.size >= LOG_CAPACITY || logChars + line.length > LOG_MAX_CHARS)) {
                logChars -= logRing.removeFirst().length
            }
            logRing.addLast(line)
            logChars += line.length
        }
        if (error != null) {
            Log.println(level, TAG, "$message: ${error.message}")
        } else {
            Log.println(level, TAG, message)
        }
    }

    private var pendingUiRx = 0L
    private var pendingUiTx = 0L
    private val pendingDaily = linkedMapOf<Long, LongArray>()
    private var lastDailyFlush = 0L
    private var lastUiTrafficAt = 0L

    /** The last cumulative counters mihomo reported, for turning totals into deltas. */
    private var lastTotalUp = 0L
    private var lastTotalDown = 0L

    /** The config directory: mihomo's home (geodata) and the last written document. */
    fun workDir(context: Context = appContext): File = File(context.filesDir, WORK_DIR).also { it.mkdirs() }

    fun configFile(context: Context = appContext): File = File(workDir(context), "config.yaml")

    /** One-time environment init: data dir, geo assets, log level. */
    fun init(context: Context) {
        if (::appContext.isInitialized) return
        appContext = context.applicationContext
        worker.execute {
            try {
                installGeoAssets()
                Nyampycore.setHome(workDir().absolutePath)
                Nyampycore.setLogLevel("info")
                // A delay probe dials the proxy by its host name. Without a system
                // resolver the core cannot reach a hostname-based server even while
                // the phone's own DNS is fine — and no VPN start has handed it one yet.
                primeSystemDns()
                Nyampycore.subscribe()
                log(Log.INFO, "mihomo ${Nyampycore.version()} environment ready")
            } catch (e: Exception) {
                initFailed = e.message ?: e.javaClass.simpleName
                log(Log.ERROR, "Failed to init core environment", e)
            } finally {
                initLatch.countDown()
            }
        }
    }

    private fun awaitInit() {
        if (!initLatch.await(10, TimeUnit.SECONDS)) {
            throw IllegalStateException("Core environment init timed out")
        }
    }

    /**
     * The geo databases are shipped in the APK; mihomo wants them as plain files with its
     * own capitalisation, in its home directory. The copy is unconditional for the same
     * reason as before: replacing two slim files is cheaper than version bookkeeping.
     */
    private fun installGeoAssets() {
        val dir = workDir()
        listOf("geosite.dat" to GEOSITE, "geoip.dat" to GEOIP).forEach { (asset, target) ->
            val file = File(dir, target)
            appContext.assets.open(asset).use { input ->
                val tmp = File(dir, "$target.tmp")
                tmp.outputStream().use { output -> input.copyTo(output) }
                if (!tmp.renameTo(file)) {
                    tmp.delete()
                    throw IllegalStateException("Could not place $target")
                }
            }
            log(Log.INFO, "Installed $target (${file.length()} bytes)")
        }
    }

    /** The device's current resolvers, for a core that has not been configured yet. */
    private fun primeSystemDns() {
        val manager = appContext.getSystemService(ConnectivityManager::class.java) ?: return
        val network = manager.activeNetwork ?: return
        val servers = manager.getLinkProperties(network)?.dnsServers.orEmpty()
            .filterIsInstance<Inet4Address>()
            .mapNotNull { it.hostAddress }
            .distinct()
        setSystemDNS(servers)
    }

    /**
     * Applies [configYaml] and, on a fresh start, attaches [tun]: blocks until the tunnel
     * is up; returns null on success or the failure to show. Must run on the worker.
     *
     * [tun] is null on a reload: mihomo keeps the live descriptor and only the document
     * is replaced. A fresh start needs the interface; its descriptor is duplicated with
     * detachFd() so the core owns one fd while the VpnService keeps the other - closing
     * the same integer twice is what fdsan aborts on.
     *
     * [authentication] is the loopback inbound's Basic-auth from the session's snapshot:
     * the core forces it on the listener itself, so a document that lost the line still
     * cannot leave an open proxy behind.
     */
    fun startLoop(configYaml: String, tun: ParcelFileDescriptor?, authentication: String): Exception? {
        return try {
            awaitInit()
            initFailed?.let { return IllegalStateException(it) }
            val file = configFile()
            // Atomic: a process death mid-write must not leave a truncated document
            // behind for the next start to trip over.
            AtomicSnapshot.write(file, configYaml)
            val freshStart = !isRunning
            Nyampycore.configure(file.absolutePath, authentication)
            // A config swap on a live TUN is just a reload: mihomo applies the document
            // without touching the device, and the client's connections re-dial by
            // themselves. Only a fresh start (after a stop) needs a new listener.
            if (freshStart) {
                val source = tun ?: throw IllegalStateException("No TUN interface for a fresh start")
                // dup() shares the interface but not the descriptor number: the core
                // closes its copy, the service closes its own.
                val fd = source.dup().detachFd()
                Nyampycore.startTun(
                    fd.toLong(),
                    ClashConfig.TUN_MTU.toLong(),
                    "gvisor",
                    ClashConfig.GATEWAY,
                    ClashConfig.DNS_HIJACK,
                )
            } else {
                // A reloaded document leaves the connections opened through the old
                // outbound alive: without this the phone would keep two exit addresses at
                // once until those streams die on their own.
                Nyampycore.closeConnections()
            }
            synchronized(this) {
                lastTotalUp = Nyampycore.upTotal()
                lastTotalDown = Nyampycore.downTotal()
                if (freshStart) {
                    // The previous session's unread bytes belong to it, not to this one.
                    pendingUiRx = 0L
                    pendingUiTx = 0L
                    lastUiTrafficAt = SystemClock.elapsedRealtime()
                } else if (lastUiTrafficAt == 0L) {
                    lastUiTrafficAt = SystemClock.elapsedRealtime()
                }
            }
            // A reload keeps the session's clock: the tunnel never went down.
            if (freshStart) connectedAtMillis = System.currentTimeMillis()
            isRunning = true
            null
        } catch (e: Exception) {
            isRunning = false
            log(Log.ERROR, "startLoop failed", e)
            e
        }
    }

    /**
     * Detaches the TUN listener and the local inbounds; the core stays loaded for the
     * next start. Worker only. Called even when [isRunning] is false: a start that
     * failed after Configure still left the loopback proxy listening.
     */
    fun stopLoop() {
        synchronized(this) {
            if (isRunning) {
                sampleTraffic()
                flushDailyTraffic()
            }
            isRunning = false
        }
        try {
            Nyampycore.stopTun()
        } catch (e: Exception) {
            log(Log.WARN, "stopTun failed", e)
        }
        connectedAtMillis = 0L
    }

    /**
     * [stopLoop] behind a watchdog: the Go call runs on its own thread, and if it never
     * returns — a hung sing-tun close would leave the service sitting in Disconnecting
     * forever — the process is reaped. The service lives in ":core", so this takes the
     * engine down and nothing else; the UI sees the binder die and shows the tunnel as
     * down. Dev-only calls that cannot afford the wait still use [stopLoop] directly.
     */
    fun stopLoopWatched() {
        val finished = CountDownLatch(1)
        val worker = Thread({
            try {
                stopLoop()
            } finally {
                finished.countDown()
            }
        }, "core-stop")
        worker.isDaemon = true
        worker.start()
        if (!finished.await(STOP_GRACE_MILLIS, TimeUnit.MILLISECONDS)) {
            log(Log.ERROR, "The core did not stop within $STOP_GRACE_MILLIS ms; reaping the process")
            android.os.Process.killProcess(android.os.Process.myPid())
        }
    }

    fun currentStatus(): TunnelStatus = status

    fun upSince(): Long = connectedAtMillis

    fun publish(newStatus: TunnelStatus) = synchronized(callbacks) {
        status = newStatus
        val count = callbacks.beginBroadcast()
        try {
            for (index in 0 until count) {
                try {
                    callbacks.getBroadcastItem(index).onStateChanged(newStatus.state.ordinal, newStatus.error)
                } catch (_: RemoteException) {
                    // The listener died with its process; the broadcast ring drops it.
                }
            }
        } finally {
            callbacks.finishBroadcast()
        }
    }

    fun register(callback: ITunnelCallback) = synchronized(callbacks) {
        callbacks.register(callback)
        try {
            callback.onStateChanged(status.state.ordinal, status.error)
        } catch (_: RemoteException) {
            callbacks.unregister(callback)
        }
    }

    fun unregister(callback: ITunnelCallback) {
        callbacks.unregister(callback)
    }

    /**
     * A real HTTP delay through the profile's own proxy: mihomo parses the one-proxy
     * document and probes it the way its url-test group does, so the number matches
     * what every other Clash client shows.
     */
    fun measureOutboundDelay(configYaml: String, testUrl: String): Long {
        if (awaitInitOrNull() == null) return -1L
        return try {
            Nyampycore.testDelay(configYaml, testUrl.ifEmpty { ClashConfig.DEFAULT_TEST_URL }, PROBE_TIMEOUT_MS.toLong()).toLong()
        } catch (e: Exception) {
            log(Log.WARN, "testDelay failed", e)
            -1L
        }
    }

    /**
     * Delay through the *running* tunnel: the core probes the proxy it currently
     * carries, the same request its own url-test would send. [timeoutMillis] bounds the
     * probe — the warm-up hands it its own remaining budget so a dead node costs that
     * budget once instead of once per attempt.
     */
    fun measureLiveDelay(testUrl: String, timeoutMillis: Long = PROBE_TIMEOUT_MS.toLong()): Long {
        if (!isRunning) return -1L
        return try {
            Nyampycore.liveDelay(
                LIVE_PROXY_NAME,
                testUrl.ifEmpty { ClashConfig.DEFAULT_TEST_URL },
                timeoutMillis.coerceIn(500L, PROBE_TIMEOUT_MS.toLong()),
            ).toLong()
        } catch (e: Exception) {
            log(Log.WARN, "liveDelay failed", e)
            -1L
        }
    }

    private fun awaitInitOrNull(): Unit? = try {
        awaitInit()
        if (initFailed != null) null else Unit
    } catch (e: Exception) {
        log(Log.WARN, "Core init not ready", e)
        null
    }


    fun coreVersion(): String = try {
        Nyampycore.version()
    } catch (_: Throwable) {
        "mihomo"
    }

    /**
     * Hands the device's current resolvers to the core's `system` nameserver. The
     * document's private-zone policy names "system"; this is what fills it in, so a
     * handover only needs a fresh call, not a rebuilt document.
     */
    fun setSystemDNS(servers: List<String>) {
        if (servers.isEmpty()) return
        try {
            Nyampycore.setSystemDNS(servers.joinToString(","))
        } catch (e: Exception) {
            log(Log.WARN, "setSystemDNS failed", e)
        }
    }

    /**
     * Per-interval {rx, tx} bytes for the UI, in the same shape the Xray build produced:
     * mihomo reports cumulative totals, so the delta since the previous read is folded here.
     */
    @Synchronized
    fun trafficBytes(): LongArray {
        sampleTraffic()
        val now = SystemClock.elapsedRealtime()
        return longArrayOf(pendingUiRx, pendingUiTx, (now - lastUiTrafficAt).coerceAtLeast(1L)).also {
            pendingUiRx = 0L
            pendingUiTx = 0L
            lastUiTrafficAt = now
        }
    }

    /**
     * The core's cumulative counters as {down, up}. Unlike [trafficBytes] this read
     * takes nothing away, so the notification's live speed and the stats loop can look
     * at the same counters without stealing each other's deltas.
     */
    @Synchronized
    fun totals(): LongArray {
        if (!isRunning) return longArrayOf(0L, 0L)
        return try {
            longArrayOf(Nyampycore.downTotal(), Nyampycore.upTotal())
        } catch (e: Exception) {
            log(Log.WARN, "traffic totals failed", e)
            longArrayOf(0L, 0L)
        }
    }

    @Synchronized
    fun sampleTraffic() {
        val delta = queryTrafficBytes()
        pendingUiRx += delta[0]
        pendingUiTx += delta[1]
        if (delta[0] != 0L || delta[1] != 0L) {
            val day = java.time.LocalDate.now().toEpochDay()
            val bucket = pendingDaily.getOrPut(day) { longArrayOf(0, 0) }
            bucket[0] += delta[0]
            bucket[1] += delta[1]
        }
        if (System.currentTimeMillis() - lastDailyFlush >= 60_000L) flushDailyTraffic()
    }

    @Synchronized
    private fun flushDailyTraffic() {
        val iterator = pendingDaily.iterator()
        while (iterator.hasNext()) {
            val (day, bytes) = iterator.next()
            try {
                DailyTrafficStore.addDay(appContext, day, bytes[0], bytes[1])
                iterator.remove()
            } catch (e: Exception) {
                log(Log.WARN, "Could not save daily traffic; retaining pending bytes", e)
                break
            }
        }
        lastDailyFlush = System.currentTimeMillis()
    }

    private fun queryTrafficBytes(): LongArray {
        if (!isRunning) return longArrayOf(0L, 0L)
        return try {
            val upTotal = Nyampycore.upTotal()
            val downTotal = Nyampycore.downTotal()
            val rx = (downTotal - lastTotalDown).coerceAtLeast(0L)
            val tx = (upTotal - lastTotalUp).coerceAtLeast(0L)
            lastTotalUp = upTotal
            lastTotalDown = downTotal
            longArrayOf(rx, tx)
        } catch (e: Exception) {
            log(Log.WARN, "traffic query failed", e)
            longArrayOf(0L, 0L)
        }
    }
}
