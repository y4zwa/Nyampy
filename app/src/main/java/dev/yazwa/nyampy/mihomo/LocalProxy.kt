package dev.yazwa.nyampy.mihomo

import java.security.SecureRandom

/**
 * The loopback mixed inbound the UI process uses while the tunnel is up. The port and
 * the credentials are regenerated for every connect: the listener is local-only, but
 * any app on the device can reach another app's loopback, so an unauthenticated fixed
 * port is a free proxy. Basic auth is what mihomo's mixed listener checks.
 */
data class LocalProxy(
    val port: Int,
    val username: String,
    val password: String,
) {
    val authentication: String get() = "$username:$password"

    companion object {
        private const val USERNAME = "nyampy"
        private val random = SecureRandom()

        /** A fresh high port and a fresh password; [port] is never 0 (that disables). */
        fun random(): LocalProxy {
            val port = freePort()
            val bytes = ByteArray(18).also(random::nextBytes)
            val password = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
            return LocalProxy(port, USERNAME, password)
        }

        /**
         * An ephemeral loopback port the OS just confirmed free. The close/bind gap is
         * tiny; the fallback range keeps a socket failure from blocking the connect.
         */
        private fun freePort(): Int = runCatching {
            java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())
                .use { it.localPort }
        }.getOrElse { 20_000 + random.nextInt(40_000) }
    }
}
