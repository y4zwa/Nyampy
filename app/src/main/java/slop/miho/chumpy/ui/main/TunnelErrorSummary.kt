package slop.miho.chumpy.ui.main

import androidx.annotation.StringRes
import slop.miho.chumpy.R

@StringRes
internal fun tunnelErrorSummary(rawError: String): Int {
    val message = rawError.lowercase()
    fun has(vararg snippets: String) = snippets.any { it in message }

    return when {
        has("address already in use", "eaddrinuse") -> R.string.tunnel_error_port_busy
        has("geosite.dat", "geoip.dat", "failed to load geosite", "failed to load geoip",
            "failed to load geo site", "failed to load geo ip", "failed to check code") ->
            R.string.tunnel_error_geodata
        has("unknown transport protocol", "unknown protocol", "unknown config id",
            "unsupported cipher method", "unknown cipher method") ->
            R.string.tunnel_error_protocol
        has("x509:", "failed to parse certificate", "failed to parse private key",
            "failed to build tls", "failed to build reality", "certificate verify failed",
            "tls handshake failure", "reality verification failed") ->
            R.string.tunnel_error_security
        has("failed to build routing configuration", "invalid router rule", "invalid field rule",
            "invalid domain rule", "illegal domain rule", "unknown balancing strategy") ->
            R.string.tunnel_error_routing
        has("failed to build dns configuration", "failed to parse name server", "invalid dns hosts",
            "failed to build nameserver", "no such host", "server misbehaving") ->
            R.string.tunnel_error_dns
        has("cannot assign requested address", "failed to listen", "bind: permission denied") ->
            R.string.tunnel_error_listener
        has("network is unreachable", "no route to host", "network is down") ->
            R.string.tunnel_error_network
        has("connection refused", "connection reset by peer") -> R.string.tunnel_error_connection
        has("i/o timeout", "context deadline exceeded", "tls handshake timeout", "connection timed out") ->
            R.string.tunnel_error_timeout
        has("core shutdown is still pending") -> R.string.tunnel_error_stopping
        has("no space left on device") -> R.string.tunnel_error_storage
        has("config error", "failed to build config", "failed to parse json config",
            "failed to read config", "failed to load config", "failed to decode config") ->
            R.string.tunnel_error_config
        else -> R.string.tunnel_error_generic
    }
}
