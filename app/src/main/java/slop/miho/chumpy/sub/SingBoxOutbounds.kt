package slop.miho.chumpy.sub

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import slop.miho.chumpy.db.ProfileEntity
import slop.miho.chumpy.db.ProfileType
import java.util.Base64
import java.util.UUID

internal object SingBoxOutbounds {
    private val tlsFields = setOf("enabled", "server_name", "insecure", "alpn", "utls", "reality", "certificate")

    private val endpointFields = setOf("type", "tag", "server", "server_port", "detour")
    private val trojanFields = endpointFields + setOf("password", "tls", "transport", "multiplex", "network")
    private val shadowsocksFields = endpointFields + setOf(
        "method", "password", "plugin", "plugin_opts", "multiplex", "network", "udp_over_tcp",
    )
    private val socksFields = endpointFields + setOf("version", "username", "password", "network", "udp_over_tcp")
    private val shadowsocksMethods = setOf(
        "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    )

    fun parse(config: JsonObject): List<ProfileEntity> =
        (config["outbounds"] as? JsonArray).orEmpty().filterIsInstance<JsonObject>().mapNotNull(::profile)

    private fun profile(outbound: JsonObject): ProfileEntity? {
        val type = when (outbound.string("type")) {
            "vless" -> ProfileType.VLESS
            "hysteria2" -> ProfileType.HYSTERIA2
            "trojan" -> ProfileType.TROJAN
            "shadowsocks" -> ProfileType.SHADOWSOCKS
            "socks" -> ProfileType.SOCKS
            else -> return null
        }
        if (outbound.string("detour").orEmpty().isNotEmpty()) return null
        val server = outbound.string("server")?.takeIf { it.isNotBlank() } ?: return null
        val port = (outbound["server_port"] as? JsonPrimitive)?.intOrNull
            ?.takeIf { it in 1..65535 } ?: return null
        val password = if (type == ProfileType.SOCKS) {
            outbound.string("password").orEmpty()
        } else if (type == ProfileType.VLESS) {
            val uuid = outbound.string("uuid") ?: return null
            val normalized = runCatching { UUID.fromString(uuid).toString() }.getOrNull() ?: return null
            if (!normalized.equals(uuid, ignoreCase = true)) return null
            normalized
        } else {
            outbound.string("password")?.takeIf { it.isNotEmpty() } ?: return null
        }
        val base = ProfileEntity(
            id = "",
            subscriptionId = null,
            type = type,
            remarks = outbound.string("tag").orEmpty(),
            server = server,
            serverPort = port,
            password = password,
        )
        val secure = applyTls(base, outbound["tls"]) ?: return null
        return when (type) {
            ProfileType.VLESS -> {
                val flow = outbound.string("flow").orEmpty()
                if (flow !in setOf("", "xtls-rprx-vision")) return null
                if (outbound.obj("multiplex")?.enabled() == true) return null
                val encoding = outbound.string("packet_encoding")
                if (encoding != null && encoding != "xudp") return null
                applyTransport(secure.copy(method = "none", flow = flow), outbound["transport"])
            }
            ProfileType.HYSTERIA2 -> applyHysteria(secure, outbound)
            ProfileType.TROJAN -> {
                if (!supportsOptions(outbound, trojanFields) || secure.security != "tls" || secure.allowInsecure) return null
                val tls = outbound.obj("tls") ?: return null
                val utls = tls["utls"]
                if (utls != null && (utls !is JsonObject || utls.keys.any { it !in setOf("enabled", "fingerprint") })) return null
                if (utls is JsonObject && utls.enabled() && secure.fingerprint.isEmpty()) return null
                applyTransport(secure, outbound["transport"])
            }
            ProfileType.SHADOWSOCKS -> {
                if (!supportsOptions(outbound, shadowsocksFields)) return null
                if (!outbound.isEmptyString("plugin") || !outbound.isEmptyString("plugin_opts")) return null
                val method = outbound.string("method")?.takeIf { it in shadowsocksMethods } ?: return null
                secure.copy(method = method)
            }
            ProfileType.SOCKS -> {
                if (!supportsOptions(outbound, socksFields)) return null
                if (outbound["version"] != null && outbound.string("version") !in setOf("", "5")) return null
                val username = outbound.string("username").orEmpty()
                if (outbound["username"] != null && outbound.string("username") == null) return null
                if (outbound["password"] != null && outbound.string("password") == null) return null
                if (username.isEmpty() && password.isNotEmpty()) return null
                secure.copy(username = username)
            }
            else -> null
        }
    }

    private fun supportsOptions(outbound: JsonObject, fields: Set<String>): Boolean {
        if (outbound.keys.any { it !in fields }) return false
        if (!outbound.isEmptyString("network") || !outbound.isEmptyString("detour")) return false
        val multiplex = outbound["multiplex"]
        if (multiplex != null && (multiplex !is JsonObject || multiplex.enabled())) return false
        val udpOverTcp = outbound["udp_over_tcp"]
        return udpOverTcp == null || udpOverTcp == JsonPrimitive(false) ||
            (udpOverTcp is JsonObject && udpOverTcp["enabled"] == JsonPrimitive(false))
    }

    private fun JsonObject.isEmptyString(key: String): Boolean = this[key] == null || string(key) == ""

    private fun applyTls(profile: ProfileEntity, element: JsonElement?): ProfileEntity? {
        if (element == null) return profile
        val tls = element as? JsonObject ?: return null
        if (!tls.enabled()) return profile
        if (tls.keys.any { it !in tlsFields }) return null
        val utls = tls.obj("utls")
        val fingerprint = if (utls?.enabled() == true) utls.string("fingerprint").orEmpty() else ""
        val reality = tls.obj("reality")
        val serverName = tls.string("server_name").orEmpty()
        if (reality?.enabled() == true) {
            val publicKey = reality.string("public_key")?.takeIf { it.isNotBlank() } ?: return null
            if (profile.type != ProfileType.VLESS || fingerprint.isEmpty() || tls.containsKey("certificate")) return null
            return profile.copy(
                security = "reality",
                sni = serverName,
                fingerprint = fingerprint,
                publicKey = publicKey,
                shortId = reality.string("short_id").orEmpty(),
            )
        }

        val certificate = tls["certificate"]?.let { value ->
            val lines = stringList(value) ?: return null
            if (lines.isEmpty()) null else validatedCertificate(lines) ?: return null
        }
        val alpn = tls["alpn"]?.let { stringList(it) ?: return null }.orEmpty()
        return profile.copy(
            security = "tls",
            sni = serverName.ifEmpty { profile.server },
            fingerprint = fingerprint,
            alpn = alpn.joinToString(","),
            allowInsecure = (tls["insecure"] as? JsonPrimitive)?.booleanOrNull == true,
            tlsTrustCertificate = certificate,
        )
    }

    private fun applyTransport(profile: ProfileEntity, element: JsonElement?): ProfileEntity? {
        if (element == null) return profile
        val transport = element as? JsonObject ?: return null
        val type = transport.string("type")
        return when (type) {
            "ws", "httpupgrade" -> {
                val fields = if (type == "ws") setOf("type", "path", "headers") else setOf("type", "path", "headers", "host")
                if (transport.keys.any { it !in fields }) return null
                val headers = transport["headers"]?.let { it as? JsonObject ?: return null }
                if (headers?.keys?.any { !it.equals("host", true) } == true) return null
                val host = headers?.entries?.firstOrNull()?.value?.let { value ->
                    stringList(value)?.singleOrNull() ?: return null
                }
                profile.copy(network = type, host = transport.string("host") ?: host.orEmpty(), path = transport.string("path") ?: "/")
            }
            "grpc" -> {
                if (transport.keys.any { it != "type" && it != "service_name" }) return null
                profile.copy(network = "grpc", serviceName = transport.string("service_name").orEmpty())
            }
            else -> null
        }
    }

    private fun applyHysteria(profile: ProfileEntity, outbound: JsonObject): ProfileEntity? {
        if (profile.security != "tls" || outbound.containsKey("server_ports") || outbound.containsKey("transport")) return null
        if ((outbound["bbr_profile"] as? JsonPrimitive)?.content?.isNotEmpty() == true) return null
        val obfs = outbound["obfs"]?.let { it as? JsonObject ?: return null }
        val obfsPassword = if (obfs == null) "" else {
            if (obfs.string("type") != "salamander") return null
            obfs.string("password")?.takeIf { it.isNotEmpty() } ?: return null
        }
        val up = outbound["up_mbps"]?.let { (it as? JsonPrimitive)?.intOrNull?.takeIf { rate -> rate >= 0 } ?: return null }
        val down = outbound["down_mbps"]?.let { (it as? JsonPrimitive)?.intOrNull?.takeIf { rate -> rate >= 0 } ?: return null }
        return profile.copy(
            network = "hysteria",
            obfsPassword = obfsPassword,
            hysteriaUpMbps = up?.takeIf { it > 0 },
            hysteriaDownMbps = down?.takeIf { it > 0 },
        )
    }

    private fun validatedCertificate(lines: List<String>): String? {
        val pem = lines.joinToString("\n").trim()
        val begin = "-----BEGIN CERTIFICATE-----"
        val end = "-----END CERTIFICATE-----"
        if (pem.length > 64 * 1024 || !pem.endsWith(end)) return null
        val blocks = pem.split(end).dropLast(1)
        for (block in blocks) {
            val certificate = block.trim()
            if (!certificate.startsWith(begin)) return null
            val payload = certificate.removePrefix(begin).filterNot(Char::isWhitespace)
            val der = runCatching { Base64.getDecoder().decode(payload) }.getOrNull() ?: return null
            if (der.firstOrNull() != 0x30.toByte()) return null
        }
        // Xray uses Go's X.509 parser, which accepts certificates with an empty issuer DN.
        return pem
    }

    private fun stringList(value: JsonElement): List<String>? {
        return when (value) {
            is JsonArray -> value.map { (it as? JsonPrimitive)?.takeIf { item -> item.isString }?.content ?: return null }
            is JsonPrimitive -> if (value.isString) listOf(value.content) else null
            else -> null
        }
    }

    private fun JsonObject.string(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
    private fun JsonObject.obj(key: String): JsonObject? = this[key] as? JsonObject
    private fun JsonObject.enabled(): Boolean = (this["enabled"] as? JsonPrimitive)?.booleanOrNull == true
}
