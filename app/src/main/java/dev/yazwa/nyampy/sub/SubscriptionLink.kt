package dev.yazwa.nyampy.sub

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

internal object SubscriptionLink {
    fun parse(link: String): String? {
        // Nyampy's own scheme, with the upstream one still honoured: links handed out
        // before the fork keep working.
        val prefix = listOf("nyampy://add/", "chumpy://add/")
            .firstOrNull { link.startsWith(it, ignoreCase = true) } ?: return null
        if (link.length > 16_384) return null
        val url = link.substring(prefix.length).toHttpUrlOrNull() ?: return null
        if (url.username.isNotEmpty() || url.password.isNotEmpty()) return null
        return url.toString()
    }
}
