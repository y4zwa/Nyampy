package dev.yazwa.nyampy.ui.wallpapers

import android.os.Bundle
import dev.yazwa.nyampy.ui.components.ControllerActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.yazwa.nyampy.data.SettingsStore
import dev.yazwa.nyampy.data.WallpaperRegistry
import dev.yazwa.nyampy.ui.theme.ChumpyTheme

/**
 * The wallpaper settings, a deep-dive screen in the fonts' footsteps rather than a navbar
 * destination. Two pages under one bar: a preview mimicking the home screen (the picker and
 * the dimming slider where the server card and the connect button sit), and the settings
 * page with the scrim tone, the dimming/blur sliders and the page-zoom toggle. The system
 * back gesture and the bar's back button both simply finish this activity.
 */
class WallpaperActivity : ControllerActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            val settings by SettingsStore.settings(this).collectAsStateWithLifecycle()
            ChumpyTheme(settings = settings) {
                Surface(color = MaterialTheme.colorScheme.surface) {
                    WallpaperScreen(
                        settings = settings,
                        onSettings = { change -> SettingsStore.update(this, change) },
                        onSetWallpaper = { uri -> WallpaperRegistry.set(this, uri) },
                        onBack = ::finish,
                    )
                }
            }
        }
    }
}
