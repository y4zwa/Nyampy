package dev.yazwa.nyampy.ui.components

import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.view.HapticFeedbackConstants
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import dev.yazwa.nyampy.ui.theme.LocalUiSettings

/**
 * A very short haptic poke for taps, gated by the "Haptic feedback" setting. A ~15ms
 * vibrator pulse rather than a system feedback constant: the constants are either a full
 * tap-sized buzz (virtual key) or barely felt (the tick family), while a pulse this short
 * stays a crisp poke. Fired from click handlers, not press state — on a quick tap the press
 * state can flip up and down within a single frame and never be observed.
 *
 * The pulse leaves the main thread: the vibrator's binder call can sit on slow ROMs for a
 * good while, and no tap's ripple — or launch it triggers — should freeze behind it.
 */
@Composable
fun rememberHapticPoke(): () -> Unit {
    val vibrator = LocalContext.current.getSystemService(Vibrator::class.java)
    val enabled = LocalUiSettings.current.hapticFeedback
    val scope = rememberCoroutineScope()
    return remember(vibrator, enabled) {
        {
            if (enabled && vibrator?.hasVibrator() == true) {
                scope.launch(Dispatchers.Default) {
                    vibrator.vibrate(
                        VibrationEffect.createOneShot(POKE_MILLIS, VibrationEffect.DEFAULT_AMPLITUDE),
                    )
                }
            }
        }
    }
}

/**
 * A tap's answer in the device's own voice: the platform's tuned UI tick (EFFECT_TICK, or
 * the view's CLOCK_TICK where effects aren't there) instead of the raw one-shot buzz. The
 * motors on Samsungs and Pixels render these from a small shaped envelope — a crisp,
 * short tick — while a bare 15 ms pulse on the same motor reads as a dull buzz.
 *
 * [firm] is the heavier cut for a button that does something bigger than a tab: the gear,
 * the back arrow. Off where the effect family is missing, the constants step up the same way.
 */
@Composable
fun rememberHapticTick(firm: Boolean = false): () -> Unit {
    val view = LocalView.current
    val vibrator = LocalContext.current.getSystemService(Vibrator::class.java)
    val enabled = LocalUiSettings.current.hapticFeedback
    val scope = rememberCoroutineScope()
    return remember(view, vibrator, enabled, firm) {
        {
            if (enabled) {
                val effect = if (firm) VibrationEffect.EFFECT_CLICK else VibrationEffect.EFFECT_TICK
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && vibrator?.hasVibrator() == true) {
                    scope.launch(Dispatchers.Default) {
                        runCatching { vibrator.vibrate(VibrationEffect.createPredefined(effect)) }
                    }
                } else {
                    view.performHapticFeedback(
                        if (firm) HapticFeedbackConstants.CONTEXT_CLICK
                        else HapticFeedbackConstants.CLOCK_TICK,
                    )
                }
            }
        }
    }
}

/**
 * A softer poke — the pull-to-refresh threshold's "you're past the line": the same brief
 * pulse as a tap at a quarter of the amplitude. Devices with a good haptic motor (Pixels)
 * read the full-amplitude poke as a heavy thump there, where the gesture only wants a
 * tick. Without amplitude control (older motors) the plain short poke stays — it is
 * barely felt on those anyway.
 */
@Composable
fun rememberHapticSoftPoke(): () -> Unit {
    val vibrator = LocalContext.current.getSystemService(Vibrator::class.java)
    val enabled = LocalUiSettings.current.hapticFeedback
    val scope = rememberCoroutineScope()
    return remember(vibrator, enabled) {
        {
            if (enabled && vibrator?.hasVibrator() == true) {
                val amplitude = if (vibrator.hasAmplitudeControl()) SOFT_POKE_AMPLITUDE
                else VibrationEffect.DEFAULT_AMPLITUDE
                scope.launch(Dispatchers.Default) {
                    vibrator.vibrate(
                        VibrationEffect.createOneShot(POKE_MILLIS, amplitude),
                    )
                }
            }
        }
    }
}

/**
 * [count] crisp pokes in a row — a double reads as "that worked". The same pulse as the tap
 * poke, so multi-poke feedback matches the single one in feel.
 */
@Composable
fun rememberHapticPokes(count: Int): () -> Unit {
    val vibrator = LocalContext.current.getSystemService(Vibrator::class.java)
    val enabled = LocalUiSettings.current.hapticFeedback
    val scope = rememberCoroutineScope()
    return remember(vibrator, enabled, count) {
        {
            if (enabled && vibrator?.hasVibrator() == true) {
                scope.launch {
                    repeat(count) {
                        vibrator.vibrate(
                            VibrationEffect.createOneShot(POKE_MILLIS, VibrationEffect.DEFAULT_AMPLITUDE),
                        )
                        delay(POKE_INTERVAL_MILLIS)
                    }
                }
            }
        }
    }
}

/**
 * [count] "grumpy" kicks — the same REJECT haptic a denied pull-to-refresh fires. Used when
 * something went wrong: a failed connect, a denied gesture.
 */
@Composable
fun rememberHapticDeniedKicks(count: Int = DENIED_KICK_COUNT): () -> Unit {
    val view = LocalView.current
    val enabled = LocalUiSettings.current.hapticFeedback
    val scope = rememberCoroutineScope()
    return remember(view, enabled, count) {
        {
            if (enabled) {
                scope.launch {
                    repeat(count) {
                        view.performHapticFeedback(deniedKickConstant())
                        delay(DENIED_KICK_INTERVAL_MILLIS)
                    }
                }
            }
        }
    }
}

private const val POKE_MILLIS = 15L
private const val SOFT_POKE_AMPLITUDE = 64
private const val POKE_INTERVAL_MILLIS = 100L
private const val DENIED_KICK_COUNT = 3
private const val DENIED_KICK_INTERVAL_MILLIS = 120L

private fun deniedKickConstant() =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) HapticFeedbackConstants.REJECT
    else HapticFeedbackConstants.CLOCK_TICK
