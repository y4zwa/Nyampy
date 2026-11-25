package dev.yazwa.nyampy.ui.components

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.spring
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import dev.yazwa.nyampy.ui.theme.LocalUiSettings

/**
 * The press bounce for the square button tiles, in two motions:
 *  - holding squashes the button deep and fast; a press that ends without a click (dragged
 *    away) settles back quietly;
 *  - every click bounces: a quick squash, then a spring past the size with a fixed pop
 *    velocity and a jelly settle.
 * The bounce is keyed to [taps] — the click counter — rather than to the press state: on a
 * quick tap the press state can flip up and down between recompositions and never be
 * observed at all, which used to leave short taps with no animation. Both springs keep one stiffness: there is no slow-motion mode any more.
 */
@Composable
fun Modifier.pressBounce(pressed: Boolean, taps: Int): Modifier {
    val scale = remember { Animatable(1f) }
    LaunchedEffect(pressed) {
        if (pressed) {
            scale.animateTo(
                targetValue = PRESS_SCALE,
                animationSpec = spring(
                    dampingRatio = 0.75f,
                    stiffness = 3000f,
                ),
            )
        } else if (scale.value < 1f) {
            // Only after a real squash; otherwise every button would move on first
            // composition. A click's own bounce runs from the taps effect below and cancels
            // this settle, so this only survives presses that ended without a click.
            scale.animateTo(
                targetValue = 1f,
                animationSpec = spring(
                    dampingRatio = 1f,
                    stiffness = 1000f,
                ),
            )
        }
    }
    LaunchedEffect(taps) {
        if (taps == 0) return@LaunchedEffect
        scale.animateTo(
            targetValue = PRESS_SCALE,
            animationSpec = spring(
                dampingRatio = 0.75f,
                stiffness = 3000f,
            ),
        )
        scale.animateTo(
            targetValue = 1f,
            animationSpec = spring(
                dampingRatio = 0.5f,
                stiffness = 520f,
            ),
            initialVelocity = POP_VELOCITY,
        )
    }
    return graphicsLayer {
        scaleX = scale.value
        scaleY = scale.value
    }
}

private const val PRESS_SCALE = 0.85f
private const val POP_VELOCITY = 5f
