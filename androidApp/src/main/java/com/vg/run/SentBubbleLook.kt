package com.vg.run

import android.provider.Settings
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.withFrameMillis
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// ---------------------------------------------------------------------------
// The sent-bubble "did it get through yet" look (owner directive 2026-11-12). Replaces the
// small check mark: a pending bubble is GREY + TRANSLUCENT and creeps up to a cap well below
// opaque; the relay's acceptance animates it to opaque + its real colour. All numbers live in
// commonMain SentBubbleFade (shared with iOS ConversationView/GroupViews — keep in step).
//
// State is keyed per MESSAGE ID (remember(messageId)) and the creep clock derives from the
// message's own send timestamp, so a LazyColumn recycling a pending bubble resumes where it was
// instead of replaying, and a bubble that is ALREADY delivered when first composed starts opaque.
// ---------------------------------------------------------------------------

@Stable
internal class SentBubbleLook(
    private val pending: State<Float>,
    private val progress: State<Float>,
) {
    /** Current whole-bubble opacity (read in draw/graphicsLayer lambdas so frames never recompose). */
    val alpha: Float get() = SentBubbleFade.transitionAlpha(pending.value, progress.value)
    /** 0 = pending grey, 1 = the real sent-bubble colour. */
    val mix: Float get() = progress.value
}

/** Animator scale 0 ("Remove animations" / Reduce Motion) = no animation, just the two states. */
private fun animationsEnabled(context: android.content.Context): Boolean =
    Settings.Global.getFloat(context.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) != 0f

@Composable
internal fun rememberSentBubbleLook(messageId: String, sentAtMs: Long, delivered: Boolean): SentBubbleLook {
    val context = LocalContext.current
    val animate = remember { animationsEnabled(context) }
    val startedAt = remember(messageId) { if (sentAtMs > 0) sentAtMs else System.currentTimeMillis() }
    val progress = remember(messageId) { Animatable(if (delivered) 1f else 0f) }
    val pending = remember(messageId) {
        mutableFloatStateOf(
            if (animate) SentBubbleFade.pendingAlpha(System.currentTimeMillis() - startedAt)
            else SentBubbleFade.reducedMotionPendingAlpha()
        )
    }
    LaunchedEffect(messageId, delivered, animate) {
        if (delivered) {
            if (animate) progress.animateTo(1f, tween(SentBubbleFade.DELIVERED_MS.toInt())) else progress.snapTo(1f)
        } else {
            progress.snapTo(0f)
            if (animate) {
                while (SentBubbleFade.isCreeping(System.currentTimeMillis() - startedAt)) {
                    pending.floatValue = SentBubbleFade.pendingAlpha(System.currentTimeMillis() - startedAt)
                    withFrameMillis { }
                }
            }
            pending.floatValue =
                if (animate) SentBubbleFade.pendingAlpha(SentBubbleFade.CREEP_MS) else SentBubbleFade.reducedMotionPendingAlpha()
        }
    }
    return remember(messageId) { SentBubbleLook(pending, progress.asState()) }
}

private val PendingGrey = Color(0xFF000000.toInt() or SentBubbleFade.PENDING_GREY_RGB)

/** Bubble background: grey -> [base] by the delivered progress, at the bubble's current opacity. Apply after `.clip(shape)`. */
internal fun Modifier.sentBubbleBackground(look: SentBubbleLook?, base: Color): Modifier =
    if (look == null) this.drawBehind { drawRect(base) }
    else this.drawBehind { drawRect(lerp(PendingGrey, base, look.mix).copy(alpha = look.alpha)) }

/** Bubble text / timestamp: the same opacity as the background (no-op for received bubbles). */
internal fun Modifier.sentBubbleContent(look: SentBubbleLook?): Modifier =
    if (look == null) this else this.graphicsLayer { alpha = look.alpha }

/**
 * The delivery status that e2e reads (`group_delivery_status` text: "·" pending / "✓" all delivered),
 * kept in the accessibility tree but NOT drawn: transparent ink in a 1 dp box. (alpha 0 would drop the
 * node from the semantics tree, so transparency is done with the text colour.)
 */
@Composable
internal fun HiddenDeliveryStatus(text: String, tag: String) {
    Text(
        text = text,
        color = Color.Transparent,
        fontSize = 12.sp,
        maxLines = 1,
        softWrap = false,
        modifier = Modifier.size(1.dp).testTag(tag),
    )
}
