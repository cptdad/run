package com.vg.run

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunWhite

// ---------------------------------------------------------------------------
// NO-PARK: every message a conversation poll fetches is
// shown in THAT screen, clearly marked when it is not the screen's own traffic —
// the relay burned it at fetch, and parking it in RAM for "its" conversation lost
// it on every lock/relaunch. Two marked kinds (GroupManager.ReceivedItemKind):
//   • PRIVATE   — a 1:1 text found by a GROUP poll (GroupConversationScreen only);
//   • GROUP_ECHO — a group text found by a 1:1 poll or another group's poll.
// The colour families and glyphs live here so both screens stay in step; the iOS
// siblings are in ConversationView.swift (GroupEchoBubbleView) and GroupViews.swift.
// ---------------------------------------------------------------------------

internal val PrivateBubbleReceived = Color(0xFF2A2238)
internal val PrivateBubbleSent = Color(0xFF3A2E50)
internal val PrivateAccent = Color(0xFFC4B2EA)
internal val EchoBubble = Color(0xFF1B2C30)
internal val EchoAccent = Color(0xFF8FC9D3)

/** A small padlock (no icon dependency in this module). */
@Composable
internal fun LockGlyph(color: Color, size: Dp = 11.dp) {
    Canvas(Modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val stroke = w * 0.14f
        drawArc(
            color = color, startAngle = 180f, sweepAngle = 180f, useCenter = false,
            topLeft = Offset(w * 0.24f, h * 0.06f), size = Size(w * 0.52f, h * 0.56f),
            style = Stroke(width = stroke),
        )
        drawLine(color, Offset(w * 0.24f, h * 0.34f), Offset(w * 0.24f, h * 0.46f), stroke)
        drawLine(color, Offset(w * 0.76f, h * 0.34f), Offset(w * 0.76f, h * 0.46f), stroke)
        drawRoundRect(
            color = color, topLeft = Offset(w * 0.1f, h * 0.44f), size = Size(w * 0.8f, h * 0.54f),
            cornerRadius = CornerRadius(w * 0.12f),
        )
    }
}

/** A small two-person "group" mark. */
@Composable
internal fun GroupGlyph(color: Color, size: Dp = 12.dp) {
    Canvas(Modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val back = color.copy(alpha = color.alpha * 0.7f)
        drawCircle(back, radius = w * 0.13f, center = Offset(w * 0.70f, h * 0.32f))
        drawArc(back, 180f, 180f, true, Offset(w * 0.47f, h * 0.56f), Size(w * 0.46f, h * 0.56f))
        drawCircle(color, radius = w * 0.16f, center = Offset(w * 0.36f, h * 0.28f))
        drawArc(color, 180f, 180f, true, Offset(w * 0.06f, h * 0.54f), Size(w * 0.60f, h * 0.62f))
    }
}

/**
 * A GROUP_ECHO bubble: a group text shown in a screen that is not its group's.
 * Received side, distinct colour, group glyph, "Group message in <group>", and an
 * "Open group" action. [senderAlias] is shown in a GROUP screen (several senders);
 * a 1:1 screen passes null (the sender is the contact of that chat). Not replyable.
 */
@Composable
internal fun GroupEchoBubble(
    groupName: String,
    senderAlias: String?,
    text: String,
    timeText: String?,
    onOpenGroup: () -> Unit,
    bubbleTag: String,
    labelTag: String,
    openTag: String,
) {
    Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.CenterStart) {
        Column(modifier = Modifier.widthIn(max = 280.dp)) {
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(16.dp, 16.dp, 16.dp, 4.dp))
                    .background(EchoBubble)
                    .testTag(bubbleTag)
                    .padding(start = 14.dp, end = 14.dp, top = 8.dp, bottom = 6.dp)
            ) {
                Column {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(5.dp),
                    ) {
                        GroupGlyph(EchoAccent)
                        Text(
                            text = stringResource(R.string.conversation_group_echo_label, groupName),
                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                            color = EchoAccent,
                            modifier = Modifier.testTag(labelTag),
                        )
                    }
                    if (senderAlias != null) {
                        Text(
                            text = senderAlias,
                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                            color = RunGrey,
                        )
                    }
                    Text(text = text, style = MaterialTheme.typography.bodyLarge, color = RunWhite)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = stringResource(R.string.conversation_group_echo_open),
                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.sp),
                            color = EchoAccent,
                            modifier = Modifier
                                .clip(RoundedCornerShape(8.dp))
                                .clickable(onClick = onOpenGroup)
                                .testTag(openTag)
                                .padding(vertical = 6.dp, horizontal = 2.dp),
                        )
                        if (timeText != null) {
                            Box(Modifier.weight(1f))
                            Text(text = timeText, fontSize = 9.sp, color = RunGrey.copy(alpha = 0.6f))
                        }
                    }
                }
            }
        }
    }
}
