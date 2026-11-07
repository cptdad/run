package com.vg.run

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunWhite

// ---------------------------------------------------------------------------
// ConnectionLogPanel — the inline, live connection log.
//
// Triple-tapping the "Connecting to…" caption on the contact list expands this
// panel; a triple-tap (or a tap on the panel) collapses it again. Unlike
// LogViewerScreen this ships in RELEASE builds: a user stuck on "Connecting…"
// can read out exactly which phase is failing.
//
// Its content comes from ConnectionLog (commonMain), whose producers emit fixed
// phrases + numbers only and whose redact() pass is the belt-and-braces net —
// no inbox ids, no capabilities, no onion hosts, no message content, no names.
//
// iOS sibling: iosApp/iosApp/ConnectionLogPanel.swift (same accessibility ids
// `connect_log_panel` / `connect_log_line`, same 40 %-of-screen cap).
// ---------------------------------------------------------------------------

/** How long a triple-tap may take, end to end. */
internal const val TRIPLE_TAP_WINDOW_MS = 600L

/**
 * Counts taps toward a triple-tap. Pure and clock-injected so the window rule
 * is unit-testable without a device (`ConnectionLogPanelTest`).
 *
 * The window is measured from the FIRST tap of the current run: three taps must
 * all land inside [TRIPLE_TAP_WINDOW_MS]. A tap that arrives after the window
 * has expired starts a fresh run rather than being discarded, so a slow user
 * never has to pause before trying again.
 */
internal class TripleTapDetector(private val windowMs: Long = TRIPLE_TAP_WINDOW_MS) {
    private var taps = 0
    private var firstTapAtMs = 0L

    /** Returns true on the tap that completes a triple-tap. */
    fun onTap(nowMs: Long): Boolean {
        if (taps == 0 || nowMs - firstTapAtMs > windowMs) {
            taps = 1
            firstTapAtMs = nowMs
            return false
        }
        taps++
        if (taps >= 3) {
            taps = 0
            firstTapAtMs = 0L
            return true
        }
        return false
    }
}

/**
 * Attaches a three-taps-within-600 ms gesture to any composable — meant for the
 * "Connecting to…" caption. Deliberately does NOT add a click role or a
 * content description: the caption keeps its existing accessibility identity
 * (`tor_progress_caption`), which the e2e suite keys on.
 */
@Composable
fun Modifier.tripleTapToggle(onToggle: () -> Unit): Modifier {
    val detector = remember { TripleTapDetector() }
    val latestOnToggle by rememberUpdatedState(onToggle)
    return this.pointerInput(Unit) {
        detectTapGestures(
            onTap = {
                if (detector.onTap(android.os.SystemClock.elapsedRealtime())) latestOnToggle()
            },
        )
    }
}

/** How long a copied connection log stays on the clipboard (same as the transfer handle). */
internal const val CONNECTION_LOG_CLEAR_AFTER_MS = 60_000L

/**
 * The text the Copy button puts on the clipboard. Each line carries its time
 * RELATIVE to the first line (`+12.3s`), not [ConnectionLog.Line.formatted]'s
 * wall-clock stamp: a pasted bug report then holds the sequence and the gaps
 * between phases, which is what diagnosis needs, without raw clock values that
 * date the user's session.
 */
internal fun connectionLogCopyText(lines: List<ConnectionLog.Line>): String {
    val first = lines.firstOrNull()?.timestamp ?: return ""
    return lines.joinToString("\n") { line ->
        val tenths = ((line.timestamp - first).coerceAtLeast(0L)) / 100L
        "+${tenths / 10}.${tenths % 10}s ${line.kind.name} ${line.text}"
    }
}

/**
 * The panel itself. Renders nothing when [expanded] is false, so the caller can
 * place it unconditionally.
 *
 * Newest line at the bottom, auto-scrolled; monospace. The lines are NOT
 * selectable: plain text selection would put them on the clipboard unflagged
 * and never cleared. The Copy button goes through [SensitiveClipboard]
 * (flagged sensitive, cleared after [CONNECTION_LOG_CLEAR_AFTER_MS]) with the
 * relative-time form of [connectionLogCopyText], ready for a bug report.
 */
@Composable
fun ConnectionLogPanel(
    expanded: Boolean,
    modifier: Modifier = Modifier,
) {
    if (!expanded) return

    val lines by ConnectionLog.lines.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()
    // ~40 % of the screen: tall enough to read the last dozen phases, short
    // enough that the Add-contact button and the caption stay on screen.
    val maxHeight = (LocalConfiguration.current.screenHeightDp * 0.4f).dp

    // FOLLOW THE TAIL ONLY WHILE AT THE BOTTOM. The newest line is
    // scrolled into view on open and on every append — unless the reader has
    // scrolled UP, in which case an append no longer yanks them back down. The old
    // unconditional snap made scrolling back during a live stall impossible (a
    // new Tor line every second or so) and cut the connect:cycle harness's
    // page-up read of a squeezed panel to its last 2 rows (device-run cycle
    // 5, 2026-10-08). `layoutInfo` still describes the PREVIOUS frame here, so
    // "at the bottom" = its last visible row was within one of the previous end.
    // iOS sibling: ContactListView's panel (XCUITest reads every row, so the
    // harness does not depend on it there).
    var tailScrolled by remember { mutableIntStateOf(0) }
    LaunchedEffect(lines.size) {
        if (lines.isEmpty()) return@LaunchedEffect
        val lastVisible = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index
        val wasAtBottom = tailScrolled == 0 || lastVisible == null || lastVisible >= tailScrolled - 1
        if (wasAtBottom) listState.scrollToItem(lines.lastIndex)
        tailScrolled = lines.lastIndex
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(RunBlack)
            .padding(horizontal = 10.dp, vertical = 8.dp)
            .testTag("connect_log_panel"),
    ) {
        val context = LocalContext.current
        Row(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = stringResource(R.string.connect_log_title),
                color = RunGrey,
                fontSize = 11.sp,
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            Text(
                text = stringResource(R.string.common_copy),
                color = RunWhite,
                fontSize = 11.sp,
                modifier = Modifier
                    .testTag("connect_log_copy")
                    .clickable {
                        SensitiveClipboard.copy(
                            context,
                            "connection log",
                            connectionLogCopyText(ConnectionLog.snapshot()),
                            CONNECTION_LOG_CLEAR_AFTER_MS,
                        )
                    },
            )
        }
        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(max = maxHeight),
        ) {
            itemsIndexed(lines) { _, line ->
                Text(
                    text = line.formatted(),
                    color = RunWhite,
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.testTag("connect_log_line"),
                )
            }
        }
    }
}
