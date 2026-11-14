package com.vg.run

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunBubbleReceived
import com.vg.run.ui.theme.RunBubbleSent
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurface
import com.vg.run.ui.theme.RunSurfaceAlt
import com.vg.run.ui.theme.RunWhite
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import com.vg.run.ui.theme.MetamorphousFamily
import com.vg.run.ui.theme.RuneDanger
import android.text.format.DateFormat
import androidx.activity.compose.BackHandler
import androidx.compose.animation.Crossfade
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import android.content.Context
import android.os.SystemClock
import java.util.Calendar
import java.util.Date
import java.util.UUID
import kotlinx.coroutines.CancellationException

// ---------------------------------------------------------------------------
// ConversationScreen — displays the message history for a single contact.
//
// Security purpose:
//
//   • Message bubbles show a local-time timestamp (formatTime). The time
//     travels inside the end-to-end-encrypted envelope, so it leaks no
//     metadata to the relay or a network observer, and messages are never
//     persisted (see below). The only exposure is a shoulder-surf or
//     screenshot of an already-unlocked conversation — an accepted tradeoff
//     for the usability of knowing when a message arrived.
//
//   • No read receipts or typing indicators. These are covert channels that
//     leak presence information to the remote party (and to anyone monitoring
//     the relay). The sender knows their message was sent; the recipient
//     sees it when they open the conversation. That is sufficient.
//
//   • Messages are never persisted to disk. They live only in the in-memory
//     display list for the duration of the conversation: sent messages are
//     added on send, received messages are appended as they arrive from the
//     poll loop. If the device is seized after the user closes the
//     conversation, no messages remain anywhere — the in-memory copies are
//     lost when the Activity is destroyed.
//
//   • The text input uses BasicTextField with no system-level autocomplete,
//     spelling suggestions, or clipboard history integration. The input
//     field is rendered as a simple dark surface that blends with the theme.
//
//   • Messages are distinguished as sent (right, darker bubble) vs received
//     (left, lighter bubble) via the IN-MEMORY DisplayMessage.isSent flag — NOT a
//     DB column. Nothing is ever written to the Messages table (see the "never
//     persisted" bullet above; the schema only ever CREATEs + DELETEs), so there is
//     no on-disk message-flow direction to forensically recover.
//
//   • While a conversation is open its inbound text inbox is drained on a
//     JITTERED loop (POLL_BASE_MS + 0..POLL_JITTER_MS ≈ 0.5–1.2 s) — snappy for
//     chat, but per-cycle randomised so it is NOT a fixed-period timing beacon.
//     KNOWN LIMITATION: text inboxes are drained ONLY
//     in-conversation (messages aren't persisted), so the relay can still infer
//     *which* contact is active from which inbox receives these reads. The
//     jitter hides the cadence, not the which-contact fact; eliminating the
//     latter needs relay-side read/peek indistinguishability or opt-in
//     persistence — tracked as a deliberate design effort.
// ---------------------------------------------------------------------------

// Jittered in-conversation poll interval: each cycle waits POLL_BASE_MS plus a
// random 0..POLL_JITTER_MS, so there is no fixed heartbeat for a traffic observer.
// GroupConversationScreen's POLL_MIN_MS..POLL_MAX_MS (4-18 s) is wider on purpose:
// one group cycle drains one inbox PER MEMBER, a 1:1 cycle drains one.
private const val POLL_BASE_MS = 500L
private const val POLL_JITTER_MS = 700L

/**
 * A UI-layer message that lives in memory only. Messages are never persisted —
 * they exist solely in this in-memory list for the life of the conversation.
 *
 * @param id        The original messageId (used for deduplication).
 * @param text      The decrypted plaintext content.
 * @param isSent    True if the user sent this message, false if received.
 */
private data class DisplayMessage(
    val id: String,
    val text: String,
    val isSent: Boolean,
    val timestamp: Long = 0L,  // millis since epoch, 0 = no timestamp
    // "X may have taken a screenshot" notice — centered/muted, no bubble,
    // never counted as a real message. PERSISTED for 24 h now (docs/
    // screenshot-notice-persistence-design.md) — loaded on open from
    // GroupManager.screenshotNotices and appended live from
    // GroupManager.drainScreenshotNotices.
    val isNotice: Boolean = false,
    // Local wall-clock deadline (ScreenshotNotice.expiresAt) past which this
    // row is dropped on the next poll tick without a vault read. Non-notice
    // rows never expire.
    val expiresAt: Long = Long.MAX_VALUE,
    // NO-PARK: non-null = a GROUP_ECHO row — a text of this group that
    // this screen's poll fetched. Shown marked, never counted as a 1:1 message.
    val echoGroupId: String? = null,
    val echoGroupName: String = "",
)

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun ConversationScreen(
    viewModel: RunViewModel,
    contactId: String,
    onBack: () -> Unit = {},
    // NO-PARK: a GROUP_ECHO bubble's "Open group" — navigates the way the contact list does.
    onOpenGroup: (String) -> Unit = {},
) {
    val vault = viewModel.vault ?: return
    // Captured once for use inside non-composable closures below (LaunchedEffect
    // bodies run as plain coroutines, not composables, so they cannot call
    // stringResource() directly).
    //
    // TWO locals, deliberately: `resources` is the CONFIGURATION-AWARE handle and
    // is what every resource lookup must go through — a `getString` on
    // LocalContext.current reads the Context's own Configuration, which does not
    // track a locale change (lint LocalContextGetResourceValueCall). `context`
    // remains only for the things that genuinely need a Context rather than
    // Resources: DateFormat.getTimeFormat (see formatTime /
    // formatNoticeTime below), which reads the user's 12/24-hour system setting.
    val context = LocalContext.current
    val resources = LocalResources.current

    // Every leave (back tap, system back) routes through here. Immediate (retrieve-ack):
    // an un-committed drain is abandoned on dispose, nothing is lost.
    val leaveCleanly: () -> Unit = { onBack() }

    // Tor connection state — determines whether the send button is active.
    val torState = viewModel.torState.collectAsState().value
    val isTorReady = !RelayConfig.isTorRequired || torState is TorManager.ConnectionState.Connected
    // Use the viewModel's StateFlow so the conversation screen picks up the
    // already-known reachability the moment it opens, instead of waiting
    // for its own poll loop (3–15 s jitter) to run the first check. The
    // previous local mutableState defaulted to `false`, which briefly
    // disabled the send button and left the runestone unlit right after
    // opening a conversation, even when Tor + relay had been ready for a
    // while.
    val isRelayReachable = viewModel.isRelayReachable.collectAsState().value
    // Instant-QR pairing: until the peer's inbox announce lands, we can
    // receive but not send. Re-checked after every poll cycle (the announce
    // is applied by pollMessages), so the send button unlocks on its own.
    var hasOutbound by remember(contactId) {
        mutableStateOf(vault.getInboxIdForContact(contactId, "outbound") != null)
    }
    val canSend = isTorReady && viewModel.messageManager != null && isRelayReachable && hasOutbound

    // Pulse animation for the send button while Tor is bootstrapping.
    val infiniteTransition = rememberInfiniteTransition(label = "sendPulse")
    val sendPulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.2f,
        targetValue = 0.6f,
        animationSpec = infiniteRepeatable(
            animation = tween(800),
            repeatMode = RepeatMode.Reverse
        ),
        label = "sendAlpha"
    )
    val listState = rememberLazyListState()

    // Look up the contact alias for the header.
    // getContact() returns a full ContactRecord carrying a raw
    // 32-byte sharedSecret (the legacy static-envelope key pre-image). Only the
    // alias is ever read here, so project it immediately and wipe the source
    // record's secret before it goes out of scope — never retain the record
    // itself in remember state. Mirrors ContactListScreen.kt's `toListItem()`
    // pattern / ContactListItem.kt.
    val contactSnapshot = remember {
        val record = vault.getContact(contactId)
        val snapshot = record?.alias to record?.vouchedByContactId
        record?.sharedSecret?.secureWipe()
        snapshot
    }
    val alias = contactSnapshot.first ?: stringResource(R.string.conversation_alias_unknown)
    // Maximum shield: re-read (on IO) whenever a vault event lands (a control batch may
    // have carried the claim or its withdrawal). False unless this device is at MAXIMUM.
    val vaultEventTick by viewModel.vaultEvents.collectAsState()
    var maximumShield by remember { mutableStateOf(false) }
    LaunchedEffect(contactId, vaultEventTick) {
        maximumShield = withContext(Dispatchers.IO) { viewModel.maximumShield?.isClaimed(contactId) ?: false }
    }
    val maximumShieldDescription = stringResource(R.string.contact_maximum_shield_description)
    val vouchedByContactId = contactSnapshot.second
    // Provenance for a referred contact — the same
    // "Introduced by X" signal ContactListScreen.kt already shows, surfaced
    // here too so it isn't only visible from the contact list. Resolved fresh
    // (not cached from the referral itself) so a renamed introducer's alias
    // stays current, mirroring ContactRow's introducerAlias lookup.
    val introducerAlias = remember(vouchedByContactId) {
        vouchedByContactId?.let { vid ->
            val introducerRecord = vault.getContact(vid)
            val resolved = introducerRecord?.alias
            introducerRecord?.sharedSecret?.secureWipe()
            resolved
        }
    }

    // In-memory message list. Security purpose: messages are never persisted to
    // disk. This list is the only place they exist — it is cleared when the
    // composable leaves the composition (i.e. when the user navigates away or
    // the Activity is destroyed).
    val messages = remember { mutableStateListOf<DisplayMessage>() }

    // One-time burn-on-read onboarding (shared BurnOnReadNotice.kt) — shown on
    // the very FIRST conversation ever opened per vault, keyed on a durable
    // vault-meta latch so it fires once total across 1:1 AND group conversations.
    var showBurnNotice by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { showBurnNotice = consumeBurnNoticeOnce(vault) }
    if (showBurnNotice) {
        BurnOnReadNotice(onClose = { showBurnNotice = false })
    }

    // Discreet, runestone-flavoured feedback shown during the first fetch on open,
    // then cleared: "Consulting the runes…" → "The runes whisper" / "are silent".
    var runeWhisper by remember(contactId) { mutableStateOf<String?>(null) }

    // Cleanup: erase messages from memory when leaving the conversation.
    DisposableEffect(contactId) {
        onDispose {
            val count = messages.size
            messages.clear()
            LogBuffer.append("D", "Chat", "conversation closed, $count message(s) erased from memory")
        }
    }

    // Track which message IDs we have already loaded to avoid duplicates
    // across poll cycles. A plain (non-snapshot) set: MAIN THREAD ONLY — the poll
    // loop touches it only outside its withContext(IO) fetches; do not touch it from IO.
    val knownIds = remember { mutableSetOf<String>() }

    // IDs of sent messages that the relay has accepted (HTTP 2xx).
    // Using a SnapshotStateMap so that each bubble can read its own
    // key and recompose independently when delivery is confirmed.
    val deliveredIds = remember { mutableStateMapOf<String, Boolean>() }

    // Initial load. Messages are never persisted, so there is nothing to load
    // from disk — the list starts empty and is populated by the poll loop
    // (received) and the send action (sent). Any list already present at open
    // (e.g. a recomposition that re-runs this effect) is scrolled to by the
    // count-keyed auto-scroll effect below — this effect owns no scroll, so it
    // can never enter a MutatorMutex race (see CONV-1 there).
    LaunchedEffect(contactId) {
        LogBuffer.append("D", "Chat", "conversation opened torReady=$isTorReady relayReachable=$isRelayReachable")
    }

    // Automatic polling on a JITTERED ~0.5–1.2 s interval for responsive chat
    // without a fixed-period beacon (see the file-header note; the which-contact
    // leak from draining only in-conversation remains a deferred limitation).
    LaunchedEffect(contactId) {
        var verdictShown = false
        val openedAt = SystemClock.elapsedRealtime()
        // Announce the fetch on open — only when the relay is reachable; with no
        // relay there are no runes to consult.
        if (isRelayReachable) runeWhisper = ConversationRunes.CONSULTING
        // A conversation with no transport drains NOTHING while the background peek
        // keeps reporting unread — the exact "relay says pending=1, nothing arrives"
        // stall that was invisible in logcat. Log the transition (not every ~1s tick).
        var loggedNoTransport = false
        // Evaluate forwardSecrecyStalled on open — off Main,
        // one meta read. The other evaluation point is after every completed send
        // (see RunViewModel.sendMessageInBackground); there is no polling loop for
        // this flag.
        withContext(Dispatchers.IO) { viewModel.refreshForwardSecrecyStalled(contactId) }
        // Evaluate ratchetRefused on open too — also re-read on every
        // poll tick below (unlike forwardSecrecyStalled, this signal is cleared by
        // an INBOUND ratchet blob, not only by this device's own send landing).
        withContext(Dispatchers.IO) { viewModel.refreshRatchetRefused(contactId) }
        // Load-on-open: every UNEXPIRED persisted notice for this conversation,
        // oldest first — this is the persistence fix for the production bug
        // where a notice drained by the background sweep while this screen
        // was closed used to be lost forever (docs/
        // screenshot-notice-persistence-design.md §0). GroupManager is set on
        // vault unlock (independent of Tor/messageManager), so it is normally
        // already available the first time this screen opens; if not, the
        // per-tick drain below still picks up anything that arrives live.
        // Runs ONCE, off Main; the poll loop only ever APPENDS newly arrived
        // notices from here on.
        viewModel.groupManager?.let { groupMgr ->
            val persisted = withContext(Dispatchers.IO) { groupMgr.screenshotNotices(contactId) }
            for (n in persisted) {
                val id = "ss-${n.senderContactId}-${n.receivedAt}"
                if (id !in knownIds) {
                    knownIds.add(id)
                    messages.add(
                        DisplayMessage(
                            id = id,
                            text = resources.getString(R.string.common_screenshot_notice, n.senderAlias) + " · " + formatNoticeTime(context, n.timestamp),
                            isSent = false,
                            timestamp = n.timestamp,
                            isNotice = true,
                            expiresAt = n.expiresAt,
                        )
                    )
                }
            }
        }
        // Retrieve-ack: the poll result not yet committed; abandoned if this loop is
        // cancelled (screen left) before the commit below ran. commit()/abandon() are
        // idempotent, first one wins, so a stale reference here is harmless.
        var uncommitted: PendingDrain<DirectItem>? = null
        try {
        while (isActive) {
            // Read messageManager on each iteration — it's set asynchronously
            // after Tor connects, so capturing it once at launch would miss it.
            val mgr = viewModel.messageManager
            val groupMgr = viewModel.groupManager
            // (Relay reachability is tracked globally by RunViewModel.startRelayCheck;
            // this screen reads viewModel.isRelayReachable directly, so no separate
            // probe is needed here.)
            // Poll the relay on a background thread — this is blocking I/O.
            // Received messages are appended directly to the in-memory list;
            // nothing is persisted to disk. The poll goes through GroupManager
            // so a group text sharing this contact's inboxes is shown HERE as a
            // marked GROUP_ECHO (NO-PARK, 2026-10-06) instead of being dropped.
                if (mgr == null && !loggedNoTransport) {
                loggedNoTransport = true
                platformLogWarn("Chat", "conversation not draining — no transport yet (waiting for Tor)")
            } else if (mgr != null && loggedNoTransport) {
                loggedNoTransport = false
                platformLog("Chat", "transport back — conversation draining again")
            }
            if (mgr != null) {
                // RETRIEVE-ACK: poll UNCOMMITTED (decrypt only), append to the list,
                // THEN commit (persist ratchet/anti-replay state + fire-and-forget
                // ack). Leaving mid-poll is immediate; a drain not yet shown is
                // abandoned in the finally below (dropping it is also safe — the relay
                // re-delivers after its lease). Screenshot notices are drained in the
                // same IO job (they resolve the alias from the vault — never main).
                val (drain, notices) = withContext(Dispatchers.IO) {
                    try {
                        // GroupManager is created at vault unlock, before the transport
                        // exists, so `mgr != null` implies it; the guard is belt-and-braces.
                        val d = groupMgr?.pollDirectPending(contactId)
                        uncommitted = d   // visible to the finally-abandon even if the result is lost to a cancel
                        d to (groupMgr?.drainScreenshotNotices(contactId) ?: emptyList())
                    } catch (e: CancellationException) {
                        throw e   // never swallow cancellation (screen left mid-poll)
                    } catch (_: Exception) { null to emptyList<ScreenshotNotice>() }
                }
                // Parked items (FIX B deliveries, system notices) come first in
                // `messages` and leave the buffer only on commit.
                val received = drain?.messages ?: emptyList()
                // NO-PARK: an echoed group text no longer counts on its group row.
                if (received.any { it.isGroupEcho }) viewModel.refreshGroupUnreadCounts()
                for (rm in received) {
                    // Stable per-contact id from the sender's monotonic
                    // counter — a real dedupe key, unlike the old
                    // fresh-random UUID which made knownIds a no-op. Also
                    // de-dupes if the relay re-serves a blob. A GROUP_ECHO row is
                    // namespaced by its group so it can never collide with a 1:1 id.
                    val id = if (rm.isGroupEcho) "ge-${rm.groupId}-${rm.dedupeId}"
                             else rm.dedupeId   // channel-namespaced (rx-/dr-), no legacy/ratchet collision
                    if (id !in knownIds) {
                        knownIds.add(id)
                        messages.add(
                            DisplayMessage(
                                id, rm.text, isSent = false, timestamp = rm.timestamp,
                                echoGroupId = if (rm.isGroupEcho) rm.groupId else null,
                                echoGroupName = rm.groupName,
                            )
                        )
                    }
                }
                // Drained from the RAM "just arrived" buffer — the notice was
                // ALSO already persisted (GroupManager.collectDirectScreenshotNotices),
                // so re-opening the conversation later still shows it via the
                // load-on-open block above. Dedupe id keys on receivedAt (the
                // store's stable, collision-adjusted ordering key), not the
                // display timestamp, so it always matches the load-on-open id
                // for the same row.
                for (n in notices) {
                    val id = "ss-${n.senderContactId}-${n.receivedAt}"
                    if (id !in knownIds) {
                        knownIds.add(id)
                        messages.add(
                            DisplayMessage(
                                id = id,
                                text = resources.getString(R.string.common_screenshot_notice, n.senderAlias) + " · " + formatNoticeTime(context, n.timestamp),
                                isSent = false,
                                timestamp = n.timestamp,
                                isNotice = true,
                                expiresAt = n.expiresAt,
                            )
                        )
                    }
                }
                // Everything is on screen (the list state holds the items): COMMIT —
                // persist the ratchet / anti-replay state, then the fire-and-forget ack.
                // Off Main, NonCancellable (a leave mid-commit must not leave it half
                // done), and finished before the next poll of this conversation starts.
                if (drain != null && !drain.isEmpty) {
                    withContext(Dispatchers.IO + NonCancellable) { drain.commit() }
                }
                uncommitted = null
                // Re-read ratchetRefused on every poll tick, not just
                // on open/after-send — an inbound ratchet blob (possibly one that
                // carries no visible text, e.g. a control-channel announce) is what
                // clears the refusal, and this is where those land.
                withContext(Dispatchers.IO) { viewModel.refreshRatchetRefused(contactId) }
                // The poll may have applied an in-band inbox announce —
                // unlock the send button without re-entering the screen.
                // Do the SQLCipher read on IO, not the main
                // thread — this LaunchedEffect body runs on Main, and an un-offloaded
                // getInboxIdForContact fired every ~0.5–1.2 s poll cycle for a pending
                // contact. (The state assignment resumes on Main after withContext.)
                if (!hasOutbound) {
                    val nowHasOutbound = withContext(Dispatchers.IO) {
                        vault.getInboxIdForContact(contactId, "outbound") != null
                    }
                    if (nowHasOutbound) hasOutbound = true
                }
                // First successful fetch: hold "Consulting…" long enough to read
                // (and let its slow fade settle) before revealing the verdict; it
                // then lingers and fades — all unhurried, for a mystic feel. Only
                // when the relay is up.
                if (!verdictShown && isRelayReachable) {
                    verdictShown = true
                    val elapsed = SystemClock.elapsedRealtime() - openedAt
                    if (elapsed < ConversationRunes.VERDICT_MIN_HOLD_MS) delay(ConversationRunes.VERDICT_MIN_HOLD_MS - elapsed)
                    runeWhisper = ConversationRunes.verdict(messages.isNotEmpty())
                }
            }
            // (Auto-scroll is NOT done here — see the count-keyed effect below, CONV-1.)
            // Hide any notice row whose TTL passed since it was rendered — cheap
            // (RAM only), no vault read per tick; the vault-side rows are pruned
            // separately (GroupManager.pruneExpiredScreenshotNotices, on the
            // background control sweep, and ScreenshotNoticeStore on write/read).
            messages.removeAll { it.isNotice && it.expiresAt <= System.currentTimeMillis() }
            // Jittered wait: POLL_BASE_MS + 0..POLL_JITTER_MS (no fixed beacon). Leaving
            // cancels this effect, so back is never delayed by the cadence.
            delay(POLL_BASE_MS + secureRandomInt(POLL_JITTER_MS.toInt()).toLong())
        }
        } finally {
            // Screen left with a result not yet shown/committed: roll it back (the relay
            // re-delivers). Off Main — abandon releases the leases.
            uncommitted?.let { u -> withContext(Dispatchers.IO + NonCancellable) { u.abandon() } }
        }
    }

    // Auto-scroll to the newest message — in its OWN effect, keyed on the message count.
    // CONV-1: this must NEVER run inside the poll loop. Every LazyListState scroll goes
    // through a MutatorMutex, so a competing scroll (the send handler below, or another
    // effect) CANCELS the in-flight one with a CancellationException. Thrown inside the
    // poll coroutine, that cancellation is — correctly — rethrown, and it kills the
    // LaunchedEffect(contactId) poll loop for the rest of the screen: the conversation
    // never drains its inbox again while the badge keeps peeking pending>0 (the exact
    // "delivered to the relay, never drained" stall). Isolated here, a lost scroll race
    // cancels only THIS effect, which the next count change restarts; a genuine screen
    // exit still cancels the poll loop as before. Keying on the count applies the same
    // gate as before — the count grows only when a message is actually appended (a relay
    // re-serve of a known blob is deduped away) — and matches both the LogViewer's
    // auto-scroll and iOS (.onChange(of: messages.count)).
    var lastScrolledCount by remember(contactId) { mutableIntStateOf(0) }
    LaunchedEffect(contactId, messages.size) {
        val count = messages.size
        val appendedNew = count > lastScrolledCount
        lastScrolledCount = count
        if (ConversationRunes.shouldAutoScrollToLatest(appendedNew, count > 0)) {
            listState.animateScrollToItem(count - 1)
        }
    }

    // Auto-clear the rune verdict ~2.6 s after it appears, without blocking the
    // 500 ms poll loop above.
    LaunchedEffect(runeWhisper) {
        val shown = runeWhisper
        if (ConversationRunes.isTransientVerdict(shown)) {
            delay(2600)
            if (runeWhisper == shown) runeWhisper = null
        }
    }

    // --- Message action state (retry/delete for stuck messages) ---
    var actionMessageId by remember { mutableStateOf<String?>(null) }

    // --- Input state ---
    var inputText by remember { mutableStateOf("") }

    // Runestone background crossfade — matches contact list.
    val torProgress = when {
        !RelayConfig.isTorRequired -> 1f
        torState is TorManager.ConnectionState.Connected -> 1f
        torState is TorManager.ConnectionState.Bootstrapping -> torState.progress / 100f
        else -> 0f
    }
    val animatedTorProgress by animateFloatAsState(
        targetValue = torProgress,
        animationSpec = tween(500, easing = LinearEasing),
        label = "convTorProgress"
    )
    // Drive the lit runestone from the same `isRelayReachable` flag that
    // gates the send button — they must agree, otherwise the marker can
    // disagree with the gate during the brief window where the in-screen
    // poll has succeeded but the VM's periodic check hasn't yet caught up.
    // Strict gate: the lit runestone must NEVER be visible while the relay
    // is unreachable, so the value snaps to 0 instantly on transitions to
    // unreachable. Fade-in is animated only when reachability becomes true.
    val litAlpha by animateFloatAsState(
        targetValue = if (isRelayReachable) 1f else 0f,
        animationSpec = tween(if (isRelayReachable) 2000 else 0, easing = LinearEasing),
        label = "convLitAlpha"
    )

    // Back is IMMEDIATE (retrieve-ack): the header arrow and system back leave at
    // once. A drain in flight is abandoned on dispose (see the poll loop's finally)
    // and nothing is lost — the relay re-delivers an un-acked blob.
    val requestBack: () -> Unit = { leaveCleanly() }
    BackHandler { requestBack() }

    // --- Layout ---
    Box(
        modifier = Modifier
            .fillMaxSize()
            .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
            .testTag("conversation_view")
            .background(RunBlack)
            .imePadding()
    ) {
        val artLevel = viewModel.vaultSelector.displayProtectionLevel()
        // Dim runestone — base layer.
        Image(
            painter = painterResource(id = RunestoneArt.dim(artLevel)),
            contentDescription = null,
            contentScale = ContentScale.FillWidth,
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.TopCenter)
        )
        // Bright runestone — fades out when relay is reachable.
        Image(
            painter = painterResource(id = RunestoneArt.bright(artLevel)),
            contentDescription = null,
            contentScale = ContentScale.FillWidth,
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.TopCenter)
                .alpha(animatedTorProgress * (1f - litAlpha))
        )
        // Lit runestone (red glow) — fades in when relay is reachable.
        Image(
            painter = painterResource(id = RunestoneArt.brightAndLit(artLevel)),
            contentDescription = null,
            contentScale = ContentScale.FillWidth,
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.TopCenter)
                .alpha(animatedTorProgress * litAlpha)
        )

        // Test-only marker exposing the lit-runestone gate state. Uses the
        // same `isRelayReachable` flag as the send button so the marker and
        // the gate cannot disagree.
        Box(modifier = Modifier.align(Alignment.TopStart)) {
            RunestoneLitMarker(active = isRelayReachable)
        }

        // Dark overlay so message bubbles remain readable.
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(RunBlack.copy(alpha = 0.6f - animatedTorProgress * 0.3f))
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .navigationBarsPadding()
        ) {
        // Header bar with back arrow and contact alias.
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(RunSurface)
                .statusBarsPadding()
                .padding(horizontal = 12.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = backArrowGlyph(),  // RTL-aware: "←" LTR / "→" RTL
                fontSize = 22.sp,
                color = RunGrey,
                modifier = Modifier
                    .clickable(onClick = requestBack)
                    .padding(8.dp)
            )
            Spacer(Modifier.width(8.dp))
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = alias,
                        style = MaterialTheme.typography.titleMedium,
                        color = RunWhite,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false).testTag("conversation_title")
                    )
                    if (maximumShield) {
                        // Maximum shield: this contact reported Maximum and this device is at
                        // MAXIMUM (MaximumShield.kt). Right after the name.
                        Spacer(Modifier.width(6.dp))
                        Text(
                            text = "\uD83D\uDEE1",
                            fontSize = 14.sp,
                            modifier = Modifier
                                .semantics { contentDescription = maximumShieldDescription }
                                .testTag("conversation_maximum_shield")
                        )
                    }
                }
                if (vouchedByContactId != null) {
                    // Same provenance signal + style
                    // family as ContactRow's "Introduced by X" subtitle
                    // (ContactListScreen.kt) — informational only, referred
                    // contacts are usable immediately (transitive trust).
                    Text(
                        text = introducerAlias?.let { stringResource(R.string.contact_list_introduced_by, it) }
                            ?: stringResource(R.string.contact_list_introduced),
                        style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                        color = RunGrey,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.testTag("conversation_provenance"),
                    )
                }
            }
        }

        // Forward-secrecy-stalled notice — a SIGNAL, never
        // a send gate (MessageManager.forwardSecrecyStalled's KDoc). Non-modal, at
        // the top of the message list; same muted-row visual family as
        // conversation_pending_banner below, not a dialog. 1:1 conversations only
        // — this screen is never used for groups.
        //
        // The ratchet-refused notice takes PRECEDENCE when both would
        // show — it is the strictly worse (send-blocking, not just advisory) state
        // that forwardSecrecyStalled's own threshold can escalate into, so showing
        // both would be redundant and confusing about which one to act on.
        val fsStalledContacts by viewModel.forwardSecrecyStalled.collectAsState()
        val ratchetRefusedContacts by viewModel.ratchetRefused.collectAsState()
        if (ratchetRefusedContacts[contactId] == true) {
            RatchetRefusedNotice()
        } else if (fsStalledContacts[contactId] == true) {
            ForwardSecrecyStalledNotice()
        }

        // (The rune whisper renders as a lower-third overlay on the message area
        // below — moved out of the column so it sits BELOW the rune and never
        // reflows the message list, matching iOS.)

        // Message area: the list plus the lower-third rune whisper, OVERLAID (not
        // in-flow). The overlay is non-interactive (no pointerInput), so list
        // scrolling passes straight through it to the LazyColumn.
        Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp)
                .testTag("message_list"),
            verticalArrangement = Arrangement.spacedBy(6.dp),
            reverseLayout = false
        ) {
            item { Spacer(Modifier.height(8.dp)) }

            items(messages, key = { it.id }) { message ->   // stable key, no position re-assoc on delete
                val delivered = deliveredIds[message.id] == true
                val echoGroupId = message.echoGroupId
                if (echoGroupId != null) {
                    GroupEchoBubble(
                        groupName = message.echoGroupName,
                        senderAlias = null,
                        text = message.text,
                        timeText = if (message.timestamp > 0) formatTime(context, message.timestamp) else null,
                        onOpenGroup = {
                            onOpenGroup(echoGroupId)
                        },
                        bubbleTag = "conversation_group_echo_bubble",
                        labelTag = "conversation_group_echo_label",
                        openTag = "conversation_group_echo_open",
                    )
                    return@items
                }
                MessageBubble(
                    message = message,
                    delivered = delivered,
                    onLongClick = {
                        // Only show action popup for undelivered sent messages.
                        if (message.isSent && !delivered) {
                            actionMessageId = message.id
                        }
                    }
                )
            }

            item { Spacer(Modifier.height(8.dp)) }
        }

            // Lower third (~2/3 down), below the rune — fades on its own. Two
            // spacers above to one below ⇒ the whisper sits in the lower third.
            Column(modifier = Modifier.fillMaxSize()) {
                Spacer(Modifier.weight(2f))
                Crossfade(
                    targetState = runeWhisper,
                    animationSpec = tween(durationMillis = 1300),
                    label = "rune_whisper"
                ) { whisper ->
                    if (whisper != null) {
                        Text(
                            text = ConversationRunes.label(whisper),
                            color = Color(0xB0DBB575),
                            fontFamily = MetamorphousFamily,
                            fontStyle = FontStyle.Italic,
                            fontWeight = FontWeight.Light,
                            fontSize = 15.sp,
                            letterSpacing = 3.5.sp,
                            textAlign = TextAlign.Center,
                            style = TextStyle(
                                shadow = Shadow(
                                    color = Color(0x4DBF3826),
                                    offset = Offset(0f, 0f),
                                    blurRadius = 18f
                                )
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 10.dp)
                                .testTag("rune_whisper")
                        )
                    }
                }
                Spacer(Modifier.weight(1f))
            }
        }

        // Pending-pairing hint: receiving works; sending unlocks when the
        // peer's inbox announce arrives on a poll.
        if (!hasOutbound) {
            Text(
                text = stringResource(R.string.conversation_pending_banner),
                style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.sp),
                color = RunGrey,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .fillMaxWidth()
                    .background(RunSurface)
                    .padding(horizontal = 16.dp, vertical = 6.dp)
                    .testTag("conversation_pending_banner"),
            )
        }

        // Input bar — dark surface, no borders, blends with the theme.
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(RunSurface)
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Text input — keyboard privacy scales with the protection tier (user
            // decision, option 3; see ComposerKeyboardPolicy). At MAXIMUM (strict)
            // this stays KeyboardType.Password, which puts the IME in a
            // no-suggestions / no-personalised-learning mode so plaintext message
            // words are NOT retained in the keyboard's learned dictionary (which
            // lives outside the app sandbox and survives a wipe) — but
            // Gboard/Samsung Keyboard both also drop the emoji key in password
            // mode. CASUAL/PRIVATE get KeyboardType.Text with autocorrect off, so
            // the emoji key stays; KeyboardOptions cannot ask for
            // IME_FLAG_NO_PERSONALIZED_LEARNING / TYPE_TEXT_FLAG_NO_SUGGESTIONS, so
            // the [NoPersonalizedLearning] wrapper adds both to the EditorInfo
            // (a hint a third-party IME may ignore). Text stays visible either
            // way — no PasswordVisualTransformation is set.
            val strictKeyboard = viewModel.strictComposerKeyboard
            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(20.dp))
                    .background(RunSurfaceAlt)
                    .padding(horizontal = 16.dp, vertical = 12.dp)
            ) {
                if (inputText.isEmpty()) {
                    Text(
                        text = stringResource(R.string.common_message_placeholder),
                        style = MaterialTheme.typography.bodyLarge,
                        color = RunGrey
                    )
                }
                // keepSuggestions: the composer keeps the suggestion strip and glide typing;
                // only the learning flag is added (secret fields also drop suggestions).
                NoPersonalizedLearning(keepSuggestions = true) {
                    BasicTextField(
                        value = inputText,
                        onValueChange = { inputText = it },
                        textStyle = MaterialTheme.typography.bodyLarge.copy(color = RunWhite),
                        cursorBrush = SolidColor(RunWhite),
                        singleLine = false,
                        maxLines = 4,
                        // strictKeyboard: Password (no suggestions/learning, no emoji key).
                        // Otherwise: plain text with autocorrect off (emoji key present),
                        // plus the no-learning/no-suggestions flags from the
                        // NoPersonalizedLearning wrapper. Text stays visible either way — not masked.
                        keyboardOptions = if (strictKeyboard) {
                            KeyboardOptions(keyboardType = KeyboardType.Password)
                        } else {
                            KeyboardOptions(keyboardType = KeyboardType.Text, autoCorrectEnabled = false)
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("message_input")
                    )
                }
            }

            Spacer(Modifier.width(8.dp))

            // Send button — pulses slowly while Tor is bootstrapping,
            // active when Tor is connected and there is text to send.
            val sendButtonAlpha = when {
                !canSend -> sendPulseAlpha  // Pulsing — Tor not ready
                inputText.isNotBlank() -> 1f
                else -> 0.3f
            }
            val sendButtonColor = if (canSend && inputText.isNotBlank()) RunWhite else RunGrey.copy(alpha = 0.3f)

            val sendEnabled = canSend && inputText.isNotBlank()
            IconButton(
                enabled = sendEnabled,
                onClick = {
                    val text = inputText.trim()
                    if (text.isEmpty()) return@IconButton

                    // Sent messages are never persisted to the DB — they live
                    // in this in-memory list only and disappear when the user
                    // leaves the conversation. Generate a local ID just to
                    // key the bubble and the deliveredIds map.
                    val msgId = UUID.randomUUID().toString()
                    messages.add(DisplayMessage(msgId, text, isSent = true, timestamp = System.currentTimeMillis()))
                    knownIds.add(msgId)
                    inputText = ""
                    // The system clipboard is NOT cleared
                    // here any more. The app has no copy-message affordance, so it never
                    // put message content on the clipboard — blanking it on every send
                    // protected nothing this app created while destroying whatever the
                    // user had copied from somewhere else (a URL, an address, a password
                    // on its way to a manager). If a copy feature is ever added, clear
                    // only the clip the app itself set.

                    // Send on the VIEWMODEL scope (not this screen's scope): the POST
                    // must survive the user leaving the conversation right after tapping
                    // send, or a slow/contended circuit silently loses the message.
                    // The bubble id doubles as the re-drive token: a transport-class
                    // failure parks this message for the transport-back re-drive, and
                    // a manual Retry below re-uses the same id so it stays ONE entry.
                    viewModel.sendMessageInBackground(contactId, text, msgId) {
                        deliveredIds[msgId] = true
                    }

                    // No scroll launched from here (CONV-1): the append above bumps the
                    // message count, which the count-keyed auto-scroll effect reacts to.
                    // A scroll started here would race the poll loop's scroll through
                    // LazyListState's MutatorMutex and cancel it — and that cancellation,
                    // raised inside the poll coroutine, killed the poll loop.
                },
                modifier = Modifier
                    .size(44.dp)
                    .alpha(sendButtonAlpha)
                    .clip(CircleShape)
                    .background(sendButtonColor)
                    .testTag("send_button")
            ) {
                Text(
                    text = "\u2191",   // Up arrow — universal send symbol
                    fontSize = 20.sp,
                    color = RunBlack,   // dark arrow on the bright-white (lit-ᚱ) button
                    textAlign = TextAlign.Center
                )
            }
        }
    }

    // Retry/Delete popup for stuck (undelivered) sent messages.
    if (actionMessageId != null) {
        val msg = messages.find { it.id == actionMessageId }
        if (msg != null) {
            RuneScrimOverlay(
                onDismiss = { actionMessageId = null },
                cardModifier = Modifier.padding(48.dp).fillMaxWidth(),
            ) {
                RuneActionRow(
                    topHairline = false,
                    actions = listOf(
                        RuneDialogAction(
                            label = stringResource(R.string.common_retry),
                            onClick = {
                                val id = msg.id
                                val text = msg.text
                                actionMessageId = null
                                // Viewmodel scope: a resend must also survive leaving.
                                // Same token as the original send (see above).
                                viewModel.sendMessageInBackground(contactId, text, id) {
                                    deliveredIds[id] = true
                                }
                            },
                        ),
                        RuneDialogAction(
                            label = stringResource(R.string.common_delete),
                            color = RuneDanger,
                            onClick = {
                                val id = msg.id
                                actionMessageId = null
                                // Remove from in-memory list — sent messages are
                                // never persisted, so there is nothing to burn.
                                // Also un-park it: a deleted bubble must not be
                                // re-driven when the transport comes back.
                                viewModel.cancelParkedSend(id)
                                messages.removeAll { it.id == id }
                            },
                        ),
                    ),
                )
            }
        }
    }
    } // end outer Box
}

// ---------------------------------------------------------------------------
// ForwardSecrecyStalledNotice.
//
// Same muted-row visual family as conversation_pending_banner (full-width
// RunSurface background, centered small text) rather than a new banner style:
// a compact, non-modal advisory that a healthy conversation clears on its own
// once the peer's first ratchet reply lands (MessageManager clears the
// underlying counter on that first landed ratchet send — no reset here).
// ---------------------------------------------------------------------------

@Composable
private fun ForwardSecrecyStalledNotice() {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .fillMaxWidth()
            .background(RunSurface)
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag("fs_stalled_notice"),
    ) {
        Text(
            text = stringResource(R.string.conversation_fs_stalled_title),
            style = MaterialTheme.typography.bodySmall.copy(
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
            ),
            color = RunWhite,
            textAlign = TextAlign.Center,
        )
        Text(
            text = stringResource(R.string.conversation_fs_stalled_body),
            style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
            color = RunGrey,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 2.dp),
        )
    }
}

// ---------------------------------------------------------------------------
// RatchetRefusedNotice.
//
// Same muted-row visual family as ForwardSecrecyStalledNotice above (full-width
// RunSurface background, centered small text), title-less: this state is the
// send-blocking escalation of the advisory above, so it takes precedence rather
// than stacking with it. Clears on its own once an inbound ratchet blob decrypts
// (MessageManager clears the underlying latch) — no reset here.
// ---------------------------------------------------------------------------

@Composable
private fun RatchetRefusedNotice() {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .fillMaxWidth()
            .background(RunSurface)
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag("ratchet_refused_notice"),
    ) {
        Text(
            text = stringResource(R.string.conversation_ratchet_refused_body),
            style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
            color = RunGrey,
            textAlign = TextAlign.Center,
        )
    }
}

// ---------------------------------------------------------------------------
// MessageBubble — a single message in the conversation.
//
// Security purpose:
//   • A local-time timestamp is rendered (formatTime). It travels inside the
//     E2E-encrypted envelope, so it leaks no metadata to the relay/observer
//     and is never persisted (messages live only in volatile memory).
//   • Sent messages align right; received messages align left. The
//     direction is the in-memory DisplayMessage.isSent flag — messages
//     are never written to the Messages table, so there is no persisted
//     "direction" (or isRead) column to recover in forensic analysis.
// ---------------------------------------------------------------------------

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun MessageBubble(message: DisplayMessage, delivered: Boolean = false, onLongClick: () -> Unit = {}) {
    val context = LocalContext.current
    if (message.isNotice) {
        // Centered, muted ephemeral notice — no bubble, no delivery marks.
        // Mirrors GroupConversationScreen's isSystem style.
        Text(
            text = message.text,
            style = MaterialTheme.typography.bodySmall,
            color = RunGrey,
            textAlign = TextAlign.Center,
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp)
                .testTag("screenshot_notice"),
        )
        return
    }
    val alignment = if (message.isSent) Alignment.CenterEnd else Alignment.CenterStart
    val bubbleColor = if (message.isSent) RunBubbleSent else RunBubbleReceived
    // Sent bubbles: grey + translucent until the relay accepts, then opaque + real colour
    // (SentBubbleFade). No check mark. Received bubbles are unchanged (look == null).
    val look = if (message.isSent) rememberSentBubbleLook(message.id, message.timestamp, delivered) else null

    // Corner radii: rounded on all sides except the tail corner.
    val shape = if (message.isSent) {
        RoundedCornerShape(16.dp, 16.dp, 4.dp, 16.dp)
    } else {
        RoundedCornerShape(16.dp, 16.dp, 16.dp, 4.dp)
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(onClick = {}, onLongClick = onLongClick),
        contentAlignment = alignment
    ) {
        Column(
            modifier = Modifier.widthIn(max = 280.dp)
        ) {
            Box(
                modifier = Modifier
                    .clip(shape)
                    .sentBubbleBackground(look, bubbleColor)
                    .testTag(if (message.isSent) "message_bubble_sent" else "message_bubble_received")
                    .padding(start = 14.dp, end = 14.dp, top = 10.dp, bottom = if (message.isSent) 2.dp else 10.dp)
            ) {
                if (message.isSent) {
                    // Delivery is the bubble's own opacity/colour (SentBubbleFade): opaque +
                    // real colour = relay accepted (HTTP 202); grey + translucent = pending.
                    Column {
                        Text(
                            text = message.text,
                            style = MaterialTheme.typography.bodyLarge,
                            color = RunWhite,
                            modifier = Modifier.sentBubbleContent(look),
                        )
                        Row(
                            modifier = Modifier.align(Alignment.End),
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            if (message.timestamp > 0) {
                                Text(
                                    text = formatTime(context, message.timestamp),
                                    fontSize = 9.sp,
                                    color = RunGrey.copy(alpha = 0.6f),
                                    modifier = Modifier.sentBubbleContent(look),
                                )
                            }
                        }
                    }
                } else {
                    Column {
                        Text(
                            text = message.text,
                            style = MaterialTheme.typography.bodyLarge,
                            color = RunWhite
                        )
                        if (message.timestamp > 0) {
                            Text(
                                text = formatTime(context, message.timestamp),
                                fontSize = 9.sp,
                                color = RunGrey.copy(alpha = 0.6f)
                            )
                        }
                    }
                }
            }

        }
    }
}

// Locale- and device-24h-setting-aware (DateFormat), not a
// hardcoded "HH:mm" — respects the user's system time format preference.
internal fun formatTime(context: Context, millis: Long): String {
    return DateFormat.getTimeFormat(context).format(Date(millis))
}

// Screenshot-notice display time: locale time for a capture today, "Yesterday
// <time>" when the calendar day differs — the notice's 24h TTL means "differs"
// can only ever mean yesterday, never further back.
internal fun formatNoticeTime(context: Context, millis: Long): String {
    val today = Calendar.getInstance()
    val captured = Calendar.getInstance().apply { timeInMillis = millis }
    val sameDay = today.get(Calendar.YEAR) == captured.get(Calendar.YEAR) &&
        today.get(Calendar.DAY_OF_YEAR) == captured.get(Calendar.DAY_OF_YEAR)
    val time = formatTime(context, millis)
    return if (sameDay) time else context.getString(R.string.common_time_yesterday, time)
}
