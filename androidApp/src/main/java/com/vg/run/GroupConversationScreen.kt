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
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
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
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vg.run.ui.theme.AvatarColors
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
import kotlin.math.absoluteValue
import com.vg.run.ui.theme.MetamorphousFamily
import com.vg.run.ui.theme.RunError
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
import android.os.SystemClock
import java.util.UUID
import kotlinx.coroutines.CancellationException

// ---------------------------------------------------------------------------
// GroupConversationScreen — message view for one group.
//
// Security properties (mirrors ConversationScreen, plus group specifics):
//
//   • Messages live ONLY in the in-memory list below; nothing is persisted.
//     Closing the screen erases them.
//
//   • The poll loop drains every RESOLVED member's pairwise inbox via
//     GroupManager.pollGroup. Member order is shuffled per cycle and the
//     interval is jittered — but that does NOT make the burst look like N
//     separate 1:1 conversations. A 1:1 screen polls
//     ONE inbox; this polls the same k every cycle, so a relay logging target
//     + arrival time recovers the member set by co-occurrence across two
//     cycles, and intersects it with the /peek sweep (which enumerates every
//     inbound text inbox this device owns) to bind that set to one device.
//     Shuffling hides ordering, not set membership. Do not describe this loop
//     as indistinguishable from 1:1 traffic.
//
//   • Sender attribution shown on each bubble comes from the pairwise
//     channel the message decrypted on — it cannot be spoofed by another
//     member.
//
//   • A "differs" marker is shown when the sender's membership hash does not
//     match ours: the sender holds a different member list (stale roster or
//     deliberate splitting). The message is shown, the disagreement is not
//     hidden.
//
//   • Sending fans out one pairwise copy per resolved member (shuffled +
//     jittered inside GroupManager). Partial delivery is surfaced on the
//     bubble rather than pretending group delivery is atomic.
// ---------------------------------------------------------------------------

// Wider than ConversationScreen's POLL_BASE_MS + POLL_JITTER_MS (0.5-1.2 s) on
// purpose: one group cycle drains one inbox PER MEMBER, a 1:1 cycle drains one.
private const val POLL_MIN_MS = 4_000L
private const val POLL_MAX_MS = 18_000L

// NO-PARK: what a row in this screen is. PRIVATE / PRIVATE_SENT carry
// the 1:1 counterpart in senderContactId/senderAlias; GROUP_ECHO names ANOTHER group.
private enum class GroupRowKind { GROUP, PRIVATE, PRIVATE_SENT, GROUP_ECHO }

private data class GroupDisplayMessage(
    val id: String,
    val text: String,
    val isSent: Boolean,
    val senderAlias: String = "",
    val senderContactId: String = "",
    val timestamp: Long = 0L,
    val membershipOk: Boolean = true,
    // System notice (e.g. "X left the group") — centered/muted, no bubble.
    val isSystem: Boolean = false,
    // "X may have taken a screenshot" notice — same centered/muted rendering
    // as isSystem, but a DISTINCT testTag (screenshot_notice_group) so e2e
    // can target it specifically. PERSISTED for 24 h now (docs/
    // screenshot-notice-persistence-design.md) — loaded on open from
    // GroupManager.screenshotNotices and appended live from
    // GroupManager.drainScreenshotNotices.
    val isScreenshotNotice: Boolean = false,
    // Local wall-clock deadline (ScreenshotNotice.expiresAt) past which this
    // row is dropped on the next poll tick without a vault read. Non-notice
    // rows never expire.
    val expiresAt: Long = Long.MAX_VALUE,
    val kind: GroupRowKind = GroupRowKind.GROUP,
    // GROUP_ECHO only: the group the text belongs to (not this screen's).
    val echoGroupId: String = "",
    val echoGroupName: String = "",
)

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun GroupConversationScreen(
    viewModel: RunViewModel,
    groupId: String,
    onBack: () -> Unit = {},
    onOpenInfo: () -> Unit = {},
    // NO-PARK: another group's GROUP_ECHO "Open group".
    onOpenGroup: (String) -> Unit = {},
) {
    val vault = viewModel.vault ?: return
    // Captured here (composable scope) so the non-composable poll-loop
    // LaunchedEffect below and formatNoticeTime/formatTime can resolve
    // localized strings from that suspend lambda (stringResource /
    // pluralStringResource are @Composable-only and cannot be called there).
    //
    // TWO locals, deliberately: `resources` is the CONFIGURATION-AWARE handle and
    // is what every resource lookup must go through — a `getString` on
    // LocalContext.current reads the Context's own Configuration, which does not
    // track a locale change (lint LocalContextGetResourceValueCall). `context`
    // remains only for the things that genuinely need a Context rather than
    // Resources: DateFormat.getTimeFormat (see
    // formatTime / formatNoticeTime below), which reads the user's 12/24-hour
    // system setting.
    val context = LocalContext.current
    val resources = LocalResources.current

    // Every leave (back tap, poll-decided leave) routes through here.
    val leaveCleanly: () -> Unit = { onBack() }

    val torState = viewModel.torState.collectAsState().value
    val isTorReady = !RelayConfig.isTorRequired || torState is TorManager.ConnectionState.Connected
    val isRelayReachable = viewModel.isRelayReachable.collectAsState().value
    val canSend = isTorReady && viewModel.messageManager != null && isRelayReachable

    val infiniteTransition = rememberInfiniteTransition(label = "groupSendPulse")
    val sendPulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.2f,
        targetValue = 0.6f,
        animationSpec = infiniteRepeatable(animation = tween(800), repeatMode = RepeatMode.Reverse),
        label = "groupSendAlpha"
    )
    val listState = rememberLazyListState()

    // Group header data. Read OFF the main thread in the poll
    // loop below — the old remember(headerRefresh)++ ran getGroup + 2× getGroupMembers
    // (3 SQLCipher decrypts) on the MAIN thread EVERY poll cycle (4–18 s). Initial values
    // are read once here on open. (Self counts as resolved — no contactId but always us.)
    var group by remember { mutableStateOf(vault.getGroup(groupId)) }
    var memberCount by remember { mutableStateOf(vault.getGroupMembers(groupId).size) }
    var resolvedCount by remember {
        mutableStateOf(vault.getGroupMembers(groupId).count { it.contactId != null } + 1)
    }

    // If the admin removed us (roster handled during a poll anywhere in the
    // app), the group row disappears — leave the screen. A genuine (app-
    // driven) pop, not a teardown.
    LaunchedEffect(group) { if (group == null) leaveCleanly() }

    // One-time burn-on-read onboarding (shared BurnOnReadNotice.kt) — fires on
    // the FIRST conversation ever opened per vault (1:1 or group), keyed on a
    // durable vault-meta latch so it shows once total across both types.
    var showBurnNotice by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { showBurnNotice = consumeBurnNoticeOnce(vault) }
    if (showBurnNotice) {
        BurnOnReadNotice(onClose = { showBurnNotice = false })
    }

    // In-memory only — cleared on dispose (ephemeral-message invariant).
    val messages = remember { mutableStateListOf<GroupDisplayMessage>() }
    DisposableEffect(groupId) {
        onDispose {
            val count = messages.size
            messages.clear()
            LogBuffer.append("D", "GroupChat", "group conversation closed, $count message(s) erased from memory")
        }
    }
    // Fourth FAST control-cadence condition: while this group
    // conversation is on screen the background control sweep polls at the fast
    // cadence (2.5–5 s, per cycle — never the persistent window), so a kick / admin
    // handoff / re-add lands in seconds instead of a 60–90 s idle interval. Ends
    // with the screen. iOS sibling: GroupConversationView onAppear/onDisappear.
    DisposableEffect(groupId) {
        val screenKey = "conv:$groupId"
        viewModel.setGroupConversationForeground(screenKey, open = true)
        onDispose { viewModel.setGroupConversationForeground(screenKey, open = false) }
    }
    // A plain (non-snapshot) set: MAIN THREAD ONLY — the poll loop touches it only
    // outside its withContext(IO) fetches; do not touch it from IO.
    val knownIds = remember { mutableSetOf<String>() }
    // msgId → (delivered, total, unreachable) for sent fan-outs.
    val deliveryState = remember { mutableStateMapOf<String, GroupSendResult>() }
    // The "did not reach N" system note is posted once per DISTINCT N in this
    // screen session; the per-bubble mark carries the number every time.
    val undeliveredNoticed = remember { mutableStateOf(-1) }

    // Discreet runestone-flavoured feedback (mirrors the 1:1 screen): the first
    // fetch on open ("Consulting the runes…" → "The runes whisper"/"are silent").
    var runeWhisper by remember(groupId) { mutableStateOf<String?>(null) }

    // Poll loop — drains all member inboxes through GroupManager.
    LaunchedEffect(groupId) {
        var verdictShown = false
        val openedAt = SystemClock.elapsedRealtime()
        var firstPoll = true
        // Announce the fetch on open — only when the relay is reachable; with no
        // relay there are no runes to consult.
        if (isRelayReachable) runeWhisper = ConversationRunes.CONSULTING
        // Load-on-open: every UNEXPIRED persisted notice for this group, oldest
        // first — mirrors ConversationScreen's load-on-open (see docs/
        // screenshot-notice-persistence-design.md §0). Runs ONCE, off Main,
        // before the poll loop below; the poll loop only ever APPENDS newly
        // arrived notices from here on.
        viewModel.groupManager?.let { groupMgr ->
            val persisted = withContext(Dispatchers.IO) { groupMgr.screenshotNotices(groupId) }
            for (n in persisted) {
                val id = "g-sys-ss-${n.senderContactId}-${n.receivedAt}"
                if (id !in knownIds) {
                    knownIds.add(id)
                    messages.add(
                        GroupDisplayMessage(
                            id = id,
                            text = "${resources.getString(R.string.common_screenshot_notice, n.senderAlias)} · ${formatNoticeTime(context, n.timestamp)}",
                            isSent = false,
                            senderAlias = n.senderAlias,
                            senderContactId = n.senderContactId,
                            timestamp = n.timestamp,
                            isScreenshotNotice = true,
                            expiresAt = n.expiresAt,
                        )
                    )
                }
            }
        }
        // Retrieve-ack: the poll result not yet committed; abandoned if this loop is
        // cancelled (screen left) before the commit below ran. commit()/abandon() are
        // idempotent, first one wins, so a stale reference here is harmless.
        var uncommitted: PendingDrain<GroupMessage>? = null
        try {
        while (isActive) {
            // Cadence wait, skipped before the FIRST poll so the open fetch is immediate
            // (matches the 1:1 screen). Leaving cancels this effect, so back is never
            // delayed by it.
            if (!firstPoll) {
                delay(POLL_MIN_MS + secureRandomInt((POLL_MAX_MS - POLL_MIN_MS).toInt()).toLong())
            }
            firstPoll = false
            val groupMgr = viewModel.groupManager
            if (groupMgr != null) {
                // RETRIEVE-ACK: poll UNCOMMITTED (decrypt only), append to the list, THEN
                // commit (persist ratchet / anti-replay state + fire-and-forget ack).
                // Leaving mid-poll is immediate; an un-shown drain is abandoned in the
                // finally below (dropping it is also safe — the relay re-delivers after
                // its lease). The fan-out's GETs run concurrently (GROUP-FANOUT). Parked
                // items (FIX B deliveries, system notices) come first in `messages` and
                // leave the buffer only on commit.
                val drain = withContext(Dispatchers.IO) {
                    try { groupMgr.pollGroupPending(groupId).also { uncommitted = it } }
                    catch (e: CancellationException) { throw e }
                    catch (_: Exception) { null }
                }
                val received = drain?.messages ?: emptyList()
                // NO-PARK: another group's echoed text no longer counts on its row.
                if (received.any { it.isGroupEcho }) viewModel.refreshGroupUnreadCounts()
                for (gm in received) {
                    // Stable dedupe key: pairwise channel + sender's monotonic
                    // counter. System notices share counter 0, so key by timestamp.
                    // NO-PARK: PRIVATE / GROUP_ECHO rows get their own namespaces so a
                    // 1:1 id or another group's id can never collide with a group one.
                    val id = when {
                        gm.isSystem -> "g-sys-${gm.senderContactId}-${gm.timestamp}"
                        gm.isPrivate -> "gp-${gm.senderContactId}-${gm.dedupeId}"
                        gm.isGroupEcho -> "ge-${gm.groupId}-${gm.senderContactId}-${gm.dedupeId}"
                        else -> "g-${gm.senderContactId}-${gm.dedupeId}"   // dedupeId is rx-/dr- namespaced
                    }
                    if (id !in knownIds) {
                        knownIds.add(id)
                        messages.add(
                            GroupDisplayMessage(
                                id = id,
                                text = gm.text,
                                isSent = false,
                                senderAlias = gm.senderAlias,
                                senderContactId = gm.senderContactId,
                                timestamp = gm.timestamp,
                                membershipOk = gm.membershipOk,
                                isSystem = gm.isSystem,
                                kind = when {
                                    gm.isPrivate -> GroupRowKind.PRIVATE
                                    gm.isGroupEcho -> GroupRowKind.GROUP_ECHO
                                    else -> GroupRowKind.GROUP
                                },
                                echoGroupId = if (gm.isGroupEcho) gm.groupId else "",
                                echoGroupName = if (gm.isGroupEcho) gm.groupName else "",
                            )
                        )
                    }
                }
                // "Screenshot taken" notices: collected automatically inside the
                // poll above (pollGroup/pollAllControls), drained here OFF the
                // main thread (it resolves the alias from the vault — mirrors
                // the header-refresh withContext below). The RAM buffer drain is
                // destructive (rendered once here), but the notice was ALSO
                // already persisted, so it still shows on the next open via the
                // load-on-open block above. Dedupe id keys on receivedAt (the
                // store's stable ordering key) so it matches the load-on-open id.
                val notices = withContext(Dispatchers.IO) { groupMgr.drainScreenshotNotices(groupId) }
                for (n in notices) {
                    val id = "g-sys-ss-${n.senderContactId}-${n.receivedAt}"
                    if (id !in knownIds) {
                        knownIds.add(id)
                        messages.add(
                            GroupDisplayMessage(
                                id = id,
                                text = "${resources.getString(R.string.common_screenshot_notice, n.senderAlias)} · ${formatNoticeTime(context, n.timestamp)}",
                                isSent = false,
                                senderAlias = n.senderAlias,
                                senderContactId = n.senderContactId,
                                timestamp = n.timestamp,
                                isScreenshotNotice = true,
                                expiresAt = n.expiresAt,
                            )
                        )
                    }
                }
                // Everything is on screen (the list state holds the items): COMMIT —
                // persist the ratchet / anti-replay state, then the fire-and-forget ack.
                // Off Main, NonCancellable, finished before the next poll starts.
                if (drain != null && !drain.isEmpty) {
                    withContext(Dispatchers.IO + NonCancellable) { drain.commit() }
                }
                uncommitted = null
                // Rosters may have been applied during the poll — refresh the header, but
                // read it OFF the main thread and only touch state on a real change.
                val (g, mc, rc) = withContext(Dispatchers.IO) {
                    val members = vault.getGroupMembers(groupId)
                    Triple(vault.getGroup(groupId), members.size, members.count { it.contactId != null } + 1)
                }
                if (g != group) group = g
                if (mc != memberCount) memberCount = mc
                if (rc != resolvedCount) resolvedCount = rc
                // (Auto-scroll is NOT done here — see the count-keyed effect below, CONV-1:
                // a scroll cancelled by a competing scroll would kill this poll loop.)
                // First successful fetch: hold "Consulting…" long enough to read
                // before revealing the verdict (matches the 1:1 screen). Only
                // when the relay is up.
                if (!verdictShown && isRelayReachable) {
                    verdictShown = true
                    val elapsed = SystemClock.elapsedRealtime() - openedAt
                    if (elapsed < ConversationRunes.VERDICT_MIN_HOLD_MS) delay(ConversationRunes.VERDICT_MIN_HOLD_MS - elapsed)
                    runeWhisper = ConversationRunes.verdict(messages.isNotEmpty())
                }
            }
            // Hide any notice row whose TTL passed since it was rendered — cheap
            // (RAM only), no vault read per tick; the vault-side rows are pruned
            // separately (GroupManager.pruneExpiredScreenshotNotices, on the
            // background control sweep, and ScreenshotNoticeStore on write/read).
            messages.removeAll { it.isScreenshotNotice && it.expiresAt <= System.currentTimeMillis() }
        }
        } finally {
            // Screen left with a result not yet shown/committed: roll it back (the relay
            // re-delivers). Off Main — abandon releases the leases.
            uncommitted?.let { u -> withContext(Dispatchers.IO + NonCancellable) { u.abandon() } }
        }
    }

    // Auto-scroll to the newest message — its OWN effect, keyed on the message count
    // (CONV-1, mirrors the 1:1 screen). It must NEVER run inside the poll loop: every
    // LazyListState scroll goes through a MutatorMutex, so a competing scroll cancels the
    // in-flight one with a CancellationException — and inside the poll coroutine that
    // cancellation is (correctly) rethrown and kills the LaunchedEffect(groupId)
    // poll loop for the rest of the screen, leaving the group silently un-drained. The
    // count grows only when a message is genuinely appended (a re-served blob is deduped
    // away), so the gate is the same one the loop used — kept as the shared
    // ConversationRunes rule so the 1:1 and group screens still cannot diverge.
    var lastScrolledCount by remember(groupId) { mutableIntStateOf(0) }
    LaunchedEffect(groupId, messages.size) {
        val count = messages.size
        val appendedNew = count > lastScrolledCount
        lastScrolledCount = count
        if (ConversationRunes.shouldAutoScrollToLatest(appendedNew, count > 0)) {
            listState.animateScrollToItem(count - 1)
        }
    }

    // Auto-clear the rune verdict ~2.6 s after it appears (non-blocking).
    LaunchedEffect(runeWhisper) {
        val shown = runeWhisper
        if (ConversationRunes.isTransientVerdict(shown)) {
            delay(2600)
            if (runeWhisper == shown) runeWhisper = null
        }
    }

    var inputText by remember { mutableStateOf("") }

    // NO-PARK private-reply mode: (contactId, alias) of the 1:1 counterpart, or null.
    // Entered from a PRIVATE bubble's "Reply privately"; it STAYS until the user
    // closes the chip, so a follow-up line is never accidentally sent to the group.
    var privateReplyTo by remember(groupId) { mutableStateOf<Pair<String, String>?>(null) }

    // Long-press on a received bubble: VIEW the sender's personal memory
    // (alias to mnemonic) — read-only here; editing lives in the contact list.
    var memoryPopup by remember { mutableStateOf<Pair<String, String>?>(null) }  // (alias, mnemonic)

    // Back is IMMEDIATE (retrieve-ack): the header arrow and system back leave at
    // once. A drain in flight is abandoned on dispose (the poll loop's finally) and
    // nothing is lost — the relay re-delivers an un-acked blob.
    val requestBack: () -> Unit = { leaveCleanly() }
    BackHandler { requestBack() }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
            .testTag("group_conversation_view")
            .background(RunBlack)
            .imePadding()
    ) {
        // Runestone background — dim base plus the lit stone fading in while
        // the relay is reachable (parity with the iOS group view and the 1:1
        // conversation). Opacity-only, so it never zooms.
        val artLevel = viewModel.vaultSelector.displayProtectionLevel()
        val groupLitAlpha by animateFloatAsState(
            targetValue = if (isRelayReachable) 1f else 0f,
            animationSpec = tween(if (isRelayReachable) 2000 else 0, easing = LinearEasing),
            label = "groupLitAlpha"
        )
        Image(
            painter = painterResource(id = RunestoneArt.dim(artLevel)),
            contentDescription = null,
            contentScale = ContentScale.FillWidth,
            modifier = Modifier.fillMaxWidth().align(Alignment.TopCenter)
        )
        Image(
            painter = painterResource(id = RunestoneArt.brightAndLit(artLevel)),
            contentDescription = null,
            contentScale = ContentScale.FillWidth,
            modifier = Modifier.fillMaxWidth().align(Alignment.TopCenter).alpha(groupLitAlpha)
        )
        Box(modifier = Modifier.fillMaxSize().background(RunBlack.copy(alpha = 0.55f)))

        Column(
            modifier = Modifier
                .fillMaxSize()
                .navigationBarsPadding()
        ) {
            // Header bar.
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
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .clickable(onClick = onOpenInfo)
                        .testTag("group_info_button")
                ) {
                    Text(
                        text = group?.name ?: "",
                        style = MaterialTheme.typography.titleMedium,
                        color = RunWhite,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.testTag("group_conversation_title")
                    )
                    Text(
                        text = pluralStringResource(R.plurals.group_info_members, memberCount, memberCount) +
                            if (resolvedCount < memberCount)
                                " · " + stringResource(R.string.group_info_not_reachable_suffix, memberCount - resolvedCount)
                            else if (group?.isAdmin == true)
                                " · " + stringResource(R.string.group_info_admin_suffix)
                            else "",
                        style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                        color = RunGrey,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }

            // Message area: the list plus the lower-third rune whisper, OVERLAID
            // (not in-flow) so it sits below the rune and never reflows the list.
            Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp)
                    .testTag("group_message_list"),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                item { Spacer(Modifier.height(8.dp)) }
                items(messages, key = { it.id }) { message ->   // stable key
                    if (message.kind == GroupRowKind.GROUP_ECHO) {
                        GroupEchoBubble(
                            groupName = message.echoGroupName,
                            senderAlias = message.senderAlias,
                            text = message.text,
                            timeText = if (message.timestamp > 0) formatTime(context, message.timestamp) else null,
                            onOpenGroup = {
                                onOpenGroup(message.echoGroupId)
                            },
                            bubbleTag = "group_echo_bubble",
                            labelTag = "group_echo_label",
                            openTag = "group_echo_open",
                        )
                        return@items
                    }
                    if (message.kind == GroupRowKind.PRIVATE || message.kind == GroupRowKind.PRIVATE_SENT) {
                        PrivateBubble(
                            message = message,
                            delivery = deliveryState[message.id],
                            onReply = { privateReplyTo = message.senderContactId to message.senderAlias },
                        )
                        return@items
                    }
                    GroupMessageBubble(
                        message = message,
                        delivery = deliveryState[message.id],
                        onLongClick = {
                            if (!message.isSent && !message.isSystem && !message.isScreenshotNotice && message.senderContactId.isNotEmpty()) {
                                // getContact() carries a raw sharedSecret;
                                // project the mnemonic then wipe before it goes out of scope.
                                val senderRecord = vault.getContact(message.senderContactId)
                                val mnemonic = senderRecord?.mnemonic ?: ""
                                senderRecord?.sharedSecret?.secureWipe()
                                memoryPopup = message.senderAlias to mnemonic
                            }
                        },
                    )
                }
                item { Spacer(Modifier.height(8.dp)) }
            }

            // Lower third (~2/3 down), below the rune — fades on its own. Mirrors
            // the 1:1 conversation's rune whisper.
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

            // Private-reply chip (NO-PARK): while shown, Send goes to that contact's
            // 1:1 channel. Explicit exit only — the × closes it.
            privateReplyTo?.let { (_, alias) ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(RunSurface)
                        .padding(start = 12.dp, end = 12.dp, top = 8.dp),
                ) {
                    Row(
                        modifier = Modifier
                            .clip(RoundedCornerShape(14.dp))
                            .background(PrivateBubbleReceived)
                            .testTag("composer_private_chip")
                            .padding(start = 10.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        LockGlyph(PrivateAccent)
                        Text(
                            text = stringResource(R.string.group_private_reply_chip, alias),
                            style = MaterialTheme.typography.bodySmall,
                            color = PrivateAccent,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false),
                        )
                        val closeLabel = stringResource(R.string.group_private_reply_chip_close)
                        Text(
                            text = "×",
                            fontSize = 18.sp,
                            color = PrivateAccent,
                            modifier = Modifier
                                .clip(CircleShape)
                                .clickable { privateReplyTo = null }
                                .semantics { contentDescription = closeLabel }
                                .testTag("composer_private_chip_close")
                                .padding(horizontal = 8.dp),
                        )
                    }
                }
            }

            // Input bar.
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(RunSurface)
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Keyboard privacy scales with the protection tier (see ComposerKeyboardPolicy) — same rationale
                // and same Compose-API ceiling as ConversationScreen's 1:1 composer.
                val strictKeyboard = viewModel.strictComposerKeyboard
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .clip(RoundedCornerShape(20.dp))
                        .background(RunSurfaceAlt)
                        .padding(horizontal = 16.dp, vertical = 12.dp)
                ) {
                    if (inputText.isEmpty()) {
                        Text(stringResource(R.string.common_message_placeholder), style = MaterialTheme.typography.bodyLarge, color = RunGrey)
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
                            // strictKeyboard: Password (no IME suggestions/learning, no
                            // emoji key). Otherwise: plain text with autocorrect off
                            // (emoji key present) plus the no-learning/no-suggestions
                            // flags from the NoPersonalizedLearning wrapper — see
                            // ConversationScreen's composer for the full rationale.
                            // Text stays visible either way — not masked.
                            keyboardOptions = if (strictKeyboard) {
                                KeyboardOptions(keyboardType = KeyboardType.Password)
                            } else {
                                KeyboardOptions(keyboardType = KeyboardType.Text, autoCorrectEnabled = false)
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("group_message_input")
                        )
                    }
                }

                Spacer(Modifier.width(8.dp))

                val sendButtonAlpha = when {
                    !canSend -> sendPulseAlpha
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
                        val msgId = UUID.randomUUID().toString()
                        val privateTarget = privateReplyTo
                        if (privateTarget != null) {
                            // NO-PARK private reply: the EXISTING 1:1 send path to that
                            // contact (no new wire format), shown inline as PRIVATE_SENT.
                            val (cid, alias) = privateTarget
                            messages.add(
                                GroupDisplayMessage(
                                    id = msgId, text = text, isSent = true,
                                    senderAlias = alias, senderContactId = cid,
                                    timestamp = System.currentTimeMillis(),
                                    kind = GroupRowKind.PRIVATE_SENT,
                                )
                            )
                            knownIds.add(msgId)
                            inputText = ""
                            // Bubble id = re-drive token (same rule as the 1:1 screen).
                            viewModel.sendMessageInBackground(cid, text, msgId) {
                                deliveryState[msgId] = GroupSendResult(1, 1)
                            }
                            return@IconButton
                        }
                        messages.add(
                            GroupDisplayMessage(
                                id = msgId, text = text, isSent = true,
                                timestamp = System.currentTimeMillis(),
                            )
                        )
                        knownIds.add(msgId)
                        inputText = ""
                        // Clipboard no longer blanked on send — see the sibling note
                        // in ConversationScreen. The app never puts message text on the
                        // clipboard, so this only destroyed unrelated user content.

                        // Viewmodel scope so the fan-out POST survives leaving the group.
                        viewModel.sendGroupMessageInBackground(groupId, text) { result ->
                            deliveryState[msgId] = result
                            // Explain the mark once: who got nothing and why, and that
                            // there is no later delivery (no backfill, burn-on-read).
                            val n = result.undelivered
                            if (n > 0 && n != undeliveredNoticed.value) {
                                undeliveredNoticed.value = n
                                val now = System.currentTimeMillis()
                                messages.add(
                                    GroupDisplayMessage(
                                        id = "g-sys-local-undelivered-$now",
                                        text = resources.getString(R.string.group_notice_not_delivered, n),
                                        isSent = false, timestamp = now, isSystem = true,
                                    )
                                )
                            }
                        }
                        // No scroll launched from here (CONV-1): the append above bumps the
                        // message count and the count-keyed effect scrolls. A scroll started
                        // here would race the poll loop's scroll through LazyListState's
                        // MutatorMutex and cancel — and thereby kill — the poll loop.
                    },
                    modifier = Modifier
                        .size(44.dp)
                        .alpha(sendButtonAlpha)
                        .clip(CircleShape)
                        .background(sendButtonColor)
                        .testTag("group_send_button")
                ) {
                    Text(
                        text = "↑",
                        fontSize = 20.sp,
                        color = RunBlack,   // dark arrow on the bright-white (lit-ᚱ) button
                        textAlign = TextAlign.Center
                    )
                }
            }
        }

        // Memory popup — view-only (alias + the user's private memory).
        memoryPopup?.let { (alias, mnemonic) ->
            RuneScrimOverlay(
                onDismiss = { memoryPopup = null },
                testTag = "group_memory_alert",
            ) {
                RuneCardBody {
                    RuneDialogTitle(alias)
                    RuneDialogMessage(
                        mnemonic.ifEmpty { stringResource(R.string.contact_list_no_memory_yet) },
                        modifier = Modifier.testTag("group_memory_text"),
                    )
                }
            }
        }
    }
}

/** NO-PARK: a PRIVATE (received) or PRIVATE_SENT bubble — a 1:1 text shown in the
 *  group screen, visible only to us. Distinct colour family + padlock + label. */
@Composable
private fun PrivateBubble(
    message: GroupDisplayMessage,
    delivery: GroupSendResult?,
    onReply: () -> Unit,
) {
    val sent = message.kind == GroupRowKind.PRIVATE_SENT
    Box(
        modifier = Modifier.fillMaxWidth(),
        contentAlignment = if (sent) Alignment.CenterEnd else Alignment.CenterStart,
    ) {
        Column(modifier = Modifier.widthIn(max = 280.dp)) {
            Box(
                modifier = Modifier
                    .clip(
                        if (sent) RoundedCornerShape(16.dp, 16.dp, 4.dp, 16.dp)
                        else RoundedCornerShape(16.dp, 16.dp, 16.dp, 4.dp)
                    )
                    .background(if (sent) PrivateBubbleSent else PrivateBubbleReceived)
                    .testTag(if (sent) "group_private_sent_bubble" else "group_private_bubble")
                    .padding(start = 14.dp, end = 14.dp, top = 8.dp, bottom = if (sent) 2.dp else 6.dp)
            ) {
                Column {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(5.dp),
                    ) {
                        LockGlyph(PrivateAccent)
                        Text(
                            text = if (sent) stringResource(R.string.group_private_to, message.senderAlias)
                                   else stringResource(R.string.group_private_from, message.senderAlias),
                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                            color = PrivateAccent,
                            modifier = if (sent) Modifier else Modifier.testTag("group_private_label"),
                        )
                    }
                    Text(text = message.text, style = MaterialTheme.typography.bodyLarge, color = RunWhite)
                    Row(
                        modifier = Modifier.align(Alignment.End),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        if (!sent) {
                            Text(
                                text = stringResource(R.string.group_private_reply),
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.sp),
                                color = PrivateAccent,
                                modifier = Modifier
                                    .clip(RoundedCornerShape(8.dp))
                                    .clickable(onClick = onReply)
                                    .testTag("group_private_reply")
                                    .padding(vertical = 6.dp, horizontal = 2.dp),
                            )
                            Spacer(Modifier.width(8.dp))
                        }
                        if (message.timestamp > 0) {
                            Text(
                                text = formatTime(LocalContext.current, message.timestamp),
                                fontSize = 9.sp,
                                color = RunGrey.copy(alpha = 0.6f)
                            )
                        }
                        if (sent) {
                            Text(
                                text = if (delivery?.allDelivered == true) "✓" else "·",
                                fontSize = 12.sp,
                                color = if (delivery?.allDelivered == true) RunGrey else RunGrey.copy(alpha = 0.3f),
                            )
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun GroupMessageBubble(
    message: GroupDisplayMessage,
    delivery: GroupSendResult?,
    onLongClick: () -> Unit = {},
) {
    if (message.isScreenshotNotice) {
        // Same centered/muted style as a system notice, but a DISTINCT testTag
        // so e2e can target it specifically (see GroupManager.drainScreenshotNotices).
        Text(
            text = message.text,
            style = MaterialTheme.typography.bodySmall,
            color = RunGrey,
            textAlign = TextAlign.Center,
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp)
                .testTag("screenshot_notice_group"),
        )
        return
    }
    if (message.isSystem) {
        // Centered, muted system notice — no bubble, no avatar/attribution.
        Text(
            text = message.text,
            style = MaterialTheme.typography.bodySmall,
            color = RunGrey,
            textAlign = TextAlign.Center,
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp)
                .testTag("group_system_message"),
        )
        return
    }
    val alignment = if (message.isSent) Alignment.CenterEnd else Alignment.CenterStart
    val bubbleColor = if (message.isSent) RunBubbleSent else RunBubbleReceived
    val shape = if (message.isSent) {
        RoundedCornerShape(16.dp, 16.dp, 4.dp, 16.dp)
    } else {
        RoundedCornerShape(16.dp, 16.dp, 16.dp, 4.dp)
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            // Long-press a received bubble (the contact's name is on it) to
            // view your private memory of the sender.
            .combinedClickable(onClick = {}, onLongClick = onLongClick),
        contentAlignment = alignment,
    ) {
        Column(modifier = Modifier.widthIn(max = 280.dp)) {
            Box(
                modifier = Modifier
                    .clip(shape)
                    .background(bubbleColor)
                    .testTag(if (message.isSent) "group_bubble_sent" else "group_bubble_received")
                    .padding(start = 14.dp, end = 14.dp, top = 8.dp, bottom = if (message.isSent) 2.dp else 8.dp)
            ) {
                Column {
                    if (!message.isSent) {
                        // Sender attribution from the pairwise channel —
                        // unforgeable by other members.
                        val senderColor = AvatarColors[
                            message.senderContactId.hashCode().absoluteValue % AvatarColors.size
                        ]
                        Text(
                            text = message.senderAlias,
                            style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                            color = senderColor,
                        )
                    }
                    Text(
                        text = message.text,
                        style = MaterialTheme.typography.bodyLarge,
                        color = RunWhite
                    )
                    Row(
                        modifier = Modifier.align(Alignment.End),
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        if (!message.membershipOk) {
                            // The sender's member list differs from ours —
                            // never hide the disagreement.
                            Text(
                                text = stringResource(R.string.group_member_list_differs),
                                fontSize = 9.sp,
                                color = RunError,
                            )
                        }
                        if (message.timestamp > 0) {
                            Text(
                                text = formatTime(LocalContext.current, message.timestamp),
                                fontSize = 9.sp,
                                color = RunGrey.copy(alpha = 0.6f)
                            )
                        }
                        if (message.isSent) {
                            Text(
                                text = when {
                                    delivery == null -> "·"                            // pending
                                    // Refused copies + members with no resolved contact (no
                                    // retry, no backfill) — be honest, in words.
                                    delivery.undelivered > 0 ->
                                        stringResource(R.string.group_delivery_not_delivered, delivery.undelivered)
                                    delivery.allDelivered -> "✓"                       // all copies accepted
                                    else -> "${delivery.delivered}/${delivery.total}"  // nobody addressable (0/0)
                                },
                                fontSize = 12.sp,
                                color = when {
                                    delivery == null -> RunGrey.copy(alpha = 0.3f)
                                    delivery.allDelivered -> RunGrey
                                    else -> RunError
                                },
                                // e2e: the delivered/total indicator, present in all
                                // three states (the text IS the state). Id must stay
                                // byte-identical to the iOS deliveryMark's
                                // accessibilityIdentifier (GroupViews.swift).
                                modifier = Modifier.testTag("group_delivery_status"),
                            )
                        }
                    }
                }
            }
        }
    }
}

