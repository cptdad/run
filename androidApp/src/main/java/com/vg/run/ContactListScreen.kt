package com.vg.run

import androidx.compose.animation.core.Animatable
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import com.vg.run.ui.theme.AvatarColors
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurface
import com.vg.run.ui.theme.RunWhite
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.heightIn
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalConfiguration
import kotlin.math.absoluteValue
import com.vg.run.ui.theme.RunError
import com.vg.run.ui.theme.RunSurfaceAlt
import com.vg.run.ui.theme.RuneDanger
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.input.KeyboardType
import android.os.SystemClock

@OptIn(ExperimentalComposeUiApi::class, ExperimentalFoundationApi::class)
@Composable
fun ContactListScreen(
    viewModel: RunViewModel,
    onContactTapped: (String) -> Unit,
    onAddContact: () -> Unit,
    onChangePin: () -> Unit,
    onGroupTapped: (String) -> Unit = {},
    onCreateGroup: () -> Unit = {},
    onProtectionLevel: () -> Unit = {},
    onMoveToNewDevice: () -> Unit = {}
) {
    val context = LocalContext.current
    // Localized copy for the pre-connect relay status line + stall hints
    // (RelayConnectHints.connectStatusLine / TOR_STALLED_HINT). Resolved once
    // per composition — locale doesn't change without a process restart.
    val connectStrings = remember { ConnectStrings.from(context) }
    // Captured here (not inline in the onClick below) because that callback
    // runs OUTSIDE composition, where stringResource() cannot be called.
    val introduceErrorMessage = stringResource(R.string.referral_introduce_error)

    // Contacts the relay has lost (persistent 404) — flagged for re-pair, same UI
    // as a stale/legacy contact (tap → re-pair).
    val relayLostContacts by viewModel.relayLostContacts.collectAsState()
    // Introducer-side "your intro was relayed" info modal queue — see the
    // dialog block below (rendered only when no referralOffer consent gate
    // is up) and [RunViewModel.referralRelayEvents].
    val referralRelayEvents by viewModel.referralRelayEvents.collectAsState()
    // First-open push-notification prompt (set post-unlock; see
    // RunViewModel.onVaultOpened).
    val showPushPrompt by viewModel.showPushPrompt.collectAsState()
    // In-app update nudge — same deferral
    // pattern as the push prompt, see the gating `if` below.
    val showUpdateNudge by viewModel.showUpdateNudge.collectAsState()
    // In-app store-review nudge (ReviewPromptPolicy.kt, commonMain) — a
    // one-shot per-session signal, not a dialog; see the LaunchedEffect below.
    val requestReviewFlow by viewModel.requestReviewFlow.collectAsState()
    // Debug mode (Settings → Debug mode, DebugMode.kt commonMain): opt-in
    // anonymous diagnostic-log upload to the relay — see the settings row and
    // its consent dialog below.
    val debugMode by viewModel.debugMode.collectAsState()
    // The contact list, its groups and the stale ("Re-pair") / pending
    // ("Waiting…") sets: loaded by RunViewModel on IO whenever the vault events,
    // the relay-lost set or an explicit refresh change (see
    // RunViewModel.contactList), never read from the vault here. null = the
    // session's first load has not landed yet (the surface stays hidden, so a
    // revealed list never flashes "no contacts yet"). Returning from another
    // screen shows the session's previous snapshot while a refresh runs:
    // this screen is a NavHost destination, so navigating away disposes it and
    // the LaunchedEffect below asks for a reload on every re-entry (e.g. back
    // from AddContact with a new row). In-place events (delete, accept, rename)
    // call refreshContactList() themselves.
    val snapshot by viewModel.contactList.collectAsState()
    LaunchedEffect(Unit) { viewModel.refreshContactList() }
    val contacts = snapshot?.contacts ?: emptyList()
    val groups = snapshot?.groups ?: emptyList()
    val staleContactIds = snapshot?.staleIds ?: emptySet()
    val pendingContactIds = snapshot?.pendingIds ?: emptySet()

    // The one user-initiated overlay on screen (contact menu, confirms, the
    // memory editor, the introduce picker, the settings modals). They are
    // mutually exclusive: every hand-off replaces the slot in one assignment.
    // Holds the secret-free ContactListItem projection, not ContactRecord (see
    // loadContactListSnapshot). The aliases it holds are also in the
    // ViewModel's contactList, which lock and wipe null out explicitly; this
    // slot dies with the composition.
    var dialog by remember { mutableStateOf<ContactListDialog?>(null) }
    // "Reset relay access": an in-flight flag (two relay round-trips per inbox
    // over Tor) read by the contact menu, and the one-line result, which
    // arrives after the confirm dialog closed.
    var resetRelayBusy by remember { mutableStateOf(false) }
    var resetRelayResult by remember { mutableStateOf<String?>(null) }
    var settingsMenuExpanded by remember { mutableStateOf(false) }
    // Anonymous "Report bug" (BugReportSender.kt, commonMain): the text-entry
    // modal is ContactListDialog.ReportBug (its draft lives in ReportBugDialog),
    // then a separate one-shot thanks modal on success.
    var showReportBugThanks by remember { mutableStateOf(false) }
    // External SOCKS proxy mode (Settings → External Tor proxy,
    // ExternalProxySettingsModal.kt): this session's status for the connecting
    // UI (OFF renders nothing there).
    val extProxyStatus by viewModel.externalProxyStatus.collectAsState()
    // Referral/vouching (referral.md): the introduce picker is
    // ContactListDialog.Introduce; below is the incoming offer awaiting consent.
    // Referred contacts are trusted transitively (no verification step).
    // startReferral's result surfaced — set only on a null (no transport /
    // invalid) outcome; success closes the picker with no confirmation (the
    // send is durably queued+redriven core-side).
    var introduceError by remember { mutableStateOf<String?>(null) }
    var referralOffer by remember { mutableStateOf<ReferralOffer?>(null) }
    var referralBusy by remember { mutableStateOf(false) }
    // The last accept attempt failed (e.g. the inbox mint timed out over a
    // flaky Tor circuit) — re-present the offer as a Retry instead of silently
    // reverting to "Approve".
    var referralAcceptFailed by remember { mutableStateOf(false) }

    // GROUP-1 consent gate: the next parked group invite awaiting accept/decline.
    // Mirrors the referral offer flow — the background control poll parks the
    // invite in GroupManager; this lifts it into a dialog. No group is joined and
    // no contact-tag is disclosed until the user taps Join.
    var groupInvite by remember { mutableStateOf<GroupInvite?>(null) }
    var groupInviteBusy by remember { mutableStateOf(false) }

    // A declined offer stays in pendingOffers until the ViewModel's IO decline
    // drops it; until then it must not be re-presented (see the decline button).
    var declinedIntroId by remember { mutableStateOf<String?>(null) }

    // Surface the next incoming referral offer / group invite for consent AND
    // dismiss it once consumed (the rules: [consentToShow]). What is pending
    // comes from RunViewModel.pendingConsent, refreshed by the control poll,
    // the unread prime, unlock, the accept/decline completions and a 4 s
    // backstop tick; the busy flags are this screen's in-flight state.
    val pendingConsent by viewModel.pendingConsent.collectAsState()
    LaunchedEffect(pendingConsent, dialog is ContactListDialog.Introduce, referralBusy, groupInviteBusy, declinedIntroId) {
        val pending = if (declinedIntroId != null && pendingConsent.offer?.introId == declinedIntroId) {
            pendingConsent.copy(offer = null)
        } else {
            pendingConsent
        }
        val next = consentToShow(
            pending = pending,
            shown = ConsentShown(referralOffer, groupInvite),
            introduceOpen = dialog is ContactListDialog.Introduce,
            referralBusy = referralBusy,
            groupInviteBusy = groupInviteBusy,
        )
        referralOffer = next.offer
        groupInvite = next.invite
    }

    // Tor bootstrap progress for the ring animation.
    val torState = viewModel.torState.collectAsState().value
    val torProgress = when {
        !RelayConfig.isTorRequired -> 1f
        torState is TorManager.ConnectionState.Connected -> 1f
        torState is TorManager.ConnectionState.Bootstrapping -> torState.progress / 100f
        else -> 0f
    }
    val animatedProgress by animateFloatAsState(
        targetValue = torProgress,
        animationSpec = tween(500, easing = LinearEasing),
        label = "ringProgress"
    )

    // "Still connecting" = we have not yet completed a round-trip to the relay's
    // onion. Deliberately NOT `torState !is Connected`: Tor reports Connected on
    // `Bootstrapped 100%`, which only proves it reached the directory system and
    // built *a* circuit — the descriptor fetch + rendezvous with the relay happens
    // afterwards, so the ring used to go solid seconds (sometimes minutes) before
    // anything could actually be sent. iOS has always pulsed until the relay itself
    // answered (`litVisible`); this is the Android sibling of that gate.
    val relayHandshakeComplete = viewModel.relayHandshakeComplete.collectAsState().value
    val isTorConnecting = RelayConfig.isTorRequired && !relayHandshakeComplete
    // Breath phase for the red ring (RingPulse.kt, commonMain — shared with
    // iOS): a linear 0..1 sawtooth over RingPulse.PERIOD_MS; the opacity
    // curve itself lives in RingPulse.opacity (cosine-eased, grows with the
    // paced connect percent). Computed further down once connectPercent exists.
    val infiniteTransition = rememberInfiniteTransition(label = "ringPulse")
    val ringPhase by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(RingPulse.PERIOD_MS.toInt(), easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "ringPhase",
    )

    val isRelayReachable = viewModel.isRelayReachable.collectAsState().value
    // The connect TRANSITION (ring solid → runestone lit → list revealed → rows
    // and Add contact enabled) keys on this, NOT the raw reachability flag: it
    // also waits for the connect-time unread prime, so the "message waiting"
    // dots are in the list the frame it appears (user requirement 2026-09-14).
    // The raw flag stays for the outage banner + hints below.
    val contactsReady = viewModel.contactsReady.collectAsState().value
    val relayConnectPhase = viewModel.relayConnectPhase.collectAsState().value
    // PRE-connect bootstrap stall (iOS sibling: AppState.torBootstrapStalled).
    // Outranked by RelayConnectPhase.Stalled below, which has an actionable
    // Reconnect; this only speaks while the phase is still Connecting.
    val torBootstrapStalled = viewModel.torBootstrapStalled.collectAsState().value
    // Live connection-log panel (ConnectionLogPanel.kt): hidden until the user
    // triple-taps the "Connecting to…" caption. rememberSaveable so a rotation
    // mid-diagnosis doesn't collapse it. iOS sibling:
    // ContactListView.swift's `showConnectLog`.
    var showConnectLog by rememberSaveable { mutableStateOf(false) }
    // Real Tor bootstrap percent — the pacer's PHASE-ONE input. Total, never
    // null: Idle/Failed/Connected all read as 0 here because once Connected
    // the pacer switches to its phase-two target and ignores this value (see
    // BootstrapProgressPacer.realTarget).
    val torPercent = when (val s = torState) {
        is TorManager.ConnectionState.Bootstrapping -> s.progress
        else -> 0
    }
    val torConnectedNow = torState is TorManager.ConnectionState.Connected
    // The percent shown in BOTH phases comes from the shared
    // [BootstrapProgressPacer] — never the raw Tor percent, never a time
    // curve. App Store review 2.1 rejected 1.6.15 over a number that SAT
    // STILL at 95 for a minute ("loads indefinitely"): Tor parks at 95% while
    // it builds its first circuit, and the old phase-two curve was capped at
    // 95. The pacer climbs at a bounded rate, keeps creeping while the real
    // state doesn't move, and only reaches 100 when the relay actually
    // answers. elapsedRealtime is kernel uptime, immune to wall-clock changes
    // (same primitive InactivityWipe/ReauthPolicy use elsewhere in this app).
    // iOS sibling: ContactListView's `connectPacer` / `connectPercent`.
    val connectPacer = remember { BootstrapProgressPacer { SystemClock.elapsedRealtime() } }
    // rememberUpdatedState so the 1 Hz loop below can stay keyed on Unit: its
    // cadence must NOT be restarted by every Tor progress emission (that would
    // re-arm the delay and starve the creep), but it must still read the
    // freshest state on each tick.
    val connectRealTarget = rememberUpdatedState(
        BootstrapProgressPacer.realTarget(torConnected = torConnectedNow, torPercent = torPercent)
    )
    // Relay REACHABILITY is the true 100% (the same signal that lights the
    // runestone and enables the rows), not Tor's own 100%.
    val connectDone = rememberUpdatedState(contactsReady)
    var connectPercent by remember { mutableIntStateOf(0) }
    // 1 Hz tick across the WHOLE pre-connect window — the old ticker only ran
    // once Tor was already connected, so phase one had no tick of its own and
    // moved only when Tor itself emitted.
    LaunchedEffect(Unit) {
        while (true) {
            connectPacer.observe(connectRealTarget.value, connectDone.value)
            connectPercent = connectPacer.displayed()
            delay(1000)
        }
    }
    // The one status line, shared verbatim by both render sites below (the
    // e2e "Connecting" XPath that used to force these two sites to differ in
    // wording is now scoped to the referral dialog — see e2e-tests/helpers).
    // No percent parameter any more: the wording is pure phase
    // text now, and each render site appends its own animated-dots suffix
    // (connectCaptionWithDots) purely for display — connectPercent itself is
    // still computed above and still drives RingPulse.opacity/ConnectionLog.
    val connectStatusLine = RelayConnectHints.connectStatusLine(
        torConnected = torConnectedNow,
        strings = connectStrings,
    )
    // Lit (white R) layer follows RELAY REACHABILITY, not Tor 100%: the ring
    // already goes solid at Tor 100% on its own (pulseMultiplier above), while
    // the white R must light the moment BEFORE the rows become tappable (user
    // directive 2026-09-05). Fade-in is LIT_FADE_MS; rows (rowsEnabled below)
    // enable when it completes. Snaps to 0 instantly on reachable→false so the
    // lit stone is NEVER shown while the relay is down. (The 09-01 ring change
    // had moved this onto torConnectedNow, which lit the R up to a full cold
    // relay-probe budget ahead of the rows.)
    // Ring → solid → R (RingPulse.kt): the instant
    // the relay answers the ring snaps to solid red (250 ms), holds
    // RingPulse.SOLID_HOLD_MS, and only then does the white R fade in. Seeded
    // from the current value so a recomposition on an already-connected
    // session (rotation, popping back from a conversation) never re-runs the
    // sequence. Loss of reachability darks the R immediately (unchanged) and
    // returns the ring to its pulse.
    var litOn by remember { mutableStateOf(contactsReady) }
    LaunchedEffect(contactsReady) {
        if (contactsReady) {
            if (!litOn) {
                delay(RingPulse.SOLID_HOLD_MS)
                litOn = true
            }
        } else {
            litOn = false
        }
    }
    val litAlpha by animateFloatAsState(
        targetValue = if (litOn) 1f else 0f,
        animationSpec = tween(if (litOn) LIT_FADE_MS else 0, easing = LinearEasing),
        label = "litAlpha"
    )
    val ringSolid by animateFloatAsState(
        targetValue = if (contactsReady) 1f else 0f,
        animationSpec = tween(250),
        label = "ringSolid",
    )
    val ringPulseAlpha = RingPulse.opacity(connectPercent / 100f, ringPhase)
    val ringAlpha = ringPulseAlpha + (1f - ringPulseAlpha) * ringSolid
    // Rows + the e2e relay-warm marker go live only once the white R has
    // finished fading in — never before it. Derived, no timer: the animated
    // value reaches exactly 1f at the end of the tween, and a reachability
    // drop snaps it (and therefore this) off in the same frame.
    val rowsEnabled = contactsReady && litAlpha >= 1f

    // FIRST-REVEAL GATE. The contact list — every
    // row (contacts, groups, pending/awaiting-inbox, referred), the unread
    // badges, the repair banner AND the empty-contacts copy — is not on screen
    // AT ALL until the relay has actually answered once this session. Until
    // then the main screen shows only the runestone, the paced connect caption
    // and the connect hint (plus the cogwheel and Add contact, unchanged).
    // The gate signal is [contactsReady] (relay answered AND unread prime settled) — the same `done` the shared
    // [BootstrapProgressPacer] is fed and the same signal that lights the
    // runestone — so the list arrives WITH the lit stone instead of sitting
    // there greyed out over a "Connecting…" caption.
    //
    // ONLY THE FIRST REVEAL IS GATED. Once revealed the list STAYS visible
    // even if reachability is later lost (the stall / grey-out phases): the
    // ask was "not visible until connected", NOT "hidden whenever
    // disconnected" — yanking a populated list mid-session would lose scroll
    // position and read as data loss, and the rows already dim + disable
    // (rowsEnabled) plus show a relay-status strip in that state.
    //
    // Seeded from the CURRENT value, not false, so a recomposition or an
    // activity recreation (rotation, config change) on an already-connected
    // session never flashes the placeholder.
    // iOS sibling: ContactListView.swift's `listRevealed`.
    var listRevealed by remember { mutableStateOf(contactsReady) }
    LaunchedEffect(contactsReady) {
        listRevealed = contactListRevealed(listRevealed, contactsReady)
    }
    val surface = contactListSurface(
        revealed = listRevealed,
        hasContent = snapshot?.let { it.contacts.isNotEmpty() || it.groups.isNotEmpty() },
    )

    Box(modifier = Modifier
        .fillMaxSize()
        .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
        .testTag("unlocked_root")
        .background(RunBlack)
    ) {
        val artLevel = viewModel.vaultSelector.displayProtectionLevel()
        // Dim runestone — always visible as the base layer.
        Image(
            painter = painterResource(id = RunestoneArt.dim(artLevel)),
            contentDescription = null,
            contentScale = ContentScale.FillWidth,
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.TopCenter)
        )

        // Bright runestone — fades in as Tor bootstraps, and fades out (into the
        // solid lit layer below) the instant Tor reaches 100%. Pulses gently
        // only while Tor is still bootstrapping.
        Image(
            painter = painterResource(id = RunestoneArt.bright(artLevel)),
            contentDescription = null,
            contentScale = ContentScale.FillWidth,
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.TopCenter)
                .alpha(ringAlpha * (1f - litAlpha))
        )

        // Lit runestone (white R) — fades in when the relay answers; the rows
        // enable when this fade completes (rowsEnabled).
        Image(
            painter = painterResource(id = RunestoneArt.brightAndLit(artLevel)),
            contentDescription = null,
            contentScale = ContentScale.FillWidth,
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.TopCenter)
                .alpha(litAlpha)
        )

        // Contact list content overlaid on top.
        Scaffold(
            containerColor = Color.Transparent
        ) { padding ->
            if (surface != ContactListSurface.Rows) {
                // The first-run how-to prompt is driven once by the durable vault-meta
                // LaunchedEffect above (not from here — this block re-enters whenever the
                // list is empty, which is exactly what used to re-ask on every open).
                // Empty state — matches iOS: no "No contacts yet" title/subtitle,
                // just the Add-contact button sitting in the lower third (top
                // spacer weighted 2:1 over the bottom, so it's BELOW the centered
                // runestone glyph), plus a "Connecting…" line while the relay is
                // unreachable. A visible next action (not a blank screen) is what
                // App Store review asked for; iOS is the reference look.
                //
                // THE SAME layout also serves the pre-connect placeholder (see the
                // first-reveal gate above) — it is already exactly what that state
                // must show — but under a DIFFERENT container tag: a vault WITH
                // contacts must never report `empty_contacts_state` just because
                // the relay hasn't answered yet (the e2e freshness/empty-state
                // probes key on that id), and a fresh vault must not flash "no
                // contacts" before the relay answers. iOS sibling:
                // ContactListView.swift's emptyState under containerA11yId.
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .testTag(
                            if (surface == ContactListSurface.HiddenUntilConnected)
                                "contact_list_hidden_until_connected"
                            else "empty_contacts_state"
                        ),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    // Anchor below the stone (RunestoneGeometry, shared with
                    // iOS): the art is width-filled from the window top, so
                    // the stone's foot is at a known y; the Add-contact pill
                    // (≈48 dp) sits on the foot and the caption starts just
                    // below it. Weighted spacers used to float the caption
                    // over the stone on tall phones.
                    val screenWDp = LocalConfiguration.current.screenWidthDp.toFloat()
                    val screenHDp = LocalConfiguration.current.screenHeightDp.toFloat()
                    val stoneBottom = RunestoneGeometry.stoneBottomY(screenWDp, screenHDp, fillWidth = true).dp
                    // The connect caption block starts BELOW the blue ring's
                    // bottom edge (RunestoneGeometry.captionTopY), whatever sits above it.
                    val captionTop = RunestoneGeometry.captionTopY(screenWDp, screenHDp, fillWidth = true).dp
                    val addButtonComposed = surface != ContactListSurface.HiddenUntilConnected
                    Spacer(
                        Modifier.height(
                            (stoneBottom - padding.calculateTopPadding() - 48.dp - RunestoneGeometry.BELOW_STONE_GAP.dp)
                                .coerceAtLeast(0.dp)
                        )
                    )
                    // Pairing mints an inbox on the relay, so keep the entry
                    // point inert until the relay is reachable — otherwise
                    // AddContact just parks on "Setting up inbox…". Not composed
                    // at all until the relay has answered once:
                    // the pre-connect placeholder is only the
                    // runestone + caption; after the first reveal a reachability
                    // flap keeps it on screen, disabled. iOS sibling:
                    // ContactListView.emptyState.
                    if (addButtonComposed) {
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(24.dp))
                                .background(if (contactsReady) RunWhite.copy(alpha = 0.85f) else RunWhite.copy(alpha = 0.4f))
                                .clickable(enabled = contactsReady, onClick = onAddContact)
                                .padding(horizontal = 24.dp, vertical = 12.dp)
                                .testTag("empty_add_contact_button"),
                        ) {
                            Text(text = stringResource(R.string.add_contact_title), color = RunBlack)
                        }
                    }
                    if (!contactsReady) {
                        // Column y so far: the foot minus the gap, minus the
                        // button's ≈48 dp when it is not composed (pre-connect).
                        val columnYSoFar = stoneBottom - RunestoneGeometry.BELOW_STONE_GAP.dp -
                            (if (addButtonComposed) 0.dp else 48.dp)
                        Spacer(Modifier.height((captionTop - columnYSoFar).coerceAtLeast(8.dp)))
                        // External SOCKS proxy mode: say so (and whether the
                        // proxy answers) above the usual status — nothing when
                        // the mode is off.
                        if (extProxyStatus != RunViewModel.ExternalProxyStatus.OFF) {
                            ExternalProxyStatusText(
                                extProxyStatus,
                                modifier = Modifier.padding(horizontal = 24.dp, vertical = 4.dp),
                            )
                        }
                        if (relayConnectPhase == RunViewModel.RelayConnectPhase.Stalled) {
                            // Self-heal exhausted (QA #1): the embedded Tor already
                            // auto-restarted once and the relay is still unreachable.
                            // Honest status (it's the LOCAL Tor, not the relay) + a manual
                            // Reconnect that rebuilds Tor, instead of an endless spinner.
                            Text(
                                text = stringResource(R.string.connect_relay_stalled),
                                style = MaterialTheme.typography.bodySmall,
                                color = RunGrey,
                            )
                            Spacer(Modifier.height(10.dp))
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(24.dp))
                                    .background(RunWhite.copy(alpha = 0.12f))
                                    .clickable(onClick = { viewModel.reconnectRelay() })
                                    .padding(horizontal = 20.dp, vertical = 10.dp)
                                    .testTag("relay_reconnect_button"),
                            ) {
                                Text(text = stringResource(R.string.connect_reconnect_button), color = RunWhite)
                            }
                        } else if (torBootstrapStalled) {
                            // Tor has been bootstrapping past its own 90s budget and
                            // still isn't connected — by far the likeliest cause is a
                            // network that blocks it. NON-TERMINAL: the bootstrap is
                            // still running and this retracts itself if it lands.
                            Text(
                                text = connectStrings.torStalledHint,
                                style = MaterialTheme.typography.bodySmall,
                                color = RunGrey,
                                textAlign = TextAlign.Center,
                                modifier = Modifier
                                    .padding(horizontal = 24.dp)
                                    .testTag("tor_stalled_hint"),
                            )
                        } else {
                            // Two-phase status line, always present — visible
                            // movement (animated dots, not a raw percent) instead
                            // of a frozen caption. The percent itself is still
                            // computed (connectPercent, feeding RingPulse) — it
                            // just no longer renders in this text.
                            val dotStep = rememberConnectDotsStep()
                            Text(
                                text = connectCaptionWithDots(connectStatusLine, dotStep),
                                style = MaterialTheme.typography.bodyLarge,
                                color = RunGrey,
                                // tripleTapToggle only ADDS a tap recognizer; the
                                // caption keeps its testTag (the e2e suite keys on
                                // `tor_progress_caption`) and had no click
                                // behaviour to interfere with.
                                modifier = Modifier
                                    .testTag("tor_progress_caption")
                                    .tripleTapToggle { showConnectLog = !showConnectLog },
                            )
                            // Expectation-setting, delayed: absent for the first 10 s, then the
                            // original "first connection" hint for 10-30 s, then
                            // REPLACED by the slow-network hint past 30 s — see
                            // rememberConnectHintStage. Separate line from the
                            // 90 s stall hint above, which says something
                            // different (this network may be blocking) and
                            // replaces the caption entirely — the two never
                            // render together.
                            val hintStage = rememberConnectHintStage()
                            if (hintStage > 0) {
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    text = stringResource(
                                        if (hintStage == 1) R.string.connect_relay_first_time_hint
                                        else R.string.connect_relay_slow_hint
                                    ),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = RunGrey,
                                    textAlign = TextAlign.Center,
                                    modifier = Modifier
                                        .padding(horizontal = 24.dp)
                                        .testTag("connect_relay_hint"),
                                )
                            }
                        }
                    }
                    // Connection-log panel, OUTSIDE the !isRelayReachable block:
                    // once opened (triple-tap on the caption) it stays until the
                    // user taps it closed — it must NOT vanish when the relay is
                    // reached. Renders nothing while
                    // collapsed. iOS sibling: ContactListView.emptyState.
                    ConnectionLogPanel(
                        expanded = showConnectLog,
                        modifier = Modifier
                            .padding(horizontal = 12.dp)
                            .padding(top = 8.dp)
                            .clickable { showConnectLog = false },
                    )
                    Spacer(Modifier.weight(1f))
                }
            } else {
                // Contacts-present case: the relay progress caption used to
                // render ONLY in the empty-contacts branch above, so once a
                // first contact existed a slow/stalled bootstrap went silent —
                // the connection percent must ALWAYS be presented while it is
                // being established. Rendered as a BOTTOM-anchored floating
                // banner overlaying the list —
                // matching iOS, which pins this via .safeAreaInset(edge:
                // .bottom) instead of stacking it above the list at the top.
                // iOS sibling: ContactListView.swift's relayTroubleBanner.
                val relayBannerVisible = (RelayConfig.isTorRequired || viewModel.externalProxyMode) && !isRelayReachable
                // Measured banner height (post clip/background, i.e. the
                // surface only — NOT the floating 40dp gap below it) so the
                // list can reserve exactly enough bottom content padding for
                // the last row to clear it, same purpose as iOS's
                // safeAreaInset automatically growing the ScrollView's
                // content inset by the banner's height.
                var relayBannerHeightPx by remember { mutableStateOf(0) }
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                ) {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(top = 16.dp)
                            .testTag("contact_list"),
                        // Bottom content inset: navigation-bars inset (belt-and-braces
                        // alongside the Scaffold's own contentWindowInsets — every other
                        // screen in this app applies navigationBarsPadding explicitly
                        // rather than relying on it) plus a fixed margin, so the LAST
                        // contact/group row can scroll fully clear of the nav bar
                        // instead of landing flush against it — half-visible/hard to
                        // tap once the list exactly fills the screen. While the relay
                        // banner floats above the list, the reserve grows to the
                        // banner's own measured height plus its 40dp floating gap
                        // (see relayTroubleBanner below) so the last row clears the
                        // banner too. iOS sibling fix: ContactListView.swift's
                        // contactsList trailing spacer + safeAreaInset(edge: .bottom)
                        // for relayTroubleBanner.
                        contentPadding = PaddingValues(
                            bottom = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() +
                                if (relayBannerVisible) {
                                    with(LocalDensity.current) { relayBannerHeightPx.toDp() } + 40.dp
                                } else {
                                    24.dp
                                }
                        ),
                    ) {
                        if (staleContactIds.isNotEmpty()) {
                            item(key = "stale_banner") {
                                RepairBanner(
                                    staleCount = staleContactIds.size,
                                    onTap = onAddContact,
                                )
                            }
                        }
                        items(groups, key = { "group_" + it.groupId }) { group ->
                            GroupRow(
                                group = group,
                                unreadCountsFlow = viewModel.groupUnreadCounts,
                                reachable = rowsEnabled,
                                onClick = {
                                    viewModel.markGroupRead(group.groupId)
                                    onGroupTapped(group.groupId)
                                },
                                onLongClick = { dialog = ContactListDialog.LeaveGroup(group) },
                            )
                        }
                        items(contacts, key = { it.contactId }) { contact ->
                            val stale = staleContactIds.contains(contact.contactId) ||
                                relayLostContacts.contains(contact.contactId)
                            ContactRow(
                                contact = contact,
                                stale = stale,
                                pending = pendingContactIds.contains(contact.contactId),
                                // Resolve the voucher's alias so the row can say who
                                // introduced this contact — the one trust signal that
                                // matters in the transitive-trust model.
                                introducerAlias = contact.vouchedByContactId?.let { vid ->
                                    contacts.firstOrNull { it.contactId == vid }?.alias
                                },
                                // ContactRow collects this itself. Computing the
                                // count here and passing an Int did NOT make the
                                // row react to live /peek updates — LazyColumn
                                // never re-invoked this item lambda (verified via
                                // logs + a11y tree). Subscribing INSIDE the row
                                // gives each composed row its own live collector,
                                // which invalidates the row directly on change.
                                unreadCountsFlow = viewModel.unreadCounts,
                                reachable = rowsEnabled,
                                onClick = {
                                    if (stale) onAddContact()
                                    else {
                                        // Clear the badge the instant they tap in.
                                        viewModel.markContactRead(contact.contactId)
                                        onContactTapped(contact.contactId)
                                    }
                                },
                                onLongClick = { dialog = ContactListDialog.ContactMenu(contact) }
                            )
                        }
                    }

                    // Bottom-anchored relay-trouble banner, floating over the
                    // list rather than pushing it down — same visual language
                    // as iOS's relayTroubleBanner (rounded surface, ~0.92
                    // alpha of the app background, 40dp floating gap above the
                    // nav bar, 16dp horizontal margin from the screen edges).
                    // Shared phase→content decision with the empty-contacts
                    // state above (see relayStatusContent below the composable)
                    // — this used to be a bare torBootstrapStalled/else branch
                    // that silently ignored RelayConnectPhase.Stalled, so once
                    // Tor connected but the relay itself stayed unreachable
                    // past RunViewModel.startRelayStallWatch's self-heal, a
                    // user WITH contacts was stuck on a frozen "Connecting to
                    // Relay… 95%" forever with no Reconnect action.
                    // Also kept on screen while the connection-log panel is
                    // open — the log must not vanish when the relay is reached
                    // only the status content is
                    // gated on reachability.
                    if (relayBannerVisible || showConnectLog) {
                        Box(
                            modifier = Modifier
                                .align(Alignment.BottomCenter)
                                .padding(horizontal = 16.dp)
                                .padding(
                                    bottom = WindowInsets.navigationBars.asPaddingValues()
                                        .calculateBottomPadding() + 40.dp
                                )
                                .onSizeChanged { relayBannerHeightPx = it.height }
                                .clip(RoundedCornerShape(14.dp))
                                .background(RunBlack.copy(alpha = 0.92f))
                                .padding(horizontal = 16.dp, vertical = 12.dp),
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                if (relayBannerVisible && extProxyStatus != RunViewModel.ExternalProxyStatus.OFF) {
                                    ExternalProxyStatusText(
                                        extProxyStatus,
                                        modifier = Modifier.padding(bottom = 6.dp),
                                    )
                                }
                                if (relayBannerVisible) when (relayStatusContent(relayConnectPhase, torBootstrapStalled)) {
                                    RelayStatusContent.RelayStalled -> {
                                        // Self-heal exhausted (mirrors the empty-contacts-
                                        // state Stalled block): honest status + a manual
                                        // Reconnect that rebuilds Tor, instead of an
                                        // endless spinner. Same copy/action as the empty
                                        // state; the two never render at once so reusing
                                        // testTag("relay_reconnect_button") is safe.
                                        Text(
                                            text = stringResource(R.string.connect_relay_stalled),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = RunGrey,
                                            textAlign = TextAlign.Center,
                                        )
                                        Spacer(Modifier.height(10.dp))
                                        Box(
                                            modifier = Modifier
                                                .clip(RoundedCornerShape(24.dp))
                                                .background(RunWhite.copy(alpha = 0.12f))
                                                .clickable(onClick = { viewModel.reconnectRelay() })
                                                .padding(horizontal = 20.dp, vertical = 10.dp)
                                                .testTag("relay_reconnect_button"),
                                        ) {
                                            Text(text = stringResource(R.string.connect_reconnect_button), color = RunWhite)
                                        }
                                    }
                                    RelayStatusContent.TorBootstrapStalled -> {
                                        Text(
                                            text = connectStrings.torStalledHint,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = RunGrey,
                                            textAlign = TextAlign.Center,
                                            modifier = Modifier.testTag("tor_stalled_hint"),
                                        )
                                    }
                                    RelayStatusContent.StatusLine -> {
                                        // Same two-phase status line as the empty-state
                                        // caption above (the e2e "Connecting" XPath that
                                        // used to force these two sites to differ in
                                        // wording is now scoped to the referral dialog —
                                        // see e2e-tests/helpers/Device.ts). Animated dots
                                        // + delayed hint escalation: see the empty-state
                                        // sibling above for the full rationale.
                                        val dotStep = rememberConnectDotsStep()
                                        Text(
                                            text = connectCaptionWithDots(connectStatusLine, dotStep),
                                            style = MaterialTheme.typography.bodyLarge,
                                            color = RunGrey,
                                            textAlign = TextAlign.Center,
                                            // See the empty-state sibling above: additive
                                            // tap recognizer only, testTag untouched.
                                            modifier = Modifier
                                                .testTag("tor_progress_caption")
                                                .tripleTapToggle { showConnectLog = !showConnectLog },
                                        )
                                        val hintStage = rememberConnectHintStage()
                                        if (hintStage > 0) {
                                            Spacer(Modifier.height(4.dp))
                                            // Same up-front "this can take minutes" /
                                            // slow-network hint escalation as the empty
                                            // state (see there).
                                            Text(
                                                text = stringResource(
                                                    if (hintStage == 1) R.string.connect_relay_first_time_hint
                                                    else R.string.connect_relay_slow_hint
                                                ),
                                                style = MaterialTheme.typography.bodySmall,
                                                color = RunGrey,
                                                textAlign = TextAlign.Center,
                                                modifier = Modifier.testTag("connect_relay_hint"),
                                            )
                                        }
                                    }
                                }
                                // Same placement rule as the empty state: directly
                                // under the status content; outlives it once opened
                                // (see the gate above).
                                ConnectionLogPanel(
                                    expanded = showConnectLog,
                                    modifier = Modifier
                                        .padding(top = 8.dp)
                                        .clickable { showConnectLog = false },
                                )
                            }
                        }
                    }
                }
            }
        }

        // Top-right settings cogwheel → dropdown (Add contact / Change pin code / About / Support).
        Box(
            modifier = Modifier
                .align(Alignment.TopEnd)
                .statusBarsPadding()
                .padding(end = 8.dp, top = 4.dp)
        ) {
            IconButton(
                onClick = { settingsMenuExpanded = true },
                modifier = Modifier.testTag("settings_button")
            ) {
                Image(
                    painter = painterResource(id = R.drawable.ic_settings),
                    contentDescription = stringResource(R.string.common_settings),
                    modifier = Modifier.size(24.dp)
                )
            }
            DropdownMenu(
                expanded = settingsMenuExpanded,
                onDismissRequest = { settingsMenuExpanded = false },
                // DropdownMenu renders in a separate Popup composition, which
                // does NOT inherit the root's testTagsAsResourceId — set it here
                // so the menu items are discoverable by Appium via resource-id.
                modifier = Modifier
                    .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
                    .background(RunSurface)
            ) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.add_contact_title), color = if (contactsReady) RunWhite else RunGrey) },
                    onClick = {
                        settingsMenuExpanded = false
                        onAddContact()
                    },
                    // Minting needs the relay; disable until it answers.
                    enabled = contactsReady,
                    modifier = Modifier.testTag("add_contact_button")
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.create_group_title), color = if (contactsReady) RunWhite else RunGrey) },
                    onClick = {
                        settingsMenuExpanded = false
                        onCreateGroup()
                    },
                    // Creating a group mints its inbox and sends the invites over
                    // the relay; disable it until the relay answers, same as
                    // "Add contact" above.
                    enabled = contactsReady,
                    modifier = Modifier.testTag("create_group_menu_button")
                )
                DropdownMenuItem(
                    // Label follows the credential mode (Lever A): the same
                    // route hosts the mode-aware ChangeCredentialScreen.
                    text = {
                        Text(
                            if (viewModel.vaultSelector.isPassphraseMode()) stringResource(R.string.contact_list_change_passphrase)
                            else stringResource(R.string.contact_list_change_pin),
                            color = RunWhite
                        )
                    },
                    onClick = {
                        settingsMenuExpanded = false
                        onChangePin()
                    },
                    modifier = Modifier.testTag("change_pin_button")
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.contact_list_protection_level), color = RunWhite) },
                    onClick = {
                        settingsMenuExpanded = false
                        onProtectionLevel()
                    },
                    modifier = Modifier.testTag("protection_level_menu_button")
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.move_menu_item), color = if (contactsReady) RunWhite else RunGrey) },
                    onClick = {
                        settingsMenuExpanded = false
                        onMoveToNewDevice()
                    },
                    // Relay-dependent row: a row that's tappable while the relay
                    // is unavailable leads to a flow that can only fail or wait,
                    // and the runestone already tells the user the relay isn't
                    // answering — this row follows it. The export needs the
                    // relay for its upload, so gate it like Add contact / Create
                    // group above rather than let it start into a dead wait.
                    enabled = contactsReady,
                    modifier = Modifier.testTag("move_to_new_device_button")
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.contact_list_notifications), color = if (contactsReady) RunWhite else RunGrey) },
                    onClick = {
                        settingsMenuExpanded = false
                        dialog = ContactListDialog.Notifications
                    },
                    // Relay-dependent: push registration (and the opt-out DELETE)
                    // needs the relay; see the rationale comment above "Move".
                    enabled = contactsReady,
                    modifier = Modifier.testTag("menu_notifications")
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.settings_language), color = RunWhite) },
                    onClick = {
                        settingsMenuExpanded = false
                        dialog = ContactListDialog.Language
                    },
                    modifier = Modifier.testTag("menu_language")
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.contact_list_how_it_works), color = RunWhite) },
                    onClick = {
                        settingsMenuExpanded = false
                        dialog = ContactListDialog.About
                    },
                    modifier = Modifier.testTag("menu_about")
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.contact_list_about), color = RunWhite) },
                    onClick = {
                        settingsMenuExpanded = false
                        dialog = ContactListDialog.AboutInfo
                    },
                    modifier = Modifier.testTag("menu_about_info")
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.donate_title), color = RunWhite) },
                    onClick = {
                        settingsMenuExpanded = false
                        dialog = ContactListDialog.Donate
                    },
                    modifier = Modifier.testTag("menu_donate")
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.settings_report_bug), color = if (contactsReady) RunWhite else RunGrey) },
                    onClick = {
                        settingsMenuExpanded = false
                        // Always starts blank — no draft persistence by design
                        // (the draft lives inside ReportBugDialog).
                        dialog = ContactListDialog.ReportBug
                    },
                    // Relay-dependent: the report POSTs to the relay. Gated on
                    // [contactsReady] rather than [relayHandshakeComplete] — the
                    // latter is a monotonic latch that never turns back off once
                    // the relay has answered once, so it would leave this row
                    // enabled after a later relay drop; contactsReady tracks
                    // current reachability, same as the rows above.
                    enabled = contactsReady,
                    modifier = Modifier.testTag("report_bug_menu_item")
                )
                DropdownMenuItem(
                    text = {
                        Text(
                            stringResource(
                                if (debugMode) R.string.settings_debug_mode_on
                                else R.string.settings_debug_mode
                            ),
                            color = RunWhite,
                        )
                    },
                    onClick = {
                        settingsMenuExpanded = false
                        dialog = ContactListDialog.DebugMode
                    },
                    // Not relay-gated: this is a local toggle (redacted log
                    // stream), and it must stay switchable OFF even while the
                    // relay is unavailable.
                    modifier = Modifier.testTag("settings_debug_mode")
                )
                DropdownMenuItem(
                    text = {
                        Text(stringResource(R.string.ext_proxy_title), color = RunWhite)
                    },
                    onClick = {
                        settingsMenuExpanded = false
                        dialog = ContactListDialog.ExtProxy
                    },
                    // Not relay-gated: a user whose proxy is down (relay
                    // unavailable) must still reach this to fix or turn it off.
                    modifier = Modifier.testTag("settings_ext_proxy")
                )
            }
        }

        // Static info modals.
        if (dialog == ContactListDialog.About) {
            AboutModal(onClose = { dialog = null })
        }
        if (dialog == ContactListDialog.Notifications) {
            NotificationSettingsModal(
                viewModel = viewModel,
                onClose = { dialog = null }
            )
        }
        if (dialog == ContactListDialog.Language) {
            LanguagePickerModal(onClose = { dialog = null })
        }
        if (dialog == ContactListDialog.ExtProxy) {
            ExternalProxySettingsModal(viewModel = viewModel, onClose = { dialog = null })
        }
        // Anonymous "Report bug" — text-entry modal (RuneDialog's content
        // slot, matching the mnemonic-edit dialog's BasicTextField chrome
        // above). Dismissible via Cancel/back/tap-outside EXCEPT while a send
        // is in flight, so a background success/failure callback never lands
        // on a screen the user thinks they already left mid-tap. See ReportBugDialog.
        if (dialog == ContactListDialog.ReportBug) {
            ReportBugDialog(
                viewModel = viewModel,
                onClose = { dialog = null },
                onSent = {
                    dialog = null
                    showReportBugThanks = true
                },
            )
        }
        if (showReportBugThanks) {
            ReportBugThanksDialog(onDismiss = { showReportBugThanks = false })
        }
        // Debug mode (Settings → Debug mode) consent gate. Not destructive by
        // RuneDialog.kt's ordering rule (it sends no message content, no
        // names, no identifiers — see the message copy), so it follows the
        // plain "otherwise" order: Cancel first, confirm second, matching
        // every other non-destructive confirm dialog on this screen (e.g.
        // reset_relay_alert above).
        if (dialog == ContactListDialog.DebugMode) {
            DebugModeDialog(debugMode = debugMode, viewModel = viewModel, onClose = { dialog = null })
        }
        // First-open push-notification prompt (onboard_push_prompt_v1, one-shot
        // per vault — see PushPromptOnboarding.kt). Neither button is
        // destructive, so "Yes" (affirmative) takes the safe reflex-tap slot
        // per RuneDialog.kt's ordering rule, "No" the secondary slot.
        if (showPushPrompt) {
            PushPromptDialog(
                onYes = {
                    viewModel.dismissPushPrompt()
                    dialog = ContactListDialog.Notifications
                },
                onNo = { viewModel.dismissPushPrompt() },
            )
        }
        // In-app update nudge Lowest
        // priority of the dialogs — there is no priority queue, so the gate
        // keeps this one deferred behind the push prompt (two true `if`s would
        // stack two Dialog windows). Store button only when the running install came from the
        // Play Store (everyone else gets info-only, no
        // store egress); the info-only OK button REUSES
        // update_nudge_later_button (one e2e selector for both variants — the
        // test phones run sideloaded debug builds, so only that variant can
        // ever render there). Neither action is destructive, but "Open Google
        // Play" is a user-initiated clearnet egress,
        // so — unlike the push prompt above — the SAFE reflex-tap slot is
        // "Later", not the store button.
        val nudgeVersion = showUpdateNudge
        if (nudgeVersion != null && !showPushPrompt) {
            UpdateNudgeDialog(
                isPlayInstall = viewModel.isPlayInstall,
                onLater = { viewModel.dismissUpdateNudge() },
                onOpenStore = {
                    viewModel.dismissUpdateNudge()
                    viewModel.openPlayStoreForUpdate()
                },
            )
        }
        // Privacy-respecting in-app store-review nudge (ReviewPromptPolicy.kt,
        // commonMain — decides WHEN; this is only the Play call). Not a
        // RuneDialog: the ordering rule against the push prompt / update
        // nudge above is already enforced inside RunViewModel.startRelayCheck
        // (ReviewPromptPolicy gates), so `requestReviewFlow` firing true here
        // means "go ahead", no further gating needed. Play In-App Review
        // needs the hosting Activity, not just a Context — see
        // Context.findActivity() (ActivityExt.kt; same walk used for
        // launchBillingFlow). VendorReview is the flavour seam: Play In-App
        // Review in `google`, a no-op in `foss`. Any failure (no Play Services,
        // a non-Play install, no resolvable Activity) silently no-ops — never a
        // custom dialog, never a browser fallback. We only ever cared that the
        // request was MADE, already latched by markReviewPromptShown before this
        // fired; the OS alone decides whether its sheet renders.
        LaunchedEffect(requestReviewFlow) {
            if (requestReviewFlow) {
                viewModel.consumeRequestReviewFlow()
                try {
                    val activity = context.findActivity()
                    if (activity != null) VendorReview.requestReview(context, activity)
                } catch (_: Exception) {
                    // Never let a cosmetic nudge crash the contact list.
                }
            }
        }
        if (dialog == ContactListDialog.AboutInfo) {
            AboutInfoModal(onClose = { dialog = null })
        }
        if (dialog == ContactListDialog.Donate) {
            DonateModal(onClose = { dialog = null })
        }

        // --- Referral / vouching dialogs (referral.md) ---
        (dialog as? ContactListDialog.Introduce)?.from?.let { from ->
            IntroducePickerDialog(
                from = from,
                contacts = contacts,
                isRelayReachable = isRelayReachable,
                onDismiss = { dialog = null },
                onIntroduce = { toIds ->
                    // Fan out on viewModelScope (blocking Tor sends must not
                    // run on the UI thread → ANR).
                    viewModel.startReferralsInBackground(from.contactId, toIds) { allStarted ->
                        // A null result (no transport / invalid) is the only
                        // outcome worth surfacing — a send that started but
                        // failed to deliver is a durable, redriven obligation
                        // core-side, so success never needs a toast here.
                        if (!allStarted) {
                            introduceError = introduceErrorMessage
                        }
                    }
                    dialog = null
                },
            )
        }

        // startReferral returned null for at least one recipient (no transport
        // / invalid pairing) — the picker has already closed, so this is a
        // standalone dismissible alert rather than inline picker content.
        introduceError?.let { msg ->
            IntroduceErrorDialog(message = msg, onDismiss = { introduceError = null })
        }

        referralOffer?.let { offer ->
            // Consent gate — onDismissRequest = null: no back-press / tap-outside.
            RuneDialog(
                onDismissRequest = null,
                testTag = "referral_offer_dialog",
                title = stringResource(R.string.referral_offer_title),
                message = stringResource(R.string.referral_offer_message, offer.introducerAlias, offer.peerAlias),
                actions = listOf(
                    RuneDialogAction(
                    label = when {
                        referralBusy -> stringResource(R.string.referral_connecting)
                        referralAcceptFailed -> stringResource(R.string.common_retry)
                        else -> stringResource(R.string.referral_approve)
                    },
                    enabled = !referralBusy,
                    testTag = "referral_approve",
                    onClick = {
                        val id = offer.introId
                        referralOffer = null
                        referralBusy = true
                        referralAcceptFailed = false
                        // Accept on viewModelScope so a cancel mid-accept can't
                        // silently dead-end the referral (offer removed but never sent).
                        viewModel.acceptReferralOfferInBackground(id) { ok ->
                            referralBusy = false
                            // On failure the offer is still pending; the consent
                            // refresh re-presents it and this flag flips the label to Retry.
                            referralAcceptFailed = !ok
                            viewModel.refreshContactList()
                        }
                    },
                    ),
                    runeSecondary(stringResource(R.string.common_decline), testTag = "referral_decline") {
                        val id = offer.introId
                        declinedIntroId = id
                        referralOffer = null
                        referralAcceptFailed = false
                        // The decline drops vault records, so it runs on IO in the
                        // ViewModel; declinedIntroId keeps the consent refresh from
                        // re-presenting the offer before the drop lands.
                        viewModel.declineReferralOfferInBackground(id) {
                            viewModel.refreshPendingConsent()
                            if (declinedIntroId == id) declinedIntroId = null
                        }
                    },
                ),
            )
        }

        // Introducer-side info modal: an introducee's accept landed on us and
        // was passed on to the other introducee. Simple precedence against the
        // consent gate above — no fancy queueing between the two, just don't
        // show both at once: the offer dialog demands a decision, this one is
        // purely informational and can wait a beat.
        if (referralOffer == null && dialog != ContactListDialog.DebugMode) {
            referralRelayEvents.firstOrNull()?.let { event ->
                val title = if (event.complete) {
                    stringResource(R.string.referral_relayed_complete_title)
                } else {
                    stringResource(R.string.referral_relayed_title)
                }
                val message = when {
                    event.complete -> stringResource(R.string.referral_relayed_complete, event.acceptedByAlias, event.otherAlias)
                    event.relayed -> stringResource(R.string.referral_relayed_first, event.acceptedByAlias, event.otherAlias)
                    else -> stringResource(R.string.referral_relayed_queued, event.acceptedByAlias, event.otherAlias)
                }
                RuneDialog(
                    onDismissRequest = { viewModel.dismissReferralRelayEvent() },
                    testTag = "referral_relayed_dialog",
                    title = title,
                    message = message,
                    actions = listOf(
                        RuneDialogAction(
                            label = stringResource(R.string.common_ok),
                            testTag = "referral_relayed_ok",
                            onClick = { viewModel.dismissReferralRelayEvent() },
                        ),
                    ),
                )
            }
        }

        // GROUP-1 consent gate: join a group only on explicit accept. Joining
        // discloses our group tag to the members, so it
        // must be the user's decision — never automatic.
        groupInvite?.let { inv ->
            // Warn loudly when a DIFFERENT contact than this
            // group's original admin is inviting you (a re-invite eclipse).
            // Bidi-isolate the peer-supplied group name at the
            // interpolation point (see bidiIsolate's kdoc below).
            val isolatedGroupName = bidiIsolate(inv.groupName)
            val body = if (inv.adminMismatch) {
                val prior = inv.priorAdminAlias
                if (prior != null) {
                    stringResource(R.string.contact_list_group_invite_mismatch_with_prior, inv.inviterAlias, isolatedGroupName, prior)
                } else {
                    stringResource(R.string.contact_list_group_invite_mismatch, inv.inviterAlias, isolatedGroupName)
                }
            } else {
                stringResource(R.string.contact_list_group_invite_message, inv.inviterAlias, isolatedGroupName)
            }
            // Consent gate — onDismissRequest = null: no back-press / tap-outside.
            // RuneDialog exposes testTags as resource-ids, so the buttons carry ids
            // now (e2e previously matched these by their "Join"/"Decline" text).
            RuneDialog(
                onDismissRequest = null,
                testTag = "group_invite_dialog",
                title = stringResource(R.string.contact_list_group_invite_title),
                message = body,
                actions = listOf(
                    RuneDialogAction(
                        label = if (groupInviteBusy) stringResource(R.string.contact_list_group_invite_joining) else stringResource(R.string.contact_list_group_invite_join),
                        enabled = !groupInviteBusy,
                        testTag = "group_invite_join",
                        onClick = {
                            val id = inv.groupId
                            groupInvite = null
                            groupInviteBusy = true
                            // Accept on viewModelScope (survives the screen going away).
                            viewModel.runGroupOpInBackground(op = { viewModel.groupManager?.acceptInvite(id) }) {
                                groupInviteBusy = false
                                viewModel.refreshContactList()
                            }
                        },
                    ),
                    runeSecondary(stringResource(R.string.common_decline), testTag = "group_invite_decline") {
                        val id = inv.groupId
                        groupInvite = null
                        groupInviteBusy = true
                        // Mirrors the accept branch above: declineInvite now persists a
                        // decline tombstone (a vault write) via viewModelScope, off the
                        // main thread. groupInviteBusy (reset in onDone) keeps the consent
                        // refresh above from re-presenting this same invite while the
                        // tombstone write is still in flight.
                        viewModel.runGroupOpInBackground(op = { viewModel.groupManager?.declineInvite(id) }) {
                            groupInviteBusy = false
                        }
                    },
                ),
            )
        }


        // Delete confirmation dialog.
        (dialog as? ContactListDialog.DeleteContact)?.c?.let { c ->
            DeleteContactDialog(
                c = c,
                onDismiss = { dialog = null },
                onConfirm = {
                    // Delete off the main thread.
                    val id = c.contactId
                    dialog = null
                    viewModel.deleteContactInBackground(id) { viewModel.refreshContactList() }
                },
            )
        }

        // "Reset relay access" confirmation. Honest copy: this re-keys the
        // relay side only — it cannot un-read anything already taken, which is why
        // it points at delete + re-pair for a phone that really was seized.
        // Identical wording on iOS (ContactListView.swift).
        (dialog as? ContactListDialog.ResetRelayConfirm)?.c?.let { target ->
            // Captured here (not inline below) — resetRelayAccessInBackground's
            // callback runs OUTSIDE composition, where stringResource() cannot
            // be called.
            val resetRelaySuccessText = stringResource(R.string.contact_list_reset_relay_success)
            val resetRelayFailureText = stringResource(R.string.contact_list_reset_relay_failure)
            ResetRelayConfirmDialog(
                alias = target.alias,
                onDismiss = { dialog = null },
                onConfirm = {
                    val id = target.contactId
                    dialog = null
                    // Busy only gates a SECOND reset from the menu while this
                    // one is in flight; the rotation itself is lock-guarded.
                    resetRelayBusy = true
                    viewModel.resetRelayAccessInBackground(id) { ok ->
                        resetRelayBusy = false
                        // Failure copy is literally true: the pending marker is
                        // durable and the poll loop reconciles it.
                        resetRelayResult = if (ok) resetRelaySuccessText else resetRelayFailureText
                    }
                },
            )
        }

        resetRelayResult?.let { msg ->
            ResetRelayResultDialog(message = msg, onDismiss = { resetRelayResult = null })
        }

        // Leave-group confirmation dialog. Honest copy: leaving notifies the
        // other members and deletes the group locally; it cannot recall
        // anything already sent — and a member who has not yet read our texts
        // drops them on arrival once the leave notice removed us from their
        // roster, hence the unread warning paragraph.
        (dialog as? ContactListDialog.LeaveGroup)?.g?.let { g ->
            LeaveGroupDialog(
                g = g,
                onDismiss = { dialog = null },
                onConfirm = {
                    val gid = g.groupId
                    dialog = null
                    // The row disappears the moment the local
                    // delete lands; leave notices keep fanning
                    // out on the ViewModel scope behind it.
                    viewModel.leaveGroupInBackground(gid) { viewModel.refreshContactList() }
                },
            )
        }

        // Long-press context menu. Each hand-off replaces the dialog slot in
        // one assignment; rolling the alias replaces the menu in place (it stays open
        // so the user can tap to cycle names).
        (dialog as? ContactListDialog.ContactMenu)?.c?.let { c ->
            ContactMenuDialog(
                c = c,
                isRelayReachable = isRelayReachable,
                resetRelayBusy = resetRelayBusy,
                onDismiss = { dialog = null },
                onEditMemory = { dialog = ContactListDialog.EditMemory(c) },
                onRemoveMemory = {
                    dialog = null
                    viewModel.saveContactMnemonicInBackground(c.contactId, "") { viewModel.refreshContactList() }
                },
                onRollAlias = {
                    // The vault write runs on IO in the ViewModel; the open menu is
                    // replaced in place once it lands, if it is still this contact's.
                    viewModel.rollContactAliasInBackground(c) { updated ->
                        if ((dialog as? ContactListDialog.ContactMenu)?.c?.contactId == c.contactId) {
                            dialog = ContactListDialog.ContactMenu(updated)
                        }
                        viewModel.refreshContactList()
                    }
                },
                onIntroduce = { dialog = ContactListDialog.Introduce(c) },
                onResetRelay = { dialog = ContactListDialog.ResetRelayConfirm(c) },
                onDelete = { dialog = ContactListDialog.DeleteContact(c) },
            )
        }

        // Personal-memory (mnemonic) view/edit dialog. The memory is the
        // user's PRIVATE reminder of who a contact is — never sent anywhere;
        // it lives only in the vault row. Saving copies the loaded record so
        // the anti-replay counters/epoch are preserved (same rule
        // the iOS saveMnemonic follows).
        (dialog as? ContactListDialog.EditMemory)?.c?.let { c ->
            EditMemoryDialog(
                c = c,
                onDismiss = { dialog = null },
                onSave = { text ->
                    dialog = null
                    viewModel.saveContactMnemonicInBackground(c.contactId, text) { viewModel.refreshContactList() }
                },
                onRemove = {
                    dialog = null
                    viewModel.saveContactMnemonicInBackground(c.contactId, "") { viewModel.refreshContactList() }
                },
            )
        }

        // Invisible tap target over the bottom-right stone — ON TOP of
        // all content so taps aren't absorbed by the Scaffold.
        // 5 taps within 3 seconds opens the debug log viewer.
        // Debug builds only; not shipped in release.
        // Debug-only surface: gate the whole Box (not just the 5-tap action) out
        // of release/beta builds — an always-rendered, always-clickable overlay
        // here blocks taps on the bottom contact row once the list fills the
        // screen, even though the action it triggers was already a no-op.
        if (BuildConfig.DEBUG) {
            var stoneTapCount by remember { mutableIntStateOf(0) }
            var lastStoneTapMs by remember { mutableLongStateOf(0L) }
            var showLogs by remember { mutableStateOf(false) }
            Box(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(bottom = 80.dp)
                    .width(100.dp)
                    .height(120.dp)
                    .clickable(
                        indication = null,
                        interactionSource = remember { MutableInteractionSource() }
                    ) {
                        val now = System.currentTimeMillis()
                        if (now - lastStoneTapMs > 3000) stoneTapCount = 0
                        lastStoneTapMs = now
                        stoneTapCount++
                        if (stoneTapCount >= 5) {
                            stoneTapCount = 0
                            showLogs = true
                        }
                    }
            )

            if (showLogs) {
                Box(modifier = Modifier.fillMaxSize()) {
                    LogViewerScreen(onClose = { showLogs = false })
                }
            }
        }

        // Test-only marker: rowsEnabled (relay reachable AND the lit fade
        // finished) — "the contact list is interactive". The e2e suites tap
        // rows right after this marker appears, so it must never lead them.
        Box(modifier = Modifier.align(Alignment.TopStart)) {
            RunestoneLitMarker(active = rowsEnabled)
        }
    }
}

/**
 * Which content the contacts-present relay-status strip (and, in principle,
 * the empty-contacts state — see ContactListScreen above) should render while
 * `!isRelayReachable`. Priority order (highest first): [RelayStalled] — the
 * self-heal-exhausted case ([RunViewModel.startRelayStallWatch] gave up and
 * set [RunViewModel.RelayConnectPhase.Stalled]) — outranks [TorBootstrapStalled]
 * (Tor itself is still bootstrapping past its own budget, non-terminal),
 * which outranks the default [StatusLine] two-phase caption.
 *
 * Extracted as a pure, device-free decision so the contacts-present strip
 * cannot silently fall out of sync with the empty state again: before this
 * existed, the contacts-present strip only ever checked torBootstrapStalled
 * and had no branch at all for RelayConnectPhase.Stalled, so once Tor
 * connected but the relay stayed unreachable long enough for the self-heal
 * watchdog to exhaust itself, a user WITH contacts was stuck on a frozen
 * "Connecting to Relay… 95%" (the old phase-two curve's 95 cap, since
 * replaced by [BootstrapProgressPacer]) forever, with no Reconnect action —
 * the empty state already handled this via the same
 * [RunViewModel.RelayConnectPhase.Stalled] read.
 *
 * iOS sibling: `ContactListView.swift`'s `relayTroubleBanner` covers the
 * analogous case set for both surfaces, plus `AppState`'s `.relaunchRequired`
 * case, which has no Android equivalent — [RunViewModel.RelayConnectPhase]
 * only defines `Connecting`/`Stalled`.
 */
internal enum class RelayStatusContent { RelayStalled, TorBootstrapStalled, StatusLine }

/**
 * The one user-initiated overlay ContactListScreen shows at a time. Screen state
 * (a remember{} slot), never VM state: the variants hold aliases and memories.
 */
private sealed interface ContactListDialog {
    /** Long-press menu; replaced in place when its alias is re-rolled. */
    data class ContactMenu(val c: ContactListItem) : ContactListDialog
    data class DeleteContact(val c: ContactListItem) : ContactListDialog
    data class ResetRelayConfirm(val c: ContactListItem) : ContactListDialog
    data class EditMemory(val c: ContactListItem) : ContactListDialog
    /** The introduce (referral) recipient picker. */
    data class Introduce(val from: ContactListItem) : ContactListDialog
    data class LeaveGroup(val g: GroupRecord) : ContactListDialog
    data object ReportBug : ContactListDialog
    data object DebugMode : ContactListDialog
    data object About : ContactListDialog
    data object AboutInfo : ContactListDialog
    data object Donate : ContactListDialog
    data object Language : ContactListDialog
    data object Notifications : ContactListDialog
    data object ExtProxy : ContactListDialog
}

/**
 * Anonymous "Report bug" — text-entry modal (RuneDialog's content slot, matching
 * the mnemonic-edit dialog's BasicTextField chrome). Dismissible via
 * Cancel/back/tap-outside EXCEPT while a send is in flight, so a background
 * success/failure callback never lands on a screen the user thinks they already
 * left mid-tap. The draft, in-flight flag and inline error live here: each open
 * starts blank (no draft persistence by design). [onSent] closes it and shows the
 * one-shot thanks dialog.
 */
@Composable
private fun ReportBugDialog(viewModel: RunViewModel, onClose: () -> Unit, onSent: () -> Unit) {
    var reportBugText by remember { mutableStateOf("") }
    var reportBugSending by remember { mutableStateOf(false) }
    var reportBugError by remember { mutableStateOf<String?>(null) }
    // Resolved in composable scope (not inside the onClick lambda
    // below, which isn't @Composable) — same hoisting pattern as
    // resetRelaySuccessText/resetRelayFailureText above.
    val reportBugFailureText = stringResource(R.string.report_bug_failed)
    val dismissReportBug: () -> Unit = onClose
    RuneDialog(
        onDismissRequest = if (reportBugSending) null else dismissReportBug,
        title = stringResource(R.string.report_bug_title),
        content = {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(RunSurfaceAlt)
                    .padding(horizontal = 14.dp, vertical = 12.dp)
            ) {
                if (reportBugText.isEmpty()) {
                    Text(
                        text = stringResource(R.string.report_bug_placeholder),
                        style = MaterialTheme.typography.bodyLarge,
                        color = RunGrey,
                    )
                }
                NoPersonalizedLearning {
                    BasicTextField(
                        value = reportBugText,
                        onValueChange = {
                            reportBugText = if (it.length > BugReportSender.MAX_TEXT_CHARS)
                                it.substring(0, BugReportSender.MAX_TEXT_CHARS) else it
                            reportBugError = null
                        },
                        textStyle = MaterialTheme.typography.bodyLarge.copy(color = RunWhite),
                        cursorBrush = SolidColor(RunWhite),
                        enabled = !reportBugSending,
                        // Password keyboard type = no IME
                        // suggestions / no learning of user prose (text stays
                        // visible, not masked) — the same treatment every other
                        // free-text field in the app already has.
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                        ),
                        minLines = 4,
                        maxLines = 6,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("report_bug_text_field")
                    )
                }
            }
            reportBugError?.let { err ->
                Text(
                    text = err,
                    style = MaterialTheme.typography.bodySmall,
                    color = RuneDanger,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.testTag("report_bug_error"),
                )
            }
        },
        actions = listOf(
            runeSecondary(
                stringResource(R.string.common_cancel),
                testTag = "report_bug_cancel_button",
            ) {
                if (!reportBugSending) onClose()
            },
            RuneDialogAction(
                label = stringResource(R.string.report_bug_send),
                testTag = "report_bug_send_button",
                enabled = reportBugText.isNotBlank() && !reportBugSending,
                onClick = {
                    reportBugSending = true
                    reportBugError = null
                    viewModel.sendBugReportInBackground(reportBugText) { ok ->
                        reportBugSending = false
                        if (ok) {
                            reportBugText = ""
                            onSent()
                        } else {
                            reportBugError = reportBugFailureText
                        }
                    }
                },
            ),
        ),
        testTag = "report_bug_dialog",
    )
}

/** Debug mode (Settings → Debug mode) consent gate; see the call site for the button order. */
@Composable
private fun DebugModeDialog(debugMode: Boolean, viewModel: RunViewModel, onClose: () -> Unit) {
    RuneDialog(
        onDismissRequest = onClose,
        testTag = "debug_mode_dialog",
        title = stringResource(R.string.debug_mode_title),
        message = stringResource(
            if (debugMode) R.string.debug_mode_message_off else R.string.debug_mode_message
        ),
        actions = listOf(
            runeSecondary(
                stringResource(R.string.common_cancel),
                testTag = "debug_mode_cancel",
            ) {
                onClose()
            },
            RuneDialogAction(
                label = stringResource(
                    if (debugMode) R.string.debug_mode_turn_off else R.string.debug_mode_turn_on
                ),
                testTag = "debug_mode_confirm",
                onClick = {
                    onClose()
                    viewModel.setDebugMode(!debugMode)
                },
            ),
        ),
    )
}

/** Delete-contact confirmation (in-tree scrim; `delete_alert` names the scrim). */
@Composable
private fun DeleteContactDialog(c: ContactListItem, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    RuneScrimOverlay(
        onDismiss = onDismiss,
        testTag = "delete_alert",
    ) {
        RuneCardBody {
            RuneDialogTitle(stringResource(R.string.contact_list_delete_confirm_title, c.alias), maxLines = 2)
            RuneDialogMessage(stringResource(R.string.contact_list_delete_confirm_message))
        }
        // Destructive LAST (safety rule, RuneDialog.kt).
        RuneActionRow(listOf(
            runeSecondary(stringResource(R.string.common_cancel), onClick = onDismiss),
            RuneDialogAction(
                label = stringResource(R.string.common_delete),
                color = RuneDanger,
                testTag = "delete_confirm_button",
                onClick = onConfirm,
            ),
        ))
    }
}

/** Leave-group confirmation (in-tree scrim; see the call site for the copy rationale). */
@Composable
private fun LeaveGroupDialog(g: GroupRecord, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    RuneScrimOverlay(
        onDismiss = onDismiss,
        testTag = "leave_group_alert",
    ) {
        RuneCardBody {
            RuneDialogTitle(stringResource(R.string.group_info_leave_confirm_title_android, g.name))
            RuneDialogMessage(
                (if (g.isAdmin)
                    stringResource(R.string.contact_list_leave_group_admin_message_android)
                else
                    stringResource(R.string.group_info_leave_confirm_message))
                    + "\n\n" + stringResource(R.string.group_info_leave_unread_warning)
            )
        }
        // Destructive LAST (safety rule, RuneDialog.kt).
        RuneActionRow(listOf(
            runeSecondary(stringResource(R.string.common_cancel), onClick = onDismiss),
            RuneDialogAction(
                label = stringResource(R.string.group_info_leave_confirm_action),
                color = RuneDanger,
                testTag = "leave_group_confirm_button",
                onClick = onConfirm,
            ),
        ))
    }
}

/**
 * Long-press context menu (in-tree scrim, untagged; the rows carry the menu_* ids).
 * The memory, shown directly with Edit and Remove to its right, then New name,
 * Introduce, Reset relay access and Delete (destructive last).
 */
@Composable
private fun ContactMenuDialog(
    c: ContactListItem,
    isRelayReachable: Boolean,
    resetRelayBusy: Boolean,
    onDismiss: () -> Unit,
    onEditMemory: () -> Unit,
    onRemoveMemory: () -> Unit,
    onRollAlias: () -> Unit,
    onIntroduce: () -> Unit,
    onResetRelay: () -> Unit,
    onDelete: () -> Unit,
) {
    RuneScrimOverlay(
        onDismiss = onDismiss,
        cardModifier = Modifier.padding(36.dp),
    ) {
        Text(
            text = c.alias,
            style = MaterialTheme.typography.titleMedium,
            color = RunWhite,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp),
        )
        // The personal memory, shown directly — with Edit and
        // Remove to its right. (Vault-local; only you see this.)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.contact_list_memory_label),
                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                    color = RunGrey,
                )
                Text(
                    text = c.mnemonic.ifEmpty { stringResource(R.string.contact_list_no_memory_yet) },
                    style = MaterialTheme.typography.bodyLarge.copy(fontSize = 14.sp),
                    color = if (c.mnemonic.isEmpty()) RunGrey else RunWhite,
                    maxLines = 3,
                    modifier = Modifier.testTag("menu_memory_text"),
                )
            }
            Spacer(Modifier.width(12.dp))
            Box(
                modifier = Modifier
                    .testTag("menu_memory")
                    .clip(RoundedCornerShape(8.dp))
                    .background(RunSurfaceAlt)
                    .clickable(onClick = onEditMemory)
                    .padding(horizontal = 14.dp, vertical = 10.dp),
            ) {
                Text(
                    text = if (c.mnemonic.isEmpty()) stringResource(R.string.contact_list_add_memory_button) else stringResource(R.string.contact_list_edit_memory_button),
                    color = RunWhite,
                )
            }
            if (c.mnemonic.isNotEmpty()) {
                Spacer(Modifier.width(8.dp))
                Box(
                    modifier = Modifier
                        .testTag("menu_memory_remove")
                        .clip(RoundedCornerShape(8.dp))
                        .background(RunSurfaceAlt)
                        .clickable(onClick = onRemoveMemory)
                        .padding(horizontal = 14.dp, vertical = 10.dp),
                ) {
                    Text(stringResource(R.string.contact_list_remove_memory_button), color = RuneDanger)
                }
            }
        }
        // Re-roll the vault-local pseudonym. Stays open and updates
        // the title in place so the user can tap to cycle names.
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .testTag("menu_new_name")
                .clip(RoundedCornerShape(8.dp))
                .clickable(onClick = onRollAlias)
                .padding(horizontal = 20.dp, vertical = 14.dp)
        ) {
            Text(stringResource(R.string.contact_list_new_name_button), color = RunWhite)
        }
        // Referral: introduce this contact to another of yours. It is
        // gated on relay reachability exactly like "Reset relay
        // access" below — it is a relay round-trip (two blocking Tor
        // sends), so it must not even open the picker when there is no
        // transport to send over yet.
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .testTag("menu_introduce")
                .clip(RoundedCornerShape(8.dp))
                .clickable(enabled = isRelayReachable, onClick = onIntroduce)
                .padding(horizontal = 20.dp, vertical = 14.dp)
        ) {
            Text(stringResource(R.string.contact_list_introduce_to_button), color = if (isRelayReachable) RunWhite else RunGrey)
        }
        // Re-key this conversation's relay inboxes. NOT destructive
        // (nothing is deleted and the peer is unaffected), so it is styled
        // as an ordinary action — but it IS a relay round-trip, so it is
        // gated on reachability exactly like the add-contact entry point.
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .testTag("menu_reset_relay_access")
                .clip(RoundedCornerShape(8.dp))
                .clickable(enabled = isRelayReachable && !resetRelayBusy, onClick = onResetRelay)
                .padding(horizontal = 20.dp, vertical = 14.dp)
        ) {
            Text(
                if (resetRelayBusy) stringResource(R.string.contact_list_reset_relay_in_progress) else stringResource(R.string.contact_list_reset_relay_button),
                color = if (isRelayReachable && !resetRelayBusy) RunWhite else RunGrey,
            )
        }
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .clickable(onClick = onDelete)
                .padding(horizontal = 20.dp, vertical = 14.dp)
        ) {
            Text(stringResource(R.string.contact_list_delete_contact_button), color = RuneDanger)
        }
    }
}

/**
 * Personal-memory (mnemonic) edit dialog: in-tree scrim (`mnemonic_alert`), the
 * card swallows taps so typing never dismisses it. The draft lives here, seeded
 * from the contact's current memory each time the dialog opens for a contact.
 */
@Composable
private fun EditMemoryDialog(
    c: ContactListItem,
    onDismiss: () -> Unit,
    onSave: (String) -> Unit,
    onRemove: () -> Unit,
) {
    var mnemonicEditText by remember(c.contactId) { mutableStateOf(c.mnemonic) }
    RuneScrimOverlay(
        onDismiss = onDismiss,
        testTag = "mnemonic_alert",
        imePadding = true,
        cardModifier = Modifier
            .padding(32.dp)
            // Swallow taps so typing doesn't dismiss the dialog.
            .clickable(
                indication = null,
                interactionSource = remember { MutableInteractionSource() }
            ) { },
    ) {
        RuneCardBody {
            RuneDialogTitle(c.alias, maxLines = 1)
            Text(
                text = stringResource(R.string.contact_list_memory_dialog_subtitle),
                style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.sp),
                color = RunGrey,
                textAlign = TextAlign.Center
            )
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(RunSurfaceAlt)
                    .padding(horizontal = 14.dp, vertical = 12.dp)
            ) {
                if (mnemonicEditText.isEmpty()) {
                    Text(
                        text = stringResource(R.string.contact_list_memory_placeholder_android),
                        style = MaterialTheme.typography.bodyLarge,
                        color = RunGrey,
                    )
                }
                // KeyboardType.Password so the IME does NOT
                // learn/sync this private per-contact note (the add-time field
                // sets it too). A cloud-
                // syncing or hostile IME would otherwise capture an identity-
                // revealing note off-device, surviving an app wipe. Password
                // input disables personalized learning; it does NOT mask the
                // text (no PasswordVisualTransformation), so the note stays
                // readable while editing.
                NoPersonalizedLearning {
                    BasicTextField(
                        value = mnemonicEditText,
                        onValueChange = { if (it.length <= 200) mnemonicEditText = it },
                        textStyle = MaterialTheme.typography.bodyLarge.copy(color = RunWhite),
                        cursorBrush = SolidColor(RunWhite),
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password
                        ),
                        maxLines = 3,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("mnemonic_edit_input")
                    )
                }
            }
        }
        // Cancel first, destructive "Remove" LAST (safety rule,
        // RuneDialog.kt) — Save keeps the stable middle slot.
        RuneActionRow(listOfNotNull(
            runeSecondary(stringResource(R.string.common_cancel), onClick = onDismiss),
            RuneDialogAction(
                label = stringResource(R.string.common_save),
                testTag = "mnemonic_save_button",
                onClick = { onSave(mnemonicEditText) },
            ),
            if (c.mnemonic.isNotEmpty())
                RuneDialogAction(
                    label = stringResource(R.string.contact_list_remove_memory_button),
                    color = RuneDanger,
                    testTag = "mnemonic_remove_button",
                    onClick = onRemove,
                )
            else null,
        ))
    }
}

internal fun relayStatusContent(
    relayConnectPhase: RunViewModel.RelayConnectPhase,
    torBootstrapStalled: Boolean,
): RelayStatusContent = when {
    relayConnectPhase == RunViewModel.RelayConnectPhase.Stalled -> RelayStatusContent.RelayStalled
    torBootstrapStalled -> RelayStatusContent.TorBootstrapStalled
    else -> RelayStatusContent.StatusLine
}

/**
 * Which of the three main-screen surfaces the unlocked contact list renders.
 *
 * - [HiddenUntilConnected] — the pre-connect placeholder: runestone + paced
 *   connect caption + connect hint + the (relay-gated) Add-contact button, and
 *   NO rows and NO empty-state copy. Tagged `contact_list_hidden_until_connected`.
 * - [EmptyState] — relay answered, vault genuinely has nothing. Tagged
 *   `empty_contacts_state` (the id the e2e empty-vault probes key on).
 * - [Rows] — relay answered and there is something to show.
 *
 * Pure so the gating decision is JVM-testable ([ContactListRevealTest]) rather
 * than only observable through Compose; same reason [relayStatusContent] above
 * exists. iOS sibling: `ContactListView.swift` makes the identical three-way
 * choice inline in `body` off its own `listRevealed` @State.
 */
internal enum class ContactListSurface { HiddenUntilConnected, EmptyState, Rows }

/**
 * The first-reveal LATCH. Monotone by design: once the relay has answered
 * ONCE in this session the list stays revealed for the rest of it, even if
 * reachability is lost again (stall / grey-out phases). The intent is
 * "not visible until connected", NOT "hidden whenever disconnected" — see the
 * gate comment in ContactListScreen.
 */
internal fun contactListRevealed(alreadyRevealed: Boolean, relayReachable: Boolean): Boolean =
    alreadyRevealed || relayReachable

/**
 * [hasContent] = any contact OR group row (incl. pending/awaiting-inbox and
 * referred rows, which are ordinary contact rows), or null while the
 * session's first contact-list load has not landed. Note the ordering: the
 * reveal gate outranks emptiness, so a fresh vault shows the pre-connect
 * placeholder — never a flash of "no contacts yet" — until the relay answers,
 * and a revealed list stays on the placeholder until the first load lands.
 */
internal fun contactListSurface(revealed: Boolean, hasContent: Boolean?): ContactListSurface = when {
    !revealed || hasContent == null -> ContactListSurface.HiddenUntilConnected
    hasContent -> ContactListSurface.Rows
    else -> ContactListSurface.EmptyState
}

/**
 * Animation clock for `tor_progress_caption`'s trailing dots (2026-09-16
 * redesign: the Tor bootstrap percent no longer renders in this caption at
 * all — it stays available internally via ConnectionLog/telemetry, see
 * RelayConnectHints.connectStatusLine). Steps 0→1→2→0 every 600 ms for as
 * long as this call site stays composed; a plain `if`/`when` branch drop
 * discards the `remember`ed step and cancels the [LaunchedEffect] below, so
 * the cadence restarts clean the next time the branch is entered — no
 * separate "stop" call needed. Shared by both `tor_progress_caption` render
 * sites (empty-contacts state + contacts-present strip) so the cadence can't
 * drift between them. iOS sibling: ContactListView's own dots Timer.
 */
@Composable
private fun rememberConnectDotsStep(): Int {
    var step by remember { mutableIntStateOf(0) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(600)
            step = (step + 1) % 3
        }
    }
    return step
}

/**
 * [statusLine] plus a FIXED 3-glyph dot slot, [dotStep] (0..2) of which are
 * opaque and the rest [Color.Transparent] — reserves the full three-dot width
 * so the caption never resizes as the animation cycles. The un-styled run
 * (the phase text itself, and the visible dots) inherits the host [Text]'s
 * own `color`; only the hidden dots get an explicit transparent [SpanStyle].
 * Kept as ONE [AnnotatedString] rather than a Row of separate Text nodes so
 * `tor_progress_caption`'s own accessibility text stays a stable "…" (three
 * literal characters, always) regardless of animation phase — that is what
 * keeps e2e `getText()` / `contains(text, "Connecting")` lookups on this id
 * unaffected by the animation (no percent digits ever appear here now).
 */
private fun connectCaptionWithDots(statusLine: String, dotStep: Int): AnnotatedString =
    buildAnnotatedString {
        append(statusLine)
        for (i in 0 until 3) {
            if (i <= dotStep) {
                append('.')
            } else {
                withStyle(SpanStyle(color = Color.Transparent)) { append('.') }
            }
        }
    }

/**
 * Escalation clock for the hint line rendered under `tor_progress_caption`:
 * 0 (no hint at all) for the first 10 s, 1
 * ([R.string.connect_relay_first_time_hint]) from 10–30 s, 2
 * ([R.string.connect_relay_slow_hint]) from 30 s on — the slow-network hint
 * REPLACES the first-connection hint, it does not append to it. Resets
 * whenever the call site leaves composition, exactly like
 * [rememberConnectDotsStep] (same branch-drop mechanism). iOS sibling: each
 * ContactListView render site's own hintStage Task-based timer.
 */
@Composable
private fun rememberConnectHintStage(): Int {
    var stage by remember { mutableIntStateOf(0) }
    LaunchedEffect(Unit) {
        delay(10_000)
        stage = 1
        delay(20_000)
        stage = 2
    }
    return stage
}

/**
 * Wraps a peer-supplied string in Unicode bidi isolation (FSI…PDI, U+2068 /
 * U+2069) before it is interpolated into a template sentence.
 * [GroupManager] already strips actual bidi CONTROL characters out of a group
 * name at ingest (ContactAliasGenerator.sanitizeDisplayName), but an ordinary
 * legitimate RTL name (real Arabic/Persian/Hebrew letters, no override
 * needed) still carries inherent strong directionality under the Unicode
 * Bidirectional Algorithm — isolating it keeps the surrounding sentence's own
 * direction (and trailing punctuation/clauses) from being reordered by it.
 * iOS mirrors this in ContactListView.swift.
 */
private fun bidiIsolate(s: String): String = String(Character.toChars(0x2068)) + s + String(Character.toChars(0x2069))

// ---------------------------------------------------------------------------
// ContactRow
// ---------------------------------------------------------------------------


@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ContactRow(
    contact: ContactListItem,
    stale: Boolean,
    pending: Boolean = false,
    introducerAlias: String? = null,
    unreadCountsFlow: StateFlow<Map<String, Int>>,
    reachable: Boolean,
    onClick: () -> Unit,
    onLongClick: () -> Unit = {}
) {
    // Collected INSIDE the row: each composed row owns a live collector, so a
    // /peek update invalidates this row directly. Reading the map in the
    // LazyColumn item lambda did NOT work — that lambda is not re-invoked on a
    // live update; subscribing here recomposes the already-composed row.
    val unreadCounts by unreadCountsFlow.collectAsState()
    val unreadCount = unreadCounts[contact.contactId] ?: 0
    // Captured here (not inline below) — the `.semantics { }` block's lambda
    // is not @Composable, so stringResource() cannot be called inside it.
    val unreadMessagesDescription = stringResource(R.string.contact_list_unread_messages_description)
    // Grey out + disable until `reachable` (= rowsEnabled: relay reachable
    // AND the white R's fade-in complete). The fade is animated; the
    // tap-disable is NOT (it flips the instant `reachable` does, so it lifts
    // the moment AFTER the runestone lights and snaps back the instant
    // reachability is lost — the e2e marker follows the same signal).
    val rowAlpha by animateFloatAsState(
        targetValue = if (reachable) 1f else 0.4f,
        animationSpec = tween(400),
        label = "contactRowAlpha"
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("contact_row_${contact.contactId}")
            .alpha(rowAlpha)
            .combinedClickable(enabled = reachable, onClick = onClick, onLongClick = onLongClick)
            .padding(horizontal = 20.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        ContactAvatar(alias = contact.alias, contactId = contact.contactId)
        Spacer(Modifier.width(16.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = contact.alias,
                style = MaterialTheme.typography.titleMedium,
                color = if (stale) RunGrey else RunWhite,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.testTag("contact_name_${contact.contactId}")
            )
            if (stale) {
                Spacer(Modifier.height(2.dp))
                Text(
                    text = stringResource(R.string.contact_list_repair_required),
                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                    color = RunGrey,
                    modifier = Modifier.testTag("contact_repair_${contact.contactId}"),
                )
            } else if (pending) {
                Spacer(Modifier.height(2.dp))
                Text(
                    text = stringResource(R.string.contact_list_waiting_for_inbox),
                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                    color = RunGrey,
                    modifier = Modifier.testTag("contact_pending_${contact.contactId}"),
                )
            } else if (contact.vouchedByContactId != null) {
                // Informational provenance only — referred contacts are usable
                // immediately (transitive trust), no verification step.
                Spacer(Modifier.height(2.dp))
                Text(
                    text = introducerAlias?.let { stringResource(R.string.contact_list_introduced_by, it) } ?: stringResource(R.string.contact_list_introduced),
                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                    color = RunGrey,
                    modifier = Modifier.testTag("contact_referred_${contact.contactId}"),
                )
            }
        }
        if (stale) {
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(RunSurface)
                    .padding(horizontal = 10.dp, vertical = 4.dp)
                    .testTag("contact_repair_chip_${contact.contactId}"),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = stringResource(R.string.contact_list_repair_chip),
                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                    color = RunWhite,
                )
            }
        } else if (unreadCount > 0) {
            // A big, hard-to-miss unread dot in the app's accent red. It is a
            // bare "●" Text on purpose — NOT a drawn circle/Box: inside the
            // merged clickable contact row, any badge with a background/clip
            // graphicsLayer (or a wrapping Box) is dropped from the
            // accessibility tree, hiding it from BOTH screen readers and the
            // e2e harness (verified exhaustively). A bare Text glyph is the
            // only form that stays a real, queryable, accessible a11y node.
            Text(
                text = "●",
                fontSize = 22.sp,
                color = RunError,
                modifier = Modifier
                    .semantics { contentDescription = unreadMessagesDescription }
                    .testTag("contact_unread_${contact.contactId}")
            )
        }
    }
}

// ---------------------------------------------------------------------------
// GroupRow — one group in the list. Distinguished from contacts by a square
// avatar and a member-count style line.
// ---------------------------------------------------------------------------

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun GroupRow(
    group: GroupRecord,
    unreadCountsFlow: StateFlow<Map<String, Int>>,
    reachable: Boolean,
    onClick: () -> Unit,
    onLongClick: () -> Unit = {}
) {
    val unreadCounts by unreadCountsFlow.collectAsState()
    val unreadCount = unreadCounts[group.groupId] ?: 0
    // Captured here (not inline below) — the `.semantics { }` block's lambda
    // is not @Composable, so stringResource() cannot be called inside it.
    val unreadMessagesDescription = stringResource(R.string.contact_list_unread_messages_description)
    // Same dim+disable treatment as ContactRow — see its comment.
    val rowAlpha by animateFloatAsState(
        targetValue = if (reachable) 1f else 0.4f,
        animationSpec = tween(400),
        label = "groupRowAlpha"
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("group_row_${group.groupId}")
            .alpha(rowAlpha)
            .combinedClickable(enabled = reachable, onClick = onClick, onLongClick = onLongClick)
            .padding(horizontal = 20.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        val color = AvatarColors[group.groupId.hashCode().absoluteValue % AvatarColors.size]
        Box(
            modifier = Modifier
                .size(44.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(color),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = (group.name.firstOrNull()?.uppercaseChar() ?: '?').toString(),
                color = RunWhite,
                fontSize = 18.sp
            )
        }
        Spacer(Modifier.width(16.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = group.name,
                style = MaterialTheme.typography.titleMedium,
                color = RunWhite,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.testTag("group_name_${group.groupId}")
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = if (group.isAdmin) stringResource(R.string.contact_list_group_admin_label) else stringResource(R.string.contact_list_group_label),
                style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                color = RunGrey,
            )
        }
        if (unreadCount > 0) {
            // Same bare "●" accent-red badge as ContactRow (see its note: a bare
            // Text glyph is the only form that stays an accessible/queryable node
            // inside the merged clickable row).
            Text(
                text = "●",
                fontSize = 22.sp,
                color = RunError,
                modifier = Modifier
                    .semantics { contentDescription = unreadMessagesDescription }
                    .testTag("group_unread_${group.groupId}")
            )
        }
    }
}

// ---------------------------------------------------------------------------
// RepairBanner — shown above the list when any contacts have pre-capability
// inbox rows. Tapping opens AddContact so the user can re-pair.
// ---------------------------------------------------------------------------

@Composable
private fun RepairBanner(staleCount: Int, onTap: () -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(RunSurface)
            .clickable(onClick = onTap)
            .testTag("repair_banner")
            .padding(horizontal = 14.dp, vertical = 12.dp),
    ) {
        Text(
            text = pluralStringResource(R.plurals.contact_list_repair_banner, staleCount, staleCount),
            style = MaterialTheme.typography.bodyLarge.copy(fontSize = 13.sp),
            color = RunWhite,
        )
    }
}

// ---------------------------------------------------------------------------
// ContactAvatar
// ---------------------------------------------------------------------------

@Composable
private fun ContactAvatar(alias: String, contactId: String) {
    val color = AvatarColors[contactId.hashCode().absoluteValue % AvatarColors.size]
    val initial = alias.firstOrNull()?.uppercaseChar() ?: '?'

    Box(
        modifier = Modifier
            .size(44.dp)
            .clip(CircleShape)
            .background(color),
        contentAlignment = Alignment.Center
    ) {
        Text(text = initial.toString(), color = RunWhite, fontSize = 18.sp)
    }
}

/** Fade-in of the lit (white R) runestone layer; rows enable when it completes. */
private const val LIT_FADE_MS = 800

// ---------------------------------------------------------------------------
// Dialogs of the contact list body (called at their original tree positions)
// ---------------------------------------------------------------------------

/** One-shot thanks after a successful anonymous bug report. */
@Composable
private fun ReportBugThanksDialog(onDismiss: () -> Unit) {
    RuneDialog(
        onDismissRequest = onDismiss,
        message = stringResource(R.string.report_bug_thanks),
        actions = listOf(
            RuneDialogAction(
                label = stringResource(R.string.common_ok),
                testTag = "report_bug_thanks_ok_button",
                onClick = onDismiss,
            ),
        ),
        testTag = "report_bug_thanks_dialog",
    )
}

/** First-open push-notification prompt (see the call site for the slot order). */
@Composable
private fun PushPromptDialog(onYes: () -> Unit, onNo: () -> Unit) {
    RuneDialog(
        onDismissRequest = null,
        message = stringResource(R.string.push_prompt_message),
        actions = listOf(
            RuneDialogAction(
                label = stringResource(R.string.common_yes),
                testTag = "push_prompt_yes",
                onClick = onYes,
            ),
            runeSecondary(label = stringResource(R.string.common_no), testTag = "push_prompt_no") {
                onNo()
            },
        ),
        testTag = "push_prompt",
    )
}

/**
 * In-app update nudge. Store button only on a Play install; the info-only OK
 * reuses `update_nudge_later_button` (one e2e selector for both variants).
 */
@Composable
private fun UpdateNudgeDialog(isPlayInstall: Boolean, onLater: () -> Unit, onOpenStore: () -> Unit) {
    RuneDialog(
        onDismissRequest = null,
        message = stringResource(R.string.nudge_message),
        messageTestTag = "update_nudge_message",
        actions = if (isPlayInstall) {
            listOf(
                runeSecondary(label = stringResource(R.string.nudge_later), testTag = "update_nudge_later_button") {
                    onLater()
                },
                RuneDialogAction(
                    label = stringResource(R.string.nudge_open_play_store),
                    testTag = "update_nudge_store_button",
                    onClick = onOpenStore,
                ),
            )
        } else {
            listOf(
                RuneDialogAction(
                    label = stringResource(R.string.common_ok),
                    testTag = "update_nudge_later_button",
                    onClick = onLater,
                ),
            )
        },
        testTag = "update_nudge_dialog",
    )
}

/**
 * The introduce picker: introduce [from] to every chosen contact at once.
 * Tap selects, long-press reveals that contact's memory in a FLAG_SECURE
 * dialog, the confirm button hands the chosen ids to [onIntroduce].
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun IntroducePickerDialog(
    from: ContactListItem,
    contacts: List<ContactListItem>,
    isRelayReachable: Boolean,
    onDismiss: () -> Unit,
    onIntroduce: (List<String>) -> Unit,
) {
    val candidates = contacts.filter { it.contactId != from.contactId }
    // Multi-select: introduce `from` to EVERY chosen contact at once.
    // Keyed on `from` so the selection resets each time the picker opens.
    val selected = remember(from.contactId) { mutableStateListOf<String>() }
    // Show the per-contact mnemonic in a FLAG_SECURE-
    // inheriting AlertDialog, NOT a Toast. A Toast is a separate
    // system-owned window that does NOT inherit the Activity's FLAG_SECURE,
    // so the identity-revealing memory note would be capturable by screen
    // recording / screenshots / an accessibility service.
    val mnemonicToShow = remember { mutableStateOf<String?>(null) }
    // Captured here (not inline below) — onLongClick runs OUTSIDE
    // composition, where stringResource() cannot be called.
    val noMemoryYetText = stringResource(R.string.contact_list_no_memory_yet)
    // RuneDialog sets testTagsAsResourceId at its own root (its window is a
    // separate composition that doesn't inherit the Activity root's flag),
    // so introduce_pick_* / introduce_confirm stay visible to Appium.
    RuneDialog(
        onDismissRequest = onDismiss,
        title = stringResource(R.string.referral_introduce_title, from.alias),
        actions = listOf(
            RuneDialogAction(
                // Relay reachability can drop WHILE this dialog is open
                // (the menu-item gate below only covers opening it) — same
                // "Connecting…" label swap referral_approve already uses
                // for the accept side of this same feature.
                label = when {
                    !isRelayReachable -> stringResource(R.string.referral_connecting)
                    selected.isEmpty() -> stringResource(R.string.referral_introduce_button)
                    else -> stringResource(R.string.referral_introduce_button_count, selected.size)
                },
                enabled = selected.isNotEmpty() && isRelayReachable,
                testTag = "introduce_confirm",
                onClick = { onIntroduce(selected.toList()) },
            ),
            runeSecondary(stringResource(R.string.common_cancel)) { onDismiss() },
        ),
    ) {
        Text(
            stringResource(R.string.referral_introduce_body, from.alias),
            color = RunGrey, style = MaterialTheme.typography.bodySmall,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        if (candidates.isEmpty()) {
            Text(stringResource(R.string.referral_no_candidates), color = RunGrey)
        }
        // Scrollable list of centered, toggle-able recipient
        // buttons. Tap selects/deselects; long-press reveals that
        // contact's memory; the confirm button introduces all.
        Column(
            modifier = Modifier
                .heightIn(max = 320.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            candidates.forEach { other ->
                val isSelected = other.contactId in selected
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("introduce_pick_${other.contactId}")
                        .clip(RoundedCornerShape(12.dp))
                        .background(if (isSelected) RunWhite else RunSurface)
                        .combinedClickable(
                            onClick = {
                                if (isSelected) selected.remove(other.contactId)
                                else selected.add(other.contactId)
                            },
                            onLongClick = {
                                // FLAG_SECURE-safe reveal (not a Toast).
                                mnemonicToShow.value =
                                    other.mnemonic.ifEmpty { noMemoryYetText }
                            },
                        )
                        .padding(vertical = 14.dp, horizontal = 16.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        (if (isSelected) "✓  " else "") + other.alias,
                        color = if (isSelected) RunBlack else RunWhite,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    }
    // Mnemonic reveal in a FLAG_SECURE-inheriting dialog.
    mnemonicToShow.value?.let { memo ->
        RuneDialog(
            onDismissRequest = { mnemonicToShow.value = null },
            message = memo,
            actions = listOf(
                RuneDialogAction(label = stringResource(R.string.common_ok), onClick = { mnemonicToShow.value = null }),
            ),
        )
    }
}

/** startReferral failed for at least one recipient (the picker already closed). */
@Composable
private fun IntroduceErrorDialog(message: String, onDismiss: () -> Unit) {
    RuneDialog(
        onDismissRequest = onDismiss,
        testTag = "introduce_error_dialog",
        message = message,
        actions = listOf(
            RuneDialogAction(label = stringResource(R.string.common_ok), onClick = onDismiss),
        ),
    )
}

/**
 * "Reset relay access" confirmation. Honest copy: this re-keys the relay side
 * only — it cannot un-read anything already taken, which is why it points at
 * delete + re-pair for a phone that really was seized. Identical wording on
 * iOS (ContactListView.swift).
 */
@Composable
private fun ResetRelayConfirmDialog(alias: String, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    RuneDialog(
        onDismissRequest = onDismiss,
        testTag = "reset_relay_alert",
        title = stringResource(R.string.contact_list_reset_relay_title),
        message = stringResource(R.string.contact_list_reset_relay_message, alias),
        actions = listOf(
            runeSecondary(stringResource(R.string.common_cancel)) { onDismiss() },
            RuneDialogAction(
                label = stringResource(R.string.contact_list_reset_button),
                testTag = "reset_relay_confirm_button",
                onClick = onConfirm,
            ),
        ),
    )
}

/** The one-line reset-relay result; it arrives after the confirm closed. */
@Composable
private fun ResetRelayResultDialog(message: String, onDismiss: () -> Unit) {
    RuneDialog(
        onDismissRequest = onDismiss,
        testTag = "reset_relay_result",
        message = message,
        actions = listOf(
            RuneDialogAction(
                label = stringResource(R.string.common_ok),
                testTag = "reset_relay_result_ok",
                onClick = onDismiss,
            ),
        ),
    )
}
