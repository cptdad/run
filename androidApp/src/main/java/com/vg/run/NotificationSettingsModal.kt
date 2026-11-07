package com.vg.run

import android.Manifest
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurface
import com.vg.run.ui.theme.RunWhite
import kotlinx.coroutines.launch

// ---------------------------------------------------------------------------
// NotificationSettingsModal — the Tier-1 background-notification opt-in
// (OFF by default, enabled only with the trade disclosed).
//
// Presented as a short CAROUSEL so the trade is understood before the switch.
// Every education page uses ONE unified shape (NotifEduPage): a prominent
// title, plus — only when the page carries technical depth (`deep != null`)
// — an expandable "Technical details" block for technical users. Page 0 is
// the intro ("Before you turn on notifications…"), a title-only page with no
// expander; the remaining education pages each cover one privacy trade, most
// with a "Technical details" expansion. The final page is the actual on/off
// Switch (bg_notifications_toggle).
//
// THREE STATES, in strict precedence order (the Android WorkManager background
// poll has been removed entirely and is never coming back):
//
//   1. VendorPush.isAvailable  (Play Services present)
//      — the FCM flow. Copy comes from the shared commonMain
//      NotificationEducationContent (same single-source pattern as
//      AboutContent) so Android and iOS carousels stay identical; the switch
//      writes NotificationLevel.VENDOR_PUSH.
//
//   2. else, a UnifiedPush distributor is installed — the same carousel+switch
//      shape, but with the ANDROID-LOCAL UnifiedPushEducationContent (a
//      distributor + its push server are a different, and one-party-larger,
//      trade than FCM, so the copy must not be shared with iOS — see that
//      file's header). The switch writes NotificationLevel.UNIFIED_PUSH.
//      Distributor SELECTION happens here, in the UI layer, because the system
//      picker needs an Activity: saved-or-single →
//      tryUseCurrentOrDefaultDistributor, several installed → tryPickDistributor.
//
//   3. else — no delivery mechanism at all. The page keeps its `notif_unavailable`
//      container tag but is no longer a dead end: it tells the user what to
//      install and links straight to ntfy on F-Droid
//      (notif_no_distributor_install_link).
//
// Precedence is FCM-first deliberately: it needs no extra app, and a user
// with Play Services is not made to install a distributor. There is no
// two-transport picker in v1.
//
// Plus a one-time notif_unregistered_notice line, shown when the distributor
// dropped our registration while the app was closed.
// ---------------------------------------------------------------------------

@OptIn(
    androidx.compose.ui.ExperimentalComposeUiApi::class,
    androidx.compose.foundation.ExperimentalFoundationApi::class,
)
@Composable
fun NotificationSettingsModal(
    viewModel: RunViewModel,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val isFcm = VendorPush.isAvailable(context)
    // Re-probed on every open, never cached across sessions: a distributor is
    // an ordinary app the user can install or remove at any time (same reason
    // VendorPush.isAvailable is re-probed).
    val hasDistributor = remember(isFcm) { !isFcm && UnifiedPushSupport.isAvailable(context) }
    val transport = when {
        isFcm -> NotificationLevel.VENDOR_PUSH
        hasDistributor -> NotificationLevel.UNIFIED_PUSH
        else -> NotificationLevel.OFF
    }
    val canToggle = transport != NotificationLevel.OFF

    var enabled by remember { mutableStateOf(viewModel.isBackgroundNotificationsEnabled()) }
    // registering: a relay round-trip (and, on UnifiedPush, a wait for the
    // distributor to answer) is in flight — the switch is disabled and a
    // spinner shows next to it. registerError: the last enable attempt failed
    // and reverted, so the brief error line shows until the next toggle attempt
    // clears it; registerErrorText carries the cause-specific copy.
    var registering by remember { mutableStateOf(false) }
    var registerError by remember { mutableStateOf(false) }
    // Resolved in composition scope rather than off `context` inside the
    // remember lambda: a `remember {}` body is not @Composable (so
    // `stringResource` cannot be called in it) and `LocalContext.current`
    // resource reads are not configuration-aware (lint
    // LocalContextGetResourceValueCall). The remember stays UNKEYED so this is
    // still only the INITIAL value of the state, exactly as before.
    val genericRegisterErrorText = stringResource(R.string.notif_settings_register_error_generic)
    var registerErrorText by remember { mutableStateOf(genericRegisterErrorText) }

    // One-shot: the distributor dropped us while the app was closed
    // (RunPushService.onUnregistered recorded it). Read ONCE per modal open and
    // consumed in the same breath, so it can never re-appear.
    //
    // Main-thread I/O, deliberately bounded: in the steady state (no notice
    // pending, i.e. always, on every install that never lost a distributor)
    // this is a single SharedPreferences READ and nothing else —
    // [KeyValueStore.remove]'s `contains()` guard means no editor is even
    // opened, so there is no commit() to block on. The one time it does write,
    // it writes one removed key to a file with at most four.
    val unregisteredNotice = remember {
        try { UnifiedPushStateStore(context.applicationContext).consumeUnregisteredNotice() }
        catch (_: Exception) { false }
    }

    // POST_NOTIFICATIONS is a runtime permission on API 33+. Denial is fine:
    // the feature stays enabled but the notification is silently skipped
    // (NotificationHelper checks areNotificationsEnabled) — graceful degradation.
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* result intentionally unused */ }

    val scope = rememberCoroutineScope()

    fun applyLevel(level: NotificationLevel, turningOn: Boolean) {
        scope.launch {
            try {
                val success = viewModel.setBackgroundNotificationsEnabledAwaiting(level)
                // Disabling always reports success (best-effort unregister);
                // enabling reflects whether registration actually landed —
                // on failure the switch must revert to OFF, not stay stuck on.
                enabled = if (turningOn) success else false
                registerError = turningOn && !success
                if (registerError) {
                    registerErrorText = errorCopyFor(context, viewModel.lastPushEnableFailure)
                }
            } finally {
                registering = false
            }
        }
    }

    fun setEnabled(value: Boolean) {
        // Stay defensive against a programmatic toggle even though the switch
        // below is disabled in this state: never write an opt-in flag nothing
        // can act on.
        if (!canToggle) return
        // Permission timing is independent of the relay registration result
        // below — request it right away on enable, same as before.
        if (value && Build.VERSION.SDK_INT >= 33) {
            permissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        registerError = false
        registering = true

        if (!value) {
            // Turning OFF tears down BOTH transports unconditionally
            // (RunViewModel), so it needs no transport argument.
            applyLevel(NotificationLevel.OFF, turningOn = false)
            return
        }
        if (transport == NotificationLevel.VENDOR_PUSH) {
            applyLevel(NotificationLevel.VENDOR_PUSH, turningOn = true)
            return
        }
        // UnifiedPush: a distributor must be SELECTED before it can be asked
        // for an endpoint, and the system picker starts an Activity — which is
        // why selection lives here and not in the ViewModel. One installed (or
        // one already saved) resolves without any UI; several need the picker.
        val activity = context.findActivity()
        // The connector's selection callbacks are not documented to land on any
        // particular thread (tryUseCurrentOrDefaultDistributor may resolve
        // inline, or after a LinkActivity round trip), so EVERY branch hops
        // back through `scope` — a Main-dispatcher scope — before touching
        // Compose state. Writing `enabled`/`registering` from a background
        // thread is the classic silently-wrong recomposition bug.
        val onSelected: (Boolean) -> Unit = { selected ->
            scope.launch {
                if (selected) {
                    applyLevel(NotificationLevel.UNIFIED_PUSH, turningOn = true)
                } else {
                    enabled = false
                    registerError = true
                    // A failed SELECTION is not proof there is no distributor —
                    // re-probe and classify honestly. "Install ntfy" when ntfy
                    // is installed and resolvable sends the user to fix the one
                    // thing that isn't broken (the reproduced 2026-08-11 shape:
                    // a same-process wipe wedged the connector's DB handle, so
                    // saveDistributor threw while getDistributors still listed
                    // ntfy). See PushEnableFailure.forFailedDistributorSelection.
                    registerErrorText = errorCopyFor(
                        context,
                        PushEnableFailure.forFailedDistributorSelection(
                            distributorInstalled = UnifiedPushSupport.isAvailable(context)
                        )
                    )
                    registering = false
                }
            }
        }
        if (UnifiedPushSupport.distributorCount(context) > 1 &&
            !UnifiedPushSupport.hasAcknowledgedDistributor(context)
        ) {
            UnifiedPushSupport.pickDistributor(activity, onSelected)
        } else {
            UnifiedPushSupport.useCurrentOrDefaultDistributor(context, onSelected)
        }
    }

    // Education pages: the SHARED commonMain copy on the FCM path (so this
    // carousel and iOS's PushSettingsView stay word-for-word identical), the
    // Android-local UnifiedPush copy on the distributor path. The
    // no-delivery state renders the single NoDistributorPage below instead.
    val eduPages = when (transport) {
        NotificationLevel.UNIFIED_PUSH -> UnifiedPushEducationContent.pages
        else -> NotificationEducationContent.pages
    }
    val switchTitle = when (transport) {
        NotificationLevel.UNIFIED_PUSH -> UnifiedPushEducationContent.switchTitle(context)
        else -> NotificationEducationContent.switchTitle
    }
    val pageCount = eduPages.size + 1 // education pages (incl. intro) + switch page
    val lastIndex = pageCount - 1
    val pagerState = rememberPagerState(pageCount = { pageCount })

    Dialog(
        onDismissRequest = onClose,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                // Separate window — keep the Lever-C idle clock fed while the
                // user is reading the education pager (60 s on MAXIMUM).
                .keepUnlockedOnInteraction()
                .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
                .testTag("notification_settings_modal")
                .padding(32.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(16.dp))
                    .background(RunSurface.copy(alpha = 0.8f))
                    .padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Box(modifier = Modifier.fillMaxWidth()) {
                    Box(
                        modifier = Modifier
                            .align(Alignment.TopEnd)
                            .size(36.dp)
                            .clip(CircleShape)
                            .clickable(onClick = onClose)
                            .testTag("notification_settings_close"),
                        contentAlignment = Alignment.Center
                    ) {
                        Text("✕", color = RunGrey, fontSize = 20.sp)
                    }
                }

                if (unregisteredNotice) {
                    Text(
                        UnifiedPushEducationContent.unregisteredNotice(context),
                        color = RunGrey,
                        fontSize = 13.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("notif_unregistered_notice"),
                    )
                }

                if (canToggle) {
                HorizontalPager(
                    state = pagerState,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(300.dp),
                    verticalAlignment = Alignment.Top,
                ) { page ->
                    when {
                        page == lastIndex -> SwitchPage(
                            title = switchTitle,
                            enabled = enabled,
                            available = canToggle,
                            registering = registering,
                            showError = registerError,
                            errorText = registerErrorText,
                            onToggle = { setEnabled(it) },
                        )
                        else -> EduPageView(eduPages[page])
                    }
                }

                // Page-position dots.
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center
                ) {
                    repeat(pageCount) { i ->
                        val active = i == pagerState.currentPage
                        Box(
                            modifier = Modifier
                                .padding(horizontal = 3.dp)
                                .size(if (active) 8.dp else 6.dp)
                                .clip(CircleShape)
                                .background(if (active) RunWhite else RunGrey)
                        )
                    }
                }

                // Back / Next navigation. Next is hidden on the last (switch) page.
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (pagerState.currentPage > 0) {
                        Text(
                            stringResource(R.string.notif_settings_carousel_back),
                            color = RunGrey,
                            fontSize = 15.sp,
                            modifier = Modifier
                                .clickable {
                                    scope.launch { pagerState.animateScrollToPage(pagerState.currentPage - 1) }
                                }
                                .testTag("notif_carousel_back")
                                .padding(8.dp)
                        )
                    } else {
                        Spacer(Modifier.width(1.dp))
                    }
                    if (pagerState.currentPage < lastIndex) {
                        Text(
                            stringResource(R.string.notif_settings_carousel_next),
                            color = RunWhite,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 15.sp,
                            modifier = Modifier
                                .clickable {
                                    scope.launch { pagerState.animateScrollToPage(pagerState.currentPage + 1) }
                                }
                                .testTag("notif_carousel_next")
                                .padding(8.dp)
                        )
                    } else {
                        Spacer(Modifier.width(1.dp))
                    }
                }
                } else {
                    NoDistributorPage(context)
                }
            }
        }
    }
}

/**
 * Cause-specific copy for a failed enable. Every branch names something the
 * user can DO — the generic "check your connection" line is actively misleading
 * for a distributor that will never work (VAPID) or one that was never selected.
 */
private fun errorCopyFor(context: Context, failure: PushEnableFailure?): String = when (failure) {
    PushEnableFailure.NO_DISTRIBUTOR ->
        context.getString(R.string.notif_settings_register_error_no_distributor)
    PushEnableFailure.DISTRIBUTOR_SELECTION ->
        context.getString(R.string.notif_settings_register_error_distributor_selection)
    PushEnableFailure.VAPID_UNSUPPORTED ->
        context.getString(R.string.notif_settings_register_error_vapid_unsupported)
    PushEnableFailure.DISTRIBUTOR_REFUSED ->
        context.getString(R.string.notif_settings_register_error_distributor_refused)
    PushEnableFailure.NO_ENDPOINT ->
        context.getString(R.string.notif_settings_register_error_no_endpoint)
    PushEnableFailure.RELAY, null ->
        context.getString(R.string.notif_settings_register_error_generic)
}

/**
 * State 3: no FCM and no distributor installed.
 *
 * Keeps the `notif_unavailable` container tag (the e2e suite keys on it) but
 * replaces the old dead "notification is not available right now" line with
 * something actionable — the whole point of the UnifiedPush tier is that this
 * state is now fixable by the user.
 */
@Composable
private fun NoDistributorPage(context: Context) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("notif_unavailable")
            .padding(vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            UnifiedPushEducationContent.noDistributorMessage(context),
            color = RunGrey,
            fontSize = 15.sp,
            textAlign = TextAlign.Center,
        )
        Text(
            UnifiedPushEducationContent.noDistributorLinkLabel(context),
            color = RunWhite,
            fontSize = 15.sp,
            fontWeight = FontWeight.SemiBold,
            textAlign = TextAlign.Center,
            textDecoration = TextDecoration.Underline,
            modifier = Modifier
                .clickable { openFDroidNtfyListing(context) }
                .testTag("notif_no_distributor_install_link")
                .padding(8.dp),
        )
    }
}

/**
 * Opens the ntfy F-Droid listing in whatever handles it (the F-Droid client if
 * installed, else a browser). `FLAG_ACTIVITY_NEW_TASK` because the launching
 * context may be an application context inside the Dialog's own window; the
 * catch is not defensive dressing — a hardened/de-Googled device may genuinely
 * have no handler for an https VIEW intent, and a settings modal must not crash.
 *
 * Nothing about the user is carried in this intent: it is a constant URL.
 */
private fun openFDroidNtfyListing(context: Context) {
    try {
        context.startActivity(
            Intent(Intent.ACTION_VIEW, Uri.parse(UnifiedPushEducationContent.NTFY_FDROID_URL))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    } catch (_: ActivityNotFoundException) {
        LogBuffer.append("W", "NotifSettings", "no handler for the distributor install link")
    } catch (_: Exception) {
        LogBuffer.append("W", "NotifSettings", "could not open the distributor install link")
    }
}

/**
 * Unified education-page rendering: a prominent title, plus — only when the
 * page carries technical depth (`page.deep != null`) — an expandable
 * "Technical details" block. The intro page and any title-only page (e.g.
 * metadata) render with no expander at all.
 */
@Composable
private fun EduPageView(page: NotifEduPage) {
    var expanded by remember { mutableStateOf(false) }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            page.title,
            color = RunWhite,
            fontWeight = FontWeight.Bold,
            fontSize = 17.sp,
            textAlign = TextAlign.Center,
            modifier = page.disclosureTag?.let { Modifier.testTag(it) } ?: Modifier,
        )
        val deep = page.deep
        if (deep != null) {
            Spacer(Modifier.height(12.dp))
            Row(
                modifier = Modifier
                    .clickable { expanded = !expanded }
                    .testTag("notif_info_expand")
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(if (expanded) "▾  " else "▸  ", color = RunWhite, fontSize = 13.sp)
                Text(
                    stringResource(R.string.notif_settings_technical_details),
                    color = RunWhite,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 13.sp,
                )
            }
            if (expanded) {
                Spacer(Modifier.height(12.dp))
                Text(
                    deep,
                    color = RunGrey,
                    fontSize = 12.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.testTag("notif_info_deep"),
                )
            }
        }
    }
}

@Composable
private fun SwitchPage(
    title: String,
    enabled: Boolean,
    available: Boolean,
    registering: Boolean,
    showError: Boolean,
    errorText: String,
    onToggle: (Boolean) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            title,
            color = RunWhite,
            fontWeight = FontWeight.Bold,
            fontSize = 17.sp,
            textAlign = TextAlign.Center,
        )
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (registering) {
                CircularProgressIndicator(
                    modifier = Modifier
                        .size(20.dp)
                        .padding(end = 8.dp)
                        .testTag("notif_registering_spinner"),
                    color = RunWhite,
                    strokeWidth = 2.dp,
                )
            }
            // Disabled (never interactable) rather than merely a no-op
            // onToggle when unavailable — the switch itself must not claim a
            // capability the build doesn't have (see the intro/info copy).
            // Also disabled while `registering` — the relay round-trip (and,
            // on UnifiedPush, the distributor handshake) is in flight and the
            // switch must not be re-tapped mid-flight (double-registration /
            // lost revert).
            Switch(
                checked = enabled,
                onCheckedChange = onToggle,
                enabled = available && !registering,
                modifier = Modifier.testTag("bg_notifications_toggle")
            )
        }
        if (showError) {
            Text(
                errorText,
                color = RunGrey,
                fontSize = 13.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("notif_register_error"),
            )
        }
        // Sound / vibration / pop-on-screen are the OS's to own, not ours:
        // NotificationHelper only sets a first-run default and never re-imposes
        // it (see its ensureChannel kdoc), so this is the real control surface.
        // Shown whenever alerts are on, since that is when tuning them matters.
        if (enabled) {
            val context = LocalContext.current
            Text(
                stringResource(R.string.notif_settings_sound_row_label),
                color = RunWhite,
                fontSize = 14.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .clickable { NotificationHelper.openChannelSettings(context) }
                    .padding(vertical = 6.dp, horizontal = 12.dp)
                    .testTag("notif_system_settings"),
            )
            Text(
                stringResource(R.string.notif_settings_sound_row_hint),
                color = RunGrey,
                fontSize = 12.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("notif_system_settings_hint"),
            )
        }
    }
}
