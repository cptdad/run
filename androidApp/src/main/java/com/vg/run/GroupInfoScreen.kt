package com.vg.run

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vg.run.ui.theme.AvatarColors
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunError
import com.vg.run.ui.theme.RuneDanger
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurface
import com.vg.run.ui.theme.RunSurfaceAlt
import com.vg.run.ui.theme.RunWhite
import kotlin.math.absoluteValue
import androidx.compose.ui.ExperimentalComposeUiApi

// ---------------------------------------------------------------------------
// GroupInfoScreen — member list and (for the admin) membership management.
//
// Security framing carried into the UI:
//   • Membership changes are admin-only by protocol (rosters are honored
//     only from the admin's channel) — so the management affordances are
//     simply absent for non-admins rather than disabled-but-promising.
//   • An unresolved member ("Not yet reachable") is shown as such: we hold
//     their memberId but no pairwise tag has bound it to one of our
//     contacts yet, so we can neither send to nor receive from them.
//   • Removal copy is honest: it stops future messages; it cannot recall
//     anything the member already received.
//   • Add-member states the IRL precondition (the newcomer must have paired
//     with every member) — the protocol cannot verify it; the admin vouches.
// ---------------------------------------------------------------------------

private data class MemberDisplay(
    val memberId: String,
    val contactId: String?,
    val alias: String,        // resolved alias, "You", or "Not yet reachable"
    val mnemonic: String,     // the user's PRIVATE memory of who this is ("" if none)
    val isSelf: Boolean,
    val isAdmin: Boolean,
    val resolved: Boolean,
)

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun GroupInfoScreen(
    viewModel: RunViewModel,
    groupId: String,
    onLeft: () -> Unit,
    onBack: () -> Unit,
) {
    val vault = viewModel.vault ?: return
    // Captured here (composable scope) — the "You"/"Not yet reachable" alias
    // fallbacks below run inside a `remember` calculation lambda, which is
    // @DisallowComposableCalls (stringResource can't be called there).
    val youLabel = stringResource(R.string.group_info_you)
    val notYetReachableLabel = stringResource(R.string.group_info_not_reachable)

    // Same fourth FAST control-cadence condition as GroupConversationScreen: this
    // screen is reached only from the group conversation, and on iOS group info is a
    // SHEET over the still-visible conversation, so it is covered there by
    // construction — parity. Its own key, because Compose may dispose the
    // conversation AFTER this screen has composed.
    DisposableEffect(groupId) {
        val screenKey = "info:$groupId"
        viewModel.setGroupConversationForeground(screenKey, open = true)
        onDispose { viewModel.setGroupConversationForeground(screenKey, open = false) }
    }

    var refreshKey by remember { mutableIntStateOf(0) }
    val group = remember(refreshKey) { vault.getGroup(groupId) }
    val members = remember(refreshKey) {
        val g = vault.getGroup(groupId) ?: return@remember emptyList()
        vault.getGroupMembers(groupId).map { m ->
            val isSelf = m.memberId == g.myMemberId
            // getContact() returns a full ContactRecord carrying a raw
            // sharedSecret. Project alias/mnemonic/resolved into locals, THEN wipe —
            // never let the record (or its secret) escape this scope.
            val contact = m.contactId?.let { vault.getContact(it) }
            val resolvedAlias = when {
                isSelf -> youLabel
                contact != null -> contact.alias
                else -> notYetReachableLabel
            }
            val mnemonic = contact?.mnemonic ?: ""
            val resolved = isSelf || contact != null
            contact?.sharedSecret?.secureWipe()
            MemberDisplay(
                memberId = m.memberId,
                contactId = m.contactId,
                alias = resolvedAlias,
                mnemonic = mnemonic,
                isSelf = isSelf,
                isAdmin = m.memberId == g.adminMemberId,
                resolved = resolved,
            )
        }.sortedWith(compareByDescending<MemberDisplay> { it.isSelf }
            .thenByDescending { it.isAdmin }
            .thenBy { it.alias })
    }
    // Contacts that could be added: FULLY paired (sendable) and not a member.
    // getAllContacts() returns full ContactRecords, each carrying
    // a raw 32-byte sharedSecret (the legacy static-envelope key pre-image). Only
    // contactId/alias are read below, so project to the secret-free ContactListItem
    // and wipe every source record's secret before it goes out of scope — never
    // retain ContactRecord itself in remember state. Mirrors ContactListScreen.kt's
    // `toListItem()` pattern / ContactListItem.kt.
    val eligibleToAdd = remember(refreshKey) {
        val memberContactIds = vault.getGroupMembers(groupId).mapNotNull { it.contactId }.toSet()
        // Wipe the UNFILTERED source list — the filtered-out
        // records (the group's own members) still carry a live sharedSecret and
        // were previously left un-zeroed.
        val allRecords = vault.getAllContacts()
        val records = allRecords.filter {
            it.contactId !in memberContactIds && contactFullyPaired(vault, it.contactId)
        }
        val projected = records.map { it.toListItem() }
        allRecords.forEach { it.sharedSecret.secureWipe() }
        projected
    }

    // If we left / were removed, the group row is gone — exit the screen.
    // Run the navigation side-effect in a LaunchedEffect, NOT
    // inline. Calling onLeft() (popBackStack) directly in the composable body fires
    // DURING composition — Navigation-Compose warns against this (can double-pop or
    // re-run on every recomposition). Sibling GroupConversationScreen already does this.
    if (group == null) {
        LaunchedEffect(Unit) { onLeft() }
        return
    }

    var memberAction by remember { mutableStateOf<MemberDisplay?>(null) }
    var showAddPicker by remember { mutableStateOf(false) }
    var showLeaveConfirm by remember { mutableStateOf(false) }
    var makeAdminTarget by remember { mutableStateOf<MemberDisplay?>(null) }
    var showChooseAdmin by remember { mutableStateOf(false) }
    // Shown when transferAdmin returns false (the
    // chosen successor left between the sheet opening and the tap) instead of
    // leaving anyway, which would strand the group with a dead adminMemberId.
    var transferFailed by remember { mutableStateOf(false) }
    var working by remember { mutableStateOf(false) }

    // A roster applied by the background control sweep while this screen is open (admin
    // handed over, member added / removed / resolved) must show without closing and
    // reopening it: poll the shared roster stamp and re-read on a change. Skipped while
    // our own membership op runs (it refreshes when it finishes) and when the vault could
    // not be read. A vanished group re-reads too, which routes to onLeft above.
    val shownStamp by rememberUpdatedState(remember(refreshKey) { groupRosterStamp(vault, groupId) })
    val busy by rememberUpdatedState(working)
    LaunchedEffect(groupId) {
        while (true) {
            kotlinx.coroutines.delay(2_000)
            val now = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) { groupRosterStamp(vault, groupId) }
            if (now != ROSTER_STAMP_UNAVAILABLE && now != shownStamp && !busy) refreshKey++
        }
    }

    /** Runs a blocking membership operation off the main thread, then refreshes the
     *  screen. Guarded so only one runs at a time.
     *  Routed through viewModelScope (via the VM helper) so the
     *  op SURVIVES the user backing out mid-"working" — a screen-scoped launch was
     *  cancelled on dispose, leaving add/remove/transfer-admin roster fan-outs unsent
     *  (a group whose membership diverged silently). */
    fun runMembershipOp(op: () -> Unit) {
        if (working) return
        working = true
        viewModel.runGroupOpInBackground(op = op) {
            working = false
            refreshKey++
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
            .testTag("group_info_view")
            .background(RunBlack)
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
                    .clickable(onClick = onBack)
                    .padding(8.dp)
                    .testTag("group_info_back")
            )
            Spacer(Modifier.width(8.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = group.name,
                    style = MaterialTheme.typography.titleMedium,
                    color = RunWhite,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.testTag("group_info_title")
                )
                Text(
                    text = pluralStringResource(R.plurals.group_info_members, members.size, members.size) +
                        if (group.isAdmin) " · " + stringResource(R.string.group_info_admin_suffix) else "",
                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                    color = RunGrey,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .testTag("group_info_member_list")
        ) {
            if (group.isAdmin) {
                item(key = "add_member") {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .alpha(if (working) 0.4f else 1f)
                            .clickable(enabled = !working) { showAddPicker = true }
                            .padding(horizontal = 20.dp, vertical = 14.dp)
                            .testTag("add_group_member_button"),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .clip(CircleShape)
                                .background(RunSurfaceAlt),
                            contentAlignment = Alignment.Center
                        ) {
                            Text("+", color = RunWhite, fontSize = 20.sp)
                        }
                        Spacer(Modifier.width(14.dp))
                        Text(
                            text = stringResource(R.string.group_info_add_member),
                            style = MaterialTheme.typography.titleMedium,
                            color = RunWhite,
                        )
                    }
                }
            }
            items(members, key = { it.memberId }) { member ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(
                            // Only the admin gets member actions, and never on
                            // their own row (leave is the affordance for that).
                            enabled = group.isAdmin && !member.isSelf && !working
                        ) { memberAction = member }
                        .padding(horizontal = 20.dp, vertical = 12.dp)
                        .testTag("group_member_info_row_${member.memberId}"),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    val seed = member.contactId ?: member.memberId
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .clip(CircleShape)
                            .background(
                                if (member.resolved)
                                    AvatarColors[seed.hashCode().absoluteValue % AvatarColors.size]
                                else RunSurfaceAlt
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = if (member.resolved)
                                (member.alias.firstOrNull()?.uppercaseChar() ?: '?').toString()
                            else "?",
                            color = RunWhite,
                            fontSize = 16.sp
                        )
                    }
                    Spacer(Modifier.width(14.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = member.alias,
                            style = MaterialTheme.typography.titleMedium,
                            color = if (member.resolved) RunWhite else RunGrey,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        if (!member.resolved) {
                            Text(
                                text = stringResource(R.string.group_info_no_verified_pairing),
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                                color = RunGrey,
                            )
                        } else if (member.mnemonic.isNotEmpty()) {
                            // The user's own private memory of who this member
                            // is — vault-local, never sent anywhere; shown here
                            // because aliases are pseudonyms and a group is
                            // exactly where you need to remember who's who.
                            Text(
                                text = member.mnemonic,
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                                color = RunGrey,
                                overflow = TextOverflow.Ellipsis,
                                maxLines = 2,
                                modifier = Modifier.testTag("group_member_mnemonic_${member.memberId}"),
                            )
                        }
                    }
                    if (member.isAdmin) {
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(RunSurface)
                                .padding(horizontal = 10.dp, vertical = 4.dp)
                                .testTag("group_admin_badge_${member.memberId}"),
                        ) {
                            Text(
                                text = stringResource(R.string.group_info_admin_badge),
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                                color = RunWhite,
                            )
                        }
                    }
                }
            }
        }

        // Leave button.
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(RunSurface)
                .clickable(enabled = !working) {
                    // An admin must hand the role to a chosen member before
                    // leaving (else nobody can ever change the member list). Force
                    // the choice when a successor is reachable; otherwise fall
                    // back to the plain confirm.
                    val eligible = members.any { !it.isSelf && it.resolved }
                    if (group.isAdmin && eligible) showChooseAdmin = true
                    else showLeaveConfirm = true
                }
                .padding(vertical = 14.dp)
                .testTag("group_info_leave_button"),
            contentAlignment = Alignment.Center
        ) {
            Text(stringResource(R.string.group_info_leave_group), color = RuneDanger, style = MaterialTheme.typography.titleMedium)
        }
    }

    // ----- Member action dialog (admin only): remove / transfer admin -----
    memberAction?.let { target ->
        RuneScrimOverlay(
            onDismiss = { memberAction = null },
            cardModifier = Modifier.padding(48.dp),
        ) {
            Text(
                text = target.alias,
                style = MaterialTheme.typography.titleMedium,
                color = RunWhite,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(horizontal = 24.dp, vertical = 10.dp)
            )
            // Admin transfer only makes sense to a member we can reach —
            // an unresolved admin could never coordinate the group.
            if (target.resolved) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .clickable {
                            // A group has ONE admin: this hands the role over, so
                            // confirm first (iOS sibling: GroupViews.swift makeAdminTarget).
                            makeAdminTarget = target
                            memberAction = null
                        }
                        .padding(horizontal = 24.dp, vertical = 14.dp)
                        .testTag("member_action_make_admin")
                ) {
                    Text(stringResource(R.string.group_info_make_admin), color = RunWhite)
                }
            }
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .clickable {
                        val id = target.memberId
                        memberAction = null
                        runMembershipOp { viewModel.groupManager?.removeMember(groupId, id) }
                    }
                    .padding(horizontal = 24.dp, vertical = 14.dp)
                    .testTag("member_action_remove")
            ) {
                Text(stringResource(R.string.group_info_remove_from_group), color = RuneDanger)
            }
        }
    }

    // ----- Add-member picker (admin only) -----
    if (showAddPicker) {
        RuneScrimOverlay(
            onDismiss = { showAddPicker = false },
        ) {
            Text(
                text = stringResource(R.string.group_info_add_member),
                style = MaterialTheme.typography.titleMedium,
                color = RunWhite,
                modifier = Modifier.padding(horizontal = 24.dp, vertical = 10.dp)
            )
            Text(
                text = stringResource(R.string.group_info_add_member_precondition),
                style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.sp),
                color = RunGrey,
                modifier = Modifier.padding(horizontal = 24.dp)
            )
            Spacer(Modifier.height(6.dp))
            if (eligibleToAdd.isEmpty()) {
                Text(
                    text = stringResource(R.string.group_info_add_member_empty),
                    style = MaterialTheme.typography.bodyLarge,
                    color = RunGrey,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .padding(24.dp)
                        .testTag("add_member_empty_state")
                )
            } else {
                LazyColumn {
                    items(eligibleToAdd, key = { it.contactId }) { contact ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    val cid = contact.contactId
                                    showAddPicker = false
                                    runMembershipOp { viewModel.groupManager?.addMember(groupId, cid) }
                                }
                                .padding(horizontal = 24.dp, vertical = 12.dp)
                                .testTag("add_member_row_${contact.contactId}"),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = contact.alias,
                                style = MaterialTheme.typography.titleMedium,
                                color = RunWhite,
                            )
                        }
                    }
                }
            }
        }
    }

    // ----- Make-admin confirmation (the role is TRANSFERRED, not shared) -----
    makeAdminTarget?.let { target ->
        RuneScrimOverlay(
            onDismiss = { makeAdminTarget = null },
            testTag = "make_admin_alert",
        ) {
            RuneCardBody {
                RuneDialogTitle(stringResource(
                    R.string.group_info_make_admin_confirm_title,
                    String(Character.toChars(0x2068)) + target.alias + String(Character.toChars(0x2069))))
                RuneDialogMessage(stringResource(R.string.group_info_make_admin_confirm_body))
            }
            RuneActionRow(listOf(
                runeSecondary(stringResource(R.string.common_cancel), testTag = "make_admin_cancel") {
                    makeAdminTarget = null
                },
                RuneDialogAction(
                    label = stringResource(R.string.group_info_make_admin),
                    testTag = "make_admin_confirm",
                    onClick = {
                        val id = target.memberId
                        makeAdminTarget = null
                        runMembershipOp { viewModel.groupManager?.transferAdmin(groupId, id) }
                    },
                ),
            ))
        }
    }

    // ----- Leave confirmation -----
    if (showLeaveConfirm) {
        RuneScrimOverlay(
            onDismiss = { showLeaveConfirm = false },
            testTag = "group_info_leave_alert",
        ) {
            RuneCardBody {
                RuneDialogTitle(stringResource(R.string.group_info_leave_confirm_title_android, group.name))
                // Unread warning appended on every leave path (see ContactListScreen).
                RuneDialogMessage(
                    (if (group.isAdmin)
                        stringResource(R.string.group_info_leave_confirm_admin_message)
                    else
                        stringResource(R.string.group_info_leave_confirm_message))
                        + "\n\n" + stringResource(R.string.group_info_leave_unread_warning)
                )
            }
            // Destructive LAST (safety rule, RuneDialog.kt).
            RuneActionRow(listOf(
                runeSecondary(stringResource(R.string.common_cancel)) { showLeaveConfirm = false },
                RuneDialogAction(
                    label = stringResource(R.string.group_info_leave_confirm_action),
                    color = RuneDanger,
                    testTag = "group_info_leave_confirm",
                    onClick = {
                        showLeaveConfirm = false
                        if (!working) {
                            working = true
                            // Navigate back as soon as the LOCAL delete
                            // lands — the leave notices continue on the
                            // ViewModel scope, which survives this
                            // screen's disposal (a screen-scoped launch
                            // here would cancel them mid-fan-out).
                            viewModel.leaveGroupInBackground(groupId) {
                                working = false
                                onLeft()
                            }
                        }
                    },
                ),
            ))
        }
    }

    // ----- Admin handoff on leave: choose the successor -----
    if (showChooseAdmin) {
        RuneScrimOverlay(
            onDismiss = { showChooseAdmin = false },
            testTag = "choose_admin_dialog",
        ) {
            RuneCardBody {
            Text(
                text = stringResource(R.string.group_info_choose_admin_title),
                style = MaterialTheme.typography.titleMedium,
                color = RunWhite,
            )
            Text(
                text = stringResource(R.string.group_info_choose_admin_subtitle_android),
                style = MaterialTheme.typography.bodySmall,
                color = RunGrey,
            )
            members.filter { !it.isSelf && it.resolved }.forEach { member ->
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .clickable(enabled = !working) {
                            showChooseAdmin = false
                            if (working) return@clickable
                            working = true
                            // Re-read the member list AT TAP TIME —
                            // `members` above is only re-derived when
                            // `refreshKey` changes, so a background-poll
                            // KIND_LEAVE for exactly this member while the
                            // sheet was open would otherwise go unnoticed
                            // and transferAdmin would be attempted (and
                            // fail) anyway.
                            val stillMember = vault.getGroupMembers(groupId)
                                .any { it.memberId == member.memberId }
                            if (!stillMember) {
                                working = false
                                transferFailed = true
                                refreshKey++
                                return@clickable
                            }
                            viewModel.transferAdminThenLeaveInBackground(
                                groupId,
                                member.memberId,
                                onLocalDelete = {
                                    working = false
                                    onLeft()
                                },
                                onTransferFailed = {
                                    working = false
                                    transferFailed = true
                                    refreshKey++
                                },
                            )
                        }
                        .padding(vertical = 10.dp)
                        .testTag("choose_admin_row_${member.memberId}"),
                ) {
                    Column {
                        Text(member.alias, color = RunWhite, style = MaterialTheme.typography.bodyLarge)
                        if (member.mnemonic.isNotEmpty()) {
                            Text(
                                text = member.mnemonic,
                                style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                                color = RunGrey,
                                modifier = Modifier.testTag("choose_admin_mnemonic_${member.memberId}"),
                            )
                        }
                    }
                }
            }
            }
        }
    }

    // ----- Admin handoff failed: transferAdmin returned false, so we did NOT
    // leave (fail-closed — see transferAdminThenLeaveInBackground). Mirrors
    // iOS's `transferFailed` RuneDialog in GroupViews.swift. -----
    if (transferFailed) {
        RuneDialog(
            onDismissRequest = { transferFailed = false },
            title = stringResource(R.string.group_info_transfer_failed_title),
            message = stringResource(R.string.group_info_transfer_failed_message),
            actions = listOf(
                RuneDialogAction(
                    label = stringResource(R.string.common_ok),
                    onClick = { transferFailed = false },
                ),
            ),
            testTag = "group_transfer_failed_dialog",
        )
    }
}
