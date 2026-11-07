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
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.toMutableStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vg.run.ui.theme.AvatarColors
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurface
import com.vg.run.ui.theme.RunSurfaceAlt
import com.vg.run.ui.theme.RunWhite
import kotlin.math.absoluteValue
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.text.input.KeyboardType
import com.vg.run.ui.theme.RunError

// ---------------------------------------------------------------------------
// CreateGroupScreen — name a group and pick its members.
//
// Security purpose:
//   • Only contacts with valid capability-protocol inboxes are offered —
//     a stale ("re-pair required") contact could never receive the invite.
//   • The screen states the IRL precondition explicitly: every member must
//     have paired with every other member. The protocol cannot verify this
//     (there are no global identities to check against, by design) — the
//     creator is the accountable party, so the UI says so instead of
//     pretending otherwise.
//   • Group creation is pure fan-out of pairwise invites: nothing about the
//     group is revealed to the relay.
// ---------------------------------------------------------------------------

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun CreateGroupScreen(
    viewModel: RunViewModel,
    onCreated: (String) -> Unit,
    onBack: () -> Unit,
) {
    val vault = viewModel.vault ?: return

    // getAllContacts() returns full ContactRecords, each carrying
    // a raw 32-byte sharedSecret (the legacy static-envelope key pre-image). This
    // screen only ever reads contactId/alias, so project to the secret-free
    // ContactListItem and wipe every source record's secret before it goes out of
    // scope — never retain ContactRecord itself in remember state. Mirrors
    // ContactListScreen.kt's `toListItem()` pattern / ContactListItem.kt.
    val eligibleContacts = remember {
        // Fully paired only: a pending contact (awaiting their inbox) can't
        // receive the invite; a stale one can't be messaged at all.
        // Wipe the UNFILTERED source list — the filtered-out
        // (not-yet-paired) records still carry a live sharedSecret and were
        // previously left un-zeroed.
        val allRecords = vault.getAllContacts()
        val records = allRecords.filter { contactFullyPaired(vault, it.contactId) }
        val projected = records.map { it.toListItem() }
        allRecords.forEach { it.sharedSecret.secureWipe() }
        projected
    }
    val selectedIds = remember { mutableListOf<String>().toMutableStateList() }
    var groupName by remember { mutableStateOf("") }
    var creating by remember { mutableStateOf(false) }
    var createFailed by remember { mutableStateOf(false) }

    val canCreate = groupName.isNotBlank() && selectedIds.isNotEmpty() &&
        !creating && viewModel.messageManager != null

    Column(
        modifier = Modifier
            .fillMaxSize()
            .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
            .testTag("create_group_view")
            .background(RunBlack)
            .navigationBarsPadding()
            // Keep the Create button above the soft keyboard while the name
            // field is focused (caught by groups.spec.ts on device).
            .imePadding()
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
                    .testTag("create_group_back")
            )
            Spacer(Modifier.width(8.dp))
            Text(
                text = stringResource(R.string.create_group_title),
                style = MaterialTheme.typography.titleMedium,
                color = RunWhite,
            )
        }

        // Group name input.
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(RunSurfaceAlt)
                .padding(horizontal = 16.dp, vertical = 12.dp)
        ) {
            if (groupName.isEmpty()) {
                Text(stringResource(R.string.create_group_name_placeholder), style = MaterialTheme.typography.bodyLarge, color = RunGrey)
            }
            NoPersonalizedLearning {
                BasicTextField(
                    value = groupName,
                    onValueChange = { if (it.length <= GroupManager.MAX_GROUP_NAME_CHARS) groupName = it },
                    textStyle = MaterialTheme.typography.bodyLarge.copy(color = RunWhite),
                    cursorBrush = SolidColor(RunWhite),
                    // KeyboardType.Password so the IME doesn't learn/sync
                    // the group name (can name a real-world circle).
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password
                    ),
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("group_name_input")
                )
            }
        }

        // The IRL trust precondition — stated, because it cannot be enforced.
        Text(
            text = stringResource(R.string.create_group_precondition),
            style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.sp),
            color = RunGrey,
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp)
        )

        // Member picker.
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .testTag("group_member_list")
        ) {
            items(eligibleContacts, key = { it.contactId }) { contact ->
                val selected = contact.contactId in selectedIds
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            if (selected) selectedIds.remove(contact.contactId)
                            else if (selectedIds.size + 2 <= GroupManager.MAX_GROUP_MEMBERS) {
                                selectedIds.add(contact.contactId)
                            }
                        }
                        .padding(horizontal = 20.dp, vertical = 12.dp)
                        .testTag("group_member_row_${contact.contactId}"),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    val color = AvatarColors[contact.contactId.hashCode().absoluteValue % AvatarColors.size]
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .clip(CircleShape)
                            .background(color),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = (contact.alias.firstOrNull()?.uppercaseChar() ?: '?').toString(),
                            color = RunWhite,
                            fontSize = 16.sp
                        )
                    }
                    Spacer(Modifier.width(14.dp))
                    Text(
                        text = contact.alias,
                        style = MaterialTheme.typography.titleMedium,
                        color = RunWhite,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    Box(
                        modifier = Modifier
                            .size(22.dp)
                            .clip(CircleShape)
                            .background(if (selected) RunWhite else RunSurfaceAlt),
                        contentAlignment = Alignment.Center
                    ) {
                        if (selected) {
                            Text("✓", color = RunBlack, fontSize = 13.sp)
                        }
                    }
                }
            }
        }

        if (createFailed) {
            Text(
                text = stringResource(R.string.create_group_failed),
                style = MaterialTheme.typography.bodySmall,
                color = RunError,
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp)
            )
        }

        // Create button.
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(if (canCreate) RunWhite else RunSurfaceAlt)
                .alpha(if (canCreate) 1f else 0.5f)
                .clickable(enabled = canCreate) {
                    creating = true
                    createFailed = false
                    val name = groupName.trim()
                    val members = selectedIds.toList()
                    // Create on viewModelScope so the persist +
                    // invite fan-out (PoW-free pairwise sends with jitter) SURVIVES a
                    // back-out mid-"Creating…". A screen-scoped launch was cancelled on
                    // dispose, leaving a locally-persisted group whose members were
                    // never invited (and onCreated never fired).
                    viewModel.runGroupOpInBackground(
                        op = { viewModel.groupManager?.createGroup(name, members) },
                    ) { groupId ->
                        creating = false
                        if (groupId != null) onCreated(groupId) else createFailed = true
                    }
                }
                .padding(vertical = 14.dp)
                .testTag("create_group_button"),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = when {
                    creating -> stringResource(R.string.create_group_creating)
                    selectedIds.isEmpty() -> stringResource(R.string.create_group_select_members)
                    else -> stringResource(R.string.create_group_button_label, selectedIds.size + 1)
                },
                color = if (canCreate) RunBlack else RunGrey,
                style = MaterialTheme.typography.titleMedium
            )
        }
    }
}
