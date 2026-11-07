package com.vg.run

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunWhite
import androidx.compose.foundation.layout.Row
import androidx.compose.ui.ExperimentalComposeUiApi

// ---------------------------------------------------------------------------
// RecoveryCodeScreen — shows the one-time Lever B recovery code (spec #2) after
// hardware binding is enabled. It is NEVER stored in the clear, so this is the
// only moment the user can save it. A confirm checkbox gates "Continue" so the
// code can't be dismissed by accident.
// ---------------------------------------------------------------------------

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun RecoveryCodeScreen(
    code: String,
    onDone: () -> Unit,
) {
    var acknowledged by remember { mutableStateOf(false) }
    // Tapping Continue before ticking the box used to be a silent no-op (disabled
    // button). Keep the acknowledgment gate, but flash a hint on tap instead.
    var showAckHint by remember { mutableStateOf(false) }
    val grouped = remember(code) { Base32.formatGrouped(code, group = 4, separator = "-") }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
            .background(RunBlack),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .padding(horizontal = 28.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(28.dp))
            Text(
                stringResource(R.string.protection_recovery_code_title),
                style = MaterialTheme.typography.headlineSmall,
                color = RunWhite,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("recovery_code_title"),
            )
            Spacer(Modifier.height(10.dp))
            Text(
                stringResource(R.string.protection_recovery_code_body_android),
                style = MaterialTheme.typography.bodySmall.copy(fontSize = 12.5.sp),
                color = RunGrey,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(22.dp))
            Box(
                Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF14181F), RoundedCornerShape(14.dp))
                    .padding(vertical = 20.dp, horizontal = 16.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    grouped,
                    color = RunWhite,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 17.sp,
                    letterSpacing = 1.5.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.testTag("recovery_code_value"),
                )
            }
            Spacer(Modifier.height(24.dp))
            Row(
                Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center,
            ) {
                Checkbox(
                    checked = acknowledged,
                    onCheckedChange = { acknowledged = it; if (it) showAckHint = false },
                    colors = CheckboxDefaults.colors(checkedColor = Color(0xFFD4463A)),
                    modifier = Modifier.testTag("recovery_ack_checkbox"),
                )
                Text(stringResource(R.string.protection_recovery_ack_label), color = RunWhite, fontSize = 13.sp)
            }
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = { if (acknowledged) onDone() else showAckHint = true },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("recovery_done_button"),
                colors = ButtonDefaults.buttonColors(
                    // Looks gated until acknowledged, but stays tappable so a tap
                    // surfaces the hint below instead of silently doing nothing.
                    containerColor = if (acknowledged) RunWhite else Color(0xFF20262F),
                    contentColor = if (acknowledged) RunBlack else RunGrey,
                ),
            ) {
                // ONE line, never a mid-word break.
                // iOS sibling: ProtectionLevelView.swift's recovery_done_button.
                Text(
                    stringResource(R.string.common_continue),
                    maxLines = 1,
                    softWrap = false,
                    autoSize = TextAutoSize.StepBased(minFontSize = 10.sp, maxFontSize = 16.sp, stepSize = 0.5.sp),
                )
            }
            if (showAckHint && !acknowledged) {
                Spacer(Modifier.height(10.dp))
                Text(
                    stringResource(R.string.protection_recovery_ack_hint_android),
                    color = Color(0xFFD4463A),
                    fontSize = 12.5.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.testTag("recovery_ack_hint"),
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}
