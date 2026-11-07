package com.vg.run

import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunWhite
import com.vg.run.ui.theme.SerifFamily
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.graphics.Color

// ---------------------------------------------------------------------------
// AboutInfoModal — the classic "About" box: app name, the runic mark, the
// installed version, and a one-line description. (The swipeable feature/
// privacy carousel lives in AboutModal, surfaced as "How Rún works".)
//
// Static content.
// ---------------------------------------------------------------------------

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun AboutInfoModal(onClose: () -> Unit) {
    var showClearnetConfirm by remember { mutableStateOf(false) }
    val uriHandler = LocalUriHandler.current
    Dialog(
        onDismissRequest = onClose,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                // Separate window — keep the Lever-C idle clock fed while the
                // user is actually reading/tapping in here.
                .keepUnlockedOnInteraction()
                .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
                .testTag("about_info_modal")
                .padding(32.dp)
        ) {
            RuneCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    // Close button — top-right.
                    Box(modifier = Modifier.fillMaxWidth()) {
                        Box(
                            modifier = Modifier
                                .align(Alignment.TopEnd)
                                .size(36.dp)
                                .clip(CircleShape)
                                .clickable(onClick = onClose)
                                .testTag("about_info_close"),
                            contentAlignment = Alignment.Center
                        ) {
                            Text("✕", color = RunGrey, fontSize = 20.sp)
                        }
                    }

                    Text("ᚱ", color = RunWhite, fontFamily = SerifFamily, fontSize = 56.sp)
                    Text(
                        "Rún",
                        color = RunWhite,
                        fontFamily = SerifFamily,
                        fontWeight = FontWeight.Bold,
                        fontSize = 28.sp
                    )
                    Text(
                        stringResource(
                            R.string.about_info_version_label,
                            BuildConfig.VERSION_NAME,
                            BuildConfig.VERSION_CODE,
                        ),
                        color = RunGrey,
                        fontSize = 14.sp,
                        modifier = Modifier.testTag("about_info_version")
                    )
                    Text(
                        stringResource(R.string.about_info_tagline),
                        color = RunWhite,
                        fontSize = 14.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                    Text(
                        stringResource(R.string.about_info_tor_version, AboutContent.torVersion),
                        color = RunGrey,
                        fontSize = 13.sp,
                        modifier = Modifier.testTag("about_info_tor_version")
                    )

                    // Open-source acknowledgements.
                    Text(
                        stringResource(R.string.about_info_open_source_heading),
                        color = RunWhite,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 14.sp,
                        modifier = Modifier.padding(top = 12.dp)
                    )
                    AboutContent.credits.forEach { credit ->
                        Text(
                            "${credit.name} — ${credit.license}",
                            color = RunGrey,
                            fontSize = 12.sp,
                            textAlign = TextAlign.Center
                        )
                    }

                    // Maker — opens the company site in the EXTERNAL browser over the
                    // clearnet (not Tor), which reveals the device IP to the site and
                    // any on-path observer. Gate behind an explicit confirmation so a
                    // Tor-messenger user isn't one accidental tap from a clearnet
                    // IP↔Rún correlation.
                    Text(
                        "Vikstrom Group AB",
                        color = RunWhite,
                        fontSize = 14.sp,
                        modifier = Modifier.padding(top = 18.dp)
                    )
                    Text(
                        "vgab.eu ↗",
                        color = Color(0xFFDBB575),
                        fontFamily = SerifFamily,
                        fontSize = 14.sp,
                        modifier = Modifier
                            .clickable { showClearnetConfirm = true }
                            .testTag("about_info_website")
                    )
                }
            }
        }
    }

    if (showClearnetConfirm) {
        RuneDialog(
            onDismissRequest = { showClearnetConfirm = false },
            title = stringResource(R.string.about_info_clearnet_title),
            message = stringResource(R.string.about_info_clearnet_message),
            actions = listOf(
                RuneDialogAction(
                    label = stringResource(R.string.common_open),
                    testTag = "clearnet_open_confirm",
                    onClick = {
                        showClearnetConfirm = false
                        uriHandler.openUri("https://vgab.eu")
                    },
                ),
                runeSecondary(stringResource(R.string.common_cancel)) { showClearnetConfirm = false },
            ),
        )
    }
}
