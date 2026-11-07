package com.vg.run

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunWhite
import com.vg.run.ui.theme.RuneHairline
import com.vg.run.ui.theme.SerifFamily
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// ---------------------------------------------------------------------------
// "Licences and notices" — the full texts the app is published under, opened
// from the About-info modal (AboutInfoModal.kt). iOS sibling: LicencesView in
// iosApp/iosApp/ContactListView.swift (same file order, same separators).
//
// The four files are COMMITTED byte-for-byte copies of the repo-root files in
// assets/licences/, produced by scripts/sync-licence-bundle.sh and pinned by
// LicenceBundleTest. They are read only when this screen opens (off the main
// thread) — never when the About modal opens (~65 KB of text).
// ---------------------------------------------------------------------------

// Display order. The asset name is the root file's basename (OFL.txt lives
// under assets/fonts/ at the repo root).
internal val LICENCE_BUNDLE_FILES: List<String> = listOf(
    "LICENSE-EXCEPTION",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "OFL.txt",
)

internal const val LICENCE_ASSET_DIR = "licences"

// One file's text, or null if the asset is missing/unreadable (the screen then
// skips it instead of crashing).
private fun readLicenceAsset(context: Context, name: String): String? =
    try {
        context.assets.open("$LICENCE_ASSET_DIR/$name").use { it.readBytes().toString(Charsets.UTF_8) }
    } catch (_: Exception) {
        null
    }

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun LicencesScreen(onClose: () -> Unit) {
    val context = LocalContext.current
    val texts by produceState<List<Pair<String, String>>?>(initialValue = null) {
        value = withContext(Dispatchers.IO) {
            LICENCE_BUNDLE_FILES.mapNotNull { name -> readLicenceAsset(context, name)?.let { name to it } }
        }
    }
    Dialog(
        onDismissRequest = onClose,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(RunBlack)
                // Separate window — keep the Lever-C idle clock fed while reading.
                .keepUnlockedOnInteraction()
                .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
                .testTag("about_info_licences_screen")
                .safeDrawingPadding(),
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 20.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    stringResource(R.string.about_info_licences_title),
                    color = RunWhite,
                    fontFamily = SerifFamily,
                    fontWeight = FontWeight.Bold,
                    fontSize = 20.sp,
                    modifier = Modifier.weight(1f),
                )
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .clickable(onClick = onClose)
                        .testTag("about_info_licences_close"),
                    contentAlignment = Alignment.Center,
                ) {
                    Text("✕", color = RunGrey, fontSize = 20.sp)
                }
            }
            HorizontalDivider(color = RuneHairline)
            SelectionContainer(modifier = Modifier.fillMaxSize()) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    texts.orEmpty().forEachIndexed { i, (name, body) ->
                        if (i > 0) HorizontalDivider(color = RuneHairline, modifier = Modifier.padding(vertical = 8.dp))
                        Text(
                            name,
                            color = RunWhite,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp,
                        )
                        Text(
                            body,
                            color = RunWhite.copy(alpha = 0.85f),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            lineHeight = 15.sp,
                        )
                    }
                }
            }
        }
    }
}
