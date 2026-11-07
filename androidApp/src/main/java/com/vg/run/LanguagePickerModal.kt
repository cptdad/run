package com.vg.run

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurfaceAlt
import com.vg.run.ui.theme.RunWhite
import java.util.Locale

// ---------------------------------------------------------------------------
// LanguagePickerModal — per-app language override (localization plumbing,
// both platforms — see AppLocale.kt). "System default" plus one row per
// AppLocale.SUPPORTED tag, each row labelled in ITS OWN language
// (Locale.forLanguageTag(tag).getDisplayName(that same locale)) so the row
// labels themselves never need translating — only the chrome strings in
// strings_settings.xml do.
//
// Selecting a row applies immediately and dismisses — no separate confirm
// step, same pattern as NotificationSettingsModal's toggles. Static content
// otherwise, so no ViewModel dependency.
// ---------------------------------------------------------------------------

@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
fun LanguagePickerModal(onClose: () -> Unit) {
    val context = LocalContext.current
    val current = AppLocale.current(context)

    fun select(tag: String?) {
        context.findActivity()?.let { AppLocale.apply(it, tag) }
        onClose()
    }

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
                .testTag("language_picker")
                .padding(32.dp)
        ) {
            RuneCard(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Text(
                        stringResource(R.string.settings_language),
                        color = RunWhite,
                        fontWeight = FontWeight.Bold,
                        fontSize = 18.sp,
                        modifier = Modifier.padding(horizontal = 24.dp, vertical = 4.dp)
                    )

                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            // Tall enough for all nine rows (System default + 8
                            // languages) on a 6"-class phone; scrolls on smaller
                            // screens instead of hiding the last rows below the fold.
                            .heightIn(max = 560.dp)
                            .verticalScroll(rememberScrollState())
                    ) {
                        LanguageRow(
                            label = stringResource(R.string.language_option_system),
                            selected = current == null,
                            testTag = "language_option_system",
                            onClick = { select(null) },
                        )
                        AppLocale.SUPPORTED.forEach { tag ->
                            val locale = Locale.forLanguageTag(tag)
                            val label = locale.getDisplayName(locale)
                                .replaceFirstChar { c -> if (c.isLowerCase()) c.titlecase(locale) else c.toString() }
                            LanguageRow(
                                label = label,
                                selected = current == tag,
                                testTag = "language_option_$tag",
                                onClick = { select(tag) },
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LanguageRow(
    label: String,
    selected: Boolean,
    testTag: String,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 24.dp, vertical = 14.dp)
            .testTag(testTag),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            color = if (selected) RunWhite else RunGrey,
            fontSize = 15.sp,
            modifier = Modifier.weight(1f)
        )
        Box(
            modifier = Modifier
                .size(20.dp)
                .clip(CircleShape)
                .background(if (selected) RunWhite else RunSurfaceAlt),
            contentAlignment = Alignment.Center
        ) {
            if (selected) {
                Text("✓", color = RunBlack, fontSize = 11.sp)
            }
        }
    }
}

