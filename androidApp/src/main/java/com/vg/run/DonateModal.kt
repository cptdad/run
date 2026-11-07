package com.vg.run

import android.content.Context
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurface
import com.vg.run.ui.theme.RunSurfaceAlt
import com.vg.run.ui.theme.RunWhite
import com.vg.run.ui.theme.SerifFamily
import kotlinx.coroutines.delay

// ---------------------------------------------------------------------------
// DonateModal — "Support Rún". Two top-level tabs: the Google Play Billing tip
// jar (default) and a Crypto tab that surfaces DonateContent.methods (Monero is
// live; Bitcoin/Lightning are TBA "coming soon").
//
// Play-policy note (why the crypto tab is allowed): it's a 100%-pass-through
// peer-to-peer tip that grants NO digital content or services, which Google
// Play's Payments policy exempts from Play Billing (the tips/contributions
// carve-out — no nonprofit requirement). Keep it that way: the crypto tab must
// never unlock a feature/badge/content, or it would owe Play Billing. Copy and
// addresses come from DonateContent (commonMain). iOS stays tip-only
// (SupportView) by design.
// ---------------------------------------------------------------------------

@Composable
fun DonateModal(onClose: () -> Unit) {
    Dialog(onDismissRequest = onClose) {
        // Separate window — taps here don't reach Activity.onUserInteraction,
        // so without this the Lever-C auto-lock could close the app mid-tip-flow.
        Box(Modifier.keepUnlockedOnInteraction()) {
            DonateModalContent(onClose = onClose)
        }
    }
}

/** Which support method the modal is showing. Tip is the default so Play
 *  Billing stays the prominent path; Crypto is the opt-in alternative. */
private enum class SupportTab { TIP, CRYPTO }

/**
 * The donate body, without the [Dialog] window wrapper, so it can be hosted
 * directly in Compose UI tests (a Dialog renders in a separate window that
 * `createComposeRule` cannot see). At runtime [DonateModal] wraps it in a Dialog.
 */
@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
fun DonateModalContent(onClose: () -> Unit) {
    // VendorBilling.isSupported gates the in-app Tip tab (false ⇒ crypto/Monero
    // only). Always true since the 2026-08-04 flavor collapse; kept as the one
    // seam a future zero-Google build would flip back off.
    val billingSupported = VendorBilling.isSupported
    var tab by remember {
        mutableStateOf(if (billingSupported) SupportTab.TIP else SupportTab.CRYPTO)
    }

    RuneCard(
        modifier = Modifier
            .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
            .testTag("donate_modal"),
        horizontalAlignment = Alignment.CenterHorizontally,
        contentPadding = PaddingValues(24.dp),
    ) {
        // Header with title + close.
        Box(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = stringResource(R.string.donate_title),
                fontFamily = SerifFamily,
                fontWeight = FontWeight.Bold,
                fontSize = 24.sp,
                color = RunWhite,
                textAlign = TextAlign.Center,
                // Keep clear of the 36dp ✕ on the right (and symmetric on the
                // left): longer localized titles ("Rún unterstützen") wrap
                // instead of running under the close button.
                modifier = Modifier
                    .align(Alignment.Center)
                    .padding(horizontal = 44.dp)
            )
            Box(
                modifier = Modifier
                    .align(Alignment.CenterEnd)
                    .size(36.dp)
                    .clip(CircleShape)
                    .clickable(onClick = onClose)
                    .testTag("donate_close"),
                contentAlignment = Alignment.Center
            ) {
                Text("✕", color = RunGrey, fontSize = 18.sp)
            }
        }

        Spacer(Modifier.height(16.dp))

        // Mission line (shared copy).
        Text(
            text = DonateContent.appeal,
            color = RunGrey,
            fontSize = 14.sp,
            lineHeight = 20.sp,
            textAlign = TextAlign.Center
        )

        Spacer(Modifier.height(20.dp))

        // Top-level [Tip] [Crypto] selector — shown only when Play Billing is in
        // this build; without it the selector is dropped and the crypto body
        // renders directly.
        if (billingSupported) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(RunBlack)
                    .padding(4.dp),
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                SupportSegment(
                    label = stringResource(R.string.donate_tab_tip),
                    selected = tab == SupportTab.TIP,
                    testTag = "donate_seg_tip",
                    modifier = Modifier.weight(1f)
                ) { tab = SupportTab.TIP }
                SupportSegment(
                    label = stringResource(R.string.donate_tab_crypto),
                    selected = tab == SupportTab.CRYPTO,
                    testTag = "donate_seg_crypto",
                    modifier = Modifier.weight(1f)
                ) { tab = SupportTab.CRYPTO }
            }

            Spacer(Modifier.height(24.dp))
        }

        when (tab) {
            SupportTab.TIP -> TipJarBody()
            SupportTab.CRYPTO -> CryptoBody()
        }

        // Footer — Play-tip disclosure only (a Play tip is processed by Google,
        // tied to the Google account). The crypto tab carries no footer line
        // (the old "you pay from your own wallet"
        // copy was removed).
        if (tab == SupportTab.TIP) {
            Spacer(Modifier.height(24.dp))
            Text(
                text = stringResource(R.string.donate_play_disclosure),
                color = RunGrey,
                fontSize = 12.sp,
                textAlign = TextAlign.Center
            )
        }
    }
}

/** One pill in a segmented selector (used for both the top [Tip]/[Crypto] tabs
 *  and the crypto method sub-selector). */
@Composable
private fun SupportSegment(
    label: String,
    selected: Boolean,
    testTag: String,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(if (selected) RunSurfaceAlt else Color.Transparent)
            .clickable(onClick = onClick)
            .testTag(testTag)
            .padding(vertical = 10.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            color = if (selected) RunWhite else RunGrey,
            fontSize = 14.sp
        )
    }
}

/** The Crypto tab: a sub-selector over DonateContent.methods (Monero default),
 *  each showing its scannable address or a "coming soon" placeholder. */
@Composable
private fun CryptoBody() {
    val context = LocalContext.current
    val methods = DonateContent.methods
    // Monero is index 0. All methods are TBA placeholders today; the selector
    // and AddressBody below still work unchanged once a real address ships.
    var idx by remember { mutableIntStateOf(0) }

    Column(
        modifier = Modifier.fillMaxWidth().testTag("donate_crypto_body"),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Method sub-selector — one segment per crypto method.
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(10.dp))
                .background(RunBlack)
                .padding(4.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            methods.forEachIndexed { i, method ->
                SupportSegment(
                    label = method.label,
                    selected = i == idx,
                    testTag = "donate_seg_" + method.id,
                    modifier = Modifier.weight(1f)
                ) { idx = i }
            }
        }

        Spacer(Modifier.height(20.dp))

        val selected = methods[idx]
        if (selected.isPlaceholder) {
            PlaceholderBody()
        } else {
            AddressBody(method = selected, context = context)
        }
    }
}

/** Shown while a method's address is still TBA: a "coming soon" line and a
 *  disabled Copy button. */
@Composable
private fun PlaceholderBody() {
    Text(
        text = stringResource(R.string.donate_tba),
        color = RunGrey,
        fontSize = 16.sp,
        textAlign = TextAlign.Center,
        modifier = Modifier.testTag("donate_address")
    )
    Spacer(Modifier.height(16.dp))
    // Disabled Copy — nothing to copy while TBA.
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .background(RunSurfaceAlt.copy(alpha = 0.5f))
            .padding(horizontal = 28.dp, vertical = 10.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(stringResource(R.string.common_copy), color = RunGrey.copy(alpha = 0.5f))
    }
}

/**
 * Real-address branch — reached for a non-placeholder [DonateMethod] (none
 * today; all three crypto methods are TBA). Shows a scannable QR of the
 * address, the address in a mono font, and an enabled Copy button with a
 * "Copied ✓" flash. The QR is rendered via the shared ZXing helper
 * [generateQrBitmap] (AddContactScreen) and encodes the raw address — the
 * form a wallet's "scan address" accepts.
 */
@Composable
private fun AddressBody(method: DonateMethod, context: Context) {
    var copied by remember { mutableStateOf(false) }
    // Tracks whether THIS composable wrote the clipboard, so
    // the dismiss-time clear below knows whether to fire — without needing to read
    // the clipboard back (see the onDispose comment for why that read isn't usable).
    var copiedAddress by remember { mutableStateOf<String?>(null) }
    val qrBitmap = remember(method.address) { generateQrBitmap(method.address, sizePx = 600) }

    // Reset the "Copied ✓" flash after a moment.
    LaunchedEffect(copied) {
        if (copied) {
            delay(1500)
            copied = false
        }
    }

    // Clear the clip when this display goes away (crypto tab switched away from,
    // or the modal closed) rather than on a short timer, so the common
    // paste-into-wallet flow still has time to work. No secret is exposed here — the
    // address is an app-wide constant, identical for every user — but it's a
    // use-artifact that would otherwise outlive the wipe and, on OEM ROMs with
    // persistent clipboard history, land in a filesystem extraction.
    DisposableEffect(Unit) {
        onDispose {
            // Don't gate the clear on a successful
            // primaryClip() read-back. Since Android 10 (minSdk 30 — confirmed
            // in androidApp/build.gradle.kts) getPrimaryClip() returns null for
            // a caller without input focus that isn't the default IME — which
            // is exactly the state this onDispose runs in for the flows that
            // matter: the user switched to their wallet app to paste, or the
            // Activity is being torn down by MainActivity.onStop ->
            // finishAndRemoveTask(). An ownership check that needs the read
            // silently no-ops in both. SensitiveClipboard therefore clears when
            // the clip is still ours OR cannot be read (setPrimaryClip /
            // clearPrimaryClip are writes, not the gated read, so they work
            // without focus), and only when THIS composable copied the address.
            // Trade-off: an unreadable clipboard is cleared even if the user
            // copied something unrelated in another app meanwhile — a clear that
            // actually fires beats a precise one that fails exactly when the
            // flow leaves Rún.
            copiedAddress?.let { SensitiveClipboard.clearIfOursOrUnreadable(context, it) }
        }
    }

    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        // Scannable QR of the address — black-on-white with a quiet-zone pad so
        // another device's wallet camera can read it.
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(10.dp))
                .background(RunWhite)
                .padding(12.dp)
        ) {
            Image(
                bitmap = qrBitmap.asImageBitmap(),
                contentDescription = stringResource(R.string.donate_qr_content_description, method.label),
                modifier = Modifier.size(200.dp)
            )
        }

        Spacer(Modifier.height(16.dp))

        // Address — monospace so it's unambiguous.
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(10.dp))
                .background(RunBlack)
                .padding(12.dp)
        ) {
            Text(
                text = method.address,
                color = RunWhite,
                fontFamily = FontFamily.Monospace,
                fontSize = 13.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("donate_address")
            )
        }

        Spacer(Modifier.height(16.dp))

        // Copy — an enabled pill with a "Copied ✓" flash.
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(8.dp))
                .background(RunSurfaceAlt)
                .clickable {
                    // Sensitive (hidden from the preview overlay, discouraged in
                    // OEM clipboard history); cleared on dismiss by the
                    // DisposableEffect above, not on a timer, so the
                    // paste-into-wallet flow has time to work.
                    SensitiveClipboard.copy(context, method.label + " address", method.address, clearAfterMs = null)
                    copiedAddress = method.address
                    copied = true
                }
                .testTag("donate_copy")
                .padding(horizontal = 28.dp, vertical = 10.dp),
            contentAlignment = Alignment.Center
        ) {
            Text(
                if (copied) stringResource(R.string.donate_copied_confirmation) else stringResource(R.string.common_copy),
                color = RunWhite,
            )
        }
    }
}
