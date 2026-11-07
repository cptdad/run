package com.vg.run

import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * UI tests for [AboutModal] and [DonateModal].
 *
 * These cover the testTag contract relied on by the e2e suite and verify the
 * static behaviour of each modal. Both modals render their copy from
 * AboutContent / DonateContent (commonMain), so the tests assert structure and
 * interaction rather than re-checking the exact strings.
 */
class AboutDonateModalTest {

    @Rule
    @JvmField
    val composeRule = createComposeRule()

    // --- AboutModal -------------------------------------------------------

    @Test
    fun about_modal_rendersPagerAndClose() {
        composeRule.setContent { AboutModalContent(onClose = {}) }

        composeRule.onNodeWithTag("about_modal").assertExists()
        composeRule.onNodeWithTag("about_pager").assertExists()
        composeRule.onNodeWithTag("about_close").assertExists()
    }

    @Test
    fun about_modal_firstPageShowsFirstTitle() {
        composeRule.setContent { AboutModalContent(onClose = {}) }

        // The first About page's title must be visible on open.
        composeRule.onNodeWithText(AboutContent.pages.first().title).assertExists()
    }

    @Test
    fun about_close_invokesCallback() {
        var closed = false
        composeRule.setContent { AboutModalContent(onClose = { closed = true }) }

        composeRule.onNodeWithTag("about_close").performClick()
        composeRule.waitForIdle()
        assertTrue("about_close should invoke onClose", closed)
    }

    // --- DonateModal ------------------------------------------------------

    @Test
    fun donate_modal_hasTipAndCryptoTabs_tipDefault() {
        composeRule.setContent { DonateModalContent(onClose = {}) }

        composeRule.onNodeWithTag("donate_modal").assertExists()
        composeRule.onNodeWithTag("donate_close").assertExists()

        if (VendorBilling.isSupported) {
            // google: two top-level tabs; Tip is the default so the Play jar shows on open.
            composeRule.onNodeWithTag("donate_seg_tip").assertExists()
            composeRule.onNodeWithTag("donate_seg_crypto").assertExists()
            // The tip body renders regardless of whether Play has products wired
            // (loading / tiers / unavailable resolve asynchronously).
            composeRule.onNodeWithTag("tip_jar_body").assertExists()
            // Crypto content is behind its tab — not shown until selected.
            composeRule.onNodeWithTag("donate_crypto_body").assertDoesNotExist()
        } else {
            // Billing unsupported (dead branch since the 2026-08-04 collapse;
            // kept for a future zero-Google build): no Tip tab, crypto direct.
            composeRule.onNodeWithTag("donate_seg_tip").assertDoesNotExist()
            composeRule.onNodeWithTag("tip_jar_body").assertDoesNotExist()
            composeRule.onNodeWithTag("donate_crypto_body").assertExists()
        }
    }

    @Test
    fun donate_cryptoTab_showsRealAddressesWithQrAndCopy() {
        composeRule.setContent { DonateModalContent(onClose = {}) }

        // With billing, crypto sits behind a tab; without it, it shows directly.
        if (VendorBilling.isSupported) {
            composeRule.onNodeWithTag("donate_seg_crypto").performClick()
            composeRule.waitForIdle()
        }

        // Crypto tab is up with exactly the two real methods — Lightning was
        // removed as a choice (2026-08-25).
        composeRule.onNodeWithTag("donate_crypto_body").assertExists()
        composeRule.onNodeWithTag("donate_seg_monero").assertExists()
        composeRule.onNodeWithTag("donate_seg_bitcoin").assertExists()
        composeRule.onNodeWithTag("donate_seg_lightning").assertDoesNotExist()

        val monero = DonateContent.methods.first { it.id == "monero" }
        val bitcoin = DonateContent.methods.first { it.id == "bitcoin" }

        // Monero is selected by default — its verbatim address renders with an
        // enabled Copy pill (the QR Image carries no tag; the address string
        // feeding it is what DonateContentTest pins).
        composeRule.onNodeWithTag("donate_address").assertTextEquals(monero.address)
        composeRule.onNodeWithTag("donate_copy").assertExists()

        // Bitcoin segment swaps in the bitcoin address, Copy still present.
        composeRule.onNodeWithTag("donate_seg_bitcoin").performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("donate_address").assertTextEquals(bitcoin.address)
        composeRule.onNodeWithTag("donate_copy").assertExists()
    }

    @Test
    fun donate_close_invokesCallback() {
        var closed = false
        composeRule.setContent { DonateModalContent(onClose = { closed = true }) }

        composeRule.onNodeWithTag("donate_close").performClick()
        composeRule.waitForIdle()
        assertTrue("donate_close should invoke onClose", closed)
    }
}
