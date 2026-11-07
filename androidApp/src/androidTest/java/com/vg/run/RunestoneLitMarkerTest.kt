package com.vg.run

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import org.junit.Rule
import org.junit.Test

/**
 * Verifies that the runestone_bright_and_lit gate marker reports `active`
 * when the relay is reachable and `inactive` when it is not.
 *
 * This is a unit-level UI test of [RunestoneLitMarker]. The screen-level
 * gating that uses the marker is exercised end-to-end by the e2e suite.
 */
class RunestoneLitMarkerTest {

    @Rule
    @JvmField
    val composeRule = createComposeRule()

    @Test
    fun marker_isInactive_whenRelayUnreachable() {
        composeRule.setContent {
            RunestoneLitMarker(active = false)
        }
        composeRule.onNodeWithTag("runestone_lit_inactive").assertExists()
        composeRule.onNodeWithTag("runestone_lit_active").assertDoesNotExist()
    }

    @Test
    fun marker_isActive_whenRelayReachable() {
        composeRule.setContent {
            RunestoneLitMarker(active = true)
        }
        composeRule.onNodeWithTag("runestone_lit_active").assertExists()
        composeRule.onNodeWithTag("runestone_lit_inactive").assertDoesNotExist()
    }

    @Test
    fun marker_flipsToInactive_whenRelayBecomesUnreachable() {
        var reachable by mutableStateOf(true)
        composeRule.setContent {
            RunestoneLitMarker(active = reachable)
        }
        composeRule.onNodeWithTag("runestone_lit_active").assertExists()

        composeRule.runOnIdle { reachable = false }
        composeRule.waitForIdle()

        composeRule.onNodeWithTag("runestone_lit_inactive").assertExists()
        composeRule.onNodeWithTag("runestone_lit_active").assertDoesNotExist()
    }

    @Test
    fun marker_flipsToActive_whenRelayBecomesReachable() {
        var reachable by mutableStateOf(false)
        composeRule.setContent {
            RunestoneLitMarker(active = reachable)
        }
        composeRule.onNodeWithTag("runestone_lit_inactive").assertExists()

        composeRule.runOnIdle { reachable = true }
        composeRule.waitForIdle()

        composeRule.onNodeWithTag("runestone_lit_active").assertExists()
        composeRule.onNodeWithTag("runestone_lit_inactive").assertDoesNotExist()
    }
}
