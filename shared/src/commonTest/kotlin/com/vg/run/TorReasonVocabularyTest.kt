package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * [TorReasonVocabulary] — the HS_DESC REASON → connect-code split and the
 * debug-mode passthrough list (2026-10-23). Both are privacy-relevant: the map
 * decides what reaches the relay, the list decides what the redactor leaves.
 */
class TorReasonVocabularyTest {

    @Test
    fun hsDescFailureCode_mapsExactlyTheFiveSplitReasons() {
        assertEquals(ConnectionLog.Code.HSDESC_NOT_FOUND, TorReasonVocabulary.hsDescFailureCode("NOT_FOUND"))
        assertEquals(ConnectionLog.Code.HSDESC_NO_HSDIR, TorReasonVocabulary.hsDescFailureCode("QUERY_NO_HSDIR"))
        assertEquals(ConnectionLog.Code.HSDESC_RATE_LIMITED, TorReasonVocabulary.hsDescFailureCode("QUERY_RATE_LIMITED"))
        assertEquals(ConnectionLog.Code.HSDESC_BAD_DESC, TorReasonVocabulary.hsDescFailureCode("BAD_DESC"))
        assertEquals(ConnectionLog.Code.HSDESC_UNEXPECTED, TorReasonVocabulary.hsDescFailureCode("UNEXPECTED"))
        // Case-insensitive like the parser's allowlist.
        assertEquals(ConnectionLog.Code.HSDESC_NOT_FOUND, TorReasonVocabulary.hsDescFailureCode("not_found"))
    }

    @Test
    fun hsDescFailureCode_anythingElseKeepsThePreSplitCode() {
        for (reason in listOf(null, "", "QUERY_REJECTED", "SOMETHING_NEW", "NOT_FOUND ", "NOT_FOUNDX",
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion")) {
            assertEquals(ConnectionLog.Code.HSDESC_FAILED, TorReasonVocabulary.hsDescFailureCode(reason), "$reason")
        }
    }

    @Test
    fun failureFamily_isExactlyWhatTheMapCanReturn() {
        val returned = (TorReasonVocabulary.HS_DESC_FAIL + listOf("x", "")).map {
            TorReasonVocabulary.hsDescFailureCode(it)
        }.toSet() + TorReasonVocabulary.hsDescFailureCode(null)
        assertEquals(TorReasonVocabulary.HS_DESC_FAILURE_CODES, returned)
    }

    @Test
    fun newCodeNames_stayWithinTheTelemetryNameCeiling() {
        // The body ceiling is sized by the longest code name (21 chars,
        // TOR_BOOTSTRAP_PROBLEM); none of the new ones may exceed it.
        for (code in TorReasonVocabulary.HS_DESC_FAILURE_CODES + ConnectionLog.Code.TOR_REUSED) {
            assertTrue(code.name.length <= 21, code.name)
        }
    }

    @Test
    fun debugPassthrough_isOnlyTorProtocolKeywords() {
        // Upper-case letters and `_` only: no digit and no lower-case letter can
        // ever appear, so no id/capability/onion (all of which mix in digits or
        // lower case) can be equal to an entry. Short, too.
        assertTrue(TorReasonVocabulary.DEBUG_PASSTHROUGH.isNotEmpty())
        for (word in TorReasonVocabulary.DEBUG_PASSTHROUGH) {
            assertTrue(word.all { it in 'A'..'Z' || it == '_' }, word)
            assertTrue(word.length in 3..20, word)
        }
        assertEquals(
            TorReasonVocabulary.HS_DESC_FAIL + TorReasonVocabulary.CIRC_FAIL + TorReasonVocabulary.STREAM_FAIL +
                TorReasonVocabulary.ORCONN_FAIL + TorReasonVocabulary.BOOTSTRAP_PROBLEM + "CLOCK_JUMPED",
            TorReasonVocabulary.DEBUG_PASSTHROUGH,
        )
    }
}
