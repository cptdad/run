package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

// The iOS unlock result crosses the bridge as a bare Int: IosAppController's
// companion `UNLOCK_*` codes on the Kotlin side, AppState.swift's
// `enum UnlockOutcome: Int` on the Swift side. Nothing but this test ties the two
// (a renumbering on one side would turn "wrong PIN" into "transient error", or a
// recovery-required unlock into a counted failure). Review D7.
class UnlockCodeParitySourceTest {

    private val kotlinCodes: Map<String, Int> by lazy {
        val src = stripComments(File(repoRoot(), "shared/src/iosMain/kotlin/com/vg/run/IosAppController.kt").readText())
        Regex("""const val UNLOCK_(OPENED|DENIED|ERROR|RECOVERY_REQUIRED) = (\d)""").findAll(src)
            .associate { it.groupValues[1] to it.groupValues[2].toInt() }
    }

    private val swiftCodes: Map<String, Int> by lazy {
        val src = stripComments(iosAppStateSources())
        Regex("""case (opened|denied|error|recoveryRequired)\s*= (\d)""").findAll(src)
            .associate { it.groupValues[1] to it.groupValues[2].toInt() }
    }

    @Test
    fun theFourUnlockCodes_matchOnBothSides() {
        val expected = mapOf("OPENED" to 0, "DENIED" to 1, "ERROR" to 2, "RECOVERY_REQUIRED" to 3)
        assertEquals("IosAppController UNLOCK_* codes", expected, kotlinCodes)
        assertEquals(
            "AppState.swift UnlockOutcome raw values",
            mapOf("opened" to 0, "denied" to 1, "error" to 2, "recoveryRequired" to 3),
            swiftCodes,
        )
    }
}
