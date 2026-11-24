package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * RÚN-02: a retry of an interrupted wipe can NEVER delete a newly provisioned key.
 *
 * The guarantee is an ORDERING, and this test pins it over one shared event log:
 *  - in-process, deletions run only while the erase latch is unresolved, and an
 *    unresolved latch makes minting and provisioning impossible;
 *  - across a relaunch (latch gone with the process), deletions run only in the
 *    fresh-setup gate, BEFORE the first seal — i.e. before any key exists for the
 *    new vault.
 * So after a MINT, no DELETE of a key may follow unless a NEW wipe started.
 */
class WipeRetryNeverTargetsNewKeyTest {

    /** The Keychain / Keystore as the tests see it: one device key, one hardware key. */
    private class KeyWorld : WipeKeyStore {
        var deviceKey: Int? = 1
        var hardwareKey: Int? = 1
        private var nextId = 2
        var failDeviceDeletes = 0
        var failHardwareDeletes = 0
        val events = mutableListOf<String>()

        override fun protectedDataAvailable(): Boolean = true

        override fun erase(item: WipeItem): EraseResult = when (item) {
            WipeItem.DEVICE_KEY -> {
                events += "DELETE dk${deviceKey ?: "-"}"
                if (failDeviceDeletes > 0) { failDeviceDeletes--; EraseResult(EraseOutcome.UNRESOLVED, -25308) }
                else if (deviceKey == null) EraseResult(EraseOutcome.ALREADY_ABSENT, -25300)
                else { deviceKey = null; EraseResult(EraseOutcome.DELETED, 0) }
            }
            WipeItem.HARDWARE_KEY -> {
                events += "DELETE hk${hardwareKey ?: "-"}"
                if (failHardwareDeletes > 0) { failHardwareDeletes--; EraseResult(EraseOutcome.UNRESOLVED, -25308) }
                else if (hardwareKey == null) EraseResult(EraseOutcome.ALREADY_ABSENT, -25300)
                else { hardwareKey = null; EraseResult(EraseOutcome.DELETED, 0) }
            }
            else -> EraseResult(EraseOutcome.DELETED, 0)
        }

        /** getOrCreateKey's mint branch, with the production gate. */
        fun mint(): Boolean {
            if (!WipeErasePolicy.mayMintDeviceKey()) { events += "MINT-REFUSED"; return false }
            if (deviceKey == null) { deviceKey = nextId++; events += "MINT dk$deviceKey" }
            return true
        }

        /** A provision as both platforms run it: gate first, then the first seal. */
        fun provision(credentialPair: Boolean? = false): Boolean {
            if (!FreshProvisionGate.prepare(this, credentialPair, true, true) { events += "DROP-CACHE" }) {
                events += "PROVISION-REFUSED"; return false
            }
            if (!mint()) return false
            events += "SEAL"
            return true
        }

        fun wipe(): WipeEraseReport {
            events += "WIPE"
            val token = WipeEraseLatch.begin()
            return WipeEraser.run(this, WipeEraser.KEY_ITEMS).also { WipeEraseLatch.finish(token, it) }
        }

        fun retryTrigger(): Boolean = WipeEraseRetry.retryIfPending(this) { events += "DROP-CACHE" }

        fun relaunch() { events += "RELAUNCH"; WipeEraseLatch.resetForTest() }
    }

    @BeforeTest fun reset() = WipeEraseLatch.resetForTest()
    @AfterTest fun tearDown() = WipeEraseLatch.resetForTest()

    private fun assertNoDeleteAfterMint(events: List<String>) {
        events.forEachIndexed { i, e ->
            if (!e.startsWith("MINT dk")) return@forEachIndexed
            val nextWipe = events.subList(i + 1, events.size).indexOf("WIPE").let { if (it < 0) events.size else i + 1 + it }
            val offending = events.subList(i + 1, nextWipe).firstOrNull { it.startsWith("DELETE") }
            assertEquals(null, offending, "a delete followed `$e` with no new wipe in between: $events")
        }
    }

    @Test
    fun inProcess_unresolvedWipe_retryResolves_provisionMints_laterRetriesDoNothing() {
        val w = KeyWorld()
        w.failDeviceDeletes = WipeEraser.IMMEDIATE_PASSES
        assertFalse(w.wipe().complete)

        assertFalse(w.provision(), "no fresh setup while the erase is unresolved")
        assertFalse(w.mint(), "and no mint either")
        assertEquals(1, w.deviceKey, "the OLD key is still there — not replaced, not reused")

        assertTrue(w.retryTrigger(), "the unlock/activation/button retry resolves it")
        assertEquals(null, w.deviceKey)

        assertTrue(w.provision())
        val newKey = assertNotNull(w.deviceKey)
        repeat(3) { assertTrue(w.retryTrigger()) }
        assertEquals(newKey, w.deviceKey, "the new key survives every later retry trigger")
        assertNoDeleteAfterMint(w.events)
    }

    @Test
    fun safeRestart_unresolvedWipe_relaunch_freshSetupPurgesBeforeTheMint() {
        val w = KeyWorld()
        w.failDeviceDeletes = WipeEraser.IMMEDIATE_PASSES
        w.failHardwareDeletes = WipeEraser.IMMEDIATE_PASSES
        assertFalse(w.wipe().complete)
        w.relaunch()   // process died; the RAM latch is gone, the old keys are not

        assertTrue(w.provision(), "the fresh-setup gate purges the leftovers, then setup proceeds")
        val purgeAt = w.events.lastIndexOf("DELETE dk1")
        val mintAt = w.events.indexOfFirst { it.startsWith("MINT dk") }
        assertTrue(purgeAt in 0 until mintAt, "the purge strictly precedes the mint: ${w.events}")
        assertEquals(null, w.hardwareKey, "the hardware key leftover went too")
        assertTrue(w.events.indexOf("DROP-CACHE") in purgeAt until mintAt, "cached copies dropped between purge and mint")

        val newKey = assertNotNull(w.deviceKey)
        repeat(3) { w.retryTrigger() }
        assertTrue(w.provision(credentialPair = true), "a configured install re-entering the gate deletes nothing")
        assertEquals(newKey, w.deviceKey)
        assertNoDeleteAfterMint(w.events)
    }

    @Test
    fun safeRestart_aFailingPurge_blocksSetup_untilARetryResolvesIt() {
        val w = KeyWorld()
        w.relaunch()
        w.failDeviceDeletes = WipeEraser.IMMEDIATE_PASSES
        assertFalse(w.provision(), "the leftover key could not be removed — setup must not reuse it")
        assertFalse(w.events.any { it.startsWith("MINT dk") })
        assertTrue(WipeEraseLatch.unresolved)

        assertTrue(w.retryTrigger())
        assertTrue(w.provision(), "fresh setup succeeds after resolution")
        assertNoDeleteAfterMint(w.events)
    }

    @Test
    fun aSecondWipe_isAllowedToDeleteTheNewKey() {
        // The invariant is about RETRIES. A new wipe is a new, intended deletion.
        val w = KeyWorld()
        w.wipe()
        assertTrue(w.provision())
        val newKey = assertNotNull(w.deviceKey)
        assertTrue(w.wipe().complete)
        assertEquals(null, w.deviceKey)
        assertTrue(w.events.contains("DELETE dk$newKey"))
        assertNoDeleteAfterMint(w.events)
    }
}
