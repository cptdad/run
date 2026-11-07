package com.vg.run

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * Pins the fix for the 2026-08-14 hardware regression: a distributor's answer
 * to [UnifiedPushSupport.register] was silently dropped because the
 * connector's OWN `InternalPushServiceConnection.connected`/`binding` static
 * flags were stuck `true` from an earlier bind cycle in this process — see
 * the kdoc on `UnifiedPushSupport`'s private `resetConnectorBindState` for
 * the full mechanism, verified by disassembling connector-3.3.5:
 * `InternalPushServiceConnection.bind` schedules an UNCONDITIONAL 5-second
 * `Timer` that calls `unbindService()` without ever resetting those flags, so
 * every later `sendEvent()` in the same process (a rotated endpoint, a
 * REGISTRATION_FAILED from our own opt-out cycle, or the very next
 * toggle-on) either short-circuits into a stale `mService` reference or never
 * calls `bind()` again at all.
 *
 * Drives the connector's REAL `InternalPushServiceConnection` singleton via
 * reflection (the library exposes no reset) rather than a mock, because the
 * regression IS a piece of third-party state this app does not own — a fake
 * would test our fake, not the fix. Same idiom as
 * [UnifiedPushArtifactSweepTest]'s `resetConnectorStore`.
 *
 * Run with:
 * ./gradlew connectedAndroidTest --tests "*.UnifiedPushBindStateResetTest"
 */
class UnifiedPushBindStateResetTest {

    private val ctx: Context get() = ApplicationProvider.getApplicationContext()

    private val connectionCls: Class<*>
        get() = Class.forName(
            "org.unifiedpush.android.connector.internal.InternalPushServiceConnection"
        )

    private fun setBindState(connected: Boolean, binding: Boolean) {
        for ((name, value) in listOf("connected" to connected, "binding" to binding)) {
            val field = connectionCls.getDeclaredField(name)
            field.isAccessible = true
            field.setBoolean(null, value)
        }
    }

    private fun getBindState(): Pair<Boolean, Boolean> {
        val connectedField = connectionCls.getDeclaredField("connected").apply { isAccessible = true }
        val bindingField = connectionCls.getDeclaredField("binding").apply { isAccessible = true }
        return connectedField.getBoolean(null) to bindingField.getBoolean(null)
    }

    @After
    fun tearDown() {
        // Leave the connector's static state clean for whatever test runs
        // next in this instrumentation process.
        setBindState(connected = false, binding = false)
    }

    /**
     * Simulates EXACTLY what the connector's own 5-second auto-unbind timer
     * leaves behind: `connected` and `binding` both stuck `true` with no live
     * bind. Before the fix, the NEXT [UnifiedPushSupport.register] call's
     * distributor answer would be delivered (if at all) through this stale
     * state instead of a fresh `bindService()`/`onServiceConnected()` cycle —
     * the exact mechanism behind "endpoint delivered in ~8ms, never
     * persisted" and "second register attempt never binds at all".
     */
    @Test
    fun register_forcesStaleConnectorBindStateBackToFalse() {
        setBindState(connected = true, binding = true)

        UnifiedPushSupport.register(ctx)

        val (connected, binding) = getBindState()
        assertFalse(
            "register() must reset the connector's InternalPushServiceConnection.connected " +
                "flag before broadcasting REGISTER, or the distributor's answer is delivered " +
                "through a stale mService reference instead of a fresh bind cycle",
            connected,
        )
        assertFalse(
            "register() must also reset InternalPushServiceConnection.binding, or the NEXT " +
                "sendEvent() believes a bind is already in flight and never calls bind() at all",
            binding,
        )
    }

    /** The steady-state case: nothing stuck, nothing to reset — must stay false. */
    @Test
    fun register_leavesCleanBindStateAsFalse() {
        setBindState(connected = false, binding = false)

        UnifiedPushSupport.register(ctx)

        val (connected, binding) = getBindState()
        assertFalse(connected)
        assertFalse(binding)
    }
}
