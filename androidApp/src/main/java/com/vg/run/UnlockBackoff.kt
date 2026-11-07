package com.vg.run

import android.os.SystemClock
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import kotlinx.coroutines.delay

/**
 * Wrong-credential backoff gate shared by the lock screen and the recovery-code
 * screen. The delay is derived from the DURABLE failed-attempt count
 * ([CredentialPolicy.launchBackoffMs]) and re-applied each time the screen opens,
 * so a force-quit + relaunch cannot shed it. It is measured on
 * [SystemClock.elapsedRealtime] (monotonic) — no wall-clock timestamp is
 * persisted, so a clock change can neither skip nor stretch it.
 * iOS sibling: PinEntryView.swift / RecoveryEntryView.swift `backoffUntil`.
 */
@Stable
class UnlockBackoff(initialMs: Long) {
    private var untilMs by mutableLongStateOf(
        if (initialMs > 0L) SystemClock.elapsedRealtime() + initialMs else 0L
    )
    internal var nowMs by mutableLongStateOf(SystemClock.elapsedRealtime())

    /** Start (or extend, never shorten) a wait of [ms] from now. */
    fun start(ms: Long) {
        val now = SystemClock.elapsedRealtime()
        nowMs = now
        untilMs = maxOf(untilMs, now + ms)
    }

    val secondsLeft: Int get() = CredentialPolicy.backoffSecondsLeft(untilMs - nowMs)
    val active: Boolean get() = secondsLeft > 0
    internal val deadline: Long get() = untilMs
}

@Composable
fun rememberUnlockBackoff(initialMs: Long): UnlockBackoff {
    val state = remember { UnlockBackoff(initialMs) }
    // Tick while a wait is outstanding; re-keyed on the deadline so start() restarts it.
    LaunchedEffect(state.deadline) {
        while (true) {
            val now = SystemClock.elapsedRealtime()
            state.nowMs = now
            if (now >= state.deadline) break
            delay(250)
        }
    }
    return state
}
