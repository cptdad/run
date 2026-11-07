package com.vg.run

import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Hands a decoded QR text from the camera ANALYSIS thread to the MAIN executor
 * before the screen's callback sees it.
 *
 * **Why (GrapheneOS crash report 2026-09-27, `com.vg.run:1022`):** [QrCameraScanner]
 * used to invoke its decode callback inline on the single-thread CameraX
 * analysis executor. The "Move to new device" screen's callback navigates
 * (`navController.navigate(Routes.SETUP_PIN)`), which advances a back-stack entry's
 * lifecycle — `LifecycleRegistry.setCurrentState` is main-thread-only — so every
 * camera scan of a move code died with `IllegalStateException: Method
 * setCurrentState must be called on the main thread` from `pool-N-thread-1`.
 * The pairing scanner shares the scanner but only writes Compose snapshot state,
 * which tolerates any thread, so it never crashed; the paste path already ran on
 * main, so the e2e move suites (they paste) never saw it.
 *
 * Contract, unit-tested in `QrDecodeHandoffTest`:
 *  - [offer] is called on the analysis thread with an already-decoded text. It
 *    never runs [onDecodedText] inline; it posts it to [main].
 *  - While one acceptance is posted and not yet run, further frames are dropped
 *    (a 30 fps camera would otherwise queue dozens of duplicate callbacks).
 *  - The callback's `true` means ACCEPTED and latches [done] for good; `false`
 *    (a stray QR that is not ours) reopens the gate so scanning continues.
 *  - A throwing callback still releases the in-flight flag.
 */
class QrDecodeHandoff(
    private val main: Executor,
    private val onDecodedText: (String) -> Boolean,
) {
    private val accepted = AtomicBoolean(false)
    private val inFlight = AtomicBoolean(false)

    /** True once a decode was accepted; the analyzer stops decoding frames. */
    val done: Boolean get() = accepted.get()

    /** Returns true if [text] was posted to the main executor, false if dropped. */
    fun offer(text: String): Boolean {
        if (accepted.get()) return false
        if (!inFlight.compareAndSet(false, true)) return false
        main.execute {
            try {
                if (!accepted.get() && onDecodedText(text)) accepted.set(true)
            } finally {
                inFlight.set(false)
            }
        }
        return true
    }
}
