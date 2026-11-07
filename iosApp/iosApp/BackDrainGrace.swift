import Foundation

// ---------------------------------------------------------------------------
// RETRIEVE-ACK (2026-11-03; supersedes the BACK CONTRACT / grace window).
//
// Leaving a conversation is IMMEDIATE: the back chevron and the edge swipe pop at
// once and the screen's poll task is cancelled on disappear. Nothing needs to be
// awaited any more — the relay deletes a blob only when the client ACKS it, and a
// screen acks (commits its PendingDrain) only after the messages are on screen. A
// drain the user walked away from is abandoned (or simply dropped) and the relay
// re-delivers it after its lease.
//
// `awaitDrain` remains only because a Swift `Task.detached(...).value` does not
// unblock on cancellation: when the VIEW goes away the poll loop must still unwind
// while the blocking poll finishes in the background. The caller's closure abandons
// a drain that lands after cancellation.
// ---------------------------------------------------------------------------

/// Observation tick — the same 50 ms cadence the conversation loops' own
/// interruptible inter-poll wait uses.
private let drainTickMs: UInt64 = 50

/// Main-actor box for the drain's result: the awaiting loop below and the drain
/// task both run on the main actor, so no synchronisation beyond that is needed.
@MainActor
private final class DrainBox<T> {
    var value: T?
    var done = false
}

/// Awaits [poll] to completion. Returns nil
/// only when the CALLING task is cancelled (the screen is going away), so a
/// torn-down screen never holds its loop open on a hung drain.
@MainActor
func awaitDrain<T>(_ poll: @escaping @MainActor () async -> T) async -> T? {
    let box = DrainBox<T>()
    let drain = Task { @MainActor in
        let v = await poll()
        box.value = v
        box.done = true
    }
    while true {
        if box.done { return box.value }
        if Task.isCancelled {
            drain.cancel()
            return nil
        }
        try? await Task.sleep(nanoseconds: drainTickMs * 1_000_000)
    }
}
