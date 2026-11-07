package com.vg.run

// Per-SESSION budget of the EARLY NEWNYM rungs: the cold rung
// ([MessageManager.shouldFireEarlyNewnym]), the pre-unlock warm-up rotation
// ([MessageManager.shouldFireWarmupNewnym]) and the descriptor-stage stall
// ([DescriptorHedge]) spend ONE cap of [MessageManager.EARLY_NEWNYM_MAX_FIRES];
// the cold rung's own count picks its 35 s / 80 s floor. Also renders the shared
// `NEWNYM n/max` phrase. Sibling of [WarmNewnymLedger] (the WARM rung's budgets).
//
// Owned by the platform session: Android `RunViewModel.earlyNewnymLedger` (one
// ViewModel = one session, never reset); iOS `IosAppController.earlyNewnymLedger`
// (process-lived; `AppState.beginWarmTorSession` calls [reset] for a new session
// in a surviving process). Not thread-safe by design, like [WarmNewnymLedger]:
// Android touches it on Main, iOS on the main actor.
class EarlyNewnymLedger {
    // NEWNYMs fired this session by any early rung (the cap's count).
    var firedThisSession: Int = 0
        private set

    // How many of [firedThisSession] were the COLD rung's own (its floor's count).
    var coldFiresThisSession: Int = 0
        private set

    val hasBudget: Boolean get() = firedThisSession < MessageManager.EARLY_NEWNYM_MAX_FIRES

    // Books one fired NEWNYM; returns the new count.
    fun noteFired(cold: Boolean = false): Int {
        firedThisSession++
        if (cold) coldFiresThisSession++
        return firedThisSession
    }

    // The control channel is down: spend the rest of the budget for this session.
    fun exhaust() {
        firedThisSession = MessageManager.EARLY_NEWNYM_MAX_FIRES
    }

    fun reset() {
        firedThisSession = 0
        coldFiresThisSession = 0
    }

    // Byte-identical to today's `NEWNYM $n/$max` inside the panel / LogBuffer lines.
    fun phrase(): String = "NEWNYM $firedThisSession/${MessageManager.EARLY_NEWNYM_MAX_FIRES}"
}
