# Threat-Level Slider — Draft Spec

**Status:** Implemented (shipped). Items marked **(decided)** were decided in discussion; items marked
**(default — review)** are recommended defaults, applied so there's a complete spec — change freely.
Concrete numbers are recommended starting values, meant to be tuned.

## Concept

A single onboarding + settings control that maps the user's *intent* to a coherent bundle of the
existing security levers (A = passphrase, B = hardware auth-bound key, C = auto-lock) plus the
self-wipe timers. Replaces three cryptic toggles.

**Always on at every level — never on the slider (this is just what Rún is):** Tor-only, E2E,
no accounts, no notifications, lock-on-background, screenshot/app-switcher protection (release).

## The four levels

`Casual  ·  Private  ·  Hardened  ·  Maximum`

| Dimension | Casual | Private | Hardened | Maximum |
|---|---|---|---|---|
| **Credential** | 6-digit PIN | 6-digit PIN | 6-digit PIN *(default — review; PIN keeps it distinct from Maximum)* | **Passphrase** (≥70-bit / ~6 words) |
| **Hardware key (Lever B)** | off | on (biometric) | on (biometric) | off by default; advanced "add hardware binding" toggle |
| **Biometric unlock** | none | yes (Lever-B gate) | yes (Lever-B gate) | none (compellable) |
| **Idle auto-lock (Lever C)** | 15 min *(default)* | 2 min *(default)* | 1 min *(default)* | 60 s *(default)* |
| **Inactivity self-wipe** *(always on, scaled)* | 180 days *(default)* | 90 days *(default)* | 30 days *(default)* | 7 days *(default)* |
| **Wrong-tries self-wipe** *(always on, escalating backoff)* | 10 tries *(default)* | 8 *(default)* | 5 *(default)* | 5 *(default)* |
| Background lock | immediate | immediate | immediate | immediate |

Progression logic: PIN + hardware, getting tighter (Private → Hardened as the live-device window
shrinks), then **Maximum changes strategy entirely** — passphrase (entropy), no hardware crutch,
biometric off (coercion-resistant).

## Locked design decisions

| # | Decision | Choice | Source |
|---|---|---|---|
| 1 | Default position | **Force a choice at onboarding**, **bare-forced** (no pre-selected rung, no "Recommended" tag; Continue disabled until a rung is picked). Descriptions must be concrete enough to self-select. | (decided) |
| 2 | Lever-B key invalidation | **Recover, floor only for v1**: detect → explain → re-provision (no brick). Data-recovery code is a fast-follow. **Never** a silent PIN-only recovery copy (it would re-open the extract-key + brute-PIN attack Lever B prevents). | (decided) |
| 3 | Self-wipe settings | **Floored** — always on, cannot be disabled at any tier; thresholds scale gentle → aggressive. Onboarding must state plainly that Rún self-wipes and it can't be turned off. | (decided) |
| 4 | Maximum + hardware key | **Off by default** (passphrase carries it); advanced opt-in toggle. Consequence: Maximum never hits invalidation/brick — the recover-floor concern is scoped to Private/Hardened only. | (decided) |
| 8 | No-hardware devices | **Always show all four levels; gray out (disabled, not hidden)** the ones this device can't do — the user sees what the device *could* support, and the slider layout stays stable. A **device-status panel** (above the slider) states the detected capability, what it means for the hardware-bound key, and which levels are consequently unavailable. Applies to genuinely-no-hardware (Simulator / ancient) → Private + Hardened grayed & non-selectable. **Hardware-present-but-not-enrolled is different** — those stay *selectable* with a "turn on Face ID / set a screen lock" prompt (one setup step away, not unavailable). *(Revised from the earlier "hide them" call — hiding made the device look broken and dropped the teaching moment.)* | (decided) |
| — | Casual "maybe not for you" screen | Fires when Casual is chosen. Informational, **Continue anyway** (not a hard block), respectful. **Do not name a competitor** — describe the category ("a mainstream messenger"). | (decided) |
| — | Android biometric-invalidation sequencing | **v1: survive fingerprint re-enroll** (`setInvalidatedByBiometricEnrollment = false`) + loud enable warning, so a routine fingerprint change doesn't wipe data with no recovery. **Flip to invalidate-on-re-enroll once the recovery code ships.** (iOS already survives re-enroll via `.userPresence`; only device-passcode removal resets it.) | (default — review) |
| 5 | Hardened credential | **PIN** (keeps the passphrase as the single feature that defines Maximum). | (default — review) |
| 6 | Level storage | Store as an **opaque enum**, not the display string; **no plaintext "high-risk/dissident" flag**. Accept that the credential *type* is inferable pre-unlock (the unlock UI differs) — that's unavoidable. | (default — review) |
| 7 | Changing level later | **Requires authentication** (must be unlocked / re-enter credential) so a grabbed unlocked phone can't be slid down to weaken it. **Any downgrade shows a "this reduces your protection" warning + confirmation.** Credential-type or Lever-B changes route through the existing change-credential / `setDbKeyAuthBinding` re-wrap paths. | (default — review) |
| — | Lever-C warning countdown *(added 2026-07-16)* | **A 5-second in-app countdown overlay before the idle auto-lock fires, at every tier.** Appears at `timeout − 5s` of touch-idle ("Locking in 5… — tap to stay"), ticks 1 Hz; **the lock deadline never moves** — lock still fires at exactly `timeout`, so Lever C's window is unchanged (the warning sits *inside* it, it is not a grace period). Any touch dismisses it by resetting the idle clock exactly as touches already do (`onUserInteraction` / the catch-all recognizer); the overlay itself generates no interaction events. Implementation note: the Android watchdog polls at 10 s (`AUTO_LOCK_CHECK_INTERVAL_MS`), so once `idle ≥ timeout − 15s` the check tightens to 1 s ticks — which also makes the lock itself punctual (today it can fire up to ~10 s late). Same pattern on iOS ahead of `lockAndResetNavigation()`. Release-only, alongside the auto-lock it warns for (debug builds skip both; no e2e impact — verified manually on release, like the rest of Lever C). Matters most at MAXIMUM's 60 s (raised from 30 s on 2026-07-21), where reading a long message currently gets the app closed mid-read with no warning. | (decided) |

## Key flows

**Onboarding:** … EULA → (jailbreak-ack) → device-capability detection → **threat-level choice
(bare-forced)** → the credential setup that matches the chosen level (PIN keypad, or passphrase field
with the strength meter for Maximum) → provisioning. The choice is a *first* choice, changeable later
(guardrails per #7).

**Enable-time warning (Private/Hardened):** *"If you change your device passcode or re-enroll a
fingerprint later, this vault resets and its messages are gone."* — mandatory in v1 because there's no
data-recovery yet (#2/#3).

**Onboarding copy (mandatory, per #3):** *"Rún erases itself after repeated wrong PINs or long
inactivity, to protect your data if your phone is lost. This can't be turned off."*

## Deferred / fast-follows (explicitly out of v1)

- **Data-recovery code** at Lever-B enable (high-entropy, user-held — the only safe way to recover
  data without re-opening the Lever-B hole). Once it ships → flip Android to invalidate-on-re-enroll.
- Optional "biometric-caches-KEK" convenience unlock (weaker — compelled face opens it) — not now.
- Tuning of all the numeric thresholds above against real usage.

## Highest-value items to review first

1. **Android survive-re-enroll for v1** (default — review): the safest v1 call, but it accepts a niche
   "newly-added fingerprint could unlock" risk until the recovery code lands. Confirm you're OK with that.
2. **The self-wipe thresholds** (default): the Casual floors (180-day inactivity, 10 tries) are
   deliberately gentle so "always-on" doesn't punish casual users — sanity-check they're not *too* gentle.
3. **Hardened = PIN** (default): confirm you don't want Hardened to require/offer a passphrase.
