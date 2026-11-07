import Foundation
import UIKit
import shared

// ---------------------------------------------------------------------------
// InactivityWipe — wipes all vault data if the app hasn't been opened
// for 7 days. The EXPIRY DECISION (threshold + clock-rollback defense) is the
// SHARED commonMain InactivityPolicy, so it can no longer diverge from Android
// (the clock-rollback branch used to be Android-only, letting a
// seized-but-unlocked iPhone defer the wipe forever by setting the clock back).
// Only storage + the protected-data check stay iOS-side below.
//
// The sealed record is now
// InactivityPolicy.formatStamp's "<wallMs>|<uptimeMs>" — the kernel-uptime anchor
// (currentUptimeMs) rides INSIDE the same AEAD blob as the timestamp, so the
// switch also measures elapsed time on a clock Settings cannot wind, and
// the backward-clock branch now needs InactivityPolicy.CLOCK_BACK_TOLERANCE_MS of
// slack before it may crypto-erase a vault (it fires unattended, without
// confirmation, and takes the recovery blob with it). Every LEGACY bare-decimal
// record — Keychain-native OR the earlier UserDefaults copy migrated below — still
// parses and is judged on the wall clock alone, then gains its anchor on the next
// touch(). Migrate-on-write; no vault is ever hard-broken by the format change.
//
// The last-activity timestamp is encrypted with CryptoProvider. Fail-SAFE,
// biased toward preserving data: an ABSENT timestamp with no anchor marker
// defers (records 'now', never wipes — see the deletion-tamper anchor below for the marker-present
// case), and a device key that is transiently unavailable (locked keybag /
// transient Keychain error) defers.  Only a genuine decryption failure on a
// resolvable key — i.e. the key was rotated — or a confirmed deletion-tamper
// (deletion-tamper anchor) is treated as expired and triggers the wipe.
//
// A PRESENT-but-malformed blob (not valid
// Base64 — e.g. one flipped byte outside the AEAD tag) is NOT the same as an
// ABSENT one. It used to fold into the same "absent" branch (touch + defer),
// silently disarming the dead-man's switch forever on a single corrupted
// byte, while Android's equivalent decode failure is caught by the SAME
// exception handler as an AEAD failure and — when the device is unlocked —
// is treated as tamper. isExpired() below now mirrors that split exactly:
// decoding never touches the device key, so it uses the same direct
// OS-level proxy Android's `isDeviceCurrentlyLocked` uses for "can this be
// trusted as tamper right now" — `UIApplication.shared.isProtectedDataAvailable`.
// Protected data unavailable (locked keybag / prewarm launch) still defers,
// never wipes; only a malformed blob on a device that CAN currently decrypt
// is treated as tamper.
//
// Deletion-tamper anchor, mirroring
// Android InactivityWipe.kt's armInactivityMarker / inactivityMarkerArmed /
// absentTimestampIsDeletionTamper / absentTimestampShouldEstablish exactly
// (do not invent different semantics — the two platforms must agree). Without
// this, an examiner can delete the timestamp before every launch and restart
// the 7-day clock forever, because an absent timestamp used to be treated
// unconditionally as "never armed". The fix: a "timestamp has been armed at
// least once" marker (`markerKey`), and — critically — BOTH the marker and
// the timestamp itself now live in the SAME Keychain KV service
// (KeychainHelper's "com.vg.run.kv") that also holds the vault's own
// credential verifier / wrapped DB key. That is a deliberate departure from
// Android's storage choice (there the marker moved into the fate-shared
// vault_selector_prefs FILE while the timestamp stayed in the separate,
// still-independently-deletable inactivity_prefs FILE) — the iOS Keychain has
// no per-item "same file" fate-sharing (every kv key is individually
// addressable/deletable), so the file-level anchor Android relies on doesn't
// exist here. What DOES transfer: both values now sit behind the same
// kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly class and the same kvGet/
// kvPut primitives as vlt_a/vlt_c, rather than a bare UserDefaults plist an
// examiner can edit directly with the app closed (which would have made the
// anchor decorative — exactly the hole this closes) — and moving the
// timestamp there too is what makes a SAFE anchor possible at all (see the
// crash-safety note below).
//
// CRASH-SAFETY (coordinator follow-up, same day): Android's first anchor patch
// wrote the timestamp with SharedPreferences.apply() (asynchronous disk
// flush) and armed the marker with a synchronous commit(). A process kill
// between the two could leave "marker durable, timestamp lost", which
// absentTimestampIsDeletionTamper reads as deletion and wipes an honest
// vault — fixed there by switching the timestamp write to a checked
// commit(), arming only when it returns true. The same shape of bug is
// reachable on iOS with UserDefaults: `.set()` updates the in-memory cache
// synchronously but flushes to disk asynchronously/coalesced, and
// `.string(forKey:)` reads that SAME in-memory cache — so a naive read-back
// against UserDefaults would appear to confirm a write that hasn't reached
// disk yet, which is no confirmation at all. The Keychain does not have this
// property: SecItemAdd/SecItemUpdate are synchronous IPC round-trips to
// securityd and commit before returning, and a subsequent SecItemCopyMatching
// queries that same durable state with no client-side cache in between — so
// a read-back against the Keychain is trustworthy. touch() below writes the
// timestamp, reads it back to CONFIRM it landed, and arms the marker ONLY on
// a confirmed match — "write durably, verify, then arm; if you cannot verify,
// do not arm". The marker is therefore never more durable than the timestamp
// it attests to. kvPut fails SILENTLY on a locked keybag (KeychainHelper);
// the read-back is what surfaces that as "unverified" rather than as tamper.
//
// MIGRATION FIX (2026-07-30, same-day correction): the move above left a
// gap — on upgrade, `kvGet(key)` on the Keychain genuinely returns
// itemMissing (nothing has EVER been written there), and the marker is
// naturally unarmed too (same reason), so isExpired()'s "confirmed absent,
// marker not armed" branch used to read this as a brand-new install and call
// touch() to establish "now" — silently resetting an existing install's
// dead-man clock to a fresh 7 days on the very first launch after this
// build lands, regardless of how far into the old window the device was.
// isExpired() now checks the LEGACY UserDefaults copy under the SAME key
// name before establishing a fresh baseline, and — if present — adopts it
// into the Keychain (write, verify read-back, THEN arm the marker, THEN
// remove the legacy copy — never the reverse order, for the same
// crash-safety reason as touch() above) via migrateLegacyTimestamp(), which
// returns the REAL expiry verdict for the adopted value so this launch
// answers correctly rather than deferring to the next one. A decode/AEAD
// failure on the legacy value is explicitly NOT treated as tamper during
// this one-time migration (unlike the steady-state present-value path
// further below) — this build has never validated that blob before, unlike
// an established Keychain-native marker an examiner could be seen deleting
// — so it falls back to the same establish-on-read touch() as if no legacy
// value existed. Protected-data-unavailable defers outright (no migrate
// attempt at all): kvPut fails silently on a locked keybag, so this keeps
// the migration attempt simple rather than trying to reason about a partial
// write under those conditions.
//
// PLIST MTIME — known limitation (the iOS sibling of Android
// InactivityWipe.kt's, mitigated there by the same probe trick mirrored below): the
// AEAD seals only touch()'s VALUE, not the WRITE — UserDefaults.set()
// rewrites Library/Preferences/<bundleid>.plist, so the file's inode mtime
// equals the last real vault-unlock wall-clock time in the CLEAR, readable
// from any filesystem image with no need to break the AEAD at all. Since the anchor
// moved the real timestamp OFF UserDefaults and into the Keychain, that
// PRECISE signal no longer lives in the plist at all — but the probe below is
// left running anyway (harmless, still dilutes whatever else touches that
// plist). isExpired() below still
// writes an unrelated, content-free random probe on every bare (unlocked,
// app-open) launch that reaches its "present + valid timestamp, not expired"
// path — specifically to widen what that mtime correlates with, from a
// precise "last real vault unlock" down to the coarser "app was opened around
// this time". That is genuinely less specific, but NOT concealment: there is
// no application-code fix for the mtime leak itself (mirrors Android's
// documented limitation — see InactivityWipe.kt's header — including its
// warning that "fixing" this by resetting the file's mtime after the fact
// doesn't work: the write already happened, and any attempt to normalize a
// timestamp post hoc leaves other forensic signals — e.g. ctime — pointing at
// the true instant, which no unprivileged app can override). The probe key is
// SEPARATE from the real timestamp key and is never read back by anything, so
// it cannot affect the wipe decision or reopen the "bare launch can't keep a
// seized vault alive" guarantee — touch() (the real write) still fires ONLY
// from a genuine unlock or a verified establish-on-read, never from
// isExpired()'s other branches.
// ---------------------------------------------------------------------------

final class InactivityWipe {

    private static let key = "inactivity_ts_enc"
    private static let context = "inactivity-wipe"
    // mtime-dilution probe (see header) — deliberately a SEPARATE
    // key from `key`, never read back by anything. Its value is random, not
    // temporal, so it discloses nothing on its own even if read directly.
    // NOTE: although its VALUE is content-free,
    // this key is written ONLY by a previously-configured+unlocked vault, so its
    // mere PRESENCE proves prior setup — a deniability tell. It must be
    // cleared by every wipe path. The canonical wipe enumeration is Kotlin's
    // IosUserDefaultsKeys.all (swept by IosAppController.emergencyWipe); the
    // literal here MUST match IosUserDefaultsKeys.INACTIVITY_MTIME_PROBE.
    private static let probeKey = "inactivity_mtime_probe"

    // The "timestamp has been durably armed at least once" anchor marker.
    // Lives in the SAME Keychain KV service as `key` (see header) — armed only
    // from touch(), only after a verified timestamp write. Not credential
    // material, so no AEAD; a plain presence flag mirrors Android's
    // INACTIVITY_ARMED_KEY / PinAttemptsStore.ESTABLISHED_KEY convention.
    private static let markerKey = VaultStoreKeysKt.INACTIVITY_ARMED_ANCHOR_KEY

    /// Records the current time. Call on every successful unlock, and from
    /// isExpired()'s establish-on-read branch.
    ///
    /// `encrypt` is `@Throws` — a transient Keychain failure used to cross a
    /// non-throwing K/N boundary and ABORT the process. Now it defers: the stored
    /// timestamp keeps its previous value and the next successful touch (every
    /// unlock calls this) records the real one. Never write a timestamp we could
    /// not seal, and never crash the app over a Keychain glitch.
    static func touch(crypto: CryptoProvider) {
        // Seal the monotonic uptime anchor alongside the wall-clock stamp,
        // inside the SAME AEAD blob (see currentUptimeMs + the header). A legacy
        // bare-decimal record is rewritten in the anchored shape right here, on the
        // next unlock — migrate-on-write, no separate migration pass.
        let now = InactivityPolicy.shared.formatStamp(
            timestampMs: Int64(Date().timeIntervalSince1970 * 1000),
            uptimeMs: currentUptimeMs()
        )
        let plaintext = kotlinByteArray(from: now)
        let ctx = kotlinByteArray(from: context)
        guard let encrypted = try? crypto.encrypt(plaintext: plaintext, contextInfo: ctx) else {
            // LogBuffer is the sanctioned sink (no-op in release); NSLog/print are
            // barred outright by the pre-push release-logging guard.
            LogBuffer.shared.append(level: "W", tag: "InactivityWipe", message: "touch deferred — device key unavailable")
            return
        }
        // Convert KotlinByteArray to Data then Base64
        let b64 = dataFromKotlin(encrypted).base64EncodedString()
        // See the header's CRASH-SAFETY note: write the timestamp to the
        // Keychain KV service — synchronous, durable, no client-side cache —
        // NOT UserDefaults, whose async/coalesced flush would make a read-back
        // unreliable.
        KeychainHelper.shared.kvPut(key: key, value: b64)
        // Verify the write actually landed via a FRESH Keychain query (not the
        // `b64` value already held in memory) BEFORE arming the marker:
        // "write durably, verify, then arm — if you cannot verify, do not
        // arm." kvPut fails SILENTLY on a locked keybag, so this read-back is
        // the only way to know whether it landed. Skipping the arm here can
        // only ever delay deletion-tamper detection to the next verified
        // touch() — it can never cause a false wipe.
        guard KeychainHelper.shared.kvGet(key: key).value == b64 else {
            LogBuffer.shared.append(level: "W", tag: "InactivityWipe", message: "timestamp write unverified — marker NOT armed this call")
            return
        }
        armInactivityMarker()
    }

    /// Returns true if the 7-day inactivity threshold is exceeded.
    /// A genuine decryption failure (e.g. key rotated) is treated as expired —
    /// fail-safe — but a failure while protected data is unavailable (device
    /// locked) defers instead of wiping the vault. An ABSENT
    /// timestamp with NO anchor marker is NOT treated as expired
    /// (establish-on-read, see below); a PRESENT but malformed one IS,
    /// mirroring Android.
    static func isExpired(crypto: CryptoProvider, thresholdMs: Int64 = InactivityPolicy.shared.THRESHOLD_MS) -> Bool {
        let tsRead = KeychainHelper.shared.kvGet(key: key)
        guard let b64 = tsRead.value, !b64.isEmpty else {
            if !tsRead.itemMissing {
                // Transient Keychain read failure on the TIMESTAMP itself
                // (locked keybag mid-call, errSecInteractionNotAllowed, a
                // -34018-class securityd glitch). The item
                // may still exist; this is NOT "absent". Reading it as absent
                // here would consult the marker and could misfire the
                // tamper branch below on a device that simply can't answer
                // right now. DEFER — do not touch, do not check the marker,
                // do not wipe.
                LogBuffer.shared.append(level: "W", tag: "InactivityWipe", message: "timestamp read failed (transient) — deferring inactivity check")
                return false
            }
            // Confirmed absent (errSecItemNotFound). Two sub-cases,
            // mirroring Android's absentTimestampIsDeletionTamper /
            // absentTimestampShouldEstablish exactly — do not invent
            // different semantics; the two platforms must agree:
            //  - marker ARMED ⇒ the timestamp WAS durably written at least
            //    once (touch() only arms AFTER a verified write — see its
            //    CRASH-SAFETY note) and has since been deleted. That is the
            //    deletion-tamper signature an examiner exploits by
            //    deleting the timestamp before every launch to keep
            //    restarting the 7-day clock. Treat exactly like an expired
            //    timestamp — do NOT touch() here, which would erase the
            //    tamper evidence and hand back a fresh window.
            //  - marker NOT armed (a genuinely fresh provision — PIN SETUP
            //    merely sets isConfigured=true and never calls touch(), so a
            //    configured-but-never-unlocked app legitimately has neither —
            //    OR an install upgrading from a build that predates this
            //    marker/store) ⇒ ESTABLISH-ON-READ: touch() (which verifies
            //    its own write before arming the marker) and return false.
            //    Ambiguous absence must NEVER brick a vault. (AppState only
            //    calls isExpired when configured AND protected data is
            //    available, so this is only ever reached when the vault
            //    genuinely exists — the same AND-gate Android's
            //    vaultConfigured(selector) applies.)
            if inactivityMarkerArmed() {
                LogBuffer.shared.append(level: "W", tag: "InactivityWipe", message: "timestamp missing but marker survived — treating as deleted (expired)")
                return true
            }
            // MIGRATION FIX (2026-07-30, same-day correction of the anchor move off
            // UserDefaults): before treating this as a genuinely fresh install and
            // establishing a brand-new "now" baseline, check whether the OLD
            // (pre-anchor) UserDefaults copy of this same timestamp is still on disk.
            // Without this check EVERY existing install's dead-man's clock
            // silently resets to a fresh 7 days on the first launch after the anchor
            // build lands — a device already 5 days into its 7-day window reads
            // Keychain-absent (it was never written there), the marker isn't
            // armed either (also Keychain-only), and the old code fell straight
            // through to touch()+establish. That is a security regression (an
            // examiner benefits from every upgrade silently resetting the clock),
            // not just a UX blip.
            guard UIApplication.shared.isProtectedDataAvailable else {
                // Can't safely read/adopt/arm — kvPut fails SILENTLY on a locked
                // keybag (KeychainHelper), so an attempted migration here could
                // "succeed" without actually landing, then arm nothing and lose
                // nothing — but to keep this launch's behavior simple and safe,
                // just defer outright: no touch(), no migrate, no wipe. A later
                // launch with protected data available makes the real decision,
                // and the legacy UserDefaults copy (untouched) is still there to
                // migrate from then.
                LogBuffer.shared.append(level: "W", tag: "InactivityWipe", message: "timestamp absent, protected data unavailable — deferring (no migrate)")
                return false
            }
            if let legacyB64 = UserDefaults.standard.string(forKey: key), !legacyB64.isEmpty {
                if let migratedExpired = migrateLegacyTimestamp(legacyB64: legacyB64, crypto: crypto, thresholdMs: thresholdMs) {
                    return migratedExpired
                }
                // BRICK-SAFETY: migrateLegacyTimestamp returns nil for a decode
                // failure (not valid Base64) or an AEAD failure (KeyUnavailable,
                // or the key resolved but verification failed) on the LEGACY
                // value. Neither is read as tamper during migration — this build
                // has never itself validated that blob, unlike an established
                // Keychain-native marker an examiner could be seen deleting — so
                // fall through to the same establish-on-read touch() below as if
                // no legacy value had existed. The corrupt legacy entry is left
                // in place (not removed): a future launch may find a Keychain-
                // native value already armed by the touch() below, in which case
                // this branch is never reached again, or it may retry migration
                // harmlessly (base64-decode is a pure/idempotent check).
            }
            touch(crypto: crypto)
            return false
        }
        guard let encData = Data(base64Encoded: b64) else {
            // PRESENT but not valid Base64 — a corrupted blob, not an
            // absent one. This decode never touches the device key, so it
            // cannot distinguish "key unavailable" from "key works" on its
            // own; use the same OS-level proxy Android's isDeviceCurrentlyLocked
            // uses for that. Protected data unavailable (locked keybag /
            // prewarm launch) MUST defer — never treat as tamper. Only a
            // malformed blob on a device that CAN currently decrypt is
            // tamper — fail-safe → expired, matching Android's catch(Exception)
            // branch (isDeviceCurrentlyLocked false ⇒ fail-safe expired).
            // Deliberately does NOT call touch() here (same as every other
            // defer branch below) — overwriting a corrupted blob with a fresh
            // "now" would erase the tamper evidence and re-arm the window.
            guard UIApplication.shared.isProtectedDataAvailable else { return false }
            return true
        }
        let encrypted = kotlinByteArray(from: encData)
        let ctx = kotlinByteArray(from: context)

        // tryDecrypt now SEPARATES the two failure modes (was: both folded to nil,
        // so a transient Keychain glitch on an unlocked phone read as "expired" and
        // wiped the vault):
        //   - throws KeyUnavailableException → the device key is transiently
        //     unresolvable (locked keybag, errSecAuthFailed, or wiped). DEFER —
        //     never wipe on a transient; a later launch with the Keychain readable
        //     makes the real decision.
        //   - returns nil → the key resolved but AEAD verification failed, i.e. the
        //     key was rotated. That is the genuine fail-safe → expired signal.
        let decrypted: KotlinByteArray?
        do {
            decrypted = try crypto.tryDecrypt(ciphertext: encrypted, contextInfo: ctx)
        } catch {
            return false   // KeyUnavailableException → transient → defer, never wipe
        }
        guard let decrypted else {
            // Genuine key-rotation failure → fail-safe → expired. Keep the
            // protected-data check as a last belt-and-suspenders defer.
            if !UIApplication.shared.isProtectedDataAvailable { return false }
            return true
        }

        let data = dataFromKotlin(decrypted)
        // parseStamp accepts BOTH the legacy bare-decimal record and the
        // anchored "<wallMs>|<uptimeMs>" one; a legacy record yields NO_UPTIME and
        // is judged by the wall clock alone, exactly as before. A record whose
        // wall-clock field is unparseable still returns true (fail-safe), which is
        // what `Int64(str)` failing produced here before.
        guard let str = String(data: data, encoding: .utf8),
              let stamp = InactivityPolicy.shared.parseStamp(raw: str) else { return true }
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        // Shared decision, incl. the clock-rollback branch that was
        // previously missing on iOS (now tolerance-gated) and the
        // monotonic term.
        // Per-level inactivity threshold (threat-level slider); the default is the
        // current shared constant (legacy install / no chosen level).
        let expired = InactivityPolicy.shared.isStampExpired(
            stamp: stamp, nowMs: now, nowUptimeMs: currentUptimeMs(), thresholdMs: thresholdMs)
        if !expired {
            // See header: refresh the mtime-dilution probe on this
            // "present + valid timestamp, not expired" bare launch — mirrors
            // Android's refreshMtimeProbe() call site exactly (never on the wipe
            // branch, never on a KeyUnavailable/locked-device defer above, and
            // never touching `key` itself, so the "bare launch can't
            // keep a seized vault alive" guarantee is unaffected).
            refreshMtimeProbe()
        }
        return expired
    }

    /// MIGRATION FIX (2026-07-30): adopts a pre-anchor, UserDefaults-stored
    /// encrypted timestamp into the Keychain KV store instead of letting the
    /// caller establish a fresh "now" baseline over it — see the call site in
    /// [isExpired] for why silently resetting an existing install's clock on
    /// upgrade is a security regression, not a UX blip.
    ///
    /// Returns the REAL expiry verdict for the legacy value on success — this
    /// decrypts the actual old timestamp and runs it through the normal
    /// threshold check, so a device 5 days into its 7-day window stays 5 days
    /// in rather than being handed a fresh window. Returns `nil` if the
    /// legacy value is not valid Base64, or fails to decrypt (device key
    /// transiently unavailable, or a genuine AEAD verification failure) — per
    /// BRICK-SAFETY, neither is read as tamper during migration (this build
    /// has never itself validated this blob, unlike an established
    /// Keychain-native marker an examiner could be seen deleting); the caller
    /// falls back to establish-on-read in that case.
    ///
    /// Only writes to the Keychain / arms the marker / removes the legacy
    /// UserDefaults copy on a FULLY verified adoption — write, read back,
    /// confirm the match, THEN arm, THEN remove the legacy copy — mirroring
    /// touch()'s CRASH-SAFETY ordering exactly (the marker must never be more
    /// durable than the value it attests to, and the legacy copy must never
    /// be deleted before its replacement is confirmed durable, or a crash
    /// between the two would lose the only copy of the real timestamp).
    /// Caller must have already confirmed
    /// `UIApplication.shared.isProtectedDataAvailable`.
    private static func migrateLegacyTimestamp(legacyB64: String, crypto: CryptoProvider, thresholdMs: Int64) -> Bool? {
        guard let encData = Data(base64Encoded: legacyB64) else { return nil }
        let encrypted = kotlinByteArray(from: encData)
        let ctx = kotlinByteArray(from: context)
        let decrypted: KotlinByteArray?
        do {
            decrypted = try crypto.tryDecrypt(ciphertext: encrypted, contextInfo: ctx)
        } catch {
            LogBuffer.shared.append(level: "W", tag: "InactivityWipe", message: "legacy timestamp migration deferred — device key unavailable")
            return nil
        }
        guard let decrypted else {
            LogBuffer.shared.append(level: "W", tag: "InactivityWipe", message: "legacy timestamp failed to decrypt — not treated as tamper, falling back to establish-on-read")
            return nil
        }
        let data = dataFromKotlin(decrypted)
        // Same parser as the steady-state path. A pre-anchor UserDefaults record is by
        // construction the legacy bare-decimal shape (it predates the anchor), so
        // this yields NO_UPTIME and the adopted value keeps being judged on the wall
        // clock until the next touch() re-writes it with an anchor.
        guard let str = String(data: data, encoding: .utf8),
              let stamp = InactivityPolicy.shared.parseStamp(raw: str) else { return nil }

        // The decrypted legacy value is trustworthy — adopt it into the
        // Keychain verbatim (same CryptoProvider context, same ciphertext
        // format; no re-encryption needed) so the on-disk representation
        // matches what touch()/isExpired() write and read from here on.
        KeychainHelper.shared.kvPut(key: key, value: legacyB64)
        guard KeychainHelper.shared.kvGet(key: key).value == legacyB64 else {
            // Write did not land (kvPut fails SILENTLY on a locked keybag).
            // Do NOT arm the marker and do NOT remove the legacy copy — the
            // legacy value is still the only durable copy of the real
            // timestamp, so leave it in place for the next launch to retry.
            // Still answer THIS call's question correctly using the value we
            // already decrypted: the substantive expiry decision is real,
            // only its persistence failed.
            LogBuffer.shared.append(level: "W", tag: "InactivityWipe", message: "legacy timestamp migration write unverified — retrying next launch")
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            return InactivityPolicy.shared.isStampExpired(
                stamp: stamp, nowMs: now, nowUptimeMs: currentUptimeMs(), thresholdMs: thresholdMs)
        }
        armInactivityMarker()
        // Only remove the legacy copy once its replacement is confirmed
        // durable in the Keychain — never before, or a crash between the two
        // writes could lose the only copy of the real timestamp.
        UserDefaults.standard.removeObject(forKey: key)
        LogBuffer.shared.append(level: "I", tag: "InactivityWipe", message: "legacy UserDefaults timestamp migrated to Keychain")

        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let expired = InactivityPolicy.shared.isStampExpired(
            stamp: stamp, nowMs: now, nowUptimeMs: currentUptimeMs(), thresholdMs: thresholdMs)
        if !expired {
            refreshMtimeProbe()
        }
        return expired
    }

    static func clear() {
        // The live copies are in the Keychain KV service now (see touch() /
        // isExpired()) — kvDeleteAll() already sweeps the WHOLE service and is
        // called by every wipe path immediately before clear() (both call
        // sites in AppState.swift call controller.emergencyWipe() —
        // which runs kvDeleteAll() — right before InactivityWipe.clear()), so
        // these two removes are belt-and-suspenders, mirroring the same
        // self-consistency reasoning the probeKey remove below already uses.
        // No IosUserDefaultsKeys.all entry is needed for either key — that
        // list is UserDefaults-only, and both of these live in the Keychain.
        KeychainHelper.shared.kvRemove(key: key)
        KeychainHelper.shared.kvRemove(key: markerKey)
        // Legacy sweep: installs that wrote the timestamp under this SAME key
        // name in UserDefaults before the anchor migration off it (see
        // IosUserDefaultsKeys.INACTIVITY_TS_ENC) may still have a stale copy
        // there.
        UserDefaults.standard.removeObject(forKey: key)
        // Also drop the mtime-dilution probe so
        // this method fully forgets InactivityWipe's UserDefaults footprint. The
        // production wipe already sweeps it via IosUserDefaultsKeys.all; clearing
        // it here too keeps clear() self-consistent (it is called alongside
        // emergencyWipe on both the inactivity-wipe path and the panic-wipe path
        // in AppState.swift).
        UserDefaults.standard.removeObject(forKey: probeKey)
    }

    /// Has the anchor marker been armed? A read failure for ANY reason —
    /// item genuinely absent, OR a transient Keychain error (locked keybag,
    /// errSecInteractionNotAllowed, a -34018-class securityd glitch) — folds
    /// to `false` (not armed): the same fail-toward-NOT-tamper direction
    /// Android's `inactivityMarkerArmed` (catch(Exception) → false) uses. A
    /// locked-keybag read of THIS key must never be read as tamper; folding
    /// it to "not armed" routes the caller to establish-on-read (touch(),
    /// never a wipe). This is deliberately simpler than the tri-state read
    /// used for the TIMESTAMP itself above (which defers instead of folding)
    /// — that one guards the OTHER operand of the tamper/establish decision
    /// and must not silently supply a false "absent" for it; folding is safe
    /// here specifically because every path this function feeds into is
    /// non-destructive on "false".
    private static func inactivityMarkerArmed() -> Bool {
        KeychainHelper.shared.kvGet(key: markerKey).value != nil
    }

    /// Idempotent, best-effort "timestamp has been durably armed at least
    /// once" marker write. Checks presence first so repeated calls don't
    /// re-write, and never throws: kvPut already fails SILENTLY on a locked
    /// keybag (KeychainHelper), so a missed arm here only delays
    /// deletion-tamper detection to the next verified touch(), never crashes
    /// or wipes the launch it runs on. Called ONLY from touch(), and ONLY
    /// after touch() has read back a matching timestamp value — see touch()'s
    /// CRASH-SAFETY note in the header for why that ordering (and not
    /// Android's original apply()-then-commit() shape) is what makes this
    /// safe against a crash between the two writes.
    private static func armInactivityMarker() {
        if KeychainHelper.shared.kvGet(key: markerKey).value != nil { return }
        KeychainHelper.shared.kvPut(key: markerKey, value: "1")
    }

    // MARK: - Helpers

    /// The un-rollable corroborating clock, sampled at the
    /// same instants as the wall clock and sealed into the same AEAD blob.
    /// `ProcessInfo.systemUptime` is boot-relative and cannot be wound by Settings
    /// → General → Date & Time, which is what made "disable automatic time, pin the
    /// date to the seizure day" a permanent disarm of the dead-man's switch.
    /// Identical source to `IosAppController.monotonicSampler`, which feeds
    /// `PinAttemptsStore`'s `windowRolled` — same trust argument, and deliberately
    /// not a second mechanism.
    ///
    /// Honest limitation, and the reason InactivityPolicy treats this as an
    /// ADDITIVE term rather than the source of truth: `systemUptime` is
    /// `mach_absolute_time`-based, so it does NOT advance while the device is in
    /// deep sleep. It therefore UNDERSTATES real elapsed time on an idle phone —
    /// it can only ever make the switch fire late, never early, and the wall-clock
    /// term (which nothing here vetoes) still covers the ordinary case.
    private static func currentUptimeMs() -> Int64 {
        Int64(ProcessInfo.processInfo.systemUptime * 1000.0)
    }

    /// Mitigation (see header): writes [probeKey] — a throwaway
    /// random value, NOT a timestamp, and never read back by anything — so
    /// UserDefaults' backing plist gets a fresh disk write (and therefore a
    /// fresh mtime) on every bare launch that reaches here, not only on a real
    /// vault unlock. Does NOT touch [key] — the real encrypted timestamp, and
    /// the wipe decision above, are unaffected. Best-effort: swallows nothing
    /// because there is nothing here that can throw, but is never allowed to
    /// influence the expiry decision — it only runs after that decision is
    /// already made.
    private static func refreshMtimeProbe() {
        let nonce = (0..<8).map { _ in UInt8.random(in: UInt8.min...UInt8.max) }
        UserDefaults.standard.set(Data(nonce).base64EncodedString(), forKey: probeKey)
    }
}
