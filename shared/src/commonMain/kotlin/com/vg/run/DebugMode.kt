package com.vg.run

import kotlinx.coroutines.withContext

// ---------------------------------------------------------------------------
// Debug mode — the user-consented diagnostic log upload.
//
// THE PRODUCT RULE. A user who is helping debug a
// problem turns "Debug mode" ON behind an explicit consent dialog on either
// platform. While it is on, the app streams its own diagnostic log to the relay
// for development: AS MUCH AS POSSIBLE, but NOTHING that can identify the user
// or the device — no names/aliases, no message content, no addresses, no keys,
// no inbox/contact ids, no network identifiers. Off by default, it survives
// lock (it lives in the platform [KeyValueStore]) and it is cleared by a wipe.
//
// THREE OBJECTS, THREE JOBS:
//   • [DebugMode]         — the consent flag itself: persistence + the runtime
//                           [LoggingState] switch it drives.
//   • [DebugLogRedactor]  — the pure, hand-rolled line scrubber. This is where
//                           the "nothing identifying" half of the product rule
//                           actually lives.
//   • [DebugLogUploader]  — the incremental, cursor-based batch sender.
//
// WHY INCREMENTAL BATCHES AND NOT A SNAPSHOT. The
// interesting logs are usually the ones written just before the app went away —
// a lock, a crash, a force-quit, a Tor recycle. A "collect the buffer and POST
// it" design loses exactly those. So every line gets a process-wide monotonic
// sequence number ([DebugLogSeq]), the uploader keeps a CURSOR, and the
// platforms tick it roughly once a second: each tick ships only what is new and
// advances the cursor ONLY on a confirmed 204, so a failed tick simply re-sends
// the same lines next time instead of dropping them.
//
// WHAT THIS PATH DELIBERATELY DOES NOT DO — it is the same standalone,
// unauthenticated shape as [BugReportSender] and [ConnectTelemetry]:
//   • NO vault, NO contact, NO capability token, NO PoW, NO anti-replay
//     counter. It shares nothing with the message protocol.
//   • NO auth header, NO custom header of any kind. Nothing beyond what every
//     relay call already carries.
//   • NO retry loop, NO persisted queue. A tick that cannot send just does not
//     send; the next tick tries the same lines again. Nothing about the upload
//     is written to disk.
//   • NO new transport. It rides the SAME [RelayHttp] this session already
//     uses (MessageManager.relayTransport()) — Tor SOCKS in production, the
//     direct client only where the app already uses one in debug/emulator.
//
// Known limitation: like [ConnectTelemetry], these POSTs ride the session's
// own Tor circuit, so the relay can correlate a batch with the session that
// sent it. That is inherent — the logs describe that session — which is why the
// body carries nothing the relay does not already see from the connection, and
// why [DebugLogUploader.session] is a per-PROCESS random value that is never
// persisted and never derived from anything about the device.
//
// TWO THINGS THE SESSION TAG DOES THAT THE CIRCUIT DOES NOT, stated plainly:
//   • It RE-JOINS BATCHES ACROSS A CIRCUIT ROTATION. A NEWNYM (the self-heal
//     ladder issues them) gives the next batch a different exit path and a
//     different-looking connection, but the SAME `session` value, so the relay
//     can still link the batches before and after the rotation into one run.
//     That is what the tag is for — it is also exactly what it costs.
//   • It SURVIVES A CONSENT TOGGLE WITHIN ONE PROCESS. Turning Debug mode off
//     and back on again does not re-roll it (it is drawn once, at class init),
//     so the relay sees the two stretches as one run rather than two. Only a
//     process restart draws a new tag.
//
// TIME ON THE WIRE. The uploaded lines do NOT carry the device's wall clock:
// [DebugLogUploader] rewrites every line's `HH:MM:SS.mmm` prefix to `+SSSSS.mmm`
// seconds since a per-process origin, and the batch carries ONE coarse `t0`
// (the origin's epoch seconds, floored to a multiple of 60). A millisecond UTC
// stamp on every line, arriving at 1 Hz, is a clock-skew/drift fingerprint that
// follows a device across sessions; a minute-floored anchor plus relative
// offsets keeps the ordering and the durations, which is all a developer reads.
// ---------------------------------------------------------------------------

/**
 * The process-wide monotonic line counter shared by [LogBuffer] and
 * [ConnectionLog].
 *
 * ONE counter for BOTH buffers on purpose: the uploader merges the two into a
 * single stream and remembers one cursor, so the sequence numbers have to be
 * comparable ACROSS them. Two per-buffer counters would collide and a cursor
 * would silently skip half the lines.
 *
 * Never persisted, never exported, never derived from a clock — it starts at 0
 * in every process and dies with it, so it cannot become a cross-run
 * identifier. It carries its own lock because the two buffers hold DIFFERENT
 * locks; nothing here ever takes a buffer lock, so the nesting
 * (buffer lock → this lock) has one direction and cannot deadlock.
 */
internal object DebugLogSeq {
    private val lock = SyncLock()
    private var counter = 0L

    /** The next sequence number. Called while the caller holds ITS buffer lock. */
    fun next(): Long = lock.withLock { ++counter }

    /** The highest number handed out so far — i.e. "everything up to here exists". */
    fun current(): Long = lock.withLock { counter }
}

/**
 * The consent flag. Persisted in the platform [KeyValueStore] under [KEY] as a
 * DEVICE-KEY AEAD blob sealing the literal value `"1"`; absence — or any value
 * that does not come out of a successful decrypt under [SLOT] — means off.
 *
 * This used to be the bare string `"1"`. On Android it
 * sits in `debug_mode_prefs.xml`, unencrypted and unauthenticated, so anyone who
 * can write the app's files (root, a restored backup, an unlocked-device
 * forensic workflow) could plant six bytes and have a RELEASE build start
 * streaming its redacted diagnostic log to the relay — a consent the user never
 * gave, and one that shows in Settings as ON only if they happen to look. iOS
 * kept the same flag in the Keychain, so this was an Android hole by
 * construction; the fix lives in commonMain anyway so the two platforms cannot
 * drift, and on iOS it simply adds an authentication layer over an item that was
 * already confidentiality-protected.
 *
 * DELIBERATELY NOT MIGRATED. A pre-fix plaintext `"1"` now reads as
 * [SealedPrefState.UNAUTHENTICATED] and therefore OFF, and the user must
 * re-consent. Trusting it once — the shape the push opt-in needs, so
 * real users do not silently lose push — would be exactly the plant this closes:
 * unlike push, nothing breaks for a legitimate user when a diagnostic upload
 * they asked for last week stops, and a developer-support flag is re-armed with
 * one tap. Same reasoning as the internals doc's "do NOT migrate an
 * unauthenticated `vlt_lvl` to an authenticated blob on unlock" rule.
 */
object DebugMode {

    /** [KeyValueStore] key. A sealed `"1"` = on; absent/unauthenticated = off. */
    const val KEY: String = "debug_mode_v1"

    /**
     * The AEAD context this flag's blob is bound to. A NEW string — never
     * one of `VaultSelector`'s — so a blob lifted from any other slot cannot be
     * replayed into this one.
     */
    internal const val SLOT: String = "debug-mode-consent:v1"

    private const val ON_VALUE = "1"

    /**
     * The EXPLICIT off value, written only when [setEnabledIn] cannot get the
     * key removed (a store that refuses/ignores the delete). Absence still
     * means off — this is the belt for a store that cannot forget, and
     * [isEnabledIn]'s proven-`ON_VALUE` test already reads it as off.
     *
     * Deliberately written as PLAINTEXT, not sealed: this is the revocation
     * belt, and it has to be writable in exactly the state where sealing cannot
     * happen (the device key transiently unavailable — a locked screen on
     * Android, a locked keybag on iOS). An unsealed value reads OFF under the
     * sealed-flag reader whatever it says, so the weaker write is also the safe one.
     */
    private const val OFF_VALUE = "0"

    /**
     * True when the user has consented and not revoked.
     *
     * FAILS TOWARD OFF. The iOS store throws [KeyUnavailableException] on a
     * transient Keychain failure (locked keybag, securityd glitch); every other
     * consumer of that tri-state has to fail toward "defer" because guessing
     * costs data. Here the safe guess is unambiguous and it is `false`: the
     * only consequence of a wrong `false` is that a batch is not uploaded,
     * whereas a wrong `true` would upload diagnostics the user may have
     * revoked consent for. Never reverse this.
     *
     * That same `false` also covers an UNAUTHENTICATED value — a
     * plant, or a legacy plaintext `"1"` from before this fix.
     */
    fun isEnabled(store: KeyValueStore, crypto: CryptoProvider): Boolean =
        isEnabledIn(store.asDebugModeStore(), crypto.asDeviceKeyCipher())

    /**
     * Persists the choice and applies it to this process.
     *
     * ON flips [LoggingState.enabled] to true **even in a RELEASE build** —
     * that is the entire point of the feature. `scripts/verify-release-clean.sh` still pins the DEFAULT to `false`,
     * which is the property that actually matters: a production build that the
     * user never consented on logs nothing.
     *
     * OFF flips it back to false, drops [LogBuffer]'s buffered entries, and
     * forgets the key — or, when the store will not forget it, overwrites it
     * with [OFF_VALUE], which [isEnabled] reads exactly like absence.
     * [ConnectionLog] is deliberately NOT cleared: its ring is
     * live in release builds regardless of this feature (a user stuck on
     * "Connecting…" reads it out of the panel), so clearing it here would take
     * away a diagnostic the user did not ask to lose. Nothing in it can be
     * uploaded once the flag is off.
     *
     * BOTH directions reset the uploader cursor, and that is load-bearing on
     * the ON path: [ConnectionLog] has been recording since app start, so
     * without the reset the very first batch after consent would ship every
     * line buffered BEFORE the user consented. Consent is not retroactive.
     *
     * Ordering: the persist is attempted FIRST in BOTH directions, and only
     * then is the runtime switch flipped. ON has always worked that way (a
     * failed write still enables the session — see below); OFF now does too, so
     * that a store which refuses the delete can be caught and overwritten with
     * an explicit [OFF_VALUE] while this call is still running. The session
     * stops logging either way; what the ordering buys is that "off" STICKS
     * across the next launch.
     *
     * @return the consent flag AS IT NOW STANDS, which is what both UIs bind
     * their toggle to. ON returns true even when the persist failed (the
     * session really is on — showing "off" while the app uploads would be the
     * dangerous lie). OFF returns false only when the store CONFIRMED the flag
     * is no longer `"1"`; if it could neither remove nor overwrite the key, it
     * returns true, because the next launch will read consent again and the
     * user must see that rather than a toggle that quietly re-arms itself.
     */
    fun setEnabled(store: KeyValueStore, crypto: CryptoProvider, on: Boolean): Boolean =
        setEnabledIn(store.asDebugModeStore(), crypto.asDeviceKeyCipher(), on)

    /**
     * Called ONCE at app start by each platform, after the store is available.
     *
     * Only ever turns logging ON, never off — DEBUG builds flip
     * [LoggingState.enabled] on unconditionally at their own entry points
     * (RunApplication.onCreate / RunApp.init) for the in-app log viewer and the
     * e2e suites, and writing `false` here would silently switch that off for
     * every debug build. "Debug mode was never enabled" means "leave the flag
     * exactly as this build set it", not "force it off".
     *
     * Always resets the cursor: a new process must not re-upload the tail of
     * the previous run (those lines are gone from the buffers anyway, and the
     * counter restarts at 0).
     */
    fun applyAtStartup(store: KeyValueStore, crypto: CryptoProvider) =
        applyAtStartupIn(store.asDebugModeStore(), crypto.asDeviceKeyCipher())

    /**
     * Re-reads the persisted consent at a moment the store is KNOWN readable and
     * turns logging on if it says so. Never turns it off.
     *
     * WHY (prod, 2026-09-20). On iOS the flag lives in the Keychain under the
     * unlocked-only accessibility class, and [applyAtStartup] runs in the app's
     * first initializer — before protected data is guaranteed available (a push
     * wake, a launch from the lock screen, the first instants after unlock). That
     * read fails, [isEnabledIn] deliberately reads the failure as OFF, and nothing
     * re-read it for the life of the process: the Settings row (read later, phone
     * unlocked) showed ON while the connect flush and the periodic loop, gated on
     * the cached startup answer, uploaded nothing. Two cold relaunches of a phone
     * with the flag provably persisted ("debug mode set to true (persisted true)")
     * reached the relay as connect telemetry and shipped zero batches. Debug
     * builds mask it: they force [LoggingState.enabled] on regardless.
     *
     * Called from the vault-open path (both platforms), which is by construction
     * the earliest point the keybag is unlocked. Only ever ENABLES: an unreadable
     * or absent flag here changes nothing, so a revoked consent (an explicit "0",
     * or a wipe having removed the key) is never resurrected — the OFF direction
     * stays the exclusive job of [setEnabled] and the wipe paths.
     *
     * This call is load-bearing on ANDROID too, where it previously only
     * ever confirmed what [applyAtStartup] already knew. The flag is now sealed
     * under the device key, and the Android device key is minted with
     * `setUnlockedDeviceRequired(true)` (`CryptoManager.buildMasterKeySpec`) —
     * so a process started by a push wake on a LOCKED screen reads
     * [SealedPrefState.UNREADABLE] at startup, exactly like iOS's locked keybag.
     * The vault-open re-apply is what turns consent back on in that session.
     *
     * @return true when the persisted flag reads ON (whether or not logging was
     *   already on), so the caller can refresh its own cached copy.
     */
    fun reapplyPersisted(store: KeyValueStore, crypto: CryptoProvider): Boolean =
        reapplyPersistedIn(store.asDebugModeStore(), crypto.asDeviceKeyCipher())

    internal fun reapplyPersistedIn(store: DebugModeStore, cipher: DeviceKeyCipher): Boolean =
        reapplyPersistedTriStateIn(store, cipher) == PERSISTED_ON

    /** [reapplyPersistedTriState] answers. */
    const val PERSISTED_ON: Int = 1
    const val PERSISTED_OFF: Int = 0
    /** The store could not be read (locked keybag / securityd glitch) — retry later. */
    const val PERSISTED_UNREADABLE: Int = -1

    /**
     * [reapplyPersisted] with the failure distinguished from a genuine OFF, so a
     * caller that RETRIES (the iOS periodic loop, 2026-09-21) can stop retrying
     * on a definite "0"/absent and keep retrying only while the Keychain is
     * unreadable. Enables logging exactly as [reapplyPersisted] does on ON.
     */
    fun reapplyPersistedTriState(store: KeyValueStore, crypto: CryptoProvider): Int =
        reapplyPersistedTriStateIn(store.asDebugModeStore(), crypto.asDeviceKeyCipher())

    internal fun reapplyPersistedTriStateIn(store: DebugModeStore, cipher: DeviceKeyCipher): Int {
        val read = try {
            SealedPref.open(cipher, SLOT, store.get(KEY))
        } catch (_: Exception) {
            return PERSISTED_UNREADABLE
        }
        // Only a PROVEN read decides. An UNREADABLE one keeps the iOS
        // periodic retry going (that is what this tri-state exists for);
        // ABSENT and UNAUTHENTICATED are both a definite OFF — a planted or
        // legacy-plaintext `"1"` must stop the retry, not drive it.
        if (read.state == SealedPrefState.UNREADABLE) return PERSISTED_UNREADABLE
        if (!(read.proven && read.value == ON_VALUE)) return PERSISTED_OFF
        if (!LoggingState.enabled) {
            DebugLogUploader.resetCursor()
            LoggingState.enabled = true
        }
        return PERSISTED_ON
    }

    // -- internal seam -------------------------------------------------------
    //
    // [KeyValueStore] is an `expect class` whose actuals need a platform handle
    // (an Android Context / the iOS Keychain bridge), so commonTest cannot
    // construct one — the same constraint DbKeyRotationTest and
    // ProvisionWriteGuardTest document. These three take a tiny interface
    // instead so the behaviour is unit-testable without a platform.

    internal fun isEnabledIn(store: DebugModeStore, cipher: DeviceKeyCipher): Boolean = try {
        val read = SealedPref.open(cipher, SLOT, store.get(KEY))
        read.proven && read.value == ON_VALUE
    } catch (_: Exception) {
        false
    }

    internal fun setEnabledIn(store: DebugModeStore, cipher: DeviceKeyCipher, on: Boolean): Boolean {
        if (on) {
            try {
                store.putSync(KEY, SealedPref.seal(cipher, SLOT, ON_VALUE))
            } catch (_: Exception) {
                // A store that refuses the write — or, since the flag is sealed, a device key
                // that cannot seal right now — leaves the flag off on the next
                // launch; enabling this session anyway is the lesser evil (the
                // user chose it and can re-enable), and it is bounded by the
                // process lifetime. It is also nearly unreachable on this path:
                // the consent dialog is only reachable from an UNLOCKED, open
                // session, which is exactly when the device key works.
            }
            DebugLogUploader.resetCursor()
            LoggingState.enabled = true
            return true
        }
        // OFF. The persist goes FIRST — while the flag is still "on" there is
        // nothing to lose by trying, and a store that refuses the delete has to
        // be caught HERE, where we can still overwrite the key with an explicit
        // OFF_VALUE. (iOS Keychain deletes fail on a locked keybag; before this,
        // the delete's failure was unobservable and a revoked consent silently
        // came back on at the next launch.)
        val persistedOff = revokePersisted(store, cipher)
        // `isDebugBuild`, never a bare `false`: a debug build enables logging
        // for its own reasons (log viewer, e2e capture) and must keep it — the
        // same rule applyAtStartupIn's kdoc and both wipe paths follow.
        LoggingState.enabled = isDebugBuild
        LogBuffer.clear()
        DebugLogUploader.resetCursor()
        return !persistedOff
    }

    /**
     * Best effort to make the store stop reading [ON_VALUE]: remove, verify,
     * and if the key is still on, overwrite it with [OFF_VALUE] and verify
     * again. True only when the flag is CONFIRMED no longer on — an
     * unreadable store is not a confirmation (see [setEnabled]'s @return).
     */
    private fun revokePersisted(store: DebugModeStore, cipher: DeviceKeyCipher): Boolean {
        val removed = try {
            store.remove(KEY)
        } catch (_: Exception) {
            false
        }
        if (removed && readIsOff(store, cipher) == true) return true
        // The remove was refused, ignored, or unverifiable. An explicit "0" is
        // as good as absence everywhere it is read ([isEnabledIn]) and a WRITE
        // can succeed where a delete did not. Written UNSEALED on purpose — see
        // [OFF_VALUE]: revocation must work even when the device key does not.
        try {
            store.putSync(KEY, OFF_VALUE)
        } catch (_: Exception) {
            return false
        }
        return readIsOff(store, cipher) == true
    }

    /**
     * True/false when the store answered, null when it could not be read.
     *
     * "off" is now "not a PROVEN [ON_VALUE]", so an unsealed [OFF_VALUE],
     * a legacy plaintext `"1"` and a plant all confirm off. An UNREADABLE device
     * key confirms NOTHING — it is mapped to null, so [revokePersisted] does not
     * report a revocation it cannot see.
     */
    private fun readIsOff(store: DebugModeStore, cipher: DeviceKeyCipher): Boolean? = try {
        val read = SealedPref.open(cipher, SLOT, store.get(KEY))
        if (read.state == SealedPrefState.UNREADABLE) null else !(read.proven && read.value == ON_VALUE)
    } catch (_: Exception) {
        null
    }

    internal fun applyAtStartupIn(store: DebugModeStore, cipher: DeviceKeyCipher) {
        DebugLogUploader.resetCursor()
        if (isEnabledIn(store, cipher)) LoggingState.enabled = true
    }
}

/**
 * The three [KeyValueStore] operations [DebugMode] needs, as an interface
 * commonTest can implement. See the seam note in [DebugMode].
 */
internal interface DebugModeStore {
    fun get(key: String): String?
    fun putSync(key: String, value: String)
    /** True when the key is confirmed gone — see [KeyValueStore.remove]. */
    fun remove(key: String): Boolean
}

/** Adapts the platform store. [putStringSync] because a consent flag is a
 *  state transition, not a hint — it must survive a force-quit. */
internal fun KeyValueStore.asDebugModeStore(): DebugModeStore {
    val self = this
    return object : DebugModeStore {
        override fun get(key: String): String? = self.getString(key)
        override fun putSync(key: String, value: String) = self.putStringSync(key, value)
        override fun remove(key: String): Boolean = self.remove(key)
    }
}

// ---------------------------------------------------------------------------

/**
 * Scrubs ONE already-formatted log line so that what is left is useful to a
 * developer and useless to anyone trying to identify the user or the device.
 *
 * Input is either a [LogEntry.formatted] line (`HH:MM:SS.mmm D/Tag: message`)
 * or a [ConnectionLog.Line.formatted] line (`HH:mm:ss.SSS KIND text`). The
 * PREFIX — clock plus level/tag or kind — is kept VERBATIM; everything after it
 * is the message and goes through the ladder below. Keeping the prefix out of
 * the scrubber is what lets rule 3 be aggressive: a tag like `Argon2` or
 * `L10nFormat` would otherwise be mangled into a placeholder.
 *
 * THE LADDER, in EXECUTION order ([LADDER] is its executable form, pinned by
 * DebugLogRedactorLadderOrderTest; over-redaction is fine, under-redaction is
 * a bug):
 *  1a. `http(s)://…` / `ws(s)://…` up to whitespace ⇒ `[url]`.
 *  1b. any `.onion` host ⇒ `[onion]`.
 *  1c. IPv4 and bracketed/unbracketed IPv6 literals, with an optional `:port`,
 *     ⇒ `[ip]` — also when trailing `.`/`:` punctuation follows the literal.
 *  2. Quoted strings (`"…"`, `'…'`, `“…”`) ⇒ `[str]` — aliases, group titles,
 *     message text and JSON string values all arrive quoted.
 *  3a. TRUNCATION MARKER. Any run of `[A-Za-z0-9_-]` of 4 or more characters
 *     immediately followed by `...` or `…` ⇒ `[id]`. That ellipsis is the
 *     PRODUCERS' OWN marker: call sites (mostly MessageManager) log `${inboxId.take(8)}...`, and
 *     the 8-char prefix they emit is the single most common identifier shape in
 *     the whole log. It is caught here on the SHAPE of the truncation, not on
 *     the contents of the prefix, so a prefix that happens to be all letters is
 *     caught just the same. See the known-limitations note below for why that matters.
 *  3b. LABEL. After an identifier label — `inbox`, `inboxId`, `contact`,
 *     `contactId`, `group`, `groupId`, `cap`, `token`, `peer`, `target` as a
 *     whole word, or anything ending in `…id=`, `…cap=`, `…inbox=`, `…from=`,
 *     `…to=`, `…ref=`, `…intro=`, `…session=` and friends at a camelCase or
 *     `_`/`-` boundary — an optional `=`/`:`/space and then a run of 4 or more
 *     `[A-Za-z0-9_-]` ⇒ `[id]`. The LABEL itself is kept: `contactId=[id]` is
 *     exactly as readable as `contactId=aB3dEfG7` and carries nothing. A value
 *     that is itself a label starts the next label, so in a CHAIN the id after
 *     the last label is the one taken: `contact inbox aBcD…` ⇒ `contact inbox [id]`.
 *  3c. CASE TRANSITIONS. A PURE-LETTER run of 8 or more characters with 3 or
 *     more lower→upper transitions ⇒ `[id]`. Identifier alphabets mix case at
 *     random (~1.75 such transitions in 8 base64url letters, and the tail past
 *     3 is thick); hand-written CamelCase names do not — `MessageManager`,
 *     `ReferralManager`, `GroupManager`, `PeekTarget`, `KeychainHelper`,
 *     `TorManager` all have exactly 1 and `Bootstrapped` has 0.
 *  3 + 4a + 4b (ONE token pass). Any run of `[A-Za-z0-9_-]` of 8 or more
 *     characters containing at least one digit OR at least one `-`/`_` ⇒ a
 *     placeholder: `[num]` for a digit run of 10+ (epoch millis, 4b), `[hex]`
 *     for a hex run of 8+ (4a), `[id]` otherwise. That covers the
 *     18-char contact id, the 8-char shortId, the 32-char inbox id, the 43-char
 *     capability, base64 keys and tokens. PURE-LETTER runs survive THIS rule,
 *     which is what keeps `MessageManager` and `Bootstrapped` readable — 3a,
 *     3b and 3c are what close the pure-letter hole for the shapes that
 *     actually carry identifiers.
 *     ONE EXPLICIT EXCEPTION: a run that EXACTLY equals one of
 *     Tor's fixed REASON keywords ([TorReasonVocabulary.DEBUG_PASSTHROUGH] —
 *     `QUERY_NO_HSDIR`, `NOT_FOUND`, `CHANNEL_CLOSED`, `CLOCK_JUMPED`, …) is
 *     kept verbatim. Those are protocol constants identical on every client,
 *     and `[id]` erased precisely the word that explains a stalled connect.
 *     An allowlist of whole words, case-sensitive — never a loosening of the
 *     rule: an id, a capability or an onion still lands on its placeholder.
 *  4c. Path-like tokens (a `/`, two or more segments, and either a leading `/`
 *     or `~/` or a segment containing a letter) ⇒ `[path]`.
 *  5. After `alias=`, `name=`, `text=`, `title=`, `body=` (case-insensitive,
 *     anywhere in the token so `displayName=` and `groupName=` are covered)
 *     ⇒ `[str]`.
 *  7. CONTACT-GRAPH COUNTS. An integer immediately followed by a space and one
 *     of `contact(s)`, `inbox(es)`, `group(s)`, `member(s)`, `peer(s)`,
 *     `target(s)`, `referral(s)`, `row(s)` ⇒ a bucket: `0`, `1-5`, `6-20`,
 *     `20+`. "17 contacts" is a stable, unusual number — across a few batches
 *     it is a fingerprint of the user's social graph, and the exact value tells
 *     a developer nothing that the bucket does not. A digit run that is the
 *     VALUE of a `<word>=` label (`code=200`, `status=404`) is NEVER a count,
 *     however close a count noun sits behind it.
 *  6. [ConnectionLog.redact] as a final pass, so this is never WEAKER than the
 *     scrubber the release-visible connection panel already applies. It stays
 *     LAST despite the number — rule 7 runs just before it.
 *
 * Rules 3, 4a and 4b are evaluated in ONE token pass that tries the most
 * specific label first (`[num]`, then `[hex]`, then `[id]`). The SET of tokens
 * redacted is identical to running them separately — every token rule 3 would
 * take is also taken here — only the placeholder is more informative.
 *
 * HAND-ROLLED, NOT [Regex] — the Kotlin/Native stack-safety rule
 * [ConnectionLog.redact] and `UpdateCheck.parseAppVersion` already follow. A
 * backtracking engine on a 500-line batch is both a stack risk on K/N and a
 * pointless CPU cost on the log path.
 *
 * Known limitations, stated plainly:
 *  • A pure-letter run of 8+ characters still survives rule 3 itself, and 3c
 *    only catches the case-mixed share of them. The number that matters: an
 *    8-character base64url prefix is ALL LETTERS with probability
 *    (52/64)^8 − (12/64)^8 ≈ 19 % — roughly one prefix in five, NOT the "1 in
 *    10^4" this comment claimed before 2026-09-14. That is why 3a and 3b exist:
 *    every producer of a `take(8)` prefix in this app writes it either with the
 *    `...` marker or behind a label, so the prefix is caught on its CONTEXT and
 *    the 19 % never becomes a leak. A NEW producer that logs a bare prefix with
 *    neither marker nor label is the remaining hole — rule 3c catches ~24 % of
 *    those, rule 3 the other 81 % of prefixes, and the rest survives. Add the
 *    marker or the label at the producer; do not rely on 3c alone. Better:
 *    log no identifier at all — `LogLineNoIdentifierSourceGuardTest`
 *    (androidUnitTest) fails on a `take(N)` or an exception message inside ANY
 *    commonMain log call (its exception list is empty).
 *  • A bare FULL contactId (24 base64url chars) survives only when it is all
 *    letters with fewer than 3 lower→upper transitions — about 2.5e-5 of ids
 *    (DebugModeRedactorPropertyTest, I5). The producer guard is the fix for it.
 *  • Rule 5 consumes the REST OF THE LINE, not just the token: a name or a
 *    message body contains spaces, and stopping at the first one would leak
 *    everything after it.
 *  • 3a, 3b and 3c OVER-REDACT ordinary prose, by design and in the safe
 *    direction: `Connecting...` becomes `[id]...` (a prose ellipsis looks
 *    exactly like a truncation marker), the word after a bare label goes with
 *    it (`contact added:` ⇒ `contact [id]:`), and an unusually case-mixed class
 *    name such as `AesGcmBridgeHolder` (3 transitions) is redacted. Losing a
 *    word of narration is cheap; losing an identifier is not.
 *  • Small numbers, percentages and plain prose pass through untouched. That is
 *    the point — `Bootstrapped 45%` has to survive for the logs to be worth
 *    uploading at all. Rule 7 buckets ONLY a number that a count noun follows,
 *    so timings (`in 4.2 s`), ratios (`3/3 answered`) and percentages are not
 *    touched.
 */
object DebugLogRedactor {

    const val PLACEHOLDER_URL: String = "[url]"
    const val PLACEHOLDER_ONION: String = "[onion]"
    const val PLACEHOLDER_IP: String = "[ip]"
    const val PLACEHOLDER_STR: String = "[str]"
    const val PLACEHOLDER_ID: String = "[id]"
    const val PLACEHOLDER_HEX: String = "[hex]"
    const val PLACEHOLDER_NUM: String = "[num]"
    const val PLACEHOLDER_PATH: String = "[path]"

    /** Rule 3's run length: the shortest identifier the app emits is an 8-char shortId. */
    internal const val MIN_ID_RUN: Int = 8

    /** Rule 4: the shortest hex run treated as a fingerprint/digest fragment. */
    internal const val MIN_HEX_RUN: Int = 8

    /** Rule 4: epoch millis is 13 digits; 10 is the conservative floor. */
    internal const val MIN_NUM_RUN: Int = 10

    /**
     * Rules 3a and 3b: how short a run behind a truncation marker or a label is
     * still treated as an identifier. 4, not 8 — `${id.take(8)}...` is the
     * common shape but `take(6)` and `take(4)` exist too, and behind a marker
     * or a label there is nothing a short run could be EXCEPT an identifier.
     */
    internal const val MIN_MARKED_RUN: Int = 4

    /** Rule 3c: how many lower→upper transitions make a pure-letter run an id. */
    internal const val MIN_CASE_TRANSITIONS: Int = 3

    private val URL_SCHEMES = listOf("https://", "http://", "wss://", "ws://")

    /** Rule 5's keys. Matched case-insensitively ANYWHERE in a token. */
    private val VALUE_LABELS = listOf("alias=", "name=", "text=", "title=", "body=")

    /**
     * Rule 3b, bare form: the WHOLE run must equal one of these
     * (case-insensitively) for the next run to be an identifier. Equality, not
     * containment — `target` must not match inside `PeekTarget`, or the
     * READABLE half of `PeekTarget(contactId=…)` would go too.
     */
    private val ID_LABELS_BARE = listOf(
        "inbox", "inboxid", "contact", "contactid", "group", "groupid",
        "cap", "token", "peer", "target",
    )

    /**
     * Rule 3b, `=` form: the run is followed by `=` and ENDS WITH one of these
     * at a boundary (whole run, a camelCase hump, or after `_`/`-`), so
     * `contactId=`, `readCap=` and `targetInbox=` all match while `valid=` and
     * `android=` do not.
     */
    private val ID_LABELS_EQ = listOf(
        "inbox", "contact", "group", "id", "cap", "token", "peer",
        "from", "to", "target", "ref", "intro", "introid", "session",
    )

    /** Rule 7's nouns. An integer directly in front of one of these is a count. */
    private val COUNT_NOUNS = listOf(
        "contact", "contacts", "inbox", "inboxes", "group", "groups",
        "member", "members", "peer", "peers", "target", "targets",
        "referral", "referrals", "row", "rows",
    )

    /** Rule 7's buckets. `0` stays exact — "none" is not a graph fingerprint. */
    internal const val BUCKET_ZERO: String = "0"
    internal const val BUCKET_SMALL: String = "1-5"
    internal const val BUCKET_MEDIUM: String = "6-20"
    internal const val BUCKET_LARGE: String = "20+"

    /**
     * The whole ladder, prefix preserved. Pure: no clock read, no buffer
     * access, no allocation beyond the rebuilt string.
     */
    fun redactLine(line: String): String {
        val split = prefixLength(line)
        if (split <= 0) return redactMessage(line)
        return line.substring(0, split) + redactMessage(line.substring(split))
    }

    /**
     * Length of the verbatim prefix: `HH:MM:SS.mmm ` plus either `LEVEL/Tag: `
     * ([LogEntry.formatted]) or `KIND ` ([ConnectionLog.Line.formatted]).
     * 0 when the line does not start with a clock at all — then the whole line
     * is treated as message, which is the safe direction.
     */
    internal fun prefixLength(line: String): Int {
        if (!startsWithClock(line)) return 0
        val afterClock = CLOCK_LEN
        // "D/Tag: " — a single-letter level, a slash, a tag, ": ".
        if (afterClock + 1 < line.length && isAsciiLetter(line[afterClock]) && line[afterClock + 1] == '/') {
            var j = afterClock + 2
            while (j < line.length && isTagChar(line[j])) j++
            if (j > afterClock + 2 && j + 1 < line.length && line[j] == ':' && line[j + 1] == ' ') return j + 2
        }
        // "KIND " — ConnectionLog renders the enum name, which is upper-case only.
        var k = afterClock
        while (k < line.length && line[k] in 'A'..'Z') k++
        if (k > afterClock && k < line.length && line[k] == ' ') return k + 1
        return afterClock
    }

    // One pass of the ladder: its rule id (as cited in the class kdoc and the
    // tests) and the function that applies it.
    internal class Pass(val rule: String, val apply: (String) -> String)

    // THE LADDER, in EXECUTION order. The order is load-bearing (see the class
    // kdoc): 1a before 1b (an onion inside a URL takes its path with it); 2 before
    // 3a/3b (a quoted alias is gone before labels look at it); 3a and 3b before
    // 3+4ab (a labelled pure-letter prefix is only caught there, and
    // `contactId=<hex>` lands on `[id]`, not `[hex]`); 3+4ab before 7 (a 10+ digit
    // run is `[num]` before counting); 6 LAST (it catches a long pure-letter run
    // that survived 3c and 3+4ab). `DebugLogRedactorLadderOrderTest` pins it.
    internal val LADDER: List<Pass> = listOf(
        Pass("1a") { stripUrls(it) },
        Pass("1b") { ConnectionLog.stripOnionHosts(it) },
        Pass("1c") { stripIpLiterals(it) },
        Pass("2") { stripQuoted(it) },
        Pass("3a") { stripTruncatedIds(it) },
        Pass("3b") { stripLabelledIds(it) },
        Pass("3c") { stripCaseMixedIds(it) },
        Pass("3+4ab") { stripOpaqueTokens(it) },
        Pass("4c") { stripPaths(it) },
        Pass("5") { stripLabelledValues(it) },
        Pass("7") { bucketCounts(it) },
        Pass("6") { ConnectionLog.redact(it) },
    )

    /** The ladder applied to a message with no prefix of its own. */
    internal fun redactMessage(message: String): String = LADDER.fold(message) { s, pass -> pass.apply(s) }

    // -- rule 1 --------------------------------------------------------------

    /** `http(s)://…` / `ws(s)://…` up to the next whitespace ⇒ [PLACEHOLDER_URL]. */
    private fun stripUrls(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val scheme = URL_SCHEMES.firstOrNull { s.regionMatches(i, it, 0, it.length, ignoreCase = true) }
            if (scheme != null) {
                sb.append(PLACEHOLDER_URL)
                while (i < s.length && !s[i].isWhitespace()) i++
            } else {
                sb.append(s[i])
                i++
            }
        }
        return sb.toString()
    }

    // Rule 1b is [ConnectionLog.stripOnionHosts]: the same `[A-Za-z0-9_.-]` host
    // class, the same `.onion` test and the same `[onion]` placeholder.

    /**
     * IPv4 (`1.2.3.4`, `1.2.3.4:9001`) and IPv6 (`[2001:db8::1]:443`,
     * `2001:db8::1`) literals ⇒ [PLACEHOLDER_IP].
     *
     * Bracketed IPv6 is matched first so the brackets go with it. The
     * unbracketed scan takes a maximal run of `[0-9a-fA-F:.]` and only replaces
     * it when it actually parses — so `1.8 s` (the health-probe timing),
     * `probe #1:` and a `1.6.17` app version are all left alone, while a
     * 4-group dotted quad is not.
     */
    private fun stripIpLiterals(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '[') {
                val close = s.indexOf(']', i + 1)
                if (close > i + 1 && looksLikeIpv6(s.substring(i + 1, close))) {
                    sb.append(PLACEHOLDER_IP)
                    i = skipPort(s, close + 1)
                    continue
                }
                sb.append(c)
                i++
                continue
            }
            if (isIpRunChar(c)) {
                var j = i
                while (j < s.length && isIpRunChar(s[j])) j++
                // Trailing `.`/`:` is sentence or list punctuation (`… 1.2.3.4.`,
                // `1.2.3.4...`, `1.2.3.4:`), not part of the literal: retry the
                // parse without it so the address still goes (and the punctuation
                // stays). Only ever redacts MORE: the trimmed run must still parse.
                var end = j
                while (end > i && !looksLikeIp(s.substring(i, end)) && (s[end - 1] == '.' || s[end - 1] == ':')) end--
                if (end > i && looksLikeIp(s.substring(i, end))) {
                    sb.append(PLACEHOLDER_IP)
                    sb.append(s.substring(end, j))
                } else {
                    sb.append(s.substring(i, j))
                }
                i = j
                continue
            }
            sb.append(c)
            i++
        }
        return sb.toString()
    }

    private fun looksLikeIp(run: String): Boolean = looksLikeIpv4WithOptionalPort(run) || looksLikeIpv6(run)

    /** Consumes a trailing `:1234` after a bracketed IPv6 literal. */
    private fun skipPort(s: String, from: Int): Int {
        if (from >= s.length || s[from] != ':') return from
        var j = from + 1
        while (j < s.length && s[j] in '0'..'9') j++
        return if (j > from + 1) j else from
    }

    private fun looksLikeIpv4WithOptionalPort(run: String): Boolean {
        val colon = run.indexOf(':')
        val host = if (colon >= 0) run.substring(0, colon) else run
        if (colon >= 0) {
            val port = run.substring(colon + 1)
            if (port.isEmpty() || port.length > 5 || port.any { it !in '0'..'9' }) return false
        }
        val parts = host.split('.')
        if (parts.size != 4) return false
        for (p in parts) {
            if (p.isEmpty() || p.length > 3) return false
            var v = 0
            for (ch in p) {
                if (ch !in '0'..'9') return false
                v = v * 10 + (ch - '0')
            }
            if (v > 255) return false
        }
        return true
    }

    /**
     * At least two colons and every non-empty group a 1-4 digit hex number (an
     * IPv4-mapped tail is allowed). Deliberately loose — it is a redaction
     * trigger, not a parser, and a false positive costs nothing.
     */
    private fun looksLikeIpv6(run: String): Boolean {
        if (run.isEmpty()) return false
        var colons = 0
        for (ch in run) if (ch == ':') colons++
        if (colons < 2) return false
        for (group in run.split(':')) {
            if (group.isEmpty()) continue
            if (group.contains('.')) {
                if (!looksLikeIpv4WithOptionalPort(group)) return false
                continue
            }
            if (group.length > 4) return false
            for (ch in group) if (!isHexChar(ch)) return false
        }
        return true
    }

    // -- rule 2 --------------------------------------------------------------

    /**
     * Quoted strings ⇒ [PLACEHOLDER_STR].
     *
     * A double or curly quote always opens — an unterminated one swallows the
     * rest of the line, because a stray `"` in a log line is far more likely to
     * be the start of user content than punctuation. A SINGLE quote is treated
     * as an apostrophe unless it is both preceded and followed by a non
     * alphanumeric, so `don't` and `Tor's` stay intact while `'Family'` does
     * not.
     */
    private fun stripQuoted(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            when (val c = s[i]) {
                '"' -> {
                    val close = s.indexOf('"', i + 1)
                    sb.append(PLACEHOLDER_STR)
                    i = if (close >= 0) close + 1 else s.length
                }
                '“', '”' -> {
                    var close = -1
                    var j = i + 1
                    while (j < s.length) {
                        if (s[j] == '”' || s[j] == '“') { close = j; break }
                        j++
                    }
                    sb.append(PLACEHOLDER_STR)
                    i = if (close >= 0) close + 1 else s.length
                }
                '\'' -> {
                    val openerOk = i == 0 || !isAsciiAlnum(s[i - 1])
                    val close = if (openerOk) s.indexOf('\'', i + 1) else -1
                    val closeOk = close > i && (close + 1 >= s.length || !isAsciiAlnum(s[close + 1]))
                    if (closeOk) {
                        sb.append(PLACEHOLDER_STR)
                        i = close + 1
                    } else {
                        sb.append(c)
                        i++
                    }
                }
                else -> {
                    sb.append(c)
                    i++
                }
            }
        }
        return sb.toString()
    }

    // -- rule 3a ---------------------------------------------------------------

    /**
     * A run of [MIN_MARKED_RUN]+ id characters immediately followed by `...` or
     * `…` ⇒ [PLACEHOLDER_ID]; the marker itself is kept, so the reader still
     * sees that the producer truncated something.
     *
     * This is the rule that closes the `${inboxId.take(8)}...` hole. It keys on
     * the MARKER, never on the contents of the run, so an all-letter prefix —
     * ≈ 19 % of them — is caught exactly like a mixed one.
     */
    private fun stripTruncatedIds(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            if (!isIdChar(s[i])) {
                sb.append(s[i])
                i++
                continue
            }
            var j = i
            while (j < s.length && isIdChar(s[j])) j++
            sb.append(if (j - i >= MIN_MARKED_RUN && isEllipsisAt(s, j)) PLACEHOLDER_ID else s.substring(i, j))
            i = j
        }
        return sb.toString()
    }

    /** `…` or `...` starting at [at]. */
    private fun isEllipsisAt(s: String, at: Int): Boolean {
        if (at >= s.length) return false
        if (s[at] == '…') return true
        return s[at] == '.' && at + 2 < s.length && s[at + 1] == '.' && s[at + 2] == '.'
    }

    // -- rule 3b ---------------------------------------------------------------

    /**
     * After an identifier label (see [ID_LABELS_BARE] / [ID_LABELS_EQ]) and an
     * optional `=`/`:`/space separator, a run of [MIN_MARKED_RUN]+ id
     * characters ⇒ [PLACEHOLDER_ID]. The label is kept verbatim.
     *
     * The value must follow IMMEDIATELY (at most one separator, plus one space
     * after an `=`/`:`). Scanning further would eat the wrong token —
     * `group [str] renamed` would lose `renamed` — and the whole point is that
     * what is redacted stays predictable.
     */
    private fun stripLabelledIds(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            if (!isIdChar(s[i])) {
                sb.append(s[i])
                i++
                continue
            }
            var j = i
            while (j < s.length && isIdChar(s[j])) j++
            val run = s.substring(i, j)
            sb.append(run)
            i = j
            if (!isIdLabel(run, if (j < s.length) s[j] else ' ')) continue

            var k = j
            if (k < s.length && (s[k] == '=' || s[k] == ':')) {
                sb.append(s[k])
                k++
                if (k < s.length && s[k] == ' ') {
                    sb.append(' ')
                    k++
                }
            } else if (k < s.length && s[k] == ' ') {
                sb.append(' ')
                k++
            } else {
                continue
            }

            var v = k
            while (v < s.length && isIdChar(s[v])) v++
            if (v - k >= MIN_MARKED_RUN && !isIdLabel(s.substring(k, v), if (v < s.length) s[v] else ' ')) {
                sb.append(PLACEHOLDER_ID)
                i = v
            } else {
                // Too short to be an id, or itself a LABEL (`contact inbox abcd…`):
                // left for the loop, which reads a label as the NEXT label, so the
                // id after a chain of labels is still taken.
                i = k
            }
        }
        return sb.toString()
    }

    /** [run] is an identifier label — whole-word bare, or an `=`-suffixed one. */
    private fun isIdLabel(run: String, next: Char): Boolean {
        val lower = run.lowercase()
        for (label in ID_LABELS_BARE) if (lower == label) return true
        if (next != '=') return false
        for (label in ID_LABELS_EQ) {
            if (lower == label) return true
            if (lower.length > label.length && lower.endsWith(label)) {
                // Only at a boundary: `contactId=`/`readCap=`/`peer_id=` yes,
                // `valid=`/`android=` no.
                val at = run.length - label.length
                if (run[at] in 'A'..'Z' || run[at - 1] == '_' || run[at - 1] == '-') return true
            }
        }
        return false
    }

    // -- rule 3c ---------------------------------------------------------------

    /**
     * A pure-letter run of [MIN_ID_RUN]+ characters with at least
     * [MIN_CASE_TRANSITIONS] lower→upper transitions ⇒ [PLACEHOLDER_ID].
     *
     * lower→upper ONLY (the start of an interior upper-case hump), which is the
     * measure that separates the two populations: every CamelCase identifier
     * this codebase logs has 0–2, while random mixed-case base64url letters
     * average 1.75 per 8 characters with a thick tail. The counterpart
     * transition (upper→lower) fires once per hump in ordinary CamelCase too,
     * so counting both would take `MessageManager` with it.
     */
    private fun stripCaseMixedIds(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            if (!isIdChar(s[i])) {
                sb.append(s[i])
                i++
                continue
            }
            var j = i
            var pureLetters = true
            while (j < s.length && isIdChar(s[j])) {
                if (!isAsciiLetter(s[j])) pureLetters = false
                j++
            }
            val run = s.substring(i, j)
            sb.append(
                if (pureLetters && run.length >= MIN_ID_RUN && lowerToUpperTransitions(run) >= MIN_CASE_TRANSITIONS) {
                    PLACEHOLDER_ID
                } else {
                    run
                }
            )
            i = j
        }
        return sb.toString()
    }

    /** How many times a lower-case letter is directly followed by an upper-case one. */
    internal fun lowerToUpperTransitions(run: String): Int {
        var n = 0
        for (k in 1 until run.length) {
            if (run[k - 1] in 'a'..'z' && run[k] in 'A'..'Z') n++
        }
        return n
    }

    // -- rules 3 + 4a + 4b ---------------------------------------------------

    /**
     * One pass over maximal `[A-Za-z0-9_-]` runs, most specific label first:
     * all-digits ≥ [MIN_NUM_RUN] ⇒ `[num]`, all-hex ≥ [MIN_HEX_RUN] ⇒ `[hex]`,
     * ≥ [MIN_ID_RUN] with a digit or a `-`/`_` ⇒ `[id]`. Anything else — every
     * pure-letter word, every short token — is emitted verbatim.
     */
    private fun stripOpaqueTokens(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            if (!isIdChar(s[i])) {
                sb.append(s[i])
                i++
                continue
            }
            var j = i
            var hasDigit = false
            var hasSeparator = false
            var allDigits = true
            var allHex = true
            while (j < s.length && isIdChar(s[j])) {
                val c = s[j]
                if (c in '0'..'9') hasDigit = true else allDigits = false
                if (c == '-' || c == '_') hasSeparator = true
                if (!isHexChar(c)) allHex = false
                j++
            }
            val len = j - i
            sb.append(
                when {
                    // Tor's own REASON keywords (QUERY_NO_HSDIR, CHANNEL_CLOSED, …)
                    // are 8+ char runs holding `_` and would land on `[id]` below,
                    // erasing the one word that explains a stall. EXACT,
                    // case-sensitive match of the WHOLE run against a fixed list of
                    // Tor protocol constants only — the general rule is not
                    // loosened, and a keyword with anything glued to it (the run
                    // is maximal over [A-Za-z0-9_-]) is not a match.
                    isTorReasonKeyword(s, i, j) -> s.substring(i, j)
                    allDigits && len >= MIN_NUM_RUN -> PLACEHOLDER_NUM
                    allHex && len >= MIN_HEX_RUN -> PLACEHOLDER_HEX
                    len >= MIN_ID_RUN && (hasDigit || hasSeparator) -> PLACEHOLDER_ID
                    else -> s.substring(i, j)
                }
            )
            i = j
        }
        return sb.toString()
    }

    /** `s[start, end)` is exactly one of [TorReasonVocabulary.DEBUG_PASSTHROUGH]. */
    private fun isTorReasonKeyword(s: String, start: Int, end: Int): Boolean {
        val len = end - start
        if (len < MIN_ID_RUN) return false // shorter runs are never touched anyway
        return s.substring(start, end) in TorReasonVocabulary.DEBUG_PASSTHROUGH
    }

    // -- rule 4c -------------------------------------------------------------

    /**
     * Whitespace-delimited tokens that are actually PATHS ⇒ [PLACEHOLDER_PATH]:
     * a `/`, two or more non-empty segments, and either a leading `/` or `~/`
     * or a segment containing a letter. Sandbox container paths carry the
     * install UUID and the user name; this is also why the `D/Tag:` prefix is
     * excluded from the scan (it would otherwise look path-like).
     *
     * The letter/leading-slash requirement is what keeps RATIOS readable —
     * `3/3 answered` (the unread prime) and `1/4,` (a retry counter) are not
     * paths and used to be eaten as if they were. `digits/digits` carries no
     * file name, no user name and no container UUID; there is nothing in it to
     * redact.
     */
    private fun stripPaths(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            if (s[i].isWhitespace()) {
                sb.append(s[i])
                i++
                continue
            }
            var j = i
            while (j < s.length && !s[j].isWhitespace()) j++
            val token = s.substring(i, j)
            sb.append(if (isPathLike(token)) PLACEHOLDER_PATH else token)
            i = j
        }
        return sb.toString()
    }

    private fun isPathLike(token: String): Boolean {
        if (!token.contains('/')) return false
        var segments = 0
        var run = 0
        var segmentHasLetter = false
        var anySegmentHasLetter = false
        for (c in token) {
            if (c == '/') {
                if (run > 0) {
                    segments++
                    if (segmentHasLetter) anySegmentHasLetter = true
                }
                run = 0
                segmentHasLetter = false
            } else {
                run++
                if (isAsciiLetter(c)) segmentHasLetter = true
            }
        }
        if (run > 0) {
            segments++
            if (segmentHasLetter) anySegmentHasLetter = true
        }
        if (segments < 2) return false
        return token.startsWith("/") || token.startsWith("~/") || anySegmentHasLetter
    }

    // -- rule 7 ----------------------------------------------------------------

    /**
     * An integer directly in front of a count noun ⇒ its bucket. `17 contacts`
     * ⇒ `6-20 contacts`.
     *
     * Only a digit run that IS a whole token (not a slice of a larger id-char
     * run) and is followed by exactly one space and a count noun is touched, so
     * `4.2 s`, `3/3 answered`, `45%` and `probe #1` are all left alone.
     *
     * AND NEVER THE VALUE OF A `key=` LABEL. The single most
     * common line in a real upload is `poll → code=200 inbox=…`: "200" is a
     * standalone digit run and the count noun `inbox` follows it with exactly
     * one space, so rule 7 rewrote the HTTP status to `code=20+` on every poll
     * and every send. A number written as `<word>=<digits>` is a labelled VALUE
     * — a status, a port, an attempt number — never a contact-graph count, so
     * [isLabelledValueAt] excludes it. Nothing else about rule 7 moves:
     * `17 contacts` still buckets, `0` is still exact.
     */
    private fun bucketCounts(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            if (!isIdChar(s[i])) {
                sb.append(s[i])
                i++
                continue
            }
            var j = i
            var allDigits = true
            while (j < s.length && isIdChar(s[j])) {
                if (s[j] !in '0'..'9') allDigits = false
                j++
            }
            val run = s.substring(i, j)
            // Not after a `.` or `/`: the `2` of `4.2 targets` is a decimal, not a count.
            // Not after a `<word>=` either: `code=200 inbox=…` is a STATUS, not a count.
            val standalone = i == 0 ||
                (s[i - 1] != '.' && s[i - 1] != '/' && !isLabelledValueAt(s, i))
            sb.append(if (allDigits && standalone && countNounFollows(s, j)) bucketFor(run) else run)
            i = j
        }
        return sb.toString()
    }

    /**
     * True when the run starting at [at] is the VALUE of a `<word>=` label —
     * `code=200`, `status=404`, `port=9050`, `attempt=2`. One identifier
     * character in front of the `=` is enough to call it a label; a bare `=200`
     * (no key) is not one and keeps rule 7's ordinary treatment.
     */
    private fun isLabelledValueAt(s: String, at: Int): Boolean =
        at >= 2 && s[at - 1] == '=' && isIdChar(s[at - 2])

    /** Exactly one space and then one of [COUNT_NOUNS] as a whole word. */
    private fun countNounFollows(s: String, at: Int): Boolean {
        if (at >= s.length || s[at] != ' ') return false
        var k = at + 1
        while (k < s.length && isAsciiLetter(s[k])) k++
        if (k == at + 1) return false
        if (k < s.length && isIdChar(s[k])) return false
        val word = s.substring(at + 1, k).lowercase()
        for (noun in COUNT_NOUNS) if (word == noun) return true
        return false
    }

    /** `0` exact; otherwise `1-5` / `6-20` / `20+`. Never overflows: it returns
     *  the top bucket as soon as the running value passes it. */
    internal fun bucketFor(digits: String): String {
        var v = 0
        for (c in digits) {
            v = v * 10 + (c - '0')
            if (v > 20) return BUCKET_LARGE
        }
        return when {
            v == 0 -> BUCKET_ZERO
            v <= 5 -> BUCKET_SMALL
            else -> BUCKET_MEDIUM
        }
    }

    // -- rule 5 --------------------------------------------------------------

    /**
     * From the FIRST `alias=` / `name=` / `text=` / `title=` / `body=` onwards,
     * the rest of the line is [PLACEHOLDER_STR]. See the known-limitations note in the
     * class doc for why it is the line and not the token.
     */
    private fun stripLabelledValues(s: String): String {
        var cut = -1
        for (label in VALUE_LABELS) {
            val idx = indexOfIgnoreCase(s, label)
            if (idx >= 0) {
                val end = idx + label.length
                if (cut < 0 || end < cut) cut = end
            }
        }
        return if (cut < 0) s else s.substring(0, cut) + PLACEHOLDER_STR
    }

    private fun indexOfIgnoreCase(s: String, needle: String): Int {
        if (needle.isEmpty() || needle.length > s.length) return -1
        for (i in 0..(s.length - needle.length)) {
            if (s.regionMatches(i, needle, 0, needle.length, ignoreCase = true)) return i
        }
        return -1
    }

    // -- character classes ---------------------------------------------------

    /** `HH:MM:SS.mmm ` — both formatters emit exactly this. */
    private const val CLOCK_LEN = 13

    private fun startsWithClock(line: String): Boolean {
        if (line.length < CLOCK_LEN) return false
        for (idx in intArrayOf(0, 1, 3, 4, 6, 7, 9, 10, 11)) if (line[idx] !in '0'..'9') return false
        return line[2] == ':' && line[5] == ':' && line[8] == '.' && line[12] == ' '
    }

    private fun isAsciiLetter(c: Char): Boolean = (c in 'A'..'Z') || (c in 'a'..'z')
    private fun isAsciiAlnum(c: Char): Boolean = isAsciiLetter(c) || (c in '0'..'9')
    private fun isTagChar(c: Char): Boolean = isAsciiAlnum(c) || c == '_' || c == '.' || c == '$' || c == '-'
    private fun isIdChar(c: Char): Boolean = isAsciiAlnum(c) || c == '_' || c == '-'
    private fun isHexChar(c: Char): Boolean = (c in '0'..'9') || (c in 'a'..'f') || (c in 'A'..'F')
    private fun isIpRunChar(c: Char): Boolean = isHexChar(c) || c == ':' || c == '.'
}

// ---------------------------------------------------------------------------

/**
 * The incremental batch sender.
 *
 * WIRE CONTRACT (agreed with the relay side — do not change without also
 * updating the relay):
 *   POST `<relayBaseUrl>/debuglog`
 *   `Content-Type: application/json; charset=utf-8`, no auth, no other header
 *   `{"v":1,"platform":"android"|"ios","app":"<version>","reason":"connect"|"periodic"|"lock","session":"<8 hex>","t0":<epoch seconds>,"lines":["…",…]}`
 *   204 = accepted. ANY other status, and any transport failure, leaves the
 *   cursor where it was so the same lines go again on the next tick.
 *
 * TIME IS RELATIVE ON THE WIRE. Each line's `HH:MM:SS.mmm ` prefix is rewritten
 * to `+SSSSS.mmm ` — seconds since this process's ORIGIN, the first line this
 * uploader ever saw — and the batch carries one `t0`: the origin's epoch
 * SECONDS floored to a multiple of 60. A millisecond wall clock on every line,
 * shipped at 1 Hz, is a clock-skew and drift fingerprint (two devices are
 * distinguishable by their offset from the relay's own clock, and that offset
 * follows a device across sessions); relative offsets keep everything a
 * developer actually reads — ordering, gaps, how long a bootstrap took. The
 * origin is per-PROCESS, RAM-only, and deliberately NOT reset by a consent
 * toggle (a second stretch of logging in one process stays on one time base).
 * A line whose time-of-day is SMALLER than the origin's is a midnight wrap and
 * counts as the next day (+86400). Lines with no recognised clock prefix go
 * unchanged. The relay accepts `t0` as an optional integer.
 *
 * THE CURSOR. [flush] sends only the lines whose [DebugLogSeq] number is above
 * the cursor, merged from [LogBuffer] and [ConnectionLog] and sorted oldest
 * first, and advances the cursor to the last line it actually PUT ON THE WIRE
 * and got a 204 for. Nothing about it is persisted: it is RAM state that starts
 * at 0 and is reset at session start, on consent change and after a wipe.
 *
 * BOUNDS, so a pathological session cannot turn a 1 Hz tick into a flood:
 *   • [MAX_LINES_PER_BATCH] lines per POST, oldest first. Anything beyond that
 *     simply waits for the next tick.
 *   • [MAX_PENDING_LINES] total backlog. Past that the OLDEST pending lines are
 *     dropped — the cursor jumps over them when the batch that follows them
 *     succeeds — because an unbounded backlog on a device that cannot reach the
 *     relay is the failure mode to avoid.
 *   • [MAX_LINE_CHARS] per line, applied AFTER redaction so a truncation can
 *     never cut a redaction short.
 *   • [MAX_BODY_BYTES] per POST. Overflow drops from the NEWEST end, never the
 *     oldest: a dropped-newest line stays above the cursor and ships next tick,
 *     whereas dropping the oldest would silently lose it when the cursor
 *     advanced past it.
 *   • The ONE content filter: an UNEVENTFUL Tor stream
 *     pair — `STREAM_SENT` + `STREAM_OK` inside [ConnectionLog.SLOW_STREAM_MS]
 *     — does not ship. It was the largest single share of the first real-device
 *     uploads (two lines per relay request, saying nothing), and the caps above
 *     were being spent on it. A SLOW or FAILED stream still ships, together
 *     with its `SENT` line. See [Disposition]. The PANEL is untouched: it still
 *     shows every stream line, because that is where a stuck user reads one out.
 *
 * NEVER TWO AT ONCE. A tick that finds a flush already in flight returns true
 * immediately rather than queueing — the next tick is 1 second away, and two
 * concurrent flushes would read the same cursor and send the same lines twice.
 */
object DebugLogUploader {

    /** Path appended to the relay base URL. No capability, no auth. */
    const val PATH: String = "/debuglog"

    /** Lines per POST, oldest first. The rest waits for the next tick. */
    const val MAX_LINES_PER_BATCH: Int = 500

    /** Per-line ceiling, applied after redaction. */
    const val MAX_LINE_CHARS: Int = 512

    /** Relay ceiling for one batch body. */
    const val MAX_BODY_BYTES: Int = 65_536

    /** Backlog ceiling. Beyond this the oldest pending lines are dropped. */
    const val MAX_PENDING_LINES: Int = 2500

    /** Fire-and-forget: one attempt, a short budget, never the 60 s default. */
    const val HTTP_TIMEOUT_SECONDS: Int = 20

    const val REASON_CONNECT: String = "connect"
    const val REASON_PERIODIC: String = "periodic"
    const val REASON_LOCK: String = "lock"

    private const val CONTENT_TYPE = "application/json; charset=utf-8"

    private const val HEX_DIGITS = "0123456789abcdef"

    /** 4 random bytes ⇒ [SESSION_CHARS] lowercase hex. */
    internal const val SESSION_BYTES: Int = 4

    /** Length of [session]. */
    const val SESSION_CHARS: Int = SESSION_BYTES * 2

    /**
     * A random 8-character lowercase-hex tag, drawn ONCE per process from the
     * CSPRNG and never persisted.
     *
     * It exists so an operator looking at several devices uploading at the same
     * time can read ONE app run in order. It is NOT a device identifier and
     * must never become one: it is not derived from anything about the device,
     * it is not written to disk, it changes on every launch, and it dies with
     * the process. 32 bits is deliberately small — it only has to separate a
     * handful of concurrent runs, and a wider value would start to look like a
     * durable handle.
     */
    val session: String by lazy { buildSessionTag() }

    /**
     * Lazy AND non-throwing: the iOS [generateSecureRandom] fails CLOSED
     * (throws when `SecRandomCopyBytes` fails), and this object is first
     * touched from `RunApp.init` via [DebugMode.applyAtStartup], which is not
     * `@Throws` — an eager `val` would have turned an unlikely CSPRNG failure
     * into an uncatchable launch crash. The tag is only a
     * correlation id, so the fallback is the low bits of the clock and the
     * seq counter: still per-process, still nothing about the device.
     */
    private fun buildSessionTag(): String {
        val bytes = try {
            generateSecureRandom(SESSION_BYTES)
        } catch (_: Exception) {
            val v = currentTimeMillis() xor (DebugLogSeq.current() shl 17)
            ByteArray(SESSION_BYTES) { i -> (v ushr (8 * i)).toByte() }
        }
        val sb = StringBuilder(SESSION_CHARS)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            sb.append(HEX_DIGITS[v ushr 4]).append(HEX_DIGITS[v and 0x0F])
        }
        return sb.toString()
    }

    private val cursorLock = SyncLock()
    private var cursor = 0L
    /**
     * The in-flight latch, as the wall-clock ms the running flush BEGAN (0 =
     * none). A timestamp, not a boolean, since 2026-09-21: on iOS the "lock"
     * flush runs in a detached task while the app is leaving the foreground and
     * `AppState.lock()` waits only ~1.5 s for it; a Tor POST takes longer, the
     * process is suspended mid-POST, and the task that would have released a
     * boolean latch never runs again while the process lives. Every later
     * flush of that process (connect, periodic, the next lock) then saw
     * "already flushing", returned true, and uploaded NOTHING — the Settings
     * row said ON, the flag was persisted, and the relay saw connect telemetry
     * and zero batches after the first background/return (prod iPhone,
     * 1.6.27, 2026-09-21). [tryBeginFlush] therefore treats a latch older than
     * [STALE_FLUSH_MS] as abandoned and takes it over; the abandoned POST, if
     * it ever completes, finds its cursor advance is a no-op ([flushTo] only
     * moves the cursor forward) and its [endFlush] releases whatever latch is
     * current — at worst one tick is skipped. See also [abandonFlush].
     */
    private var flushingSinceMs = 0L

    /** A flush older than this is treated as abandoned. Comfortably above the POST timeout. */
    internal const val STALE_FLUSH_MS: Long = (HTTP_TIMEOUT_SECONDS + 10) * 1_000L

    /**
     * Periodic-tick backoff (under [cursorLock]). A POST that did not get a
     * 204 leaves the cursor in place, so without this the 1 Hz ticker would
     * re-run the redaction ladder and open a fresh Tor stream every second
     * for as long as the relay does not answer. Doubles
     * from [PERIODIC_BACKOFF_BASE_MS] to [PERIODIC_BACKOFF_CAP_MS], resets on
     * the first 204 and on every cursor reset. Only the periodic reason is
     * damped — a connect or lock flush is a one-shot and must always try.
     */
    private var periodicFailures = 0
    private var periodicRetryAtMs = 0L
    private const val PERIODIC_BACKOFF_BASE_MS = 2_000L
    private const val PERIODIC_BACKOFF_CAP_MS = 30_000L

    /**
     * The per-process time origin, RAM-only. [originMsOfDay] is the time-of-day
     * of the first line this uploader ever rendered (−1 until then) and
     * [originEpochMs] is that same instant as epoch millis, reconstructed from
     * the line's own clock so `t0` is the origin and not "whenever the batch
     * was built".
     *
     * Its OWN lock, never [cursorLock]: the iOS [SyncLock] is an `NSLock` and
     * is NOT reentrant, so a nested take would deadlock the log path.
     */
    private val originLock = SyncLock()
    private var originMsOfDay = -1
    private var originEpochMs = 0L

    /** `t0`'s granularity. A minute is coarse enough not to be a clock sample. */
    internal const val T0_GRANULARITY_SECONDS: Long = 60

    /** Milliseconds in a day — the midnight-wrap addend. */
    private const val DAY_MS = 86_400_000L
    /**
     * How far "ahead of now" a line's time-of-day may read before it is taken
     * for YESTERDAY (2026-10-26). A line is rendered from a buffer at batch
     * time, so it can only be newer than `now` by a clock inversion of a few
     * ms; anything beyond this is the previous day's instant.
     */
    private const val FUTURE_TOLERANCE_MS = 60_000L

    /**
     * Points the cursor at the current end of the stream, so nothing already
     * buffered is uploaded.
     *
     * Called at session start ([DebugMode.applyAtStartup]), on every consent
     * change ([DebugMode.setEnabled] — consent is not retroactive) and after a
     * wipe.
     */
    fun resetCursor() {
        val now = DebugLogSeq.current()
        cursorLock.withLock {
            cursor = now
            periodicFailures = 0
            periodicRetryAtMs = 0L
        }
    }

    /**
     * The EXACT request body, fixed key order `v` / `platform` / `app` /
     * `reason` / `session` / `t0` / `lines`. Pure; pinned byte-for-byte by
     * DebugModeTest. Every string goes through [jsonEscapeString] — the body is
     * built by hand, and an unescaped quote in a log line would otherwise
     * produce a silently malformed request instead of a loud failure.
     *
     * `t0` is a bare integer (epoch seconds, a multiple of
     * [T0_GRANULARITY_SECONDS]) — the anchor for the `+SSSSS.mmm` offsets the
     * lines carry.
     */
    fun payload(platform: String, app: String, reason: String, session: String, t0: Long, lines: List<String>): String {
        val sb = StringBuilder(256 + lines.size * 64)
        sb.append("{\"v\":1,\"platform\":").append(jsonEscapeString(platform))
        sb.append(",\"app\":").append(jsonEscapeString(app))
        sb.append(",\"reason\":").append(jsonEscapeString(reason))
        sb.append(",\"session\":").append(jsonEscapeString(session))
        sb.append(",\"t0\":").append(t0)
        sb.append(",\"lines\":[")
        for ((i, line) in lines.withIndex()) {
            if (i > 0) sb.append(',')
            sb.append(jsonEscapeString(line))
        }
        sb.append("]}")
        return sb.toString()
    }

    /**
     * Ships everything new since the cursor, or nothing at all.
     *
     * Returns true when there was nothing pending OR the relay answered 204;
     * false on any other status, on a transport failure, when there is no
     * transport / no relay configured, and on a platform or reason outside the
     * closed vocabularies. The cursor advances ONLY on true-with-a-POST.
     *
     * Never throws. Only the POST itself suspends (on [ioDispatcher], because
     * [RelayHttp.post] blocks), so cancelling the caller's scope — lock, wipe,
     * move quiesce — cancels the upload rather than being swallowed.
     *
     * The [LoggingState] gate at the top is structural, not cosmetic: in a
     * RELEASE build that flag is true if and only if the user consented
     * ([DebugMode.setEnabled] is the only thing that sets it), so a stray tick
     * from a future caller cannot upload anything without consent.
     */
    suspend fun flush(transport: RelayHttp?, platform: String, app: String, reason: String): Boolean =
        flushTo(transport, RelayConfig.BASE_URL, platform, app, reason)

    /**
     * [flush] with the relay base URL and the line source injected, so the
     * batching, the cursor and the failure semantics are unit-testable without
     * a relay, a clock or the process-wide buffers.
     */
    internal suspend fun flushTo(
        transport: RelayHttp?,
        relayBaseUrl: String,
        platform: String,
        app: String,
        reason: String,
        collect: (Long) -> List<PendingLine> = { collectPending(it) },
    ): Boolean {
        if (!LoggingState.enabled) return true
        if (platform != ConnectTelemetry.PLATFORM_ANDROID && platform != ConnectTelemetry.PLATFORM_IOS) return false
        if (reason != REASON_CONNECT && reason != REASON_PERIODIC && reason != REASON_LOCK) return false
        if (reason == REASON_PERIODIC && cursorLock.withLock { currentTimeMillis() < periodicRetryAtMs }) return false
        if (!tryBeginFlush()) return true
        try {
            val at = cursorLock.withLock { cursor }
            // Non-suspending: a CancellationException cannot be raised here, so
            // catching Exception around it cannot swallow one.
            val built = try {
                buildBatch(platform, ConnectTelemetry.sanitizeAppVersion(app), reason, collect(at))
            } catch (e: Exception) {
                platformLogWarn("DebugLog", "batch build failed: ${e::class.simpleName}")
                return false
            }
            val batch = built ?: return true
            if (transport == null || relayBaseUrl.isEmpty()) return false
            val sent = withContext(ioDispatcher) { postBatch(transport, relayBaseUrl, batch.body) }
            if (!sent) {
                if (reason == REASON_PERIODIC) notePeriodicFailure()
                return false
            }
            cursorLock.withLock {
                if (batch.lastSeq > cursor) cursor = batch.lastSeq
                periodicFailures = 0
                periodicRetryAtMs = 0L
            }
            return true
        } finally {
            endFlush()
        }
    }

    private fun notePeriodicFailure() {
        cursorLock.withLock {
            periodicFailures = minOf(periodicFailures + 1, 8)
            val wait = minOf(PERIODIC_BACKOFF_CAP_MS, PERIODIC_BACKOFF_BASE_MS shl (periodicFailures - 1))
            periodicRetryAtMs = currentTimeMillis() + wait
        }
    }

    /** Test seam: the periodic backoff deadline (0 when none). */
    internal fun periodicRetryAtForTest(): Long = cursorLock.withLock { periodicRetryAtMs }

    /**
     * The bare POST, split out so the wire shape (URL, method, headers, body,
     * timeout) is testable without a coroutine. True only on 204. Never throws
     * — and never logs the failure detail, which could name the relay host.
     *
     * `suppressLog = true` is LOAD-BEARING, not a nicety: the transport's own
     * `POST <path> → <code>` line would be a brand-new line above this
     * uploader's cursor, so the next tick would ship it and log another one —
     * an idle app uploading at 1 Hz forever. Silencing it AT THE TRANSPORT is
     * why nothing downstream has to recognise and drop the uploader's own lines
     * by text (a text filter would also blanket-drop real stuck-stream
     * diagnostics). See [RelayHttp.post]'s
     * six-argument overload.
     */
    internal fun postBatch(http: RelayHttp, relayBaseUrl: String, body: String): Boolean = try {
        http.post(
            "$relayBaseUrl$PATH",
            body.encodeToByteArray(),
            CONTENT_TYPE,
            emptyMap(),
            HTTP_TIMEOUT_SECONDS,
            suppressLog = true,
        ).code == 204
    } catch (_: Exception) {
        false
    }

    // -- batching ------------------------------------------------------------

    /**
     * One buffered line and its place in the merged stream.
     *
     * [worthATick] answers ONE question: would this line, ALONE, justify
     * spending a POST? Every [LogBuffer] entry does (default true — real app
     * activity). A [ConnectionLog] line does only when it carries a [Code] that
     * is not the narration of the uploader's OWN previous POST — see
     * [justifiesTick]. It is never rendered and never reaches the wire; it only
     * decides whether [buildBatch] builds a batch at all. A line that does not
     * justify a tick still SHIPS in the next batch a real line triggers —
     * this is a "worth waking up for" test, not a filter.
     */
    internal data class PendingLine(
        val seq: Long,
        val formatted: String,
        val worthATick: Boolean = true,
        /**
         * Whether this line belongs in a BATCH at all, and when.
         * Defaults to [Disposition.SHIP], so every [LogBuffer] entry, every
         * non-stream panel line and every hand-built test fixture behaves
         * exactly as it did before the stream pairing existed.
         */
        val disposition: Disposition = Disposition.SHIP,
    )

    /**
     * What [buildBatch] does with a pending line.
     *
     * >90 % of the lines in a real debug-mode upload were per-request plumbing,
     * and the largest single share of it was the control-port tap's narration
     * of every ordinary Tor stream — `stream connecting` + `stream connected`,
     * twice per relay request, carrying nothing when the stream connected
     * normally. Those pairs are now left OUT of the upload; a stream that took
     * longer than [ConnectionLog.SLOW_STREAM_MS] or ended in `STREAM_FAILED`
     * still ships, TOGETHER WITH ITS `SENT` LINE, because "when did this stream
     * start" is half of the stuck-stream diagnosis.
     *
     * [HOLD] is what makes "together with its SENT line" possible at 1 Hz: a
     * `SENT` whose outcome has not landed yet is not YET decidable, so the
     * batch stops in front of it and the cursor does not advance past it. It is
     * bounded by [ConnectionLog.SLOW_STREAM_MS] — an open stream older than
     * that IS the slow case and ships — so nothing can be held for longer than
     * a few seconds, and a backwards clock step resolves to SHIP rather than
     * stalling the cursor.
     */
    internal enum class Disposition { SHIP, SKIP, HOLD }

    /**
     * Whether a [ConnectionLog] line's code justifies a tick on its own.
     *
     * Every batch POST opens ONE Tor stream (Connection: close) and the
     * control-event tap narrates it as STREAM_SENT + STREAM_OK. With the
     * transport's own log line already silenced ([postBatch]'s `suppressLog`),
     * those two are the last remaining echo of the uploader's own traffic — and
     * shipping them would open the next stream, which narrates itself, forever.
     * So they do not wake the uploader up. STREAM_FAILED is NOT in this set: a
     * stuck or failing stream is exactly the diagnostic this feature exists to
     * collect.
     *
     * Uncoded narration (`code == null`) does not justify a tick either: it is
     * panel prose with no phase transition in it, and anything interesting
     * happening alongside it produces either a coded line or a LogBuffer entry
     * in the same second, which ships the narration with it.
     */
    internal fun justifiesTick(code: ConnectionLog.Code?): Boolean =
        code != null && code != ConnectionLog.Code.STREAM_SENT && code != ConnectionLog.Code.STREAM_OK

    /** A ready-to-POST body plus the sequence number the cursor moves to. */
    internal data class Batch(val body: String, val lastSeq: Long, val lineCount: Int)

    /**
     * Everything above [cursorAt] from BOTH buffers, unsorted (the caller
     * sorts). Reads only the formatted forms — this is the one place the
     * uploader touches the process-wide singletons.
     *
     * [Disposition.SKIP] lines are dropped HERE, so the cursor is free to move
     * past them; [Disposition.HOLD] lines are carried through and stop
     * [buildBatch] in front of them. [nowMs] is a parameter only so a test can
     * drive [ConnectionLog.SLOW_STREAM_MS] without waiting for it.
     */
    internal fun collectPending(cursorAt: Long, nowMs: Long = currentTimeMillis()): List<PendingLine> {
        val out = ArrayList<PendingLine>()
        // Skip the "Conn" mirror lines: ConnectionLog copies every CODE into LogBuffer for the
        // e2e log viewer (93cd2260), and this stream already ships the ConnectionLog lines
        // themselves below — shipping the mirror too would double every phase in the upload.
        for (e in LogBuffer.since(cursorAt)) if (e.tag != "Conn") out.add(PendingLine(e.seq, e.formatted()))
        for (l in ConnectionLog.since(cursorAt)) {
            val disposition = streamDisposition(l, nowMs)
            if (disposition == Disposition.SKIP) continue
            out.add(
                PendingLine(
                    l.seq,
                    l.formatted(),
                    worthATick = justifiesTick(l.code),
                    disposition = disposition,
                )
            )
        }
        return out
    }

    /**
     * Whether one [ConnectionLog] line belongs in an upload batch.
     *
     * Every line that is not a `STREAM_SENT`/`STREAM_OK` ships, `STREAM_FAILED`
     * included: a failure is the diagnostic this feature exists to collect.
     * A stream line with NO pairing key ships too — that is the pre-2026-09-16
     * behaviour, and it is the honest answer for a producer that cannot tell us
     * which stream it meant.
     *
     * For a PAIRED line, [ConnectionLog.Line.streamShip] already carries the
     * decision the pair's outcome made. The only undecided case is a `SENT`
     * still waiting for its outcome, and it is decided BY AGE: still young ⇒
     * [Disposition.HOLD] (the outcome is seconds away, and the `SENT` has to be
     * in the same batch as an `OK` that turns out to be slow); older than
     * [ConnectionLog.SLOW_STREAM_MS] ⇒ it IS the slow case, ship it. A negative
     * age (a backwards wall-clock step) ships too — never stall the cursor on a
     * clock.
     */
    internal fun streamDisposition(line: ConnectionLog.Line, nowMs: Long): Disposition {
        val code = line.code
        if (code != ConnectionLog.Code.STREAM_SENT && code != ConnectionLog.Code.STREAM_OK) {
            return Disposition.SHIP
        }
        if (line.streamKey == null) return Disposition.SHIP
        when (line.streamShip) {
            true -> return Disposition.SHIP
            false -> return Disposition.SKIP
            null -> {}
        }
        // Only a SENT can still be undecided; an OK decides itself at append.
        if (code != ConnectionLog.Code.STREAM_SENT) return Disposition.SKIP
        val age = nowMs - line.timestamp
        return if (age < 0L || age >= ConnectionLog.SLOW_STREAM_MS) Disposition.SHIP else Disposition.HOLD
    }

    /**
     * Merge ⇒ drop-oldest backlog ⇒ take the oldest [MAX_LINES_PER_BATCH] ⇒
     * redact, re-base the clock, clip each ⇒ trim from the NEWEST end until the
     * body fits [MAX_BODY_BYTES]. Null when nothing is pending, and null when
     * nothing pending is [PendingLine.worthATick] — an idle app whose only new
     * lines are its own last POST's stream narration posts NOTHING rather than
     * feeding itself at 1 Hz. A line that merely does not justify a TICK is not
     * filtered: it stays above the cursor and ships in the next batch a real
     * line triggers. (The one thing that IS filtered is an uneventful Tor
     * stream pair — dropped in [collectPending], see [streamDisposition].)
     *
     * ORDER MATTERS: redact FIRST, re-base SECOND. [DebugLogRedactor] keeps the
     * `HH:MM:SS.mmm LEVEL/Tag: ` prefix verbatim and only scrubs what follows,
     * so handing it an already-re-based `+00012.345 D/Tag: …` line would lose
     * the prefix (no clock ⇒ the whole line is treated as message, and `D/Tag:`
     * then reads as a path). Clipping stays last so a truncation can never cut
     * a redaction short.
     *
     * The body-size trim is computed from each line's own escaped length rather
     * than by re-rendering the body once per candidate size — a 500-line,
     * 64 KiB body would otherwise be rebuilt up to 500 times on the log path.
     */
    internal fun buildBatch(
        platform: String,
        app: String,
        reason: String,
        pending: List<PendingLine>,
        // Injectable so a test can pin "now" next to the pinned origin; production
        // takes the clock. Both the origin pin and every offset resolve against it.
        nowMs: Long = currentTimeMillis(),
    ): Batch? {
        // Nothing pending, or nothing pending that is worth a POST (see
        // [PendingLine.worthATick]) ⇒ no batch at all. `none` also covers the
        // empty list.
        val ordered = pending.sortedBy { it.seq }
        // The batch stops in front of the OLDEST undecided line
        // ([Disposition.HOLD] — a Tor stream whose outcome has not landed yet),
        // so the cursor cannot advance past a `STREAM_SENT` whose partner is
        // about to prove it worth shipping. Bounded by
        // [ConnectionLog.SLOW_STREAM_MS]; see [streamDisposition].
        //
        // EXCEPT ON [REASON_LOCK]. That flush is the LAST one of the session —
        // the lines just before the app goes away are the whole reason this is
        // incremental rather than a snapshot — so there is no "next tick" to
        // defer to. An undecided SENT simply ships, which is the same direction
        // the age rule resolves to anyway.
        val holdAt =
            if (reason == REASON_LOCK) -1 else ordered.indexOfFirst { it.disposition == Disposition.HOLD }
        val sorted = if (holdAt >= 0) ordered.subList(0, holdAt) else ordered
        if (sorted.none { it.worthATick }) return null
        val kept = if (sorted.size > MAX_PENDING_LINES) {
            sorted.subList(sorted.size - MAX_PENDING_LINES, sorted.size)
        } else {
            sorted
        }
        val slice = if (kept.size > MAX_LINES_PER_BATCH) kept.subList(0, MAX_LINES_PER_BATCH) else kept

        val redacted = ArrayList<String>(slice.size)
        for (p in slice) redacted.add(DebugLogRedactor.redactLine(p.formatted))
        val origin = establishOrigin(redacted, nowMs)
        val rendered = ArrayList<String>(slice.size)
        for (r in redacted) rendered.add(clipLine(toRelativeTime(r, origin, nowMs)))
        val t0 = originEpochSeconds()

        var total = payload(platform, app, reason, session, t0, emptyList()).encodeToByteArray().size
        var n = 0
        for (line in rendered) {
            val add = jsonEscapeString(line).encodeToByteArray().size + (if (n > 0) 1 else 0)
            if (total + add > MAX_BODY_BYTES) break
            total += add
            n++
        }
        // Unreachable in practice — MAX_LINE_CHARS bounds one escaped line far
        // below MAX_BODY_BYTES — but a zero-line batch would stall the cursor
        // forever, so always ship at least one line rather than spin.
        if (n == 0) n = 1
        val lines = if (n == rendered.size) rendered else rendered.subList(0, n)
        return Batch(
            body = payload(platform, app, reason, session, t0, lines),
            lastSeq = slice[n - 1].seq,
            lineCount = n,
        )
    }

    // -- the relative clock --------------------------------------------------

    /**
     * Pins the process time origin to the first clock-bearing line ever
     * rendered and returns the origin's time-of-day (−1 while no line has
     * carried a clock yet, in which case nothing is re-based).
     *
     * [originEpochMs] is reconstructed from that line's OWN time-of-day rather
     * than read off the clock at batch time, so `t0` names the origin instant
     * even if the first batch is built a while after the line was written.
     */
    internal fun establishOrigin(lines: List<String>, nowMs: Long = currentTimeMillis()): Int = originLock.withLock {
        if (originMsOfDay < 0) {
            for (line in lines) {
                val ms = clockMsOfDay(line)
                if (ms >= 0) {
                    originMsOfDay = ms
                    val now = nowMs
                    val nowMsOfDay = ((now % DAY_MS) + DAY_MS) % DAY_MS
                    // How long ago that line was written, wrapped at midnight.
                    var back = ((nowMsOfDay - ms) % DAY_MS + DAY_MS) % DAY_MS
                    // Same clamp as toRelativeTime: a line stamped a few ms AHEAD of nowMs (two
                    // threads read the clock under separate locks — the seq/timestamp inversion)
                    // is "just now", not yesterday.
                    if (back > DAY_MS - FUTURE_TOLERANCE_MS) back -= DAY_MS
                    originEpochMs = now - back
                    break
                }
            }
        }
        originMsOfDay
    }

    /**
     * `t0`: the origin's epoch seconds floored to [T0_GRANULARITY_SECONDS].
     * Falls back to the current minute while no origin has been pinned (a batch
     * of lines that carry no clock at all), which keeps the field well-formed
     * without ever making it finer than a minute.
     */
    internal fun originEpochSeconds(): Long = originLock.withLock {
        val ms = if (originEpochMs > 0L) originEpochMs else currentTimeMillis()
        (ms / 1000L / T0_GRANULARITY_SECONDS) * T0_GRANULARITY_SECONDS
    }

    /**
     * Rewrites a line's leading `HH:MM:SS.mmm ` to `+SSSSS.mmm `. Returns the
     * line unchanged when it has no clock prefix or no origin is pinned.
     *
     * A time-of-day BELOW the origin's is a midnight wrap, not a negative
     * offset — the buffers hold at most a few hours, so "smaller ⇒ next day" is
     * the only reading that makes sense (and the only one that keeps the offset
     * monotonic across the boundary).
     */
    internal fun toRelativeTime(line: String, originAtMsOfDay: Int, nowMs: Long = currentTimeMillis()): String {
        if (originAtMsOfDay < 0) return line
        val ms = clockMsOfDay(line)
        if (ms < 0) return line
        val originEpoch = originLock.withLock { originEpochMs }
        if (originEpoch <= 0L) return line
        // The line's own clock is TIME-OF-DAY only. Resolve it to the instant it
        // names — the most recent one at or before now (a batch is rendered from
        // buffers that hold at most a few hours) — and measure from the origin's
        // EPOCH instant, never from its time-of-day. The old time-of-day
        // subtraction assumed the process was younger than half a day: an
        // Android process that stays alive for days (TorKeepAlive) rendered every
        // line written at a time-of-day earlier than the origin's as `+00000.000`
        // (2026-10-26, a production Pixel: one day-old `t0`, every offset zero).
        val nowMsOfDay = ((nowMs % DAY_MS) + DAY_MS) % DAY_MS
        var back = ((nowMsOfDay - ms) % DAY_MS + DAY_MS) % DAY_MS
        if (back > DAY_MS - FUTURE_TOLERANCE_MS) back -= DAY_MS
        var delta = (nowMs - back) - originEpoch
        // A SMALL negative delta is seq/timestamp inversion between the two
        // buffers (each reads its clock and draws its seq under its own lock,
        // so two threads can interleave by a few ms); clamp it.
        if (delta < 0) delta = 0L
        return relativeClock(delta) + line.substring(CLOCK_CHARS)
    }

    /** `+SSSSS.mmm` — seconds zero-padded to 5 so the column stays aligned. */
    internal fun relativeClock(deltaMs: Long): String {
        val seconds = deltaMs / 1000L
        val millis = deltaMs % 1000L
        val sb = StringBuilder(10)
        sb.append('+')
        val digits = seconds.toString()
        for (pad in digits.length until 5) sb.append('0')
        sb.append(digits).append('.')
        if (millis < 100) sb.append('0')
        if (millis < 10) sb.append('0')
        sb.append(millis)
        return sb.toString()
    }

    /** Length of `HH:MM:SS.mmm` (without the trailing space). */
    private const val CLOCK_CHARS = 12

    /**
     * Milliseconds-of-day of a line's `HH:MM:SS.mmm ` prefix, or −1 when the
     * line does not start with one. Both [LogEntry.formatted] and
     * [ConnectionLog.Line.formatted] emit exactly this shape (both via UTC
     * time-of-day arithmetic), so ONE parser covers both.
     */
    internal fun clockMsOfDay(line: String): Int {
        if (line.length <= CLOCK_CHARS) return -1
        for (idx in intArrayOf(0, 1, 3, 4, 6, 7, 9, 10, 11)) if (line[idx] !in '0'..'9') return -1
        if (line[2] != ':' || line[5] != ':' || line[8] != '.' || line[12] != ' ') return -1
        val h = (line[0] - '0') * 10 + (line[1] - '0')
        val m = (line[3] - '0') * 10 + (line[4] - '0')
        val s = (line[6] - '0') * 10 + (line[7] - '0')
        val ms = (line[9] - '0') * 100 + (line[10] - '0') * 10 + (line[11] - '0')
        if (h > 23 || m > 59 || s > 59) return -1
        return ((h * 3600 + m * 60 + s) * 1000) + ms
    }

    /**
     * [MAX_LINE_CHARS] cap plus a control-character sweep. Control characters
     * are replaced (not escaped) because [jsonEscapeString] only knows
     * `\n`/`\r`/`\t`, so anything else below 0x20 would land RAW inside a JSON
     * string literal and make the batch unparseable for the relay. Collapsing
     * an embedded newline to a space also keeps one buffered entry on one line.
     */
    internal fun clipLine(line: String): String {
        val limited = if (line.length > MAX_LINE_CHARS) line.substring(0, MAX_LINE_CHARS) else line
        if (limited.none { it < ' ' || it == '' }) return limited
        val sb = StringBuilder(limited.length)
        for (c in limited) sb.append(if (c < ' ' || c == '') ' ' else c)
        return sb.toString()
    }

    // -- the in-flight latch -------------------------------------------------

    /**
     * True when this caller took the latch; false when a flush is running AND
     * is younger than [STALE_FLUSH_MS]. An older latch is abandoned (see
     * [flushingSinceMs]) and taken over.
     */
    internal fun tryBeginFlush(nowMs: Long = currentTimeMillis()): Boolean = cursorLock.withLock {
        val since = flushingSinceMs
        if (since != 0L && nowMs - since in 0 until STALE_FLUSH_MS) {
            false
        } else {
            flushingSinceMs = if (nowMs == 0L) 1L else nowMs
            true
        }
    }

    internal fun endFlush() {
        cursorLock.withLock { flushingSinceMs = 0L }
    }

    /**
     * Releases the latch WITHOUT waiting for the flush that holds it — for a
     * caller that started a flush it can no longer wait for (the iOS lock path
     * once its bounded wait expires: the process is about to be suspended and
     * the detached task may never run again). The abandoned flush's own
     * [endFlush], if it ever runs, is harmless (idempotent release).
     */
    fun abandonFlush() = endFlush()

    /** Test seams — the cursor is process-wide state, so tests must pin it. */
    internal fun cursorForTest(): Long = cursorLock.withLock { cursor }

    internal fun setCursorForTest(value: Long) {
        cursorLock.withLock {
            cursor = value
            periodicFailures = 0
            periodicRetryAtMs = 0L
        }
    }

    /** Test seam — so is the time origin. Pin it, or `t0` and every `+SSSSS.mmm`
     *  offset depend on which test ran first. */
    internal fun setOriginForTest(msOfDay: Int, epochMs: Long) {
        originLock.withLock {
            originMsOfDay = msOfDay
            originEpochMs = epochMs
        }
    }

    internal fun clearOriginForTest() {
        originLock.withLock {
            originMsOfDay = -1
            originEpochMs = 0L
        }
    }
}
