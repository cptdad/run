import Foundation
import Security
import LocalAuthentication
import shared

// ---------------------------------------------------------------------------
// KeychainHelper — Swift wrapper for iOS Keychain, exposed to Kotlin.
//
// Stores the CryptoProvider device key in the Keychain. Preferred
// accessibility class is kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly —
// the key is only readable when the device is currently unlocked, every
// time. A screen-locked-but-powered-on device cannot reach the key,
// defeating USB-restricted-mode bypass attacks (GrayKey-class tools).
//
// On a device without a passcode, that class refuses storage. Real hardware
// reports this as errSecNotAvailable (-25291, "No key available for class");
// some configurations report errSecParam (-50). In either case we fall back
// to AfterFirstUnlockThisDeviceOnly so the app remains functional — but ONLY
// after LocalAuthentication affirmatively confirms there is no passcode, since
// errSecNotAvailable is also returned for a transiently LOCKED keybag, where
// downgrading would permanently weaken the root key (fail-open against the
// seized-but-locked threat). This is logged loudly because a passcode-less
// device is a poor target for a privacy app — the UX should later add a
// pre-setup screen telling the user to set a passcode in Settings.
// ---------------------------------------------------------------------------

@objc public class KeychainHelper: NSObject, KeychainBridge {

    @objc public static let shared = KeychainHelper()

    private let service = "com.vg.run.crypto"
    private let account = "device_key"

    /// Loads the device key from Keychain. Distinguishes "genuinely absent"
    /// (errSecItemNotFound → safe to create a new key) from a transient failure
    /// such as the device being locked (errSecInteractionNotAllowed → the key
    /// may still exist and must NOT be regenerated). See KeychainLoadResult.
    @objc public func loadKey() -> KeychainLoadResult {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data {
            // Self-heal: if this key was stored under the weaker fallback class
            // (because the device had no passcode when it was created) and a
            // passcode now exists, upgrade it to the strict class. Best-effort,
            // idempotent, and uses SecItemUpdate so there is no delete/re-add
            // window in which the root key could be lost.
            upgradeAccessibilityToStrict()
            // Also promote the kv items (verifier / wrapped DB
            // key / attempt counters) written under the no-passcode AfterFirstUnlock
            // fallback — otherwise they keep the weaker at-rest class until their next
            // write, an accessibility asymmetry vs the device key just upgraded.
            upgradeKvAccessibilityToStrict()
            return KeychainLoadResult(data: data, keyMissing: false, status: status)
        }
        return KeychainLoadResult(data: nil, keyMissing: status == errSecItemNotFound, status: status)
    }

    /// Stores the device key in Keychain under the strict accessibility class
    /// (readable only while the device is currently unlocked). Falls back to
    /// AfterFirstUnlockThisDeviceOnly ONLY when the device has no passcode,
    /// which the Keychain reports as errSecParam. Any OTHER failure does NOT
    /// downgrade the protection class — silently weakening the root key would be
    /// a fail-open against the seized-but-locked-device threat model — so we
    /// fail closed and let the caller surface it (getOrCreateKey re-reads and
    /// verifies the stored key).
    @objc public func storeKey(key: Data) {
        // Update-first / add-if-absent — NEVER delete-then-add (a failed add after
        // a delete loses the device key → unrecoverable vault). Delete is reserved
        // for explicit wipe (deleteKey). Preferred: strict class.
        let strictStatus = addOrUpdateKey(key, accessible: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
        if strictStatus == errSecSuccess { return }

        // The strict (passcode-gated) class is legitimately unusable in exactly
        // one case: the device has no passcode. Hardware reports that as
        // errSecNotAvailable (-25291, "No key available for class" — the
        // passcode-gated keybag class key does not exist) or, in some configs,
        // errSecParam (-50). errSecNotAvailable is ALSO returned for a
        // transiently LOCKED keybag, where the strict class WILL succeed once
        // the device unlocks — downgrading there would permanently weaken the
        // root key (fail-open against the seized-but-locked threat). So treat
        // those two statuses only as CANDIDATES, and downgrade solely when
        // LocalAuthentication affirmatively confirms no passcode is set. Any
        // other status, or a present passcode (i.e. merely locked), fails closed
        // and getOrCreateKey surfaces it for retry once unlocked. (LogBuffer is
        // the on-device, DEBUG-gated sink — never NSLog, which persists to the
        // unified system log readable via Console/sysdiagnose.)
        guard strictStatus == errSecParam || strictStatus == errSecNotAvailable else {
            LogBuffer.shared.append(level: "E", tag: "KeychainHelper", message: "strict accessibility class rejected (status=\(strictStatus)) — NOT downgrading; device key not stored (fail-closed)")
            return
        }
        guard !deviceHasPasscode() else {
            LogBuffer.shared.append(level: "E", tag: "KeychainHelper", message: "strict add failed (status=\(strictStatus)) but a passcode is set — treating as transiently locked; NOT downgrading (fail-closed)")
            return
        }

        LogBuffer.shared.append(level: "W", tag: "KeychainHelper", message: "kv at-rest class downgraded (fallback)")
        let fallbackStatus = addOrUpdateKey(key, accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        if fallbackStatus != errSecSuccess {
            LogBuffer.shared.append(level: "E", tag: "KeychainHelper", message: "fallback SecItemAdd failed with status \(fallbackStatus)")
        }
    }

    /// True when the device has a passcode set. Evaluates LocalAuthentication's
    /// device-owner-authentication policy — `canEvaluatePolicy` never prompts and
    /// succeeds iff a passcode exists. This is the discriminator that lets
    /// storeKey tell a genuinely passcode-less device (where the strict Keychain
    /// class is permanently unusable, so a downgrade is the only option) apart
    /// from a transiently LOCKED device (where the strict class returns the same
    /// errSecNotAvailable but WILL work on unlock, so we must NOT downgrade). On
    /// any ambiguous LAContext error we assume a passcode IS set — fail closed,
    /// never weaken the root key on uncertainty.
    private func deviceHasPasscode() -> Bool {
        var error: NSError?
        if LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            return true
        }
        return error?.code != LAError.passcodeNotSet.rawValue
    }

    /// Base query identifying the single device-key item (no value/accessibility).
    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    /// Adds the key item under the given accessibility class; returns the OSStatus.
    private func addKey(_ key: Data, accessible: CFString) -> OSStatus {
        var query = baseQuery()
        query[kSecValueData as String] = key
        query[kSecAttrAccessible as String] = accessible
        return SecItemAdd(query as CFDictionary, nil)
    }

    /// Update-first / add-if-absent write for the device key. Updates the VALUE
    /// and accessibility class of any existing item IN PLACE (SecItemUpdate), and
    /// only SecItemAdds when none exists — so we NEVER delete-then-add. A
    /// delete-then-failed-add would leave the device key absent and make the vault
    /// unrecoverable; with update-first, ANY failure here leaves the existing item
    /// intact. Delete is reserved for explicit wipe (deleteKey). Also avoids the
    /// errSecDuplicateItem race a bare SecItemAdd would hit.
    private func addOrUpdateKey(_ key: Data, accessible: CFString) -> OSStatus {
        let attributes: [String: Any] = [
            kSecValueData as String: key,
            kSecAttrAccessible as String: accessible,
        ]
        let updateStatus = SecItemUpdate(baseQuery() as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecItemNotFound {
            return addKey(key, accessible: accessible)
        }
        return updateStatus
    }

    /// Best-effort promotion of the existing device-key item to the strict
    /// accessibility class. Idempotent (no-op if already strict) and ignored
    /// when there is still no passcode (errSecParam) or the device is locked
    /// (errSecInteractionNotAllowed). Uses SecItemUpdate so there is never a
    /// window in which the root key is absent.
    private func upgradeAccessibilityToStrict() {
        let attributes: [String: Any] = [
            kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        ]
        SecItemUpdate(baseQuery() as CFDictionary, attributes as CFDictionary)
    }

    /// The kv-item sibling of upgradeAccessibilityToStrict().
    /// A single SecItemUpdate over ALL items in the kv service (no account filter)
    /// promotes any still on the no-passcode AfterFirstUnlockThisDeviceOnly fallback
    /// to the strict WhenPasscodeSetThisDeviceOnly class once a passcode exists. The
    /// values are device-key AEAD ciphertext, so this closes an at-rest class
    /// asymmetry, not a plaintext leak. Best-effort, idempotent.
    private func upgradeKvAccessibilityToStrict() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kvService,
        ]
        let attributes: [String: Any] = [
            kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        ]
        SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }

    /// Deletes the device key from Keychain. Kept for the mint path's orphan cleanup
    /// (`getOrCreateKey`); it goes through the checked delete and ignores the
    /// outcome there. Every wipe path calls `deleteKeyChecked()` and acts on it.
    @objc public func deleteKey() {
        _ = deleteKeyChecked()
    }

    // -----------------------------------------------------------------------
    // RÚN-02 — CHECKED deletion. Each delete keeps its OSStatus and is followed
    // by a verify probe: an ATTRIBUTE query (no data, no key use), so the probe
    // can never read secret bytes. Outcome codes are Kotlin's EraseOutcome:
    // 0 DELETED (delete succeeded, probe: not found), 1 ALREADY_ABSENT (delete
    // and probe: not found), 2 UNRESOLVED (anything else — the item still
    // visible, a refused delete, or a probe that could not answer). Kotlin
    // additionally refuses to trust "absent" while protected data is
    // unavailable: whether a locked keybag can see these items at all is what
    // the RÚN-02 device procedure measures.
    // -----------------------------------------------------------------------

    /// The decision for one delete + its verify probe. The mapping lives in Kotlin
    /// (`classifyKeychainDelete`, pinned by iosTest) so there is exactly one copy.
    static func classifyDelete(deleteStatus: OSStatus, probeStatus: OSStatus) -> KeychainDeleteResult {
        KeychainBridgeKt.classifyKeychainDelete(deleteStatus: deleteStatus, probeStatus: probeStatus)
    }

    /// Worst of two outcomes (one service's leftover makes the whole sweep unresolved).
    static func combineDeletes(_ a: KeychainDeleteResult, _ b: KeychainDeleteResult) -> KeychainDeleteResult {
        KeychainBridgeKt.combineKeychainDeletes(a: a, b: b)
    }

    /// Attribute-only presence probe for [query] (one item, or every item of a service).
    static func attributeProbe(_ query: [String: Any], all: Bool = false) -> OSStatus {
        var q = query
        q[kSecReturnAttributes as String] = true
        q[kSecMatchLimit as String] = all ? kSecMatchLimitAll : kSecMatchLimitOne
        var out: AnyObject?
        return SecItemCopyMatching(q as CFDictionary, &out)
    }

    /// Deletes the device key and proves it gone.
    @objc public func deleteKeyChecked() -> KeychainDeleteResult {
        let query = baseQuery()
        let deleteStatus = SecItemDelete(query as CFDictionary)
        return KeychainHelper.classifyDelete(deleteStatus: deleteStatus,
                                             probeStatus: KeychainHelper.attributeProbe(query))
    }

    /// The block-list item (BlockStore: service `com.vg.run.crypto`, account
    /// `blocked_contacts_v1` — keep both in step with UserSafety.swift).
    private let blockListAccount = "blocked_contacts_v1"

    private func blockListQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: blockListAccount,
        ]
    }

    /// Deletes the block list (sealed, or a pre-fix PLAINTEXT list of contact IDs) and proves it gone.
    @objc public func deleteBlockListChecked() -> KeychainDeleteResult {
        let query = blockListQuery()
        let deleteStatus = SecItemDelete(query as CFDictionary)
        return KeychainHelper.classifyDelete(deleteStatus: deleteStatus,
                                             probeStatus: KeychainHelper.attributeProbe(query))
    }

    #if DEBUG
    /// DEBUG-ONLY (`--test-wipe-probe`, the RÚN-02 device procedure): presence flags
    /// and item COUNTS only — never a value, never an account name. 1 = present,
    /// 0 = absent, ?<status> = the Keychain could not answer.
    func debugWipeProbe() -> String {
        func presence(_ s: OSStatus) -> String { s == errSecSuccess ? "1" : (s == errSecItemNotFound ? "0" : "?\(s)") }
        func count(_ svc: String) -> String {
            let q: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: svc,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
            ]
            var out: AnyObject?
            let s = SecItemCopyMatching(q as CFDictionary, &out)
            if s == errSecItemNotFound { return "0" }
            guard s == errSecSuccess else { return "?\(s)" }
            return "\((out as? [Any])?.count ?? 1)"
        }
        return "dk=\(presence(KeychainHelper.attributeProbe(baseQuery()))) kv=\(count(kvService)) " +
            "diag=\(count(diagService)) bl=\(presence(KeychainHelper.attributeProbe(blockListQuery())))"
    }
    #endif

    // -----------------------------------------------------------------------
    // Generic keyed storage (KeyValueStore backing). Holds the vault credential
    // verifier, the PIN-wrapped DB key, and the wrong-PIN counters — values that
    // were in NSUserDefaults (backup-exposed, no file-protection class) and now
    // live in the Keychain under the same strict accessibility class as the
    // device key. A separate service keeps them isolated from the device key so
    // kvDeleteAll() can clear them without touching it.
    // -----------------------------------------------------------------------

    private let kvService = "com.vg.run.kv"

    private func kvBaseQuery(_ key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kvService,
            kSecAttrAccount as String: key,
        ]
    }

    /// Tri-state kv read (mirrors loadKey/KeychainLoadResult): value on success,
    /// itemMissing only for errSecItemNotFound. Every OTHER status (locked keybag
    /// errSecInteractionNotAllowed, errSecAuthFailed / -34018-class daemon
    /// glitches, …) is a transient error the Kotlin side maps to
    /// KeyUnavailableException — NEVER to "absent", which upstream reads as a
    /// wrong PIN (wipe budget) or an unprovisioned install (re-provision over
    /// the real vault).
    @objc public func kvGet(key: String) -> KvReadResult {
        var query = kvBaseQuery(key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data, let value = String(data: data, encoding: .utf8) {
            return KvReadResult(value: value, itemMissing: false, status: status)
        }
        // Success-but-undecodable (can't happen for our own base64/ASCII writes)
        // deliberately lands on the error leg, not the missing leg — fail safe.
        return KvReadResult(value: nil, itemMissing: status == errSecItemNotFound, status: status)
    }

    /// Stores a keyed value under the strict (passcode-gated, this-device-only)
    /// accessibility class, with the SAME no-passcode fallback discipline as the
    /// device key: downgrade ONLY when LocalAuthentication confirms there is no
    /// passcode; on any other failure (incl. a merely-locked device) fail closed
    /// rather than silently weakening at-rest protection.
    @objc public func kvPut(key: String, value: String) {
        guard let data = value.data(using: .utf8) else { return }
        // Update-first / add-if-absent — never delete-then-add (see kvAddOrUpdate).
        let strictStatus = kvAddOrUpdate(key, data, accessible: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
        if strictStatus == errSecSuccess { return }

        guard strictStatus == errSecParam || strictStatus == errSecNotAvailable else {
            LogBuffer.shared.append(level: "E", tag: "KeychainHelper", message: "kv strict class rejected (status=\(strictStatus)) for \(key) — NOT downgrading (fail-closed)")
            return
        }
        guard !deviceHasPasscode() else {
            LogBuffer.shared.append(level: "E", tag: "KeychainHelper", message: "kv strict add failed (status=\(strictStatus)) for \(key) but a passcode is set — transiently locked; NOT downgrading (fail-closed)")
            return
        }
        LogBuffer.shared.append(level: "W", tag: "KeychainHelper", message: "kv at-rest class downgraded (fallback)")
        let fb = kvAddOrUpdate(key, data, accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        if fb != errSecSuccess {
            LogBuffer.shared.append(level: "E", tag: "KeychainHelper", message: "kv fallback SecItemAdd failed (status=\(fb)) for \(key)")
        }
    }

    private func kvAdd(_ key: String, _ data: Data, accessible: CFString) -> OSStatus {
        var query = kvBaseQuery(key)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = accessible
        return SecItemAdd(query as CFDictionary, nil)
    }

    /// Update-first / add-if-absent kv write (same data-loss rationale as
    /// addOrUpdateKey: a failed add after a delete would drop the credential
    /// verifier / wrapped DB key / counters → unrecoverable vault). Delete is
    /// reserved for explicit kvRemove/kvDeleteAll.
    private func kvAddOrUpdate(_ key: String, _ data: Data, accessible: CFString) -> OSStatus {
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessible,
        ]
        let updateStatus = SecItemUpdate(kvBaseQuery(key) as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecItemNotFound {
            return kvAdd(key, data, accessible: accessible)
        }
        return updateStatus
    }

    /// Returns whether the item is CONFIRMED gone. `errSecItemNotFound` counts
    /// as gone (nothing to delete); anything else — above all
    /// `errSecInteractionNotAllowed` on a locked keybag, where the delete does
    /// not happen at all — is a failure the caller has to be able to see. The
    /// status used to be discarded, so a refused delete looked exactly like a
    /// successful one; `KeyValueStore.remove` now propagates this and
    /// `DebugMode.setEnabledIn` acts on it (an un-revoked consent flag would
    /// otherwise re-arm Debug mode on the next launch).
    @discardableResult
    @objc public func kvRemove(key: String) -> Bool {
        let status = SecItemDelete(kvBaseQuery(key) as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    /// Unchecked sweep (the DEBUG e2e wipe); the outcome is the checked one's.
    @objc public func kvDeleteAll() {
        _ = kvDeleteAllChecked()
    }

    /// RÚN-02: sweeps the kv service AND the diagnostic service, then proves both
    /// empty with an attribute-only match-all probe.
    ///
    /// The diagnostic service is swept by the SAME call, deliberately: this is
    /// the one Keychain sweep that BOTH the production wipe
    /// (IosAppController.emergencyWipe → KeychainBridge.kvDeleteAllChecked, which
    /// runs AFTER the crypto-erase there) and the DEBUG e2e wipe
    /// (RunApp.wipeAllPersistentStateForTest → kvDeleteAll) already call, so a
    /// breadcrumb cannot survive a wipe through a call site someone forgot to
    /// update. AppState.clearWipeResidue() ALSO removes it explicitly, as the
    /// Swift-side belt — same belt-and-braces posture as the EULA flag. See diagService.
    @objc public func kvDeleteAllChecked() -> KeychainDeleteResult {
        let kv: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kvService,
        ]
        let kvStatus = SecItemDelete(kv as CFDictionary)
        let kvResult = KeychainHelper.classifyDelete(deleteStatus: kvStatus,
                                                     probeStatus: KeychainHelper.attributeProbe(kv, all: true))
        let diag: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: diagService,
        ]
        let diagStatus = SecItemDelete(diag as CFDictionary)
        let diagResult = KeychainHelper.classifyDelete(deleteStatus: diagStatus,
                                                       probeStatus: KeychainHelper.attributeProbe(diag, all: true))
        return KeychainHelper.combineDeletes(kvResult, diagResult)
    }

    // -----------------------------------------------------------------------
    // Local DIAGNOSTIC breadcrumbs — NON-vault state, own service, own
    // accessibility class.
    //
    // Today this holds exactly one item: the Tor bootstrap breadcrumb
    // (TorManager.swift / shared `TorBootstrapSelfHeal`), a cross-launch
    // "consecutive failed bootstraps + the percent they stalled at + the day of
    // the last state discard" record.
    //
    // Three deliberate choices:
    //
    //  • KEYCHAIN, not UserDefaults. A plist is AFU-readable and freely writable
    //    by anyone with the container — a WEAKER class than the `<Caches>/tor`
    //    evidence the record summarises, and this record can authorise deleting
    //    that directory (an entry-guard re-sample). It also must not live INSIDE
    //    `<Caches>/tor`: every fast-terminal Tor failure wipes that dir on
    //    failure #1, so a counter stored there could never survive its own trigger.
    //
    //  • A SEPARATE service from [kvService]. `upgradeKvAccessibilityToStrict()`
    //    blanket-promotes every item in the kv service to
    //    WhenPasscodeSetThisDeviceOnly, and on a passcode-less device `kvPut`
    //    then falls back to AfterFirstUnlockThisDeviceOnly — exactly the
    //    AFU-readable class this record must never land in. An isolated service
    //    keeps its class explicit and stable, and keeps non-vault diagnostics out
    //    of the service that holds the verifier / wrapped DB key / counters.
    //
    //  • kSecAttrAccessibleWhenUnlockedThisDeviceOnly (the default below), NOT
    //    the vault's WhenPasscodeSetThisDeviceOnly. Rún supports passcode-less
    //    devices (DeviceLockPolicy forces them to MAXIMUM rather than refusing
    //    them), where the passcode-gated class is unstorable and would silently
    //    degrade to AFU. WhenUnlocked behaves identically on both kinds of device,
    //    is unreadable on a seized-but-locked phone, and `ThisDeviceOnly` keeps it
    //    out of backups and off any other device.
    // -----------------------------------------------------------------------

    private let diagService = "com.vg.run.diag"

    private func diagBaseQuery(_ key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: diagService,
            kSecAttrAccount as String: key,
        ]
    }

    /// Reads a diagnostic breadcrumb, or nil for absent/unreadable/undecodable.
    /// Deliberately NOT tri-state (unlike [kvGet]): nothing here is credential
    /// state, and every consumer treats nil as "no evidence", which is the
    /// fail-safe direction for a record that can authorise a state discard.
    func diagGet(key: String) -> String? {
        var query = diagBaseQuery(key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Writes a diagnostic breadcrumb under [accessible] (see the section note
    /// for why the default is WhenUnlockedThisDeviceOnly). Update-first /
    /// add-if-absent, like every other write in this file — never
    /// delete-then-add. Best-effort and silent: a failure here costs one missed
    /// data point, never correctness, so it must not surface anywhere.
    func diagPut(key: String, value: String,
                 accessible: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly) {
        guard let data = value.data(using: .utf8) else { return }
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessible,
        ]
        let updateStatus = SecItemUpdate(diagBaseQuery(key) as CFDictionary, attributes as CFDictionary)
        guard updateStatus == errSecItemNotFound else { return }
        var addQuery = diagBaseQuery(key)
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = accessible
        SecItemAdd(addQuery as CFDictionary, nil)
    }

    func diagRemove(key: String) {
        SecItemDelete(diagBaseQuery(key) as CFDictionary)
    }

    // The whole diagnostic service is swept (checked) by kvDeleteAllChecked, so
    // every wipe path gets it for free — see the comment there.
}
