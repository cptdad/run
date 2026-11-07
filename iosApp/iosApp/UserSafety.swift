import SwiftUI
import UIKit
import Security
import LocalAuthentication
import shared

// ---------------------------------------------------------------------------
// UserSafety — App Store Guideline 1.2 (user-generated content) precautions.
//
// Rún is end-to-end encrypted: the relay only ever sees opaque ciphertext, so
// there is no server-side feed to moderate and no content for us to inspect.
// The required safeguards are therefore client-side and centre on the one
// abusive actor a user can actually point at — a paired contact:
//
//   • EULA      — a terms agreement with an explicit zero-tolerance clause,
//                 shown BEFORE the user sets up or unlocks a vault (EulaView,
//                 gated in ContentView).
//   • Report    — a per-contact "Report" action that opens a prefilled email
//                 to Rún support so we can act within 24 h (AbuseReport).
//   • Block     — a per-contact "Block" action that hides the contact and all
//                 their messages from the UI (BlockStore + filtering in
//                 ContactListView/ConversationView) AND threads the block set into
//                 the shared poll: a blocked inbox is skipped on BOTH the text and
//                 control channels, so block suppresses the
//                 network fetch, not just the display (best-effort; see BlockStore).
//                 Block does NOT touch group membership: a blocked contact who
//                 shares a group with the user stays a member of it. The group SEND fan-out
//                 (GroupManager.kt's sendGroupMessage/sendGroupScreenshotNotice)
//                 also honors the block set — the same protection every group
//                 RECEIVE path already had — but a blocked member obviously still
//                 gets copies from every OTHER (non-blocking) member. ContactListView's
//                 block-confirm flow now surfaces that: it offers to leave a shared
//                 group, or block anyway, at block time (showBlockGroupWarning) —
//                 never automatic, so block stays reversible.
//   • Unblock   — BlockedContactsView, reachable from the settings menu.
//
// Everything lives in this one file so the Xcode project only needs a single
// new source reference.
// ---------------------------------------------------------------------------

// MARK: - EULA consent

/// Records whether the user has accepted the current EULA. Backed by
/// UserDefaults (NOT the Keychain device key): the EULA gate must render
/// BEFORE the vault is unlocked — and even before a device passcode unlock on a
/// fresh launch — where the Keychain device key is unreadable. Acceptance is
/// not sensitive, so the file-protected UserDefaults plist is the right home.
/// Bump `version` whenever the terms change to re-prompt every user.
enum EulaConsent {
    static let version = 2   // bumped 2026-06-17: Report/Block terms reworded → re-prompt
    static let storageKey = "eula_accepted_version"

    /// Contact address surfaced in the EULA and used for abuse reports.
    /// Change this to a dedicated support inbox before launch if desired.
    static let supportEmail = "cptdad12@proton.me"
}

/// Full-screen terms gate. Shown until the user accepts; there is no way past
/// it without agreeing (Decline explains the app cannot be used otherwise).
struct EulaView: View {
    let onAccept: () -> Void
    @State private var showDecline = false

    var body: some View {
        ZStack {
            Color.runBackground.ignoresSafeArea()

            VStack(spacing: 0) {
                Text(L10n.eulaBeforeYouStartTitle)
                    .font(.runeTitle2).bold()
                    .foregroundColor(Color.runTextPrimary)
                    .padding(.top, 24)
                    .padding(.bottom, 4)
                Text(L10n.eulaTermsOfUseTitle)
                    .font(.runeSubheadline)
                    .foregroundColor(Color.runTextSecondary)
                    .padding(.bottom, 12)

                ScrollView {
                    Text(L10n.eulaBody(EulaConsent.supportEmail))
                        .font(.runeFootnote)
                        .foregroundColor(Color.runTextPrimary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 20)
                        .padding(.bottom, 16)
                        .accessibilityIdentifier("eula_text")
                }

                VStack(spacing: 10) {
                    Button {
                        onAccept()
                    } label: {
                        // ONE line, never a mid-word break (2026-09-11): shrink to fit instead.
                        Text(L10n.eulaAgreeButton)
                            .lineLimit(1)
                            .minimumScaleFactor(0.5)
                            .fontWeight(.semibold)
                            .foregroundColor(Color.runBackground)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .background(Color.runTextPrimary)
                            .clipShape(Capsule())
                    }
                    .accessibilityIdentifier("eula_agree_button")

                    Button {
                        showDecline = true
                    } label: {
                        Text(L10n.commonDecline)
                            .foregroundColor(Color.runTextSecondary)
                            .padding(.vertical, 8)
                    }
                    .accessibilityIdentifier("common_decline")
                }
                .padding(.horizontal, 24)
                .padding(.bottom, 20)
            }
        }
        // localization PHASE 0: containerA11yId (accessibilityElement(children:
        // .contain) + id) instead of a bare accessibilityIdentifier, so the
        // Agree/Decline buttons' own ids (eula_agree_button/eula_decline_button)
        // surface instead of being shadowed by this root id — see
        // UIComponents.swift's OptionalContainerA11yId for why.
        .containerA11yId("eula_screen")
        .runeDialog(isPresented: $showDecline, title: L10n.eulaDeclineAlertTitle,
                    message: L10n.eulaDeclineAlertMessage,
                    actions: [RuneDialogAction(L10n.commonOk) { }])
    }

    // The terms body now lives in strings_onboarding.xml (key eula_body) —
    // see L10n.eulaBody(_:), called from the Text() above. Deliberately short
    // and plain-language; the middle paragraph is the App Store Guideline 1.2
    // zero-tolerance clause.
}

// MARK: - Block store (Keychain-backed)

/// Persistent set of blocked contact IDs. Stored in the Keychain (device-only,
/// readable after first unlock) rather than the vault, so blocking does not
/// require a schema change to the shared/cross-platform vault database. Blocked
/// contacts are filtered out of the contact list and their conversations are
/// closed, so a blocked contact's messages never reach the UI. The shared
/// background sweeps EXCLUDE these IDs on BOTH channels: the TEXT peek
/// (contactUnreadCounts/peekUnreadCounts) and
/// the CONTROL channel too (GroupManager.blockedContacts, set from
/// BlockStore.blocked(): pollAllControls/pollGroup skip a blocked contact's
/// inbox and ingest drops any invite/referral-offer/inbox-announce from a
/// blocked sender). So a blocked contact's inbox is normally not polled on either
/// channel and can neither surface a consent modal nor mutate the vault — block
/// suppresses the network fetch, not just the display. BEST-EFFORT, not absolute:
/// blocked() FAILS OPEN (returns []) if the WhenPasscodeSet Keychain
/// item is unreadable — e.g. the device is screen-locked while the app vault is
/// still unlocked (before the 2-min auto-lock) — so a blocked inbox may be polled
/// for that window. Availability is favored for this harassment-safety feature; a
/// vault-at-rest block list would remove even this window.
///
/// The stored value is device-key AEAD
/// ciphertext (CryptoProvider), same as every KeyValueStore value, NOT raw JSON —
/// a Keychain dump alone no longer discloses the blocked-contact social graph. A
/// leading format-marker byte (`encFormatMarker`) distinguishes this from a
/// pre-fix plaintext item so an existing block list keeps decoding (see
/// `blocked()`); `save()` always writes the new sealed format, so the first
/// block/unblock after upgrading migrates the item in place. The Keychain
/// accessibility class is unchanged by this fix (still strict-first with the
/// existing no-passcode fallback, self-healed back to strict opportunistically —
/// see `upgradeAccessibilityToStrict()`): removing that fallback outright would
/// silently break Block on any passcode-less device (the physical test phones's
/// iPhones included), since `blocked()` re-reads the Keychain rather than caching
/// in memory, so a failed write is a failed block, not just weaker at rest. The
/// AEAD seal is what actually closes the plaintext-outside-the-vault leak; the
/// fallback class only ever holds ciphertext now, bound to the same device key
/// that already sits at that class on such a device.
enum BlockStore {
    private static let service = "com.vg.run.crypto"
    private static let account = "blocked_contacts_v1"

    /// AEAD context binding for the sealed block list — mirrors InactivityWipe's
    /// `context` constant. Deliberately distinct from any other CryptoProvider
    /// caller's context string.
    private static let aeadContext = "blocked-contacts-v1"

    /// Leading byte of the new sealed format: version-marker + ciphertext. Chosen
    /// as a control byte (0x00) so it can never collide with the first byte of a
    /// pre-fix plaintext item, which is always the JSON array opener `[` (0x5B) —
    /// that's what lets `blocked()` tell the two formats apart unambiguously.
    private static let encFormatMarker: UInt8 = 0x00

    static func blocked() -> Set<String> {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data, !data.isEmpty else {
            return []
        }
        // Best-effort self-heal (mirrors KeychainHelper.upgradeAccessibilityToStrict(),
        // which does not reach this service/account): promotes an item still sitting
        // on the no-passcode fallback class back to strict once a passcode exists,
        // without waiting for the next block/unblock write. SecItemUpdate touches
        // only the accessibility attribute, never the value, so this is safe to run
        // unconditionally and is a no-op when already strict.
        upgradeAccessibilityToStrict()

        if data[data.startIndex] == encFormatMarker {
            // blocked() runs on EVERY control-poll cycle and
            // again per contact inside GroupManager, so each call used to leave a
            // separate populated 32-byte device key behind in freed Kotlin/Native heap
            // — dozens to hundreds per session, which defeats the zeroing AppState.lock()
            // performs on the vault's own provider and on inactivityCrypto. The `defer`
            // zeroes this short-lived instance on EVERY exit path, including the two
            // early `return []`s below.
            let crypto = CryptoProvider()
            defer { crypto.wipeKey() }
            let decrypted: KotlinByteArray?
            do {
                decrypted = try crypto.tryDecrypt(
                    ciphertext: kotlinByteArray(from: data.dropFirst()),
                    contextInfo: kotlinByteArray(from: aeadContext))
            } catch {
                // Device key transiently unavailable (locked keybag / wiped) — fail
                // open, same as every other unreadable-item case here.
                return []
            }
            guard let decrypted,
                  let ids = try? JSONDecoder().decode([String].self, from: dataFromKotlin(decrypted)) else {
                return []
            }
            return Set(ids)
        }

        // Pre-fix plaintext item (no format marker): still decodable so an existing
        // block list is never silently dropped. save() below rewrites it into the
        // sealed format on the next block()/unblock().
        guard let ids = try? JSONDecoder().decode([String].self, from: data) else {
            return []
        }
        return Set(ids)
    }


    static func block(_ id: String) {
        var set = blocked(); set.insert(id); save(set)
    }

    static func unblock(_ id: String) {
        var set = blocked(); set.remove(id); save(set)
    }

    /// Drops the entire block list — called from AppState.emergencyWipe so a
    /// wipe leaves nothing behind.
    static func clear() {
        SecItemDelete(baseQuery() as CFDictionary)
    }

    private static func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    private static func deviceHasPasscode() -> Bool {
        var error: NSError?
        if LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) { return true }
        return error?.code != LAError.passcodeNotSet.rawValue
    }

    /// Sibling of KeychainHelper.upgradeAccessibilityToStrict() /
    /// upgradeKvAccessibilityToStrict(), which do NOT
    /// reach this service/account (they filter on "device_key" / the kv service).
    /// Promotes an item still on the no-passcode AfterFirstUnlock fallback back to
    /// the strict class once a passcode exists. SecItemUpdate only changes the
    /// accessibility attribute, never the value, so this is idempotent and safe to
    /// call unconditionally (no-op when already strict or when there's still no
    /// passcode).
    private static func upgradeAccessibilityToStrict() {
        let attrs: [String: Any] = [
            kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        ]
        SecItemUpdate(baseQuery() as CFDictionary, attrs as CFDictionary)
    }

    /// Update-first / add-if-absent — NEVER delete-then-add. A
    /// delete-then-failed-add (crash/jetsam between the two) would leave NO item, so
    /// the next launch would decode nothing and silently UNBLOCK every contact.
    /// SecItemUpdate leaves the existing item intact on any failure; SecItemAdd runs
    /// only when none exists. (Mirrors KeychainHelper.addOrUpdateKey.)
    private static func addOrUpdate(_ data: Data, accessible: CFString) -> OSStatus {
        let attrs: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessible,
        ]
        let updateStatus = SecItemUpdate(baseQuery() as CFDictionary, attrs as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var add = baseQuery()
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = accessible
            return SecItemAdd(add as CFDictionary, nil)
        }
        return updateStatus
    }

    private static func save(_ set: Set<String>) {
        // Encode FIRST and abort on failure — never write an empty `?? Data()`
        // that would decode to [] on read (a silent mass-unblock).
        guard let json = try? JSONEncoder().encode(set.sorted()) else {
            return  // encode failed — keep the prior item, never write empty
        }
        // Seal the JSON under the device-key
        // AEAD before it ever reaches the Keychain — a fresh CryptoProvider() is used
        // and allowed to fall out of scope on return rather than retained, so this
        // enum doesn't hold a long-lived RAM copy of the device key across a vault
        // lock (unlike AppState.inactivityCrypto, which is deliberately wiped on
        // lock/background — BlockStore has no such lifecycle hook to piggyback on).
        // Falling out of scope is NOT enough — ARC releasing
        // the provider frees its 32-byte device-key copy without zeroing it. Wipe it
        // explicitly on every exit path, exactly like the sibling in blocked().
        let crypto = CryptoProvider()
        defer { crypto.wipeKey() }
        guard let ciphertext = try? crypto.encrypt(
            plaintext: kotlinByteArray(from: json), contextInfo: kotlinByteArray(from: aeadContext)) else {
            // Device key unavailable (locked keybag / wiped) — never fall back to
            // writing plaintext; keep whatever was there before, same discipline as
            // the encode-failure guard above.
            return
        }
        var data = Data([encFormatMarker])
        data.append(dataFromKotlin(ciphertext))
        // Strict at-rest class: legible only while the device is currently unlocked.
        let status = addOrUpdate(data, accessible: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
        // Downgrade to the weaker AfterFirstUnlock class ONLY when
        // the device genuinely has NO passcode. errSecNotAvailable is ALSO returned
        // for a transiently-locked keybag; downgrading then would legibly persist the
        // blocked-contact list on a seized, locked-but-powered device. Passcode set →
        // fail closed (keep the strict class / prior item), mirroring KeychainHelper.
        if status == errSecParam || status == errSecNotAvailable {
            // Passcode set → keybag is only transiently locked; fail closed (keep the
            // strict class / prior item) rather than downgrading legibility.
            guard !deviceHasPasscode() else { return }
            _ = addOrUpdate(data, accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        }
    }
}

// MARK: - Abuse reporting (mailto, with a no-mail-client fallback)

/// Opens a prefilled report email to Rún support. mailto keeps Rún backend-free
/// and works with whatever mail client the user has configured. Message content
/// is never persisted by Rún, so the report identifies the contact by the name
/// the user gave it and asks them to describe what happened in their own words.
///
/// What the prefill deliberately does NOT contain: this
/// draft lands in the system mail app, OUTSIDE Rún's sandbox, in unencrypted
/// storage that survives a crypto-erase.
///   • `contactId` is a locally-generated UUID that support cannot act on, so
///     including it was pure forensic residue — dropped. The parameter is kept
///     for the existing call sites and is intentionally unused.
///   • The body no longer invites the user to paste decrypted message plaintext
///     into the draft; it asks for a description instead and says plainly that
///     the email leaves Rún's encrypted storage. Guideline 1.2 is unaffected —
///     the EULA already states we act on what the user tells us, because the
///     messages themselves are end-to-end encrypted.
///
/// If the device has no mail client, `UIApplication.open` reports failure — it
/// would otherwise do nothing, a silently dead "Report" button that a reviewer
/// could read as a missing Guideline 1.2 safeguard. We then surface an alert
/// with the support address and a one-tap "Copy report" so the user can still
/// file it from any app.
enum AbuseReport {
    static func compose(contactAlias: String, contactId: String) {
        _ = contactId   // Deliberately NOT exported — see the note above.
        let subject = L10n.reportAbuseEmailSubject
        let body = L10n.reportAbuseEmailBody(contactAlias)

        var components = URLComponents()
        components.scheme = "mailto"
        components.path = EulaConsent.supportEmail
        components.queryItems = [
            URLQueryItem(name: "subject", value: subject),
            URLQueryItem(name: "body", value: body),
        ]
        guard let url = components.url else {
            presentFallback(subject: subject, body: body)
            return
        }
        // completionHandler is the only reliable signal that a mailto handler
        // exists: canOpenURL(mailto:) needs an LSApplicationQueriesSchemes entry
        // and still lies on some configs, so we just try and react to failure.
        UIApplication.shared.open(url, options: [:]) { success in
            if !success { presentFallback(subject: subject, body: body) }
        }
    }

    /// Blank mailto to support — the entry point for the "Terms & contact"
    /// settings surface (TermsContactView, Guideline 1.2 bullet 8), which
    /// isn't attached to any one contact the way `compose` above is. Reuses
    /// the exact same open/fallback mechanics: try mailto first, and if no
    /// mail client handles it, fall back to the address + "Copy report" alert.
    static func openSupportEmail() {
        var components = URLComponents()
        components.scheme = "mailto"
        components.path = EulaConsent.supportEmail
        guard let url = components.url else {
            presentFallback(subject: "", body: "")
            return
        }
        UIApplication.shared.open(url, options: [:]) { success in
            if !success { presentFallback(subject: "", body: "") }
        }
    }

    /// Shown when no mail client handled the mailto URL. Keeps the report
    /// actionable: the user copies a ready-to-send report and pastes it into any
    /// mail/notes app addressed to the support inbox.
    private static func presentFallback(subject: String, body: String) {
        let email = EulaConsent.supportEmail
        let alert = UIAlertController(
            title: L10n.reportEmailFallbackTitle,
            message: L10n.reportEmailFallbackMessage(email),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: L10n.reportCopyReportButton, style: .default) { _ in
            let report = L10n.reportCopyReportClipboard(email, subject, body)
            // localOnly keeps the abuse report off Universal Clipboard / Handoff
            // (no off-device sync to other Apple devices).
            // The old 180 s expiry with NO active clear was
            // the weakest clipboard discipline in the app. Mirror the sibling in
            // AddContactView (my-code copy): a SHORT expiry as the killed-before-the-
            // timer backstop, PLUS a timer that actually empties the pasteboard. 60 s
            // is long enough to switch to another app and paste, a third of the old
            // window, and the expiry still covers the case where the app is
            // backgrounded (this timer only fires while we are running).
            SensitivePasteboard.copy(report, expiresAfter: 60, clearAfter: 60)
        })
        alert.addAction(UIAlertAction(title: L10n.commonOk, style: .cancel, handler: nil))
        topViewController()?.present(alert, animated: true)
    }

    /// Top-most presented view controller — needed to present the fallback alert
    /// from this non-SwiftUI helper. The app is a single SwiftUI scene in a
    /// UIHostingController, so we walk up from the key window's root.
    private static func topViewController() -> UIViewController? {
        let windowScenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let scene = windowScenes.first { $0.activationState == .foregroundActive } ?? windowScenes.first
        let window = scene?.windows.first { $0.isKeyWindow } ?? scene?.windows.first
        var top = window?.rootViewController
        while let presented = top?.presentedViewController { top = presented }
        return top
    }
}

// MARK: - Blocked-contacts management

/// Lists currently blocked contacts and lets the user unblock them. Reachable
/// from the settings (cogwheel) menu. A blocked contact keeps its vault record,
/// so its alias is still available to show here.
struct BlockedContactsView: View {
    @EnvironmentObject private var appState: AppState
    let onClose: () -> Void

    @State private var rows: [Row] = []

    struct Row: Identifiable {
        let id: String       // contactId
        let alias: String
    }

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Color.runBackground.ignoresSafeArea()

            VStack(spacing: 0) {
                Text(L10n.contactListBlockedContacts)
                    .font(.runeHeadline)
                    .foregroundColor(Color.runTextPrimary)
                    .padding(.top, 20)
                    .padding(.bottom, 12)

                if rows.isEmpty {
                    Spacer()
                    Text(L10n.reportBlockedEmptyState)
                        .font(.runeSubheadline)
                        .foregroundColor(Color.runTextSecondary)
                        .accessibilityIdentifier("blocked_empty_state")
                    Spacer()
                } else {
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(rows) { row in
                                HStack {
                                    Text(row.alias)
                                        .font(.runeBody)
                                        .foregroundColor(Color.runTextPrimary)
                                        .lineLimit(1)
                                    Spacer()
                                    Button {
                                        BlockStore.unblock(row.id)
                                        NotificationCenter.default.post(name: .contactsChanged, object: nil)
                                        load()
                                    } label: {
                                        Text(L10n.reportUnblockButton)
                                            .font(.runeCaption)
                                            .foregroundColor(Color.runTextPrimary)
                                            .padding(.horizontal, 12)
                                            .padding(.vertical, 6)
                                            .background(Color.runSurface)
                                            .clipShape(Capsule())
                                    }
                                    .accessibilityIdentifier("unblock_\(row.id)")
                                }
                                .padding(.horizontal, 20)
                                .padding(.vertical, 12)
                            }
                        }
                    }
                }
            }

            Button(action: onClose) {
                Image(systemName: "xmark")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundColor(Color.runTextPrimary)
                    .padding(12)
            }
            // An icon-only Button is unreliably surfaced in the accessibility tree
            // (XCUITest/VoiceOver both need a label): give it one so the close control
            // is reachable by assistive tech AND by the e2e block round-trip.
            .accessibilityLabel(L10n.commonClose)
            .accessibilityIdentifier("blocked_close")
            .padding(.top, 8)
            .padding(.trailing, 8)
        }
        .preferredColorScheme(.dark)
        .accessibilityIdentifier("blocked_contacts_modal")
        .onAppear { load() }
    }

    private func load() {
        guard let vault = appState.vault else { rows = []; return }
        let blocked = BlockStore.blocked()
        // getAllContacts() carries a live
        // sharedSecret per record; wipe the UNFILTERED source list once the
        // secret-free Row projection is built — the filtered-out (non-blocked)
        // records must not keep an un-zeroed secret either.
        let allContacts = vault.getAllContacts()
        rows = allContacts
            .filter { blocked.contains($0.contactId) }
            .map { Row(id: $0.contactId, alias: $0.alias) }
        for contact in allContacts { contact.sharedSecret.secureWipe() }
    }
}
