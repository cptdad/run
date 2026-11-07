# Rún — Privacy Policy

**Last updated:** November 3, 2026

## Overview

Rún is a secure messaging application designed to protect your privacy. This policy explains what data the app handles, what the message relay keeps, and which outside parties can be involved. It is written to match what the shipped apps and the relay actually do; where a feature is optional, it says so and says what turning it on discloses.

## Data Collection

**Rún does not collect, transmit, or store any personal data on external servers.**

- No account registration required
- No email, phone number, or name collected
- No analytics, tracking, advertising, or crash-reporting service of any kind
- No crash reports sent anywhere

Out of the box, a Rún install talks to exactly one party: the message relay, over Tor. It sends the relay nothing about you or your device beyond the encrypted message traffic itself.

Three **optional** things can send more, and each is off, absent, or user-initiated until you act: the diagnostics described under **Diagnostics You Can Choose to Send**, push notifications, and the tip jar. Neither the relay nor any third party ever receives message content.

## Data Stored on Your Device

All data is stored locally on your device, encrypted with AES-256 via SQLCipher. Opening the vault requires **two** factors together — your PIN or passphrase, and a device key held by the platform keystore (Android Keystore or iOS Keychain). Neither one alone can decrypt it.

The device key is hardware-rooted **at rest**: it is non-exportable and tied to this specific handset, so copying the vault files to another machine does not make them readable. We want to be precise about the limit of that, because it is easy to overstate: by default the device key is not held inside a dedicated secure chip while the app is running, so on a device that is powered on and already unlocked, the practical strength of your vault rests on your PIN or passphrase — which is why the higher protection levels require a long passphrase rather than a short PIN. Enabling the optional biometric / Secure Enclave binding adds a hardware barrier that must be satisfied on the device itself before the vault key can be used at all.

Both the Android and iOS apps use the same encrypted vault design:

- **PIN or passphrase credentials** — Salted and stretched with a memory-hard KDF (Argon2id), then stored only as a one-way verifier. Never stored in plaintext.
- **Contact aliases** — User-chosen pseudonyms. No real names or identifiers are stored.
- **Messages** — Never written to disk. A message exists only in memory while its conversation is open and is destroyed when the conversation closes (burn-after-read); it is never persisted at rest.
- **Relay inbox addresses** — Opaque, proof-of-work-minted addresses plus bearer capability tokens, used only to route messages. They are not derived from you and contain no identifying information.
- **Shared secrets and message keys** — Cryptographic keys exchanged via QR code, and the per-conversation ratchet state derived from them. Encrypted at rest.
- **Optional recovery code** — If you enable it, a code you hold is the only other thing that can open the vault. The app stores only an encrypted blob that the code unlocks; the code itself is never stored.

## Data Transmitted

- **Messages** are encrypted end-to-end before leaving the device. Text conversations use a Double Ratchet with fresh keys per message (forward secrecy) once both sides have sent something; texts you send before anything has arrived back from a new contact, and the small control signals described below, use a static AES-256-GCM envelope under the shared secret from your QR exchange, so a one-sided conversation stays on that envelope until the other side replies. The relay server only sees opaque encrypted blobs and cannot read message content.
- **Relay communication always goes over Tor.** The app ships its own Tor client and reaches the relay only as a Tor onion service. A production build refuses to talk to the relay any other way: if Tor is unavailable, messaging is simply off — it never falls back to a direct connection. Neither the relay nor your internet provider can learn your IP address or location from relay traffic.
- **Minimal metadata** — no read receipts, typing indicators, or user identifiers are transmitted. A coarse per-message timestamp (rounded down to the minute) travels *inside* the end-to-end-encrypted envelope, so it is readable only by your contact — never by the relay server or your network.
- **Control signals** — a few small end-to-end-encrypted notices travel between contacts the same way messages do: a one-time "new inbox" announcement when you pair, group membership changes, and — on iOS — a notice to the other person if you take a screenshot of a conversation. Each is encrypted to your contact; the relay cannot read them.
- **Push wake-up signals** — only if you turn notifications on. These are content-free; see **Third-Party Services** below.
- **Update notice** — the relay tells the app the latest published version number as part of every normal reply. This involves no extra request and nothing is sent to ask for it; the app only compares the number against its own.

### External proxy mode (Android, optional)

Instead of the built-in Tor, you can point the app at a SOCKS5 proxy you run yourself on your own device or local network. The app then sends every relay request to that proxy and does not start its own Tor. This exists so that you can inspect exactly what the app sends, or use a Tor client you already trust. Whoever controls that proxy and the network hop to it can see the app's request metadata (never message content, which stays end-to-end encrypted); the app warns you about this when the proxy is on your local network rather than on the phone itself. If the proxy is unreachable, messaging stops — the app does not fall back to anything else.

## Diagnostics You Can Choose to Send

Nothing in this section happens unless you act. All of it goes to the message relay only, over Tor, and none of it carries anything that identifies you or your device.

- **Report a bug (both platforms, one tap).** The settings screen has a "Report bug" form. When you send it, the relay receives the text you typed, the app version, and the platform name ("android" or "ios") — nothing else, and no identifier of any kind. The relay keeps reports for **90 days** and then deletes them. Please do not paste message content into a report.
- **Debug mode (both platforms, off by default, behind a consent dialog).** While you keep it on, the app streams its own diagnostic log to the relay about once a second so that connection problems can be investigated. The log is scrubbed before it leaves the device: no names or aliases, no message content, no addresses, no keys, no inbox or contact identifiers, no network identifiers. While Debug mode is on, the app also sends one short **connect-time report** after each successful connection: the platform name, the app version, how many seconds the connection took (rounded up to 5 seconds), and a coded list of which connection phases took how long. The relay keeps debug logs for **14 days** and connect-time reports for **30 days**, then deletes them. Turning Debug mode off stops both immediately; a wipe clears the setting. Nothing in this section is sent on a device where Debug mode is off.

Because these requests go over the same Tor connection the app is already using for its messages, the relay can tell that a given report or log came from the session that was just connected. That is inherent in sending them at all, and it is why their contents carry nothing the relay cannot already see from the connection itself.

## Camera Permission

The camera is used **exclusively** for scanning QR codes during contact exchange and when moving to a new device. No images or video are captured, stored, or transmitted. Camera frames are processed in memory and immediately discarded.

## Internet Permission

Internet access is used to run the built-in Tor client and, through it, to communicate with the message relay server (sending and receiving encrypted messages). That is the **only** network activity in a default install. The same Tor connection carries the optional diagnostics above if — and only if — you send them. Separately, the operating system's own push service and the store's billing and review libraries reach their own providers if — and only if — you turn notifications on, open the tip jar, or accept a review prompt; see **Third-Party Services** below.

## What the Relay Keeps

The relay is operated by the app provider. It cannot read any message. Here is what it holds, and for how long:

- **Encrypted message blobs** are held in memory only, never written to persistent storage, and are deleted once the recipient has received them or when they expire, whichever comes first: ordinary messages after **24 hours**, pairing and other control signals after at most **7 days**.
- **Inbox records** — the opaque inbox address, a one-way hash of its capability tokens, its expiry time, and a lockout counter — are kept while the inbox is in use. A freshly created inbox expires after **90 days** if never used; one that has been used by its owner is kept for up to **one year** of inactivity, so that long-quiet contacts can still reach you. These records are periodically written to disk on an encrypted volume so that a relay restart does not disconnect every user. They contain no message content and nothing that identifies you.
- **Push registrations** — if you turn notifications on, the relay stores the push token (or UnifiedPush endpoint) alongside each of your inboxes, in the same inbox records, so it can send the wake-up signal. A push token is a device address issued by Google, Apple, or your UnifiedPush server; the relay stores it as received. Turning notifications off, or wiping the app, asks the relay to delete it.
- **Diagnostics** you chose to send, for the retention periods given above.
- **Relay logs.** The relay writes an operational log (errors, counts, and startup configuration), which is also forwarded to a log server operated by the app provider. No log line carries an inbox address, a capability token, a push token, or message data. The web server in front of the relay keeps no access log.

## Data Deletion

- Messages are never written to disk on your device; they are destroyed when the conversation closes.
- **Automatic self-wipe is always on, but its thresholds depend on the protection level you chose** (Decent / Secure / Maximum — picked at first run, changeable in Settings). The app wipes itself if it has not been opened for the period below, and after that many consecutive incorrect unlock attempts:

  | Protection level | Wiped if unopened for | Wiped after this many wrong attempts |
  |---|---|---|
  | Decent | 180 days | 10 |
  | Secure | 90 days | 8 |
  | Maximum | 7 days | 5 |

  The 7-day / 5-attempt figures are **Maximum's** values only — on Decent or Secure your vault survives far longer without being opened and tolerates more wrong attempts. A wipe erases the encryption keys themselves, so whatever remains on disk is unrecoverable. A wipe also asks the relay to delete any push registration, clears Debug mode, and clears the external proxy setting.
- Uninstalling the app deletes the encrypted database and app data. On iOS, a small number of key-protection items may remain in the system Keychain until you reinstall the app (which purges them) or reset the device; these are unusable without your PIN or passphrase.
- No data is backed up to any cloud service. Backup is explicitly disabled.
- Your inboxes on the relay expire on their own per the schedule above; there is nothing in them that identifies you.

## Third-Party Services

**No build of Rún, on either platform, contains an analytics, tracking, advertising, or crash-reporting SDK**, and none of your data is ever sent to such a service. Apart from the message relay, the only outside parties Rún can involve are the ones below, and each stays dormant unless you act.

### Android

There is **one** Android build, distributed through Google Play and as a direct download. It contains the Firebase Cloud Messaging (FCM) library, the Google Play Billing library, the Google Play In-App Review library, and the UnifiedPush connector. None of them does anything until you use the feature it serves.

- **Push notifications — off unless you turn them on.** Notifications are disabled by default; out of the box Rún reaches the network only while you have it open. The Firebase library's automatic start-up is switched **off** in the app manifest, so it does not contact Google at launch or register your device merely because the app is installed. If you turn notifications on, the app picks a transport:
  - **On a phone with Google Play services**, your device registers with Google's FCM and receives a **content-free wake-up signal** — no message text, no sender, no conversation. Google learns only that something arrived for this device and roughly when.
  - **On a phone without Google Play services** (for example a de-Googled phone), the app uses **UnifiedPush**: you install a distributor app of your choice (such as ntfy) and the wake-up signal travels through the push server that distributor uses — which may be a third-party server you do not operate. That server learns the same thing Google would: that something arrived for this device and roughly when, and nothing more. The distributor and its server are chosen and controlled by you, not by us.

  In either case the message itself is fetched over Tor and decrypted on your phone after you unlock it. The app explains exactly this in the screens shown before the on/off switch. Turning notifications off revokes the registration, and every wipe asks the relay to delete it too — that last request needs a working network connection, so on an offline device it is best-effort. It makes no practical difference to you: a wipe destroys the vault and the inbox the notification would have pointed at, so a surviving registration has nothing left to signal about.
- **Tip jar — only if you open it.** The optional donation screen uses Google Play Billing. The purchase is handled entirely by Google Play; Rún receives no payment details, and the tip is not linked to any account inside the app.
- **Review prompt — only if you accept it.** After you have used the app for a while, it may once ask whether you would like to rate it. If you say yes, the Google Play In-App Review flow opens; that flow is Google's, runs under Google's own privacy policy, and sends nothing from Rún. Declining sends nothing, and the app does not ask again. The counters that decide when to ask live inside your encrypted vault.

### iOS

There is one iOS build. Optional notifications use Apple's Push Notification service, the optional tip jar uses StoreKit, and the optional review prompt uses Apple's standard rating sheet — all Apple operating-system services rather than bundled third-party SDKs.

- **Push notifications — off unless you turn them on.** If you turn them on, your device registers with Apple and receives a **content-free wake-up signal** — no message text, no sender, no conversation. Apple learns only that something arrived for this device and roughly when. Everything else works as described for Android above, including what turning notifications off and wiping do.
- **Tip jar — only if you open it.** Handled entirely by the App Store through StoreKit; Rún receives no payment details.
- **Review prompt — only if you accept it.** Apple's rating sheet; the same once-only rule as on Android.
- **Reporting a contact.** The "report" option in a conversation opens a prefilled email to the app provider in your own mail app. Nothing is sent until you choose to send that email, and it contains only what you see in the draft.

Everything else — messages, contacts, keys, and the optional diagnostics — communicates only with the message relay server, which is operated by the app provider, is reached over Tor, and holds only what **What the Relay Keeps** describes.

### The Tor network

Rún reaches the relay through the Tor network so that neither the relay nor a network observer can learn your IP address. Tor is run by the Tor Project and independent volunteers; it is a third-party network and its use is subject to the Tor Project's own practices. Rún uses Tor solely for its own connection to the relay — it is not a general-purpose proxy or VPN and routes no other app's traffic.

### Donations

The support screen shows cryptocurrency addresses (Monero and Bitcoin) for voluntary donations. This is informational only: the app processes no payment, receives and stores no wallet information, and a donation is a transaction you make yourself, outside the app, on a public blockchain governed by its own rules.

### Operating-system diagnostics

Rún contains no crash-reporting SDK and sends no crash reports. If you have separately opted in, at the operating-system level, to share diagnostics with developers, Apple or Google may provide the app provider with aggregated, anonymised crash information. That is governed by Apple's or Google's privacy policies, is outside Rún's control, and never includes message content.

## Data Sharing and Legal Requests

We do not sell, rent, trade, or share your information with anyone, for any purpose — there is no personal data to share. We would disclose information only if required by valid legal process. Because the relay holds no accounts, sees no IP addresses, and stores only unreadable ciphertext addressed to opaque identifiers, there is effectively nothing identifying for us to disclose; the most it could produce is the retention-bounded material listed under **What the Relay Keeps**, none of which names a person or device.

## Your Rights

Privacy laws such as the GDPR and CCPA give you rights to access, correct, or delete personal data a service holds about you, and not to have it sold. Because we operate no accounts and hold no personal data about you, there is nothing on our side to access, correct, delete, or sell. You already hold all of your data on your own device and can erase it instantly. If you have sent a bug report or Debug mode logs and want them deleted before their retention period ends, contact us; since they carry no identifier, you will need to tell us roughly when they were sent and from which platform so we can find them.

## International Use

Rún is available internationally. Strong encryption is regulated in some jurisdictions; you are responsible for ensuring your use of the app is lawful where you are.

## Children's Privacy

Rún does not knowingly collect any data from children under 13. The app does not collect data from anyone.

## Changes to This Policy

Any changes to this privacy policy will be reflected in app updates. The "last updated" date at the top of this document will be revised accordingly.

## Contact

For questions about this privacy policy, contact: cptdad12@proton.me
