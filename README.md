# Rún

Rún is a private messenger for Android and iOS. You add contacts in person, by scanning each
other's QR codes; there is no account, phone number or email address. Messages are end-to-end
encrypted, held in memory only while a conversation is open, and never written to disk. The app
reaches its message relay only as a Tor onion service, through a Tor client built into the app;
a release build has no other way to connect. Rún is available on Google Play and the App Store.

## What it protects against, and what it does not

Rún is built mainly for one situation: someone takes your phone and tries to read it, possibly
with a commercial forensic extraction tool. The full threat model, and where each protection
stops, is in [`docs/SECURITY_OVERVIEW.md`](docs/SECURITY_OVERVIEW.md).

It is designed to protect against:

- **Someone with your phone.** Contacts, keys and settings live in one encrypted vault that needs
  your PIN or passphrase and a device key together. Messages are not on disk. Too many wrong
  attempts, or a long time unopened, wipes the keys. How strong this is depends on the protection
  level you choose; the overview explains why the default PIN level is the weakest.
- **The relay operator.** The relay sees encrypted blobs only, never message content, and never
  your IP address. There are no accounts, so it holds nothing that names you.
- **A network observer.** Your ISP or Wi-Fi operator sees Tor traffic and nothing about who you
  talk to. Messages are padded to size classes, so their length does not show.

It does not protect against:

- **A compromised phone.** A rooted or jailbroken device, a malicious keyboard or accessibility
  service, or malware on an unlocked phone sees what you see and type.
- **A contact who leaks.** Anyone you message can photograph their screen or hand over their phone.
- **Being watched or forced** while you unlock the app.
- **Metadata the relay can still see:** when inboxes are written and read, size classes, timing,
  and that a group exists and roughly how large it is.
- **Push providers**, if you turn notifications on: Google, Apple or your UnifiedPush server learn
  that something arrived for your device and when, never what or from whom.

## The relay is not open source yet

The relay server's source code is not published. This repository contains the client only; it
went out first.

That order is a priority, not a principle. The client is the part you can check: you can read
it, build it yourself and compare it with what you run (next section). Publishing the relay's
source would let you review that implementation too, and it is the step before running your
own relay, but it cannot show you which code our server is actually running; that stays a
statement by the operator. So the client was made to stay safe against a relay that lies, and
it was published first. The relay follows, together with a configurable relay address, so that
the code you read can be the code that runs. That is on the roadmap after the client is out.

In place of the source, [`docs/RELAY_SPEC.md`](docs/RELAY_SPEC.md) describes the relay's
behaviour: every endpoint, what each one stores, where and for how long, and what the relay
logs. Those are statements by the operator that you cannot check. The client treats the relay
as untrusted for that reason: it should stay safe even if those statements are false. The
overview lists what a hostile relay can still do (mainly drop, delay or withhold messages).

**Using the production relay from your own build.** The relay serves any client that follows
the protocol in the spec; it does not check who built the app. The one thing tied to the
official build is push on iOS, whose APNs key belongs to the official bundle id. The production
relay's onion address is `http://fmmg3eei3i6uektuo7fanp2i6i5sc6m3xfdnhwjdq7xjuow5rhispjyd.onion`.
[`relay.properties.example`](relay.properties.example) already carries it: copy that file to
`relay.properties` (or set `RELAY_ONION_URL`) and your build messages over the same relay as
the store apps. Details in [`BUILDING.md`](BUILDING.md), section 3.

## Verifying what you run

Publishing the source does not by itself prove that a store binary was built from it.

- **Build from source.** [`BUILDING.md`](BUILDING.md) takes you from a fresh clone to an Android
  APK and an iOS app on your own devices. This is the strongest check available today.
- **iOS App Store binaries cannot be matched to this source by users.** Apple encrypts and
  re-signs every App Store binary for each device, so nobody outside Apple can show that a
  downloaded copy was built from this code. If you need that certainty, build and install your
  own copy with Xcode.
- **A self-built iOS copy gets no push notifications.** The relay's Apple push key is tied to the
  official bundle ID. Everything else works.
- **Android reproducible builds are planned**, so that you can compare the store or
  direct-download APK with your own build. They are not available yet.
- **Watch the traffic.** On Android (app versions after 1.6.32), the external SOCKS proxy mode lets you route the app through
  a SOCKS5 proxy you run and log every request it makes. This checks behaviour, not the binary,
  and cannot show what is inside the encrypted blobs. See
  [`docs/external-socks-proxy.md`](docs/external-socks-proxy.md).

## Security

- To report a vulnerability, follow [`SECURITY.md`](SECURITY.md). Please report privately, not in
  a public issue.
- The security model, the protection levels and the known limitations are in
  [`docs/SECURITY_OVERVIEW.md`](docs/SECURITY_OVERVIEW.md).

Rún has had no independent third-party security review yet.

## Privacy

What data exists, where it goes and how long the relay keeps it is in
[`docs/PRIVACY_POLICY.md`](docs/PRIVACY_POLICY.md). The app contains no analytics, tracking,
advertising or crash-reporting code, and its diagnostics (bug reports and Debug mode) are sent
only if you choose to send them.

## Repository map

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — code tour: where the vault, ratchet, wire format, wipe
  and connect path live, and a reading order.
- [`BUILDING.md`](BUILDING.md) — prerequisites, relay configuration, Android and iOS builds, tests.
- `shared/` — Kotlin Multiplatform module with nearly all protocol, crypto and vault logic.
- `androidApp/` — the Android app (Jetpack Compose).
- `iosApp/` — the iOS app (SwiftUI), the Swift side of the platform bridges, and the pinned Tor
  framework.
- `e2e-tests/` — single-device end-to-end specs for an emulator or simulator, with a mock relay.
- `docs/` — security overview, relay specification, privacy policy and engineering references.

## Contributing

Issues are welcome: bug reports, questions, and disagreements with the documentation. Pull
requests are not accepted at this stage, because the contributor agreement is still being decided.
[`CONTRIBUTING.md`](CONTRIBUTING.md) has the details, including how this repository is produced
from the private one; [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) applies in every project space.

The app is translated into 12 languages besides English. Translations are produced through the
pipeline in `scripts/l10n/` and kept in step with the English text there.

## Development

Rún is developed with AI assistance; every change is reviewed and tested by the maintainer.

## Licence

The client code is free software, licensed under the GNU General Public License, version 3 or
later (GPL-3.0-or-later; [`LICENSE`](LICENSE)), with an additional permission under its
section 7 ([`LICENSE-EXCEPTION`](LICENSE-EXCEPTION)) that lets the program be linked with the
Google and Apple platform libraries it uses and be distributed through the app stores.

"Open source" here means the client code. The relay is not published yet (above). The name
"Rún", the app icon and the runestone artwork are not free: the code licence does not cover
them, the artwork is under CC BY-NC-ND 4.0, and forks must use their own name and artwork. See
[`TRADEMARK.md`](TRADEMARK.md) and [`LICENSE-ART`](LICENSE-ART).

Third-party components keep their own licences; see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Contact

cptdad12@proton.me
