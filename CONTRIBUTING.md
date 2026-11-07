# Contributing to Rún

Thank you for looking. This file says what kind of contribution is useful right now, how to
make it, and what to run before you propose a change.

## What is open right now

**Issues are welcome.** Bug reports, questions, disagreements with the documentation,
observations about the relay's behaviour that contradict [`docs/RELAY_SPEC.md`](docs/RELAY_SPEC.md),
and translation corrections (see below).

**Pull requests are not accepted yet.** Not because the code is closed to change, but because
the contributor terms are still being decided: a DCO or a CLA, which fixes what the maintainer
may do with contributed code later (relicensing, keeping the section 7 permission in
`LICENSE-EXCEPTION`). A patch posted in an issue raises the same question, so please do not
post code yet: describe the bug, how to reproduce it and, if you like, how you would fix it.
The maintainer reproduces it, writes the fix and credits you in the commit.

**Security problems go to [`SECURITY.md`](SECURITY.md), never to a public issue.**

## How this repository is produced

Development happens in a private repository. Each release is exported into this one as a
single commit, after a gate that checks nothing private (relay addresses, device identifiers,
signing material, internal notes) is included. Consequences:

- The history here is one commit per release, not the development history.
- A branch based on this repository cannot be merged back directly; it has to be re-applied
  on the private side. That is another reason PRs are off until the process changes.
- The file `EXPORT_MANIFEST.txt` lists what the export kept and what it dropped.

## Reporting a bug

Include, as far as you can:

- Platform (Android or iOS), device model and OS version, and the app version
  (Settings → About, or the store listing).
- What you did, what you expected, what happened instead.
- Whether it happens every time.
- For connection problems: how long "Connecting…" lasted and what the connection log showed
  (triple-tap the status caption on the contact list while it is connecting). The log
  contains no identifiers.

Do not paste the contents of messages, contact names or anything from someone else's phone.
The in-app bug report (Settings → Report bug) sends only the text you type plus the app
version and platform, and goes to the relay over Tor. Use whichever you prefer.

## Translations

The app ships in 12 languages besides English. Every non-English string is produced through
the pipeline in `scripts/l10n/` from the English source files in
`androidApp/src/main/res/values/strings_*.xml`, and `scripts/l10n/l10n.lock.json` records which
English text each translation was made from. Please do not hand-edit the generated files
(`iosApp/iosApp/Localizable.xcstrings`, `L10n.swift`, `L10nKeys.kt`, `fastlane/metadata/**`).
To correct a translation, open an issue with the key or the English text, the current
translation, and your proposed wording. Security and technical terms are left in English on
purpose (see `docs/l10n/terms.md`).

## Building and testing

[`BUILDING.md`](BUILDING.md) is the reference: prerequisites, relay configuration (an empty
relay is valid and safe), the Android and iOS builds, and the invocations Gradle refuses and
why. The short version:

```
./gradlew :androidApp:assembleDebug     # alone, never together with a release task
./gradlew test                          # JVM unit tests (shared module + Android app)
./gradlew lint
```

End-to-end tests run against an emulator or simulator with the local mock relay; see
[`e2e-tests/README.md`](e2e-tests/README.md). The physical-device suites and
the tooling that schedules them are not part of this repository.

Before proposing a change, run the gates the pre-push hook runs (BUILDING.md §6): network APIs
only in the approved transport files, log calls behind the debug gate, release cleanliness,
security dependency floors, the Tor framework and Argon2 source integrity checks, and
localization freshness.

## Conventions worth knowing

- **Both platforms.** The shared Kotlin module compiles into the Android APK and the iOS
  framework. A change in `shared/` affects both; a user-visible change on one platform needs
  its counterpart on the other unless there is a stated reason. [`ARCHITECTURE.md`](ARCHITECTURE.md)
  explains the split.
- **Accessibility identifiers are an interface.** The e2e tests find views by them on both
  platforms. Keep existing ids; add new ones for new interactive views.
- **No identifiers in logs or on the wire.** Inbox ids, capabilities, onion addresses and
  contact names never appear in a log line, a telemetry payload or a bug report.
- **Vault and relay code are brick-sensitive.** Anything under the encrypted vault, the key
  derivation, the wipe paths or the message protocol has invariants documented in
  `docs/SECURITY_OVERVIEW.md` and `docs/RELAY_SPEC.md`. Read them before proposing a change
  there, and expect a slow, careful review.
- **English strings only in the source files.** Translations follow through the pipeline.

## AI assistance

Rún is developed with AI assistance. Every change is reviewed and tested by the maintainer
before it ships. Issues and discussions are read and answered by a person.

## Licence of contributions

The code is GPL-3.0-or-later with the additional permission in `LICENSE-EXCEPTION`. When pull
requests open, contributions will be accepted under those same terms, inbound as outbound, and
this file will say whether a DCO sign-off or a CLA is used. Until then, please post bug reports
and reproductions, not code: a patch in an issue carries the same rights question as a pull
request, and GitHub's terms do not settle it.

## Conduct

See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
