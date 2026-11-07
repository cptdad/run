# Security policy

Rún is a privacy-focused messenger. Its security model is described in
[`docs/SECURITY_OVERVIEW.md`](docs/SECURITY_OVERVIEW.md); the relay's observable
behaviour is specified in [`docs/RELAY_SPEC.md`](docs/RELAY_SPEC.md). This file is
about how to report a problem.

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue.

- Email: **cptdad12@proton.me**, subject line starting with `[security]`.
- Encrypt to our PGP key if your mail does not go Proton-to-Proton (that path is
  end-to-end encrypted on its own). The public key is in [`SECURITY.asc`](SECURITY.asc)
  in this repository and on Proton's key server (`gpg --locate-keys cptdad12@proton.me`).
  Fingerprint: `8FC4 A9AE 95E0 4E04 B5D1 284B DE1F 313B 1829 74A3` (Ed25519, 2026-03-31).
- Or use GitHub's private vulnerability reporting on this repository ("Report a
  vulnerability" under the Security tab). It goes over HTTPS to GitHub and never
  through mail.

Include what you can: the affected component (Android app, iOS app, shared Kotlin
module, relay as observed from the client), the version (Settings → About, or the
store listing), steps to reproduce, and what you believe the impact is. A proof of
concept helps; please do not send real users' data, and do not test against other
people's inboxes.

## What is in scope

- The Android and iOS apps and the shared module in this repository.
- The relay as its **observable behaviour**: anything the published client can make
  the relay do that `docs/RELAY_SPEC.md` says it must not. The relay source is not
  published yet, so relay-internal issues are reported the same way and fixed on our
  side.
- The build and release pipeline in this repository (gates, verification scripts,
  dependency pins).

Out of scope: a compromised operating system or rooted/jailbroken device, a contact
who leaks a conversation, social engineering, denial of service by sheer volume
against the Tor onion service, and findings that only reproduce in a debug build
(debug builds deliberately weaken several protections; see the overview).

## What to expect

- Acknowledgement within **7 days**.
- An assessment and a planned fix date within **30 days** of acknowledgement, or an
  explanation of why we disagree that it is a vulnerability.
- Fixes ship as ordinary app updates on both stores. We cannot force-update a
  device, so a fix reaches users as they update.
- **Coordinated disclosure after 90 days** from the report, or earlier once a fix has
  shipped and had time to roll out, whichever comes first. If we need longer for a
  hard problem we will say so and propose a date. You are free to publish after the
  window regardless of our status.
- Credit in the release notes and in the overview's acknowledgements if you want it;
  anonymity if you prefer. There is no bug bounty.

## Safe harbour

If you make a good-faith effort to follow this policy — testing only against your
own devices and inboxes, not exfiltrating or altering other users' data, not
degrading the service for others, and reporting privately — we will not pursue or
support legal action against you for that research, and we will not report you to a
platform or authority for it. If a third party initiates action against you for
research conducted under this policy, we will make it known that you acted in good
faith.

## Dependencies

Issues in third-party components (Tor, SQLCipher, Tink, OkHttp, the Argon2
reference implementation, the UnifiedPush connector, platform SDKs) should go to
their maintainers first; tell us too, so we can pin a fixed version quickly.
`scripts/security-deps-report.sh` lists the security-relevant dependencies and
their pinned versions.
