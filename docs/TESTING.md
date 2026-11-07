# Testing Rún — What to Test

**Rún** is a privacy-first messenger: every message is end-to-end encrypted, all traffic is
routed over the **Tor network**, there are **no accounts** (no email/phone/username), and
everything is stored in an **encrypted vault** on your device, locked by a credential you
choose. Your job is to try to break it, confuse it, or find anything that looks/feels wrong.

## Before you start — please read

- **You need at least 2 devices** (or 2 testers) for messaging, pairing, and groups. A third
  helps for group tests.
- **Be patient on first launch.** The app starts the Tor network in the background — the first
  connection can take **30 seconds to a few minutes**, especially on mobile data. Watch the
  **runestone**: it pulses while connecting, glows **red** once you're on Tor, and its centre
  **ᚱ turns white** when the relay is reachable. Sending is disabled until it's connected.
- **Your credential cannot be recovered.** There's no reset and no backup by design. If you
  forget your PIN or passphrase, your data is gone. **Use a throwaway credential you'll
  remember for testing.** (The **Private** level's recovery code is *not* a PIN reset — see §1.)
- **Some tests are destructive** (they wipe all data) — they're marked ⚠️. Expect to lose your
  test contacts/messages. Because each protection level behaves differently, a throwaway setup
  **per level** is handy.
- **Screenshots are intentionally blocked** on sensitive screens (you'll get a black image) —
  that's a feature, not a bug. To report a UI issue, **describe it in words** instead.

## 1. First run — protection level & credential

On first launch you choose a **protection level** ("Choose your protection"). This is the most
important thing to test, because each level unlocks and wipes differently. (iOS: accept the
EULA first. On a rooted/emulated Android device a "Device Compromised" warning appears first —
that's expected.)

- **Casual** — a **6-digit PIN**. Smoothest; most lenient timers.
- **Private** — a **PIN *plus* your fingerprint or face** (bound to the phone's security chip).
  When you enable it you're shown a **one-time recovery code — write it down.** Needs a device
  with the right hardware (newer phones); on unsupported devices it's greyed out.
- **Maximum** — a **passphrase** instead of a PIN (typed at every unlock, **no** fingerprint or
  face). Strictest timers; the runestone shows an extra ward behind it.

Test, ideally once per level on a throwaway setup:

- Set up the level, then set + confirm your PIN/passphrase.
- Close and reopen the app — you should be asked for your credential.
- **Private:** confirm unlock uses fingerprint/face. Then test the **recovery code** — on the
  unlock screen tap **"Can't unlock? Use recovery code"** and confirm the code **plus your PIN**
  restores your data (and that a wrong code does not).
- **Maximum:** confirm it asks for the **passphrase** (no PIN pad, no biometric).
- Enter the **wrong** credential a few times — note the behavior (it slows / shakes). ⚠️ After
  enough wrong tries it **wipes everything**; the limit is **stricter at higher levels** (around
  ten at Casual, as few as five at Maximum). Only do this on a throwaway setup.
- Background the app and reopen — it should re-lock and ask again. **Auto-lock is faster at
  higher levels** (Casual is relaxed; Maximum locks within seconds).

You can also change level later in **Settings → Protection level**. Confirm that choosing
**Maximum** takes you **straight to setting a passphrase** (no separate screen, no
fingerprint/face), and choosing **Private** sets up fingerprint/face **plus** a fresh recovery
code.

## 2. Pairing / adding a contact (needs 2 devices)

- On the empty contact list you'll be asked **"Do you want quick info on how to add contacts?"**
  — try **Yes** (a short how-to carousel) and **No**.
- On each device: **Add Contact → Show My Code** / **Scan Code** (QR). Try scanning each
  other's codes.
- Confirm both devices show the new contact with a random alias (e.g. "verb + animal").
- Try this when Tor **isn't** connected yet — confirm it waits / tells you rather than failing
  silently.
- Edge: cancel mid-pairing, rescan, pair the same person twice — anything weird?

## 3. 1:1 messaging

- Send messages **both directions**; confirm they arrive and look right.
- **Offline delivery:** put the recipient's app in the background or close it, send them a
  message, then have them reopen — the message should arrive (and the contact row should show
  an unread indicator).
- **Ephemerality:** read messages, leave the conversation / close the app, reopen — confirm the
  expected disappearing behavior.
- **Cross-platform:** test **iPhone ↔ Android** messaging specifically.
- Try: very long messages, emoji, multiple languages, rapid-fire sending, sending with a weak
  signal.

## 4. Groups (best with 3 devices)

- Create a group, add your contacts, confirm everyone sees the group appear (it should show up
  **without** them opening anything).
- Send group messages from **each** member; confirm all members receive them (including
  member-to-member, not just from the creator).
- **Admin-only checks:** confirm only the group creator can add/remove members; other members
  shouldn't see those controls.
- **Leave / removal:** have a member leave; confirm the others see them disappear and a
  "left/removed" notice. Have the admin remove someone.
- **Admin transfer** (if available in the UI): hand admin to another member and confirm the
  controls move.

## 5. Referral / "introductions"

- As a contact of two people who **aren't** connected to each other, **introduce** them.
- Confirm both sides get a request, approve it, and end up with a new contact labeled
  **"Introduced by [your name]"**.
- Then confirm those two can message each other directly.

## 6. Privacy & security behaviors

- **Screenshots/screen recording:** try to screenshot a conversation/unlock screen — it should
  come out **black**. Check the **app switcher** (recent apps) — the preview should be
  hidden/covered, not showing your chats.
- **Block / Report** (iOS): block a contact, confirm they disappear and you can manage blocked
  contacts; try the Report flow.
- ⚠️ **Emergency wipe:** find and trigger the wipe; confirm it clears everything and returns you
  to first-run.
- **Inactivity:** leave the app unused for a long time and relaunch — note any auto-wipe
  behavior (a safeguard; the untouched-time before it triggers is **shorter at higher levels**).

## 7. Robustness / "try to break it"

- Toggle **airplane mode** / switch Wi-Fi ↔ mobile mid-conversation; confirm it recovers
  (reconnects Tor, resumes sending). If it stays stuck on "connecting", there's a **Reconnect**
  button — try it.
- **Kill the app** mid-send / mid-pairing / mid-group-create and reopen — is the state sane?
- Lock the phone, wait, unlock — contacts and groups should still be there.
- Low storage / low battery, OS back-button spamming, rotating the screen, rapid navigation.
- **Donations / "Support Rún" (tip jar):** open it and tap a tip tier — the store checkout
  sheet (Google Play / App Store) should appear. **Don't complete real purchases** unless asked.

## How to report a bug

For each issue, please include:

1. **What you did** (exact steps to reproduce).
2. **What happened** vs. **what you expected**.
3. **Device + OS version** (e.g. "iPhone 13, iOS 18.5" / "Pixel 7, Android 15") **and which
   protection level** you were on (Casual / Private / Maximum).
4. **How often** it happens (every time / sometimes / once).
5. A short screen recording **only if it's not a sensitive screen** (those record black) —
   otherwise describe it.

The most valuable reports are: **messages that don't arrive or arrive wrong, anything that
crashes, anything that exposes data that should be hidden** (lock screen, app switcher,
screenshots, notifications), **and anything confusing about pairing, groups, or unlocking.**

Thank you — break it thoroughly! 🛡️
