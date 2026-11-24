# Rún — Security Overview

This document explains what Rún protects against, how, and where the protection stops. It is
written for readers who want to decide whether to trust the app. It describes the shipped Android
and iOS apps. The relay server is described from the client's side: what the client sends it and
what the operator says it keeps.

Two companion documents go deeper:

- `docs/vault-relay-internals.md` is the detailed engineering reference for the vault, key
  handling, wipe logic and the relay protocol.
- `docs/PRIVACY_POLICY.md` lists what data exists, where it goes and how long the relay keeps it.

If this overview and the code disagree, the code is right and this document is a bug. Please
report it.

---

## 1. Threat model

Rún is built mainly for one situation: **someone takes your phone and tries to read it**, possibly
with a commercial forensic extraction tool, possibly after the phone has been unlocked at least once
since it was powered on.

The adversaries considered, in order of priority:

1. **Physical possession of the phone.** An examiner with the device, a full filesystem image (taken
   before or after first unlock), and time to work offline. Goal: nothing readable at rest, nothing
   readable from an image without your credential, and a self-wipe that destroys the keys when the
   app is abandoned or guessed at.
2. **A curious or compromised relay.** The relay operator, or anyone who takes over the relay host.
   Goal: the relay never sees message content, never learns your IP address, and holds nothing that
   names you. It does see traffic metadata, listed in section 5.
3. **A network observer.** Your ISP, a Wi-Fi operator, or anyone on the path. Goal: they see Tor
   traffic and nothing more about who you talk to.

**Out of scope.** Rún does not defend against:

- **A compromised operating system** (a rooted or jailbroken phone with an attacker's code in it, a
  malicious keyboard, a hostile accessibility service). Such code sees what you see and type.
- **A contact who leaks.** Anyone you message can photograph their screen, forward what you said, or
  hand over their own phone. On iOS, Rún can tell you when the other person takes a screenshot, but
  it cannot prevent it.
- **Targeted malware on an unlocked phone**, or someone who watches you unlock it, or who forces you
  to.
- **Push providers.** If you turn notifications on, Google, Apple or your UnifiedPush server learns
  that something arrived for your device and when. Content never goes through them.

## 2. The vault

Everything the app keeps on the device (contacts, aliases, keys, inbox addresses, ratchet state)
lives in one encrypted database, the vault. **Messages are not written to disk at all.** What the
app keeps in memory, and for how long:

- **A message you have opened** is erased when you leave its chat or the app locks. After that, no
  late network reply can put it back on a closed screen or into a locked session.
- **A message still waiting to be shown** because its sender is not yet confirmed (a group member
  your phone has not matched to a contact yet, or a group whose invitation has not arrived) stays
  in memory until it is shown or the app locks. It is never shown more than ten minutes after it
  arrived and is dropped from memory at the next background check or conversation refresh after
  that (there is no separate timer), or at the lock. If the app locks first it is
  lost unseen: by then the relay has normally deleted its copy. A waiting message from a confirmed
  sender stays until its chat shows it or the app locks.
- **Locking ends everything.** On lock, background or wipe every waiting message is discarded and
  nothing about them is saved, not even a count.
- On Android, opening Group Info leaves the group chat, so the chat's messages are erased; on iOS
  Group Info is a sheet over the chat and they stay until you leave the chat.
- A message from another conversation can appear inside the chat you have open (a private message
  shown in a group, a message of another group shown in a group or in a private chat). By design it
  is shown there in full, on both platforms, and accessibility services can read it like any other
  text on screen. When you take a screenshot on iOS, a notice therefore goes to the chat you have
  open AND to every conversation whose message is in that chat's list (once each, best effort, never
  retried), so the people in those conversations learn of the capture too. Android sends no notice;
  its release builds block screenshots.

"Erased" means the app drops every reference to the text. What the app cannot control: copies the
operating system keeps in memory it manages itself (text layout and drawing caches, the accessibility
tree, the system's own string copies) and when the runtime's garbage collector reuses that memory.
These have not been measured on a device.

### Encryption and the two factors

The vault is a SQLCipher database (AES-256). Its key is wrapped in two layers:

1. an inner layer under a key derived from your **PIN or passphrase**, and
2. an outer layer under a **device key** held by the platform keystore.

Neither factor opens the vault alone. Your PIN is checked against a stored verifier in constant
time. Nothing about the PIN is stored in plaintext.

**Key derivation.** New vaults and every PIN change use **Argon2id at 64 MiB of memory, 3 passes,
1 lane**. Each vault records the cost it was created with and keeps using it. Vaults created by
older versions (PBKDF2) still open and are upgraded to Argon2id on the next successful unlock.
Release builds run Argon2id from the same reference C sources on both platforms.

Note on debug builds: a debug build (one you compile yourself in debug mode) uses a deliberately
weak cost of 1 MiB × 1 pass so testing stays fast. Do not keep real data in a debug build. If a
vault created by a debug build is later opened by a release build, the release build re-derives it
at the release cost on that first unlock.

### What the device key really is

The device key is hardware-rooted **at rest** on both platforms. It is not exportable and is tied
to this handset, so copying the vault files to another machine gets an attacker nothing. Its limits:

- **Android.** The device key is a Tink AES keyset. On disk it is wrapped by a non-exportable
  Android Keystore key (StrongBox when the phone has one, otherwise the TEE) that only works while
  the device is unlocked. Once the app unwraps the keyset, it is ordinary software key material in
  the app's memory.
- **iOS.** The device key is a Keychain item that can only be read while the device has a passcode
  and is unlocked (`WhenPasscodeSetThisDeviceOnly`). By default it is **not** a Secure Enclave key.

So by default, **on a phone that is powered on and has been unlocked, the device key can be
reached, and your vault rests on your PIN or passphrase and the Argon2id cost.** A 6-digit PIN has
one million possible values. An attacker who has the device key and the wrapped blobs can try them
offline, where no attempt counter runs. The higher protection levels exist because of this.

A phone with **no screen lock** gives the device key away for free. Rún detects this at every
unlock and forces such a phone onto the Maximum level, after you acknowledge what that means.

### The three protection levels

You pick a level at first run. You can change it later in Settings.

| | Decent | Secure | Maximum |
|---|---|---|---|
| Credential | 6-digit PIN | 6-digit PIN | Passphrase, at least ~70 bits estimated |
| Hardware-bound vault key | no | yes, biometric | no |
| Recovery code | no | yes | no |
| Idle auto-lock | 15 min | 2 min | 60 s |
| Wipe if not opened for | 180 days | 90 days | 7 days |
| Wipe after wrong attempts in a row | 10 | 8 | 5 |

On every level, the app also wipes after 30 wrong attempts within 24 hours, whether or not they
were in a row. Leaving the app (backgrounding it) locks the vault and clears its keys from memory
on every level.

**Decent** relies on the PIN and the Argon2id cost. It is not built to survive a determined
examiner who holds the device key.

**Secure** adds a **hardware-bound key**. The vault key's outer layer is wrapped by a key that
lives in the phone's secure hardware and is only released after a **strong biometric** check, with
no passcode fallback:

- Android: an RSA key in the Android Keystore (StrongBox if present, otherwise the TEE), requiring
  a Class 3 biometric for every use.
- iOS: a P-256 key generated inside the Secure Enclave, with access control `biometryCurrentSet`.

Knowing your PIN is then not enough. The vault also needs your fingerprint or face on that phone.
A forced biometric unlock still works, and a passcode cracked by a forensic tool does not.
Changing enrolled fingerprints or faces destroys this key by design. The recovery code below is
then the only way back in. This level needs biometrics enrolled and is unavailable otherwise.

**Maximum** replaces the PIN with a passphrase that must estimate at roughly 70 bits or more. The
estimate is deliberately conservative: words are scored as word choices, not letters, and a run of
letters typed without spaces is scored as natural language, so a song line or a quote does not
qualify however long it is. It uses no biometrics and no hardware binding. Its strength comes from the passphrase alone, so it
stays shut even after the device key has been extracted. It also uses a password-style message
keyboard so the system keyboard does not learn your words.
On iOS, Rún blocks third-party keyboards inside the app at every level, so only the system
keyboard sees what you type there. Android cannot block them, so on message fields Rún instead
asks the keyboard not to learn from what you type (a no-personalized-learning hint).

### The recovery code: a second way into the vault

When you enable Secure, the app shows you a **recovery code** once: 160 random bits written as
32 Base32 characters. The app never stores it. It stores the vault's database key wrapped under a
key derived from the code, and that wrapped blob is itself sealed with the default device key.

This is a **second, independent way to decrypt the vault**. Cryptographically it does not need
your PIN or your biometric: anyone who has the code and this phone's default device key can
recover the database key. The in-app recovery screen also asks for your PIN and counts wrong
entries toward the 30-per-day wipe limit, but that is app logic, not cryptography. **Store the code as
carefully as the phone itself.** After a recovery on a phone that can still hardware-bind, the
binding is switched straight back on under the **same** recovery code, which stays valid — keep
guarding it. Only if the phone can no longer hardware-bind does the binding stay off; the used code
then opens nothing, and turning the binding back on later creates a new code.

### Wipe

A wipe **destroys the keys first** (Keystore and Keychain keys, the wrapped device keyset, the
credential and recovery blobs) and then deletes the files. What remains on disk is ciphertext with
no key. A wipe also clears Debug mode, the external proxy setting and the in-memory contact data,
and it sends a best-effort, non-blocking request asking the relay to forget push registrations.

Wipes happen on the inactivity and wrong-attempt limits above. The inactivity wipe runs the next
time the app is opened after the limit has passed, on an unlocked phone; nothing erases the vault
while the app is never opened. You can also trigger one after
moving to a new phone, or when a vault file has no credential left to open it ("Erase and start
over"). A wipe or tamper decision is only made on positive evidence. A missing or unreadable value
that could come from an old install or an interrupted setup is repaired, never treated as grounds
to wipe. A temporarily unavailable keystore makes the app wait and try again.

Other on-device measures: no cloud backup (backup is disabled); on Android, screenshots, screen
recording and the app-switcher preview are blocked; on iOS the app-switcher preview and screen
recording are covered.

## 3. Transport

- **Tor only.** The app ships its own Tor client and reaches the relay only as a **Tor onion
  service**. Relay HTTP runs inside the onion connection. The onion service encrypts the connection
  end to end and authenticates the relay's onion address, so there is no TLS layer on top.
- **No clearnet in release builds.** A release build refuses any relay that is not a `.onion`
  address. A direct, non-Tor connection exists only in debug builds for emulator testing.
- **Fail-closed.** If Tor is unavailable, messaging is off. The app never falls back to a direct
  connection. Names go to Tor unresolved (SOCKS5h), so no local DNS lookup reveals the relay.
- **Tor configuration.** The app keeps its Tor guard state between launches, which is better for
  anonymity than picking new guards every time. The data is deleted on every wipe. To work around
  slow guards, the app spreads circuits across Tor's three primary guards instead of using one.
  That gives a hostile guard more chances to be in your path, a trade made for reliability. After
  you leave the app, Tor may keep running for a short, capped time (at most about three minutes, and
  never on Maximum) so a quick return reconnects faster. The vault is locked during that time.

### External SOCKS proxy mode (Android)

Instead of the built-in Tor, you can point the Android app at a SOCKS5 proxy you run, on the phone
(for example Orbot) or on your local network. The embedded Tor is then not started, and every relay
request goes to your proxy. If the proxy is unreachable, messaging stops. This mode lets you
**watch every request the app makes** and use a Tor you already trust. The proxy sees request
metadata and the relay capability tokens, never message content. See
`docs/external-socks-proxy.md` for setup, a logging forwarder, and the risks. Among them: the app
keeps dialling the configured address on any network, and on Android another app can listen on a
loopback port while your proxy app is not running.

## 4. Messaging

### Pairing

Contacts are added **in person by QR code**. Each phone shows a code and scans the other's. Each
side contributes 32 random bytes (its "half"), which never cross the network. The codes also carry
the relay inbox addresses and the capabilities to write to them.

How the keys of a new contact are made depends on the app version on **both** phones:

- **Both phones run a version with the one-time key exchange.** Each code also carries a one-time
  X25519 public key made for this pairing only. Each phone combines its own one-time private key
  with the other phone's public key, and everything the conversation starts from (the pairing
  secret the vault stores and the first ratchet keys) is derived from that result together with
  the two halves. The one-time private keys are held only in the app's memory, are never written to
  the vault, and are overwritten once the contact is saved or the pairing is abandoned (this
  follows from the code; it has not been checked in a memory image). A picture of both codes
  therefore gives neither the stored pairing secret nor any message key.
- **Either phone runs an older version.** The pairing works exactly as before: the pairing secret is
  SHA-256 of the two halves in a fixed order. Both halves are shown on screen in the clear, so a
  camera that captures **both** codes during the pairing has the pairing secret without touching
  either phone. Pair where the screens are not overlooked.

**Contacts are not upgraded.** A contact keeps the construction it was made with for as long as it
exists: every contact added before this change, and every contact added with a phone running an
older version, stays on the older construction. Installing a newer version does not change this:
the construction is stored in the contact's row in the vault, and nothing rewrites it. Each
contact's menu (press and hold the contact) shows it: **Current** for the one-time key exchange,
**Older pairing** for the older construction. While at least one contact uses an older pairing,
the contact list shows a banner that can be closed. Closing it is one setting for the whole vault;
a move to a new phone does not carry it and a wipe erases it. There is no marker on the list rows.

What is weaker for an older pairing is narrow (details in the next two sections). Someone who has
**both** recorded relay traffic **and** that pairing's secret (from an opened vault of either phone,
from a move bundle together with its transfer code, or, for a contact paired in person, from a
picture of both codes) can read the texts each side sent before it first received something from
the other, the few texts the receiving side may send on the static envelope before its first
ratchet message arrives (at most 8 in a row), the first ratchet chain, and the static pairing,
introduction and group signals, and can forge those static signals. Recorded traffic alone opens
nothing. Ratchet messages after a round trip in both directions are protected the same way for
both kinds of contact.

**Pairing again** is the only way to move to the one-time key exchange, and it protects only the
messages sent after it. It creates a **new** contact (a new name, no memory note, not marked as
introduced); it does not convert the old one. The in-app guide gives this order: both phones
update; pair again in person; check that the new contact shows Current and that messages get
through both ways; then both delete the old contact. A cancelled or failed pairing therefore leaves
the old contact working. Deleting the old contact also deletes its inboxes on the relay, so
messages still waiting there are lost; read them first. Traffic recorded earlier stays readable to
anyone who later gets the old pairing secret, which stays in the other phone's vault until that
person deletes the old contact too. If the other phone runs a version without the exchange, the new
contact is an older pairing again, and the add-contact screen says so.

**Groups after pairing again.** Group members are matched to contacts by tags derived from the
pairing secret at the time they joined, and nothing re-sends those tags for an existing membership.
So after pairing again and deleting the old contact, that person is no longer matched in the groups
you already share, on either phone, until the group's admin removes them and adds them again; the
guide asks for that. If that person was the admin, a new invitation from them to the same group can
show the warning that the group has a different admin. This follows from the code; it has not been
checked on devices.

A contact you already have can also **introduce** two of their contacts remotely. Then the two new
contacts agree on a secret with ephemeral X25519 keys passed through the introducer. The introducer
never learns the resulting secret. They could, however, substitute their own keys and sit in the
middle undetected. You trust an introduced contact exactly as far as you trust the person who
introduced them. Introduced contacts are labelled as such.

When both introduced phones run a version with the one-time key exchange, the first ratchet keys
are derived from that ephemeral exchange in the same way (introductions involving an older version
keep the older construction). One difference from scanning: each introduced phone keeps its
ephemeral private key in the vault from the moment it accepts until the introduction completes on
that phone, because the other side's answer can arrive much later. A copy of that vault taken in
this window, together with recorded relay traffic, can open the messages each side sends before it
has heard back from the other. Once both phones have completed the introduction, nothing they store
opens those messages. An introducer who removes the capability marker from one side's answer leaves
the two contacts unable to talk to each other; the phone with the one-time exchange then shows
"secure channel lost" once the other side sends a text. Removing it from both answers gives two
contacts on the older construction, without a warning; that is within the trust you already place
in the introducer.

### Double Ratchet on the text channel

Text messages use the **Double Ratchet** (the Signal algorithm: X25519, HKDF-SHA256, HMAC-SHA256,
AES-256-GCM, header bound as associated data). Once ratchet messages have gone in both directions
(see the next section for what comes before, which differs between new and older contacts),
messages have **forward secrecy** (past message keys are deleted as the chain advances) and
**post-compromise recovery** (a new key exchange the attacker did not see locks them out again).
For a contact made with the one-time key exchange, both phones can send ratchet messages from the
first message, and their keys are deleted as the chain advances from the start; a conversation in
which only one side ever writes has that forward secrecy but no post-compromise recovery. Skipped keys for out-of-order
messages expire after 24 hours; an expired key is deleted from the vault the next time that
conversation is used or the app is unlocked, whichever comes first. Group messages are sent separately to each member over that member's
own pairwise channel.

### The static envelope: bootstrap and fallback

Some messages use a **static envelope**: AES-256-GCM under a key derived from the stored pairing
secret. This envelope has **no forward secrecy**. Anyone who later gets the pairing secret from an
opened vault can decrypt every static-envelope message they recorded. What uses it depends on how
the contact was made.

**Contacts made with the one-time key exchange.** Texts (one-to-one and group), the inbox
announcement at pairing, and the introduction and group-membership signals always use the ratchet,
from the first message, on both phones. If the ratchet cannot be used for a message (for example its
stored state cannot be read at that moment), that send fails; the message is never sent on the
static envelope instead, and the ratchet is never restarted from the pairing
secret. If the stored state is proven damaged, the app marks the contact "secure channel lost",
tells the other phone so it shows the same, and refuses to send until you pair again (and then
delete the old contact). Static-envelope texts and signals of those kinds that claim to come from such a contact
are dropped. Only small notices still use the static envelope: group activity hints, screenshot
notices, the "I use Maximum" notice and the "secure channel lost" notice. For these contacts the
static key comes from the exchanged pairing secret, so it cannot be computed from a picture of the
codes, but someone with an opened vault and recorded traffic can read those notices, and forge them.

**Contacts on the older construction** (made before this change, or with a phone running an older
version). The ratchet cannot start until both sides have heard from each other. Until then, and for
some control signals, messages use the static envelope:

- **Texts sent before you have received anything from the contact.** In a normal two-way
  conversation this is the first few messages of a new pairing. In a conversation where only one
  side ever writes, it stays this way for as long as it stays one-sided.
- **The side that receives first**, until it gets its first ratchet message. If that side has sent
  8 static-envelope texts in a row after the ratchet should have started, the app warns that
  forward secrecy has not engaged and **refuses to send more texts** until a ratchet message
  arrives or you re-pair.
- **Control signals:** the one-time inbox announcement at pairing, group activity notices (the
  "new group message" hint) and screenshot notices always use it. Referral and group-membership
  signals (invite, join, roster, leave) move onto the ratchet once both phones support it and the
  ratchet is running. Until then they use the static envelope too.

For these older contacts the **first ratchet chain is also started from the pairing secret**: the
root key and the receiving side's first ratchet key are derived from it. So the ratchet messages
the initiating side sends before it has received the other side's first ratchet message can be
decrypted, like static-envelope messages, by anyone who recorded them and later gets the pairing
secret, from an opened vault or, for a scanned contact, from a picture of both codes. Full forward
secrecy and post-compromise recovery start once ratchet messages have gone in both directions.
Contacts made with the one-time key exchange do not have this: their first ratchet keys cannot be
derived from the stored pairing secret or from the codes. (Like any ratchet state, the receiving
phone's current state opens messages sent to it that it has not processed yet; that is the
in-transit exposure listed below.)

**What a seized phone or a recorded relay can recover**, in short:

- **Recorded relay traffic alone** opens nothing, for either kind of contact.
- **Contact made with the one-time key exchange, phone opened later.** Messages that the receiving
  phone has already received and processed cannot be decrypted from what remains in either phone's
  vault. This is pinned by automated tests that run every key derivation in the code against
  everything both simulated phones store; it is not a measurement on real devices, and whether old
  copies survive in flash memory below the file system has not been examined. What an opened vault
  does give: messages still in transit or not yet processed by the receiving phone, the ability to
  impersonate you to that contact and the contact to you until the next exchange of replies, and the
  small static-envelope notices listed above.
- **Contact on the older construction, phone opened later** (or, for a scanned contact, a picture
  of both codes): every static-envelope text and the first ratchet chain described above, plus the
  same current-state exposure.

Messages without the replay fields described below are dropped, never accepted as a downgrade.

### Anti-replay and binding

Every static envelope carries, inside the encryption, a per-contact **counter** and an **epoch**.
The receiver accepts only strictly increasing counters. It also checks a **channel tag** and the
**destination inbox**, so the relay cannot move a genuine message to another inbox or reflect your
own message back at you. Ratchet messages are protected by the ratchet's own message numbering: each
message key is used once.

### Padding and metadata

Before encryption, every message is padded to a power-of-two size between 256 bytes and 128 KiB,
filled with random bytes, so the relay sees size classes, not lengths. There are no read receipts,
typing indicators or user identifiers. A send time rounded down to the minute travels inside the
encryption.

## 5. The relay

The relay is a store-and-forward server reached only as a Tor onion service. It is operated by the
app provider.

- **Capability model.** There are no accounts. Each conversation uses opaque inbox addresses. To
  read an inbox you need its read capability, and to write to it you need its write capability.
  These are random bearer tokens, and the relay stores only a one-way hash of them. The read
  capability is effectively the inbox owner's key (it can also delete the inbox and rotate
  capabilities), so it is kept only inside your vault. You can rotate it per contact ("Reset relay
  access"). Wrong-capability, missing and locked inboxes all get the same `404`.
- **Proof-of-work.** Creating an inbox requires solving a SHA-256 proof-of-work puzzle set by the
  relay, to make bulk inbox creation expensive.
- **Delivery.** The app fetches messages under a short lease and confirms them afterwards. The
  relay deletes a message when it is confirmed, or when it expires.

**What it keeps** (consistent with the privacy policy):

- Encrypted message blobs, **in memory only**, until confirmed or expired. Ordinary messages expire
  after **24 hours** (the relay's default; the app asks for no longer); pairing and other control
  signals ask for **7 days**, the relay's maximum. Nothing is kept longer than 7 days.
- Inbox records (address, capability hash, expiry, a lockout counter): a new inbox expires after
  **90 days** if never used, and one its owner uses is kept for up to **one year** of inactivity. These records are
  periodically written to disk on an encrypted volume.
- Push tokens or UnifiedPush endpoints, stored with the inbox records, only if you turn
  notifications on.
- Diagnostics you chose to send (section 6).
- An operational log (errors, counts, configuration) that is also forwarded to a log server run by
  the provider. No log line carries an inbox address, a capability, a push token or message data.
  Both the host's own journal and the log server keep lines for 30 days, and only the relay,
  Tor and proxy units are forwarded (`RELAY_SPEC.md` §7). The web server in front of the relay
  keeps no access log.

**What it can see anyway:** when inboxes are written and read, and which inboxes one Tor session
touches. When the app connects, it asks for the pending counts of all your inboxes in one request,
so the relay learns your full set of inbox addresses at once. It also sees size classes and timing.
The shape of a group send reveals that a group exists and roughly how large it is. Some request
features show the kind of traffic: whether a message is allowed to wake the recipient, whether it is
text or control, and whether it is a ratchet message. That last point also shows whether a new
pairing used the one-time key exchange (its first control message is a ratchet message). If you enabled notifications, it can link your
inboxes to a push token. It cannot see your IP address or any message content.

**What a hostile relay can do:** drop, delay or withhold messages; show a message a second time
once; push an older-construction contact into the "refuse to send" state by serving junk; make the
add-contact screen of a new pairing show "Pairing didn't work" by serving junk before the genuine
first message (the notice clears when that message arrives, and nothing is deleted unless you tap
"Start again"); and choose when the app shows its "new version available" notice. It cannot inject readable messages, read your traffic, or learn
who you are from the relay connection.

**On iOS it can also put any text on your lock screen under Rún's name.** The relay operator holds
the APNs key, and iOS shows a push's alert text itself, without running any Rún code, so a hostile
relay (or anyone with that key) can send notifications with chosen text, for example a fake
message preview. Each one also leaves a record in the iOS notification store, outside the app, until
Rún next clears delivered notifications (it does so when it locks, and when it is opened and left
again without unlocking) or wipes. Android is not affected:
FCM hands the message to the app first, and the app removes any display fields before anything is
shown. If you use notifications on iOS and do not want this risk, turn them off in Rún or in iOS
Settings → Rún → Notifications.

**The relay source code is not published yet.** The client is published first, together with
a written specification of the relay's behaviour (`RELAY_SPEC.md`: endpoints, what each stores,
for how long, what is logged). Publishing the relay's source would not let you check anything
more: you cannot see which code the server actually runs, so it would be one more operator
statement. Its retention and logging therefore remain statements by the operator that you cannot
check, and the design treats the relay as untrusted for that reason: the client is meant to stay
safe even if those statements are false. The relay source is planned for when you can run your
own relay, which is the point at which reading it tells you something.

## 6. Diagnostics

Nothing here is sent unless you act. Everything goes only to the relay, over the same Tor
connection, so the relay can tell which session sent it.

- **Report a bug.** Sends the text you typed, the app version and the platform name. Kept for
  90 days.
- **Debug mode.** Off by default and behind a consent dialog. While it is on, the app streams a
  scrubbed diagnostic log about once a second: fixed phrases and numbers, with no names, message
  content, addresses, keys or inbox identifiers. Kept for 14 days.
- **Connect-time report.** Sent **only while Debug mode is on**, once per connection: platform, app
  version, connection time rounded to 5 seconds, and a coded list of connection phases. Kept for 30
  days. It is not sent in external proxy mode.
- **Connection log panel.** The panel behind a triple tap on the "connecting" caption is local only.
  It is held in memory, uses fixed phrases, and is cleared on lock and wipe.

## 7. Review history

Rún has had **no independent third-party security review**. All review so far has been internal:
repeated rounds through 2026, done with AI assistance and checked by hand. They looked at the
vault, key handling, wipe paths, the message protocol and the relay interaction against the threat
model above. Findings were reproduced before they were fixed, and many fixes come with tests that
pin the behaviour. This is not a substitute for outside review. No cryptographer has reviewed the
protocol. The protocol description is public so that anyone can read and check it. Treat the
design as unreviewed by outsiders.

## 8. Known limitations

These are open gaps and accepted trade-offs. Each line says what it means for you.

### Traces left on the device

- **File timestamps show roughly when you last used the app.** The file that records your last
  unlock is encrypted, but the filesystem's modification time is not, and an image can read it.
- **An examiner can read that timestamp and set the phone's clock to just after it**, so the
  inactivity wipe does not fire. The inactivity wipe works against neglect, not against a careful
  examiner.
- **The names of stored items reveal your settings.** Even without any key, an examiner can tell
  whether the hardware-bound key is in use and whether a recovery code exists. A one-byte marker
  showing which wrapping scheme is used is also unencrypted.
- **Every group you have left still has one note in the vault**: the group's random ID and who its
  admin was (one of your contacts, or you). It lets the app warn you if someone else later invites
  you back into the same group. Deleting that contact removes the reference to them; the group ID
  stays. The note moves to a new phone with you and only a wipe erases it. Anyone who opens the vault
  with your credential can read it, and the group ID is the same on every member's phone.
- **On Android, Tor's data directory stays between launches**, so an image taken after first unlock
  shows the app has used Tor. Every wipe deletes it.
- **On Android with UnifiedPush**, a settings file shows that push was configured and names the push
  server. After you turn push off, deleted entries can linger in freed database pages until the next
  wipe.
- **On iOS, some copies of key material in memory cannot be reliably erased**: copies made when
  data crosses between the Swift and Kotlin layers, copies inside Apple's CryptoKit during X25519
  operations (ratchet steps and the one-time pairing key exchange), and two copies of the database
  key that the database engine keeps while the vault is open. They live only in the running process.
- **After you leave the app, the process may linger up to about three minutes** (not on Maximum)
  with the vault locked but freed memory from the session not yet cleared.
- **On iOS, uninstalling may leave a few Keychain items** until you reinstall or reset the device.
  They are useless without your credential.
- **The system keeps the camera and notification permissions after a wipe.** Rún asks for the
  camera only to scan pairing codes and for notifications only when you turn push on, so a granted
  permission shows that the feature was used. On Android 13 and later a wipe asks the system to
  revoke both (it takes effect when the app's process ends). On Android 11 and 12 and on iOS there
  is no way for the app to revoke them.
- **On Android, the notification channels stay on record after a wipe.** A wipe deletes the message
  channel and the background-connection channel, but Android keeps deleted channels and the app's
  notification settings show "N categories deleted", which shows the app posted notifications.

### Counters and settings that fail open

- **The wrong-attempt counter can be rolled back.** Someone who can write to the app's storage can
  restore an older valid copy and reset the count. And the counter only limits guesses made in the
  app. Guessing offline against an extracted vault is limited only by the Argon2id cost and the
  strength of your credential.
- **The 30-per-day limit resets if its record is damaged**, which someone with write access to the
  storage can do on purpose.
- **On iOS, deleting both the attempt counter and its marker resets the count to zero** instead of
  triggering a wipe.
- **The Debug mode setting can be replayed.** An old "on" record restored from an earlier image is
  accepted. The worst case is that the scrubbed diagnostic upload you once agreed to turns back on.
- **On Android, a failed disk write can look like it succeeded** in some places, because the check
  reads back an in-memory copy.
- **On Android, the push-replay guard lives in memory only**, so a replayed push wake-up can wake
  the app again after a restart. Wake-ups carry no content.
- **On Android, a notification setting turned on under a much older version may read as off after
  upgrading.** Turn it on again.
- **Switching from a PIN level to Maximum normally re-keys the database once.** If that re-key fails and rolls back, a
  database write at that exact moment could leave pages under two different keys, which the repair
  logic does not fully handle. It needs a rare failure and precise timing, but the result can be
  loss of the vault.

### Ratchet and pairing roles

- **Existing contacts keep the older construction for life** (section 4). Only contacts added after
  this change, with both phones up to date, get the one-time key exchange. Pairing again, which
  makes a new contact, is the only way to move, and it protects only later messages. Each contact's
  menu shows which construction it uses; the list itself has no per-contact marker, only a banner
  that can be closed. After pairing again, the person drops out of groups you already share until
  the group's admin removes and re-adds them.
- **Static-envelope messages have no forward secrecy** (section 4). For older-construction contacts
  this covers one-sided conversations, the bootstrap, the always-static control signals, and up to
  8 refused-later sends. For contacts made with the one-time key exchange it covers only the small
  notices listed in section 4.
- **An opened vault lets someone impersonate you to your contacts until the next ratchet round
  trip**, for every contact. The vault holds the pairing secrets, write capabilities and current
  ratchet state. For older-construction contacts, forged static-envelope control signals are also
  accepted until the ratchet is fully established; for contacts made with the one-time key exchange,
  only the small static notices can be forged this way.
- **Introductions keep the one-time private key in the vault for a while.** Until an introduction
  completes on a phone, a copy of that phone's vault can open the first messages of the new
  conversation (section 4). A scanned pairing never stores its one-time keys.
- **A lost secure channel needs a new pairing.** For a contact made with the one-time key exchange,
  damaged ratchet state is never repaired by restarting from the pairing secret. The contact shows
  "secure channel lost" and stays unusable until it is removed and paired again. Someone holding an
  opened vault image of either phone can also forge the notice that causes this, for that one
  contact.
- **A pairing whose one-time key was removed from one code does not work and may not say why.** If
  someone substitutes or edits a displayed code (already a full man-in-the-middle, as with any
  pairing), one phone can end up waiting for the other indefinitely instead of reporting a failure.
- **The ratchet roles in older pairings can be chosen by the other side.** Pairings made with older
  versions, or where either side runs an older version, decide which phone takes which ratchet role
  by comparing inbox addresses, and the peer controls its own address. Newer pairings derive the
  role from the pairing secrets, but a modified client can still pick its role in about two tries.
  A role clash is detected and leads to the send refusal above, not to silent weakening. (For a
  contact made with the one-time key exchange both roles come from one shared derivation; a
  mismatch there means the two phones derived different keys; for a scanned pairing the add-contact
  screen then reports "Pairing didn't work", an introduction has no such notice.)
- **An introducer can strip the role information from an introduction** of older-construction
  contacts, and the pair then falls back to the older rule instead of refusing.
- **For older-construction contacts, the first ratchet steps prove possession of the pairing
  secret, nothing more.** Someone who holds the pairing secret and a write capability can forge the
  second step of the bootstrap.

### The relay and push

- The relay sees the metadata listed in section 5, including your full set of inboxes at connect
  time and the size of your groups.
- A hostile relay can deny service in the ways listed in section 5.
- The relay's retention and logging cannot be checked until its source is published.
- Push providers learn when your device receives something. Push does not go through Tor or the
  external proxy.
- On iOS, whoever holds the relay's APNs key can show any notification text attributed to Rún, and
  each such notification stays in the iOS notification store until Rún next runs and clears it
  (on lock, or on leaving the app while locked) or wipes (section 5). Turning notifications off in iOS Settings removes the risk.

### Build guards (only if you build it yourself)

- The build refuses to put a development relay address into a release build, but Gradle's
  abbreviated task names (`aR` for `assembleRelease`) get around that check. Use full task names
  and run `scripts/verify-release-artifact.sh` on any release you build.
- Debug builds use the weak Argon2id cost and, on the iOS simulator, a direct connection that
  follows HTTP redirects. Never use a debug build for real conversations.

## 9. How to verify

- **Build from source.** The client code is published. Building it yourself is the strongest check
  available today.
- **iOS App Store binaries cannot be matched to the source by users.** Apple encrypts and re-signs
  every App Store binary for each device, so nobody outside Apple can show that a downloaded copy
  was built from this code. If you need that certainty, build and install your own copy with Xcode.
  A self-built copy gets no push notifications, because the relay's Apple push key is tied to the
  official bundle ID. Everything else works.
- **Android.** Reproducible builds, so you can compare the Play or direct-download APK with your own
  build, are planned but not available yet.
- **Watch the traffic.** On Android, the external SOCKS proxy mode (section 3) lets you log every
  request the app makes. This checks behaviour, not the binary: it cannot show what is inside the
  encrypted blobs. See `docs/external-socks-proxy.md`.

## 10. Reporting a vulnerability

See `SECURITY.md` for how to report a vulnerability privately.
