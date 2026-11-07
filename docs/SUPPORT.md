# Rún — Support

**Rún** is a private messenger: messages are end-to-end encrypted and routed over the Tor network. No accounts, no phone number, no email sign-up.

If you need help, the FAQ below covers the most common questions. For anything else, contact us at **«support@your-domain»**.

---

## Getting started

**How do I add a contact?**
Open **Add Contact** and either scan the other person's QR code or paste their contact code. Each side generates half of a shared key, and Rún combines them — so the encryption key for your conversation only ever exists on your two devices. You both need to exchange codes for messaging to work.

**Why does it take a moment to connect?**
On first launch (and after reopening), Rún establishes a Tor connection before it can send or receive. This can take anywhere from a few seconds to a minute depending on your network. A progress ring shows the status; once it's complete, messaging is ready.

**Messages aren't sending / receiving.**
- Make sure the Tor connection has finished bootstrapping (wait for the progress ring to complete).
- Check that you have a working internet connection.
- Confirm both people have added each other via QR/contact code.
- If a contact is tagged "Re-pair," exchange codes again to refresh the connection.

---

## PIN, privacy & data

**I forgot my PIN. How do I recover my messages?**
You can't — and that's by design. Your messages are encrypted with a key derived from your PIN, and there is no account, server copy, or backdoor that could restore them. A forgotten PIN means the data cannot be decrypted by anyone, including us. You can reinstall the app to start fresh.

**My messages disappeared.**
For your protection, Rún erases its data after too many incorrect PIN attempts, and after an extended period of inactivity. This is a security feature, not a bug. Erased data cannot be recovered.

**Do you have my messages on a server?**
No. Messages are end-to-end encrypted and relayed only as encrypted, padded data that the relay cannot read. We don't run accounts and don't store your conversations.

**What data do you collect?**
None. Rún has no ads, no trackers, and no analytics. There is no account and nothing tying a conversation to your identity.

**How do I delete everything?**
Delete the app from your device. All of Rún's data is stored locally and is removed with the app.

---

## Contact

- **General support & bug reports:** «support@your-domain»
- **Security disclosures:** «security@your-domain» — please report suspected vulnerabilities privately before disclosing publicly.

Rún is free and supported by donations. No subscriptions, no upsells.

_Last updated: June 2026_
