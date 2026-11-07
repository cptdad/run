import { Ids, byId } from './AccessibilityIds'
import { dismissPostConnectModalsIfPresent } from './PinHelper'

/**
 * Single-device (non-multiremote) contact-list waits.
 *
 * FIRST-REVEAL GATE (2026-09-11, both platforms): the contact list — rows,
 * unread badges, repair banner AND the empty-contacts copy — is not rendered at
 * all until the relay has answered ONCE this session (Android
 * `ContactListScreen.ContactListSurface`, iOS `ContactListView.listRevealed`,
 * both keyed on `isRelayReachable` — the same `done` signal the shared
 * `BootstrapProgressPacer` is fed and the signal that lights the runestone).
 * Until then the screen shows `contact_list_hidden_until_connected`, which
 * still carries the runestone, the paced connect caption, the connect hint and
 * the (relay-gated) Add-contact button.
 *
 * Consequence for the emulator/simulator suites: several of them never start
 * the mock relay at all, so `empty_contacts_state` legitimately NEVER appears
 * there — the app sits on the placeholder forever, which is correct behaviour,
 * not a failure. Those specs assert "a fresh vault shows no contacts", and
 * BOTH ids prove exactly that, so accept either (widen, never narrow).
 *
 * The SAME relay answer that flips `contact_list_hidden_until_connected` to
 * `empty_contacts_state` is also what fires push_prompt (2026-09-11 — see
 * PinHelper's dismissPostConnectModalsIfPresent), so this is exactly the
 * wait that needs to race it: a caller of this function against a mock relay
 * that's already up can otherwise get the whole a11y tree occluded by the
 * prompt (Android) or its scrim (iOS) mid-poll.
 */
export async function waitForEmptyOrPreConnectContactList(timeout = 30_000): Promise<string> {
    let seen = ''
    await browser.waitUntil(async () => {
        await dismissPostConnectModalsIfPresent()
        for (const id of [Ids.emptyContactsState, Ids.contactListHiddenUntilConnected]) {
            if (await (await $(byId(id))).isExisting().catch(() => false)) {
                seen = id
                return true
            }
        }
        return false
    }, {
        timeout,
        interval: 500,
        timeoutMsg:
            `neither ${Ids.emptyContactsState} nor ${Ids.contactListHiddenUntilConnected} appeared within ${timeout}ms `
            + '— the unlocked main screen rendered neither the empty state nor the pre-connect placeholder',
    })
    return seen
}
