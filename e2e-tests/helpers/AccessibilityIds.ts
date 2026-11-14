/**
 * Accessibility identifiers used by the Rún E2E test suite.
 *
 * These strings are set in the app source code:
 *   - iOS (SwiftUI): `.accessibilityIdentifier("...")`
 *   - Android (Compose): `Modifier.testTag("...")` with `testTagsAsResourceId = true`
 *     at the root of each screen.
 *
 * Appium uses `~` prefix for accessibility IDs, e.g. `~key_0`.
 */
export const Ids = {
    // ---- PIN keypad ----
    /** The six-digit dots above the keypad indicating entered digits. */
    pinDots: 'pin_dots',
    /** Prompt text ("Choose your PIN", etc.) — present on setup screen only. */
    pinPrompt: 'pin_prompt',
    /** Individual keypad digit buttons. */
    key: (digit: number | string) => `key_${digit}`,
    keyDelete: 'key_delete',

    /** Root of the unlocked-state navigation stack. */
    unlockedRoot: 'unlocked_root',

    /** iOS only, DEBUG builds only: the 6 pt transparent target the Lever-C
     *  keep-alive taps so a no-touch wait never reads as idle (helpers/
     *  KeepAwake.ts). Android resets the same clock over adb instead. */
    keepAlivePoke: 'keepalive_poke',

    // ---- First-unlock push-notification prompt ----
    /**
     * Shown once per vault, immediately after the FIRST unlock of a FRESH
     * vault — i.e. every fresh provision hits it (completePinSetup's confirm
     * stage auto-unlocks straight into it), over the contact list. Persisted
     * as a vault-meta flag, so a resetApp wipe re-arms it. Identical ids on
     * both platforms (Android Compose testTag exposed as a resource-id; iOS
     * accessibilityIdentifier).
     */
    pushPrompt: 'push_prompt',
    /** "Yes" — opens the notification-settings carousel (Android
     *  notif_carousel_next/back + notification_settings_close; iOS
     *  push_settings_next/back + push_settings_done — see those ids below). */
    pushPromptYes: 'push_prompt_yes',
    /** "No" — dismisses with no further action. THE ONLY button any e2e guard
     *  may tap: pushPromptYes opens the carousel and blocks whatever the
     *  guard's caller expected to happen next. */
    pushPromptNo: 'push_prompt_no',

    // ---- Update-available nudge ----
    /**
     * Shown at most once per calendar day per advertised version (a
     * vault-meta throttle key, `update_nudge_v1`; a resetApp wipe re-arms
     * it), on the contact list, once the relay's platform-specific version
     * header (read off the first successful relay response of the session)
     * compares strictly newer than the app's own. Identical id on both
     * platforms, same convention as push_prompt above.
     */
    updateNudgeDialog: 'update_nudge_dialog',
    /**
     * The dialog's body copy ("New version available" / …). No separate
     * title on this dialog — this id is on the MESSAGE text node itself
     * (RuneDialog.kt's `messageTestTag`, UIComponents.swift's
     * `messageA11yId`), added for update-nudge-layout.spec.ts's geometry
     * checks (it needs the message's own rendered bottom edge). Identical id
     * on both platforms, same convention as the ids above.
     */
    updateNudgeMessage: 'update_nudge_message',
    /**
     * "Later" — dismisses without opening a store. The info-only variant's sole "OK" button
     * REUSES this exact id (there is no separate OK id), so one selector
     * covers both variants — the test phones/emulator/sim only ever renders the
     * info-only one (no store installer).
     */
    updateNudgeLaterButton: 'update_nudge_later_button',
    /**
     * "Open Google Play" / "Open App Store" — present ONLY on a Play-
     * installed Android build / App-Store-receipted iOS build. Absent on
     * every sideloaded/debug/emulator/simulator build, which is the ONLY
     * class this e2e suite drives — update-nudge.spec.ts asserts its
     * ABSENCE, never its presence or a tap on it.
     */
    updateNudgeStoreButton: 'update_nudge_store_button',

    // ---- Contact list ----
    /** The scrollable list containing contacts. */
    contactList: 'contact_list',
    /** Top-left cogwheel that opens the settings dropdown menu. */
    settingsButton: 'settings_button',
    /** "Add contact" item inside the settings dropdown menu. */
    addContactButton: 'add_contact_button',
    /** "Change pin code" item inside the settings dropdown menu. */
    changePinButton: 'change_pin_button',
    /** "Protection level" item inside the settings dropdown menu/sheet — opens
     *  the threat-level chooser (see the `protectionLevel*` ids below). Local
     *  (no relay round trip), so it stays enabled while the relay is down. */
    protectionLevelMenuButton: 'protection_level_menu_button',
    /** Shown when the vault has zero contacts AND the relay has answered.
     *  Before the relay's first answer the pre-connect placeholder below is
     *  shown instead — even on a fresh vault — so a wait for THIS id after a
     *  bare unlock must tolerate the reveal delay (or accept either id). */
    emptyContactsState: 'empty_contacts_state',
    /**
     * Pre-connect placeholder that REPLACES the whole contact list (rows,
     * unread badges, repair banner and the empty-contacts copy) until the
     * relay has answered ONCE this session — the 2026-09-11 first-reveal gate
     * (Android ContactListScreen.ContactListSurface / iOS ContactListView
     * `listRevealed`, both keyed on isRelayReachable, the same `done` signal
     * BootstrapProgressPacer is fed).
     *
     * What it still shows: the runestone, tor_progress_caption,
     * connect_relay_hint (or the stall/reconnect variants),
     * empty_add_contact_button and the settings cogwheel — all with their
     * existing ids and existing enabled state.
     *
     * ONLY the first reveal is gated: losing reachability later does NOT hide
     * an already-visible list, so a mid-suite relay flap never brings this
     * back. Any wait that looks for rows straight after an unlock/resume must
     * be bounded generously (the relay round-trip over Tor is minutes cold) —
     * see Device.waitForContactRowsRevealed.
     */
    contactListHiddenUntilConnected: 'contact_list_hidden_until_connected',
    /** A specific contact row. Append the contactId. */
    contactRow: (contactId: string) => `contact_row_${contactId}`,
    /** A specific contact's alias text. Append the contactId. */
    contactName: (contactId: string) => `contact_name_${contactId}`,
    /**
     * Unread "●" badge on a contact row in the contact list. Append the
     * contactId. Identical id on both platforms (Android ContactListScreen
     * testTag, iOS ContactListView accessibilityIdentifier). A group text
     * must NEVER cause this to appear — see plan-group-inbox-2026-09-24.md
     * §4.3 (R8) and Device.waitForGroupUnreadDotWithoutContactDot.
     */
    contactUnread: (contactId: string) => `contact_unread_${contactId}`,

    // ---- Add Contact wizard ----
    /** Step 1 "How do you want to start?" choice buttons. */
    addChoiceShow: 'add_choice_show',
    addChoiceScan: 'add_choice_scan',
    /** "Next / I've shown it" button on the Show step. */
    addShowNext: 'add_show_next',
    /** Hidden 5-tap target on the choice step that reveals the no-camera paste
     *  exchange (mirrors the log-viewer's hidden open). Replaces the old Debug
     *  tab + 8888 PIN gate. */
    addPasteReveal: 'add_paste_reveal',
    /** TextField in the paste exchange where a contact code is entered. */
    debugCodeInput: 'debug_code_input',
    /** Button that adds the contact from the pasted code. */
    debugAddContactButton: 'debug_add_contact_button',
    /**
     * DEBUG-only scanner-injection seam on the wizard's SCAN step — feeds a
     * base64-of-JSON pairing payload to the same decode path a camera frame
     * takes (Android: ScanInjectRow in AddContactScreen.kt; iOS: scanInjectRow
     * in AddContactView.swift). Present only in debug builds, on both platforms.
     */
    scanInjectField: 'scan_inject_field',
    scanInjectSubmit: 'scan_inject_submit',
    /** DEBUG-only text mirror of the INSTANT secret-only QR on the Show step —
     *  the code a peer's camera reads first. */
    debugInstantCode: 'debug_instant_code',
    /** DEBUG-only text mirror of the FULL QR rendered in the Done step's
     *  scan-back state — the code the peer must scan BACK. */
    debugScanBackCode: 'debug_scanback_code',
    /** "Almost there / let them scan your code" heading — present ONLY while the
     *  pairing is half done (we scanned their instant secret-only code and our
     *  full code has not been scanned back yet). Its disappearance is the signal
     *  that the peer's in-band inbox announce has been applied. */
    addContactScanBackTitle: 'add_contact_scan_back_title',
    /** The QR the peer must scan back, in that same half-done state. */
    addContactScanBackQr: 'add_contact_scan_back_qr',
    /** Cancel button in the AddContact sheet toolbar. */
    addContactCancel: 'add_contact_cancel',
    /** Done button shown after a successful add. */
    addContactDone: 'add_contact_done',
    /** Save button in the Android alias entry overlay after debug add. */
    aliasSaveButton: 'alias_save_button',
    /** Skip button in the post-add personal-memory prompt sheet. */
    mnemonicPromptSkip: 'mnemonic_prompt_skip',
    /** Save button in the post-add personal-memory prompt sheet. */
    mnemonicPromptSave: 'mnemonic_prompt_save',

    // ---- Conversation ----
    conversationView: 'conversation_view',
    conversationTitle: 'conversation_title',
    messageList: 'message_list',
    messageInput: 'message_input',
    sendButton: 'send_button',
    messageBubbleSent: 'message_bubble_sent',
    messageBubbleReceived: 'message_bubble_received',
    /**
     * "X may have taken a screenshot" notice row in a 1:1 conversation —
     * centered/muted, same style family as groupSystemMessage but its own id
     * (the group's screenshot notice is `screenshotNoticeGroup` below).
     * Identical id on both platforms. PERSISTED for 24 h (docs/
     * screenshot-notice-persistence-design.md): one row per received
     * screenshot notice (multiple can coexist), loaded on conversation open
     * AND appended live while it's open, text ends with " · HH:mm" (the
     * sender's capture time, "Yesterday HH:mm" if the day differs). Survives
     * a kill+relaunch — that is the whole point of the persistence fix (the
     * old RAM-only buffer lost it unless the recipient's conversation was
     * open at the exact moment the background sweep drained it). Use `$$` to
     * count/match more than one row. See MessageManager.sendScreenshotNotice,
     * GroupManager.screenshotNotices (load-on-open) /
     * GroupManager.drainScreenshotNotices (live).
     */
    screenshotNotice: 'screenshot_notice',
    /**
     * Non-modal notice in a
     * 1:1 conversation shown once MessageManager.ratchetRefused reports the secure
     * channel with this contact has provably failed to establish (a ratchet
     * role-collision) and sends are being refused. Takes precedence over the
     * (not yet in this helper) `fs_stalled_notice` row when both would fire —
     * same muted-row visual family, identical id on both platforms, title-less
     * single body. Clears on its own once an inbound ratchet blob decrypts,
     * re-read on conversation open and on every poll tick (not just after a
     * send).
     */
    ratchetRefusedNotice: 'ratchet_refused_notice',
    /**
     * Step 1 of the one-time first-open onboarding: the burn-on-read CONCEPT
     * dialog. Since the RuneDialog rework both platforms carry these ids (the
     * iOS overlay buttons take accessibilityIdentifiers, unlike the old
     * `.alert`), so sel() matches them directly.
     */
    burnNotice: 'burn_notice',
    burnNoticeOk: 'burn_notice_ok',

    // ---- Dialogs ----
    mnemonicAlert: 'mnemonic_alert',
    deleteAlert: 'delete_alert',
    deleteConfirmButton: 'delete_confirm_button',

    // ---- Groups ----
    /** "New group" item inside the settings dropdown menu. */
    createGroupMenuButton: 'create_group_menu_button',
    /** Group name TextField on the create-group screen/sheet. */
    groupNameInput: 'group_name_input',
    /** Selectable contact row in the create-group member picker. Append contactId. */
    groupMemberRow: (contactId: string) => `group_member_row_${contactId}`,
    /** "Create group (N)" button. Disabled until name + ≥1 member. */
    createGroupButton: 'create_group_button',
    /** Back/Cancel affordance on the create-group screen/sheet. */
    createGroupBack: 'create_group_back',
    /**
     * GROUP-1 consent gate: the incoming-invite Rune dialog. Since the
     * RuneDialog rework the dialog + its buttons carry stable ids on BOTH
     * platforms (the old AlertDialog/.alert buttons couldn't).
     */
    groupInviteDialog: 'group_invite_dialog',
    groupInviteJoin: 'group_invite_join',
    groupInviteDecline: 'group_invite_decline',
    /** "Later" on the invite dialog: closes it without deciding; the invite stays pending as a row. */
    groupInviteLater: 'group_invite_later',
    /** A PENDING (undecided, "Later") invitation row in the contact list's groups area. Append the groupId. NOT a joined group: it never starts with `group_row_`. */
    groupInviteRow: (groupId: string) => `group_invite_row_${groupId}`,
    /** Prefix of every [groupInviteRow] id, for "any pending invitation row" selectors. */
    groupInviteRowPrefix: 'group_invite_row_',
    /** A group row in the contact list. Append the groupId. */
    groupRow: (groupId: string) => `group_row_${groupId}`,
    /** Group conversation title (group name). */
    groupConversationTitle: 'group_conversation_title',
    groupMessageInput: 'group_message_input',
    groupSendButton: 'group_send_button',
    groupBubbleSent: 'group_bubble_sent',
    groupBubbleReceived: 'group_bubble_received',
    /**
     * INLINE PRIVATE / GROUP-ECHO bubbles (2026-10-06 decision, see
     * inline-private-and-group-messages): a 1:1 text the GROUP poll fetches is shown
     * in the group view as a PRIVATE bubble (never counted as group_bubble_received);
     * "Reply privately" arms a composer chip and the reply shows as PRIVATE_SENT. A
     * group text a 1:1 poll fetches is shown in the 1:1 view as a GROUP-ECHO bubble.
     */
    groupPrivateBubble: 'group_private_bubble',
    groupPrivateLabel: 'group_private_label',
    groupPrivateReply: 'group_private_reply',
    groupPrivateSentBubble: 'group_private_sent_bubble',
    composerPrivateChip: 'composer_private_chip',
    composerPrivateChipClose: 'composer_private_chip_close',
    conversationGroupEchoBubble: 'conversation_group_echo_bubble',
    conversationGroupEchoLabel: 'conversation_group_echo_label',
    conversationGroupEchoOpen: 'conversation_group_echo_open',
    /**
     * The delivered/total indicator on a SENT group bubble — the honest
     * partial-fan-out surface (GroupManager.sendGroupMessage returns
     * GroupSendResult; GroupConversationScreen.kt renders it as "·" while the
     * fan-out is in flight, "✓" once every member copy was accepted, and
     * "not delivered to N" (English UI; N = refused copies + members with no
     * resolved contact — since 2026-11-05, before that "1/2") when any member
     * got nothing; GroupViews.swift's deliveryMark is the byte-identical iOS
     * twin). One element PER sent
     * bubble, present in ALL THREE states on both platforms (the id is on the
     * indicator Text itself, whose content is the state), so read its TEXT to
     * learn the verdict — existence alone only proves a sent bubble renders.
     * Since 2026-11-12 the "·" and "✓" states are NOT DRAWN (the sent bubble's own
     * opacity/colour is the visible signal — grey+translucent until delivered); the
     * element still exists with the same text: Android = transparent-ink Text in a 1dp
     * box, iOS = clear-ink Text in a 1pt frame (both stay in the a11y tree, so
     * getText() is unchanged). The failure texts remain visible.
     * Use `$$` + last element for the most recent send
     * (Device.readGroupDeliveryStatus).
     */
    groupDeliveryStatus: 'group_delivery_status',
    /** Opens the group-info screen/sheet (header on Android, ⓘ on iOS). */
    groupInfoButton: 'group_info_button',
    groupInfoMemberList: 'group_info_member_list',
    /** A member row in group info. Append the memberId. */
    groupMemberInfoRow: (memberId: string) => `group_member_info_row_${memberId}`,
    /** "Admin" badge on a member row. Append the memberId. */
    groupAdminBadge: (memberId: string) => `group_admin_badge_${memberId}`,
    /** "Add member" row — present ONLY when this device is the group admin. */
    addGroupMemberButton: 'add_group_member_button',
    /** A contact row in the add-member picker. Append the contactId. */
    addMemberRow: (contactId: string) => `add_member_row_${contactId}`,
    /** Back/Done affordance on the group-info screen/sheet. */
    groupInfoBack: 'group_info_back',
    groupInfoLeaveButton: 'group_info_leave_button',
    groupInfoLeaveConfirm: 'group_info_leave_confirm',
    /** Confirm / cancel buttons of the "Make <name> admin?" dialog (the role is transferred). */
    makeAdminConfirm: 'make_admin_confirm',
    makeAdminCancel: 'make_admin_cancel',
    /** The Play Billing tip-jar body inside the Support modal (Android). */
    tipJarBody: 'tip_jar_body',
    /** Unread "●" badge on a group row in the contact list. Append the groupId. */
    groupUnread: (groupId: string) => `group_unread_${groupId}`,
    /** A system notice in a group conversation ("X left/was removed"). */
    groupSystemMessage: 'group_system_message',
    /**
     * "X may have taken a screenshot" notice row in a group conversation —
     * same centered/muted style as groupSystemMessage, but a DISTINCT id so
     * it can be targeted specifically. Identical id on both platforms.
     * PERSISTED for 24 h, same semantics as `screenshotNotice` above (one row
     * per screenshot, multiple coexist, text ends with " · HH:mm", survives
     * kill+relaunch). Use `$$` to count/match more than one row. See
     * GroupManager.sendGroupScreenshotNotice, GroupManager.screenshotNotices
     * (load-on-open) / GroupManager.drainScreenshotNotices (live).
     */
    screenshotNoticeGroup: 'screenshot_notice_group',
    /** Admin-leave "choose new admin" picker row. Append the memberId. */
    chooseAdminRow: (memberId: string) => `choose_admin_row_${memberId}`,
    /** The mnemonic shown under a member in the choose-new-admin picker. */
    chooseAdminMnemonic: (memberId: string) => `choose_admin_mnemonic_${memberId}`,

    // ---- Runestone gate markers (test-only, see RunestoneLitMarker) ----
    /** Present on the contact-list / conversation screen iff relay is reachable. */
    runestoneLitActive: 'runestone_lit_active',
    /** Present on the contact-list / conversation screen iff relay is unreachable. */
    runestoneLitInactive: 'runestone_lit_inactive',

    // ---- Pre-connect status: caption, hint, expandable log panel ----
    /**
     * The two-phase "Connecting to Tor… N%" / "Connecting to Relay… N%"
     * status line shown while the relay is not yet reachable
     * (RelayConnectHints.connectStatusLine / AppState.connectStatusLine).
     * Same id in both the empty-contacts state and the contacts-present
     * strip. Triple-tapping it toggles connectLogPanel below.
     */
    torProgressCaption: 'tor_progress_caption',
    /**
     * "The first connection can take a few minutes." — renders alongside
     * torProgressCaption. Absent once the caption is replaced entirely by
     * tor_stalled_hint / relay_reconnect_button (the two never render
     * together).
     */
    connectRelayHint: 'connect_relay_hint',
    /**
     * Manual "Reconnect" shown once the connect watch gives up (RelayConnectPhase
     * .Stalled) — on the pre-connect placeholder and in the relay-trouble banner.
     * In external SOCKS proxy mode an unreachable proxy goes Stalled at once, and
     * the tap re-runs the proxy check (never the embedded Tor).
     */
    relayReconnectButton: 'relay_reconnect_button',
    /**
     * Inline panel toggled by a TRIPLE-tap on torProgressCaption: shows
     * recent connection-attempt log lines without leaving the contact list.
     * Must not exist before the first triple-tap and must be gone again
     * after a second one on the same caption. Contains one or more
     * connectLogLine rows.
     */
    connectLogPanel: 'connect_log_panel',
    /**
     * One line inside connectLogPanel. Use `$$` to read every line. Lines
     * must never surface anything relay-identifying — no 32-char inbox id
     * (MessageManager.kt's INBOX_ID_REGEX shape) and no ".onion" host.
     */
    connectLogLine: 'connect_log_line',

    // ---- About / Support-Rún (donate) modals, opened from the cogwheel ----
    /** "How Rún works" (feature carousel) item in the settings dropdown. */
    menuAbout: 'menu_about',
    /** "About" (app/version info) item in the settings dropdown. */
    menuAboutInfo: 'menu_about_info',
    /** "Support Rún" item in the settings dropdown. */
    menuDonate: 'menu_donate',

    // ---- Report bug (anonymous) — settings dropdown (Android) / sheet (iOS),
    //      opened from the cogwheel. Same relay-reachability gate as
    //      create_group_menu_button / add_contact_button (Android:
    //      `enabled = contactsReady`; iOS: `disabled: !litVisible`) — a single
    //      POST /bugreport over the app's existing relay transport, so it's
    //      disabled while the relay is unavailable. The relay writes the
    //      report to disk BEFORE answering 204, so the thanks dialog
    //      appearing (once enabled and tapped) is the end-to-end persistence
    //      proof. ----
    /** "Report bug" item in the settings dropdown (Android) / sheet (iOS). */
    reportBugMenuItem: 'report_bug_menu_item',
    /** Root of the report-bug free-text dialog. */
    reportBugDialog: 'report_bug_dialog',
    /** Free-text field inside the dialog (client-clipped to
     *  BugReportSender.MAX_TEXT_CHARS; always opened blank). */
    reportBugTextField: 'report_bug_text_field',
    /** Cancel button — dismissible except while a send is in flight. */
    reportBugCancelButton: 'report_bug_cancel_button',
    /** Send button — disabled while the field is blank (RuneDialogAction `enabled`). */
    reportBugSendButton: 'report_bug_send_button',
    /** Inline error text shown after a failed send (non-204 / transport failure). */
    reportBugError: 'report_bug_error',
    /** Root of the post-send "Thank you" dialog. */
    reportBugThanksDialog: 'report_bug_thanks_dialog',
    /** OK button dismissing the thanks dialog. */
    reportBugThanksOkButton: 'report_bug_thanks_ok_button',

    // ---- Debug mode (2026-09-14) — user-consented anonymous diagnostic log
    //      upload to the relay's /debuglog (DebugMode.kt / DebugLogUploader.kt,
    //      commonMain). Same settings-row-opens-consent-dialog shape as
    //      reportBugMenuItem above, on BOTH platforms (Android DropdownMenuItem
    //      testTag / iOS settingsRow accessibilityIdentifier). ----
    /** "Debug mode" / "Debug mode (on)" row in the settings dropdown (Android) /
     *  settings sheet (iOS) — same id either way, the LABEL carries the state
     *  (mirrors settingsButton's dual-string convention elsewhere in this file,
     *  e.g. push_prompt). Opens debugModeDialog. Never relay-gated (a local
     *  Keychain/SharedPreferences write, not a relay round trip at tap time). */
    settingsDebugMode: 'settings_debug_mode',
    /** Root of the on/off confirmation dialog (RuneDialog / RuneDialogOverlay). */
    debugModeDialog: 'debug_mode_dialog',
    /** "Turn on" / "Turn off" — flips DebugMode.setEnabled(!current). */
    debugModeConfirm: 'debug_mode_confirm',
    /** "Cancel" — dismisses with no state change. Safe to auto-dismiss, so this
     *  is the one the generic modal racer taps (Device.dismissDebugModeDialogIfPresent)
     *  — it must never tap debugModeConfirm, which would flip the toggle. */
    debugModeCancel: 'debug_mode_cancel',

    // ---- External SOCKS proxy mode (d2389e37, docs/external-socks-proxy.md) —
    //      Settings → "External Tor proxy". Identical ids on both platforms
    //      (Android ExternalProxySettingsModal.kt testTags / iOS
    //      accessibilityIdentifiers); ext_proxy_dialog is Android-only. ----
    /** The settings row that opens the modal. NOT relay-gated (a user whose proxy
     *  is down must still reach it to fix or turn it off). */
    settingsExtProxy: 'settings_ext_proxy',
    /** Android-only root of the modal (RuneDialog testTag). */
    extProxyDialog: 'ext_proxy_dialog',
    /** "Use an external proxy" switch. The host/port fields render ONLY while it is on. */
    extProxyToggle: 'settings_ext_proxy_toggle',
    extProxyHost: 'settings_ext_proxy_host',
    extProxyPort: 'settings_ext_proxy_port',
    extProxySave: 'settings_ext_proxy_save',
    extProxyDone: 'settings_ext_proxy_done',
    /** Inline notes: "Changes take effect the next time…" (before a save) /
     *  "Saved. Close and reopen…" (after a verified save) — mutually exclusive. */
    extProxyNextLaunch: 'settings_ext_proxy_next_launch',
    extProxySaved: 'settings_ext_proxy_saved',
    extProxyError: 'settings_ext_proxy_error',
    extProxyLanWarning: 'settings_ext_proxy_lan_warning',
    /** THIS SESSION's proxy status line — in the modal, and on the contact list's
     *  connecting surface / relay-trouble banner. Renders NOTHING while the mode is
     *  off for this launch (status OFF), so its absence is the "mode off" signal. */
    extProxyStatus: 'ext_proxy_status',

    // ---- Language (localization) ----
    /** "Language" item in the settings dropdown (Android) / settings sheet (iOS).
     *  Android opens the in-app picker; iOS hands off to Apple's per-app
     *  language row in Settings (no in-app picker on iOS by design). */
    menuLanguage: 'menu_language',
    /** Root of the Android language picker dialog. */
    languagePicker: 'language_picker',
    /** "System default" row of the Android language picker. */
    languageOptionSystem: 'language_option_system',
    /** Per-language rows: `language_option_<bcp47 tag>` (en, sv, de, fr, es, nb, da, fi). */
    languageOption: (tag: string) => `language_option_${tag}`,
    /** Root of the About-info modal (app name / version / Tor / credits). */
    aboutInfoModal: 'about_info_modal',
    /** Version line inside the About-info modal. */
    aboutInfoVersion: 'about_info_version',
    /** Close button of the About-info modal. */
    aboutInfoClose: 'about_info_close',
    /** Root of the About carousel modal. */
    aboutModal: 'about_modal',
    /** The swipeable pager inside the About modal. */
    aboutPager: 'about_pager',
    /** Close button of the About modal. */
    aboutClose: 'about_close',
    /** Root of the Support-Rún (donate) modal. */
    donateModal: 'donate_modal',
    /** A donation-method segment. Append the method id (monero/bitcoin/lightning). */
    donateSeg: (id: string) => `donate_seg_${id}`,
    /** The address / "TBA — coming soon" text for the selected method. */
    donateAddress: 'donate_address',
    /** Close button of the donate modal. */
    donateClose: 'donate_close',

    // ---- User safety (App Store Guideline 1.2: EULA, report, block) — iOS only ----
    /** Root of the Terms-of-Use (EULA) gate, shown before PIN setup/entry. */
    eulaScreen: 'eula_screen',
    /** The scrollable Terms-of-Use body text. */
    eulaText: 'eula_text',
    /** "I Agree & Continue" button on the EULA gate. */
    eulaAgreeButton: 'eula_agree_button',
    /** "Decline" button on the EULA gate. */
    eulaDeclineButton: 'eula_decline_button',
    /** "Report" item in a contact's long-press menu. */
    menuReport: 'menu_report',
    /** "Block" item in a contact's long-press menu. */
    menuBlock: 'menu_block',
    /** Destructive "Block" button in the block-confirmation alert. */
    blockConfirmButton: 'block_confirm_button',
    /** "Report to Rún" button in the post-block prompt. */
    postBlockReportButton: 'post_block_report_button',
    /**
     * "Report to Rún" button in the confirmation dialog that now gates the
     * contact-menu Report action (the
     * mailto draft lands outside Rún and survives the wipe, so the export is
     * disclosed before it happens). `menuReport` opens this dialog; it no
     * longer opens the mail app directly.
     */
    reportConfirmButton: 'report_confirm_button',
    /** "Blocked contacts" item in the settings dropdown menu. */
    menuBlockedContacts: 'menu_blocked_contacts',
    /** Root of the blocked-contacts management modal. */
    blockedContactsModal: 'blocked_contacts_modal',
    /** Shown in the blocked-contacts modal when no one is blocked. */
    blockedEmptyState: 'blocked_empty_state',
    /** Close (✕) button of the blocked-contacts modal. */
    blockedClose: 'blocked_close',
    /** "Unblock" button for a blocked contact row. Append the contactId. */
    unblock: (contactId: string) => `unblock_${contactId}`,
    /** ••• menu in the conversation toolbar (Report / Block live here). */
    conversationMenu: 'conversation_menu',
    /** "Report" item in the conversation toolbar menu. */
    conversationReport: 'conversation_report',
    /** Confirm button of the dialog `conversationReport` now opens. */
    conversationReportConfirmButton: 'conversation_report_confirm_button',
    /** "Block" item in the conversation toolbar menu. */
    conversationBlock: 'conversation_block',

    // ---- Protection level (threat-level slider onboarding + settings) ----
    /** Title on the "Choose your protection" chooser (first-run onboarding AND settings). */
    protectionLevelTitle: 'protection_level_title',
    /** A selectable level stop on the slider. Append the storage value
     *  (casual / private / hardened / maximum). Tap selects that level. */
    protectionLevel: (storageValue: string) => `level_${storageValue}`,
    /** "Continue" / confirm button on the chooser — DISABLED until a level is picked. */
    protectionLevelConfirm: 'protection_level_confirm',
    /** Cancel / back affordance on the chooser (present when opened from settings). */
    protectionLevelBack: 'protection_level_back',
    /** Why the greyed stops are greyed — no device lock screen, or no Lever-B hardware. */
    protectionLevelStopReason: 'protection_level_stop_reason',
    /** Notice shown when the tier is FORCED (this device has no passcode, so only
     *  MAXIMUM is legal). Confirm on the chooser opens it; it must be acknowledged
     *  before the tier applies, because it carries the 7-day inactivity self-wipe. */
    protectionForcedNotice: 'protection_forced_notice',
    /** "I understand" — the acknowledgment that applies the forced tier. */
    protectionForcedAck: 'protection_forced_ack',
    /** "Not now" — dismisses the forced notice, leaving the chooser up. */
    protectionForcedCancel: 'protection_forced_cancel',

    // ---- No-device-passcode warning gate (iOS only, first-run) ----
    /** Root of the ContentView gate shown at first-run when the device has no
     *  passcode set, before PinSetupView provisions the vault. Exposed as a
     *  CONTAINER (containerA11yId) so the buttons below surface their own ids. */
    passcodeWarning: 'passcode_warning',
    /** "Continue anyway" — acknowledges and proceeds without a device passcode. */
    passcodeWarningContinue: 'passcode_warning_continue',

    // ---- Passphrase / change-credential (the Maximum protection level, Lever A) ----
    // NOTE: the standalone "High-risk mode" screen was removed — the protection-level
    // chooser now drives the passphrase directly, so its IDs (high_risk_*, downgrade_
    // confirm, auth_binding_switch) are gone.
    /** Secure passphrase text field (unlock + change-credential passphrase steps). */
    passphraseField: 'passphrase_field',
    /** "Continue" button in the change-credential passphrase steps. */
    credentialContinue: 'credential_continue',
    /** "Continue" button in FIRST-RUN passphrase setup (PinSetupScreen /
     *  PinSetupView) — a different id from the change-credential one above. */
    passphraseContinue: 'passphrase_continue',
    /** Passphrase strength-meter label (Choose step only). */
    passphraseStrength: 'passphrase_strength',
    /** "Unlock" button on the passphrase-mode entry screen. */
    unlockButton: 'unlock_button',

    // ---- Periodic re-auth at MAXIMUM (docs/periodic-reauth-design.md) ----
    /** The countdown text on the periodic-re-auth warning overlay (the ONLY
     *  new id the feature adds — the prompt itself reuses pin_prompt /
     *  passphrase_field / unlock_button / pin_dots). Present on BOTH
     *  platforms' warning overlays; absent on the Lever-C (idle) variant of
     *  the same overlay, which carries no id. */
    reauthCountdown: 'reauth_countdown',

    // ---- Referral / vouching (referral.md) ----
    /** "Introduce to…" item in a contact's long-press menu. */
    menuIntroduce: 'menu_introduce',
    /** A selectable recipient in the multi-select "Introduce X to…" picker.
     *  Append the contactId. Tap toggles selection; long-press shows its memory. */
    introducePick: (contactId: string) => `introduce_pick_${contactId}`,
    /** "Introduce (N)" confirm button in the picker — fires the referrals to all
     *  selected recipients. */
    introduceConfirm: 'introduce_confirm',
    /** "Introduced" provenance badge on a referred contact row (informational;
     *  referred contacts are usable immediately). Append the contactId. */
    contactReferred: (contactId: string) => `contact_referred_${contactId}`,
    /** The "Connection request" CONSENT GATE shown to an introducee (both
     *  platforms): Android `RuneDialog(testTag = "referral_offer_dialog")`
     *  (ContactListScreen.kt) / iOS `RuneDialogOverlay(a11yId:)`
     *  (ContactListView.swift ReferralOfferAlert). NOT a hard gate since
     *  2026-11-13: "Later" (referralOfferLater; back press / scrim tap mean the
     *  same) closes it WITHOUT deciding and the offer becomes a
     *  referral_offer_row_<introId> list row that reopens it.
     *
     *  CAVEAT — never assert on this id ALONE. On iOS it lands on the RuneCard
     *  CONTAINER via OptionalA11yId, and a SwiftUI container is not guaranteed
     *  to publish as its own a11y element; on Android it only becomes a
     *  resource-id because RuneDialog sets `testTagsAsResourceId =
     *  BuildConfig.DEBUG` (release APKs expose nothing). Device
     *  .waitForReferralOffer() therefore matches a UNION of this id, the
     *  approve button's id, and the button LABEL. */
    referralOfferDialog: 'referral_offer_dialog',
    /** Primary action on that consent gate. The ID is stable across the whole
     *  cell lifecycle — including the in-flight "Connecting…" phase — so the
     *  LABEL is what distinguishes idle ("Approve"/"Retry") from in-flight.
     *  Device.referralApproveOrRetryButton matches this id OR the labels
     *  (id-first since 2026-09-15: a label-only match silently misses the
     *  dialog on any language whose needle list is stale, which reads as
     *  "consumed"), and pairs it with Device.referralConnecting for the
     *  idle-vs-busy distinction. */
    referralApprove: 'referral_approve',
    /** Secondary "Decline" action on the consent gate (declineOffer). */
    referralDecline: 'referral_decline',
    /** "Later" on the consent gate: closes it without deciding; the offer stays pending as a row. */
    referralOfferLater: 'referral_offer_later',
    /** A PENDING (undecided, "Later") introduction row in the contact list. Append the introId (base64url, a11y-safe). NOT a contact row. */
    referralOfferRow: (introId: string) => `referral_offer_row_${introId}`,
    /** Prefix of every [referralOfferRow] id, for "any pending introduction row" selectors. */
    referralOfferRowPrefix: 'referral_offer_row_',
    /** INTRODUCER-side modal: raised each time this device's control-inbox
     *  drain relays an introducee's accept onward — title "Introduction
     *  accepted" (first accept, or a queued one) or "Introduction complete"
     *  (second accept), one OK action. Same dialog component as
     *  referralOfferDialog (RuneDialog / RuneDialogOverlay), rendered on the
     *  CONTACT LIST ONLY. Timing is Tor-dependent (the drain can land seconds
     *  to minutes after an introducee's Approve tap), so — like update-nudge —
     *  it can occlude any later contact-list-adjacent wait/tap on the
     *  introducer seat; see Device.dismissReferralRelayedIfPresent, raced by
     *  every helper that already races push_prompt/update_nudge for the
     *  identical reason. */
    referralRelayedDialog: 'referral_relayed_dialog',
    /** Sole action on that modal — no yes/no semantics, always safe to
     *  auto-dismiss. */
    referralRelayedOk: 'referral_relayed_ok',
    /** Dismissible alert shown when startReferral returned null for at
     *  least one recipient (no transport / invalid) — the picker has already
     *  closed by the time this appears. Android `RuneDialog(testTag =
     *  "introduce_error_dialog")` (ContactListScreen.kt) / iOS
     *  `.runeDialog(a11yId: "introduce_error_dialog")` (ContactListView.swift).
     *  Its single "OK" action carries no id on either platform (matches the
     *  mnemonic-reveal dialog's OK button, which also has none). */
    introduceErrorDialog: 'introduce_error_dialog',

    // ---- Push notifications (Phase-3 Tier-2 opt-in, contentless relay→APNs) ----
    /** iOS: "Push notifications" row inside the settings sheet — opens PushSettingsView. */
    pushSettingsMenuButton: 'push_settings_menu_button',
    /** iOS: the Tier-2 opt-in toggle in PushSettingsView (on = Tier 2, off = Tier 0). */
    pushSettingsToggle: 'push_settings_toggle',
    /** iOS: the privacy-disclosure card in PushSettingsView. */
    pushSettingsDisclosure: 'push_settings_disclosure',
    /** iOS: "Done" button dismissing PushSettingsView. */
    pushSettingsDone: 'push_settings_done',
    /** iOS: "Next ›" control below PushSettingsView's carousel — advances to
     *  the next page (hidden on the last/switch page). */
    pushSettingsNext: 'push_settings_next',
    /** iOS: "‹ Back" control below PushSettingsView's carousel — retreats to
     *  the previous page (hidden on page 0). */
    pushSettingsBack: 'push_settings_back',
    /** Android: "Notifications" item in the settings dropdown menu. */
    menuNotifications: 'menu_notifications',
    /** Android: root of the background-notifications settings modal. */
    notificationSettingsModal: 'notification_settings_modal',
    /** Android: the background-notifications (Tier-1) opt-in switch. */
    bgNotificationsToggle: 'bg_notifications_toggle',
    /** Android: spinner shown next to bgNotificationsToggle while the FCM
     *  token registers with the relay (switch is disabled meanwhile). */
    notifRegisteringSpinner: 'notif_registering_spinner',
    /** Android: brief error line shown when FCM registration fails and the
     *  switch reverts to OFF. */
    notifRegisterError: 'notif_register_error',
    /** Android: close button of the notification-settings modal. */
    notificationSettingsClose: 'notification_settings_close',
    /** Android: shown in the notification-settings modal when push is
     *  unavailable on this device/build (e.g. no distributor and FCM
     *  unavailable). */
    notifUnavailable: 'notif_unavailable',
    /** Android: "‹ Back" control for the notification-settings carousel
     *  (mirrors iOS's pushSettingsBack). */
    notifCarouselBack: 'notif_carousel_back',
    /** Android: "Next ›" control for the notification-settings carousel
     *  (mirrors iOS's pushSettingsNext). */
    notifCarouselNext: 'notif_carousel_next',
    /** BOTH: opens the OS's own notification settings (Android = this app's
     *  `run_new_messages_v3` channel page; iOS = the app's Settings entry) so
     *  sound/vibration/banner style stay user-owned. Shown only while alerts
     *  are ON, on the switch page of the carousel. */
    notifSystemSettings: 'notif_system_settings',
    /** BOTH: the explanatory line under [notifSystemSettings]. */
    notifSystemSettingsHint: 'notif_system_settings_hint',
    /** Android: expands the inline "what does this share" info section in the
     *  notification-settings modal. */
    notifInfoExpand: 'notif_info_expand',
    /** Android: deep-link-out row inside the expanded info section (e.g. to
     *  unifiedpush.org / the distributor's info). */
    notifInfoDeep: 'notif_info_deep',
    /** Android: UnifiedPush-specific privacy-disclosure card in the
     *  notification-settings modal (mirrors iOS's pushSettingsDisclosure). */
    unifiedPushDisclosure: 'unified_push_disclosure',
    /** Android: shown instead of the toggle when no UnifiedPush distributor
     *  app is installed — links out to install one. */
    notifNoDistributorInstallLink: 'notif_no_distributor_install_link',
    /** Android: notice shown when a previously-registered push token has been
     *  unregistered (e.g. distributor uninstalled, registration revoked). */
    notifUnregisteredNotice: 'notif_unregistered_notice',

    // ---- Move to new device (docs/device-move.md) ----
    /** "Move to new device" item in the settings sheet (both platforms). */
    moveToNewDeviceButton: 'move_to_new_device_button',
    /** Continue button on the explain screen ("what moves, what does not"). */
    moveExplainContinue: 'move_explain_continue',
    moveCredentialCancel: 'move_credential_cancel',
    /** The QR code image on the export screen (old phone). */
    moveQrImage: 'move_qr_image',
    /** "Show as text" toggle — reveals move_handle_text as the paste-path
     *  fallback (same convention as the pairing QR's text fallback). */
    moveShowTextToggle: 'move_show_text_toggle',
    /** The handle text itself (JSON: v/inbox/rcap/code/bid) once revealed by
     *  moveShowTextToggle. Read with Device.readFieldText, pasted on the new
     *  phone with Device.pasteText(movePasteField, ‹this text›). */
    moveHandleText: 'move_handle_text',
    /** Status line on the export/QR screen while old polls `peek` on the
     *  transfer inbox every ~10s ("waiting" until B drains it). */
    moveWaitingStatus: 'move_waiting_status',
    /** "Wipe this phone" — shown once old detects B has drained the bundle
     *  (peek 404/drained). Triggers performEmergencyWipe(deniable: false). */
    moveDoneWipeButton: 'move_done_wipe_button',
    /** "Keep it off" — leaves old frozen (mig_frozen) without wiping. */
    moveDoneKeepButton: 'move_done_keep_button',
    /** Cancels the export before B has drained the bundle (refused after). */
    moveCancelButton: 'move_cancel_button',
    /** "Set up as new" — first-run setup chooser, entry unaffected by Move. */
    setupChooseNew: 'setup_choose_new',
    /** "Move from another phone" — first-run setup chooser, enters the scan/
     *  paste screen (MoveFromDeviceScreen/MoveFromDeviceView) BEFORE the
     *  normal PIN/passphrase onboarding. */
    setupChooseMove: 'setup_choose_move',
    /** Root of the QR scanner view on the new phone's move-import screen
     *  (reuses ScanCodeTab/QRScannerView internals). Not automatable —
     *  e2e always uses the paste path below instead. */
    moveScanView: 'move_scan_view',
    /** Paste-path fallback text field on the new phone — receives the old
     *  phone's move_handle_text verbatim. */
    movePasteField: 'move_paste_field',
    /** Submits the pasted handle, parsing it into RAM (no persistence). */
    movePasteSubmit: 'move_paste_submit',
    /** Post-unlock import progress line on the new phone ("Fetching →
     *  Importing → Securing"). Self-dismisses once the import transaction
     *  commits — wait for it to disappear (Device.waitForGone), not for a
     *  particular stage string (WIDEN, never narrow — the exact stage labels
     *  are app-side copy, not a stable id union). */
    moveProgressStatus: 'move_progress_status',
    /** Error line shown when the import fails (wrong code, tampered chunk,
     *  bundle schema too new, etc). */
    moveErrorText: 'move_error_text',
    /** Retry affordance next to moveErrorText — re-attempts the drain/import
     *  against the same still-live transfer inbox. */
    moveErrorRetry: 'move_error_retry',
} as const

/**
 * Helper to build a cross-platform Appium selector from a plain ID.
 *
 * - iOS (XCUITest): `~id` matches `accessibilityIdentifier`.
 * - Android (UiAutomator2): Compose's `testTagsAsResourceId` exposes
 *   testTags as `resource-id`. The `id=` locator strategy matches these.
 *   The `~` (accessibility id) strategy only checks `content-description`
 *   on Android, so it wouldn't work.
 *
 * Platform is detected via WDIO_PLATFORM env var (set by each config)
 * or defaults to iOS.
 */
export const byId = (id: string): string => {
    if (process.env.WDIO_PLATFORM === 'android') {
        return `id=${id}`
    }
    return `~${id}`
}
