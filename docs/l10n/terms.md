# Rún — per-locale TERM SHEET

Authoritative renderings for Rún's recurring concepts, one section per target
locale. `scripts/l10n/l10n-sync.mjs tasks` appends this file to the generated
`RULES.md`, so every translation brief and every translator sees it.

**How to use it**
- These are *binding*. If a string needs one of these concepts, use the
  rendering below — do not coin a new one, even if a synonym reads better in
  isolation. Cross-area consistency beats local elegance.
- Inflect freely (case, definiteness, possessive, agreement). The sheet gives
  the citation form plus the shape that appears most often in the UI.
- The three tier names are **frozen**: they must be byte-identical in the UI
  strings and in the store copy, in every area.
- Glossary items (`Rún`, `Tor`, `PIN`, `QR`, `Face ID`, `Touch ID`,
  `Secure Enclave`, `SQLCipher`, `Monero`, `Bitcoin`, `FCM`, `APNs`,
  `UnifiedPush`, `ntfy`, `Orbot`, `Argon2`) stay Latin and uninflected in every
  locale and are *not* repeated per section.
- Anchor keys worth remembering, because they are spliced into other strings
  and therefore fix the wording everywhere: `protection_credential_type_passphrase`
  (passphrase), `protection_device_lock_term_ios` (passcode),
  `protection_device_lock_term_android` (lock screen),
  `contact_list_protection_level` (the Settings row that other strings quote as
  "Settings › Protection level").
- English reference: `androidApp/src/main/res/values/strings_*.xml`.

---

## en — English (source)

| concept | rendering |
| --- | --- |
| vault | vault |
| relay | relay |
| runestone | runestone |
| passphrase | passphrase |
| protection level | Protection level |
| burn on read | Burn on read |
| vouched introduction / introduce / introduced by | Vouched introductions / Introduce / Introduced by %1$s |
| inbox | inbox |
| device key (a.k.a. hardware key) | device key |
| hardware lock | Hardware lock |
| device passcode / lock screen | passcode / lock screen |
| recovery code | Recovery code |

- **Tiers:** Decent / Secure / Maximum
- **Register:** informal "you", plain second person.
- **Quotes:** curly “ ” for quoted UI labels and names; the source keeps a few
  escaped straight `\"` for linguistic mentions ("rún", "burn on read") — a
  translation may normalise those to its own quote style.

---

### Introduction-relay modal sweep (2026-09-13)

The introducer-side modal (`referral_relayed_*`, ReferralManager.onIntroRelayed).
Hard rule in every locale: the *complete* variant must NOT say the two are now
connected — the introducer never learns that. Render "each now has what they
need to reach the other", and keep the privacy line ("you have no part in their
conversation and cannot read it") plain and literal.

| English term | rendering |
| --- | --- |
| Introduction accepted (modal title) | Introduction accepted |
| Introduction complete (modal title) | Introduction complete |
| connection details (the forwarded keys/inbox offer) | connection details |
| pass on / passed on (forward to the other party) | pass on / passed on |
| next time you open the app | next time you open the app |

### Debug-mode sweep (2026-09-14)

The opt-in anonymous diagnostic-log upload: settings row `settings_debug_mode` /
`settings_debug_mode_on` plus the consent dialog `debug_mode_title`,
`debug_mode_message`, `debug_mode_message_off`, `debug_mode_turn_on`,
`debug_mode_turn_off` (ContactListScreen.kt / ContactListView.swift, DebugMode.kt).
Hard rules in every locale: **"Debug mode" is a product term** — the settings row
and the dialog title must be byte-identical, and the on-state row is that term +
the locale's "(on)". The privacy promise in `debug_mode_message` stays **literal**:
"never include anything that identifies you or this device" followed by the five
explicit negations (names, message content, addresses, keys, inbox or contact ids).
Do not soften it to "minimal data", do not merge the five items, do not add claims.

| English term | en rendering |
| --- | --- |
| Debug mode (row label + dialog title) | Debug mode |
| Debug mode (on) (row when enabled) | Debug mode (on) |
| diagnostic logs | diagnostic logs |
| log (noun) | log (cf. `connect_log_title` "Connection log") |
| Turn on / Turn off (dialog buttons) | Turn on / Turn off |

- The message is a privacy **promise**, not a summary. Any future edit to the
  five-item list is a semantic change: re-translate, never `relock`.

### Ratchet-refusal notice sweep (2026-09-18)

`conversation_ratchet_refused_body` (ConversationScreen.kt / ConversationView.swift)
— the conversation banner shown when the ratchet refuses a role-colliding
session, so nothing is going out at all. Hard rules in every locale:

- Render "secure channel" with the locale's **channel** noun, never with its
  *connection* noun. The Tor/relay connection is a separate, user-actionable
  concept (`connect_log_title`, "check your connection"); borrowing that word
  here sends the user off to reconnect instead of re-pairing.
- "Messages are not being sent." is a statement of the **current state** — not a
  forecast and not a hedge ("may not arrive"). Keep it factual and short.
- "pair again" reuses the locale's established pairing lexeme from
  `add_contact_cancel_pairing` / `contact_list_reset_relay_message`. Never coin a
  new verb, and never fall back on the milder "add again" of
  `conversation_fs_stalled_body`: that string describes a degraded-but-working
  channel, this one a dead one.

| English term | en rendering |
| --- | --- |
| secure channel | secure channel |
| could not be established | could not be established |
| Messages are not being sent. | Messages are not being sent. |
| pair again | pair again |

### Message-keyboard sentence sweep (2026-09-20)

The trailing sentence of `protection_tier_tagline_casual` / `_private` /
`_maximum` (AboutContent.kt protection carousel) describes what the *message
composer's keyboard* does per tier. First occurrence of keyboard vocabulary in
the product, so these renderings are set here for every future string.

Hard rules in every locale:

- **The casual and private taglines end with the SAME sentence** (the English
  does): keep the two byte-identical inside a locale.
- "password mode" is the keyboard's **password input type**, not the phone's
  passcode and not Rún's passphrase. Use the locale's plain *password* word
  (`lösenord`, `Passwort`, `mot de passe`, `contraseña`, `passord`,
  `adgangskode`, `salasana`, `كلمة المرور`, `گذرواژه`, `erayga sirta ah`,
  `пароль`, `лозинка`) — never the passcode or passphrase term-sheet entry,
  which are reserved.
- 2026-09-21 rewording: Decent/Secure now end with "…so the keyboard may learn
  words you type" — an honest **warning**, not a request. Compose exposes no
  no-learning flag for a plain text field and iOS drops the password content
  type at those tiers, so nothing asks the keyboard not to learn. Translate it
  as a plain possibility ("kan lära sig", "kann … lernen", "peut apprendre"),
  never as a promise in either direction. (The old "is asked not to learn"
  sentence was shipped in 1.6.27 and is being replaced.)
- 2026-09-21, second pass: that whole sentence is now **Android-scoped** — the
  English opens it with "On Android," because iOS keeps the no-learning composer
  at every tier. Only the sentence *opening* moved; the closing "…may learn words
  you type" clause below is unchanged. Front the locale's own phrase (sv/nb/da
  `På Android`, de `Unter Android`, fr `Sur Android,`, es `En Android,`, fi
  `Androidissa`, ar `على Android،`, fa `در Android،`, so topic `Android-ka,`,
  ru/mk `На Android`) and invert the verb where the language is V2.
- The emoji-key clause is **Android-only**; keep "Android" and keep the clause
  attached to it. Locales that must attach a case/definite suffix may
  (`Androidissa`, `Android-kana`); the token itself is never translated.

| locale | keyboard | suggestions | emoji | emoji key | password mode |
| --- | --- | --- | --- | --- | --- |
| en | keyboard | keyboard suggestions | emoji | emoji key | password mode |
| sv | tangentbord | ordförslag | emoji (invariable) | emoji-tangenten | lösenordsläge |
| de | Tastatur | Tastaturvorschläge | Emojis | Emoji-Taste | Passwortmodus |
| fr | clavier | suggestions | emoji (invariable, no accent) | touche emoji | mode mot de passe |
| es | teclado | sugerencias | emojis | tecla de emojis | modo contraseña |
| nb | tastatur | ordforslag | emoji (invariable) | emoji-tasten | passordmodus |
| da | tastatur | ordforslag | emoji (invariable) | emoji-tasten | adgangskodetilstand |
| fi | näppäimistö | sanaehdotukset | emojit | emoji-näppäin | salasanatila |
| ar | لوحة المفاتيح | اقتراحات لوحة المفاتيح | الرموز التعبيرية | مفتاح الرموز التعبيرية | وضع كلمة المرور |
| fa | صفحه‌کلید | پیشنهادها | ایموجی | کلید ایموجی | حالت گذرواژه |
| so | keyboard (loanword: *keyboard-ka*) | soo-jeedinta erayada | emoji (*emoji-ga*) | badhanka emoji-ga | habka erayga sirta ah |
| ru | клавиатура | подсказки | эмодзи (indeclinable) | клавиша эмодзи | режим пароля |
| mk | тастатура | предлози | емоџи | копчето за емоџи | режим за лозинка |

- **ar:** `الرموز التعبيرية` (Apple/Google Arabic), **not** the transliteration
  `الإيموجي` — this is the jargon policy's "established native term" exception.
  `وضع كلمة المرور` stays distinct from `عبارة المرور` (Rún's passphrase).
- **fa:** the Persian semicolon `؛` joins the two clauses, matching the rest of
  the locale. `گذرواژه` is deliberately neither `عبارت عبور` (passphrase) nor
  `رمز دستگاه` (device passcode).
- **so:** `keyboard` follows the locale's loanword rule (English stem +
  hyphenated suffix). The *key* is `badhan` (button), never `fure` — `fure` is
  reserved for cryptographic/device keys. `erayga sirta ah` = password, already
  fixed by the so sheet's rejected-alternatives note.
- **da:** `adgangskodetilstand` re-uses `adgangskode`, which the da sheet
  reserves for the phone's passcode; the collision is accepted because the
  subject of the sentence is the keyboard, and Danish has no other current word
  for a password field. Do not "fix" it to `adgangssætningstilstand`.
- **mk:** `лозинка` is the sheet's reserved rendering of English *password* —
  this is its second legitimate use.

#### "…so the keyboard may learn words you type" (applied 2026-09-21)

The exact clause now closing `protection_tier_tagline_casual` and `_private` in
every locale. Byte-identical between the two keys inside a locale; everything
before it was left untouched from the 2026-09-20 sweep. The modal is a plain
possibility (*kan / kann / peut / puede / voi / может / може / قد / ممکن است /
karaa*) — never a promise, never a request.

| locale | clause |
| --- | --- |
| en | so the keyboard may learn words you type |
| sv | så tangentbordet kan lära sig ord du skriver |
| de | sodass die Tastatur Wörter lernen kann, die du tippst |
| fr | le clavier peut donc apprendre les mots que vous tapez |
| es | así que el teclado puede aprender palabras que escribes |
| nb | så tastaturet kan lære ord du skriver |
| da | så tastaturet kan lære ord, du skriver |
| fi | joten näppäimistö voi oppia kirjoittamiasi sanoja |
| ar | لذا قد تتعلّم لوحة المفاتيح كلمات تكتبها |
| fa | پس ممکن است صفحه‌کلید واژه‌هایی را که می‌نویسید یاد بگیرد |
| so | markaa keyboard-ku wuxuu baran karaa erayada aad qorto |
| ru | поэтому клавиатура может запоминать слова, которые вы набираете |
| mk | па тастатурата може да ги научи зборовите што ги пишувате |

- The English ";" became a plain comma, so every locale moved its own clause
  separator to its comma as well (fa "،" replaces "؛"; fr loses the spaced " ; ").
- **fi:** *kirjoittamiasi sanoja* (participle + partitive), not a relative
  clause — the idiomatic Finnish for "words you type".
- **ru:** keeps *запоминать* ("memorise"), the verb the retired request sentence
  used, so the reversal reads as the same claim inverted; *учить* would read as
  studying.
- **so:** the connector is *markaa*, not a second *sidaa darteed* — the casual
  tagline already spends that phrase one sentence earlier.
- **ar:** indefinite *كلمات تكتبها* matches the English indefinite "words"; the
  definite *الكلمات التي تكتبها* would over-claim completeness.
- **de/da:** the comma before the relative clause (*die du tippst*, *ord, du
  skriver*) is grammatical, not stylistic — keep it.

## sv — Swedish

| concept | rendering |
| --- | --- |
| vault | valv |
| relay | relä |
| runestone | runsten |
| passphrase | lösenfras |
| protection level | Skyddsnivå |
| burn on read | Brinner vid läsning |
| vouched introduction / introduce / introduced by | Betrodda introduktioner / Introducera / Introducerad av %1$s |
| inbox | inkorg |
| device key | enhetsnyckel |
| hardware lock | hårdvarulås |
| device passcode / lock screen | lösenkod / skärmlås |
| recovery code | Återställningskod |

- **Tiers:** Normal / Säker / Maximal
- **Register:** informal **du/din/ditt** throughout. Never "ni".
- **Quotes:** ” ” (Swedish double). Straight `\"` is kept only where the English
  source uses it.
- **Deliberate loanwords:** none beyond the glossary — `relä` and `lösenfras`
  are native.

---

### Jargon (sweep 2026-09-03)

# sv — jargon decisions (locale sweep 2026-09-03)

Merge target: the `## sv — Swedish` section of `docs/l10n/terms.md`.
Policy applied (project policy, 2026-09-02): technical/security terms stay
ENGLISH or the established Swedish loanword, unless Swedish has a
well-established native term used by Signal / WhatsApp / Apple / Google
localizations. Never a literal calque.

### Jargon

| English term | sv rendering | reason |
| --- | --- | --- |
| brute force | **brute force** (noun/verb phrase: *knäckas med brute force*; attack: *brute force-attacker*) | Established loanword in Swedish security writing. `råstyrka` is a literal calque and means "raw physical strength" — explicitly rejected by the project policy. |
| end-to-end encryption | **end-to-end-kryptering / end-to-end-krypterad** | Apple's own Swedish localization uses *end-to-end-krypterad*; already the form in the UI, `play-short-sv` and both feature lists. WhatsApp's *totalsträckskryptering* is a competing coinage with far less reach — not adopted. |
| forward secrecy | **forward secrecy** | No established Swedish term; Swedish security texts keep the English. |
| ratchet (verb, key ratcheting) | **vridas framåt** (*nyckeln vrids framåt*) | Deliberately descriptive prose, not a term of art, in the one place it appears (`about_e2e_body`, store copy). The product name "Double Ratchet" stays English in the feature list. |
| relay | **relä** (def. *reläet*, always neuter: *ett relä*) | Term-sheet entry; native and unambiguous. Do **not** use `reläserver` (was in the store copy) or `relay`. |
| onion / circuit / guard / exit node | *(does not occur in sv copy)* | If ever needed: keep **onion**, **circuit**, **guard-nod**, **exit-nod**. |
| hardware-backed / hardware-bound | **hårdvarubunden**, **hårdvaruskydd**, **hårdvarulås**, **hårdvarunyckel** | `hårdvara` is the normal Swedish loan-compound stem (Google/Apple sv both use it); not a calque. |
| keystore (Android) | **Android Keystore** | Product name — glossary-like, stays English. |
| keychain (iOS) | **nyckelring** (*enhetens nyckelring*) | Apple's own Swedish localization says *nyckelring* / *iCloud-nyckelring*. This is exactly the "well-established native term" exception. |
| passcode (device) | **lösenkod** | Apple sv uses *lösenkod*. Term-sheet anchor `protection_device_lock_term_ios`. |
| lock screen (Android) | **skärmlås** | Google sv. Term-sheet anchor `protection_device_lock_term_android`. |
| password (device screen-lock option only) | **lösenord** | Occurs exactly once (`protection_forced_explainer_cta_body_android`). Keep the three-way split: *lösenfras* (Rún's own credential) / *lösenkod* (phone passcode) / *lösenord* (phone password). Do not swap. |
| biometric(s) | **biometri / biometrisk** | Standard Swedish. |
| wipe / self-wipe | **radera / radering / självradering** | Native and already consistent app-wide. |
| crypto-erase | **förstör själva krypteringsnycklarna** (descriptive) | No Swedish term of art; the store copy spells out the mechanism, which is also more persuasive. |
| forensic extraction / forensic tools | **forensisk / forensiska verktyg**, *säker mot forensik* | *forensisk* is normal Swedish. |
| AFU / BFU | **AFU / BFU** | Initialisms, untranslated (`protection_device_panel_baseline_label`). |
| proxy | *(does not occur)* | If needed: **proxy**. |
| push | **push** (compounds: *push-notiser*, *pushserver*, *pushtjänst*, *Pushen*) | Established Swedish loanword. Initialism+noun stays hyphenated (`push-notiser`), plain compounds are written together (`pushserver`). |
| token | *(does not occur in sv copy)* | If needed: **token**. |
| endpoint | **endpoint-adress** | Changed from `slutpunktsadress`. The user meets this word as "Endpoint" in the ntfy/UnifiedPush distributor UI; `slutpunkt` is a Microsoft-ism that breaks that mapping. |
| proof of work | **proof-of-work** | Kept English (`add_contact_solving_pow`). |
| jailbreak / root | **jailbreakad / rootad** | The established Swedish loan-verbs; no native equivalent. |
| rate limit / entropy / salt / KDF | *(do not occur)* | If needed: **rate limit**, **entropi**, **salt**, **nyckelhärledning** (the verb *härleds* is already used for Argon2 in the store copy). |
| padding (noun) | **padding** | Replaced `vaddering` / `vadderad`, which is the calque for quilting/upholstery and reads absurd in Swedish. |
| to pad (verb) | **fylla ut** (*Meddelanden fylls ut till fasta storlekar*) | Natural Swedish verb; keeps the noun **padding** for the term of art. |
| metadata | *(does not occur)* | If needed: **metadata**. |
| sideload | *(does not occur)* | If needed: **sidoinstallera** is NOT established — keep **sideload**. |
| timing (as an attack surface / profile) | **tidsmönster / tidsprofil** | Replaced `tajming`, which in Swedish reads as comedic/sports timing and clashed with the already-present *tidsstämplar* / *tidsprofil* family. |
| at rest (encryption) | **i vila** (*data i vila*, *krypterat i vila*) | The established Swedish rendering; attach it to the *data*, not to the protection. |
| offline attack | **offline-attacker** | Established loan-compound. |
| blob | **datablobb** | Already in use; no Swedish term exists. |
| VAPID / RFC 8291 / Web Push | unchanged | Protocol names. |
| contact discovery | **kontaktmatchning** | Replaced `kontaktupptäckt`, a non-word calque. *Kontaktmatchning* is what Swedish privacy writing calls server-side address-book matching. |
| messenger (product category) | **meddelandeapp** | Replaced `messenger` in the App Store subtitle/keywords and `meddelandetjänst` in both full descriptions. `messenger` in Swedish reads as Facebook Messenger; the UI already says *meddelandeapp* (`eula_body`, `notif_settings_sound_hint`). |
| setup (the onboarding process, noun) | **konfiguration** | Replaced `uppsättning`, which in Swedish means "a set of things"/"a stage production". Applies to *slutföra konfigurationen*, *startar en ny konfiguration*, *är konfigurerad*. |
| apply (settings button) | **Verkställ** | Replaced `Använd`, which next to a level name reads as "Use". *Verkställ* is the standard Swedish Apply. |
| abuse (user conduct) | **kränkande beteende** | Replaced `missbruk`, which in Swedish means substance abuse or misuse-of-a-service. *Missbrukar tjänsten* is retained where the English really is "abusing the service". |

### Additional sv rules confirmed this sweep

- **`Rún` is never inflected — no genitive `Rúns`.** Rephrase with a
  prepositional phrase (*reläet i Rún*, *nycklarna i Rún*, *meddelandena i
  Rún*) or a hyphenated compound (*Rún-app*, *Rún-installation*,
  *Rún-anmälan*). Four pre-existing `Rúns` were fixed (two in UI strings, two
  in store copy); `l10n-sync apply` would have rejected them.
- **Tiers:** Normal / Säker / Maximal — byte-identical in UI and both store
  descriptions. Verified.
- **Register:** informal *du/din/ditt*. Every occurrence of *ni* in the locale
  is a genuine plural ("du och din kontakt"), not a formal address. Verified.
- **Quotes:** ” ” only; no `“`. Escaped straight `\"` appears only where the
  English source has it (4 strings). Verified against the English quote counts.
- **Gendered participles:** Swedish agrees for neuter/plural only, so
  person-placeholder strings (`%1$s togs bort från gruppen`, `Introducerad av
  %1$s`) are already gender-neutral. No action needed.

### Notification-carousel sweep (2026-09-11)

The opt-in carousel was cut to three pages + the switch; these are the renderings
used across `notif_edu_*` and `notif_edu_up_*` in this locale.

| English term | sv rendering |
| --- | --- |
| wake / wake signal (contentless push) | **väckning** / **väckningssignal** |
| distributor (UnifiedPush) | **distributörsapp** / *distributören* |
| push address | **push-adress** |
| timestamps (of incoming messages) | **tidsstämplar** |

### Connect-screen sweep (2026-09-11)

The runestone ring/`R` reveal, the live connection log and the anonymous
connect-time report (`ConnectTelemetry`) — renderings used in
`about_tor_runestone_body`, `connect_log_title` and the 1.6.17 What's New.

| English term | sv rendering |
| --- | --- |
| ring (of the runestone) | **ringen** (runstenens ring) |
| the R (glyph that lights last) | **R:et** |
| live connection log | **Anslutningslogg** (UI), *anslutningslogg i realtid* i butikstext |
| connect-time report (seconds only, nothing identifying) | *rapporterar bara antalet sekunder det tog till reläet* |

### Introduction-relay modal sweep (2026-09-13)

The introducer-side modal (`referral_relayed_*`, ReferralManager.onIntroRelayed).
Hard rule in every locale: the *complete* variant must NOT say the two are now
connected — the introducer never learns that. Render "each now has what they
need to reach the other", and keep the privacy line ("you have no part in their
conversation and cannot read it") plain and literal.

| English term | sv rendering |
| --- | --- |
| Introduction accepted / complete (modal titles) | **Introduktionen godkänd** / **Introduktionen klar** |
| connection details | **anslutningsuppgifter** (2nd mention: *uppgifterna*) |
| pass on / passed on | **skicka vidare** / *har skickats vidare* |
| each now has what they need to reach the other | *var och en har det som behövs för att nå den andra* |
| next time you open the app | *nästa gång du öppnar appen* |

- Swedish `till` has no genitive reading, so *din introduktion till %2$s* is
  unambiguous here (unlike nb/da — see those sections).

### Debug-mode sweep (2026-09-14)

The opt-in anonymous diagnostic-log upload: settings row `settings_debug_mode` /
`settings_debug_mode_on` plus the consent dialog `debug_mode_title`,
`debug_mode_message`, `debug_mode_message_off`, `debug_mode_turn_on`,
`debug_mode_turn_off` (ContactListScreen.kt / ContactListView.swift, DebugMode.kt).
Hard rules in every locale: **"Debug mode" is a product term** — the settings row
and the dialog title must be byte-identical, and the on-state row is that term +
the locale's "(on)". The privacy promise in `debug_mode_message` stays **literal**:
"never include anything that identifies you or this device" followed by the five
explicit negations (names, message content, addresses, keys, inbox or contact ids).
Do not soften it to "minimal data", do not merge the five items, do not add claims.

| English term | sv rendering |
| --- | --- |
| Debug mode (row label + dialog title) | **Felsökningsläge** (def. *Felsökningsläget är på*) |
| Debug mode (on) | **Felsökningsläge (på)** |
| diagnostic logs | **diagnostikloggar** (*anonyma diagnostikloggar*) |
| log (noun) | **logg** (cf. `connect_log_title` *Anslutningslogg*) |
| Turn on / Turn off | **Slå på** / **Stäng av** |

- *Felsökning* is Google's own sv term for debugging (*USB-felsökning*) — the
  "well-established native term" exception, not a calque. `Debugläge` rejected.
- "ids" → **id** (uninflected in the compound *inkorgs- eller kontakt-id*).

### Ratchet-refusal notice sweep (2026-09-18)

See the shared rules in the `## en` section (`conversation_ratchet_refused_body`).

| English term | sv rendering |
| --- | --- |
| secure channel | **säker kanal** |
| could not be established | Det gick inte att upprätta … |
| Messages are not being sent. | Meddelanden skickas inte. |
| pair again | **parkoppla på nytt** |

- *Kanal* was chosen over *anslutning*, which is reserved for the Tor/relay connection (*Anslutningslogg*, *Kontrollera din anslutning*).
- *parkoppla på nytt* is the verb already in `contact_list_reset_relay_message`; the noun is *parkoppling* (`add_contact_cancel_pairing`).

## de — German

| concept | rendering |
| --- | --- |
| vault | Tresor |
| relay | Relay |
| runestone | Runenstein |
| passphrase | Passphrase |
| protection level | Schutzstufe |
| burn on read | Nach dem Lesen verbrannt |
| vouched introduction / introduce / introduced by | Verbürgte Vorstellungen / Vorstellen / Vorgestellt von %1$s |
| inbox | Postfach |
| device key | Geräteschlüssel |
| hardware lock | Hardware-Sperre |
| device passcode / lock screen | Gerätecode / Bildschirmsperre |
| recovery code | Wiederherstellungscode |

- **Tiers:** Solide / Sicher / Maximum
- **Register:** informal **du/dein** (not "Sie"), imperative for actions
  ("Wähle…", "Versuch es erneut").
- **Quotes:** „ “ (German).
- **Deliberate loanwords:** **Relay** (not "Vermittlungsserver"),
  **Passphrase** (not "Passwortsatz"), **Hardware-** as the compound stem.

---

### Jargon (sweep 2026-09-03)

# de — German jargon decisions (locale sweep 2026-09-03)

Companion to the `## de — German` section of `docs/l10n/terms.md` (that file was
NOT edited — merge this table into it when the sweep is signed off).

Register confirmed unchanged: informal **du/dein**, imperative for actions.
Quotes confirmed: „ … “ (18 pairs, all correctly paired). No `\"` escapes.

### Jargon

| English term | de rendering | reason |
| --- | --- | --- |
| brute force | **Brute Force** (verbal: „per Brute Force knacken“); **Brute-Force-Angriff** (noun) | Established German security term (BSI, Heise, Signal/Apple DE). Replaced the native paraphrase „durchprobieren“ — understandable but not the term readers search for; never a calque („rohe Gewalt“). |
| end-to-end encryption | **Ende-zu-Ende-Verschlüsselung**; adj. **Ende-zu-Ende-verschlüsselt** | Well-established native term (WhatsApp/Signal/Apple DE). Exception to "keep English". Hyphenated in adjective/heading position; the passive verb phrase „wird Ende-zu-Ende verschlüsselt“ stays unhyphenated (Duden). |
| forward secrecy | **Forward Secrecy** | No established German equivalent; German security writing uses the English term. |
| ratchet (noun / protocol) | **Double Ratchet** | Protocol name, English everywhere. |
| ratchet (verb, descriptive) | „die Schlüssel **rücken** … **weiter/vor**“ | German has no verb for it and no established loan verb; a plain-language paraphrase is correct here, not a calque. The *noun* stays English. |
| relay | **Relay** | Term-sheet loanword. Never „Vermittlungsserver“/„Relaisserver“. |
| onion / circuit / guard node / exit node | (not surfaced in de UI) — keep **.onion / Circuit / Guard-Node / Exit-Node** if ever needed | Tor's German docs keep them English. |
| hardware-backed / hardware-bound | **hardwaregebunden**, „an … gebunden“ | Established German adjective (Android DE docs). Never „hardware-unterstützt“. |
| hardware key / hardware lock | **Hardware-Schlüssel** / **Hardware-Sperre** | Mirrors the English source's own *hardware key* vs *device key* split; „Hardware-“ is the term sheet's compound stem. |
| device key | **Geräteschlüssel** | Term sheet. Kept distinct from Hardware-Schlüssel exactly as the English does. |
| keystore | **Android-Keystore** | Google's own German docs keep "Keystore". |
| keychain | **Schlüsselbund** (Geräte-Schlüsselbund) | **Exception to the English-first rule:** Apple's own German localization uses „Schlüsselbund“; that is the term the user sees in iOS. |
| Secure Enclave | **Secure Enclave** | Glossary. |
| passcode | **Gerätecode** | Apple's German for the device passcode. Term sheet. Normalised 5 sites that said „der Code deines Geräts“/„seinem Code“. |
| lock screen | **Bildschirmsperre** | Android DE standard. Term sheet. |
| biometric / biometrics | **Biometrie**, **biometrisch** | Established native German. |
| wipe (the app's erase-all) | **löschen / Löschung**; the destructive sense spelled out: „alle Daten in Rún löschen“ | German consumer UIs (Apple, Google) use „löschen“; a loan "Wipe" would be jargon leakage. Bare „Rún löschen“ was ambiguous with *uninstall* and was fixed. |
| self-wipe / self-destruct | **Selbstlöschung** / **Selbstzerstörung** | Native, established, unambiguous. |
| crypto-erase | descriptive: „**die Schlüssel selbst** löschen/vernichten“ | No established German term; the English source is descriptive too. |
| forensic extraction / forensic tools | **forensische Werkzeuge**, **forensische Angriffe**, **Forensik** | „Forensik“ is standard German; no calque risk. |
| AFU / BFU | **AFU** | English acronym, no German equivalent; kept verbatim in the protection panel. |
| proxy | **Proxy** | Established loanword (not currently surfaced in de UI). |
| push | **Push**, **Push-Benachrichtigung**, **Push-Server**, **Push-Dienst** | Established German loanword (Apple/Google DE). |
| token | **Token** | Established loanword (not currently surfaced in de UI). |
| endpoint | **Endpunktadresse** | „Endpunkt“ is standard German for a network endpoint (Microsoft/Google DE); understandable to the UnifiedPush audience. Kept. |
| proof of work | **Proof-of-Work** | English, capitalised as a German noun. |
| jailbreak / root | **Jailbreak** („scheint einen Jailbreak zu haben“) / **gerootet** | Established German loanwords. |
| rate limit | **Rate Limit** if ever needed | Not surfaced in de UI. |
| entropy / salt / KDF / key derivation | „mit Argon2id **abgeleitet**“ | „ableiten“ is established German crypto usage; Argon2 is glossary. Entropy/salt not surfaced. |
| padding | **Padding** (noun/term); **auffüllen** (verb, plain-language) | „Padding“ is the German security loanword. The store bullet is now „Padding verbirgt sogar die Nachrichtengröße“; the prose keeps „mit Padding aufgefüllte Datenblöcke“ / „auf feste Größen aufgefüllt“. |
| metadata | **Metadaten** if needed | Established native (not currently surfaced). |
| sideload | **Sideload / sideloaden** if needed | Not surfaced. |
| distributor (UnifiedPush) | **Distributor**, **Benachrichtigungs-Distributor**, **Distributor-App** | The UnifiedPush/ntfy German community term. |
| build | **Build** (Google-Build, Google-freier Build) | Established German tech loanword. |
| timing (as attack surface) | **Timing** | Kept English, as in German security writing; „Zeitstempel“ used for the concrete timestamps. |
| analytics / tracking | **Analyse** / **Tracking** | „Tracking“ is the established German privacy loanword; „Analyse“ reads better than „Analytics“ for the store bullet. |
| social graph | **Social Graph** | Kept English. „soziales Netz“ (previous rendering) is a **false friend** — in German that means the social safety net. |
| on the wire | **im Datenverkehr** | „auf der Leitung“ (previous rendering) is a false friend: the German idiom *auf der Leitung stehen* means "to be slow on the uptake". |
| at rest | **im Ruhezustand** | Established German („Daten im Ruhezustand“). |
| to leak (data) | **durchsickern** / „nach außen gelangen“ | „auslaufen“ (previous rendering) is liquid-leaking; wrong sense. |
| trade-off | **Kompromiss** | „Handel“ (previous rendering) means commerce; wrong sense. |
| checkout (Google Play) | **Bezahlvorgang** | „Kasse“ reads like a supermarket till; Play's German flow is a Bezahlvorgang. |
| whistleblower | **Whistleblower** | Established German loanword. |
| unblock | **Blockierung aufheben** | What Signal/WhatsApp DE use. „Freigeben“ means *approve/release*; wrong sense. |
| vault | **Tresor** | Term sheet. |
| tiers | **Solide / Sicher / Maximum** | Term sheet, frozen; verified byte-identical in UI strings and in both de store descriptions. |

### Glossary / never-inflect

`Rún` was found **inflected 4×** as the German genitive „Rúns“ (2 UI strings, 2 store
files) — a hard `apply` validator violation. All four rephrased to „… von Rún“.
Hyphenated compounds („Rún-App“, „Rún-Installation“, „Rún-Missbrauchsmeldung“) are
fine: the validator only rejects `Rún` followed by a letter.

### Notification-carousel sweep (2026-09-11)

The opt-in carousel was cut to three pages + the switch; these are the renderings
used across `notif_edu_*` and `notif_edu_up_*` in this locale.

| English term | de rendering |
| --- | --- |
| wake / wake signal (contentless push) | **Wecksignal** |
| push address | **Push-Adresse** |
| timestamps (of incoming messages) | **Zeitstempel** |

### Connect-screen sweep (2026-09-11)

The runestone ring/`R` reveal, the live connection log and the anonymous
connect-time report (`ConnectTelemetry`) — renderings used in
`about_tor_runestone_body`, `connect_log_title` and the 1.6.17 What's New.

| English term | de rendering |
| --- | --- |
| ring (of the runestone) | **der Ring** (Ring des Runensteins) |
| the R (glyph that lights last) | **das R** |
| live connection log | **Verbindungsprotokoll** (UI), *Live-Protokoll* in der Storekopie |
| connect-time report (seconds only, nothing identifying) | *meldet dem Relay nur die Dauer in Sekunden* |

### Introduction-relay modal sweep (2026-09-13)

The introducer-side modal (`referral_relayed_*`, ReferralManager.onIntroRelayed).
Hard rule in every locale: the *complete* variant must NOT say the two are now
connected — the introducer never learns that. Render "each now has what they
need to reach the other", and keep the privacy line ("you have no part in their
conversation and cannot read it") plain and literal.

| English term | de rendering |
| --- | --- |
| Introduction accepted / complete (modal titles) | **Vorstellung bestätigt** / **Vorstellung abgeschlossen** |
| connection details | **Verbindungsdaten** |
| pass on / passed on | **weitergeben** / *wurden weitergegeben* |
| each now has what they need to reach the other | *jede Seite hat jetzt, was sie braucht, um die andere zu erreichen* |
| next time you open the app | *wenn du die App das nächste Mal öffnest* |

- **Frame:** *%1$s hat bestätigt, %2$s vorgestellt zu werden.* Do **not** write
  *deine Vorstellung bei %2$s* — "Vorstellung bei" reads as a self-introduction
  (job interview), not as introducing a third person.

### Debug-mode sweep (2026-09-14)

The opt-in anonymous diagnostic-log upload: settings row `settings_debug_mode` /
`settings_debug_mode_on` plus the consent dialog `debug_mode_title`,
`debug_mode_message`, `debug_mode_message_off`, `debug_mode_turn_on`,
`debug_mode_turn_off` (ContactListScreen.kt / ContactListView.swift, DebugMode.kt).
Hard rules in every locale: **"Debug mode" is a product term** — the settings row
and the dialog title must be byte-identical, and the on-state row is that term +
the locale's "(on)". The privacy promise in `debug_mode_message` stays **literal**:
"never include anything that identifies you or this device" followed by the five
explicit negations (names, message content, addresses, keys, inbox or contact ids).
Do not soften it to "minimal data", do not merge the five items, do not add claims.

| English term | de rendering |
| --- | --- |
| Debug mode (row label + dialog title) | **Debug-Modus** (def. *Der Debug-Modus ist an*) |
| Debug mode (on) | **Debug-Modus (an)** |
| diagnostic logs | **Diagnoseprotokolle** |
| log (noun) | **Protokoll** (cf. `connect_log_title` *Verbindungsprotokoll*) |
| Turn on / Turn off | **Einschalten** / **Ausschalten** |

- **Debug** is the established German loanword (Android de: *USB-Debugging*);
  `Fehlerbehebungsmodus` / `Fehlersuchmodus` rejected as calques.
- "(an)" (not "(ein)") so the row and `debug_mode_message_off` (*ist an*) agree.
- "ids" → **IDs** (*Postfach- oder Kontakt-IDs*); inbox stays *Postfach*.

### Ratchet-refusal notice sweep (2026-09-18)

See the shared rules in the `## en` section (`conversation_ratchet_refused_body`).

| English term | de rendering |
| --- | --- |
| secure channel | **sicherer Kanal** |
| could not be established | konnte kein … aufgebaut werden |
| Messages are not being sent. | Nachrichten werden nicht gesendet. |
| pair again | **die Kopplung erneut durchführen** |

- The noun **Kopplung** (`add_contact_cancel_pairing` „Kopplung abbrechen“) carries the imperative: *führe die Kopplung erneut durch*. Rejected: *kopple ihn erneut* (reads as coupling the person), and *koppelt euch erneut* (mixes du- and ihr-imperatives in one sentence).
- *Kanal*, not *Verbindung* — *Verbindung* is the relay/Tor connection („Prüfe die Verbindung“).

## fr — French

| concept | rendering |
| --- | --- |
| vault | coffre-fort |
| relay | relais |
| runestone | pierre runique |
| passphrase | phrase secrète |
| protection level | Niveau de protection |
| burn on read | Effacement à la lecture |
| vouched introduction / introduce / introduced by | Des présentations cautionnées / Présenter / Présenté par %1$s |
| inbox | boîte de réception |
| device key | clé de l'appareil |
| hardware lock | verrou matériel |
| device passcode / lock screen | code d'appareil / écran de verrouillage |
| recovery code | Code de récupération |

- **Tiers:** Décent / Sécurisé / Maximum
- **Register:** formal **vous** throughout.
- **Quotes:** « » (with the usual French spacing as already written in the files).
- **Deliberate loanwords:** none beyond the glossary.

---

### Jargon (sweep 2026-09-03)

# fr — French jargon decisions (locale sweep 2026-09-03)

Scope: `androidApp/src/main/res/values-fr/strings_*.xml`, `docs/store-listing/play-short-fr.txt`,
`play-full-fr.txt`, `appstore-full-fr.txt`, `fr-FR:` lines of `appstore-subtitle.txt` /
`appstore-keywords.txt`. Register: formal **vous**. Quotes: « » with ordinary spaces (no NBSP —
matches the rest of the fr corpus). To be folded into `docs/l10n/terms.md` under `## fr — French`.

### Jargon

| English term | fr rendering | reason |
| --- | --- | --- |
| end-to-end encryption | chiffrement de bout en bout / chiffré de bout en bout | Established native term (Signal, WhatsApp, Apple FR). |
| forward secrecy | confidentialité persistante | Established native term (fr.wikipedia, ANSSI); not a calque. |
| brute force | (attaque par) force brute | Established native collocation. Never "force brutale". |
| ratchet (verb, key ratchets forward) | la clé progresse d'un cran / les clés progressent | Descriptive; no noun coined. "cliquet" would be opaque in consumer copy, and a literal calque is worse. |
| Double Ratchet (product name) | Double Ratchet | Protocol name — untranslated. |
| relay | relais | Term-sheet entry; native, unambiguous, already everywhere in the locale. |
| Tor hop / node | nœud | EN deliberately says "hops" to avoid colliding with Rún's own relay; "relais" is reserved for the Rún relay. |
| padding | padding (loanword); verb form "complété par du padding" | "rembourrage / rembourré" is a furniture calque. French security writing uses "padding"; "bourrage" is ambiguous (paper jam) and "remplissage" is not settled. |
| proof of work | preuve de travail | Genuinely established French term (crypto/Bitcoin literature, fr.wikipedia); not a coinage. |
| forensic (tools / attacks / extraction) | forensique (outils forensiques, attaques forensiques, analyse forensique) | Established loan-adjective in French infosec. "criminalistique / informatique légale" is legal-domain, not product copy. |
| analytics | télémétrie | "analytique" as a noun is a raw calque. "télémétrie" is what French software (Mozilla, Proton, VS Code) uses for exactly this. |
| tracking | pistage | Established native term (CNIL, Firefox FR). |
| phones home | fait remonter des données | "téléphoner à la maison" is a meaningless calque in French. |
| push (notification / server / signal) | push (notifications push, serveur push, signal de réveil) | Loanword used by every French messenger; "poussé" is not idiomatic. |
| wake / wake-up signal | signal de réveil (short form: réveil) | Native, clear once introduced. |
| endpoint (Web Push) | point de terminaison | Established in Google/MDN French Web Push docs; kept, but phrased "l'adresse de votre point de terminaison" to avoid a noun stack. |
| token | jeton (not currently surfaced in fr UI copy) | Established native term. |
| distributor (UnifiedPush) | distributeur (application distributrice) | UnifiedPush's own French wording. |
| keystore / keychain | Android Keystore (untranslated) · trousseau de l'appareil (iOS) | Keystore is a product name; Apple FR calls the keychain "le trousseau". |
| Secure Enclave | Secure Enclave | Glossary; Apple keeps it untranslated in FR. |
| hardware-bound / hardware-backed | lié au matériel · verrou matériel · clé matérielle | Term-sheet entry; native and accurate. Never "adossé au matériel" alone. |
| security chip | puce de sécurité | Native, used by French tech press for the SE/StrongBox. |
| passcode (device) | code d'appareil | Term-sheet anchor (`protection_device_lock_term_ios`). Normalised the one outlier ("code sur l'appareil"). |
| lock screen | écran de verrouillage | Term-sheet anchor; Android FR wording. |
| biometrics / biometric | biométrie / biométrique | Established native term. |
| wipe / self-wipe | effacement / s'efface / auto-effacement | Native; "effacer" is the Apple/Google FR verb for erase. |
| self-destruct | autodestruction / s'autodétruit | Native. |
| crypto-erase | un effacement détruit les clés elles-mêmes | Described, not named — no settled French term, and a coinage would be opaque. |
| AFU / BFU | AFU (untranslated, `protection_device_panel_baseline_label`) | Forensic acronym with no French equivalent. |
| offline attack | attaque hors ligne | Established native term. |
| jailbreak / root | jailbreaké / rooté | Loanwords; the only forms French users recognise. |
| blob | bloc (chiffré) | "blob" is opaque in consumer copy; "bloc chiffré" is accurate and natural. |
| bug | bug | Loanword; standard in France (vs. "bogue" in QC). |
| VAPID / RFC 8291 / Web Push / FCM / APNs / ntfy / F-Droid | untranslated | Protocol and product names. |
| app switcher | sélecteur d'applications (Android) · sélecteur d'apps (iOS) | Platform-appropriate; Apple FR says "app", Google FR says "application/appli". |
| app (store copy) | appli (Play) · app (App Store) | Deliberate per-store divergence, already present and kept. |
| vouched introduction | présentation cautionnée | Term-sheet entry — the Play/App Store prose said "sur recommandation", now aligned. |

### Register / typography
- **vous** everywhere; imperative for actions ("Choisissez…", "Réessayez").
- Guillemets « » with ordinary (not non-breaking) spaces, matching the existing fr files; narrow
  spaces before `?` `!` `:` `;` are ordinary spaces too — kept as-is for consistency.
- Em dash `—` throughout (the `<fr>` block of `whatsnew.txt` uses `–`, see report).
- Masculine default agreement with "vous" ("vous seul", "soyez prudent") is used consistently;
  left unchanged rather than half-converted.

### Notification-carousel sweep (2026-09-11)

The opt-in carousel was cut to three pages + the switch; these are the renderings
used across `notif_edu_*` and `notif_edu_up_*` in this locale.

| English term | fr rendering |
| --- | --- |
| wake / wake signal (contentless push) | **réveil** / *signal de réveil* (confirmed) |
| push address | **adresse push** |
| timestamps (of incoming messages) | **horodatages** |

### Connect-screen sweep (2026-09-11)

The runestone ring/`R` reveal, the live connection log and the anonymous
connect-time report (`ConnectTelemetry`) — renderings used in
`about_tor_runestone_body`, `connect_log_title` and the 1.6.17 What's New.

| English term | fr rendering |
| --- | --- |
| ring (of the runestone) | **l'anneau** (anneau de la pierre runique) |
| the R (glyph that lights last) | **le R** |
| live connection log | **Journal de connexion** (UI), *journal en direct* dans la copie store |
| connect-time report (seconds only, nothing identifying) | *ne signale au relais que les secondes écoulées* |

### Introduction-relay modal sweep (2026-09-13)

The introducer-side modal (`referral_relayed_*`, ReferralManager.onIntroRelayed).
Hard rule in every locale: the *complete* variant must NOT say the two are now
connected — the introducer never learns that. Render "each now has what they
need to reach the other", and keep the privacy line ("you have no part in their
conversation and cannot read it") plain and literal.

| English term | fr rendering |
| --- | --- |
| Introduction accepted / complete (modal titles) | **Présentation approuvée** / **Présentation terminée** |
| connection details | **informations de connexion** |
| pass on / passed on | **transmettre** / *ont été transmises* |
| each now has what they need to reach the other | *chacun a ce qu'il faut pour joindre l'autre* |
| next time you open the app | *à la prochaine ouverture de l'appli* |

- *votre présentation à %2$s* is unambiguous (French genitive is `de`), so the
  possessive is kept rather than restructured.

### Debug-mode sweep (2026-09-14)

The opt-in anonymous diagnostic-log upload: settings row `settings_debug_mode` /
`settings_debug_mode_on` plus the consent dialog `debug_mode_title`,
`debug_mode_message`, `debug_mode_message_off`, `debug_mode_turn_on`,
`debug_mode_turn_off` (ContactListScreen.kt / ContactListView.swift, DebugMode.kt).
Hard rules in every locale: **"Debug mode" is a product term** — the settings row
and the dialog title must be byte-identical, and the on-state row is that term +
the locale's "(on)". The privacy promise in `debug_mode_message` stays **literal**:
"never include anything that identifies you or this device" followed by the five
explicit negations (names, message content, addresses, keys, inbox or contact ids).
Do not soften it to "minimal data", do not merge the five items, do not add claims.

| English term | fr rendering |
| --- | --- |
| Debug mode (row label + dialog title) | **Mode débogage** |
| Debug mode (on) | **Mode débogage (activé)** |
| diagnostic logs | **journaux de diagnostic** |
| log (noun) | **journal** (cf. `connect_log_title` *Journal de connexion*) |
| Turn on / Turn off | **Activer** / **Désactiver** |

- *Débogage* is the established French term (Android fr: *Débogage USB*).
- The colon keeps the fr files' existing plain-space convention (` :`, U+0020),
  not a narrow no-break space — verified against the 41 other ` :` in this locale.
- "identifies you or this device" → *rien qui permette de vous identifier, vous ou
  cet appareil* (avoids the ungrammatical *rien qui vous identifie, vous ou…*).

### Ratchet-refusal notice sweep (2026-09-18)

See the shared rules in the `## en` section (`conversation_ratchet_refused_body`).

| English term | fr rendering |
| --- | --- |
| secure channel | **canal sécurisé** |
| could not be established | Impossible d'établir … |
| Messages are not being sent. | Les messages ne sont pas envoyés. |
| pair again | **appairez-vous à nouveau** |

- *appairer* is the locale's pairing verb (`add_contact_cancel_pairing` « Annuler l'appairage », `contact_list_reset_relay_message` « vous appairer à nouveau »). Formal **vous** throughout.
- *canal*, not *connexion* — « vérifiez la connexion » is the relay error family.

## es — Spanish (Spain)

| concept | rendering |
| --- | --- |
| vault | caja fuerte |
| relay | relay |
| runestone | piedra rúnica |
| passphrase | frase de contraseña |
| protection level | Nivel de protección |
| burn on read | Arde al leerse |
| vouched introduction / introduce / introduced by | Presentaciones avaladas / Presentar / Presentado por %1$s |
| inbox | buzón |
| device key | clave del dispositivo |
| hardware lock | bloqueo por hardware |
| device passcode / lock screen | código / pantalla de bloqueo |
| recovery code | Código de recuperación |

- **Tiers:** Aceptable / Seguro / Máximo
- **Register:** informal **tú** ("Fíjate", "Inténtalo de nuevo"). Never "usted".
- **Quotes:** “ ”.
- **Deliberate loanwords:** **hardware** (in "bloqueo por hardware").

---

### Jargon (sweep 2026-09-03)

# es — Spanish (Spain): jargon decisions (sweep 2026-09-03)

Decisions taken while applying the 2026-09-02 jargon policy to `values-es/`
and the Spanish store copy. Fold into `docs/l10n/terms.md` § "es — Spanish
(Spain)".

**Term-sheet delta (needs a terms.md edit):** `relay` = **relay** (el relay,
los relays), NOT `relay`. Everything else in the es section of the sheet is
unchanged and was respected: caja fuerte, piedra rúnica, frase de contraseña,
Nivel de protección, Arde al leerse, Presentaciones avaladas / Presentar /
Presentado por, buzón, clave del dispositivo, bloqueo por hardware, código /
pantalla de bloqueo, Código de recuperación; tiers **Aceptable / Seguro /
Máximo**; register informal **tú** (+ **vosotros** where the sentence addresses
the user and their contact together); quotes “ ”.

### Jargon

| English term | es rendering | reason |
| --- | --- | --- |
| relay (Rún's server) | **relay** (el relay) — was `relay` | `relay` is the electromechanical relay in Spanish; it is not used for a network node, so it read as a cognate calque. `repetidor` (Apple's "Repetidor privado de iCloud", Tor Project es) *is* established, but Tor's Spanish uses it for **Tor nodes** — using it for Rún's own server would blur exactly the distinction `about_tor_intro_body` draws ("Ni siquiera el propio relay de Rún…"). `relay` is the established Spanish IT loanword ("servidor relay", "relay abierto"). Policy default = English. |
| end-to-end encryption | cifrado de extremo a extremo | established (Signal/WhatsApp/Apple es) — kept as-is |
| brute force | fuerza bruta / romper por fuerza bruta | established Spanish security term — kept as-is |
| forward secrecy | **forward secrecy** — was `secreto hacia delante` | `secreto hacia delante` is a coined calque; Spanish security writing keeps the English term (next to the untranslated "Double Ratchet" in the same bullet) |
| ratchet (lay verb: "the keys ratchet forward") | avanzar sin volver atrás — was `avanzar como un trinquete` | `trinquete` is an obscure mechanics word in es-ES (people say "carraca"); the paraphrase states the actual property. The protocol name **Double Ratchet** stays English (store bullet) |
| offline attack | ataque offline — was `ataque sin conexión` | `sin conexión` reads as "no network"; `offline` is the mainstream Spanish security loanword |
| padding | relleno (+ "bloques de datos con relleno") | `relleno` is the established Spanish crypto rendering; kept native, but rephrased so "su tamaño rellenado" (nonsense) became "ese relleno hace que su tamaño no revele nada" |
| blob | bloque (de datos) | no Spanish loanword for "blob" in consumer copy; "bloque cifrado" is transparent |
| proof of work | prueba de trabajo | well established in Spanish (Bitcoin/crypto literature, Wikipedia es) — kept |
| keychain (iOS) | llavero (del dispositivo) | Apple es-ES ships "Llavero"/"Acceso a Llaveros" — established native |
| keystore (Android) | Android Keystore | product name, kept English |
| Secure Enclave / Face ID / Touch ID | untouched | glossary |
| hardware-backed / hardware-bound | bloqueo por hardware, clave de hardware, vinculado al hardware | `hardware` is the standard es loanword; per the term sheet |
| passcode (iOS) / lock screen (Android) | código / pantalla de bloqueo | Apple es-ES uses "código"; Android es uses "pantalla de bloqueo" — anchor keys, unchanged |
| biometric | biometría / datos biométricos | established; `protection_stop_no_biometrics` reworded to "No hay biometría configurada" (the old "Faltan los datos biométricos" implied lost data) |
| wipe / crypto-erase | borrado / borrar, autoborrado; "borra las claves" | Apple/Android es use "borrar"; the crypto-erase mechanism is described, not named |
| forensic extraction / forensic tools | herramientas forenses, a prueba de forenses, ataques forenses | established Spanish ("informática forense") |
| AFU / BFU | AFU (untranslated) | acronym, no Spanish equivalent |
| push / push notification | push, notificaciones push | mainstream es (Apple/Google es use "notificaciones push") |
| endpoint | endpoint | kept English per policy ("la dirección de tu endpoint") |
| token / capability token | (not surfaced in es UI) | n/a |
| distributor (UnifiedPush) | distribuidor (app distribuidora) | UnifiedPush's own Spanish wording; the product names UnifiedPush/ntfy stay Latin |
| VAPID / Web Push / RFC 8291 | untranslated | spec names |
| root / jailbreak | acceso root / jailbreak | both kept English, as in Spanish Android/iOS security copy |
| hop (Tor) | salto | established Spanish networking term |
| onion / circuit / guard node | (not surfaced in es UI) | n/a — if they appear, keep English (`.onion`, circuito is only OK for "circuit" if Tor es is followed) |
| metadata / entropy / salt / key derivation | (not surfaced in es UI) | n/a — keep English/loanword if they appear; "clave derivada con Argon2id" already avoids naming the KDF |
| sideload | (not surfaced) | n/a |
| background (app state) | segundo plano — was `al fondo` | `en/a segundo plano` is the Android+iOS es term; "al fondo" is not a UI term |
| feed | feed — was `muro` | `muro` = Facebook "wall", a different thing; `feed` is the mainstream es loanword |
| phone home | "no envía datos a sus desarrolladores" — was `nunca llama a casa` | English idiom; the literal calque is unreadable in Spanish store copy |
| messenger (app category) | app de mensajería — was `mensajero` | `mensajero` is a courier (a person); es-ES app category is "mensajería" |
| Wi-Fi | red Wi-Fi — was `otra wifi` | Apple/Google es-ES write "Wi-Fi"; "una wifi" is loose speech |
| subpoena | reclamar por vía judicial / reclamar judicialmente | no native noun; descriptive rendering kept |
| whistleblower | denunciante | established es term |
| app switcher / recent apps | selector de apps / apps recientes | Android es wording |
| screenshot | captura (de pantalla) | established |

### Register / style notes for es
- Informal **tú** everywhere; **vosotros** only where the English addresses the
  pair ("you and your contact"): `add_contact_choice_subtitle`, `about_e2e_body`,
  `contact_list_reset_relay_message` ("volver a emparejaros").
- Avoid gendered participles for third parties whose gender is unknown:
  `referral_offer_message` now says "añadir a esa persona"; `group_notice_removed`
  keeps the impersonal "Se ha expulsado a %1$s".
- Generic masculine is kept for the *user's own* role ("Eres el administrador"),
  matching es-ES UI convention.
- Numeric suffixes must be number-invariant: `group_info_not_reachable_suffix`
  uses "aún fuera de alcance" (no adjective agreement with %1$d).

### Notification-carousel sweep (2026-09-11)

The opt-in carousel was cut to three pages + the switch; these are the renderings
used across `notif_edu_*` and `notif_edu_up_*` in this locale.

| English term | es rendering |
| --- | --- |
| wake / wake signal (contentless push) | **activación** / *señal de activación* |
| push address | **dirección push** |
| timestamps (of incoming messages) | **marcas de tiempo** |

### Connect-screen sweep (2026-09-11)

The runestone ring/`R` reveal, the live connection log and the anonymous
connect-time report (`ConnectTelemetry`) — renderings used in
`about_tor_runestone_body`, `connect_log_title` and the 1.6.17 What's New.

| English term | es rendering |
| --- | --- |
| ring (of the runestone) | **el anillo** (anillo de la piedra rúnica) |
| the R (glyph that lights last) | **la R** |
| live connection log | **Registro de conexión** (UI), *registro en directo* en la copia de tienda |
| connect-time report (seconds only, nothing identifying) | *informa al relay de los segundos que tardó* |

### Introduction-relay modal sweep (2026-09-13)

The introducer-side modal (`referral_relayed_*`, ReferralManager.onIntroRelayed).
Hard rule in every locale: the *complete* variant must NOT say the two are now
connected — the introducer never learns that. Render "each now has what they
need to reach the other", and keep the privacy line ("you have no part in their
conversation and cannot read it") plain and literal.

| English term | es rendering |
| --- | --- |
| Introduction accepted / complete (modal titles) | **Presentación aprobada** / **Presentación completada** |
| connection details | **datos de conexión** |
| pass on / passed on | **enviar** / *ya se han enviado* |
| each now has what they need to reach the other | *cada uno tiene lo que necesita para llegar al otro* |
| next time you open the app | *la próxima vez que abras la app* |

### Debug-mode sweep (2026-09-14)

The opt-in anonymous diagnostic-log upload: settings row `settings_debug_mode` /
`settings_debug_mode_on` plus the consent dialog `debug_mode_title`,
`debug_mode_message`, `debug_mode_message_off`, `debug_mode_turn_on`,
`debug_mode_turn_off` (ContactListScreen.kt / ContactListView.swift, DebugMode.kt).
Hard rules in every locale: **"Debug mode" is a product term** — the settings row
and the dialog title must be byte-identical, and the on-state row is that term +
the locale's "(on)". The privacy promise in `debug_mode_message` stays **literal**:
"never include anything that identifies you or this device" followed by the five
explicit negations (names, message content, addresses, keys, inbox or contact ids).
Do not soften it to "minimal data", do not merge the five items, do not add claims.

| English term | es rendering |
| --- | --- |
| Debug mode (row label + dialog title) | **Modo de depuración** |
| Debug mode (on) | **Modo de depuración (activado)** |
| diagnostic logs | **registros de diagnóstico** |
| log (noun) | **registro** (cf. `connect_log_title` *Registro de conexión*) |
| Turn on / Turn off | **Activar** / **Desactivar** |

- *Depuración* is the established es term (Android es: *Depuración por USB*).
- The five negations keep the *ni … ni …* series (not *sin*), mirroring the
  English repetition item-for-item.

### Ratchet-refusal notice sweep (2026-09-18)

See the shared rules in the `## en` section (`conversation_ratchet_refused_body`).

| English term | es rendering |
| --- | --- |
| secure channel | **canal seguro** |
| could not be established | No se ha podido establecer … |
| Messages are not being sent. | Los mensajes no se están enviando. |
| pair again | **vuelve a emparejarlo** |

- Transitive *vuelve a emparejarlo* (object = *el contacto*) parallels *vuelve a añadirlo* in `conversation_fs_stalled_body` and stays in the tú register. The reciprocal vosotros form *volver a emparejaros* is kept only in `contact_list_reset_relay_message`, where the subject really is the two of you.
- *canal*, not *conexión* (« Comprueba tu conexión » is the relay family).

## nb — Norwegian Bokmål

| concept | rendering |
| --- | --- |
| vault | hvelv |
| relay | relay |
| runestone | runestein |
| passphrase | passfrase |
| protection level | Beskyttelsesnivå |
| burn on read | Brenn ved lesing |
| vouched introduction / introduce / introduced by | Betrodde introduksjoner / Introduser / Introdusert av %1$s |
| inbox | innboks |
| device key | enhetsnøkkel |
| hardware lock | maskinvarelås |
| device passcode / lock screen | kode / låseskjerm |
| recovery code | Gjenopprettingskode |

- **Tiers:** God / Sikker / Maksimal
- **Register:** informal **du/din/ditt**.
- **Quotes:** « ».
- **Deliberate loanwords:** none beyond the glossary (`maskinvare`, not
  "hardware").

---

### Jargon (sweep 2026-09-03)

# nb — Norwegian Bokmål: sweep decisions 2026-09-03

Paste-ready block for `docs/l10n/terms.md` § **nb**. The existing nb concept table (hvelv / relay / runestein /
passfrase / Beskyttelsesnivå / Brenn ved lesing / Betrodde introduksjoner /
innboks / enhetsnøkkel / maskinvarelås / kode · låseskjerm /
Gjenopprettingskode), the tiers **God / Sikker / Maksimal**, the informal
**du/din/ditt** register and the **« »** quote style are unchanged and were
confirmed correct across all 11 areas + the store copy.

### Jargon

Per the 2026-09-02 project policy: a technical/security term stays **English or
the loanword mainstream Norwegian security/OS localizations already use**,
unless Norwegian has a well-established native term. Never a literal calque.

| English term | nb rendering | reason |
| --- | --- | --- |
| brute force | **brute force** (as a noun phrase: *knekkes med brute force*, *står imot brute force*) | Established Norwegian loanword in security writing; no native term. `knekke` alone (the previous rendering) is the right verb for *crack* but silently dropped the named technique. Never *rå kraft* / *råstyrke*. |
| end-to-end encryption | **ende-til-ende-kryptering / ende-til-ende-kryptert** | Established native (Apple/Google/Signal nb). Note the **full hyphen chain** — `about_e2e_title` had *Ende-til-ende kryptert*, now fixed. |
| forward secrecy | **forward secrecy** | No established Norwegian term; kept English in the store copy feature list. |
| Double Ratchet / ratchet | **Double Ratchet** (product name, English); the metaphor verb is *nøkkelen skrus videre* | No Norwegian term for the ratchet primitive. English source uses "ratchets forward" as a lay metaphor; *skrus videre* keeps it and matches the store copy. (Was the reflexive *skrur nøkkelen seg videre* — unidiomatic.) |
| relay | **relay / relayet** | Frozen in the term sheet; established Norwegian loanword and what Tor's own nb strings use. |
| onion / circuit / guard node / exit node | *(no occurrences in nb strings)* — would stay **onion**, **krets**, **guard node**, **exit node** | Only *krets* has an established native form. |
| hardware-backed / hardware-bound | **maskinvarebasert / maskinvarebundet**, *maskinvarelås*, *maskinvarenøkkel*, *sikkerhetsbrikke* | *maskinvare* is the standard native Norwegian word; not a calque. |
| keystore | **Android Keystore** | Product name, English, uninflected. |
| keychain | **nøkkelring (på enheten)** | Apple's own nb term ("Nøkkelring i iCloud"). |
| passcode (phone) | **kode** (*kode på enheten*) | iOS nb uses "Kode". Anchor key `protection_device_lock_term_ios`. |
| lock screen | **låseskjerm** | Android nb standard. Anchor key `protection_device_lock_term_android`. |
| passphrase (Rún's own) | **passfrase** | Frozen; deliberately distinct from *kode* (the phone's). |
| biometric(s) | **biometri / biometrisk** | Established native. |
| wipe / self-wipe / crypto-erase | **slette / sletting**, *selvsletting*, *sletter selve nøklene* | Established native ("Slett alle data" in Android nb). |
| forensic tools / forensic extraction | **etterforskningsverktøy**; *dataetterforskning* (title); *beslaglagt telefon* | Native and understood; *forensisk* would be an unnecessary Latinism here. |
| offline attack | **offline-angrep** | *offline* is the established Norwegian loanword. Replaced the vague paraphrase *angrep utenfor enheten* in both store descriptions. |
| AFU / BFU | **AFU** (unexpanded) | Initialism, no Norwegian expansion. |
| proxy | *(no occurrences)* — would stay **proxy** | Loanword. |
| push | **push** (*push-varsel*, *push-server*, *push-serverne til Apple*) | Established Norwegian loanword; hyphenated compounds. |
| token / endpoint | **endepunkt(adresse)** (token has no occurrence) | *endepunkt* is established in Norwegian IT (Microsoft nb docs). |
| proof of work | **proof-of-work** | No Norwegian term; English, hyphenated as in the source. |
| jailbreak / root | **jailbreaket / rootet** | Established loanverbs in Norwegian tech usage. |
| rate limit / entropy / salt / KDF / sideload / metadata | *(no occurrences in nb)* — would stay **rate limit**, **entropi**, **salt**, **KDF**, **sideloade**, **metadata** | *entropi* and *metadata* are native; the rest are loanwords. |
| padding | **padding** (*datablokker med padding*, *fylles opp til faste størrelser med padding*, bullet: *Padding skjuler …*) | Policy-listed term; the previous *polstret / polstring / Meldingspolstring* is a literal calque ("upholstered") that no Norwegian technical text uses. |
| cloud backup | **sikkerhetskopi(er) i skyen** | Native and factually right; the previous *skylagring* means *cloud storage*, a different thing. |
| crash reporting | **krasjrapportering** | Established native. |
| phone home | **sende data hjem til oss** | *ringe hjem* is a dead calque in Norwegian — it only means placing a phone call. |
| VAPID / Web Push / RFC 8291 / UnifiedPush / ntfy / F-Droid | English, unchanged | Protocol/product names. |

### Pairing — lexical change (affects 9 strings + 1 comment)

**pair (verb) → `parkoble`; pairing (noun) → `parkobling`; re-pair →
`parkoble på nytt`.** The old *pare / paring / Par på nytt* is the wrong
register in Norwegian: transitive *pare* is used for objects (socks, gloves)
and *pare (seg) med* reads as animal mating, which is how
*"alle du har paret med"* landed. `parkoble/parkobling` is the established
Norwegian term for device pairing and matches Swedish `parkoppla`, Danish
`parre`, German `koppeln` in the sibling locales. Keys:
`contact_list_repair_required`, `contact_list_repair_chip`,
`contact_list_repair_banner` (both quantities), `contact_list_reset_relay_message`,
`group_info_no_verified_pairing`, `group_info_add_member_precondition`,
`group_info_add_member_empty`, `create_group_precondition`.

### Register / style notes added by this sweep

- **`intet` → `ikke noe`** in the store copy (×4 across the two full
  descriptions). *intet* is literary-archaic Bokmål and clashed with the
  locale's informal *du*.
- **"leave a group" is `forlate gruppen`, never `gå ut`.** *gå ut* is reserved
  for leaving a *conversation* (e.g. `burn_notice_message`), where the English
  source itself is informal.
- **`out of the box` → `fra start`**, never *rett ut av boksen* (calque).
- **`vouched introduction` is `betrodd introduksjon`** in the store copy too —
  the bullet used to paraphrase it as *introduksjoner fra folk du stoler på*,
  breaking the frozen term.
- **App Store subtitle/keywords (`no:` lines):** subtitle is
  `Privat meldingsapp via Tor` (26/30) — *messenger* is not a Norwegian noun and
  the UI already says *meldingsapp*. `meldingsapp` was added to the keyword line
  (90/100) while *privat messenger* stays for search coverage.

### Notification-carousel sweep (2026-09-11)

The opt-in carousel was cut to three pages + the switch; these are the renderings
used across `notif_edu_*` and `notif_edu_up_*` in this locale.

| English term | nb rendering |
| --- | --- |
| wake / wake signal (contentless push) | **vekkesignal** |
| distributor (UnifiedPush) | **distributørappen** |
| push address | **push-adresse** |
| timestamps (of incoming messages) | **tidspunktene** |

- **`relay` sweep 2026-09-11:** the locale was split ~50/50 between `relé/reléet`
  and the term-sheet form `relay/relayet`. All 20 remaining `relé*` occurrences in
  `values-nb/*.xml` and both nb store descriptions were changed to `relay/relayet`
  (`relétilgang` → `relaytilgang`). The term sheet form is now the only one in the locale.

### Connect-screen sweep (2026-09-11)

The runestone ring/`R` reveal, the live connection log and the anonymous
connect-time report (`ConnectTelemetry`) — renderings used in
`about_tor_runestone_body`, `connect_log_title` and the 1.6.17 What's New.

| English term | nb rendering |
| --- | --- |
| ring (of the runestone) | **ringen** (runesteinens ring) |
| the R (glyph that lights last) | **R-en** |
| live connection log | **Tilkoblingslogg** (UI), *live tilkoblingslogg* i butikkteksten |
| connect-time report (seconds only, nothing identifying) | *melder til relayet hvor mange sekunder det tok* |

### Introduction-relay modal sweep (2026-09-13)

The introducer-side modal (`referral_relayed_*`, ReferralManager.onIntroRelayed).
Hard rule in every locale: the *complete* variant must NOT say the two are now
connected — the introducer never learns that. Render "each now has what they
need to reach the other", and keep the privacy line ("you have no part in their
conversation and cannot read it") plain and literal.

| English term | nb rendering |
| --- | --- |
| Introduction accepted / complete (modal titles) | **Introduksjon godkjent** / **Introduksjon fullført** |
| connection details | **tilkoblingsdetaljene** (2nd mention: *detaljene*) |
| pass on / passed on | **sende videre** / *er sendt videre* |
| each now has what they need to reach the other | *hver av dem har det som skal til for å nå den andre* |
| next time you open the app | *neste gang du åpner appen* |

- **Do not write** *introduksjonen din til %2$s*: Norwegian `til` is also the
  possessive (*boka til Per*), so it reads as "%2$s's introduction". Use the
  clause **at du introduserer vedkommende for %2$s** — *vedkommende* is also the
  locale's gender-neutral third-person reference (already in `referral_offer_message`).

### Debug-mode sweep (2026-09-14)

The opt-in anonymous diagnostic-log upload: settings row `settings_debug_mode` /
`settings_debug_mode_on` plus the consent dialog `debug_mode_title`,
`debug_mode_message`, `debug_mode_message_off`, `debug_mode_turn_on`,
`debug_mode_turn_off` (ContactListScreen.kt / ContactListView.swift, DebugMode.kt).
Hard rules in every locale: **"Debug mode" is a product term** — the settings row
and the dialog title must be byte-identical, and the on-state row is that term +
the locale's "(on)". The privacy promise in `debug_mode_message` stays **literal**:
"never include anything that identifies you or this device" followed by the five
explicit negations (names, message content, addresses, keys, inbox or contact ids).
Do not soften it to "minimal data", do not merge the five items, do not add claims.

| English term | nb rendering |
| --- | --- |
| Debug mode (row label + dialog title) | **Feilsøkingsmodus** (masc.: *Slå den av*) |
| Debug mode (on) | **Feilsøkingsmodus (på)** |
| diagnostic logs | **diagnoselogger** |
| log (noun) | **logg** (cf. `connect_log_title` *Tilkoblingslogg*) |
| Turn on / Turn off | **Slå på** / **Slå av** |

- *Feilsøking* is the established nb term (Android nb: *USB-feilsøking*).
- "ids" → **ID-er** (*innboks- eller kontakt-ID-er*).
- `modus` is masculine, so the off-prompt is *Slå **den** av*, never *det*.

### Ratchet-refusal notice sweep (2026-09-18)

See the shared rules in the `## en` section (`conversation_ratchet_refused_body`).

| English term | nb rendering |
| --- | --- |
| secure channel | **sikker kanal** |
| could not be established | Kunne ikke opprette … |
| Messages are not being sent. | Meldinger blir ikke sendt. |
| pair again | **parkoble på nytt** |

- *parkoble på nytt* matches `contact_list_reset_relay_message`; the noun is *parkobling* (`add_contact_cancel_pairing`).
- *kanal*, not *tilkobling/forbindelse* (the relay-connection family).

## da — Danish

| concept | rendering |
| --- | --- |
| vault | boks |
| relay | relæ |
| runestone | runesten |
| passphrase | adgangssætning |
| protection level | Beskyttelsesniveau |
| burn on read | Brænd efter læsning |
| vouched introduction / introduce / introduced by | Betroede introduktioner / Introducér / Introduceret af %1$s |
| inbox | indbakke |
| device key | enhedsnøgle |
| hardware lock | hardwarelås |
| device passcode / lock screen | adgangskode / skærmlås |
| recovery code | Gendannelseskode |

- **Tiers:** God / Sikker / Maksimal
- **Register:** informal **du/din/dit**.
- **Quotes:** “ ”.
- **Deliberate loanwords:** **hardware** (in "hardwarelås").
- Note the deliberate split: `adgangssætning` = passphrase (Rún's own long
  credential), `adgangskode` = the phone's own passcode. Do not swap them.

---

### Jargon (sweep 2026-09-03)

# da — Danish jargon decisions (locale sweep 2026-09-03)

Register: informal **du/din/dit**. Plural **I/jer** only where the English "you"
genuinely means both parties (you + your contact), e.g. `about_contacts_body`
"I mødes ansigt til ansigt". Quotes: “ ”. Tiers (frozen): God / Sikker / Maksimal.

### Jargon

| English term | da rendering | reason |
| --- | --- | --- |
| brute force | **brute force** (`knækkes med brute force`, `forensisk brute force`) | Policy: stays English. Danish security press/vendors use the English term; a calque ("rå kraft", "råstyrke") is not used by anyone. Replaced the vague native paraphrase "kan brydes"/"kan gætte den". |
| cracked (a code) | **knækket** | "at knække en kode" is *the* Danish collocation; native and established. Not jargon-English. |
| end-to-end encryption | **end-to-end-kryptering** | Well-established in Danish (Apple, WhatsApp, Signal da). Hyphenated per Danish compound rules. |
| forward secrecy | **forward secrecy** | No established Danish term; kept English in the store feature list next to "Double Ratchet". |
| ratchet (Double Ratchet) | product name **Double Ratchet** kept; the mechanism described as "nøglerne drejer fremad" | No Danish verb exists; "skralde/spærrehjul" would be opaque to users. Plain-language paraphrase for prose, English for the protocol name. |
| relay | **relæ / relæet** (Rún's own: **Rún-relæet**) | Term sheet. Native, established Danish for a relay station; not a calque. Never "Rúns relæ" — Rún is never inflected. |
| onion / .onion | **onion** (unchanged) | Glossary-adjacent product term; not currently in Danish UI copy. |
| circuit (Tor) | **kredsløb** *(if needed — not currently in the copy)* | Tor Browser's own Danish localization uses "kredsløb" ("Nyt kredsløb for dette websted") ⇒ established native term. |
| guard / exit node | **guard node / exit node** *(if needed — not in the copy)* | No settled Danish rendering; keep English. |
| hardware-backed / hardware key / hardware lock | **hardwarebundet / hardwarenøgle / hardwarelås** | "hardware" is the established Danish loan stem (term sheet: hardwarelås). Never "maskinel"/"maskinvare-" in da (that is nb/sv usage). |
| keystore | **Android Keystore** | Product name, English (Google's own Danish docs keep it). |
| keychain | **nøglering** ("enhedens nøglering") | Apple's Danish is "Nøglering" / "iCloud Nøglering" ⇒ established native term, so the native form wins over the English. |
| passcode (the phone's) | **adgangskode** | Apple da. Term sheet keeps it distinct from `adgangssætning` (Rún's passphrase). |
| passphrase (Rún's) | **adgangssætning** | Term sheet coinage; deliberately not "adgangskode". |
| PIN | **PIN** standalone; **PIN-kode** in compounds | Glossary: PIN stays Latin and uninflected. Fixed the fused lowercase "pinkode", which buried the glossary term; "PIN-kode" is Apple's and Google's Danish spelling. |
| biometric / biometrics | **biometri / biometrisk** | Established Danish (Apple, Android da). |
| wipe / self-wipe | **slette alt / sletning / selvsletning** | Apple da ("Slet alt indhold og indstillinger") and Android da ("Slet alle data") ⇒ established native term; English "wipe" would read as untranslated. |
| crypto-erase | described: "en sletning ødelægger selve nøglerne" | No Danish term; the mechanism is spelled out, as in the English source. |
| forensic (tools / attacks) | **forensisk / forensiske værktøjer** | Established Danish IT-security loan-adjective. "Kriminalteknisk" is police-lab specific and would narrow the claim. `about_forensic_title` keeps the free rendering "Sikker ved beslaglæggelse" (headline). |
| AFU / BFU | **AFU** (unchanged) | Acronym, no Danish expansion in use. |
| proxy | **proxy** *(not in the copy)* | Established English loan in Danish. |
| push | **push** ("push-notifikationer", "pushserver", "pushtjeneste", "pushet") | Established Danish loan; Apple/Google da both use "push". |
| token | **token** *(not in the copy)* | Established English loan. |
| endpoint | **endpoint** ("din endpoint-adresse") | UnifiedPush/Web Push term; no Danish equivalent in use. |
| proof of work | **proof-of-work** | Policy: stays English; no Danish rendering exists. |
| jailbreak / root | **jailbreaket / rootet** | Established Danish loan participles; a native calque would be unintelligible. |
| rate limit | **rate limit** *(not in the copy)* | Stays English. |
| entropy | **entropi** *(not in the copy)* | Established Danish scientific term. |
| salt | **salt** *(not in the copy)* | Same word; stays. |
| key derivation | "en nøgle udledt med Argon2id" | "udlede" is the standard Danish math/crypto verb; native and unambiguous. |
| padding | **padding** ("fyldt op med padding", "får padding til faste størrelser", "Padding skjuler…") | Policy: stays English/loanword. Fixed "polstret/polstrede/polstring", a literal calque that reads as *upholstered*. |
| metadata | **metadata** | Identical in Danish. |
| sideload | **sideloade** *(not in the copy)* | Established Danish loan verb. |
| data at rest | **gemte data / "ligger krypteret"** | "data i hvile" is an unidiomatic calque; Danish states it plainly. Meaning (at-rest vs in-transit) preserved by context (SQLCipher, seized phone). |
| on the wire | **i trafikken** | "på nettet" means *online* and lost the wire-level claim. |
| cloud backup | **sikkerhedskopi i skyen** | Apple da uses "sikkerhedskopi" + "skyen"; the coined compound "skysikkerhedskopi" is not idiomatic. |
| crash reporting | **nedbrudsrapportering** | Google Play's Danish uses "nedbrudsrapporter". |
| security chip (Secure Enclave analogue) | **sikkerhedschip**; **Secure Enclave** kept verbatim | Glossary keeps the Apple product name; the generic Android wording is native. |
| distributor (UnifiedPush) | **distributør / distributørapp** | UnifiedPush's own terminology; no better Danish term. |
| in person (pairing) | **ansigt til ansigt** | Chosen over "personligt"; also avoids "parre sig med", which in Danish reads as *mating*. Now uniform across groups/contact-list/store copy. |
| messenger | **beskedapp** in all prose and in the App Store subtitle; **messenger** kept only in the ASC keyword line | "messenger" in Danish reads as Meta's Messenger and is an English leak, not a glossary term; "beskedapp" matches the app's own body copy and the sibling sv/nb subtitles. Keywords keep "privat messenger" purely as an ASO search term. |

### Notification-carousel sweep (2026-09-11)

The opt-in carousel was cut to three pages + the switch; these are the renderings
used across `notif_edu_*` and `notif_edu_up_*` in this locale.

| English term | da rendering |
| --- | --- |
| wake / wake signal (contentless push) | **vækning** / **vækkesignal** |
| push address | **push-adresse** |
| timestamps (of incoming messages) | **tidsstempler** |

### Connect-screen sweep (2026-09-11)

The runestone ring/`R` reveal, the live connection log and the anonymous
connect-time report (`ConnectTelemetry`) — renderings used in
`about_tor_runestone_body`, `connect_log_title` and the 1.6.17 What's New.

| English term | da rendering |
| --- | --- |
| ring (of the runestone) | **ringen** (runestenens ring) |
| the R (glyph that lights last) | **R'et** |
| live connection log | **Forbindelseslog** (UI), *live forbindelseslog* i butikstekst |
| connect-time report (seconds only, nothing identifying) | *melder kun antal sekunder til relæet* |

### Introduction-relay modal sweep (2026-09-13)

The introducer-side modal (`referral_relayed_*`, ReferralManager.onIntroRelayed).
Hard rule in every locale: the *complete* variant must NOT say the two are now
connected — the introducer never learns that. Render "each now has what they
need to reach the other", and keep the privacy line ("you have no part in their
conversation and cannot read it") plain and literal.

| English term | da rendering |
| --- | --- |
| Introduction accepted / complete (modal titles) | **Introduktion godkendt** / **Introduktion fuldført** |
| connection details | **forbindelsesoplysningerne** (2nd mention: *oplysningerne*) |
| pass on / passed on | **sende videre** / *er sendt videre* |
| each now has what they need to reach the other | *de har hver især det, der skal til for at nå hinanden* |
| next time you open the app | *næste gang du åbner appen* |

- Same `til`-possessive trap as nb: use **at du introducerer vedkommende for
  %2$s**, not *din introduktion til %2$s*.

### Debug-mode sweep (2026-09-14)

The opt-in anonymous diagnostic-log upload: settings row `settings_debug_mode` /
`settings_debug_mode_on` plus the consent dialog `debug_mode_title`,
`debug_mode_message`, `debug_mode_message_off`, `debug_mode_turn_on`,
`debug_mode_turn_off` (ContactListScreen.kt / ContactListView.swift, DebugMode.kt).
Hard rules in every locale: **"Debug mode" is a product term** — the settings row
and the dialog title must be byte-identical, and the on-state row is that term +
the locale's "(on)". The privacy promise in `debug_mode_message` stays **literal**:
"never include anything that identifies you or this device" followed by the five
explicit negations (names, message content, addresses, keys, inbox or contact ids).
Do not soften it to "minimal data", do not merge the five items, do not add claims.

| English term | da rendering |
| --- | --- |
| Debug mode (row label + dialog title) | **Fejlfindingstilstand** (common gender: *Slå den fra*) |
| Debug mode (on) | **Fejlfindingstilstand (til)** |
| diagnostic logs | **diagnoselogge** |
| log (noun) | **log** (cf. `connect_log_title` *Forbindelseslog*) |
| Turn on / Turn off | **Slå til** / **Slå fra** |

- *Fejlfinding* is the established da term (Android da: *USB-fejlfinding*).
- "ids" → **id'er** (the apostrophe is correct Danish; `apply` escapes it to \').
- `tilstand` is common gender, so the off-prompt is *Slå **den** fra*.

### Ratchet-refusal notice sweep (2026-09-18)

See the shared rules in the `## en` section (`conversation_ratchet_refused_body`).

| English term | da rendering |
| --- | --- |
| secure channel | **sikker kanal** |
| could not be established | Der kunne ikke oprettes … |
| Messages are not being sent. | Beskeder bliver ikke sendt. |
| pair again | **par jer igen** |

- Imperative *par jer igen* is the imperative of the established *parre jer igen* (`contact_list_reset_relay_message`); the noun is *parring* (`add_contact_cancel_pairing`).
- House comma before *og* between two main clauses is kept (*Fjern kontakten, og par jer igen.*), as in *Tjek din forbindelse, og prøv igen.*
- *kanal*, not *forbindelse* — *forbindelse* is the relay connection.

## fi — Finnish

| concept | rendering |
| --- | --- |
| vault | holvi |
| relay | välityspalvelin |
| runestone | riimukivi |
| passphrase | salalause |
| protection level | Suojaustaso |
| burn on read | Palaa luettaessa |
| vouched introduction / introduce / introduced by | Taatut esittelyt / Esittele / %1$s esitteli |
| inbox | postilaatikko |
| device key | laiteavain |
| hardware lock | laitteistolukitus |
| device passcode / lock screen | pääsykoodi / näytön lukitus |
| recovery code | Palautuskoodi |

- **Tiers:** Perus / Turva / Maksimi
- **Register:** informal second person singular (**sinä**-form, usually only
  visible as the verb ending and the possessive suffix).
- **Quotes:** ” ” (Finnish uses the same closing mark on both sides).
- **Deliberate loanwords:** none beyond the glossary. `välityspalvelin` is the
  agreed native rendering of "relay"; do not switch to "rele" or "relay".
- "Introduced by %1$s" is re-ordered to the natural **`%1$s esitteli`**; keep
  that word order.

---

### Jargon (sweep 2026-09-03)

# fi (Finnish) — jargon decisions, locale sweep 2026-09-03

Policy applied: technical/security terms stay ENGLISH or the loanword mainstream
Finnish security/consumer apps already use, UNLESS Finnish has a well-established
native term (Signal / WhatsApp / Apple / Google fi). Never a literal calque.
Register: **sinä** (informal 2nd person singular). Quotes: ” ”.
Glossary terms (Rún, Tor, PIN, QR, Face ID, Touch ID, Secure Enclave, SQLCipher,
FCM, APNs, UnifiedPush, ntfy, Argon2, Orbot, Monero, Bitcoin) stay Latin and are
never given a Finnish case ending directly — use a compound
(`Rún-sovelluksen`, `Tor-verkossa`, `Secure Enclave -piiriin`) or a colon
(`Face ID:n`, `Argon2id:llä`, `%1$s:lle`).

### Jargon

| English term | fi rendering | reason |
| --- | --- | --- |
| brute force | **brute force** (+ Finnish head noun: `brute force -hyökkäys/-hyökkäyksellä`) | Finnish security writing keeps the English term; `raaka voima` is a forbidden calque and `väsytyshyökkäys` is CERT-register, not consumer app. Matches sv "med brute force", de "per Brute Force". Was silently dropped ("murtaa" alone) in all three tier taglines — restored. |
| end-to-end encryption | **päästä päähän -salaus** / `päästä päähän -salattu`; adverbially `salataan päästä päähän` (no hyphen) | Established (Signal/WhatsApp fi). The linking hyphen before the head word is mandatory when the phrase is attributive — was missing in `about_e2e_title`, `eula_body` ×2, `play-short-fi`. |
| forward secrecy | **forward secrecy** (store copy) | No established Finnish consumer term; kept English exactly as sv/de/nb/da do. |
| ratchet (verb) | **avain kiertyy eteenpäin** | Descriptive, not a calque; Finnish has no consumer noun for the mechanism. The product name **Double Ratchet** stays English in the store bullet. |
| relay | **välityspalvelin** | Term-sheet decision, native and established. Never "rele"/"relay". |
| onion / circuit / hop | `Tor-verkko`, `solmu` (hop) | Only "hops" surfaces in the copy (`useiden solmujen läpi`); onion/circuit never surface. If needed: keep `onion`, use `Tor-piiri` for circuit. |
| guard / exit node | (not in the corpus) | If ever needed: `guard-solmu` / `exit-solmu` — English prefix + native head, like `push-palvelin`. |
| hardware-backed / hardware key / hardware lock | **laitteistoavain**, **laitteistolukitus**, `laitteistoon sidottu`, `laitteistosuojaus`; device key = **laiteavain** | Native and established in Android fi ("laitteistopohjainen"). Term-sheet renderings; the `laiteavain` (device key) vs `laitteistoavain` (hardware key) split is deliberate — do not merge. |
| keystore | **Android Keystore** (product name; takes a Finnish ending: `Android Keystoressa`) | Product name, not translated; not a protected glossary term, and Finnish inflects product names normally. |
| keychain (Apple) | **avainnippu** (`laitteen avainnippu`) | Apple's own Finnish localization uses "Avainnippu" — established native term. |
| passcode (device) | **pääsykoodi** | Apple fi uses "pääsykoodi". Anchor key `protection_device_lock_term_ios`. |
| lock screen | **näytön lukitus** | Android fi. Anchor key `protection_device_lock_term_android`. |
| passphrase | **salalause** (Rún's own credential) vs **salasana** = password | Term sheet; the one "password" in the corpus (`protection_forced_explainer_cta_body_android`) stays `salasana`. |
| biometric | **biometrinen tunnistus** / `biometrinen` | Established (Apple/Android fi). Fixed `protection_stop_no_biometrics`: bare noun "Biometriikka" → "Biometristä tunnistusta ei ole käytettävissä." |
| wipe / self-wipe / self-destruct | **pyyhkiä**, **pyyhintä**, **itsepyyhintä**, **itsetuho** | "Pyyhkiä" is the established Finnish verb for a remote/device wipe. |
| crypto-erase | (expressed, not named) `pyyhintä tuhoaa itse salausavaimet` | No Finnish term exists; the English source also explains rather than names it. |
| forensic extraction / forensic tools | **forensinen**, **forensiikka** (`forensiset työkalut`, `Forensiikan kestävä`) | "Forensiikka" is the established Finnish IT-security loan; "rikostekninen" is police-lab register and would read wrong. |
| at rest | **levossa** / `levossa oleva data` | Standard Finnish security phrasing. **Never `lepotila`** — that means device sleep mode; it was a real mistranslation in `gate_passcode_warning_message`, now fixed. |
| offline attack | **offline-hyökkäys** | Loan prefix + native head, standard Finnish compounding. |
| AFU / BFU | **AFU** (as-is) | Initialism with no Finnish equivalent; kept in `protection_device_panel_baseline_label`. |
| proxy | (not in the corpus) | Covered by `välityspalvelin`; if a real proxy is ever named, keep `proxy`. |
| push | **push-** as a loan prefix: `push-ilmoitus`, `push-palvelin`, `push-viesti`, `Push-ilmoitukset` | Universal in Finnish app copy; no native alternative is used by anyone. |
| distributor (UnifiedPush) | **välittäjäsovellus** / `ilmoitusten välittäjäsovellus` | No established Finnish term for the UnifiedPush role; a transparent native compound beats an opaque loan here. Consistent across all 8 UP strings. |
| endpoint | **päätepiste** (`päätepisteosoite`) | "Päätepiste" is the established Finnish IT-localization term (Microsoft/Google fi) — the well-established-native-term exception. |
| token | (not in the corpus) | If needed, keep `token`. |
| proof of work | **proof-of-work** (`Ratkaistaan proof-of-work-tehtävää…`) | Kept English exactly as sv/nb/da ("proof-of-work") and de ("Proof-of-Work"). Replaced the previous calque **työtodiste**, which is both a calque and a near-collision with `työtodistus` = *employment certificate*. |
| jailbreak / root | **jailbreakattu** / **rootattu** | Established Finnish loan verbs; no native alternative in use. |
| rate limit / entropy / salt / KDF | (not surfaced) | Key derivation appears only as `sen avain johdetaan Argon2id:llä` — native verb, term intact. |
| padding | **täyte** / `viestit täytetään` / `täytetty koko` | Native and standard for message padding in Finnish. |
| metadata | (not surfaced) | The copy names the concrete facts instead (`aikaleimat`, `ajoitusprofiili`), as the English does. |
| sideload | (not surfaced) | If needed, keep `sideload`. |
| blob | **datamöykky / möykky** | Deliberately informal, mirroring the English "blobs"; consistent between UI (`about_relay_body`) and both store descriptions. |
| scan (a QR code) | **lukea** (`Lue koodi`, `QR-koodien lukemiseen`) | "Lukea" is established for QR in Finnish ("QR-koodinlukija"); kept over "skannata" for internal consistency — all 6 occurrences use it. |
| security chip / Secure Enclave | **turvasiru** (generic, Android side) / **Secure Enclave** (Apple; `Secure Enclave -piiriin` when a case ending is needed) | Glossary term may not take a bare Finnish ending — `Secure Enclaveen` was a glossary violation in the App Store copy. |
| crash reporting | **kaatumisraportit** | Native, established. |
| tip (tip jar) | **tippi** | Colloquial loan, universally understood, matches the friendly register of the tip jar. "Juomaraha" would read as restaurant gratuity. |
| phones home | **soittaa kotiin** (`Rún ei koskaan soita kotiin.`) | KEPT: a recognized Finnish IT calque with the same jocular register as the English, and both store descriptions sit within ~30 chars of the 4000 limit. Flagged as a judgment call, not a defect. |

### Notification-carousel sweep (2026-09-11)

The opt-in carousel was cut to three pages + the switch; these are the renderings
used across `notif_edu_*` and `notif_edu_up_*` in this locale.

| English term | fi rendering |
| --- | --- |
| wake / wake signal (contentless push) | **herätys** / **herätesignaali** |
| push address | **push-osoite** |
| timestamps (of incoming messages) | **aikaleimat** |

### Connect-screen sweep (2026-09-11)

The runestone ring/`R` reveal, the live connection log and the anonymous
connect-time report (`ConnectTelemetry`) — renderings used in
`about_tor_runestone_body`, `connect_log_title` and the 1.6.17 What's New.

| English term | fi rendering |
| --- | --- |
| ring (of the runestone) | **rengas** (riimukiven rengas) |
| the R (glyph that lights last) | **R-kirjain** (ei paljas R) |
| live connection log | **Yhteysloki** |
| connect-time report (seconds only, nothing identifying) | *kertoo välityspalvelimelle vain kuluneet sekunnit* |

### Introduction-relay modal sweep (2026-09-13)

The introducer-side modal (`referral_relayed_*`, ReferralManager.onIntroRelayed).
Hard rule in every locale: the *complete* variant must NOT say the two are now
connected — the introducer never learns that. Render "each now has what they
need to reach the other", and keep the privacy line ("you have no part in their
conversation and cannot read it") plain and literal.

| English term | fi rendering |
| --- | --- |
| Introduction accepted / complete (modal titles) | **Esittely hyväksytty** / **Esittely valmis** |
| connection details | **yhteyden muodostamiseen tarvittavat tiedot** (2nd mention: *tiedot*) |
| pass on / passed on | **välittää eteenpäin** / *on välitetty eteenpäin* |
| each now has what they need to reach the other | *kummallakin on se, mitä toisen tavoittamiseen tarvitaan* |
| next time you open the app | *kun seuraavan kerran avaat sovelluksen* |

- **Never `yhteystiedot`** for *connection details* — in Finnish that is a
  person's contact information (phone/e-mail), which Rún does not have.
- The recipient of an introduction takes the allative: *esittelysi henkilölle %2$s*.

### Debug-mode sweep (2026-09-14)

The opt-in anonymous diagnostic-log upload: settings row `settings_debug_mode` /
`settings_debug_mode_on` plus the consent dialog `debug_mode_title`,
`debug_mode_message`, `debug_mode_message_off`, `debug_mode_turn_on`,
`debug_mode_turn_off` (ContactListScreen.kt / ContactListView.swift, DebugMode.kt).
Hard rules in every locale: **"Debug mode" is a product term** — the settings row
and the dialog title must be byte-identical, and the on-state row is that term +
the locale's "(on)". The privacy promise in `debug_mode_message` stays **literal**:
"never include anything that identifies you or this device" followed by the five
explicit negations (names, message content, addresses, keys, inbox or contact ids).
Do not soften it to "minimal data", do not merge the five items, do not add claims.

| English term | fi rendering |
| --- | --- |
| Debug mode (row label + dialog title) | **Virheenkorjaustila** |
| Debug mode (on) | **Virheenkorjaustila (käytössä)** |
| diagnostic logs | **diagnostiikkalokit** (part. pl. *diagnostiikkalokeja*) |
| log (noun) | **loki** (cf. `connect_log_title` *Yhteysloki*) |
| Turn on / Turn off | **Ota käyttöön** / **Poista käytöstä** |

- *Virheenkorjaus* is Google's fi term for debugging (*USB-virheenkorjaus*).
- The on-state row says **(käytössä)** — not *(päällä)* — so the row, the
  off-prompt (*on käytössä… Poista se käytöstä*) and the buttons share one
  lexical family.
- *anonyymeja* (back harmony: *anonyymi* contains a/o), not *anonyymejä*.
- "ids" → **-tunnus** (*postilaatikko- tai kontaktitunnuksia*).

### Ratchet-refusal notice sweep (2026-09-18)

See the shared rules in the `## en` section (`conversation_ratchet_refused_body`).

| English term | fi rendering |
| --- | --- |
| secure channel | **suojattu kanava** |
| could not be established | … ei voitu muodostaa |
| Messages are not being sent. | Viestejä ei lähetetä. |
| pair again | **tee paritus uudelleen** |

- *paritus* is the locale's pairing noun (`add_contact_cancel_pairing` *Peru paritus*, `contact_list_reset_relay_message` *tehdä paritus uudelleen*).
- *kanava*, not *yhteys* — *yhteys* is the relay connection. Partitive under negation: *Suojattua kanavaa ei voitu muodostaa*, *Viestejä ei lähetetä*.

## ar — Arabic

| concept | rendering |
| --- | --- |
| vault | خزنة |
| relay | مُرحّل |
| runestone | حجر الرونات |
| passphrase | عبارة المرور |
| protection level | مستوى الحماية |
| burn on read | الحرق عند القراءة |
| vouched introduction / introduce / introduced by | تقديمات بالتزكية / تقديم / قدّمه %1$s |
| inbox | صندوق الوارد |
| device key | مفتاح الجهاز |
| hardware lock | قفل العتاد |
| device passcode / lock screen | رمز دخول / قفل شاشة |
| recovery code | رمز الاسترداد |

- **Tiers:** جيد / آمن / الحد الأقصى
- **Register:** Modern Standard Arabic, addressing the user in the **2nd person
  masculine singular** (the unmarked form). Do not introduce feminine or dual
  forms — the app has no gender signal.
- **Quotes:** « ».
- **Deliberate loanwords:** none beyond the glossary; the glossary terms stay
  Latin, and Arabic clitics may attach directly ("وRún") — the validator allows it.
- RTL locale: mirrored-UI rules live with `DirectionalGlyphs.kt` and the
  forced-LTR PIN keypad/slider, not here.

---

### Jargon (sweep 2026-09-03)

# ar (Arabic) — jargon decisions, sweep of 2026-09-03

Policy applied (project policy, 2026-09-02): technical/security terms take the
rendering mainstream Arabic security-app localizations use (Signal / WhatsApp /
Apple / Google / Tor Project ar). Established Arabic term where one exists;
otherwise keep the English term in Latin script. **Never a literal calque.**

Glossary names (`Rún`, `Tor`, `PIN`, `QR`, `Face ID`, `Touch ID`,
`Secure Enclave`, `SQLCipher`, `Monero`, `Bitcoin`, `FCM`, `APNs`,
`UnifiedPush`, `ntfy`, `Orbot`, `Argon2`) stay Latin and uninflected. Arabic
clitics may attach directly (`وRún`, `بـ Tor`).

### Jargon

| English term | ar rendering | reason |
| --- | --- | --- |
| end-to-end encryption | التشفير من طرف إلى طرف / مشفّر من طرف إلى طرف | established; universal in Arabic messenger localizations |
| brute force | القوة الغاشمة (هجمات القوة الغاشمة) | established Arabic security term. Never a literal calque of "raw strength" |
| forward secrecy | سرية تامة للأمام | established Arabic technical rendering (Arabic Wikipedia / ar security writing). Was `سرية تامة إلى الأمام` — normalised to the standard form |
| ratchet (Double Ratchet) | يتقدّم المفتاح خطوة بعد خطوة (descriptive paraphrase); `Double Ratchet` stays Latin in the spec parenthetical | no established Arabic noun for the primitive. A coinage (سقّاطة/محشّرة) would be opaque; the verb-phrase paraphrase is honest and reads naturally. Brand/protocol name kept Latin |
| relay | مُرحّل | **established** — the Tor Project's own Arabic localization uses مُرحِّل for a Tor relay. Frozen in the term sheet |
| onion / circuit | (not surfaced in ar UI copy) | English kept if it ever appears |
| hardware / hardware-backed / hardware-bound | العتاد ("قفل العتاد", "مفتاح العتاد", "مرتبط بالعتاد", "حماية … عبر العتاد") | العتاد is the established Arabic computing term for hardware (العتاد والبرمجيات). Term sheet already freezes قفل العتاد. **Not** المادية ("physical") — that was a divergence and was fixed |
| keystore (Android) | مخزن مفاتيح Android (Android Keystore) | Google's Arabic + the Latin product name in parens |
| keychain (iOS) | سلسلة مفاتيح الجهاز | **Apple's own Arabic** for Keychain is سلسلة المفاتيح. Was `سجل مفاتيح` (a coinage, "key register") — fixed |
| security chip / Secure Enclave | شريحة الأمان; `Secure Enclave` stays Latin (glossary) | established; Apple's Arabic keeps Secure Enclave Latin |
| passcode (device) | رمز دخول | term sheet. Distinct from عبارة المرور (Rún's own passphrase) |
| biometric / biometrics | المقاييس الحيوية; in consumer copy the concrete "البصمة أو الوجه" | **المقاييس الحيوية** is the rendering in Android's Arabic UI. Was `القياسات الحيوية` (a variant) — normalised |
| wipe / erase | المحو / يمحو | established native Arabic; no loanword needed |
| crypto-erase | يمحو مفاتيح التشفير نفسها | described, not coined — matches the English store copy's own phrasing |
| forensic extraction / forensics | التحليل الجنائي (الهاتف المُصادَر, هجمات القوة الغاشمة الجنائية) | established Arabic for digital forensics |
| AFU / BFU | `AFU` (Latin) | no Arabic equivalent exists; initialism kept, per policy |
| proxy | (not surfaced in ar UI copy) | — |
| push (notifications) | الإشعارات الفورية ("خادم الإشعارات الفورية", "إشعارات iOS الفورية") | **established** — Apple's and Google's Arabic both use الإشعارات الفورية. A calque of "push" (دفع) would be wrong |
| wake signal (contentless push) | إشارة إيقاظ | natural Arabic description, matches the English source's own metaphor |
| token | (not surfaced in ar UI copy) | — |
| endpoint | نقطة النهاية (عنوان نقطة النهاية) | established Arabic technical rendering (Microsoft ar style) |
| proof of work | إثبات العمل | **established** — the standard Arabic term in blockchain/crypto literature |
| jailbreak | مكسور الحماية (جيلبريك) | مكسور الحماية is the established Arabic phrase; the parenthetical transliteration is a familiar reader aid |
| root (Android) | يعمل بصلاحيات الروت | الروت is the established Arabic-script loanword; the "runs with root privileges" frame is how Arabic Android apps phrase root detection. Was `خضع لعملية روت` (unidiomatic) — fixed |
| rate limit | (not surfaced in ar UI copy) | — |
| entropy / salt / KDF / key derivation | يُشتق مفتاحها بخوارزمية Argon2id | described; Argon2 stays Latin (glossary). No standalone Arabic term forced |
| padding (message padding) | الحشو (كتل محشوّة, "حجمها بعد الحشو", "حشو الرسائل") | **الحشو** is the established Arabic cryptography term. Was `تبطين/مبطّن` — a literal calque of the physical sense ("lined/quilted"). Fixed |
| metadata | (not surfaced in ar UI copy) | — |
| sideload | (not surfaced in ar UI copy) | — |
| offline attack | الهجمات دون اتصال | established, transparent |
| open source | المصدر المفتوح | **established** — مفتوح المصدر / المصدر المفتوح. Was `مصادر مفتوحة` ("open sources", i.e. sources of information) — fixed |
| disk image (forensically "imaged") | نُسخ نسخًا كاملًا | "imaged" is a disk image, not a photograph. `المصوَّر` was a false friend — fixed |
| VAPID / RFC 8291 / Web Push / AES-256-GCM | Latin, verbatim | spec names/initialisms |

### Non-jargon term decisions made in this sweep

| English | ar | note |
| --- | --- | --- |
| messenger (the app) | تطبيق مراسلة / مراسلة | `رسول` (envoy/apostle — a *person*, with strong religious connotation) was wrong in all three store files and the ASC keywords; `مراسل` = correspondent/reporter, also wrong |
| objectionable (content) | مرفوض | Apple's Arabic App Store wording. Frees مسيء for *abusive* |
| abusive (content/behaviour) | مسيء | `تعسفي` means **arbitrary/high-handed**, not abusive — a mistranslation in 4 EULA/report strings |
| vouched introduction | تقديم بالتزكية / تقديمات بالتزكية | term sheet; store copy had drifted to `تعريف موثوق` |
| inbox | صندوق الوارد / صناديق وارد | term sheet; store copy had `صناديق بريد` (mailboxes) |
| locked out | منعك ذلك من فتح الخزنة | `أقفلت في الخارج` was a literal calque of "locked outside" |
| phones home | لا يرسل Rún أي معلومات عنك إلى مطوّريه | the previous "connects to no external server" was factually false (Rún connects to its relay over Tor) |

### Register / typography (confirmed, unchanged)

- **MSA**, addressing the user in the **2nd person masculine singular** (unmarked).
  No feminine/dual address forms anywhere.
- 3rd-person contact placeholders (`%1$s`) keep **masculine default** agreement
  (`غادر %1$s المجموعة`), the MSA convention for unknown gender; passive is
  preferred where it is available and neutral (`تمت إزالة %1$s من المجموعة`).
- **Quotes: « »** only. No `“ ”`, no straight `\"` anywhere in the locale.
- **Tier names** جيد / آمن / الحد الأقصى are frozen and now carry « » wherever
  they appear as *names* (prose and `%1$s`-spliced), because Arabic has no
  capitalisation to mark جيد/آمن as proper names rather than plain adjectives.
  **Exception:** `protection_level_accessibility_label` is unquoted
  (`مستوى الحماية %1$s`) — it is a screen-reader label, so punctuation is
  avoided; the head noun also fixes the agreement problem that made
  `حماية جيد` ungrammatical.
- **RTL adaptations are deliberate, keep them:** `‹`/`›` and `←`/`→` are
  mirrored relative to the English source (`notif_settings_carousel_back`,
  `_next`, `add_contact_show_first_android`); any English "top left back
  arrow" / "tap the ← arrow" drops the direction word and the literal glyph
  because the back affordance sits top-**right** in a mirrored layout (the
  strings that carried this wording were removed 2026-11); `Settings → X → Y`
  arrow chains become `افتح … ثم … ثم …`
  (`protection_forced_explainer_cta_body_ios`).
- **Diacritics:** shadda is written on the recurring stems (`مشفّر`, `مُرحّل`)
  in prose. **Exception:** ASC keywords stay undiacritized (`مشفر`) so they
  match users' undiacritized search input.
- Arabic plurals use all six forms; `zero/one/two` omit the count,
  `few/many/other` keep `%1$d` and take the correct case
  (few = genitive plural `أعضاء`, many = accusative singular `عضوًا`,
  other = genitive singular `عضو`).

### Notification-carousel sweep (2026-09-11)

The opt-in carousel was cut to three pages + the switch; these are the renderings
used across `notif_edu_*` and `notif_edu_up_*` in this locale.

| English term | ar rendering |
| --- | --- |
| wake / wake signal (contentless push) | **إشارة إيقاظ** (confirmed) |
| distributor (UnifiedPush) | **تطبيق الموزّع** / *الموزّع* |
| push address | **عنوان الإشعارات الفورية** |
| timestamps (of incoming messages) | **الطوابع الزمنية** |

### Connect-screen sweep (2026-09-11)

The runestone ring/`R` reveal, the live connection log and the anonymous
connect-time report (`ConnectTelemetry`) — renderings used in
`about_tor_runestone_body`, `connect_log_title` and the 1.6.17 What's New.

| English term | ar rendering |
| --- | --- |
| ring (of the runestone) | **الحلقة** |
| the R (glyph that lights last) | **حرف R** (يبقى R لاتينيًا) |
| live connection log | **سجل الاتصال** |
| connect-time report (seconds only, nothing identifying) | *يُبلغ المُرحّل بعدد الثواني التي استغرقها فقط* |

### Introduction-relay modal sweep (2026-09-13)

The introducer-side modal (`referral_relayed_*`, ReferralManager.onIntroRelayed).
Hard rule in every locale: the *complete* variant must NOT say the two are now
connected — the introducer never learns that. Render "each now has what they
need to reach the other", and keep the privacy line ("you have no part in their
conversation and cannot read it") plain and literal.

| English term | ar rendering |
| --- | --- |
| Introduction accepted / complete (modal titles) | **تمت الموافقة على التقديم** / **اكتمل التقديم** |
| connection details | **تفاصيل الاتصال** |
| pass on / passed on | **مرَّر** / *وقد مُرِّرت* |
| each now has what they need to reach the other | *لدى كلٍّ منهما ما يلزم للوصول إلى الآخر* |
| next time you open the app | *في المرة القادمة التي تفتح فيها التطبيق* |

- **Introducer-side copy must not say `تقديمك إلى %2$s`** — that is the
  introducee-side wording of `referral_offer_message` and reads as "introducing
  **you** to %2$s". Use the bare verbal noun: **التقديم إلى %2$s**.
- The two contacts take the dual (*يمكنهما*, *محادثتهما*); that is grammatical
  MSA for two named people and is not the "no feminine/dual for the user" rule.

### Debug-mode sweep (2026-09-14)

The opt-in anonymous diagnostic-log upload: settings row `settings_debug_mode` /
`settings_debug_mode_on` plus the consent dialog `debug_mode_title`,
`debug_mode_message`, `debug_mode_message_off`, `debug_mode_turn_on`,
`debug_mode_turn_off` (ContactListScreen.kt / ContactListView.swift, DebugMode.kt).
Hard rules in every locale: **"Debug mode" is a product term** — the settings row
and the dialog title must be byte-identical, and the on-state row is that term +
the locale's "(on)". The privacy promise in `debug_mode_message` stays **literal**:
"never include anything that identifies you or this device" followed by the five
explicit negations (names, message content, addresses, keys, inbox or contact ids).
Do not soften it to "minimal data", do not merge the five items, do not add claims.

| English term | ar rendering |
| --- | --- |
| Debug mode (row label + dialog title) | **وضع تصحيح الأخطاء** |
| Debug mode (on) | **وضع تصحيح الأخطاء (مُفعَّل)** |
| diagnostic logs | **سجلات تشخيصية** (def. *السجلات التشخيصية*) |
| log (noun) | **سجل** (cf. `connect_log_title` *سجل الاتصال*) |
| Turn on / Turn off | **تفعيل** / **تعطيل** |

- *تصحيح الأخطاء* is the established MSA term (Android ar: *تصحيح أخطاء USB*).
- "identifies you or this device" → *يحدّد هويتك أو هوية هذا الجهاز* — *هوية* is
  repeated for the device on purpose; do not collapse it to a single genitive.
- The five negations keep the *لا … ولا …* series; "ids" → **معرّفات**.

### Ratchet-refusal notice sweep (2026-09-18)

See the shared rules in the `## en` section (`conversation_ratchet_refused_body`).

| English term | ar rendering |
| --- | --- |
| secure channel | **قناة آمنة** |
| could not be established | تعذّر إنشاء … |
| Messages are not being sent. | لا يتم إرسال الرسائل. |
| pair again | **أعد الاقتران** |

- *الاقتران* is the locale's pairing noun (`add_contact_cancel_pairing` «إلغاء الاقتران», `contact_list_reset_relay_message` «الاقتران من جديد»). *أعد الاقتران* already carries "again" — do not add *من جديد* on top of it.
- *تعذّر* is the established failure verb (*تعذّر الوصول إلى المُرحّل*). 2nd-person **masculine singular** imperative *احذف*, per the register rule.
- *قناة*, not *اتصال* — *اتصال* is the relay/network connection.

## fa — Persian (Farsi)

| concept | rendering |
| --- | --- |
| vault | گاوصندوق |
| relay | رله |
| runestone | سنگ رونی |
| passphrase | عبارت عبور |
| protection level | سطح حفاظت |
| burn on read | سوختن پس از خواندن |
| vouched introduction / introduce / introduced by | معرفی‌های ضمانت‌شده / معرفی / معرفی‌شده توسط %1$s |
| inbox | صندوق ورودی |
| device key | کلید دستگاه |
| hardware lock | قفل سخت‌افزاری |
| device passcode / lock screen | رمز دستگاه / قفل صفحه |
| recovery code | کد بازیابی |

- **Tiers:** معقول / امن / حداکثر
- **Register:** formal/polite **شما** with plural verb endings throughout.
- **Quotes:** « ».
- **Deliberate loanwords:** **رله** for relay. Keep ZWNJ (‌) spelling in
  compounds such as معرفی‌شده and سخت‌افزاری.
- RTL locale, same note as Arabic.
- Play-only locale (no App Store Connect metadata locale).

---

### Jargon (sweep 2026-09-03)

# fa (Persian) — jargon & brand decisions, sweep 2026-09-03

Scope: `androidApp/src/main/res/values-fa/strings_*.xml` + `docs/store-listing/play-short-fa.txt`,
`play-full-fa.txt`. Register is formal/polite **شما** with plural verb endings (unchanged).
Quotes « » (unchanged). These decisions belong in `docs/l10n/terms.md` § fa.

**Governing rule adopted for fa:** where a term has an established Persian rendering used by
mainstream Persian software/security writing, use it; otherwise use the Persian **transliterated
loanword** (which is fa's normal way of absorbing English tech vocabulary — اسکرین‌شات، فارنزیک،
جیلبریک), and keep **Latin script** only for glossary items, protocol/product names, and terms with
no settled Persian form at all (padding, endpoint). Never a literal calque.

### Jargon

| English term | fa rendering | reason |
| --- | --- | --- |
| PIN | **PIN** (Latin, uninflected) | Glossary item — must survive verbatim. The locale had 21 × «پین» vs 4 × Latin `PIN`; the store copy already used Latin. Unified on Latin; sentences reworded where an indefinite ی had been suffixed (`نه پینی هست` → `نه PIN در کار است`). |
| brute force / brute-forced / brute-forcing | **جستجوی فراگیر** (attack: حملهٔ جستجوی فراگیر) | Established Persian security term (per project policy). Replaced the descriptive paraphrase «با امتحان همهٔ حالت‌ها» and the bare «شکستن». Never «حملهٔ زور بی‌رحمانه»/«نیروی خام». |
| end-to-end encryption | **رمزگذاری سرتاسری** | Established; already used consistently. Kept. |
| forward secrecy | **محرمانگی پیشرو** | Established Persian term. Normalised the spelling from «پیش‌رو» (ZWNJ = "ahead/in front") to the single-word adjective «پیشرو». |
| ratchet (verb, "keys ratchet forward") | **گام‌به‌گام جلو رفتن** | «می‌چرخد» (rotates) was wrong — ratcheting is forward-only, not rotation. The store copy already used «گام‌به‌گام جلو می‌روند»; UI now matches. The proper noun *Double Ratchet* stays Latin in the store copy. |
| padding / padded | **هم‌اندازه‌شده (padding)** in UI prose; **padding** (Latin) in store copy | The existing «لایه‌گذاری» means *layering*, not padding — a semantic error that in a Tor app reads as onion-layering. No settled Persian term exists, so the English term is named once and glossed with the plain-language «هم‌اندازه» (equal-sized). |
| endpoint (UnifiedPush endpoint address) | **endpoint** (Latin) | «نقطهٔ پایانی» is a literal calque; the term appears only on the UnifiedPush technical deep card whose readers meet `endpoint` in their distributor app's English UI. |
| relay | **رله** | Term-sheet decision, unchanged. |
| forensic (tools / -safe) | **فارنزیک** | Established loanword in Persian infosec usage; consistent across UI + store. |
| forensically imaged (phone) | **ایمیج‌شده** | «تصویربرداری شده» reads as *photographed*. The store copy already said «ایمیج‌شده»; UI now matches. |
| proof of work | **اثبات کار** | Established Persian (blockchain/crypto literature). Kept. |
| push (notification / server / signal) | **پوش** (noun), **اعلان فوری** (user-facing "push notifications"), **اعلان آنی** ("real-time notifications") | Established transliteration; the فوری/آنی split mirrors the English push/real-time split. Kept. |
| wake signal | **سیگنال بیدارباش** | Natural Persian, not a calque. Kept. |
| wipe / crypto-erase | **پاک‌سازی / پاک کردن** (keys: «خودِ کلیدها را از بین می‌برد») | Native Persian is established here; no loanword needed. Kept. |
| biometric(s) | **بیومتریک** | Established loanword. Kept. |
| jailbreak / root | **جیلبریک / روت** | Established loanwords. Kept. |
| passcode (device) | **رمز دستگاه** | Term-sheet anchor (`protection_device_lock_term_ios`), spliced into 3 other strings. Kept. |
| lock screen | **قفل صفحه** | Term-sheet anchor. Kept. |
| password (device screen-lock option only) | **گذرواژه** | Deliberately distinct from عبارت عبور (= Rún's own passphrase). Kept. |
| hardware key / hardware lock | **کلید سخت‌افزاری / قفل سخت‌افزاری** | Term-sheet. Kept. |
| security chip | **تراشهٔ امنیتی** | Kept. |
| screenshot | **اسکرین‌شات** | Established loanword. Kept. |
| feed (public feed, EULA) | **فید** | «خوراک» is the RSS-reader sense and reads as *food*; «فید» is what Persian social apps use. |
| circuit / hop (Tor) | not named in the current copy; "several hops" → **چند ایستگاه** | Natural, not a calque. If a future string needs the terms, Tor Browser's own fa localisation uses **مدار** (circuit) and **رله** (relay). |
| AFU / VAPID / RFC 8291 / Web Push / SQLCipher / Argon2id / AES-256-GCM / Double Ratchet / Android Keystore | Latin, unchanged | Protocol/spec/product names. |

### Brand & platform names

| name | fa | reason |
| --- | --- | --- |
| Google, Apple | **Google**, **Apple** (Latin) | Was mixed: «گوگل/اپل» in UI prose but Latin in the store copy and inside `Google Play` / `Apple ID` — including both forms in one sentence (`donate_play_disclosure`). Unified on the Latin wordmark, matching the locale's own store copy and both vendors' Persian-facing style. |
| Android, iPhone | **Android**, **iPhone** (Latin) | Same rule; also restores parity in the `notif_cross_ref_label_*` pair, whose sibling already read `پوش iOS (APNs)`. |
| Apple Push Notification service | **سرویس Apple Push Notification (APNs)** | It is a product name; the previous «سرویس اعلان فوری اپل» translated it, while its FCM sibling kept `Firebase Cloud Messaging` Latin. |
| Google Firebase Cloud Messaging | **سرویس Google Firebase Cloud Messaging (FCM)** | Whole product name in Latin, removing the mid-string ezafe onto «گوگل». |
| Google Play, App Store, Apple ID, iOS, iCloud, F-Droid, ntfy, UnifiedPush, Tor, Rún | Latin, unchanged | |

### RTL conventions confirmed this sweep

- Directional glyphs are mirrored by hand, following the Arabic locale: `→` → `←`
  (`add_contact_show_first_android`), `‹ Back` → `› بازگشت`, `Next ›` → `بعدی ‹`.
- Copy must not name a left/right screen position: a "top left back arrow" becomes
  «پیکان بازگشتِ بالای صفحه» (ar does the same) and an inline `←` becomes «پیکان بازگشت»
  (the strings that carried this wording were removed 2026-11; the rule stands).
- No Arabic-only letters (ة ي ك ى) anywhere in fa; Persian ی/ک only. Verified mechanically.
- Persian digits (۲۴، ۶۰، ۷) in prose match what `%1$d` formats to under the fa locale.

### Notification-carousel sweep (2026-09-11)

The opt-in carousel was cut to three pages + the switch; these are the renderings
used across `notif_edu_*` and `notif_edu_up_*` in this locale.

| English term | fa rendering |
| --- | --- |
| wake / wake signal (contentless push) | **بیدارباش** / *سیگنال بیدارباش* (confirmed) |
| distributor (UnifiedPush) | **برنامهٔ توزیع‌کننده** / *توزیع‌کننده* |
| push address | **نشانی پوش** |

### Connect-screen sweep (2026-09-11)

The runestone ring/`R` reveal, the live connection log and the anonymous
connect-time report (`ConnectTelemetry`) — renderings used in
`about_tor_runestone_body`, `connect_log_title` and the 1.6.17 What's New.

| English term | fa rendering |
| --- | --- |
| ring (of the runestone) | **حلقه** |
| the R (glyph that lights last) | **حرف R** (R لاتین می‌ماند) |
| live connection log | **گزارش اتصال** |
| connect-time report (seconds only, nothing identifying) | *فقط تعداد ثانیه‌های صرف‌شده را به رله گزارش می‌دهد* |

### Introduction-relay modal sweep (2026-09-13)

The introducer-side modal (`referral_relayed_*`, ReferralManager.onIntroRelayed).
Hard rule in every locale: the *complete* variant must NOT say the two are now
connected — the introducer never learns that. Render "each now has what they
need to reach the other", and keep the privacy line ("you have no part in their
conversation and cannot read it") plain and literal.

| English term | fa rendering |
| --- | --- |
| Introduction accepted / complete (modal titles) | **معرفی تأیید شد** / **معرفی کامل شد** |
| connection details | **اطلاعات اتصال** |
| pass on / passed on | **ارسال کردن / فرستادن** (*ارسال شد*) |
| each now has what they need to reach the other | *هرکدام آنچه را برای رسیدن به دیگری لازم دارند در اختیار دارند* |
| next time you open the app | *دفعهٔ بعد که برنامه را باز کنید* |

- Same trap as ar: **not `معرفی شما به %2$s`** (that is "introducing **you**",
  the wording of `referral_offer_message`). Use **معرفی به %2$s**.

### Debug-mode sweep (2026-09-14)

The opt-in anonymous diagnostic-log upload: settings row `settings_debug_mode` /
`settings_debug_mode_on` plus the consent dialog `debug_mode_title`,
`debug_mode_message`, `debug_mode_message_off`, `debug_mode_turn_on`,
`debug_mode_turn_off` (ContactListScreen.kt / ContactListView.swift, DebugMode.kt).
Hard rules in every locale: **"Debug mode" is a product term** — the settings row
and the dialog title must be byte-identical, and the on-state row is that term +
the locale's "(on)". The privacy promise in `debug_mode_message` stays **literal**:
"never include anything that identifies you or this device" followed by the five
explicit negations (names, message content, addresses, keys, inbox or contact ids).
Do not soften it to "minimal data", do not merge the five items, do not add claims.

| English term | fa rendering |
| --- | --- |
| Debug mode (row label + dialog title) | **حالت اشکال‌زدایی** |
| Debug mode (on) | **حالت اشکال‌زدایی (روشن)** |
| diagnostic logs | **گزارش‌های تشخیصی** |
| log (noun) | **گزارش** (cf. `connect_log_title` *گزارش اتصال*) |
| Turn on / Turn off | **روشن کردن** / **خاموش کردن** |

- *اشکال‌زدایی* is the established fa term (Android fa: *اشکال‌زدایی USB*); ZWNJ kept
  in اشکال‌زدایی, گزارش‌ها, نمی‌شوند.
- relay stays **رله** per the section table; inbox stays **صندوق ورودی**.
- The five negations keep the *نه … نه …* series; "ids" → **شناسه**.

### Ratchet-refusal notice sweep (2026-09-18)

See the shared rules in the `## en` section (`conversation_ratchet_refused_body`).

| English term | fa rendering |
| --- | --- |
| secure channel | **کانال امن** |
| could not be established | … ممکن نشد |
| Messages are not being sent. | پیام‌ها ارسال نمی‌شوند. |
| pair again | **دوباره جفت‌سازی کنید** |

- *جفت‌سازی* (with ZWNJ) is the locale's pairing noun (`add_contact_cancel_pairing` «لغو جفت‌سازی»).
- *ممکن نشد* is the established failure formula. Formal **شما** with plural verb endings throughout.
- *کانال*, not *اتصال* — *اتصال* is the relay/network connection.

## so — Somali

App-only language: neither store console has a metadata locale for it, so `so`
has **UI strings only** — never write store copy for it.

| concept | rendering |
| --- | --- |
| vault | khasnad (def. *khasnadda*, poss. *khasnaddaada*) |
| relay | **relay** (loanword; def. *relay-ga*) |
| runestone | dhagaxa runaha |
| rune(s) | run / *runaha*, *runuhu* |
| passphrase | **weedh sir ah** (def. *weedhda sirta ah*, poss. *weedhdaada sirta ah*) |
| protection level | Heerka ilaalinta (indef. *heer ilaalin*) |
| burn on read | Gub marka la akhriyo |
| vouched introduction | Isbarasho la dammaanad qaaday |
| introduce (verb) | isu bar |
| introduced by | Waxaa ku soo baray %1$s |
| vouch | dammaanad qaad / *dammaanad u tahay* |
| inbox | sanduuq (def. *sanduuqa*, pl. *sanduuqyada*) |
| device key / hardware key | furaha qalabka |
| hardware lock | qufulka qalabka |
| device passcode | **passcode** (loanword; def. *passcode-ka*) |
| lock screen | quful shaashadeed (def. *qufulka shaashadda*) |
| recovery code | koodhka soo-celinta |

- **Tiers:** Caadi / Ammaan / Ugu sarreeya
- **Register:** Somali has no T/V distinction. Address the user in the 2nd
  person singular; use plain imperatives for actions ("Dooro…", "Isku day mar
  kale"). Polite but not deferential.
- **Capitalisation:** sentence case, mirroring the English source. Do **not**
  Title Case labels — the only capitals are sentence-initial, proper nouns and
  glossary terms. (Three of the four area splits had drifted into English-style
  Title Case; that has been normalised.)
- **Quotes:** “ ” (curly). Do not use escaped straight `\"`.
- **Deliberate loanwords:** `relay`, `passcode`, `push`, `app`, `browser`,
  `server`, `chip`, `cache`, `disk`, `email`, `profile`. All take the normal
  Somali definite/possessive suffix after a hyphen (*relay-ga*, *passcode-kaaga*).
- **Rejected alternatives** (do not reintroduce): `dhexdhexaadiye` for relay;
  `erayada sirta ah` for passphrase (it collides with *erayga sirta ah* =
  the device *password*); `koodh`/`lambar` for the device passcode (*koodh* is
  reserved for the **recovery code**); `furaha sirta ah` for the hardware key;
  `xidhitaan` for a lock (use *quful*).
- **Gender:** Somali marks subject gender on the verb, and contact aliases have
  no gender. Prefer constructions that avoid it: the `waxaa`-cleft
  ("Kooxda waxaa ka baxay %1$s"), impersonal `la-` passives
  ("Kooxda waxaa laga saaray %1$s"), or a neutral head noun that carries the
  agreement ("Waxaad heshay casuumaad ka timid %1$s…"). Never guess *wuxuu*/*waxay*
  for a person placeholder.

---

### Jargon (sweep 2026-09-03)

# so — Somali jargon decisions (sweep 2026-09-03)

Applies the project's jargon policy (2026-09-02): technical/security terms stay
ENGLISH (Latin, with the normal Somali definite/possessive suffix after a
hyphen: `relay-ga`, `passcode-kaaga`, `forensic-ka`) unless Somali has a
well-established native term used in mainstream app localizations. Never a
calque. Somali very rarely has such a term, so most coined descriptive phrases
were reverted to the English term.

These decisions supersede nothing in `docs/l10n/terms.md`'s existing so table
(vault/relay/passphrase/passcode/tiers/register etc. were kept exactly as
written there); they extend it with the jargon column. `docs/l10n/terms.md` was
NOT edited, per the task constraint — fold this table in when convenient.

### Jargon

| English term | so rendering | reason |
| --- | --- | --- |
| brute force | **brute force** (verbal use: *brute force ku jebin kara*) | No Somali term exists; the previous *lagu jebin karaa* ("can be broken") dropped the term entirely. Policy: never a calque, never a coined descriptive. |
| forensic (tools / attacks / examination) | **forensic** (*qalabka forensic-ka*, *weerarrada forensic-ka*, *baaritaanka forensic-ka*) | Was *farsamada* ("technical"), which is both a coinage and factually weaker than "forensic". `farsamo` is kept only where the English really says *technical* (`notif_settings_technical_details`). |
| end-to-end encryption / encrypted | **end-to-end** kept English inside a Somali frame: *sirsiin end-to-end ah* | Was the calque *bilowga ilaa dhammaadka* ("from the beginning to the end"), which is also semantically wrong (endpoint-to-endpoint, not start-to-finish). The head noun *sirsiin* stays Somali — see "encrypt" below. |
| ratchet (verb, "the key ratchets forward") | **ratchet** (*furahaasi ratchet ayuu ku sii gudbaa*) | Was *hore ayuu u soconayaa* ("moves forward") — a paraphrase that erased the term. |
| padding / padded | **padding** (*xirmooyin padding lagu daray*, *cabbirkooda padding-ku*) | Was the coinage *buux-gal* ("fill-in"), unintelligible. |
| proof of work | **proof-of-work** | Was *caddaynta shaqada* — a literal calque. |
| hop (Tor "several hops") | **hop** (*dhowr hop*) | Was *dhowr meelood oo dhexdhexaad ah*, a coinage adjacent to the term sheet's already-rejected *dhexdhexaadiye* for relay. |
| endpoint | **endpoint** (*cinwaanka endpoint-kaaga*) | Already correct in the file; confirmed and kept. |
| push / push notification | **push** (*ogeysiisyada push*, *server-ka push-ka*) | Term-sheet loanword; kept. |
| relay | **relay** (*relay-ga*) | Term-sheet loanword; kept. |
| passcode (device) | **passcode** (*passcode-ka qalabka*) | Term-sheet loanword; kept. |
| biometric / biometrics | **biometric / Biometrics** (*jid gaaban oo biometric ah*) | `protection_stop_no_biometrics` already had it; `pin_setup_passphrase_hint` had lost it to a broken paraphrase and now uses it too. |
| root / jailbreak | **root / jailbreak** (*mid la root gareeyay*, *mid la jailbreak gareeyay*) | Already English; the scare quotes were dropped so they read like the locale's other loanwords. |
| mint (relay inbox minting) | **Mint** (*Mint wuu fashilmay: %1$s*) | Rún protocol jargon, as opaque in English as in Somali; *Abuurista* ("creation") both lost the term and misdescribed it. |
| byte(s) | **byte** (*hal byte oo fariin ah*) | Was *xarfo* ("letters/characters") — wrong unit. |
| analytics | **analytics** | Was *falanqayn* ("analysis"), a coined descriptive for a tracking term of art. |
| random (words, codename) | **random** (*eray oo random ah*, *magac random ah*) | The locale already used *random* in `about_contacts_body`; the two coinages (*aan la filayn*, *aan xiriir lahayn*) were reverted to it. |
| VAPID, AFU, Web Push / RFC 8291, QR, PIN, Tor, FCM, APNs, UnifiedPush, ntfy, F-Droid, Face ID, SQLCipher | English, uninflected | Glossary / acronyms; already correct, verified against the validator's glossary rule. |
| open source | **open source** (*Ku dhisan open source*) | Was *software furan* ("open software"); no established Somali term. Lower confidence than the rows above — see the report's "unsure" list. |
| sync | **sync** (*iCloud la sync gareyn karaa*) | Already English; kept. |
| server, app, browser, disk, cache, chip, email, profile, data | English loanwords with hyphenated suffixes | Term-sheet loanwords; `iimaylo` → `email`, `profayllo` → `profile-yo`, `disk kuma hayaan` → `kuma jiraan disk-ga` were normalised to that rule. |

### Deliberately kept NATIVE (not reverted to English)

| English term | so rendering | reason |
| --- | --- | --- |
| hardware (device key / hardware lock / secure hardware) | **qalab** (*furaha qalabka*, *qufulka qalabka*, *qalabka ammaanka*) | Bound by the existing so term sheet; changing it would break four anchor strings. Reads naturally and is unambiguous in context. |
| wipe / erase | **tirtir** | The ordinary Somali verb for delete/erase and the established rendering in mainstream Somali Android localization ("Delete" = *Tirtir*). Not a coinage. The parenthetical English gloss *"(wipe)"* in `contact_list_post_block_report_message` was removed as a leak. |
| encrypt / encrypted / decrypt | **sirsii / sirsiiman / sii fur** | Transparent, already dominant in the locale (7 occurrences vs 3 of the rival *sirtir*); normalised to *sirsii-*. Only the compound term *end-to-end* is English. |
| lock / lock screen | **quful / quful shaashadeed** | Term sheet; the three surviving *xidhitaan* (an explicitly rejected alternative) were converted. |
| inbox | **sanduuq** | Term sheet. |
| timestamps | **waqtiyada** | Ordinary word, not a coinage; English uses no term of art here either. |
| distributor (UnifiedPush) | **qaybiye** | Transparent Somali agent noun, already used consistently across two areas; not a security term. |
| scan (QR) | **sawir garee** | Camera action, not security jargon; already consistent across `add_contact` and now `about_contacts_body` too. |

### Notification-carousel sweep (2026-09-11)

The opt-in carousel was cut to three pages + the switch; these are the renderings
used across `notif_edu_*` and `notif_edu_up_*` in this locale.

| English term | so rendering |
| --- | --- |
| wake / wake signal (contentless push) | **toosin** / **calaamad toosin** |
| push address | **cinwaanka push** |
| timestamps (of incoming messages) | **waqtiyada** |

### Connect-screen sweep (2026-09-11)

The runestone ring/`R` reveal, the live connection log and the anonymous
connect-time report (`ConnectTelemetry`) — renderings used in
`about_tor_runestone_body`, `connect_log_title` and the 1.6.17 What's New.

| English term | so rendering |
| --- | --- |
| ring (of the runestone) | **giraan** (def. *giraanta*, poss. *giraantiisa*) |
| the R (glyph that lights last) | **xarafka R** |
| live connection log | **Diiwaanka xidhiidhka** |
| connect-time report (seconds only, nothing identifying) | *(ma jiro nuqul dukaan oo so ah)* |

### Introduction-relay modal sweep (2026-09-13)

The introducer-side modal (`referral_relayed_*`, ReferralManager.onIntroRelayed).
Hard rule in every locale: the *complete* variant must NOT say the two are now
connected — the introducer never learns that. Render "each now has what they
need to reach the other", and keep the privacy line ("you have no part in their
conversation and cannot read it") plain and literal.

| English term | so rendering |
| --- | --- |
| Introduction accepted / complete (modal titles) | **Isbarashada waa la ansixiyay** / **Isbarashadu way dhammaatay** |
| connection details | **faahfaahinta xidhiidhka** |
| pass on / passed on | **gudbi** / *waa la gudbiyay* |
| each now has what they need to reach the other | *mid kastaa wuxuu haystaa waxa uu ugu baahan yahay si uu kan kale u soo gaaro* |
| next time you open the app | *marka xigta ee aad app-ka furto* |

- The approving contact is put in the **`waxaa`-cleft** (*… waxaa ansixiyay
  %1$s*) exactly as the gender rule above prescribes — a plain *wuxuu ansixiyay
  %1$s* would force masculine agreement on an unknown-gender alias.
- "their conversation" is **wada-hadalkooda** (the hyphenated singular-definite
  spelling this locale uses; the plural is written *wadahadallada*).

### Debug-mode sweep (2026-09-14)

The opt-in anonymous diagnostic-log upload: settings row `settings_debug_mode` /
`settings_debug_mode_on` plus the consent dialog `debug_mode_title`,
`debug_mode_message`, `debug_mode_message_off`, `debug_mode_turn_on`,
`debug_mode_turn_off` (ContactListScreen.kt / ContactListView.swift, DebugMode.kt).
Hard rules in every locale: **"Debug mode" is a product term** — the settings row
and the dialog title must be byte-identical, and the on-state row is that term +
the locale's "(on)". The privacy promise in `debug_mode_message` stays **literal**:
"never include anything that identifies you or this device" followed by the five
explicit negations (names, message content, addresses, keys, inbox or contact ids).
Do not soften it to "minimal data", do not merge the five items, do not add claims.

| English term | so rendering |
| --- | --- |
| Debug mode (row label + dialog title) | **Habka debug-ga** |
| Debug mode (on) | **Habka debug-ga (shidan)** |
| diagnostic logs | **diiwaanno baaritaan** (def. *diiwaannada baaritaanka*) |
| log (noun) | **diiwaan** (cf. `connect_log_title` *Diiwaanka xidhiidhka*) |
| anonymous (of the logs) | **qarsoodi ah** (cf. `report_bug_title` *waad qarsoon tahay*) |
| Turn on / Turn off | **Shid** / **Dami** |

- Somali has no established term for "debug", so **debug** joins the deliberate
  loanword list (*relay*, *passcode*, *push*, *app*…) and takes the normal
  definite suffix after a hyphen: *debug-ga*. `hab` supplies "mode".
- "identifies you or this device" → *wax lagu aqoonsan karo adiga ama qalabkan*
  (impersonal `la-` passive — no subject gender, per this section's gender rule).
- "ids" → **aqoonsiyo**; inbox → *sanduuq*; contact → *xiriiriye*.

### Ratchet-refusal notice sweep (2026-09-18)

See the shared rules in the `## en` section (`conversation_ratchet_refused_body`).

| English term | so rendering |
| --- | --- |
| secure channel | **kanaal ammaan ah** |
| could not be established | Lama samayn karin … |
| Messages are not being sent. | Fariimaha lama dirayo. |
| pair again | **lammaanaanta mar kale samee** |

- **kanaal** (loanword) was chosen over *xiriir ammaan ah*: *xiriir* collides with *xiriiriye* (contact), which appears in the same sentence.
- The pairing noun is **lammaanaan** (`add_contact_cancel_pairing` *Jooji lammaanaanta*, `group_info_no_verified_pairing`); *lammaanaanta mar kale samee* keeps the plain singular imperative and stays gender-free.
- *Lama samayn karin …* follows the locale's negative-passive failure pattern (*lama diri karin*, *lama gaari karin*); the relative clause *oo aad xiriiriyahan la leedahay* mirrors *lammaanaan … oo aad la leedahay xubintan*.
- Sentence order mirrors `conversation_fs_stalled_body`'s *xiriiriyaha tirtir, kadibna …*.

## ru — Russian

| concept | rendering |
| --- | --- |
| vault | хранилище |
| relay | ретранслятор |
| runestone | рунический камень |
| passphrase | **парольная фраза** |
| protection level | Уровень защиты |
| burn on read | Сжигание при прочтении |
| vouched introduction | Знакомства по поручительству |
| introduce (verb) | познакомить |
| introduced by | Знакомство через %1$s (bare badge: *Знакомство*) |
| vouch | ручаться / поручительство |
| inbox | почтовый ящик |
| device key / hardware key | аппаратный ключ |
| hardware lock | аппаратная блокировка |
| device passcode | **код-пароль** (устройства) |
| lock screen | экран блокировки |
| recovery code | код восстановления |

- **Tiers:** Базовый / Защищённый / Максимальный — always quoted as
  «Базовый» / «Защищённый» / «Максимальный» when spliced into a sentence via
  `%1$s`, matching how the existing strings read (`уровень «%1$s»`).
- **Register:** formal **вы**, written **lowercase** mid-sentence (capitalised
  only at the start of a sentence). Never "ты".
- **Quotes:** « » (guillemets), including around tier names and quoted UI labels.
- **Deliberate loanwords:** `push` (as *push-уведомление*) only; everything else
  is native.
- **Rejected alternatives** (do not reintroduce): `кодовая фраза` for passphrase
  (that is a "code phrase"; Rún uses *парольная фраза*); `сейф` for vault;
  `ключ устройства` (use *аппаратный ключ*); `пароль устройства` /
  `код блокировки` for the passcode (use *код-пароль*); `представить` for
  introduce (use *познакомить*); `По рекомендации %1$s` for the introduced-by
  badge — it was a second lexical family for one feature, so it lost to
  *Знакомство через %1$s*; `самоуничтожение при прочтении` for burn on read.
- **Gender:** contact aliases have no gender, and Russian past tense and
  participles do. Prefer present tense ("%1$s приглашает вас…",
  "%1$s покидает группу"), the impersonal 3rd-plural ("%1$s удалили из
  группы"), or a neutral head noun that carries the agreement
  ("%1$s: возможно, сделан снимок экрана"). Avoid the `сделал(а)` parenthesis
  hack.

---

### Jargon (sweep 2026-09-03)

# ru — Russian: jargon decisions (sweep 2026-09-03)

Policy: technical/security terms take the rendering mainstream Russian
security-app / vendor localizations use (Signal, WhatsApp, Apple, Google,
RU Wikipedia). Established Russian term where one exists; otherwise the
English term or its established loanword. Never a literal calque.

Sources of truth used for "established": Apple RU (Связка ключей, код-пароль,
Стереть), Google/Android RU (перебор, root-права, дистрибьютор in the FOSS/ntfy
ecosystem), RU Wikipedia (доказательство работы, прямая секретность,
информатор), Russian crypto literature (дополнение, формирование ключа).

### Jargon

| English term | ru rendering | reason |
| --- | --- | --- |
| brute force (verb/noun) | подобрать / перебор (`подобрать его за несколько часов`, `противостоит криминалистическому перебору`) | «перебор»/«подбор пароля» is the established RU security term. «Брутфорс» exists but is slangy for consumer copy; «råstyrka»-style calques rejected. |
| end-to-end encryption | сквозное шифрование | Signal/WhatsApp/Telegram RU all use it. |
| forward secrecy | прямая секретность | RU Wikipedia / crypto literature («совершенная прямая секретность»). Store copy only. |
| ratchet (key ratchets forward) | ключ обновляется (описательно); `Double Ratchet` stays Latin as a product name | «Храповик» is a literal calque and unreadable in consumer copy; the RU practice is to keep the product name and describe the behaviour. |
| relay | ретранслятор | Term-sheet binding (pre-existing). Native, and unambiguous next to Tor's own «узлы». |
| onion / Tor circuit / hop | узел (hop → «несколько узлов»); Tor stays Latin | Tor Project RU uses «узлы»; Tor itself is glossary. |
| hardware-backed / hardware-bound | аппаратный (аппаратный ключ, аппаратная блокировка) | Term-sheet binding; matches Android RU «аппаратное хранилище ключей». `infoplist_faceid_usage` was «привязанная к устройству разблокировка» → now «аппаратная блокировка» (same concept as the UI's hardware lock). |
| keystore / keychain | Android Keystore (Latin, glossary-like product name); keychain → связка ключей устройства | Apple RU calls the Keychain «Связка ключей»; Android Keystore is a product name and is left Latin in store copy. |
| secure hardware / security chip | аппаратный модуль безопасности / чип безопасности | «Защищённый аппаратный модуль» collided with the tier name «Защищённый» → replaced. `Secure Enclave` stays Latin (glossary). |
| passcode (device) | код-пароль (устройства) | Apple RU's own term. Declines second element only: «код-пароля». Term-sheet binding. |
| lock screen | экран блокировки | Term-sheet binding; Android RU. |
| biometric | биометрия / по отпечатку пальца или лицу | Android/Apple RU. |
| wipe / erase (app data) | стереть данные, стирание | Apple RU «Стереть …»; the UI already used «стираются». Store copy's «самоочистка/очистка» → «автоматическое стирание / стирание» (очистка reads like cache clearing). |
| crypto-erase (erases the keys themselves) | уничтожаются сами ключи / Стирание уничтожает сами ключи шифрования | Descriptive; there is no established RU consumer term, and the mechanism is what matters. |
| forensic extraction / forensic tools | криминалистический (криминалистические инструменты, криминалистические атаки, криминалистический перебор) | Established RU («криминалистический анализ данных»); «форензика» is specialist jargon. |
| imaged phone (full image) | полный образ памяти | «Образ» is the standard RU term for a disk/memory image. |
| data at rest | хранящиеся данные / всё, что хранится на устройстве | «Данные в состоянии покоя» is a calque; MS/Google RU use «данные при хранении»/«хранящиеся данные». |
| AFU / BFU | AFU (Latin, untranslated) | No RU rendering exists; forensic acronym, kept as in the English UI. |
| proxy | — (not surfaced in ru UI text) | n/a |
| push | push-уведомление, push-сервер, сигнал пробуждения (for the contentless wake) | Term-sheet loanword; Google/Apple RU use «push-уведомления». |
| token | — (not surfaced in ru UI text) | n/a |
| endpoint | конечная точка (`адрес вашей конечной точки`) | Microsoft/Mozilla RU push docs; «эндпоинт» is dev slang. |
| proof of work | доказательство работы | RU Wikipedia title («Доказательство работы»). |
| jailbreak | джейлбрейк | Established RU loanword. |
| root (rooted device) | получены root-права | What RU banking/security apps say. «Рутировано» was slangy → changed. |
| rate limit | — (not surfaced in ru UI text) | n/a |
| entropy / salt / KDF | ключ формируется с помощью Argon2id (KDF described, not named) | «Формирование ключа» is the standard RU rendering of key derivation; Argon2 is glossary. |
| padding | дополнение до одинакового/фиксированного размера | Established RU crypto term («дополнение»); the UI's «выравнивание по размеру» was harmonized to it so UI and store agree. |
| metadata | (described: «кто, когда, сколько») | The copy never uses the bare word; no change needed. |
| sideload / build without Google services | сборка без сервисов Google / в этой сборке нет сервисов Google | Matches the English, no calque needed. |
| UnifiedPush distributor | дистрибьютор (приложение-дистрибьютор) | The RU ntfy/UnifiedPush/F-Droid community says «дистрибьютор»; «распространитель» reads as a distributor of goods and is a calque. Changed in 11 strings. |
| Web Push / VAPID / RFC 8291 | Latin, untranslated | Protocol names. |
| pairing (contact exchange) | сопряжение / выполнить сопряжение | Android RU Bluetooth vocabulary. Reflexive «сопрячься с кем-то» reads odd → «выполнить сопряжение с». |
| authenticate (a push wake) | проверить подлинность | «Подтвердить» = confirm, which is weaker and inaccurate. |
| whistleblower | информатор | RU Wikipedia («Информатор, англ. whistleblower»). Store copy. |
| on the wire | в сетевом трафике | «По сети» is ambiguous; «в сетевом трафике» is what RU security copy uses. |

### Non-jargon decisions made in the same pass

- **conversation vs chat:** EN *conversation* → **беседа**, EN *chat* → **чат**.
  «Разговор» eliminated from the UI (was only in `contact_list_reset_relay_message`
  and `about_ready_body`). `common_conversation_interrupted` keeps «Переписка
  прервана» — a standalone banner where «переписка» reads best; flagged below.
- **timings (of a protection tier):** «таймеры» (already used by the store copy),
  not «тайминги» (gamer slang) and not «временные настройки» (would read as
  *temporary* settings).
- **Register:** formal **вы**, lowercase mid-sentence — unchanged and consistent
  in every file after the sweep.
- **Quotes:** « » throughout, including tier names and quoted UI labels.
- **Gender:** no gendered past tense/participle left on an unknown-gender
  placeholder or on the user. Fixed: `report_abuse_email_body` («имя, которое я
  дал ему» → «имя, под которым он записан»), `gate_lock_countdown_tap_to_stay`
  («остаться разблокированным» → the app stays unlocked), the passphrase
  strength meter (masculine → feminine, agreeing with «парольная фраза»).
- **Singular "they":** Russian has none. «их/они» for one contact replaced with
  «контакт»/«этот контакт»/«его» (agreeing with the masculine noun «контакт») in
  `add_contact_*`, `contact_list_waiting_for_inbox`, `referral_offer_message`.
- **Plurals:** ru needs CLDR **few** and **many**; both plurals shipped one/other
  only, so 2–4 fell back to the genitive-plural «other» («2 контактов»). Added
  few/many to `contact_list_repair_banner` and `group_info_members`.

### Notification-carousel sweep (2026-09-11)

The opt-in carousel was cut to three pages + the switch; these are the renderings
used across `notif_edu_*` and `notif_edu_up_*` in this locale.

| English term | ru rendering |
| --- | --- |
| wake / wake signal (contentless push) | **сигнал пробуждения** |
| distributor (UnifiedPush) | **приложение-дистрибьютор** / *дистрибьютор* |
| push address | **push-адрес** |
| timestamps (of incoming messages) | **временные метки** |

### Connect-screen sweep (2026-09-11)

The runestone ring/`R` reveal, the live connection log and the anonymous
connect-time report (`ConnectTelemetry`) — renderings used in
`about_tor_runestone_body`, `connect_log_title` and the 1.6.17 What's New.

| English term | ru rendering |
| --- | --- |
| ring (of the runestone) | **кольцо** (кольцо рунического камня) |
| the R (glyph that lights last) | **буква R** (никогда голое «R» в кириллице) |
| live connection log | **Журнал подключений** |
| connect-time report (seconds only, nothing identifying) | *сообщает ретранслятору лишь число секунд* |

### Introduction-relay modal sweep (2026-09-13)

The introducer-side modal (`referral_relayed_*`, ReferralManager.onIntroRelayed).
Hard rule in every locale: the *complete* variant must NOT say the two are now
connected — the introducer never learns that. Render "each now has what they
need to reach the other", and keep the privacy line ("you have no part in their
conversation and cannot read it") plain and literal.

| English term | ru rendering |
| --- | --- |
| Introduction accepted / complete (modal titles) | **Знакомство подтверждено** / **Знакомство завершено** |
| connection details | **данные для связи** |
| pass on / passed on | **передать дальше** / *переданы дальше* |
| each now has what they need to reach the other | *у каждого есть всё нужное, чтобы связаться с другим* |
| next time you open the app | *при следующем открытии приложения* |

- The approval is written in the **present tense** — *%1$s принимает ваше
  предложение познакомиться с %2$s* — per the gender rule above; *подтвердил(а)*
  is banned. The plural past (*%1$s и %2$s подтвердили*) carries no gender and is
  used for the "both approved" variant.
- `Знакомство завершено`, never *состоялось*: the introducer is not told the two
  actually connected.

### Debug-mode sweep (2026-09-14)

The opt-in anonymous diagnostic-log upload: settings row `settings_debug_mode` /
`settings_debug_mode_on` plus the consent dialog `debug_mode_title`,
`debug_mode_message`, `debug_mode_message_off`, `debug_mode_turn_on`,
`debug_mode_turn_off` (ContactListScreen.kt / ContactListView.swift, DebugMode.kt).
Hard rules in every locale: **"Debug mode" is a product term** — the settings row
and the dialog title must be byte-identical, and the on-state row is that term +
the locale's "(on)". The privacy promise in `debug_mode_message` stays **literal**:
"never include anything that identifies you or this device" followed by the five
explicit negations (names, message content, addresses, keys, inbox or contact ids).
Do not soften it to "minimal data", do not merge the five items, do not add claims.

| English term | ru rendering |
| --- | --- |
| Debug mode (row label + dialog title) | **Режим отладки** |
| Debug mode (on) | **Режим отладки (вкл.)** |
| diagnostic logs | **диагностические журналы** |
| log (noun) | **журнал** (cf. `connect_log_title` *Журнал подключений*) |
| Turn on / Turn off | **Включить** / **Выключить** |

- *Отладка* is the fully established native Russian term — no loanword needed.
- Buttons stay infinitive (*Включить* / *Выключить*), matching every other ru
  button; the prose keeps formal lowercase *вы*.
- The five negations keep the *ни … ни …* series; "ids" → **идентификаторы**;
  inbox → *почтовый ящик*.

### Ratchet-refusal notice sweep (2026-09-18)

See the shared rules in the `## en` section (`conversation_ratchet_refused_body`).

| English term | ru rendering |
| --- | --- |
| secure channel | **защищённый канал** |
| could not be established | Не удалось установить … |
| Messages are not being sent. | Сообщения не отправляются. |
| pair again | **выполните сопряжение заново** |

- *сопряжение* is the locale's pairing noun (`add_contact_cancel_pairing` «Отменить сопряжение», `contact_list_reset_relay_message` «повторное сопряжение»).
- «защищённый канал» is the standard RU term and does **not** collide with the tier «Защищённый», which is always guillemet-quoted and capitalised per this sheet; an unquoted lowercase adjective cannot be read as a tier reference.
- *канал*, not *подключение/соединение* (the relay-connection family). Formal **вы**, *Удалите* / *выполните*.

## mk — Macedonian

Play-only locale (no App Store Connect metadata locale).

- **Tiers:** Основно / Безбедно / Максимално — frozen, identical in UI and store copy.
- Play-only locale (Play code `mk`; `asc: null` — there is no App Store Connect
metadata locale, so no `appstore-*-mk` files exist and none should be written).
Store copy: `docs/store-listing/play-full-mk.txt`, `play-short-mk.txt`, `<mk>`
block of `whatsnew.txt`.

| concept | rendering |
| --- | --- |
| vault | трезор |
| relay | реле (in text almost always definite: *релето*) |
| runestone | рунски камен (*Набљудувајте го рунскиот камен*) |
| runes (conversation chrome) | руни (*Руните шепотат*, *Консултирање на руните…*) |
| passphrase | **тајна фраза** |
| protection level | Ниво на заштита |
| burn on read | Согорување по читање |
| vouched introduction | Препорачани запознавања (feature title only) |
| introduce (verb) | претстави / претставување |
| introduced by | Претставено од %1$s (bare badge: *Претставено*) |
| vouch (groups) | гарантира за |
| inbox | сандаче (pl. *сандачиња*) |
| device key | клуч на уредот (*клучот на уредот е зафатен*) |
| hardware key | хардверски клуч |
| hardware lock | хардверско заклучување |
| device passcode | код за пристап (на уредот) |
| screen lock / lock screen | заклучување на екранот |
| password (device screen-lock option only) | лозинка |
| recovery code | код за обновување |
| security chip | безбедносен чип |
| encrypt / decrypt | шифрира / дешифрира (*шифриран*, *шифрирање*) |
| personal memory (per-contact private note) | Лична белешка |
| reminder (only where English says "reminder") | потсетник |
| wake signal (push) | сигнал за будење |
| pair in person | спарување лично / спарени лично |
| notification (the generic alert title) | Известување |

- **Tiers:** Основно / Безбедно / Максимално — frozen, byte-identical in UI and
  store copy. Spliced into sentences **unquoted** (*Rún тука работи на
  Максимално*, *останува на %2$s засега*), unlike the ru sheet's guillemets.
  They also appear verbatim in prose (`about_forensic_body`,
  `protection_stop_no_lock`).
- **Register:** formal **вие / ваш**, written **lowercase mid-sentence**
  (capitalised only sentence-initially or when a string starts with it).
  Two-register split, applied consistently:
  - buttons, menu rows and one-word actions take the **short 2nd-person
    singular imperative**: *Претстави*, *Обнови*, *Испрати*, *Избриши*,
    *Ресетирај*, *Примени*, *Приклучи се*, *Отвори Поставки*;
  - headings, prompts, body copy and error text take the **polite plural**:
    *Внесете ја тековната тајна фраза*, *Проверете ја врската и обидете се
    повторно*, *вашиот телефон…*.
  - Consequence worth knowing: `pin_use_recovery_code` (button) is
    *Користи код за обновување* while `pin_use_recovery_code_prompt` (a full
    sentence) is *Не можете да отклучите? Користете код за обновување* — that
    is the rule working, not a drift.
- **Quotes:** „ … “ (low-high). Used for quoted UI labels („Пријави“,
  „Блокирај“, „Го запишав“, „Копирај пријава“), for group/contact names spliced
  via `%2$s`, for the generic alert „Известување“, and for linguistic mentions
  („rún“, „руна“, „согорување по читање“, „како што е“). No straight `"` and no
  guillemets anywhere in the locale.
- **Deliberate loanwords** (beyond the shared glossary): `push` (as
  *push-известување*, *push-сервер*, *Push-пораката*), `jailbreak`
  (`gate_compromised_body_jailbroken`), `endpoint` (*endpoint-адреса*, the
  UnifiedPush deep card). Initialism+noun compounds are **hyphenated**:
  `QR-код`, `IP-адреса`, `PIN-код`, `Google-услуги`, `Tor-сообраќај`,
  `Push-известувања`.
- **Rejected alternatives** (do not reintroduce — each one was a live split
  between the four area translators, reconciled 2026-09-02):
  - `сеф` for vault → **трезор**;
  - `пасфраза` and `лозинка` for passphrase → **тајна фраза**. `лозинка` is
    reserved for English *password*, which occurs exactly once
    (`protection_forced_explainer_cta_body_android`: "PIN, шема, лозинка или
    отпечаток");
  - `код за враќање` / *Врати* / *Се враќа…* for recovery → **код за
    обновување** / *Обнови* / *Се обновува…* (the verb *враќа* survives only in
    "ги враќа вашите пораки" = *restores your messages*);
  - `енкриптира` / `криптира` for encrypt → **шифрира** (it is the form that
    pairs with the already-universal *дешифрира*);
  - `изгори по читање` for burn on read → **согорување по читање**;
  - `заклучен екран` for the screen-lock term → **заклучување на екранот**
    (`protection_device_lock_term_android` is spliced into
    `protection_forced_notice_title` / `_body` / `protection_stop_no_lock`, so
    it fixes the wording in four other strings);
  - `Личен потсетник` for the contact note → **Лична белешка**;
  - `запознае` as the *introduce* verb → **претстави**. The noun *запознавања*
    survives only inside the frozen feature title *Препорачани запознавања*;
    everything else in the referral family is *претстави / претставување /
    Претставено*.
- **Gender:** contact aliases carry no gender and Macedonian participles do.
  Prefer the **aorist**, which is gender-neutral: *%1$s ја напушти групата*,
  *%1$s ве покани во групата „%2$s“*, *%1$s можеби направи слика од екранот*.
  Prefer plural or neuter agreement where the sentence allows it: *тие ќе бидат
  отстранети од вашата листа*, *Претставено од %1$s*. Where a passive participle
  is unavoidable, use the dual form: **%1$s беше отстранет/а од групата**
  (`group_notice_removed`) — Macedonian cannot use Russian's impersonal
  3rd-plural escape here, because obligatory object doubling would force a
  gendered clitic (*го/ја отстранија*).
- **Gendered placeholders:** `protection_credential_type_passphrase` (*тајна
  фраза*, fem.) and `_pin` (*PIN*, masc.) are spliced into
  `protection_recovery_entry_subtitle` and `protection_recovery_wrong_credential`.
  Never put a possessive or adjective in front of that `%1$s` — the subtitle
  reads *заедно со %1$s* (same solution as ru). Tier names spliced via `%1$s`
  are neuter, so *На %1$s му треба…* and *Без него…* both agree.
- **Clitics:** object clitics **precede** a finite verb (*Ја бара таа тајна
  фраза секој пат*, *Не ме потсетувај повторно*) and **follow** an imperative
  (*Прикажи го мојот код*, *Запишете го ова*). A sentence may not start with
  verb + clitic in the indicative.
- **Rún** is never inflected and never takes a Cyrillic ending; it keeps Latin
  script and its acute accent in all 69 occurrences (*на Rún*, *ја отворите
  Rún*).
- **Store-copy drift (open):** `play-full-mk.txt` predates this reconciliation —
  it still has `сеф` ×3 (*Вашиот сеф*, *клучот на сефот*, *Шифриран локален
  сеф*), five mid-sentence capitalised polite forms, and `QR код` unhyphenated.
  Tier names, *тајна фраза*, *релето*, *сандачиња* and *препорачани
  запознавања* already match. 340 characters of headroom under the Play 4000
  limit, so the `сеф → трезор` swap fits.

### Jargon (sweep 2026-09-03)

# mk (Macedonian) — jargon decisions, locale sweep 2026-09-03

Applies the project's jargon policy (2026-09-02): technical/security terms take
the rendering mainstream Macedonian apps/security writing use where one is
established; otherwise the English term stays (Latin script) as a loanword.
Never a literal calque.

Paste into the `## mk` section of `docs/l10n/terms.md`.

### Jargon

| English term | mk rendering | reason |
| --- | --- | --- |
| end-to-end encryption / end-to-end encrypted | шифрирање од крај до крај / шифриран од крај до крај | Established MK rendering (the policy's own example). Used verbatim in `about_e2e_title`, `eula_body`, `play-full-mk`, `play-short-mk`. |
| brute force (verb/noun) | разбивање со груба сила / да разбие со груба сила | Established MK phrase in security writing; "груба сила" is the standard calque-free rendering (unlike sv "råstyrka"). |
| forward secrecy | **forward secrecy** (English, Latin) | No established MK term; every candidate ("проследена тајност", "идна тајност") is an invented calque that misreads as *forwarded*. Kept English, matching the `Double Ratchet` already left English on the same store bullet. **Changed** from the previous "проследена тајност". |
| ratchet (the key ratchets forward) | постојано напредува / клучевите постојано напредуваат | No MK term for the cryptographic ratchet and the English word is opaque to MK readers in prose. Rendered as a plain description of the one-way forward movement, not a calque. The product name `Double Ratchet` stays English in the store bullet. |
| relay | реле (definite: релето) | Term-sheet decision, unchanged. |
| reach the relay | стигне / стигна до релето | Unified. "достигне" (attain) and "пристапи до" (access) were both in use; "стигне до" is the natural MK equivalent of *reach* for a network endpoint. |
| routed (through Tor) | насочен(о) преку Tor | `about_tor_intro_title` already used "Насочено"; the transliteration "рутиран" was dropped — it is a raw loan **and** collides with "рутиран" = *rooted* (see below). |
| hop (Tor hop) | скок (неколку скока) | Established MK networking term; counted plural form is correct. |
| onion / circuit / guard node / exit node / proxy / rate limit / entropy / salt / metadata / sideload / token | *not surfaced in mk copy* | No user-facing string uses them. If they appear later: keep `.onion` and `proxy` English, use "јазол" for node and "врска/патека" for circuit. |
| proof of work | доказ за работа | Established MK rendering in crypto/blockchain writing; not an ad-hoc calque. Kept in `add_contact_solving_pow`. |
| root / rooted (Android) | **root** (English) — *на овој уред е направен root* | Jargon policy: no established MK verb. "рутиран" was in use but is a raw transliteration that is ambiguous with *routed*. Now parallel to the jailbreak string. **Changed.** |
| jailbreak / jailbroken (iOS) | **jailbreak** (English) — *на овој уред е направен jailbreak* | Term-sheet loanword, unchanged. |
| push (notification/server/message) | **push** (English), hyphenated compounds: push-известувања, push-сервер, Push-пораката | Term-sheet loanword, unchanged. Extended to `notif_cross_ref_label_*` ("iOS push-известувања"), which had silently dropped *push*. |
| endpoint | **endpoint** (English) — endpoint-адреса | Term-sheet loanword, unchanged. |
| UnifiedPush distributor | дистрибутер (апликација-дистрибутер) | "дистрибутер" is the ordinary MK word and is what the UnifiedPush ecosystem uses in Slavic locales. |
| hardware-backed / hardware-bound | хардверски врзан / хардверски клуч / хардверско заклучување | Term-sheet decision, unchanged. Note the project rule that the device key is never called simply "hardware-backed" is respected — the mk copy mirrors the English hedging. |
| keystore / keychain | **Android Keystore** (English, product name) | Product name, glossary-style. No MK translation. |
| security chip (Secure Enclave / StrongBox, generically) | безбедносен чип | Term-sheet decision, unchanged. `Secure Enclave` itself stays Latin per the shared glossary. |
| passcode (device) | код за пристап | Term-sheet decision, unchanged (`protection_device_lock_term_ios`). |
| screen lock / lock screen | заклучување на екранот | Term-sheet decision, unchanged (`protection_device_lock_term_android`). |
| biometric / biometrics | биометриски / биометрија | Established MK loan-derived term, fully naturalised. |
| wipe (verb/noun) | брише / бришење (*се брише сам*, *Бришењето ги уништува самите клучеви*) | Ordinary MK verb; no better term exists and "wipe" is not recognisable in MK. |
| crypto-erase | *(paraphrased)* бришењето ги уништува самите клучеви | No MK term; the mechanism is stated instead, matching the English "a wipe erases the keys themselves". |
| forensic tool / forensic attack / forensically imaged | форензичка алатка / форензички напад / (форензички) снимен телефон | "форензички" is the established MK adjective; "снимен" for *imaged* is the ordinary word for a bit-for-bit copy. |
| AFU / BFU | **AFU** (English initialism) | No MK expansion exists; the English initialism is what forensic literature uses. Unchanged. |
| at rest | во мирување (also: складирано) | "во мирување" is the established MK rendering of *at rest* and was already used in `gate_passcode_warning_message`. |
| key derivation (KDF) | клучот се изведува (со Argon2id) | "изведување на клуч" is the standard MK phrasing; `Argon2` stays Latin per the glossary. |
| padding (message padding) | дополнување / дополнети (блокови) | Established MK rendering; not a calque. |
| offline | офлајн | Fully naturalised MK loanword. |
| timer (auto-lock/self-wipe timers) | тајмер / тајмери | Fully naturalised MK loanword (store copy). |
| timings (of a protection tier) | временски интервали | **Changed** from "временски рокови" — *рок* means *deadline*, which is wrong for auto-lock/re-auth intervals. |
| timing (traffic-timing profile) | темпирање / временски профил | "темпирање" is a real MK noun for *timing*; kept, used consistently across the three notification-education strings. |
| app switcher / recent-apps preview | преглед на неодамнешни апликации (2nd mention: листа на неодамнешни апликации) | **Changed** — the previous "пребарувач на апликации" means *app browser/search*, which is factually wrong for the Android app switcher. |
| mint (an inbox on the relay) | ковање (*Ковањето не успеа*) | Left as-is: it keeps the English metaphor and the string is a developer-facing failure prefix. **Flagged as unsure** — see report; "Поставувањето на сандачето не успеа" would be clearer to end users. |
| messenger (the app category) | месинџер (store short description only); elsewhere: апликација за пораки | "месинџер" is an established MK loan in tech press (ru uses "мессенджер"). Used only in `play-short-mk.txt`, where the 80-char budget could not fit "апликација за пораки" plus the load-bearing "од крај до крај". |
| feed (public feed) | фид | Established MK loan for a content feed (`eula_body`). |
| vault / inbox / runestone / passphrase / recovery code / protection level / burn on read / vouched introduction | *see the `## mk` term-sheet table* | Product vocabulary, not jargon; unchanged by this sweep. |

### Cross-cutting decision recorded by this sweep

**Rún takes MASCULINE agreement in Macedonian**, everywhere. It was split
(7 masculine vs 9 feminine sites) because half the copy silently substituted
*апликацијата* (fem). Masculine is fixed by `about_ready_body`
("Rún — тивок, приватен и ваш") and by the tip/donate strings
("го одржува Rún бесплатен и независен"), and is the default for an
unanalysable foreign proper noun. All feminine sites were converted:
*го отворите Rún*, *го отклучувате*, *го заштити Rún*, *Rún, кој ги презема*,
*Оставен … испратен … Rún се заклучува*, *се брише сам*.
Predicate agreement with an explicit head noun is unaffected
(`eula_body`: "Rún е приватна апликација…" stays feminine — it agrees with
*апликација*, not with *Rún*).

### Notification-carousel sweep (2026-09-11)

The opt-in carousel was cut to three pages + the switch; these are the renderings
used across `notif_edu_*` and `notif_edu_up_*` in this locale.

| English term | mk rendering |
| --- | --- |
| wake / wake signal (contentless push) | **сигнал за будење** (confirmed) |
| distributor (UnifiedPush) | **апликацијата-дистрибутер** / *дистрибутерот* |
| push address | **push-адреса** |
| timestamps (of incoming messages) | **временски ознаки** |

### Connect-screen sweep (2026-09-11)

The runestone ring/`R` reveal, the live connection log and the anonymous
connect-time report (`ConnectTelemetry`) — renderings used in
`about_tor_runestone_body`, `connect_log_title` and the 1.6.17 What's New.

| English term | mk rendering |
| --- | --- |
| ring (of the runestone) | **прстен** (прстенот на рунскиот камен) |
| the R (glyph that lights last) | **буквата R** (никогаш само „R“ во кирилица) |
| live connection log | **Дневник на поврзување** |
| connect-time report (seconds only, nothing identifying) | *му јавува на релето само колку секунди траело* |

### Introduction-relay modal sweep (2026-09-13)

The introducer-side modal (`referral_relayed_*`, ReferralManager.onIntroRelayed).
Hard rule in every locale: the *complete* variant must NOT say the two are now
connected — the introducer never learns that. Render "each now has what they
need to reach the other", and keep the privacy line ("you have no part in their
conversation and cannot read it") plain and literal.

| English term | mk rendering |
| --- | --- |
| Introduction accepted / complete (modal titles) | **Претставувањето е одобрено** / **Претставувањето е завршено** |
| connection details | **податоци за поврзување** |
| pass on / passed on | **проследи** / *се проследени* |
| each now has what they need to reach the other | *секој има сè што му треба за да стигне до другиот* |
| next time you open the app | *следниот пат кога ќе ја отворите апликацијата* |

- The approval uses the **aorist** (*го одобри*, *одобрија*) — gender-neutral,
  per the rule above. Rún keeps masculine agreement (*Rún не можеше … ќе ги
  проследи*).

### Debug-mode sweep (2026-09-14)

The opt-in anonymous diagnostic-log upload: settings row `settings_debug_mode` /
`settings_debug_mode_on` plus the consent dialog `debug_mode_title`,
`debug_mode_message`, `debug_mode_message_off`, `debug_mode_turn_on`,
`debug_mode_turn_off` (ContactListScreen.kt / ContactListView.swift, DebugMode.kt).
Hard rules in every locale: **"Debug mode" is a product term** — the settings row
and the dialog title must be byte-identical, and the on-state row is that term +
the locale's "(on)". The privacy promise in `debug_mode_message` stays **literal**:
"never include anything that identifies you or this device" followed by the five
explicit negations (names, message content, addresses, keys, inbox or contact ids).
Do not soften it to "minimal data", do not merge the five items, do not add claims.

| English term | mk rendering |
| --- | --- |
| Debug mode (row label + dialog title) | **Режим за дебагирање** (def. *Режимот за дебагирање*) |
| Debug mode (on) | **Режим за дебагирање (вклучен)** |
| diagnostic logs | **дијагностички дневници** |
| log (noun) | **дневник** (cf. `connect_log_title` *Дневник на поврзување*) |
| Turn on / Turn off | **Вклучи** / **Исклучи** |

- **Open decision (flag):** the loanword *дебагирање* was chosen over Google mk's
  native *отстранување грешки*. Two reasons: (1) "removing errors" mis-describes a
  switch that only uploads logs, and (2) *Режим за отстранување грешки (вклучен)* is
  38 characters in a settings menu where no other row exceeds ~20. Revisit if a
  reviewer prefers the Google wording — it would change all five prose strings.
- Buttons stay short singular imperatives (*Вклучи* / *Исклучи*), like every other
  mk button (*Откажи*, *Избриши*); the prose keeps formal *вие*.
- The five negations keep the *ниту … ниту …* series; "ids" → **идентификатори**;
  inbox → *сандаче* (pl. *сандачиња*).

### Ratchet-refusal notice sweep (2026-09-18)

See the shared rules in the `## en` section (`conversation_ratchet_refused_body`).

| English term | mk rendering |
| --- | --- |
| secure channel | **безбеден канал** |
| could not be established | Не можеше да се воспостави … |
| Messages are not being sent. | Пораките не се испраќаат. |
| pair again | **спарете се повторно** |

- *спарување / спарете се* is the term-sheet pairing lexeme (*pair in person* → *спарување лично*, `contact_list_reset_relay_message` *повторно да се спарите*).
- Body copy ⇒ polite plural (*Избришете го контактот и спарете се повторно*), per the two-register split.
- Lowercase *безбеден* does not collide with the tier *Безбедно* (neuter, capitalised, frozen). *канал*, not *врска* — *врска* is the relay connection.

