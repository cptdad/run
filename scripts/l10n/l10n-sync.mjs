#!/usr/bin/env node
// scripts/l10n/l10n-sync.mjs — translation DRIFT tracker + translator fan-out
// plumbing for Rún's localization. Zero npm deps (Node core only, runs on
// the pinned node@22 and the default node alike); reuses gen-l10n.mjs's
// strict strings_*.xml parser.
//
// Problem it solves: values/strings_*.xml (English) is the source of truth
// for 12 target locales, and docs/store-listing/*-en.txt (+ the <en> block of
// whatsnew.txt) is the source of truth for the store copy. The JVM validator
// (L10nResourcesTest) catches a MISSING key, but nothing caught a STALE one:
// edit an English value and the nine translations silently keep the old
// meaning. The lock file scripts/l10n/l10n.lock.json records, per locale and
// key, the hash of the English value each translation was made from, so
// drift becomes a checkable fact instead of a memory exercise.
//
// Commands:
//   status [--check] [--json]      per-locale missing / stale / unlocked /
//                                  extra counts (strings, plurals, store).
//                                  --check exits 1 on anything ≠ 0 → pre-push.
//   tasks <dir> [--locales a,b]    write one translation brief per locale
//                                  (<dir>/<l>.brief.md + <dir>/<l>.todo.json)
//                                  plus the shared <dir>/RULES.md — the input
//                                  for the per-locale translators.
//   apply <dir> [--locales a,b]    read <dir>/<l>.json (the translators' output),
//                                  validate every value (placeholders,
//                                  glossary, Rún inflection, newlines, store
//                                  limits), splice into the locale XML /
//                                  store files IN SOURCE ORDER, re-parse to
//                                  prove the round-trip, relock, then run the
//                                  generators. --no-generate skips the last.
//   relock [--locales a,b] [--keys k1,k2] [--store]
//                                  accept the CURRENT translations as matching
//                                  the CURRENT English (typo-only English
//                                  edits, hand-written translations).
//
// Never call an LLM from here: this script is deterministic. The translating
// is done by translators working from the briefs `tasks` emits.
"use strict";

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import {
  LOCALES,
  REPO_ROOT,
  RES_DIR,
  L10nError,
  localeDirName,
  loadLocale,
  parseStringsXml,
} from "./gen-l10n.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const LOCK_FILE = path.join(REPO_ROOT, "scripts/l10n/l10n.lock.json");
const STORE_DIR = path.join(REPO_ROOT, "docs/store-listing");
// The public snapshot ships no store copy (docs/store-listing is private). When the
// directory is absent every store target is treated as not applicable: status/lint/
// tasks/apply cover the app strings only and say so once.
const STORE_PRESENT = fs.existsSync(STORE_DIR);
const WHATSNEW = path.join(STORE_DIR, "whatsnew.txt");
const GEN_L10N = path.join(__dirname, "gen-l10n.mjs");
const GEN_STORE = path.join(__dirname, "gen-store-metadata.py");
const GEN_PLAY_CSV = path.join(__dirname, "gen-play-listing-csv.py");

const TARGET_LOCALES = LOCALES.filter((l) => l !== "en");

// suffix -> console locales + display name. asc === null ⇒ Play-only (App
// Store Connect has no metadata locale for it). KEEP IN SYNC with
// gen-store-metadata.py LOCALES and the table in docs/store-listing/README.md;
// `status` fails closed if a LOCALES entry has no row here.
const LOCALE_INFO = {
  sv: { asc: "sv", play: "sv-SE", name: "Swedish" },
  de: { asc: "de-DE", play: "de-DE", name: "German" },
  fr: { asc: "fr-FR", play: "fr-FR", name: "French" },
  es: { asc: "es-ES", play: "es-ES", name: "Spanish (Spain)" },
  nb: { asc: "no", play: "no-NO", name: "Norwegian Bokmål" },
  da: { asc: "da", play: "da-DK", name: "Danish" },
  fi: { asc: "fi", play: "fi-FI", name: "Finnish" },
  ar: { asc: "ar-SA", play: "ar", name: "Arabic", rtl: true }, // ASC Arabic = ar-SA, Play = ar
  fa: { asc: null, play: "fa", name: "Persian (Farsi)", rtl: true },
  // play === null too ⇒ app-only language: neither console has a metadata
  // locale for it (checked against fastlane's deliver/supply language lists),
  // so it has NO store targets at all — UI strings only.
  so: { asc: null, play: null, name: "Somali" },
  ru: { asc: "ru", play: "ru-RU", name: "Russian" },
  mk: { asc: null, play: "mk-MK", name: "Macedonian" }, // Play only (no ASC locale)
};

// Store targets: id -> how the English source and each locale's copy are read.
//   file:  docs/store-listing/<id>-<suffix>.txt
//   block: <suffix>…</suffix> block inside whatsnew.txt
//   line:  "<asc-locale>: value" line inside docs/store-listing/<file>
// ascOnly targets are skipped for Play-only locales.
const STORE_TARGETS = [
  { id: "play-short", kind: "file", limit: 80, label: "Play short description" },
  { id: "play-full", kind: "file", limit: 4000, label: "Play full description" },
  { id: "whatsnew", kind: "block", limit: 500, label: "What's New bullets (both stores; Play caps at 500)" },
  { id: "appstore-full", kind: "file", limit: 4000, ascOnly: true, label: "App Store description" },
  { id: "play-title", kind: "line", file: "play-title.txt", limit: 30, key: "play", label: "Play title" },
  { id: "appstore-name", kind: "line", file: "appstore-name.txt", limit: 30, ascOnly: true, label: "App Store name" },
  { id: "appstore-subtitle", kind: "line", file: "appstore-subtitle.txt", limit: 30, ascOnly: true, label: "App Store subtitle" },
  { id: "appstore-keywords", kind: "line", file: "appstore-keywords.txt", limit: 100, ascOnly: true, label: "App Store keywords" },
];

// Never translated (brand/protocol names). Present in the English ⇒ must be
// present verbatim in the translation. Boundaries are LATIN letters only so
// Arabic/Persian clitics ("وRún") and punctuation pass.
const GLOSSARY = [
  "Rún", "Tor", "PIN", "QR", "Face ID", "Touch ID", "Secure Enclave", "SQLCipher",
  "Monero", "Bitcoin", "FCM", "APNs", "UnifiedPush", "ntfy", "Argon2", "Orbot",
];
const LATIN = "A-Za-zÀ-ɏ";
const TIER_KEYS = ["protection_tier_name_casual", "protection_tier_name_private", "protection_tier_name_maximum"];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function die(message) {
  console.error(`l10n-sync: ${message}`);
  process.exit(1);
}

function sha(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex").slice(0, 16);
}

function hashPlural(items) {
  const entries = (items instanceof Map ? [...items.entries()] : Object.entries(items)).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return sha(JSON.stringify(entries));
}

function sortKeysDeep(value) {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = sortKeysDeep(value[k]);
    return out;
  }
  return value;
}

function rel(p) {
  return path.relative(REPO_ROOT, p);
}

function norm(text) {
  return text.replace(/\r\n/g, "\n").trim();
}

function parseArgs(argv) {
  const positional = [];
  const opts = { locales: null, keys: null, check: false, json: false, store: false, noGenerate: false, split: 1 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--check") opts.check = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--store") opts.store = true;
    else if (a === "--no-generate") opts.noGenerate = true;
    else if (a === "--split") opts.split = Math.max(1, Number(argv[++i] ?? 1) || 1);
    else if (a === "--locales") opts.locales = (argv[++i] ?? "").split(",").filter(Boolean);
    else if (a.startsWith("--locales=")) opts.locales = a.slice(10).split(",").filter(Boolean);
    else if (a === "--keys") opts.keys = (argv[++i] ?? "").split(",").filter(Boolean);
    else if (a.startsWith("--keys=")) opts.keys = a.slice(7).split(",").filter(Boolean);
    else if (a.startsWith("--")) die(`unknown option ${a}`);
    else positional.push(a);
  }
  if (opts.locales) {
    for (const l of opts.locales) if (!TARGET_LOCALES.includes(l)) die(`unknown locale "${l}" (known: ${TARGET_LOCALES.join(",")})`);
  }
  return { positional, opts };
}

function selectedLocales(opts) {
  return opts.locales ?? TARGET_LOCALES;
}

// ---------------------------------------------------------------------------
// Lock file
// ---------------------------------------------------------------------------

// Lock shape (version 2) — one entry per English key, so `git diff` of the
// lock reads as "which English text changed":
//   { strings: { <key>: { en, ok, at, prev? } }, plurals: {…}, store: {…} }
//   en   = English snapshot the `ok` locales were translated from
//   ok   = comma-joined locales whose translation is locked to hash(en)
//   at   = { locale: hash } for locales locked to an OLDER English
//   prev = the previous English text (kept only while `at` is non-empty, so
//          a stale brief can show "was: …")
function loadLock() {
  if (!fs.existsSync(LOCK_FILE)) return { version: 2, strings: {}, plurals: {}, store: {} };
  let lock;
  try {
    lock = JSON.parse(fs.readFileSync(LOCK_FILE, "utf8"));
  } catch (e) {
    die(`${rel(LOCK_FILE)} is not valid JSON: ${e.message}`);
  }
  if (lock.version !== 2) die(`${rel(LOCK_FILE)}: unsupported version ${lock.version} (delete it and run \`relock\`)`);
  lock.strings ??= {};
  lock.plurals ??= {};
  lock.store ??= {};
  return lock;
}

function saveLock(lock) {
  const out = sortKeysDeep({
    version: 2,
    _comment:
      "GENERATED by scripts/l10n/l10n-sync.mjs — do not hand-edit. Per English key: `en` = the English " +
      "text the `ok` locales were translated from; `at` = locales still locked to an older English (hash); " +
      "`prev` = that older text. Update with `apply` (after translating) or `relock` (accept as-is).",
    strings: lock.strings,
    plurals: lock.plurals,
    store: lock.store,
  });
  fs.writeFileSync(LOCK_FILE, JSON.stringify(out, null, 2) + "\n", "utf8");
}

function hashOf(section, en) {
  return section === "plurals" ? hashPlural(en) : sha(en);
}

function okList(entry) {
  return entry.ok ? entry.ok.split(",").filter(Boolean) : [];
}

// The English hash this locale's translation is locked to, or undefined.
function lockedHash(lock, section, key, locale) {
  const e = lock[section][key];
  if (!e) return undefined;
  if (okList(e).includes(locale)) return hashOf(section, e.en);
  return e.at?.[locale];
}

// Record: <locale>'s translation of <key> now matches the CURRENT English.
function setLocked(lock, section, key, locale, enCurrent) {
  const hCur = hashOf(section, enCurrent);
  let e = lock[section][key];
  if (!e) e = lock[section][key] = { en: enCurrent, ok: "", at: {} };
  e.at ??= {};
  const hOld = hashOf(section, e.en);
  if (hCur !== hOld) {
    for (const loc of okList(e)) e.at[loc] = hOld;
    e.prev = e.en;
    e.en = enCurrent;
    e.ok = "";
  }
  delete e.at[locale];
  e.ok = [...new Set([...okList(e), locale])].sort().join(",");
  if (Object.keys(e.at).length === 0) {
    delete e.at;
    delete e.prev;
  }
}

function wasText(lock, section, key, locale) {
  const e = lock[section][key];
  if (!e) return undefined;
  if (okList(e).includes(locale)) return e.en; // English moved on, lock did not
  if (e.prev !== undefined && e.at?.[locale] === hashOf(section, e.prev)) return e.prev;
  return undefined;
}

function pruneLock(lock, model) {
  for (const key of Object.keys(lock.strings)) if (!model.en.strings.has(key)) delete lock.strings[key];
  for (const key of Object.keys(lock.plurals)) if (!model.en.plurals.has(key)) delete lock.plurals[key];
  for (const id of Object.keys(lock.store)) if (!STORE_TARGETS.some((t) => t.id === id)) delete lock.store[id];
}

// ---------------------------------------------------------------------------
// Model: English + locale XML trees, store texts
// ---------------------------------------------------------------------------

// Ordered [{type, name, file}] scan of the English tree (file order, comments
// stripped) — parseStringsXml's Maps keep insertion order per type but we need
// strings and plurals interleaved for stable insertion anchors.
function scanEnOrder(enFiles) {
  const order = [];
  for (const f of enFiles) {
    const text = fs.readFileSync(path.join(RES_DIR, "values", f), "utf8").replace(/<!--[\s\S]*?-->/g, "");
    const re = /<(string|plurals)\s+name="([^"]+)"/g;
    let m;
    while ((m = re.exec(text))) order.push({ type: m[1], name: m[2], file: f });
  }
  return order;
}

function loadModel() {
  for (const l of TARGET_LOCALES) if (!LOCALE_INFO[l]) die(`LOCALES has "${l}" but LOCALE_INFO has no row for it — add one (and to gen-store-metadata.py + README)`);
  let en;
  try {
    en = loadLocale("en");
  } catch (e) {
    if (e instanceof L10nError) die(e.message);
    throw e;
  }
  if (!en) die("androidApp/src/main/res/values/ is missing");
  const enOrder = scanEnOrder(en.files);
  const enFileOf = new Map(enOrder.map((o) => [`${o.type}:${o.name}`, o.file]));
  const locales = new Map();
  for (const l of TARGET_LOCALES) {
    try {
      locales.set(l, loadLocale(l));
    } catch (e) {
      if (e instanceof L10nError) die(e.message);
      throw e;
    }
  }
  return { en, enOrder, enFileOf, locales, store: loadStore() };
}

function readStoreFile(name) {
  const p = path.join(STORE_DIR, name);
  return fs.existsSync(p) ? norm(fs.readFileSync(p, "utf8")) : undefined;
}

function readBlock(text, suffix) {
  const m = new RegExp(`^<${suffix}>\\n([\\s\\S]*?)\\n</${suffix}>`, "m").exec(text);
  return m ? norm(m[1]) : undefined;
}

function readLine(text, asc) {
  const m = new RegExp(`^${asc.replace(/[-]/g, "\\-")}:[ \\t]*(.*)$`, "m").exec(text);
  return m ? m[1].trim() : undefined;
}

function storeSourceFor(target, suffix, asc) {
  if (target.kind === "file") return readStoreFile(`${target.id}-${suffix}.txt`);
  if (target.kind === "block") return fs.existsSync(WHATSNEW) ? readBlock(fs.readFileSync(WHATSNEW, "utf8"), suffix) : undefined;
  if (target.kind === "line") {
    const p = path.join(STORE_DIR, target.file);
    return fs.existsSync(p) ? readLine(fs.readFileSync(p, "utf8"), asc) : undefined;
  }
  throw new Error(`bad target kind ${target.kind}`);
}

function applicableTargets(locale) {
  if (!STORE_PRESENT) return [];
  const info = LOCALE_INFO[locale];
  if (info.play === null) return []; // app-only language: no store copy anywhere
  return STORE_TARGETS.filter((t) => !(t.ascOnly && info.asc === null));
}

// Line-keyed store files are keyed by the STORE's locale code: App Store Connect's
// (en-GB, ar-SA, …) by default, Play's (en-US, sv-SE, …) for targets with key: "play".
function lineKeyFor(target, locale) {
  const info = LOCALE_INFO[locale];
  return target.key === "play" ? info.play : info.asc;
}

function loadStore() {
  const en = {};
  if (!STORE_PRESENT) {
    console.error("l10n-sync: docs/store-listing not present — store copy skipped (app strings only)");
    return { en, locales: new Map(TARGET_LOCALES.map((l) => [l, {}])) };
  }
  for (const t of STORE_TARGETS) {
    const v = storeSourceFor(t, "en", t.key === "play" ? "en-US" : "en-GB"); // ASC English = en-GB (the app's primary ASC locale); Play = en-US
    if (v === undefined) die(`docs/store-listing: English source for "${t.id}" not found`);
    en[t.id] = v;
  }
  const locales = new Map();
  for (const l of TARGET_LOCALES) {
    const m = {};
    for (const t of applicableTargets(l)) m[t.id] = storeSourceFor(t, l, lineKeyFor(t, l));
    locales.set(l, m);
  }
  return { en, locales };
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

function computeStatus(model, lock) {
  const result = {};
  for (const l of TARGET_LOCALES) {
    const data = model.locales.get(l);
    const r = {
      strings: { missing: [], stale: [], unlocked: [], extra: [] },
      plurals: { missing: [], stale: [], unlocked: [], extra: [] },
      store: { missing: [], stale: [], unlocked: [] },
    };
    for (const [key, entry] of model.en.strings) {
      const h = lockedHash(lock, "strings", key, l);
      if (!data || !data.strings.has(key)) r.strings.missing.push(key);
      else if (h === undefined) r.strings.unlocked.push(key);
      else if (h !== sha(entry.value)) r.strings.stale.push(key);
    }
    for (const [key, items] of model.en.plurals) {
      const h = lockedHash(lock, "plurals", key, l);
      if (!data || !data.plurals.has(key)) r.plurals.missing.push(key);
      else if (h === undefined) r.plurals.unlocked.push(key);
      else if (h !== hashPlural(items)) r.plurals.stale.push(key);
    }
    if (data) {
      for (const key of data.strings.keys()) if (!model.en.strings.has(key)) r.strings.extra.push(key);
      for (const key of data.plurals.keys()) if (!model.en.plurals.has(key)) r.plurals.extra.push(key);
    }
    const st = model.store.locales.get(l);
    for (const t of applicableTargets(l)) {
      const h = lockedHash(lock, "store", t.id, l);
      if (st[t.id] === undefined) r.store.missing.push(t.id);
      else if (h === undefined) r.store.unlocked.push(t.id);
      else if (h !== sha(model.store.en[t.id])) r.store.stale.push(t.id);
    }
    result[l] = r;
  }
  return result;
}

function countProblems(r) {
  let n = 0;
  for (const sec of Object.values(r)) for (const list of Object.values(sec)) n += list.length;
  return n;
}

// Delta = what a translation run must produce: missing + stale + unlocked
// (an unlocked translation was never recorded against any English, so it is
// re-translated unless someone `relock`s it first).
function delta(sec) {
  return [...sec.missing, ...sec.stale, ...(sec.unlocked ?? [])];
}

function hasDelta(r) {
  return delta(r.strings).length + delta(r.plurals).length + delta(r.store).length > 0;
}

function printStatus(status) {
  const fmt = (sec, withExtra) => {
    const parts = [`${sec.missing.length} missing`, `${sec.stale.length} stale`];
    if (sec.unlocked.length) parts.push(`${sec.unlocked.length} UNLOCKED`);
    if (withExtra && sec.extra.length) parts.push(`${sec.extra.length} EXTRA`);
    return parts.join(", ");
  };
  console.log(`l10n-sync status — ${model_summary()}`);
  let total = 0;
  for (const l of TARGET_LOCALES) {
    const r = status[l];
    const n = countProblems(r);
    total += n;
    const mark = n === 0 ? "✓" : "✗";
    console.log(
      `  ${mark} ${l.padEnd(3)} strings: ${fmt(r.strings, true).padEnd(26)} plurals: ${fmt(r.plurals, true).padEnd(22)} store: ${fmt(r.store, false)}`,
    );
    const detail = (label, list) => {
      if (list.length) console.log(`        ${label}: ${list.slice(0, 12).join(", ")}${list.length > 12 ? ` … (+${list.length - 12})` : ""}`);
    };
    detail("missing strings", r.strings.missing);
    detail("stale strings", r.strings.stale);
    detail("unlocked strings", r.strings.unlocked);
    detail("extra strings", r.strings.extra);
    detail("missing plurals", r.plurals.missing);
    detail("stale plurals", r.plurals.stale);
    detail("unlocked plurals", r.plurals.unlocked);
    detail("extra plurals", r.plurals.extra);
    detail("missing store", r.store.missing);
    detail("stale store", r.store.stale);
    detail("unlocked store", r.store.unlocked);
  }
  return total;
}

let _modelSummary = "";
function model_summary() {
  return _modelSummary;
}

// ---------------------------------------------------------------------------
// Briefs (tasks)
// ---------------------------------------------------------------------------

function firstComment(file) {
  const text = fs.readFileSync(path.join(RES_DIR, "values", file), "utf8");
  const m = /<!--([\s\S]*?)-->/.exec(text);
  return m ? m[1].split("\n").map((s) => s.trim()).filter(Boolean).join(" ") : "";
}

function show(value) {
  // Display a value with its newlines/tabs visible; JSON-escaped so the translator
  // sees EXACTLY what it must reproduce structurally.
  return JSON.stringify(value);
}

function rulesMarkdown() {
  return `# Rún translation rules (shared by every locale brief)

You are translating ONE locale's delta for Rún, a privacy messenger for Android + iOS.
Deliverable: write \`<dir>/<locale>.json\` with the exact shape of \`<dir>/<locale>.todo.json\`,
every empty value filled in. Do NOT edit any repository file — the sync tool splices your
JSON into the XML / store files, escapes it, validates it, and rejects anything off-spec.

## Values are PLAIN TEXT (the tool does the XML escaping)
- Write natural text. No \`\\'\`, no \`&amp;\`, no XML — the tool escapes quotes, ampersands, <, >.
- Where the English contains a real line break, your value must contain the SAME NUMBER of
  line breaks (JSON \`\\n\`). Line breaks are layout (carousel pages, dialogs), not prose.
- Placeholders are positional and must appear verbatim, same set as the English:
  \`%1$s\`, \`%2$d\`, … ; \`%%\` is a literal percent sign. Reorder them if grammar needs it.
- Never start a value with \`@\` or \`?\` (Android resource-reference syntax).
- One value per key; no leading/trailing whitespace; no trailing period added or removed
  unless the English has it.

## Glossary — NEVER translated, keep the Latin spelling and casing
Rún, Tor, PIN, QR, Face ID, Touch ID, Secure Enclave, SQLCipher, Monero, Bitcoin, FCM,
APNs, UnifiedPush, ntfy, Orbot, Argon2, and every credit/licence name. **\`Rún\` is never
inflected** — no genitive like "Rúns"/"Rún's"; rephrase ("the Rún relay" → "the relay of
Rún" or an equivalent your language allows). Arabic/Persian keep these names in Latin script.

## Technical / security jargon — English (or the locale's established loanword) by default
Terms like brute force, end-to-end encryption, forward secrecy, ratchet, relay, onion,
circuit, guard/exit node, hardware-backed, keystore, keychain, passcode, biometric, wipe,
crypto-erase, forensic extraction, AFU/BFU, proxy, push, token, endpoint, proof of work,
jailbreak/root, rate limit, entropy, salt, key derivation, padding, metadata, sideload:
keep the English term (or the loanword mainstream security apps already use in that
language) UNLESS the language has a well-established native equivalent used by Signal /
WhatsApp / Apple / Google localizations. Never coin a literal calque ("brute force" →
Swedish "råstyrka" is WRONG; keep "brute force"; German "Brute-Force-Angriff" and French
"chiffrement de bout en bout" are established and fine). When in doubt, English.

## Translated terms — use the locale's EXISTING wording (shown in the brief)
Protection tier names (Decent / Secure / Maximum), relay, runestone, vault, passphrase,
protection level, burn on read. The brief lists the tier names already used in this locale;
reuse them exactly. Match the register (formal/informal "you") of the neighbouring existing
translations shown with each item.

## Style
- Short imperatives, mobile-UI length. German/Finnish: aim for ≤ ~130 % of the English
  length in \`strings_common\` / \`strings_onboarding\` (buttons, keypad, dialogs).
- Norwegian = Bokmål. Spanish = Spain. Arabic = Modern Standard Arabic. Persian = Iranian
  Persian (no Arabic-only letters ة, and no Persian letters پچژگ in Arabic).
- Plurals: give \`one\` and \`other\` (add your language's other CLDR forms only if the
  todo lists them). Twin keys ending \`_android\` / \`_ios\` are BOTH translated.
- Stale items show the previous English (\`was:\`, or a paragraph \`diff\` for long store texts)
  and the current translation: make the smallest edit that reflects the English change; don't
  rewrite what didn't change.
- Budget: read RULES.md, your brief and your todo ONCE, write your answer ONCE. The term sheet
  for your locale is at the END of your brief. Never count characters — every limit is stated
  with the numbers you need, and \`apply\` measures exactly. Report in at most three lines
  (items filled, anything unsure) — no restating of the brief, no per-item narration.

## Store copy (if the todo has a "store" section)
- A stale long description may arrive as paragraph UNITS (\`"play-full": { "units": { "7": "…" } }\`
  in the todo): translate ONLY the listed units (the tool keeps every other paragraph's
  current translation) and answer in that exact shape; a unit is one paragraph or one bullet
  line — keep it one unit (no added blank lines).
- \`play-short\` ≤ 80 chars. \`play-full\` / \`appstore-full\` ≤ 4000 chars.
- \`whatsnew\` = bullets only, each line starting with \`• \`, ≤ 500 chars total, no header.
- \`play-title\` ≤ 30 chars: the Google Play app TITLE, keyed by the PLAY locale (en-US, sv-SE, fa, mk-MK…). Same
  shape as the App Store name: literal \`Rún – \` (en dash) + the language's short noun phrase for "private
  messenger" — REUSE your \`appstore-name\` wording where that locale has one; fa/mk coin it from the subtitle noun.
- \`appstore-name\` ≤ 30 chars: the App Store NAME — keep the literal prefix \`Rún – \` (en dash) and
  follow it with the language's natural short noun phrase for "private messenger" (reuse the head
  noun of your \`appstore-subtitle\`; never repeat "Tor"). It is what people see under the icon.
- \`appstore-subtitle\` ≤ 30 chars, no superlatives. \`appstore-keywords\` ≤ 100 chars,
  comma-separated, NO space after commas, don't repeat "Rún".
- App Store texts never mention Android/Google; Play texts may name Google's push servers
  (FCM). Keep the platform deltas exactly as the English source does.
- No unverifiable superlatives, no hard timer numbers, no "no third-party SDKs", no decoy
  PIN — mirror the English claims, never add claims.
`;
}

function neighbours(model, locale, type, name, radius = 2) {
  const idx = model.enOrder.findIndex((o) => o.type === type && o.name === name);
  if (idx < 0) return [];
  const data = model.locales.get(locale);
  const out = [];
  for (let d = -radius; d <= radius; d++) {
    if (d === 0) continue;
    const o = model.enOrder[idx + d];
    if (!o || o.type !== "string" || o.file !== model.enOrder[idx].file) continue;
    const en = model.en.strings.get(o.name)?.value;
    const tr = data?.strings.get(o.name)?.value;
    if (en === undefined || tr === undefined) continue;
    out.push({ key: o.name, en, tr });
  }
  return out;
}

// Balance one locale's area files into `split` groups by item count so a
// full-language job (422 keys) runs as several parallel translators with
// disjoint output files (<l>.partN.json); `apply` merges the parts.
function partitionAreas(byFile, split) {
  const entries = [...byFile.entries()].sort((a, b) => b[1].length - a[1].length);
  const groups = Array.from({ length: Math.max(1, split) }, () => ({ files: [], n: 0 }));
  for (const [file, items] of entries) {
    const g = groups.reduce((min, x) => (x.n < min.n ? x : min), groups[0]);
    g.files.push(file);
    g.n += items.length;
  }
  return groups.filter((g) => g.files.length).map((g) => g.files.sort());
}

// Per-locale term sheet (vault, relay, tier names, register, …) maintained by
// the localization lead; appended to every brief so independent translator
// translators share one vocabulary.
const TERMS_FILE = path.join(REPO_ROOT, "docs/l10n/terms.md");

// Token budget (2026-09-03): the term sheet is ~115 KB for 12 locales. A translator
// only needs the preamble, the English (source) section and ITS OWN locale's
// section — everything else was ~25k tokens of dead weight re-read on every turn.
function termsForLocale(locale) {
  if (!fs.existsSync(TERMS_FILE)) return "";
  const parts = fs.readFileSync(TERMS_FILE, "utf8").split(/^(?=## )/m);
  return parts.filter((p, i) => i === 0 || /^## en\b/.test(p) || new RegExp(`^## ${escRe(locale)}\\b`).test(p)).join("");
}

// Paragraph-level diff of the English (old → new) for long store texts, so a stale
// 4000-char description ships as a handful of changed lines instead of two full
// copies. LCS over lines (≤ ~60 lines); unchanged runs are elided to "…".
function lineDiff(oldText, newText) {
  const a = oldText.split("\n"), b = newText.split("\n");
  const n = a.length, m = b.length;
  const L = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i][j] = a[i] === b[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  const hunks = []; let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { hunks.push([" ", a[i]]); i++; j++; }
    else if (L[i + 1][j] >= L[i][j + 1]) { hunks.push(["-", a[i]]); i++; }
    else { hunks.push(["+", b[j]]); j++; }
  }
  while (i < n) hunks.push(["-", a[i++]]);
  while (j < m) hunks.push(["+", b[j++]]);
  const keep = new Set();
  hunks.forEach(([t], k) => { if (t !== " ") { keep.add(k - 1); keep.add(k); keep.add(k + 1); } });
  const out = []; let gap = false;
  hunks.forEach(([t, text], k) => {
    if (keep.has(k)) { out.push(`${t} ${text}`); gap = false; }
    else if (!gap) { out.push("  …"); gap = true; }
  });
  return out.join("\n");
}

// Units of a long store text: blank-line-separated paragraphs, with a block whose
// lines are all bullets ("- " / "• ") split per bullet. `sep` is the separator that
// PRECEDES the unit, so joinUnits(splitUnits(t)) === t.trimEnd().
function splitUnits(text) {
  const blocks = text.replace(/\s+$/, "").split(/\n{2,}/);
  const units = [];
  blocks.forEach((blk, bi) => {
    const lines = blk.split("\n");
    const isBullet = (ln) => /^(- |• )/.test(ln);
    // A bullet list — optionally under a one-line header ("Key features:") — splits per line.
    const listFrom = lines.length > 1 && lines.slice(1).every(isBullet) && (isBullet(lines[0]) || /:\s*$/.test(lines[0])) ? 0 : -1;
    if (listFrom === 0) lines.forEach((ln, li) => units.push({ text: ln, sep: li === 0 ? (bi === 0 ? "" : "\n\n") : "\n" }));
    else units.push({ text: blk, sep: bi === 0 ? "" : "\n\n" });
  });
  return units;
}
function joinUnits(units) { return units.map((u) => u.sep + u.text).join(""); }

// LCS alignment of unit texts: returns newIndex -> oldIndex (or -1 when the unit is
// new/changed) so an unchanged paragraph carries its translation forward untouched.
function alignUnits(oldUnits, newUnits) {
  const a = oldUnits.map((u) => u.text), b = newUnits.map((u) => u.text);
  const n = a.length, m = b.length;
  const L = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i][j] = a[i] === b[j] ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
  const map = new Array(m).fill(-1); let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { map[j] = i; i++; j++; }
    else if (L[i + 1][j] >= L[i][j + 1]) i++;
    else j++;
  }
  return map;
}

// For a changed new unit j, the old unit it most plausibly replaced: the first old
// unit between the previous and next anchors that no new unit maps to.
function replacedOldUnit(map, j, oldCount) {
  let prev = -1; for (let k = j - 1; k >= 0; k--) if (map[k] >= 0) { prev = map[k]; break; }
  let next = oldCount; for (let k = j + 1; k < map.length; k++) if (map[k] >= 0) { next = map[k]; break; }
  const used = new Set(map.filter((x) => x >= 0));
  for (let k = j - 1; k >= 0 && map[k] < 0; k--) { /* earlier changed siblings claim earlier old units */ }
  const siblingsBefore = (() => { let c = 0; for (let k = j - 1; k >= 0 && map[k] < 0; k--) c++; return c; })();
  const candidates = []; for (let o = prev + 1; o < next; o++) if (!used.has(o)) candidates.push(o);
  return candidates[siblingsBefore] ?? -1;
}

// Rebuild a whole locale text from a per-unit answer: unchanged units keep their
// current translation (aligned through the OLD English), changed/new ones come from
// the answer. Returns { text } or { error }.
function assembleUnits(oldEn, newEn, curLocale, answered) {
  const oldU = splitUnits(oldEn), newU = splitUnits(newEn), curU = splitUnits(curLocale);
  if (oldU.length !== curU.length) return { error: `current translation has ${curU.length} paragraph units but the English it was made from has ${oldU.length} — answer with the whole text instead of units` };
  const map = alignUnits(oldU, newU);
  const out = [];
  for (let j = 0; j < newU.length; j++) {
    const given = answered[String(j)];
    if (typeof given === "string" && given.trim() !== "") out.push({ text: given.trim(), sep: newU[j].sep });
    else if (map[j] >= 0) out.push({ text: curU[map[j]].text, sep: newU[j].sep });
    else return { error: `unit ${j} is new or changed but the answer has no "units"["${j}"]` };
  }
  return { text: joinUnits(out) };
}

function writeTasks(dir, model, lock, status, locales, split = 1) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "RULES.md"), rulesMarkdown(), "utf8");
  const index = [];
  for (const l of locales) {
    const r = status[l];
    if (!hasDelta(r)) continue;
    const info = LOCALE_INFO[l];
    const data = model.locales.get(l);
    const statusOf = (sec, name) =>
      sec.missing.includes(name) ? "missing" : sec.stale.includes(name) ? "stale" : sec.unlocked?.includes(name) ? "unlocked" : null;

    // Collect the work in English source order, then split it into parts.
    const byFile = new Map();
    for (const o of model.enOrder) {
      const st = statusOf(o.type === "string" ? r.strings : r.plurals, o.name);
      if (!st) continue;
      if (!byFile.has(o.file)) byFile.set(o.file, []);
      byFile.get(o.file).push({ type: o.type, name: o.name, status: st });
    }
    const storeItems = applicableTargets(l).map((t) => ({ t, st: statusOf(r.store, t.id) })).filter((x) => x.st);
    const groups = split > 1 ? partitionAreas(byFile, split) : [[...byFile.keys()]];
    if (!groups.length) groups.push([]); // store-only delta
    const tiers = TIER_KEYS.map((k) => `${k.replace("protection_tier_name_", "")} = ${show(data?.strings.get(k)?.value ?? "(missing)")} (en ${show(model.en.strings.get(k)?.value ?? "")})`);

    groups.forEach((files, gi) => {
      const isLast = gi === groups.length - 1;
      const label = groups.length > 1 ? `${l}.part${gi + 1}` : l;
      const todo = { locale: l, strings: {}, plurals: {}, store: {} };
      const lines = [];
      lines.push(`# Translation brief — ${info.name} (\`${l}\`)${info.rtl ? " — RTL script" : ""}${groups.length > 1 ? ` — part ${gi + 1} of ${groups.length}` : ""}`);
      lines.push("");
      lines.push(`Read \`RULES.md\` first. Write your answer to \`${label}.json\` (same shape as \`${label}.todo.json\`).`);
      lines.push("");
      lines.push(`Protection tier names already used in this locale: ${tiers.join("; ")}.`);
      lines.push("");
      let itemCount = 0;
      for (const file of files) {
        lines.push(`## ${file}`);
        const hdr = firstComment(file);
        if (hdr) lines.push(`_${hdr}_`);
        lines.push("");
        for (const it of byFile.get(file)) {
          itemCount++;
          if (it.type === "string") {
            const en = model.en.strings.get(it.name).value;
            todo.strings[it.name] = "";
            lines.push(`### \`${it.name}\` (${it.status === "unlocked" ? "stale — never locked, re-check against the English" : it.status})`);
            lines.push(`- en: ${show(en)}`);
            if (it.status !== "missing") {
              const oldEn = wasText(lock, "strings", it.name, l);
              if (oldEn !== undefined) lines.push(`- was: ${show(oldEn)}`);
              lines.push(`- current ${l}: ${show(data.strings.get(it.name).value)}`);
            }
            const ctx = neighbours(model, l, "string", it.name);
            if (ctx.length) lines.push(`- context: ${ctx.map((c) => `\`${c.key}\` ${show(c.en)} → ${show(c.tr)}`).join("; ")}`);
          } else {
            const items2 = model.en.plurals.get(it.name);
            todo.plurals[it.name] = Object.fromEntries([...items2.keys()].map((q) => [q, ""]));
            lines.push(`### \`${it.name}\` (plurals, ${it.status})`);
            for (const [q, v] of items2) lines.push(`- en ${q}: ${show(v)}`);
            if (it.status !== "missing" && data.plurals.get(it.name)) {
              const oldEn = wasText(lock, "plurals", it.name, l);
              if (oldEn !== undefined) for (const [q, v] of Object.entries(oldEn)) lines.push(`- was ${q}: ${show(v)}`);
              for (const [q, v] of data.plurals.get(it.name)) lines.push(`- current ${l} ${q}: ${show(v)}`);
            }
          }
          lines.push("");
        }
      }
      if (isLast && storeItems.length) {
        lines.push(`## Store copy (docs/store-listing)`);
        lines.push("");
        for (const { t, st } of storeItems) {
          itemCount++;
          todo.store[t.id] = "";
          lines.push(`### \`${t.id}\` (${st}) — ${t.label}, limit ${t.limit} chars`);
          const oldEn = st !== "missing" ? wasText(lock, "store", t.id, l) : undefined;
          const cur = st !== "missing" ? model.store.locales.get(l)[t.id] : undefined;
          const oldU = oldEn !== undefined ? splitUnits(oldEn) : null;
          const curU = cur !== undefined ? splitUnits(cur) : null;
          if (t.kind === "file" && oldU && curU && oldU.length === curU.length) {
            // Long text, aligned: ship only the changed paragraph UNITS, answered per unit.
            const newU = splitUnits(model.store.en[t.id]);
            const map = alignUnits(oldU, newU);
            const changed = newU.map((_, j) => j).filter((j) => map[j] < 0);
            const grow = model.store.en[t.id].length - oldEn.length;
            const need = Math.max(0, Math.ceil(grow * 1.2) - (t.limit - cur.length));
            todo.store[t.id] = { units: Object.fromEntries(changed.map((j) => [String(j), ""])) };
            lines.push(`- Answer form: \`"${t.id}": { "units": { "<index>": "<translated unit>" } }\` — ONLY the units below (the tool keeps every other paragraph's current translation). You may add other indices only to tighten wording for space.`);
            lines.push(`- numbers: current ${l} = ${cur.length} chars · limit ${t.limit} · headroom ${t.limit - cur.length} · English delta ${grow >= 0 ? "+" : ""}${grow} chars${need > 0 ? ` → save at least ~${need} chars (tighten the units below first, then other indices; never drop a bullet or a claim)` : " → fits without trimming"}. Do NOT count characters — apply measures exactly.`);
            lines.push(`- unit index map (English, first words): ${newU.map((u, j) => `${j}=“${u.text.slice(0, 32)}${u.text.length > 32 ? "…" : ""}”`).join("  ")}`);
            for (const j of changed) {
              const o = replacedOldUnit(map, j, oldU.length);
              lines.push(`#### unit ${j}${o >= 0 ? " (changed)" : " (new)"}`);
              lines.push("- en:");
              lines.push("```");
              lines.push(newU[j].text);
              lines.push("```");
              if (o >= 0) {
                lines.push("- was:");
                lines.push("```");
                lines.push(oldU[o].text);
                lines.push("```");
                lines.push(`- current ${l}:`);
                lines.push("```");
                lines.push(curU[o].text);
                lines.push("```");
              }
            }
            if (need > 0) {
              lines.push(`- other units' current ${l} text (index → text), for optional tightening:`);
              lines.push("```");
              newU.forEach((_, j) => { if (map[j] >= 0) lines.push(`${j}: ${curU[map[j]].text}`); });
              lines.push("```");
            }
          } else {
            lines.push("- en:");
            lines.push("```");
            lines.push(model.store.en[t.id]);
            lines.push("```");
            if (oldEn !== undefined) {
              lines.push("- was:");
              lines.push("```");
              lines.push(oldEn);
              lines.push("```");
            }
            if (cur !== undefined) {
              lines.push(`- current ${l}:`);
              lines.push("```");
              lines.push(cur);
              lines.push("```");
            }
          }
          lines.push("");
        }
      }
      const terms = termsForLocale(l);
      if (terms) {
        lines.push("---");
        lines.push("");
        lines.push(`# Term sheet for ${l} (docs/l10n/terms.md — use these renderings verbatim)`);
        lines.push("");
        lines.push(terms.trimEnd());
      }
      fs.writeFileSync(path.join(dir, `${label}.brief.md`), lines.join("\n") + "\n", "utf8");
      fs.writeFileSync(path.join(dir, `${label}.todo.json`), JSON.stringify(todo, null, 2) + "\n", "utf8");
      index.push({ locale: l, part: label, name: info.name, items: itemCount, brief: `${label}.brief.md`, todo: `${label}.todo.json`, answer: `${label}.json` });
    });
  }
  fs.writeFileSync(path.join(dir, "index.json"), JSON.stringify({ generatedAt: new Date().toISOString(), parts: index }, null, 2) + "\n", "utf8");
  return index;
}

// ---------------------------------------------------------------------------
// Validation of translator output
// ---------------------------------------------------------------------------

function placeholderSig(value) {
  const found = [];
  let pct = 0;
  const re = /%(\d+)\$([sd])|%%/g;
  let m;
  while ((m = re.exec(value))) {
    if (m[0] === "%%") pct++;
    else found.push(`%${m[1]}$${m[2]}`);
  }
  return { ph: found.sort().join(" "), pct };
}

function glossaryProblems(en, tr) {
  const problems = [];
  for (const term of GLOSSARY) {
    const re = new RegExp(`(?<![${LATIN}])${term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![${LATIN}])`, "u");
    if (re.test(en) && !re.test(tr)) problems.push(`glossary term "${term}" from the English is missing (never translate it)`);
  }
  if (/Rún(?=[A-Za-zÀ-ɏ])/u.test(tr)) problems.push(`"Rún" is inflected (e.g. "Rúns") — rephrase, Rún is never declined`);
  return problems;
}

// allowFewerPlaceholders: CLDR exact-number plural forms (zero/one/two) may
// spell the number out instead of formatting it ("عضوان", "En kontakt"), so
// a placeholder may be dropped there — never added.
function validateText(en, tr, ctx, warnings, { allowFewerPlaceholders = false } = {}) {
  const problems = [];
  if (typeof tr !== "string") return [`${ctx}: value is not a string`];
  if (tr.trim() === "") return [`${ctx}: empty value`];
  if (tr !== tr.trim()) warnings.push(`${ctx}: leading/trailing whitespace trimmed`);
  const t = tr.trim();
  if (/^[@?]/.test(t)) problems.push(`${ctx}: value starts with "${t[0]}" (Android resource-reference syntax) — rephrase`);
  const a = placeholderSig(en);
  const b = placeholderSig(t);
  if (allowFewerPlaceholders) {
    const enSet = new Set(a.ph.split(" ").filter(Boolean));
    const extra = b.ph.split(" ").filter((p) => p && !enSet.has(p));
    if (extra.length) problems.push(`${ctx}: placeholders not in the English: [${extra.join(" ")}]`);
  } else if (a.ph !== b.ph) problems.push(`${ctx}: placeholders differ — en [${a.ph || "none"}] vs [${b.ph || "none"}]`);
  if (a.pct !== b.pct) problems.push(`${ctx}: literal %% count differs (en ${a.pct}, got ${b.pct})`);
  // Strip every valid token first (%N$s / %N$d / %%), then any % left over is
  // malformed — a lookahead regex mis-flags the SECOND % of "%%" at end of string.
  if (/%/.test(t.replace(/%\d+\$[sd]|%%/g, ""))) problems.push(`${ctx}: malformed/bare % placeholder`);
  const nlA = (en.match(/\n/g) ?? []).length;
  const nlB = (t.match(/\n/g) ?? []).length;
  if (nlA !== nlB) problems.push(`${ctx}: line-break count differs (en ${nlA}, got ${nlB}) — line breaks are layout`);
  for (const p of glossaryProblems(en, t)) problems.push(`${ctx}: ${p}`);
  if (/&(amp|lt|gt|quot|apos);|\\'|\\"/.test(t)) problems.push(`${ctx}: contains XML/Android escaping — write plain text, the tool escapes`);
  if (t.length > Math.max(40, en.length * 2.5)) warnings.push(`${ctx}: ${t.length} chars vs en ${en.length} (>2.5×) — check it fits`);
  return problems;
}

// ---------------------------------------------------------------------------
// XML splicing (in source order, round-trip verified)
// ---------------------------------------------------------------------------

function encodeAndroid(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\\/g, "\\\\")
    .replace(/\n/g, "\\n")
    .replace(/\t/g, "\\t")
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"');
}

function escRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function elementRegex(type, name) {
  return type === "string"
    ? new RegExp(`([ \\t]*)<string name="${escRe(name)}"([^>]*)>([\\s\\S]*?)</string>`)
    : new RegExp(`([ \\t]*)<plurals name="${escRe(name)}"([^>]*)>[\\s\\S]*?</plurals>`);
}

function renderElement(type, name, value, indent, attrs = "") {
  if (type === "string") return `${indent}<string name="${name}"${attrs}>${encodeAndroid(value)}</string>`;
  const inner = [...value.entries()].map(([q, v]) => `${indent}    <item quantity="${q}">${encodeAndroid(v)}</item>`).join("\n");
  return `${indent}<plurals name="${name}"${attrs}>\n${inner}\n${indent}</plurals>`;
}

// changes: Map("string:key" | "plurals:key" -> value | Map(q->v))
function spliceXml(locale, file, changes, model) {
  const filePath = path.join(RES_DIR, localeDirName(locale), file);
  if (!fs.existsSync(filePath)) die(`${rel(filePath)} does not exist — every locale must carry the same strings_*.xml file set as values/`);
  let text = fs.readFileSync(filePath, "utf8");
  const present = (type, name) => elementRegex(type, name).test(text);
  const fileOrder = model.enOrder.filter((o) => o.file === file);

  for (const o of fileOrder) {
    const id = `${o.type}:${o.name}`;
    if (!changes.has(id)) continue;
    const value = changes.get(id);
    const re = elementRegex(o.type, o.name);
    const m = re.exec(text);
    if (m) {
      const indent = m[1];
      const attrs = m[2] ?? "";
      text = text.slice(0, m.index) + renderElement(o.type, o.name, value, indent, attrs) + text.slice(m.index + m[0].length);
      continue;
    }
    // Insert: after the nearest preceding English key present in this file,
    // else before the nearest following one, else before </resources>.
    const idx = fileOrder.indexOf(o);
    let anchor = null;
    for (let i = idx - 1; i >= 0; i--) if (present(fileOrder[i].type, fileOrder[i].name)) { anchor = { o: fileOrder[i], after: true }; break; }
    if (!anchor) for (let i = idx + 1; i < fileOrder.length; i++) if (present(fileOrder[i].type, fileOrder[i].name)) { anchor = { o: fileOrder[i], after: false }; break; }
    if (anchor) {
      const am = elementRegex(anchor.o.type, anchor.o.name).exec(text);
      const indent = am[1] || "    ";
      const el = renderElement(o.type, o.name, value, indent);
      if (anchor.after) {
        const end = am.index + am[0].length;
        text = text.slice(0, end) + "\n" + el + text.slice(end);
      } else {
        text = text.slice(0, am.index) + el + "\n" + text.slice(am.index);
      }
    } else {
      const close = text.lastIndexOf("</resources>");
      if (close < 0) die(`${rel(filePath)}: no </resources>`);
      text = text.slice(0, close) + renderElement(o.type, o.name, value, "    ") + "\n" + text.slice(close);
    }
  }

  // Round-trip proof BEFORE touching disk: the strict parser must read back
  // exactly the values we intended.
  let parsed;
  try {
    parsed = parseStringsXml(text, rel(filePath));
  } catch (e) {
    if (e instanceof L10nError) die(`splice produced invalid XML for ${rel(filePath)}: ${e.message}`);
    throw e;
  }
  for (const [id, value] of changes) {
    const [type, name] = id.split(":");
    if (type === "string") {
      const got = parsed.strings.get(name)?.value;
      if (got !== value) die(`round-trip mismatch for ${name} in ${rel(filePath)}: wrote ${show(value)}, parsed ${show(got)}`);
    } else {
      const got = parsed.plurals.get(name);
      if (!got) die(`round-trip: plurals ${name} missing after splice in ${rel(filePath)}`);
      for (const [q, v] of value) if (got.get(q) !== v) die(`round-trip mismatch for plurals ${name}[${q}] in ${rel(filePath)}`);
    }
  }
  fs.writeFileSync(filePath, text, "utf8");
  return filePath;
}

// ---------------------------------------------------------------------------
// Store splicing
// ---------------------------------------------------------------------------

function writeStoreTarget(locale, target, value) {
  const info = LOCALE_INFO[locale];
  if (target.kind === "file") {
    const p = path.join(STORE_DIR, `${target.id}-${locale}.txt`);
    fs.writeFileSync(p, value + "\n", "utf8");
    return p;
  }
  if (target.kind === "block") {
    let text = fs.readFileSync(WHATSNEW, "utf8");
    const block = `<${locale}>\n${value}\n</${locale}>`;
    const re = new RegExp(`^<${locale}>\\n[\\s\\S]*?\\n</${locale}>`, "m");
    if (re.test(text)) {
      text = text.replace(re, block);
    } else {
      // Insert after the previous locale (in LOCALES order) that has a block.
      let inserted = false;
      const order = LOCALES;
      for (let i = order.indexOf(locale) - 1; i >= 0; i--) {
        const prev = new RegExp(`^<${order[i]}>\\n[\\s\\S]*?\\n</${order[i]}>`, "m").exec(text);
        if (prev) {
          const end = prev.index + prev[0].length;
          text = text.slice(0, end) + "\n\n" + block + text.slice(end);
          inserted = true;
          break;
        }
      }
      if (!inserted) text = text.replace(/\s*$/, "") + "\n\n" + block + "\n";
    }
    if (!text.endsWith("\n")) text += "\n";
    fs.writeFileSync(WHATSNEW, text, "utf8");
    return WHATSNEW;
  }
  if (target.kind === "line") {
    const p = path.join(STORE_DIR, target.file);
    let text = fs.readFileSync(p, "utf8");
    const key = lineKeyFor(target, locale);
    const line = `${(key + ":").padEnd(7)}${value}`;
    const re = new RegExp(`^${escRe(key)}:[ \\t]*.*$`, "m");
    if (re.test(text)) {
      text = text.replace(re, line);
    } else {
      const lines = text.replace(/\s*$/, "").split("\n");
      let last = -1;
      for (let i = 0; i < lines.length; i++) if (/^[A-Za-z-]+:/.test(lines[i])) last = i;
      lines.splice(last + 1, 0, line);
      text = lines.join("\n") + "\n";
    }
    fs.writeFileSync(p, text, "utf8");
    return p;
  }
  throw new Error("bad target kind");
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

function cmdStatus(opts) {
  const model = loadModel();
  const lock = loadLock();
  _modelSummary = `${model.en.strings.size} strings + ${model.en.plurals.size} plurals × ${TARGET_LOCALES.length} locales, ${STORE_TARGETS.length} store targets`;
  const status = computeStatus(model, lock);
  if (opts.json) {
    console.log(JSON.stringify({ locales: status, delta: TARGET_LOCALES.filter((l) => hasDelta(status[l])) }, null, 2));
  }
  const total = opts.json ? Object.values(status).reduce((n, r) => n + countProblems(r), 0) : printStatus(status);
  if (total === 0) {
    if (!opts.json) console.log("l10n-sync: OK — every locale matches the current English source (strings, plurals, store copy).");
    return 0;
  }
  if (!opts.json) {
    console.log("");
    console.log("Next:");
    console.log("  node scripts/l10n/l10n-sync.mjs tasks <dir>     → briefs for the translators");
    console.log("  node scripts/l10n/l10n-sync.mjs apply <dir>     → splice + validate + relock + regenerate");
    console.log("  node scripts/l10n/l10n-sync.mjs relock …        → accept current translations as-is (typo-only English edits)");
  }
  return opts.check ? 1 : 0;
}

function cmdTasks(dir, opts) {
  if (!dir) die("tasks: missing <dir>");
  const model = loadModel();
  const lock = loadLock();
  const status = computeStatus(model, lock);
  const index = writeTasks(path.resolve(dir), model, lock, status, selectedLocales(opts), opts.split);
  if (!index.length) {
    console.log("l10n-sync tasks: nothing to translate (no missing/stale items for the selected locales).");
    return 0;
  }
  console.log(`l10n-sync tasks: ${index.length} brief(s) written to ${dir} (one translator per line)`);
  for (const e of index) console.log(`  ${e.part.padEnd(10)} ${e.name.padEnd(18)} ${String(e.items).padStart(4)} item(s)  → ${e.brief} / ${e.todo}  ⇒ answer in ${e.answer}`);
  return 0;
}

function cmdApply(dir, opts) {
  if (!dir) die("apply: missing <dir>");
  dir = path.resolve(dir);
  const model = loadModel();
  const lock = loadLock();
  const status = computeStatus(model, lock);
  const warnings = [];
  const touched = new Set();
  let storeTouched = false;
  let applied = 0;
  const leftovers = [];

  for (const l of selectedLocales(opts)) {
    const answerFiles = fs
      .readdirSync(dir)
      .filter((f) => f === `${l}.json` || (f.startsWith(`${l}.part`) && f.endsWith(".json") && !f.endsWith(".todo.json")))
      .sort();
    if (!answerFiles.length) continue;
    const answerLabel = answerFiles.join(", ");
    const answer = { locale: l, strings: {}, plurals: {}, store: {} };
    for (const f of answerFiles) {
      let part;
      try {
        part = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
      } catch (e) {
        die(`${f}: invalid JSON — ${e.message}`);
      }
      if (part.locale && part.locale !== l) die(`${f}: locale field is "${part.locale}", expected "${l}"`);
      for (const sec of ["strings", "plurals", "store"]) {
        for (const [k, v] of Object.entries(part[sec] ?? {})) {
          if (k in answer[sec]) die(`${f}: ${sec} "${k}" is also answered in another part of ${l} — parts must be disjoint`);
          answer[sec][k] = v;
        }
      }
    }
    const r = status[l];
    const problems = [];
    const wantStrings = new Set(delta(r.strings));
    const wantPlurals = new Set(delta(r.plurals));
    const wantStore = new Set(delta(r.store));

    // strings
    const byFile = new Map();
    const stringsIn = answer.strings ?? {};
    for (const [key, val] of Object.entries(stringsIn)) {
      if (!wantStrings.has(key)) {
        problems.push(`string "${key}" is not in this locale's delta (unexpected key) — refusing`);
        continue;
      }
      const en = model.en.strings.get(key).value;
      const p = validateText(en, val, `${l} ${key}`, warnings);
      if (p.length) {
        problems.push(...p);
        continue;
      }
      const file = model.enFileOf.get(`string:${key}`);
      if (!byFile.has(file)) byFile.set(file, new Map());
      byFile.get(file).set(`string:${key}`, val.trim());
    }
    // plurals
    const pluralsIn = answer.plurals ?? {};
    for (const [key, forms] of Object.entries(pluralsIn)) {
      if (!wantPlurals.has(key)) {
        problems.push(`plurals "${key}" is not in this locale's delta — refusing`);
        continue;
      }
      const enItems = model.en.plurals.get(key);
      if (!forms || typeof forms !== "object") {
        problems.push(`plurals "${key}": expected an object of quantity → text`);
        continue;
      }
      const out = new Map();
      let ok = true;
      for (const q of enItems.keys()) {
        if (!(q in forms)) {
          problems.push(`plurals "${key}": quantity "${q}" missing`);
          ok = false;
        }
      }
      for (const [q, v] of Object.entries(forms)) {
        if (!["zero", "one", "two", "few", "many", "other"].includes(q)) {
          problems.push(`plurals "${key}": unknown quantity "${q}"`);
          ok = false;
          continue;
        }
        const enRef = enItems.get(q) ?? enItems.get("other");
        const p = validateText(enRef, v, `${l} ${key}[${q}]`, warnings, { allowFewerPlaceholders: ["zero", "one", "two"].includes(q) });
        if (p.length) {
          problems.push(...p);
          ok = false;
        } else out.set(q, v.trim());
      }
      if (!ok) continue;
      const file = model.enFileOf.get(`plurals:${key}`);
      if (!byFile.has(file)) byFile.set(file, new Map());
      byFile.get(file).set(`plurals:${key}`, out);
    }
    // store
    const storeIn = answer.store ?? {};
    const storeWrites = [];
    for (let [id, val] of Object.entries(storeIn)) {
      if (val && typeof val === "object" && val.units && typeof val.units === "object") {
        const tgt = STORE_TARGETS.find((t) => t.id === id);
        const oldEn = tgt ? wasText(lock, "store", id, l) : undefined;
        const cur = model.store.locales.get(l)?.[id];
        if (!tgt || tgt.kind !== "file" || oldEn === undefined || cur === undefined) { problems.push(`store "${id}": a "units" answer needs an aligned current translation — return the whole text`); continue; }
        const built = assembleUnits(oldEn, model.store.en[id], cur, val.units);
        if (built.error) { problems.push(`store "${id}": ${built.error}`); continue; }
        val = built.text;
      }
      const target = STORE_TARGETS.find((t) => t.id === id);
      if (!target || !wantStore.has(id)) {
        problems.push(`store "${id}" is not in this locale's delta — refusing`);
        continue;
      }
      if (typeof val !== "string" || val.trim() === "") {
        problems.push(`store "${id}": empty`);
        continue;
      }
      const v = norm(val);
      if (v.length > target.limit) problems.push(`store "${id}": ${v.length} chars > limit ${target.limit}`);
      if (id === "whatsnew" && !v.split("\n").every((ln) => ln.startsWith("• "))) problems.push(`store "whatsnew": every line must start with "• "`);
      if (id === "appstore-keywords" && /,\s/.test(v)) problems.push(`store "appstore-keywords": no space after commas`);
      if (/\n/.test(v) && (target.kind === "line" || id === "play-short")) problems.push(`store "${id}": must be a single line`);
      for (const p of glossaryProblems(model.store.en[id], v)) problems.push(`store "${id}": ${p}`);
      if (id.startsWith("appstore") && /\b(Android|Google)\b/.test(v)) problems.push(`store "${id}": App Store copy must not mention Android/Google`);
      if (problems.length === 0 || !problems.some((p) => p.startsWith(`store "${id}"`))) storeWrites.push([target, v]);
    }

    if (problems.length) {
      console.error(`l10n-sync apply: ${answerLabel} REJECTED — nothing written for ${l}:`);
      for (const p of problems) console.error(`  - ${p}`);
      leftovers.push(l);
      continue;
    }

    // Write XML (per area file), then store, then relock exactly what we wrote.
    for (const [file, changes] of byFile) {
      touched.add(rel(spliceXml(l, file, changes, model)));
      for (const [id] of changes) {
        const [type, name] = id.split(":");
        if (type === "string") setLocked(lock, "strings", name, l, model.en.strings.get(name).value);
        else setLocked(lock, "plurals", name, l, Object.fromEntries(model.en.plurals.get(name)));
        applied++;
      }
    }
    for (const [target, v] of storeWrites) {
      touched.add(rel(writeStoreTarget(l, target, v)));
      setLocked(lock, "store", target.id, l, model.store.en[target.id]);
      storeTouched = true;
      applied++;
    }
    const remaining = [...wantStrings].filter((k) => !(k in stringsIn)).length + [...wantPlurals].filter((k) => !(k in pluralsIn)).length + [...wantStore].filter((k) => !(k in storeIn)).length;
    console.log(`l10n-sync apply: ${l} — ${Object.keys(stringsIn).length} strings, ${Object.keys(pluralsIn).length} plurals, ${storeWrites.length} store target(s) applied${remaining ? `; ${remaining} delta item(s) NOT in the answer (still pending)` : ""}`);
  }

  if (applied) saveLock(lock);
  for (const w of warnings) console.log(`  warn: ${w}`);
  if (touched.size) {
    console.log("files written:");
    for (const f of [...touched].sort()) console.log(`  ${f}`);
    console.log(`  ${rel(LOCK_FILE)}`);
  }
  if (applied && !opts.noGenerate) {
    runGenerators(storeTouched);
  }
  if (leftovers.length) {
    console.error(`l10n-sync apply: ${leftovers.length} locale answer(s) rejected: ${leftovers.join(", ")} — fix the JSON and re-run apply`);
    return 1;
  }
  if (!applied) {
    console.log(`l10n-sync apply: no <locale>.json answers found in ${dir}`);
  }
  return 0;
}

function runGenerators(storeTouched) {
  const node = process.execPath;
  console.log("regenerating: gen-l10n.mjs");
  execFileSync(node, [GEN_L10N], { stdio: "inherit", cwd: REPO_ROOT });
  if (storeTouched) {
    console.log("regenerating: gen-store-metadata.py + gen-play-listing-csv.py");
    execFileSync("python3", [GEN_STORE], { stdio: "inherit", cwd: REPO_ROOT });
    execFileSync("python3", [GEN_PLAY_CSV], { stdio: "inherit", cwd: REPO_ROOT });
  }
}

function cmdRelock(opts) {
  const model = loadModel();
  const lock = loadLock();
  const keyFilter = opts.keys ? new Set(opts.keys) : null;
  const onlyStore = opts.store && !opts.keys;
  const onlyKeys = !!opts.keys && !opts.store;
  let n = 0;
  for (const l of selectedLocales(opts)) {
    const data = model.locales.get(l);
    if (!onlyStore && data) {
      for (const [key, entry] of model.en.strings) {
        if (keyFilter && !keyFilter.has(key)) continue;
        if (!data.strings.has(key)) continue;
        setLocked(lock, "strings", key, l, entry.value);
        n++;
      }
      for (const [key, items] of model.en.plurals) {
        if (keyFilter && !keyFilter.has(key)) continue;
        if (!data.plurals.has(key)) continue;
        setLocked(lock, "plurals", key, l, Object.fromEntries(items));
        n++;
      }
    }
    if (!onlyKeys) {
      const st = model.store.locales.get(l);
      for (const t of applicableTargets(l)) {
        if (keyFilter && !keyFilter.has(t.id)) continue;
        if (st[t.id] === undefined) continue;
        setLocked(lock, "store", t.id, l, model.store.en[t.id]);
        n++;
      }
    }
  }
  pruneLock(lock, model);
  saveLock(lock);
  console.log(`l10n-sync relock: ${n} entr${n === 1 ? "y" : "ies"} locked to the current English → ${rel(LOCK_FILE)}`);
  return 0;
}

// `lint`: run the same value validators `apply` runs on INCOMING translations
// over everything already on disk. Added after the 2026-09-03 sweep found
// pre-existing "Rúns" genitives, a transliterated PIN and inflected glossary
// terms that nothing had ever checked. Exit 1 on any problem.
function cmdLint(opts) {
  const model = loadModel();
  const warnings = [];
  let problems = 0;
  for (const l of selectedLocales(opts)) {
    const data = model.locales.get(l);
    if (!data) continue;
    const found = [];
    for (const [key, enEntry] of model.en.strings) {
      const tr = data.strings.get(key)?.value;
      if (tr === undefined) continue;
      found.push(...validateText(enEntry.value, tr, key, warnings));
    }
    for (const [key, enItems] of model.en.plurals) {
      const items = data.plurals.get(key);
      if (!items) continue;
      for (const [q, v] of items) {
        const enRef = enItems.get(q) ?? enItems.get("other");
        found.push(...validateText(enRef, v, `${key}[${q}]`, warnings, { allowFewerPlaceholders: ["zero", "one", "two"].includes(q) }));
      }
    }
    const st = model.store.locales.get(l);
    for (const t of applicableTargets(l)) {
      const v = st[t.id];
      if (v === undefined) continue;
      if (v.length > t.limit) found.push(`store ${t.id}: ${v.length} chars > ${t.limit}`);
      for (const p of glossaryProblems(model.store.en[t.id], v)) found.push(`store ${t.id}: ${p}`);
      if (t.id.startsWith("appstore") && /\b(Android|Google)\b/.test(v)) found.push(`store ${t.id}: App Store copy mentions Android/Google`);
    }
    if (found.length) {
      console.log(`✗ ${l}: ${found.length} problem(s)`);
      for (const p of found) console.log(`    ${p}`);
      problems += found.length;
    } else console.log(`✓ ${l}`);
  }
  if (problems) {
    console.error(`l10n-sync lint: ${problems} problem(s) in existing translations`);
    return 1;
  }
  console.log("l10n-sync lint: OK — every existing translation passes the apply-time validators");
  return 0;
}

function usage() {
  console.log(
    [
      "usage: node scripts/l10n/l10n-sync.mjs <command> [options]",
      "  status [--check] [--json]",
      "  tasks <dir> [--locales a,b] [--split N]   (N parts per locale → N parallel agents)",
      "  apply <dir> [--locales a,b] [--no-generate]",
      "  relock [--locales a,b] [--keys k1,k2] [--store]",
      "  lint [--locales a,b]                       (apply-time validators over existing translations)",
    ].join("\n"),
  );
}

function main() {
  const { positional, opts } = parseArgs(process.argv.slice(2));
  const [cmd, arg] = positional;
  let code;
  switch (cmd) {
    case "status":
      code = cmdStatus(opts);
      break;
    case "tasks":
      code = cmdTasks(arg, opts);
      break;
    case "apply":
      code = cmdApply(arg, opts);
      break;
    case "relock":
      code = cmdRelock(opts);
      break;
    case "lint":
      code = cmdLint(opts);
      break;
    default:
      usage();
      code = cmd ? 2 : 0;
  }
  process.exit(code);
}

main();
