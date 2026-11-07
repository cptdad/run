#!/usr/bin/env node
// GENERATED-TOOLING (this file itself is hand-written, not generated).
//
// scripts/l10n/gen-l10n.mjs — single source of truth is the Android
// androidApp/src/main/res/values{,-sv,-de,-fr,-es,-nb,-da,-fi}/strings_*.xml
// tree. This script parses that tree with a small strict hand-written XML
// parser (zero npm deps — Node core modules only, so it runs unmodified on
// both the repo's default `node` and the pinned node@22 the e2e tooling
// uses) and emits:
//   - iosApp/iosApp/Localizable.xcstrings   (conversation/system strings)
//   - iosApp/iosApp/InfoPlist.xcstrings     (Info.plist usage descriptions)
//   - iosApp/iosApp/L10n.swift              (typed Swift accessors)
//   - androidApp/src/main/java/com/vg/run/l10n/L10nKeys.kt
//     (key -> R.string map for shared/commonMain's platformString() lookups)
//
// Modes:
//   node gen-l10n.mjs           write the four outputs in place
//   node gen-l10n.mjs --check   generate into a temp dir and diff against the
//                               committed outputs; exit 1 on ANY drift or
//                               validation problem, exit 0 otherwise
//
// Deterministic by construction: every object's keys are sorted before
// serialization, so a rerun over unchanged input reproduces byte-identical
// output.
"use strict";

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const REPO_ROOT = path.resolve(__dirname, "..", "..");
export const RES_DIR = path.join(REPO_ROOT, "androidApp/src/main/res");

export const LOCALES = ["en", "sv", "de", "fr", "es", "nb", "da", "fi", "ar", "fa", "so", "ru", "mk"];

const OUT_LOCALIZABLE = path.join(REPO_ROOT, "iosApp/iosApp/Localizable.xcstrings");
const OUT_INFOPLIST = path.join(REPO_ROOT, "iosApp/iosApp/InfoPlist.xcstrings");
const OUT_L10N_SWIFT = path.join(REPO_ROOT, "iosApp/iosApp/L10n.swift");
const OUT_L10N_KEYS_KT = path.join(
  REPO_ROOT,
  "androidApp/src/main/java/com/vg/run/l10n/L10nKeys.kt",
);
const SHARED_STRINGS_XML = path.join(RES_DIR, "values", "strings_shared.xml");

// Catalog KEY OVERRIDE table (spec §2a): the xcstrings/L10n.swift NSLocalizedString
// key differs from the Android XML key name for these entries.
const CATALOG_KEY_OVERRIDES = {
  apns_notification_body: "Notification",
};

const INFOPLIST_KEY_MAP = {
  infoplist_camera_usage: "NSCameraUsageDescription",
  infoplist_faceid_usage: "NSFaceIDUsageDescription",
  infoplist_local_network_usage: "NSLocalNetworkUsageDescription",
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class L10nError extends Error {}

function fail(message) {
  throw new L10nError(message);
}

// ---------------------------------------------------------------------------
// XML parsing — small strict hand-written parser (no npm deps).
//
// Supports: <string name="...">…</string>, <plurals name="..."><item
// quantity="...">…</item>…</plurals>; XML comments (stripped wholesale);
// <![CDATA[…]]> (raw, no entity/escape decoding — matches real Android
// resource-compiler behavior); the five predefined XML entities; the four
// Android backslash escapes (\' \" \n \t) plus \\ ; translatable="false".
// Rejects: any tag nested inside a <string>/<item> element (covers
// <xliff:g> and any other inline markup) with a clear error.
// ---------------------------------------------------------------------------

function stripXmlComments(text) {
  return text.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, " "));
}

function tokenize(text, fileLabel) {
  const tokens = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    if (text.startsWith("<![CDATA[", i)) {
      const end = text.indexOf("]]>", i + 9);
      if (end === -1) fail(`${fileLabel}: unterminated CDATA section`);
      tokens.push({ type: "cdata", text: text.slice(i + 9, end) });
      i = end + 3;
      continue;
    }
    if (text[i] === "<") {
      if (text.startsWith("<?", i)) {
        const end = text.indexOf("?>", i);
        if (end === -1) fail(`${fileLabel}: unterminated processing instruction`);
        i = end + 2;
        continue;
      }
      if (text.startsWith("<!", i)) {
        const end = text.indexOf(">", i);
        if (end === -1) fail(`${fileLabel}: unterminated declaration`);
        i = end + 1;
        continue;
      }
      const end = text.indexOf(">", i);
      if (end === -1) fail(`${fileLabel}: unterminated tag starting at offset ${i}`);
      let raw = text.slice(i + 1, end);
      let closing = false;
      let selfClosing = false;
      if (raw.startsWith("/")) {
        closing = true;
        raw = raw.slice(1);
      }
      if (raw.endsWith("/")) {
        selfClosing = true;
        raw = raw.slice(0, -1);
      }
      raw = raw.trim();
      const m = raw.match(/^([A-Za-z_][\w:.-]*)/);
      if (!m) fail(`${fileLabel}: malformed tag "<${raw}>"`);
      const name = m[1];
      const attrs = parseAttrs(raw.slice(m[0].length));
      tokens.push({ type: closing ? "end" : "start", name, attrs, selfClosing });
      i = end + 1;
      continue;
    }
    const next = text.indexOf("<", i);
    const textEnd = next === -1 ? n : next;
    const raw = text.slice(i, textEnd);
    if (raw.length) tokens.push({ type: "text", text: raw });
    i = textEnd;
  }
  return tokens;
}

function parseAttrs(s) {
  const attrs = {};
  const re = /([A-Za-z_][\w:.-]*)\s*=\s*"([^"]*)"|([A-Za-z_][\w:.-]*)\s*=\s*'([^']*)'/g;
  let m;
  while ((m = re.exec(s))) {
    const key = m[1] !== undefined ? m[1] : m[3];
    const val = m[2] !== undefined ? m[2] : m[4];
    attrs[key] = decodeEntities(val);
  }
  return attrs;
}

const ENTITY_MAP = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

function decodeEntities(s) {
  return s.replace(/&(amp|lt|gt|quot|apos);/g, (_, name) => ENTITY_MAP[name]);
}

function decodeAndroidEscapes(s, fileLabel, context) {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\") {
      const next = s[i + 1];
      if (next === "n") {
        out += "\n";
        i++;
      } else if (next === "t") {
        out += "\t";
        i++;
      } else if (next === "'") {
        out += "'";
        i++;
      } else if (next === '"') {
        out += '"';
        i++;
      } else if (next === "\\") {
        out += "\\";
        i++;
      } else {
        fail(`${fileLabel}: unsupported escape sequence "\\${next ?? ""}" in ${context}`);
      }
    } else {
      out += c;
    }
  }
  return out;
}

function extractElementText(innerTokens, fileLabel, elementLabel) {
  let out = "";
  for (const t of innerTokens) {
    if (t.type === "text") {
      out += decodeAndroidEscapes(decodeEntities(t.text), fileLabel, elementLabel);
    } else if (t.type === "cdata") {
      out += t.text;
    } else {
      fail(
        `${fileLabel}: nested tag <${t.name}> inside ${elementLabel} is not supported ` +
          `(no <xliff:g> or inline markup allowed — flatten it to plain text)`,
      );
    }
  }
  return out;
}

// Placeholders must be positional: %1$s, %1$d, %%. Bare %s/%d is an error.
export function scanPlaceholders(value, fileLabel, context) {
  const found = [];
  let i = 0;
  while (i < value.length) {
    if (value[i] === "%") {
      if (value[i + 1] === "%") {
        i += 2;
        continue;
      }
      const rest = value.slice(i);
      const m = /^%(\d+)\$([sd])/.exec(rest);
      if (m) {
        found.push({ full: m[0], index: Number(m[1]), type: m[2] });
        i += m[0].length;
        continue;
      }
      const bare = /^%([sd])/.exec(rest);
      if (bare) {
        fail(
          `${fileLabel}: ${context} has a bare "%${bare[1]}" placeholder — placeholders ` +
            `must be positional (e.g. %1$${bare[1]})`,
        );
      }
      fail(
        `${fileLabel}: ${context} has a malformed placeholder near "${rest.slice(0, 8)}" — ` +
          `only %N$s, %N$d, and %% are supported`,
      );
    }
    i++;
  }
  return found;
}

export function parseStringsXml(rawText, fileLabel) {
  const text = stripXmlComments(rawText);
  const tokens = tokenize(text, fileLabel);
  let i = 0;
  while (i < tokens.length && !(tokens[i].type === "start" && tokens[i].name === "resources")) {
    if (tokens[i].type === "text" && tokens[i].text.trim() !== "") {
      fail(`${fileLabel}: unexpected content before <resources>`);
    }
    i++;
  }
  if (i >= tokens.length) fail(`${fileLabel}: missing <resources> root element`);
  i++; // consume <resources>

  const strings = new Map(); // name -> { value, translatable }
  const plurals = new Map(); // name -> Map(quantity -> value)

  while (i < tokens.length) {
    const t = tokens[i];
    if (t.type === "text") {
      i++;
      continue;
    }
    if (t.type === "end" && t.name === "resources") {
      i++;
      break;
    }
    if (t.type === "start" && t.name === "string") {
      const name = t.attrs.name;
      if (!name) fail(`${fileLabel}: <string> missing name attribute`);
      const translatable = t.attrs.translatable !== "false";
      i++;
      const inner = [];
      while (!(i < tokens.length && tokens[i].type === "end" && tokens[i].name === "string")) {
        if (i >= tokens.length) fail(`${fileLabel}: unterminated <string name="${name}">`);
        inner.push(tokens[i]);
        i++;
      }
      i++; // consume end tag
      const value = extractElementText(inner, fileLabel, `<string name="${name}">`);
      if (strings.has(name)) fail(`${fileLabel}: duplicate <string name="${name}">`);
      scanPlaceholders(value, fileLabel, `string "${name}"`);
      strings.set(name, { value, translatable });
      continue;
    }
    if (t.type === "start" && t.name === "plurals") {
      const name = t.attrs.name;
      if (!name) fail(`${fileLabel}: <plurals> missing name attribute`);
      i++;
      const items = new Map();
      while (!(i < tokens.length && tokens[i].type === "end" && tokens[i].name === "plurals")) {
        if (i >= tokens.length) fail(`${fileLabel}: unterminated <plurals name="${name}">`);
        const it = tokens[i];
        if (it.type === "text") {
          i++;
          continue;
        }
        if (it.type === "start" && it.name === "item") {
          const quantity = it.attrs.quantity;
          if (!quantity) fail(`${fileLabel}: <item> in <plurals name="${name}"> missing quantity attribute`);
          i++;
          const innerItem = [];
          while (!(i < tokens.length && tokens[i].type === "end" && tokens[i].name === "item")) {
            if (i >= tokens.length) {
              fail(`${fileLabel}: unterminated <item quantity="${quantity}"> in <plurals name="${name}">`);
            }
            innerItem.push(tokens[i]);
            i++;
          }
          i++; // consume end item
          const value = extractElementText(
            innerItem,
            fileLabel,
            `<item quantity="${quantity}"> in <plurals name="${name}">`,
          );
          if (items.has(quantity)) {
            fail(`${fileLabel}: duplicate quantity "${quantity}" in <plurals name="${name}">`);
          }
          scanPlaceholders(value, fileLabel, `plurals "${name}" item "${quantity}"`);
          items.set(quantity, value);
          continue;
        }
        fail(`${fileLabel}: unexpected <${it.name}> inside <plurals name="${name}">`);
      }
      i++; // consume end plurals
      if (plurals.has(name)) fail(`${fileLabel}: duplicate <plurals name="${name}">`);
      plurals.set(name, items);
      continue;
    }
    if (t.type === "start") {
      fail(`${fileLabel}: unexpected element <${t.name}> inside <resources> (only <string>/<plurals> supported)`);
    }
    i++;
  }
  return { strings, plurals };
}

// ---------------------------------------------------------------------------
// Loading the locale tree
// ---------------------------------------------------------------------------

export function localeDirName(locale) {
  return locale === "en" ? "values" : `values-${locale}`;
}

export function loadLocale(locale) {
  const dir = path.join(RES_DIR, localeDirName(locale));
  if (!fs.existsSync(dir)) return null; // no localizations for that language yet
  const files = fs
    .readdirSync(dir)
    .filter((f) => /^strings_.*\.xml$/.test(f))
    .sort();
  const strings = new Map();
  const plurals = new Map();
  for (const f of files) {
    const full = path.join(dir, f);
    const label = path.relative(REPO_ROOT, full);
    const text = fs.readFileSync(full, "utf8");
    const parsed = parseStringsXml(text, label);
    for (const [k, v] of parsed.strings) {
      if (strings.has(k)) fail(`${label}: duplicate string key "${k}" across strings_*.xml files in ${localeDirName(locale)}/`);
      strings.set(k, v);
    }
    for (const [k, v] of parsed.plurals) {
      if (plurals.has(k)) fail(`${label}: duplicate plurals key "${k}" across strings_*.xml files in ${localeDirName(locale)}/`);
      plurals.set(k, v);
    }
  }
  return { strings, plurals, files };
}

// ---------------------------------------------------------------------------
// Placeholder conversion Android -> iOS
// ---------------------------------------------------------------------------

function convertPlaceholdersForIOS(value) {
  return value.replace(/%(\d+)\$([sd])|%%/g, (m, idx, type) => {
    if (m === "%%") return "%%";
    return type === "s" ? `%${idx}$@` : `%${idx}$lld`;
  });
}

// ---------------------------------------------------------------------------
// Deterministic JSON serialization
// ---------------------------------------------------------------------------

function sortKeysDeep(value) {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = sortKeysDeep(value[k]);
    return out;
  }
  return value;
}

function toJson(obj) {
  return JSON.stringify(sortKeysDeep(obj), null, 2) + "\n";
}

// ---------------------------------------------------------------------------
// Build the en master + per-locale data
// ---------------------------------------------------------------------------

function buildModel() {
  const byLocale = new Map();
  for (const loc of LOCALES) {
    byLocale.set(loc, loadLocale(loc));
  }
  const en = byLocale.get("en");
  if (!en) fail(`androidApp/src/main/res/values/ (strings_*.xml) is missing — nothing to generate from`);
  return { byLocale, en };
}

// ---------------------------------------------------------------------------
// Localizable.xcstrings / InfoPlist.xcstrings
// ---------------------------------------------------------------------------

function catalogKeyFor(xmlKey) {
  return CATALOG_KEY_OVERRIDES[xmlKey] ?? xmlKey;
}

function buildXcstringsCatalog({ byLocale, en }, { includeKey }) {
  const strings = {};

  for (const [key, enEntry] of en.strings) {
    if (!includeKey(key)) continue;
    const catalogKey = catalogKeyFor(key);
    const localizations = {};
    for (const loc of LOCALES) {
      const data = byLocale.get(loc);
      if (!data) continue;
      const entry = data.strings.get(key);
      if (!entry) continue;
      localizations[loc] = {
        stringUnit: { state: "translated", value: convertPlaceholdersForIOS(entry.value) },
      };
    }
    strings[catalogKey] = { extractionState: "manual", localizations };
  }

  for (const [key, enItems] of en.plurals) {
    if (!includeKey(key)) continue;
    const catalogKey = catalogKeyFor(key);
    const localizations = {};
    for (const loc of LOCALES) {
      const data = byLocale.get(loc);
      if (!data) continue;
      const items = data.plurals.get(key);
      if (!items) continue;
      const pluralObj = {};
      for (const [quantity, value] of items) {
        pluralObj[quantity] = {
          stringUnit: { state: "translated", value: convertPlaceholdersForIOS(value) },
        };
      }
      localizations[loc] = { variations: { plural: pluralObj } };
    }
    strings[catalogKey] = { extractionState: "manual", localizations };
  }

  return { sourceLanguage: "en", strings, version: "1.0" };
}

// ---------------------------------------------------------------------------
// L10n.swift
// ---------------------------------------------------------------------------

function toCamelCase(key) {
  const parts = key.split("_");
  return parts.map((p, idx) => (idx === 0 ? p : p.charAt(0).toUpperCase() + p.slice(1))).join("");
}

function swiftStringLiteralEscape(s) {
  return s
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\t/g, "\\t");
}

function computeContiguousArgs(value, fileLabel, context) {
  const placeholders = scanPlaceholders(value, fileLabel, context);
  const indices = [...new Set(placeholders.map((p) => p.index))].sort((a, b) => a - b);
  for (let k = 0; k < indices.length; k++) {
    if (indices[k] !== k + 1) {
      fail(`${fileLabel}: ${context} has non-contiguous placeholders — expected %1$.. through %${indices.length}$.. with no gaps`);
    }
  }
  const types = {};
  for (const p of placeholders) types[p.index] = p.type;
  return indices.map((idx) => ({ index: idx, type: types[idx] === "d" ? "Int" : "String" }));
}

function buildL10nSwift({ en }) {
  const lines = [];
  lines.push("// GENERATED by scripts/l10n/gen-l10n.mjs — DO NOT EDIT");
  lines.push("import Foundation");
  lines.push("");
  lines.push("enum L10n {");

  const enFileLabel = "androidApp/src/main/res/values/strings_*.xml";
  const entries = [];

  for (const [key, entry] of en.strings) {
    if (key.startsWith("infoplist_")) continue;
    entries.push({ key, kind: "string", entry });
  }
  for (const [key, items] of en.plurals) {
    entries.push({ key, kind: "plural", items });
  }
  entries.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));

  for (const e of entries) {
    const accessor = toCamelCase(e.key);
    const catalogKey = catalogKeyFor(e.key);

    if (e.kind === "string") {
      const enValue = e.entry.value;
      const args = computeContiguousArgs(enValue, enFileLabel, `string "${e.key}"`);
      const iosValue = convertPlaceholdersForIOS(enValue);
      const literal = swiftStringLiteralEscape(enValue);
      lines.push(`    /// en: "${literal}"`);
      if (args.length === 0) {
        lines.push(
          `    static var ${accessor}: String { NSLocalizedString("${catalogKey}", value: "${swiftStringLiteralEscape(iosValue)}", comment: "") }`,
        );
      } else {
        const params = args.map((a) => `_ p${a.index}: ${a.type}`).join(", ");
        const callArgs = args.map((a) => `p${a.index}`).join(", ");
        lines.push(
          `    static func ${accessor}(${params}) -> String { String.localizedStringWithFormat(NSLocalizedString("${catalogKey}", value: "${swiftStringLiteralEscape(iosValue)}", comment: ""), ${callArgs}) }`,
        );
      }
    } else {
      const other = e.items.get("other");
      if (!other) fail(`${enFileLabel}: plurals "${e.key}" has no "other" quantity`);
      const args = computeContiguousArgs(other, enFileLabel, `plurals "${e.key}" item "other"`);
      const extra = args.filter((a) => a.index !== 1);
      const literal = swiftStringLiteralEscape(other);
      lines.push(`    /// en (other): "${literal}"`);
      const params = ["_ n: Int", ...extra.map((a) => `_ p${a.index}: ${a.type}`)].join(", ");
      const callArgs = ["n", ...extra.map((a) => `p${a.index}`)].join(", ");
      lines.push(
        `    static func ${accessor}(${params}) -> String { String.localizedStringWithFormat(NSLocalizedString("${catalogKey}", comment: ""), ${callArgs}) }`,
      );
    }
  }

  lines.push("}");
  return lines.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// L10nKeys.kt
// ---------------------------------------------------------------------------

function buildL10nKeysKt() {
  const lines = [];
  lines.push("// GENERATED — DO NOT EDIT");
  lines.push("package com.vg.run.l10n");
  lines.push("");
  lines.push("import com.vg.run.R");
  lines.push("");
  lines.push("object L10nKeys {");

  if (!fs.existsSync(SHARED_STRINGS_XML)) {
    lines.push("    val strings: Map<String, Int> = mapOf()");
    lines.push("}");
    return lines.join("\n") + "\n";
  }

  const label = path.relative(REPO_ROOT, SHARED_STRINGS_XML);
  const text = fs.readFileSync(SHARED_STRINGS_XML, "utf8");
  const parsed = parseStringsXml(text, label);
  const keys = [...parsed.strings.keys()].sort();

  if (keys.length === 0) {
    lines.push("    val strings: Map<String, Int> = mapOf()");
  } else {
    lines.push("    val strings: Map<String, Int> = mapOf(");
    lines.push(keys.map((k) => `        "${k}" to R.string.${k}`).join(",\n"));
    lines.push("    )");
  }
  lines.push("}");
  return lines.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// shared/commonMain platformString("...") key-existence check is owned by
// the JVM validator test (L10nResourcesTest.kt), not this generator.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function generateAll() {
  const model = buildModel();
  const localizable = buildXcstringsCatalog(model, {
    includeKey: (key) => !key.startsWith("infoplist_"),
  });
  const infoplist = buildXcstringsCatalogInfoPlist(model);
  const l10nSwift = buildL10nSwift(model);
  const l10nKeysKt = buildL10nKeysKt();

  return {
    [OUT_LOCALIZABLE]: toJson(localizable),
    [OUT_INFOPLIST]: toJson(infoplist),
    [OUT_L10N_SWIFT]: l10nSwift,
    [OUT_L10N_KEYS_KT]: l10nKeysKt,
  };
}

function buildXcstringsCatalogInfoPlist({ byLocale, en }) {
  const strings = {};
  for (const [xmlKey, catalogKey] of Object.entries(INFOPLIST_KEY_MAP)) {
    const enEntry = en.strings.get(xmlKey);
    if (!enEntry) fail(`androidApp/src/main/res/values/strings_system.xml: missing required key "${xmlKey}"`);
    const localizations = {};
    for (const loc of LOCALES) {
      const data = byLocale.get(loc);
      if (!data) continue;
      const entry = data.strings.get(xmlKey);
      if (!entry) continue;
      localizations[loc] = {
        stringUnit: { state: "translated", value: convertPlaceholdersForIOS(entry.value) },
      };
    }
    strings[catalogKey] = { extractionState: "manual", localizations };
  }
  return { sourceLanguage: "en", strings, version: "1.0" };
}

function writeOutputs(outputs) {
  for (const [file, content] of Object.entries(outputs)) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content, "utf8");
  }
}

function checkOutputs(outputs) {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "run-l10n-check-"));
  let drift = false;
  try {
    for (const [file, content] of Object.entries(outputs)) {
      const rel = path.relative(REPO_ROOT, file);
      const tmpFile = path.join(tmpRoot, rel.replace(/[\\/]/g, "__"));
      fs.writeFileSync(tmpFile, content, "utf8");
      const committed = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : null;
      if (committed === null) {
        console.log(`DRIFT: ${rel} does not exist yet (would be created)`);
        drift = true;
        continue;
      }
      if (committed === content) continue;
      drift = true;
      console.log(`DRIFT: ${rel}`);
      try {
        const diffOut = execFileSync("diff", ["-u", file, tmpFile], { encoding: "utf8" });
        console.log(diffOut);
      } catch (e) {
        // diff exits 1 when files differ — that's expected; print its stdout.
        if (e.stdout) console.log(e.stdout);
        else console.log(`  (could not run diff: ${e.message})`);
      }
    }
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
  return !drift;
}

// ---------------------------------------------------------------------------
// Locale-list lockstep guard.
//
// Adding a locale means updating SIX hand-maintained lists (LOCALES here,
// AppLocale.SUPPORTED, the iOS knownRegions + AppLanguages.supported, and the
// two Android build/manifest lists below). On 2026-09-01 ar/fa shipped with
// their resources STRIPPED from the APK because androidResources.localeFilters
// and res/xml/locales_config.xml were the two that got missed — the app fell
// back to English on an Arabic device. Assert the two Android lists match
// LOCALES so that can't silently recur. (L10n.swift / xcstrings are already
// covered by checkOutputs' regenerate-and-diff; AppLocale.SUPPORTED by its own
// JVM test.)
// ---------------------------------------------------------------------------
function checkLockstepLists() {
  const want = [...LOCALES].sort().join(",");
  const problems = [];

  const gradle = fs.readFileSync(path.join(REPO_ROOT, "androidApp/build.gradle.kts"), "utf8");
  const lf = gradle.match(/localeFilters\s*\+=\s*listOf\(([^)]*)\)/);
  if (!lf) {
    problems.push("androidApp/build.gradle.kts: `localeFilters += listOf(...)` not found");
  } else {
    const got = [...lf[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]).sort().join(",");
    if (got !== want) {
      problems.push(`androidApp/build.gradle.kts localeFilters = [${got}] != LOCALES [${want}] — locales absent here are STRIPPED from the APK`);
    }
  }

  const cfg = fs.readFileSync(path.join(RES_DIR, "xml", "locales_config.xml"), "utf8");
  const cfgGot = [...cfg.matchAll(/android:name="([^"]+)"/g)].map((m) => m[1]).sort().join(",");
  if (cfgGot !== want) {
    problems.push(`res/xml/locales_config.xml = [${cfgGot}] != LOCALES [${want}]`);
  }

  return problems;
}

function main() {
  const checkMode = process.argv.includes("--check");

  const lockstep = checkLockstepLists();
  if (lockstep.length) {
    console.error("gen-l10n: locale-list lockstep FAILED (add the locale to LOCALES, build.gradle.kts localeFilters, AND res/xml/locales_config.xml):");
    for (const p of lockstep) console.error("  - " + p);
    if (checkMode) process.exit(1);
    console.error("  (continuing generation, but --check / pre-push WILL fail until fixed)");
  }
  let outputs;
  try {
    outputs = generateAll();
  } catch (e) {
    if (e instanceof L10nError) {
      console.error(`gen-l10n: ${e.message}`);
      process.exit(1);
    }
    throw e;
  }

  if (checkMode) {
    const ok = checkOutputs(outputs);
    if (!ok) {
      console.error("gen-l10n --check: generated output drifted from committed files (see diffs above)");
      process.exit(1);
    }
    console.log("gen-l10n --check: OK (generated output matches committed files)");
    process.exit(0);
  }

  writeOutputs(outputs);
  for (const file of Object.keys(outputs)) {
    console.log(`wrote ${path.relative(REPO_ROOT, file)}`);
  }
}

// Run only when executed directly — l10n-sync.mjs imports the parser + locale
// loader from this module and must not trigger a generation pass on import.
if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(__filename)) main();
