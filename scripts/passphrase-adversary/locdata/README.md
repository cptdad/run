# Localized passphrase-estimator data (2026-11-10 dynamic-report fixes #2/#4)

One-shot generators for the LOCALIZED_* / LOCALIZED_COMMON_WORDS / FAMOUS_PHRASES sets baked
into `shared/src/commonMain/kotlin/com/vg/run/CredentialPolicy.kt`.

- `group{1..4}*.json` — per-locale category words, common/function words, inflected forms,
  and famous phrases, produced by 4 locale agents (de/sv/nb/da/fi, fr/es, ar/fa, ru/mk/so).
- `merge.py` — merges + prunes (homograph/short-latin/known-set) + canonicalizes. Two
  normalizers mirror the Kotlin EXACTLY: `normword` = `normalizeWord` (keeps diacritics,
  for closed-category + common lookups); `canon` = `canonicalFold` (folds Latin diacritics,
  Arabic letters/harakat, native digits; strips non-alnum, for famous matching). The famous
  corpus is SEEDED from the dynamic test's ground-truth accepted famous rows
  (`<scratch>/passphrase-adversary/run/accepted.tsv`) plus the agent lists. Emits `emit.kt.txt`.
- `integrate2.py` — splices `emit.kt.txt` into CredentialPolicy.kt (sets + enum log2(size) consts).

Regenerate: `python3 merge.py && python3 integrate2.py` (needs the accepted.tsv path updated).
The sets are MONOTONE-DECREASING over the estimator, so adding members can never create a floor bypass.
