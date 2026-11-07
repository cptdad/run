#!/usr/bin/env bash
# CI checksum-pin for the vendored Argon2 C sources.
#
# The vault's KDF_VERSION_3 credential KDF is Argon2id; iOS links the PHC reference
# implementation vendored under iosApp/Argon2/ (see README-VENDOR.md). Those files were
# STRUCTURALLY verified unmodified (bar the documented blake2 symbol-
# prefix rename), but that does not byte-pin them. This re-hashes the checked-in sources
# against a recorded SHA-256 on every push so a silent edit to the crypto core
# (core.c / ref.c / blake2b.c / …) fails closed and forces a re-review.
#
#   scripts/verify-argon2-src.sh            # verify (default; used by pre-push + CI)
#   scripts/verify-argon2-src.sh --update   # regenerate the record after a genuine
#                                           # re-vendor (re-apply the blake2 rename first)
set -uo pipefail
cd "$(dirname "$0")/.."

DIR="iosApp/Argon2"
REC="$DIR/argon2-src.sha256"

# ENUMERATE the compiled sources at check time — do NOT trust a
# hardcoded list. iosApp/iosApp.xcodeproj uses a PBXFileSystemSynchronizedRootGroup,
# so ANY .c/.h added under iosApp/Argon2/ is auto-compiled into the framework; a
# hardcoded FILES list would let an ADDED evil.c compile while both gates report
# green. Pin every compiled C/H source; NOT LICENSE/README/SwiftArgon2.swift
# (docs/app glue that change legitimately).
list_sources() { ( cd "$DIR" && find . \( -name '*.c' -o -name '*.h' \) | sed 's|^\./||' | sort ); }
# Paths currently pinned in the record (record lines are "sha  path"; skip comments).
recorded_paths() { awk '$1 ~ /^[0-9a-f]+$/ { print $2 }' "$REC"; }

if [ "${1:-}" = "--update" ]; then
  {
    echo "# Argon2 vendored-source integrity record (CI checksum-pin)."
    echo "# SHA-256 of the vendored PHC reference C/H sources — freezes the verified-"
    echo "# correct state (structurally verified unmodified except the documented"
    echo "# blake2 symbol-prefix rename in blake2/blake2.h; see README-VENDOR.md)."
    echo "# Enumerated from the folder; update ONLY via a genuine re-vendor:"
    echo "# scripts/verify-argon2-src.sh --update after re-applying the blake2 rename,"
    echo "# and re-review the diff."
    list_sources | while read -r f; do
      printf '%s  %s\n' "$(shasum -a 256 "$DIR/$f" | cut -d' ' -f1)" "$f"
    done
  } > "$REC"
  echo "✓ rewrote $REC — re-review the diff before committing."
  exit 0
fi

[ -f "$REC" ] || { echo "✗ missing checksum record $REC" >&2; exit 2; }

fail=0
# 1) Every RECORD entry must exist and match its recorded hash.
while read -r sha rel; do
  case "$sha" in \#*|"") continue ;; esac        # skip comments / blank lines
  src="$DIR/$rel"
  if [ ! -f "$src" ]; then
    echo "✗ vendored Argon2 source missing: $rel" >&2; fail=1; continue
  fi
  actual="$(shasum -a 256 "$src" | cut -d' ' -f1)"
  if [ "$actual" = "$sha" ]; then
    echo "✓ $rel"
  else
    echo "✗ $rel: sha256 $actual != recorded $sha" >&2; fail=1
  fi
done < "$REC"

# 2) every COMPILED source on disk must be pinned in the record — so an
#    ADDED (auto-compiled) file can't slip in unpinned.
while read -r f; do
  if ! recorded_paths | grep -qxF "$f"; then
    echo "✗ compiled Argon2 source is NOT pinned: $f — add it via 'verify-argon2-src.sh --update' after review." >&2
    fail=1
  fi
done < <(list_sources)

if [ "$fail" -ne 0 ]; then
  echo "✗ Argon2 vendored-source integrity check FAILED — a pinned crypto source does not match its recorded hash. Re-review the change; if intentional, re-vendor and run scripts/verify-argon2-src.sh --update." >&2
  exit 1
fi
echo "✓ Argon2 vendored sources ($(list_sources | wc -l | tr -d ' ') files) match their recorded SHA-256 and all are pinned."
exit 0
