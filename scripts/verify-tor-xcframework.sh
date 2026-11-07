#!/usr/bin/env bash
# Verify the committed tor.xcframework against its recorded
# SHA-256. The framework is git-tracked (so history is one integrity record), but
# the source-build assertions in build-tor-xcframework.sh run only at REBUILD time
# — this re-hashes the checked-in bytes on every push so tampering BETWEEN rare
# rebuilds fails closed. Update the records ONLY via a genuine rebuild
# (iosApp/scripts/build-tor-xcframework.sh regenerates both).
#
# The gate used to be purely RECORD-DRIVEN: it iterated
# the record and checked that each listed path matched. Three consequences, all
# closed below:
#   1. NOTHING was checked that the record did not mention. An attacker could add
#      a whole new slice directory (ios-arm64-newslice/Tor.framework/Tor) and
#      repoint the xcframework's root Info.plist `LibraryIdentifier` at it: every
#      recorded hash still matched, the gate printed all-✓, and Xcode linked the
#      attacker's binary. The check is now an ENUMERATION: every entry under the
#      framework must be accounted for by a record, and an unlisted file is a
#      FAILURE — the same "recompute from the actual tree" property the headers
#      digest already had, extended to the whole framework.
#   2. The two `Info.plist`s were UNPINNED — the root one is the slice-selection
#      manifest (the file the attack above rewrites), the per-slice ones carry
#      the framework identity. Both are pinned in the binaries record now.
#   3. A MISSING headers record only WARNED and skipped. A gate that silently
#      disarms when its input disappears is not a gate: deleting one file turned
#      1494 compile-input headers into unverified bytes. It is a FAILURE now.
set -uo pipefail
cd "$(dirname "$0")/.."

REC="iosApp/Frameworks/tor.xcframework.sha256"
HREC="iosApp/Frameworks/tor.xcframework.headers.sha256"
FWROOT="iosApp/Frameworks/tor.xcframework"
[ -d "$FWROOT" ] || { echo "✗ missing framework tree $FWROOT" >&2; exit 2; }
[ -f "$REC" ] || { echo "✗ missing checksum record $REC" >&2; exit 2; }
# Absence of the headers record is a hard failure, never a skip.
if [ ! -f "$HREC" ]; then
  echo "✗ missing headers-tree record $HREC — the 1494 compiled headers are COMPILE INPUTS; refusing to pass with them unverified (regenerate via iosApp/scripts/build-tor-xcframework.sh)." >&2
  exit 1
fi

fail=0
# Newline-delimited sets of what each record covers, consumed by the enumeration
# pass at the bottom. Kept as strings rather than temp files so there is nothing
# to clean up and no shell-version dependency (bash 3.2 has no associative arrays).
covered_files=$'\n'
covered_dirs=$'\n'
nfiles=0
ndirs=0

# A record path must stay INSIDE the framework — a record is an integrity claim,
# not a way to point the gate somewhere else.
reject_escaping_path() {
  case "$1" in
    /*|*/../*|../*|*/..|"..") echo "✗ record entry escapes the framework tree: $1" >&2; return 1 ;;
  esac
  return 0
}

# --- 1. Per-file hashes: the two Tor Mach-O binaries + the three Info.plists ----
while read -r sha rel; do
  case "$sha" in \#*|"") continue ;; esac        # skip comments / blank lines
  reject_escaping_path "$rel" || { fail=1; continue; }
  bin="$FWROOT/$rel"
  if [ ! -f "$bin" ]; then
    echo "✗ tor.xcframework file missing: $rel" >&2; fail=1; continue
  fi
  actual="$(shasum -a 256 "$bin" | cut -d' ' -f1)"
  if [ "$actual" = "$sha" ]; then
    echo "✓ $rel"
    covered_files="$covered_files$rel"$'\n'
    nfiles=$((nfiles + 1))
  else
    echo "✗ $rel: sha256 $actual != recorded $sha" >&2; fail=1
  fi
done < "$REC"

# --- 2. Each slice's COMPILED Headers/ tree, as a whole-tree ----
# digest — so a tampered header (content) OR an added/removed one (file list) is
# caught, not just the Mach-O binaries.
while read -r sha rel; do
  case "$sha" in \#*|"") continue ;; esac
  reject_escaping_path "$rel" || { fail=1; continue; }
  dir="$FWROOT/$rel"
  if [ ! -d "$dir" ]; then
    echo "✗ tor.xcframework Headers dir missing: $rel" >&2; fail=1; continue
  fi
  actual="$( ( cd "$dir" && find . -type f | LC_ALL=C sort | xargs shasum -a256 ) | shasum -a256 | cut -d' ' -f1 )"
  if [ "$actual" = "$sha" ]; then
    echo "✓ $rel (headers tree)"
    covered_dirs="$covered_dirs$rel"$'\n'
    ndirs=$((ndirs + 1))
  else
    echo "✗ $rel: headers-tree sha256 $actual != recorded $sha" >&2; fail=1
  fi
done < "$HREC"

# A record whose entries were all comments would cover nothing and let the
# enumeration below "pass" a framework nobody checked — require both to be real.
if [ "$nfiles" -eq 0 ]; then
  echo "✗ $REC verified no files — an empty/comment-only record is not an integrity record" >&2; fail=1
fi
if [ "$ndirs" -eq 0 ]; then
  echo "✗ $HREC verified no headers trees — an empty/comment-only record is not an integrity record" >&2; fail=1
fi

# --- 3. ENUMERATE-AT-CHECK -------------------------------------------
# Walk the ACTUAL framework and require every entry to be accounted for by one of
# the records above. This is the half that makes the gate independent of what the
# record happens to mention: an added slice, an added binary, an added file beside
# a Headers tree, or a symlink pointing out of the tree all fail closed.
unlisted=0
while IFS= read -r path; do
  rel="${path#"$FWROOT/"}"
  if [ -L "$path" ]; then
    echo "✗ unexpected symlink in tor.xcframework: $rel" >&2; fail=1; continue
  fi
  [ -d "$path" ] && continue
  if [ ! -f "$path" ]; then
    echo "✗ unexpected non-regular entry in tor.xcframework: $rel" >&2; fail=1; continue
  fi
  case "$covered_files" in *$'\n'"$rel"$'\n'*) continue ;; esac
  inside_headers=0
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    case "$rel" in "$d"/*) inside_headers=1; break ;; esac
  done <<EOF
$covered_dirs
EOF
  [ "$inside_headers" -eq 1 ] && continue
  echo "✗ tor.xcframework file covered by NO integrity record: $rel" >&2
  unlisted=$((unlisted + 1)); fail=1
done < <(find "$FWROOT" -mindepth 1 | LC_ALL=C sort)
if [ "$unlisted" -eq 0 ] && [ "$fail" -eq 0 ]; then
  echo "✓ every file under $FWROOT is covered by a record (enumerate-at-check)"
fi

if [ "$fail" -ne 0 ]; then
  echo "✗ tor.xcframework integrity check FAILED — a committed Tor binary, Info.plist or header does not match its recorded hash, or a file is present that no record covers (rebuild via iosApp/scripts/build-tor-xcframework.sh, or investigate tampering)." >&2
  exit 1
fi
echo "✓ tor.xcframework binaries + Info.plists + headers match their recorded SHA-256, and nothing else is present."
exit 0
