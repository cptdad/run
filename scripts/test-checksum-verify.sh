#!/usr/bin/env bash
# Canary self-test for scripts/lib/checksum-verify.sh (shared by verify-gradle-wrapper.sh and
# the other integrity gates): an intact record passes; one flipped byte, a missing file and an
# empty record must each be reported (rc!=0 or CSV_ENTRIES==0).
#
#   usage: scripts/test-checksum-verify.sh        (bash 3.2 compatible)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(mktemp -d)"; trap 'rm -rf "$BASE"' EXIT
total=0; bad=0
check() { total=$((total + 1)); if [ "$2" = "$3" ]; then echo "  ok   $1 (rc=$3)"; else echo "  FAIL $1: want rc=$2, got rc=$3" >&2; bad=$((bad + 1)); fi; }
. "$HERE/lib/checksum-verify.sh" || { echo "cannot source checksum-verify.sh" >&2; exit 1; }

D="$BASE/with space"; mkdir -p "$D"
printf 'alpha\n' > "$D/a.txt"; printf 'beta\n' > "$D/b.txt"
REC="$BASE/record.txt"
{ echo "# comment"; echo "$(sha256_of "$D/a.txt")  a.txt"; echo ""; echo "$(sha256_of "$D/b.txt")  b.txt"; } > "$REC"

verify_checksum_record "$REC" "$D/" "fixture" >/dev/null 2>&1; check "V0 intact record" 0 $?
[ "$CSV_ENTRIES" = 2 ] && check "V0b entries counted" 0 0 || check "V0b entries counted" 0 1

printf 'alphb\n' > "$D/a.txt"                      # one byte flipped
verify_checksum_record "$REC" "$D/" "fixture" >/dev/null 2>&1; check "V1 tampered byte" 1 $?
printf 'alpha\n' > "$D/a.txt"
rm "$D/b.txt"
verify_checksum_record "$REC" "$D/" "fixture" >/dev/null 2>&1; check "V2 missing file" 1 $?
printf '# only comments\n' > "$BASE/empty.txt"
verify_checksum_record "$BASE/empty.txt" "$D/" "fixture" >/dev/null 2>&1
[ "$CSV_ENTRIES" = 0 ] && check "V3 empty record visible (CSV_ENTRIES=0)" 0 0 || check "V3 empty record visible" 0 1

echo
if [ "$bad" -ne 0 ]; then echo "test-checksum-verify: $bad of $total case(s) FAILED" >&2; exit 1; fi
echo "test-checksum-verify: all $total cases passed"
