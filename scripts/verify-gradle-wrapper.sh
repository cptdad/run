#!/usr/bin/env bash
# Verify the Gradle wrapper LAUNCHER — gradle-wrapper.jar
# plus the gradlew / gradlew.bat scripts that start it — against their recorded
# SHA-256, and assert that the distribution pin the jar is supposed to ENFORCE is
# still present.
#
# gradle-wrapper.properties pins distributionSha256Sum, but the code that checks
# that pin was itself unverified — the only tracked executable in the repo with no
# integrity record (tor.xcframework and the vendored Argon2 sources both have one).
# It runs with full developer privileges on every Android build, every iOS build
# (an Xcode build phase invokes ./gradlew) and every Xcode Cloud run, on the same
# machine as the release signing material. A trojaned jar could skip its own
# checksum check; a trojaned gradlew need never invoke the jar.
#
#   scripts/verify-gradle-wrapper.sh            # verify (default; pre-push + CI)
#   scripts/verify-gradle-wrapper.sh --update   # regenerate after a genuine
#                                               # `gradle wrapper` upgrade, then
#                                               # RE-ANCHOR the jar line against
#                                               # Gradle's published checksum
#
# Fail-closed everywhere: a missing record, a missing hashing tool, an empty
# record, an unpinned jar or a missing/absent distribution pin all EXIT NON-ZERO.
# Nothing here may report OK on a check it did not actually perform.
set -uo pipefail
cd "$(dirname "$0")/.."

# Shared hashing-tool selection (shasum → sha256sum fallback) + record-verify
# loop. Sourcing MUST succeed or this gate cannot verify anything — fail closed.
. scripts/lib/checksum-verify.sh || exit 2

REC="gradle/wrapper/gradle-wrapper.jar.sha256"
PROPS="gradle/wrapper/gradle-wrapper.properties"
WRAPPER_DIR="gradle/wrapper"

# Files this record MUST cover. Checked explicitly below so that deleting a line
# from the record cannot silently un-pin a launcher file — the per-line loop alone
# would then simply have less to verify and still print a green summary.
REQUIRED="gradle/wrapper/gradle-wrapper.jar gradlew gradlew.bat"

# Paths currently pinned in the record (record lines are "sha  path"; skip comments).
recorded_paths() { awk '$1 ~ /^[0-9a-fA-F]{64}$/ { print $2 }' "$REC"; }

# Jars currently on disk under the governed directory (same enumeration check #3
# below performs — --update must pin exactly what check #3 will demand).
wrapper_jars_on_disk() { find "$WRAPPER_DIR" -type f -name '*.jar' 2>/dev/null | sed 's#^\./##'; }

if [ "${1:-}" = "--update" ]; then
  [ -f "$REC" ] || { echo "✗ missing $REC — restore it from git rather than generating an unanchored one" >&2; exit 2; }
  # --update must CONVERGE with the checks below: it re-pins the UNION of
  # (a) the REQUIRED launcher files, (b) every path already recorded, and
  # (c) every jar currently under $WRAPPER_DIR (what check #3 enumerates).
  # The old behavior — rewriting from $REQUIRED alone — silently dropped any
  # other recorded pin, so a second legitimately pinned jar made check #3 fail,
  # the failure message said "run --update", and --update dropped the pin
  # again: a loop with no documented way out.
  extras="$( { recorded_paths; wrapper_jars_on_disk; } | LC_ALL=C sort -u )"
  for f in $REQUIRED; do
    extras="$(printf '%s\n' "$extras" | grep -vxF "$f")"
  done
  # A security gate must not auto-delete pins: every file about to be re-pinned
  # must exist on disk, and a RECORDED file that has vanished fails loud —
  # removing a pin is an operator decision, made by editing the record.
  missing=0
  for f in $REQUIRED; do
    [ -f "$f" ] || { echo "✗ cannot update: required launcher file is missing: $f" >&2; missing=1; }
  done
  while read -r f; do
    [ -z "$f" ] && continue
    if [ ! -f "$f" ]; then
      echo "✗ cannot update: $f is pinned in $REC but no longer exists on disk." >&2
      echo "  --update never silently drops a recorded pin. If the removal is deliberate," >&2
      echo "  delete that file's line from $REC by hand and re-run --update; otherwise" >&2
      echo "  restore the file (git checkout -- $f)." >&2
      missing=1
    fi
  done < <(printf '%s\n' "$extras")
  [ "$missing" -eq 0 ] || { echo "✗ --update aborted — $REC left untouched." >&2; exit 2; }
  tmp="$(mktemp)" || exit 2
  # Preserve the existing comment header verbatim: it carries the upstream trust
  # anchor (which published Gradle wrapper checksum the jar line matches). An
  # --update that dropped it would silently downgrade the jar to
  # trust-on-first-use.
  awk '/^[[:space:]]*(#|$)/ { print; next } { exit }' "$REC" > "$tmp"
  for f in $REQUIRED; do
    printf '%s  %s\n' "$(sha256_of "$f")" "$f" >> "$tmp"
  done
  while read -r f; do
    [ -z "$f" ] && continue
    printf '%s  %s\n' "$(sha256_of "$f")" "$f" >> "$tmp"
  done < <(printf '%s\n' "$extras")
  mv "$tmp" "$REC"
  echo "✓ rewrote $REC — RE-ANCHOR the gradle-wrapper.jar line against Gradle's"
  echo "  published wrapper checksum (downloads.gradle.org/distributions/"
  echo "  gradle-<version>-wrapper.jar.sha256) and re-review the diff before committing."
  exit 0
fi

[ -f "$REC" ] || { echo "✗ missing checksum record $REC" >&2; exit 2; }

fail=0

# 1) Every RECORD entry must exist and match its recorded hash (shared loop —
#    scripts/lib/checksum-verify.sh).
verify_checksum_record "$REC" "" "Gradle wrapper file" || fail=1
entries=$CSV_ENTRIES

# A record that pinned nothing is not a pass — a truncated or comment-only record
# would otherwise sail through the loop above.
if [ "$entries" -eq 0 ]; then
  echo "✗ $REC contains ZERO checksum entries — refusing to report OK." >&2
  exit 2
fi

# 2) Every REQUIRED launcher file must be pinned by the record.
for f in $REQUIRED; do
  if ! recorded_paths | grep -qxF "$f"; then
    echo "✗ Gradle wrapper launcher is NOT pinned in $REC: $f" >&2
    fail=1
  fi
done

# 3) enumerate-at-check (same shape as verify-argon2-src.sh): any OTHER jar under
#    gradle/wrapper/ must be pinned too. gradle-wrapper.properties' classpath is
#    fixed, but an added jar in that directory is exactly the kind of artifact a
#    reviewer skims past — pin it or remove it.
while read -r j; do
  [ -z "$j" ] && continue
  if ! recorded_paths | grep -qxF "$j"; then
    echo "✗ unpinned jar under $WRAPPER_DIR: $j — pin it via 'verify-gradle-wrapper.sh --update' after review." >&2
    fail=1
  fi
done < <(wrapper_jars_on_disk | LC_ALL=C sort)

# 4) The pin the jar EXISTS to enforce must still be there. Verifying the jar and
#    leaving distributionSha256Sum blank would be a green check over an unverified
#    ~150 MB distribution download.
if [ ! -f "$PROPS" ]; then
  echo "✗ missing $PROPS — the wrapper has no distribution pin at all." >&2
  fail=1
else
  if ! grep -qE '^distributionSha256Sum=[0-9a-fA-F]{64}[[:space:]]*$' "$PROPS"; then
    echo "✗ $PROPS has no 64-hex distributionSha256Sum — the downloaded Gradle distribution would be unverified." >&2
    fail=1
  fi
  # The properties file escapes the colon (https\://…), so accept an optional backslash.
  if ! grep -qE '^distributionUrl=https(\\)?://' "$PROPS"; then
    echo "✗ $PROPS distributionUrl is not https:// — the distribution would be fetched over an unauthenticated channel." >&2
    fail=1
  fi
  if grep -qE '^validateDistributionUrl=false' "$PROPS"; then
    echo "✗ $PROPS sets validateDistributionUrl=false — re-enable it (default is true)." >&2
    fail=1
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo "✗ Gradle wrapper integrity check FAILED — the code that runs on every Android/iOS/Xcode-Cloud build does not match its recorded state. Investigate tampering; if this follows a deliberate 'gradle wrapper' upgrade, run scripts/verify-gradle-wrapper.sh --update and re-anchor the jar against Gradle's published checksum." >&2
  exit 1
fi
echo "✓ Gradle wrapper launcher ($entries files) matches its recorded SHA-256, and the distribution pin is intact."
exit 0
