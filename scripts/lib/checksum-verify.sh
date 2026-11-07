# Shared checksum-verification helpers for the scripts/verify-*.sh integrity
# gates (currently sourced by verify-gradle-wrapper.sh; verify-tor-xcframework.sh
# and verify-argon2-src.sh carry hand-copied versions of the same loop and are
# planned adopters — change THEM in a separate reviewed change, they gate
# release integrity).
#
# SOURCE this file — and fail closed if sourcing fails, because a gate that
# could not set up its hashing tool must not report OK:
#
#   . scripts/lib/checksum-verify.sh || exit 2
#
# Provides:
#   SHA256_CMD  — the hashing tool present on this system ("shasum -a 256" or
#                 "sha256sum"). Expand it UNQUOTED where a raw tool invocation
#                 is needed (e.g. `xargs $SHA256_CMD`). Both tools print
#                 "<64-hex>  <name>" (and "<64-hex>  -" for stdin), so their
#                 output is interchangeable for hashing AND for digest-of-
#                 digests constructions.
#   sha256_of FILE
#               — print the 64-hex SHA-256 of FILE.
#   verify_checksum_record RECORD PREFIX LABEL
#               — the shared record-verify loop: read "sha  path" lines from
#                 RECORD (comment/blank lines skipped), hash PREFIX+path,
#                 compare against the recorded sha. Prints "✓ path" per match;
#                 on a missing file prints "✗ LABEL missing: path" to stderr,
#                 on a mismatch "✗ path: sha256 actual != recorded sha" to
#                 stderr. Sets CSV_ENTRIES to the number of checksum entries
#                 seen (callers that must reject an empty record check it).
#                 Returns 0 only if EVERY entry existed and matched; returns 1
#                 otherwise — callers MUST treat nonzero as gate failure
#                 (fail closed), e.g.:
#
#                   verify_checksum_record "$REC" "" "Gradle wrapper file" || fail=1
#
# Compatibility: macOS /bin/bash 3.2 (no arrays, no mapfile); safe under
# `set -u` and `set -o pipefail`.

# Hashing tool. Fail closed rather than let an undefined helper degrade a gate
# into "found no mismatches". macOS ships shasum (and newer macOS also
# sha256sum); GitHub's ubuntu runners ship both.
if command -v shasum >/dev/null 2>&1; then
  SHA256_CMD="shasum -a 256"
elif command -v sha256sum >/dev/null 2>&1; then
  SHA256_CMD="sha256sum"
else
  echo "✗ neither shasum nor sha256sum is available — refusing to report checksums OK" >&2
  # `return` when sourced; `exit` if someone executed this file directly.
  return 2 2>/dev/null || exit 2
fi

sha256_of() { $SHA256_CMD "$1" | cut -d' ' -f1; }

# verify_checksum_record RECORD PREFIX LABEL   (see header comment)
verify_checksum_record() {
  local _csv_rec="$1" _csv_prefix="$2" _csv_label="$3"
  local _csv_sha _csv_rel _csv_file _csv_actual _csv_fail=0
  CSV_ENTRIES=0
  while read -r _csv_sha _csv_rel; do
    case "$_csv_sha" in \#*|"") continue ;; esac        # skip comments / blank lines
    CSV_ENTRIES=$((CSV_ENTRIES + 1))
    _csv_file="${_csv_prefix}${_csv_rel}"
    if [ ! -f "$_csv_file" ]; then
      echo "✗ ${_csv_label} missing: ${_csv_rel}" >&2; _csv_fail=1; continue
    fi
    _csv_actual="$(sha256_of "$_csv_file")"
    if [ "$_csv_actual" = "$_csv_sha" ]; then
      echo "✓ ${_csv_rel}"
    else
      echo "✗ ${_csv_rel}: sha256 ${_csv_actual} != recorded ${_csv_sha}" >&2; _csv_fail=1
    fi
  done < "$_csv_rec"
  return "$_csv_fail"
}
