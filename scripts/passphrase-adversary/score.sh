#!/usr/bin/env bash
# Score passphrases against Rún's MAXIMUM estimator — the production code, no Gradle, no device.
#
#   printf 'one candidate per line\n' | scripts/passphrase-adversary/score.sh
#   -> "<bits>\t<ACCEPTED|refused>\t<candidate>"   (floor = CredentialPolicy.MIN_PASSPHRASE_BITS)
#
# Compiles CredentialPolicy.kt + ProtectionLevel.kt + Score.kt with kotlinc (`brew install kotlin`)
# the first time; the jar is cached under build/passphrase-adversary keyed on the sources' hash,
# so an estimator edit is picked up automatically. Used by the test:dynamic_passphrase workflow.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SRC=(
  "$ROOT/shared/src/commonMain/kotlin/com/vg/run/CredentialPolicy.kt"
  "$ROOT/shared/src/commonMain/kotlin/com/vg/run/ProtectionLevel.kt"
  "$ROOT/scripts/passphrase-adversary/Score.kt"
)
CACHE="${RUN_SCORER_CACHE:-$ROOT/build/passphrase-adversary}"
mkdir -p "$CACHE"
HASH=$(cat "${SRC[@]}" | shasum -a 256 | cut -c1-16)
JAR="$CACHE/scorer-$HASH.jar"
if [ ! -f "$JAR" ]; then
  command -v kotlinc >/dev/null || { echo "kotlinc not found: brew install kotlin" >&2; exit 2; }
  TMP="$CACHE/building-$HASH.jar"   # kotlinc picks the output type from the extension: keep .jar
  kotlinc "${SRC[@]}" -include-runtime -d "$TMP" -nowarn >&2
  mv "$TMP" "$JAR"
fi
exec java -jar "$JAR" "$@"
