#!/usr/bin/env bash
# Run the real cracker sources through Rún's MAXIMUM passphrase estimator (owner directive
# 2026-11-08: "use the same sources a hacker would use for brute force"). Everything is streamed
# through scripts/passphrase-adversary/score.sh — the production CredentialPolicy compiled standalone.
#
#   scripts/passphrase-adversary/cracker-sources.sh [<out dir>]      # default: <scratchpad>/passphrase-adversary/sources
#
# Sources (downloaded once into <out>/raw, each in its own directory; the files are DATA, never executed):
#   passphrases   initstring/passphrase-wordlist v2025.1 — ~20 M real phrases (lyrics, quotes, Wikipedia/IMDb titles,
#                 Urban Dictionary, Know Your Meme…), the standard passphrase-cracking list, plus its hashcat rules.
#   rockyou       SecLists Passwords/Leaked-Databases/rockyou.txt — the canonical leaked-password list (14 M).
#   pwdb-top1m    SecLists Passwords/Common-Credentials/Pwdb_top-1000000.txt — top 1 M of a 2.1 B-password corpus.
#   tatoeba-<l>   Tatoeba sentences per language (sv nb da fi de fr es ru ar fa so mk en) — the "common sentences
#                 of a language" a targeted attacker feeds a combinator/phrase attack.
# Passes:
#   1. every line of every source scored; ACCEPTED lines kept (<out>/accepted/<source>.tsv), stats per source.
#   2. hashcat rules (passphrase-rule1 + rule2) applied to a sample of REFUSED phrases in [45,70) bits — the cracker's
#      mangling step (Capitalise, strip spaces, append digits…) — and the variants scored again.
# Output: <out>/report-sources.md (+ the per-source tsv files). Idempotent: downloads and passes already done are skipped.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCORE="$ROOT/scripts/passphrase-adversary/score.sh"
OUT="${1:-$ROOT/build/passphrase-adversary/sources}"
RAW="$OUT/raw"; LISTS="$OUT/lists"; ACC="$OUT/accepted"; STATS="$OUT/stats"
mkdir -p "$RAW" "$LISTS" "$ACC" "$STATS"
RULE_SAMPLE="${RULE_SAMPLE:-150000}"   # refused near-miss phrases fed to the hashcat rules

fetch() { # name url
  local f="$RAW/$1"
  [ -s "$f" ] && return 0
  echo "== fetch $1" >&2
  curl -sSL --retry 3 -o "$f.part" "$2" && mv "$f.part" "$f"
}

echo "== sources -> $OUT" >&2
fetch passphrases.txt https://github.com/initstring/passphrase-wordlist/releases/download/v2025.1/passphrases.txt
fetch passphrase-rule1.rule https://raw.githubusercontent.com/initstring/passphrase-wordlist/master/hashcat-rules/passphrase-rule1.rule
fetch passphrase-rule2.rule https://raw.githubusercontent.com/initstring/passphrase-wordlist/master/hashcat-rules/passphrase-rule2.rule
fetch rockyou.txt.tar.gz https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz
fetch Pwdb_top-1000000.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/Pwdb_top-1000000.txt
TATOEBA="sv:swe nb:nob da:dan fi:fin de:deu fr:fra es:spa ru:rus ar:ara fa:pes so:som mk:mkd en:eng"   # app locale : Tatoeba ISO-639-3
for pair in $TATOEBA; do l=${pair%%:*}; t=${pair##*:}
  fetch "tatoeba-$l.tsv.bz2" "https://downloads.tatoeba.org/exports/per_language/$t/${t}_sentences.tsv.bz2"
done

# Normalise: one UTF-8 candidate per line (invalid bytes dropped, CR stripped) and hashcat's
# `$HEX[..]` convention (non-printable candidates as hex) decoded back to the candidate itself —
# scoring the literal "$HEX[...]" string would credit it as a long mixed-class token.
norm() { python3 -I -c '
import sys, re, binascii
rx = re.compile(rb"^\$HEX\[([0-9a-fA-F]+)\]$")
out = sys.stdout.buffer
for line in sys.stdin.buffer:
    line = line.rstrip(b"\r\n")
    m = rx.match(line)
    if m:
        try: line = binascii.unhexlify(m.group(1))
        except binascii.Error: pass
    out.write(line.decode("utf-8", "ignore").encode("utf-8") + b"\n")
'; }
[ -s "$LISTS/passphrases.txt" ] || norm < "$RAW/passphrases.txt" > "$LISTS/passphrases.txt"
[ -s "$LISTS/rockyou.txt" ] || tar -xOzf "$RAW/rockyou.txt.tar.gz" | norm > "$LISTS/rockyou.txt"
[ -s "$LISTS/pwdb-top1m.txt" ] || norm < "$RAW/Pwdb_top-1000000.txt" > "$LISTS/pwdb-top1m.txt"
for pair in $TATOEBA; do l=${pair%%:*}
  [ -s "$LISTS/tatoeba-$l.txt" ] || bzcat "$RAW/tatoeba-$l.tsv.bz2" | cut -f3 | norm > "$LISTS/tatoeba-$l.txt"
done

# Pass 1: score every source.
for f in "$LISTS"/*.txt; do
  n=$(basename "$f" .txt)
  [ -s "$STATS/$n.txt" ] && continue
  echo "== score $n ($(wc -l < "$f" | tr -d ' ') lines)" >&2
  "$SCORE" --accepted-only --stats < "$f" > "$ACC/$n.tsv" 2> "$STATS/$n.txt"
done

# Pass 2: hashcat rules on refused near misses from the PHRASE sources (passphrases + tatoeba).
if command -v hashcat >/dev/null; then
  if [ ! -s "$STATS/rules.txt" ]; then
    echo "== rules: sampling $RULE_SAMPLE refused phrases in [45,70) bits" >&2
    for f in "$LISTS"/passphrases.txt "$LISTS"/tatoeba-*.txt; do "$SCORE" --raw-range 45 70 < "$f"; done \
      | awk 'BEGIN{srand(7)} {print rand() "\t" $0}' | sort -k1,1n | awk -v n="$RULE_SAMPLE" 'NR<=n' | cut -f2- > "$LISTS/near-misses.txt"   # awk, not head: SIGPIPE under pipefail
    cat "$RAW/passphrase-rule1.rule" "$RAW/passphrase-rule2.rule" | grep -vE '^\s*(#|$)' | sort -u > "$LISTS/rules.rule"
    echo "== rules: $(wc -l < "$LISTS/rules.rule" | tr -d ' ') rules × $(wc -l < "$LISTS/near-misses.txt" | tr -d ' ') phrases" >&2
    hashcat --stdout --force -r "$LISTS/rules.rule" "$LISTS/near-misses.txt" 2>/dev/null | norm | sort -u \
      | "$SCORE" --accepted-only --stats > "$ACC/rules.tsv" 2> "$STATS/rules.txt"
  fi
else
  echo "hashcat not installed: skipping the rules pass (brew install hashcat)" >&2
fi

# Report.
R="$OUT/report-sources.md"
{
  echo "# Cracker sources vs Rún's MAXIMUM passphrase floor (70 bits)"
  echo
  echo "Scorer: production CredentialPolicy (scripts/passphrase-adversary/score.sh). Generated by cracker-sources.sh."
  echo
  echo "| source | lines | accepted | share | 70-79 | 80-89 | 90-99 | 100+ |"
  echo "|---|---:|---:|---:|---:|---:|---:|---:|"
  for s in "$STATS"/*.txt; do
    n=$(basename "$s" .txt)
    tot=$(sed -n 's/^total=\([0-9]*\).*/\1/p' "$s"); acc=$(sed -n 's/.*accepted=\([0-9]*\).*/\1/p' "$s"); pct=$(sed -n 's/.*(\([0-9.]*\)%).*/\1/p' "$s")
    h=$(sed -n 's/^histogram(bits): //p' "$s")
    b7=$(echo "$h" | tr ' ' '\n' | sed -n 's/^70://p'); b8=$(echo "$h" | tr ' ' '\n' | sed -n 's/^80://p'); b9=$(echo "$h" | tr ' ' '\n' | sed -n 's/^90://p')
    b10=$(echo "$h" | tr ' ' '\n' | awk -F: '$1>=100{s+=$2} END{print s+0}')
    echo "| $n | $tot | $acc | $pct % | $b7 | $b8 | $b9 | $b10 |"
  done
  echo
  for a in "$ACC"/*.tsv; do
    n=$(basename "$a" .tsv); c=$(wc -l < "$a" | tr -d ' ')
    [ "$c" -gt 0 ] || continue
    echo "## $n — $c accepted, 25 samples (highest bits first, then a random 10)"
    echo
    echo '```'
    sort -t$'\t' -k1,1nr "$a" | awk 'NR<=15'
    awk 'BEGIN{srand(3)} {print rand() "\t" $0}' "$a" | sort -k1,1n | awk 'NR<=10' | cut -f2-
    echo '```'
    echo
  done
} > "$R"
echo "== report: $R" >&2
