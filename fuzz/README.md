# `:fuzz` — Jazzer fuzzing harnesses for Rún's untrusted-input parsers

Rún parses attacker-controlled bytes in five places, all of them hand-rolled
(deliberately: Kotlin/Native's regex engine matches recursively and blows the
native stack, so every scanner in `:shared` is a single forward pass with manual
index arithmetic). Hand-written index arithmetic at a trust boundary is exactly
what a coverage-guided fuzzer is for.

This module holds those harnesses. Each one is a Jazzer `@FuzzTest`, which means
it runs **two ways**:

| mode | command | what happens |
|---|---|---|
| **regression** | `./gradlew :fuzz:test` | Jazzer replays every file in the harness's corpus as an ordinary JUnit 5 test. Seconds. No Jazzer agent needed beyond the JUnit extension. This is what CI runs. |
| **fuzzing** | `./gradlew :fuzz:fuzz` | libFuzzer drives each harness — **in its own JVM**, see below — for its `@FuzzTest(maxDuration=…)` budget, mutating from the seed corpus and writing any finding back into the corpus as a permanent regression. |

Neither runs as part of `./gradlew test`.

---

## Running

```bash
# Regression replay of every seed + every committed crash reproducer (fast).
./gradlew :fuzz:test

# Fuzz EVERY harness, 60s each, one forked JVM per harness.
./gradlew :fuzz:fuzz

# …longer.
./gradlew :fuzz:fuzz -PfuzzDuration=600s

# Fuzz ONE harness. Every @FuzzTest method has its own task, named after the
# method; `./gradlew :fuzz:tasks --group verification` lists them.
./gradlew :fuzz:fuzzDecryptBatchAgainstLiveSession -PfuzzDuration=900s

# Ad-hoc filter.
./gradlew :fuzz:fuzzOne --tests 'com.vg.run.fuzz.JsonScannerFuzzTest.fuzzScanners'

# Is the `internal` bridge into :shared still wired? (Empty output = broken.)
./gradlew :fuzz:fuzzFriendPaths
```

`-Pfuzz=1` on any invocation also enables the module, which is how you would
wire it into a nightly job without naming the tasks.

### One JVM per harness — a correctness requirement, not an optimisation

**Jazzer fuzzes only the FIRST `@FuzzTest` a JVM encounters.** libFuzzer's driver
is initialised once per process, so every later `@FuzzTest` in the same JVM
quietly degrades to regression mode: its corpus replays, the `Fuzzing...` phase
is skipped, the test reports PASSED, and nothing warns you. A single `Test` task
covering all the harnesses therefore *looks* like a full campaign while having
fuzzed exactly one harness — which is what happened on the first run here (19
harnesses "green" in 64 seconds; one of them had actually been fuzzed).

`:fuzz:fuzz` is an aggregate over one `Test` task per harness method, so each gets
its own forked JVM. The task list is derived from the sources at configuration
time, so a newly added `@FuzzTest` is picked up with no bookkeeping. If you write
your own runner, fork per harness — and treat "all harnesses finished
suspiciously fast" as the symptom of this trap.

Jazzer needs no separate install: `com.code-intelligence:jazzer-junit` carries
the libFuzzer driver natives for macOS/Linux on x86-64 and arm64, and
`jazzer-junit` activates them through the JUnit 5 extension. Verified working on
macOS 27 / arm64 under both JDK 21 and JDK 26.

### CI

`.github/workflows/release-gates.yml` names its Gradle targets explicitly
(`:shared:testDebugUnitTest :androidApp:testDebugUnitTest`), so `:fuzz` is
already excluded. To keep the crash corpus enforced, add `:fuzz:test` to that
list — it is the fast, deterministic regression replay, not a fuzz run. The
Jazzer artifacts are already sha256-pinned in
`gradle/verification-metadata.xml`, and the one jar carries the driver natives
for linux-x86_64 as well as macOS, so the Ubuntu runner needs nothing extra.

Do NOT put `:fuzz:fuzz` in the push/PR gate: it is minutes of CPU per harness
and its result is time-dependent. It belongs in a scheduled job.

---

## Module layout

```
fuzz/
  build.gradle.kts                      opt-in gating, -Xfriend-paths wiring,
                                        per-harness fan-out
  README.md                             this file
  findings/                             fuzz-run logs (committed; see Findings).
                                        Crash INPUTS do not live here — Jazzer
                                        writes them into the seed corpus so
                                        `:fuzz:test` replays them forever.
  .cifuzz-corpus/                       Jazzer's GENERATED working corpus.
                                        Gitignored: it is re-derived on every
                                        run and is not a regression record.
  src/test/kotlin/com/vg/run/fuzz/
      FuzzSupport.kt                    in-memory VaultDatabase / RelayHttp /
                                        RatchetStore doubles, `bounded`,
                                        `onlyThrows`, fixed ids
      JsonScannerFuzzTest.kt            the shared JSON scanners
      EnvelopeFuzzTest.kt               legacy envelope field parsing + unpad
      RatchetWireFuzzTest.kt            ratchet wire + persisted state + decryptBatch
      GroupControlFuzzTest.kt           group control bodies + parked invites
      ReferralControlFuzzTest.kt        referral offer/accept bodies
      PairingPayloadFuzzTest.kt         QR / paste-code decoders
      RelayResponseFuzzTest.kt          relay poll/peek/PoW-challenge bodies
      MigrationBundleFuzzTest.kt        device-move bundle + seal
  src/test/resources/com/vg/run/fuzz/
      <ClassName>Inputs/<methodName>/   seed corpus, one raw input per file
```

### Why an Android library module

`:shared` is a Kotlin Multiplatform module whose only JVM-shaped target is
`androidTarget()`. It publishes an AAR, which a `java-library` /
`kotlin("jvm")` project cannot consume (no `java-api`/`java-runtime` variant).
A `com.android.library` module resolves it natively, and its *unit* tests run on
the plain JVM — which is where Jazzer needs to be. Nothing here touches the
Android framework, SQLCipher, Tor or the network.

### Why `-Xfriend-paths`

Almost every parser worth fuzzing is `internal` to `:shared`: `DoubleRatchet`,
`decodeRatchetWire`, `RatchetManager`, `parseTopLevelJson`, `jsonStringField`,
`parseStringArrayField`, `GroupInviteStore.decode`, `MigJson`,
`MessageManager.parseEnvelope`, `MessageManager.parseChallenge`. From another
Gradle module those do not merely fail a visibility check — they do not resolve
at all ("Unresolved reference").

`-Xfriend-paths` is the supported escape hatch (it is the same mechanism KGP uses
to let a module's own test source set see its `internal` API). The catch is that
the friend path must be the **exact classpath entry** the compiler reads those
classes from, so `build.gradle.kts` derives it from the `KotlinCompile` task's
own `libraries`, filtered to files under `shared/`. Two things that do **not**
work, recorded so nobody re-discovers them:

* depending on the raw `shared/build/tmp/kotlin-classes/debug` **directory** — a
  directory file-dependency carries `artifactType=directory`, which AGP never
  requests, so it is silently dropped from the compile classpath and *nothing*
  from `:shared` resolves, not even public API;
* an `artifactView` over `debugUnitTestCompileClasspath` — it fails variant
  selection unless the `artifactType` attribute is replicated exactly.

If `./gradlew :fuzz:fuzzFriendPaths` prints nothing, that wiring has broken and
every `internal` symbol will fail to compile.

---

## The harnesses

| harness | target | why it is a trust boundary |
|---|---|---|
| `JsonScannerFuzzTest.fuzzScanners` | `parseTopLevelJson`, `jsonStringField`, `jsonUnescapeString`, `jsonEscapeString`, `parseStringArrayField`, `parseJsonStringArray` | every other parser is built on these |
| `JsonScannerFuzzTest.fuzzDeepNesting` | same, on synthesised deep nesting | the scanners' whole reason to exist is that recursion SIGABRTs iOS |
| `EnvelopeFuzzTest.fuzzParseEnvelope` | `MessageManager.parseEnvelope` | post-AEAD plaintext — composed by the PEER, who is in the malicious-peer threat model |
| `EnvelopeFuzzTest.fuzzUnpadMessage` | `unpadMessage` | reads a big-endian length prefix out of peer-composed plaintext |
| `RatchetWireFuzzTest.fuzzDecodeRatchetWire` | `decodeRatchetWire`, `MessageManager.isRatchetWire` | relay-supplied bytes, parsed before any authentication |
| `RatchetWireFuzzTest.fuzzDeserializeRatchetState` | `DoubleRatchet.deserialize` | the code documents "clean IllegalArgumentException, never IndexOutOfBounds" |
| `RatchetWireFuzzTest.fuzzDecryptBatchAgainstLiveSession` | `RatchetManager.decryptBatch` against a real bootstrapped session | the header is acted on (skip keys, DH step) **before** the AEAD tag is checked |
| `GroupControlFuzzTest.fuzzGroupControlBody` | `GroupManager.handleControl` (invite/join/roster/leave/activity/screenshot) | a malicious group member rewriting the roster |
| `GroupControlFuzzTest.fuzzParkedInviteRow` | `GroupInviteStore.decode`, `decodeDeclinedInvites` | a tampered `_meta` row must not park an invite the receive path would refuse |
| `ReferralControlFuzzTest.fuzzReferralBody` | `ReferralManager.handleControl` → offer/accept | the only path where a THIRD party's data crosses into the vault via someone else's envelope |
| `PairingPayloadFuzzTest.fuzzPairingPayload` | `PairingPayload.parse` | the pairing trust boundary — bytes a stranger holds up to the camera |
| `PairingPayloadFuzzTest.fuzzMoveHandle` | `MoveHandleCodec.parse`, `MigrationSeal.decodeCode`, `Base32.decode` | same, for device move |
| `RelayResponseFuzzTest.fuzzPollResponse` | `parseJsonStringArray("blobs")`, `/peek` | hostile relay, pre-auth |
| `RelayResponseFuzzTest.fuzzPowChallenge` | `MessageManager.parseChallenge` | pre-auth mint handshake; the token is echoed verbatim into an HTTP header |
| `RelayResponseFuzzTest.fuzzPowPredicate` | `computePowHash`, `hashHasLeadingZeroBits`, `solvePow` | a hostile difficulty must cost the client nothing |
| `MigrationBundleFuzzTest.fuzzBundleDecode` | `MigrationBundleCodec.decode` | a bad bundle does not fail loudly, it produces a wrong vault |
| `MigrationBundleFuzzTest.fuzzBundleDocument` | `MigJson.parseBundleDocument`, `MigJson.strictLong` | " |
| `MigrationBundleFuzzTest.fuzzBundleDocumentNesting` | same, deep | " |
| `MigrationBundleFuzzTest.fuzzSealOpen` | `MigrationSeal.open` | relay-supplied chunk list, structural checks before the AEAD |

### The invariant style

Every harness follows the same shape:

```kotlin
@FuzzTest(maxDuration = "60s")
fun fuzzX(data: FuzzedDataProvider) {
    val input = data.consumeRemainingAsString()     // or …AsBytes()
    onlyThrows(TheOneDocumentedException::class) {  // anything else = finding
        val result = bounded("label") { target(input) }   // wall-time bound
        // …assertions on the RESULT, not just on "it didn't crash"
    }
}
```

Three deliberate choices:

* **`onlyThrows` allowlists the DOCUMENTED exception type and nothing else.**
  `Error` is never in the allowlist: product code catches `Exception`, so a
  `StackOverflowError`/`OutOfMemoryError` out of a parser is a crash no matter
  how defensive the caller is — and on iOS an uncaught Kotlin throwable is a
  SIGABRT.
* **`bounded` puts a 5 s wall-clock ceiling on one input.** These scanners are
  sub-millisecond on real input; the failure mode being hunted is a quadratic
  rescan (`jsonStringField` restarts its outer scan after every false `"key"`
  match). A true infinite loop is caught by libFuzzer's own `-timeout`, not by
  this.
* **The assertions are on the RESULT.** "Did not throw" is a weak property. The
  harnesses assert the security claims the doc comments make: the counter cannot
  be smuggled inside a string value, a reflected own-secret QR is refused, a
  parked invite must satisfy every rule `handleInvite` applies, a rejected
  ratchet blob cannot poison the genuine blob behind it in the same batch.

### Each harness consumes ONE blob

`FuzzedDataProvider` takes strings from the front of the buffer and integrals
from the back, so a harness that mixes both makes its seed files unreadable.
Every harness here consumes a single `consumeRemainingAsString()` /
`consumeRemainingAsBytes()` (the three that need a size/depth take their
integrals first and are documented as such), which means **a seed file is
literally the JSON text or the wire bytes**. You can read and edit the corpus in
an editor.

---

## Adding a harness

1. Put it in `fuzz/src/test/kotlin/com/vg/run/fuzz/<Area>FuzzTest.kt`.
2. Annotate with `@FuzzTest(maxDuration = "60s")` and take a single
   `FuzzedDataProvider`. The method must not be `private`.
3. Consume the input as one blob. Name the documented exception type in
   `onlyThrows(...)`; wrap the call in `bounded("…") { … }`.
4. Assert something about the RESULT, not only that it returned.
5. Drop 5–10 seeds in
   `fuzz/src/test/resources/com/vg/run/fuzz/<ClassName>Inputs/<methodName>/`.
   Cover the happy path, each documented rejection, and the boundary values.
   The corpus is committed as plain files with no generator behind it — add
   more files by hand.
6. `./gradlew :fuzz:test` to check the seeds replay, then
   `./gradlew :fuzz:<methodName>` to fuzz it (the per-harness task is registered
   automatically from the source — no list to update).

If the target is `internal`, nothing extra is needed — `-Xfriend-paths` already
covers all of `:shared`. If it is an instance method, build the object with the
doubles in `FuzzSupport.kt` (`InMemoryVault`, `DeadRelayHttp`,
`InMemoryRatchetStore`); do not reach for a real `DatabaseManager` or a real
transport.

---

## Findings

Full campaign: **2026-09-16, all 19 harnesses, 60 s each, one JVM per harness**,
macOS 27 / arm64, JDK 26. Condensed log: `fuzz/findings/fuzz-run-20260916.log`.

**No crash was found. 19/19 harnesses PASSED, 394,537,344 total executions.**
No `IndexOutOfBoundsException`, no `NumberFormatException`, no
`NullPointerException`, no `StackOverflowError`, no unbounded allocation, no
libFuzzer OOM/timeout, and no input exceeded the 5 s per-input budget. Jazzer
wrote no crash reproducer into any corpus directory.

| harness | seeds | cov | feat | executions |
|---|---:|---:|---:|---:|
| `fuzzBundleDecode` | 9 | 18 | 24 | 13,313,453 |
| `fuzzBundleDocument` | 10 | 33 | 75 | 53,835,791 |
| `fuzzBundleDocumentNesting` | 3 | 7 | 7 | 999,255 |
| `fuzzDecodeRatchetWire` | 14 | 21 | 27 | 14,595,035 |
| `fuzzDecryptBatchAgainstLiveSession` | 7 | 55 | 57 | 326,903 |
| `fuzzDeepNesting` | 5 | 30 | 58 | 63,323 |
| `fuzzDeserializeRatchetState` | 10 | 15 | 17 | 15,387,995 |
| `fuzzGroupControlBody` | 10 | 70 | 74 | 12,766,627 |
| `fuzzMoveHandle` | 8 | 18 | 18 | 32,686,739 |
| `fuzzPairingPayload` | 10 | 39 | 49 | 13,383,360 |
| `fuzzParkedInviteRow` | 7 | 33 | 53 | 13,109,640 |
| `fuzzParseEnvelope` | 10 | 46 | 46 | 57,930,890 |
| `fuzzPollResponse` | 11 | 20 | 20 | 13,081,640 |
| `fuzzPowChallenge` | 10 | 21 | 35 | 40,179,418 |
| `fuzzPowPredicate` | 6 | 21 | 21 | 53,019,312 |
| `fuzzReferralBody` | 9 | 48 | 54 | 30,942,636 |
| `fuzzScanners` | 23 | 47 | 56 | 7,567,710 |
| `fuzzSealOpen` | 4 | 28 | 79 | 3,091,052 |
| `fuzzUnpadMessage` | 9 | 12 | 12 | 18,256,565 |

(`seeds` is what libFuzzer loaded, which for some harnesses exceeds the committed
file count because the previous run's minimised corpus is merged in. `cov`/`feat`
are libFuzzer's final edge and feature counts.)

A clean result here is not vacuous: the harnesses assert the SECURITY properties
the doc comments claim — depth-1 key isolation, ratchet rollback isolation, QR
echo rejection, PoW header-injection rejection, parked-invite validation
equivalence — not merely that nothing threw. The two lowest-throughput harnesses
are the two doing real work per input (`fuzzDecryptBatchAgainstLiveSession` runs
X25519 + AES-GCM per execution, `fuzzDeepNesting` builds strings up to 400 KB),
which is expected, not a stall.

### Observations (report-only — NO product code was changed)

1. **`MigJson.strictLong` cannot parse `Long.MIN_VALUE`** (LOW / cosmetic).
   The overflow guard `acc > (Long.MAX_VALUE - d) / 10` runs on the *magnitude*
   before the sign is applied, so `"-9223372036854775808"` is rejected while
   `"-9223372036854775807"` parses. Not exploitable: every field it reads is a
   counter, epoch or millisecond timestamp, none of which legitimately reaches
   `Long.MIN_VALUE`, and the failure mode is a clean `FormatException` ("bad
   bundle"), never a wrong value. Pinned by
   `MigrationBundleFuzzTest.strictLongRejectsUnicodeDigitsAndLeadingPlus` so a
   future change is deliberate.

2. **`parseEnvelope` accepts a NEGATIVE counter and epoch** (INFO).
   `{"c":-1}` parses to `counter = -1L`. Harmless today — the anti-replay test is
   `counter <= inboundCounter`, so a negative counter is always dropped, and the
   epoch is an opaque tag compared for equality. It matters only if the replay
   check is ever rewritten in terms of arithmetic (e.g. a window `counter -
   inboundCounter < N`), where a negative value would change behaviour. Pinned
   indirectly by the `negative-counter` seed.

3. **`MessageManager.parseChallenge` does not bound `difficulty`** (INFO).
   It validates the length and character set of `nonce`/`token` — which are
   echoed verbatim into HTTP headers, so CRLF there would be header injection on
   the iOS raw-HTTP transport — but passes `difficulty` through unclamped,
   including negative values and `Int.MAX_VALUE`. The clamp lives one layer down
   in `solvePow` (`PowDifficultyTooHigh` above `MAX_POW_DIFFICULTY_BITS`,
   immediate `0L` for `difficulty <= 0`), so a hostile relay still cannot make the
   client grind. `fuzzPowChallenge` asserts that refusal for every over-ceiling
   difficulty the fuzzer produced. Worth knowing that the safety lives entirely
   in the consumer, not in the parser.

4. **`hashHasLeadingZeroBits` has an implicit, undocumented precondition**
   (INFO). It indexes `hash[bits / 8]` with no bound of its own and relies on
   callers having clamped `difficulty` to `MAX_POW_DIFFICULTY_BITS` (23) against a
   32-byte digest. Every caller does today. `fuzzPowPredicate` encodes the
   precondition explicitly — `IndexOutOfBoundsException` is *allowed* only when
   `bits > hash.size * 8` — so a future caller that forgets the clamp fails here
   rather than on a device.

None of the four warrants a product change on its own; all four are now pinned by
tests so the behaviour cannot drift silently.

### When a finding IS produced

Jazzer writes the reproducing input into the harness's corpus directory
(`src/test/resources/…/<ClassName>Inputs/<methodName>/crash-<sha1>`) and prints a
reproducer command. **Commit the crash file** — that turns the finding into a
permanent regression `./gradlew :fuzz:test` replays forever. Then write the
minimised case as a plain `@Test` next to the harness, with severity and
reasoning in its KDoc, and add it to the list above.
