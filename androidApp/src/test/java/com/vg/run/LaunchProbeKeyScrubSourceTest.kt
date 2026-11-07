package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * **Every THROWAWAY [CryptoProvider] built on
 * the Android launch path must be scrubbed before that path returns.**
 *
 * WHAT WENT WRONG. `MainActivity.onCreate` runs two pre-unlock probes that both
 * DECRYPT with the device key — `InactivityWipe.checkAndWipeIfNeeded` (reads the
 * protection tier + the sealed last-active stamp) and the orphaned-credential
 * self-heal (`VaultSelector.credentialsReadable`) — and each built its own
 * `CryptoProvider` for the job. Decrypting unwraps the Tink/Keystore AES-256 data
 * keyset into process RAM. The orphan probe passed its provider INLINE as a
 * constructor argument, and `VaultSelector.crypto` is `private`, so no `wipeKey()`
 * was reachable from `MainActivity` at all; `InactivityWipe` owned its provider but
 * scrubbed it only on the two DESTRUCTIVE branches (and there for a different
 * reason — crypto-erase-first). So on the overwhelmingly common path — a healthy
 * configured vault, every single launch — the process reached the PIN screen with
 * the unwrapped keyset still cached in objects nobody could reach to wipe, for a
 * RAM acquisition to pick up. Commit 41633aa closed this class on iOS's three
 * `inactivityCrypto` sites and on Android's two InactivityWipe wipe branches; these
 * two ordinary-path launches were the remainder.
 *
 * These providers are THROWAWAYS — `RunViewModel.cryptoProvider` is the long-lived
 * one the unlock actually uses, and it is untouched — so the scrub cannot break a
 * subsequent unlock. Android's `wipeKey()` only drops the cached `CryptoManager`,
 * which `manager()` re-creates lazily on the next use, and it writes nothing, so it
 * is also safe AFTER a crypto-erase.
 *
 * WHY A SOURCE GUARD. Both call sites need a real `Context` (Keystore + Tink +
 * SharedPreferences) and `MainActivity.onCreate` needs a real Activity lifecycle,
 * so neither is reachable from this module's plain-JVM `test` source set (no
 * Robolectric, no mocking framework on the classpath). Same tier and same
 * justification as [TorDataDirPreservationSourceTest], [ProcessWipeCoverTest] and
 * [PrefsApplySourceGuardTest]. The ORDERING half — scrub strictly before the
 * crypto-erase — is a property of the written code anyway, which is exactly what a
 * source guard can pin and a behavioural test on a device cannot observe.
 */
class LaunchProbeKeyScrubSourceTest {

    private val mainActivity: String by lazy {
        stripComments(File(repoRoot(), MAIN_ACTIVITY).readText())
    }
    private val inactivityWipe: String by lazy {
        stripComments(File(repoRoot(), INACTIVITY_WIPE).readText())
    }

    // -----------------------------------------------------------------------
    // MainActivity — the orphaned-credential probe
    // -----------------------------------------------------------------------

    /**
     * The provider must be OWNED by a named local. Passing it inline as
     * `crypto = CryptoProvider(this)` is the exact regression: `VaultSelector`
     * keeps it private and exposes no scrub, so the last reference is the
     * argument expression and nothing can ever wipe it.
     */
    @Test
    fun orphanProbe_ownsItsProviderInANamedLocal() {
        assertTrue(
            "MainActivity's orphan check must hold its CryptoProvider in a named local " +
                "(`val orphanCrypto = CryptoProvider(this)`) so it can be scrubbed",
            mainActivity.contains("val orphanCrypto = CryptoProvider(this)"),
        )
    }

    /**
     * The catch-all. Without this the HEALTHY path — which is every launch —
     * returns with the keyset still cached.
     */
    @Test
    fun orphanProbe_scrubsInAFinallyThatCoversTheHealthyPath() {
        assertTrue(
            "the orphan-probe block must scrub its provider in a `finally`, so the " +
                "healthy path (and any throw out of the probe) drops the unwrapped " +
                "Tink keyset too — not only the rare orphan-wipe branch",
            FINALLY_SCRUB.containsMatchIn(normalize(mainActivity)),
        )
    }

    /**
     * Crypto-erase-FIRST. The destructive branch must drop the in-RAM keyset
     * BEFORE `WipeRoutine` destroys the Keystore master key — the `finally` runs
     * after `wipePersistentState` and is therefore NOT a substitute. Mirrors
     * `InactivityWipe` and `RunViewModel.performEmergencyWipe`.
     */
    @Test
    fun orphanProbe_scrubsBeforeTheCryptoErase() {
        // The probe lives in its own helper, called from onCreate.
        assertTrue(
            "onCreate must still run the orphaned-credential self-heal",
            mainActivity.functionBody("    override fun onCreate(savedInstanceState: Bundle?) {")
                .contains("selfHealOrphanedCredentials()"),
        )
        val onCreate = mainActivity.functionBody("    private fun selfHealOrphanedCredentials() {")
        assertEquals(
            "precondition: the self-heal must contain exactly one WipeRoutine.wipePersistentState " +
                "call, so the ordering assertion below is unambiguous",
            1,
            onCreate.occurrences("WipeRoutine.wipePersistentState(this)"),
        )
        assertEquals(
            "MainActivity must contain no other WipeRoutine.wipePersistentState(this) call",
            1,
            mainActivity.occurrences("WipeRoutine.wipePersistentState(this)"),
        )
        val scrub = onCreate.indexOf("orphanCrypto.wipeKey()")
        val erase = onCreate.indexOf("WipeRoutine.wipePersistentState(this)")
        assertTrue("precondition: both markers must be present", scrub >= 0 && erase >= 0)
        assertTrue(
            "the orphan-wipe branch must call orphanCrypto.wipeKey() BEFORE " +
                "WipeRoutine.wipePersistentState — a RAM capture taken right after the " +
                "crypto-erase must not still find the keyset the erase just destroyed on disk",
            scrub < erase,
        )
    }

    // -----------------------------------------------------------------------
    // InactivityWipe — the dead-man's-switch probe
    // -----------------------------------------------------------------------

    /**
     * The sibling of the orphan probe, one statement earlier in the same
     * `onCreate`. It has SEVEN non-destructive `return false` paths; only a
     * `finally` covers them all.
     */
    @Test
    fun inactivityProbe_scrubsItsProviderOnEveryExitPath() {
        val fn = inactivityWipe.functionBody("    fun checkAndWipeIfNeeded(")
        assertTrue(
            "checkAndWipeIfNeeded must own its CryptoProvider and scrub it in a `finally` — " +
                "its many `return false` paths (device key unavailable, level unreadable, " +
                "no vault configured, the ordinary not-expired launch) all left the " +
                "unwrapped Tink keyset cached in a provider nobody else can reach",
            fn.contains("val crypto = CryptoProvider(context)") &&
                FINALLY_SCRUB_LOCAL.containsMatchIn(normalize(fn)),
        )
    }

    /**
     * Regression guard on the ordering commit 41633aa's siblings already had: the
     * `finally` above must not tempt anyone to delete the ordered pre-erase scrub,
     * which is the one that matters on the destructive branches.
     */
    @Test
    fun inactivityProbe_stillScrubsBeforeEveryCryptoErase() {
        val fn = normalize(inactivityWipe.functionBody("    private fun checkAndWipeIfNeededInner("))
        val erases = fn.occurrences("wipeAllData(context)")
        assertEquals(
            "precondition: the two destructive branches (deleted-timestamp tamper, expired " +
                "window) must both still be present",
            2,
            erases,
        )
        assertEquals(
            "every wipeAllData(context) must be IMMEDIATELY preceded by crypto.wipeKey() — " +
                "the trailing finally runs after the erase and cannot stand in for it",
            erases,
            fn.occurrences("crypto.wipeKey() wipeAllData(context)"),
        )
    }

    // -----------------------------------------------------------------------
    // Nowhere else, and the detector is real
    // -----------------------------------------------------------------------

    /**
     * "Nowhere", not "here" (the [PrefsApplySourceGuardTest] lesson): a provider
     * handed straight to a constructor has no owner and therefore no scrub. Every
     * production Android construction must bind it to a `val`/`var` first.
     */
    @Test
    fun noProductionAndroidSourcePassesACryptoProviderInline() {
        val offenders = mutableListOf<String>()
        for (dir in SCANNED_DIRS) {
            val root = File(repoRoot(), dir)
            assertTrue("scanned source dir is missing: $dir", root.isDirectory)
            root.walkTopDown()
                .filter { it.isFile && it.extension == "kt" }
                .filterNot { f ->
                    f.relativeTo(root).invariantSeparatorsPath.substringBefore('/') in TEST_SOURCE_SETS
                }
                .forEach { f ->
                    if (INLINE_PROVIDER.containsMatchIn(normalize(stripComments(f.readText())))) {
                        offenders += f.relativeTo(repoRoot()).path
                    }
                }
        }
        assertTrue(
            "a CryptoProvider passed inline as a `crypto = CryptoProvider(...)` argument has " +
                "no named owner, so the unwrapped Tink keyset it caches can never be wiped " +
                "(VaultSelector.crypto is private). Bind it to a local and scrub it. " +
                "Offending file(s): $offenders",
            offenders.isEmpty(),
        )
    }

    /** A guard that cannot fire reads as coverage. Fabricated source, both directions. */
    @Test
    fun theDetectorsActuallyDetect() {
        // INLINE_PROVIDER
        for (src in listOf(
            "VaultSelector(store = s, crypto = CryptoProvider(this), vaultFactory = f)",
            "VaultSelector(\n    store = s,\n    crypto = CryptoProvider(context),\n)",
        )) {
            assertTrue("inline detector missed: $src", INLINE_PROVIDER.containsMatchIn(normalize(stripComments(src))))
        }
        for (src in listOf(
            "val crypto = CryptoProvider(context)",
            "var crypto = CryptoProvider(context)",
            "crypto = cryptoProvider,",
            "val orphanCrypto = CryptoProvider(this)",
            "// the provider used to be inline: crypto = CryptoProvider(this)",
        )) {
            assertTrue(
                "inline detector false-positived on: $src",
                !INLINE_PROVIDER.containsMatchIn(normalize(stripComments(src))),
            )
        }

        // FINALLY_SCRUB / FINALLY_SCRUB_LOCAL
        assertTrue(
            "finally detector missed the real shape",
            FINALLY_SCRUB.containsMatchIn(
                normalize("} finally { try { orphanCrypto.wipeKey() } catch (_: Exception) { } }"),
            ),
        )
        assertTrue(
            "finally detector must NOT accept a scrub that sits outside the finally body",
            !FINALLY_SCRUB.containsMatchIn(
                normalize("orphanCrypto.wipeKey() } finally { LogBuffer.append(\"D\", \"T\", \"x\") }"),
            ),
        )
        assertTrue(
            "local-provider finally detector missed the real shape",
            FINALLY_SCRUB_LOCAL.containsMatchIn(
                normalize("} finally { try { crypto.wipeKey() } catch (_: Exception) { } }"),
            ),
        )
    }

    // -----------------------------------------------------------------------

    private fun normalize(src: String): String = src.replace(WHITESPACE, " ")

    private fun String.occurrences(needle: String): Int {
        var n = 0
        var i = indexOf(needle)
        while (i >= 0) {
            n++
            i = indexOf(needle, i + needle.length)
        }
        return n
    }

    /**
     * The body of the function starting at [signature], up to the first line that
     * closes it at the same indentation. Fails loudly if the signature is gone, so
     * a rename can never turn these guards into vacuous passes.
     * (Same helper as [TorDataDirPreservationSourceTest].)
     */
    private fun String.functionBody(signature: String): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val indent = signature.takeWhile { it == ' ' }
        val closer = "\n$indent}"
        val end = indexOf(closer, start)
        assertTrue("precondition: `$signature` must be closed", end > start)
        return substring(start, end)
    }

    companion object {
        private const val MAIN_ACTIVITY = SourcePins.MAIN_ACTIVITY
        private const val INACTIVITY_WIPE = "androidApp/src/main/java/com/vg/run/InactivityWipe.kt"

        /** By DIRECTORY, so a flavor/build-type source set added later is covered
         *  without anyone remembering to extend a list (the WipeRoutine lesson). */
        private val SCANNED_DIRS = listOf("androidApp/src", "shared/src/androidMain")
        private val TEST_SOURCE_SETS = setOf("test", "androidTest")

        private val WHITESPACE = Regex("""\s+""")

        /**
         * `crypto = CryptoProvider(` as an ARGUMENT — i.e. not preceded by a
         * `val`/`var` binding. The lookbehind is what keeps the legitimate
         * `val crypto = CryptoProvider(context)` (InactivityWipe) out of it.
         */
        private val INLINE_PROVIDER = Regex("""(?<!\bval )(?<!\bvar )\bcrypto\s*=\s*CryptoProvider\(""")

        /**
         * A `finally` whose body scrubs. `[^}]` cannot cross a closing brace, so
         * the scrub must genuinely be inside the finally (a `try {` opening brace
         * on the way is fine — `{` is not excluded).
         */
        private val FINALLY_SCRUB = Regex("""\}\s*finally\s*\{[^}]{0,400}?orphanCrypto\.wipeKey\(\)""")
        private val FINALLY_SCRUB_LOCAL = Regex("""\}\s*finally\s*\{[^}]{0,400}?crypto\.wipeKey\(\)""")
    }
}
