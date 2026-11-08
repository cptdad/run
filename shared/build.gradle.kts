import java.io.File
import java.util.Properties
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFramework

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library)
}

// Emits the relay URL as a Kotlin constant compiled into commonMain, so both
// the Android APK and the iOS XCFramework pick up the same value. Source of
// truth (in precedence order):
//   1. environment variable RELAY_ONION_URL  ← never in git
//   2. a gitignored repo-root relay.properties (optional local-dev fallback)
//   3. empty string (no relay configured — valid)
// The .onion is intentionally NOT committed; set the env var (or a local
// relay.properties) at build time. See relay.properties.example.
//
// A SECOND, optional dev/test relay (RELAY_DEV_ONION_URL env var, or
// relayDevOnionUrl in relay.properties) is emitted as its own constant. It is
// consumed ONLY behind the compile-time debug gates in the RelayConfig actuals
// (BuildConfig.DEBUG / Platform.isDebugBinary), so a release build can never
// resolve to it — same pattern as the emulator/simulator
// loopback overrides. Belt-and-braces: this task FAILS the build if
// the dev URL ever equals the production URL, so the dev relay cannot be
// smuggled into the production slot either.
val relayUrlEnv = providers.environmentVariable("RELAY_ONION_URL")
val relayDevUrlEnv = providers.environmentVariable("RELAY_DEV_ONION_URL")
// SEVERAL ONION ADDRESSES FOR THE SAME RELAY (2026-10-23, comma lists since the
// same day — ONE way only). Both RELAY_ONION_URL /
// RELAY_DEV_ONION_URL and relayOnionUrl / relayDevOnionUrl accept a
// COMMA-SEPARATED list of addresses of the SAME relay backend: list order = slot
// order, whitespace trimmed, empty items ignored, at most 3. A single entry is
// exactly today's configuration. The HSDir set that serves a v3 descriptor is
// derived from the onion key (+ SRV / time period), so a second address lands on
// an INDEPENDENT HSDir set; the client races the descriptor fetch across all of
// them and uses the first that arrives (RelayAddressRace.kt). Every guard covers
// every entry: the dev==prod refusal fires if ANY dev entry equals ANY prod
// entry, and the release scrub empties the WHOLE dev list.
// RELEASE-ARTIFACT SCRUB: when this invocation is building release artifacts,
// emit the dev constant EMPTY so the dev relay address leaves no trace — not
// even as dead data — in anything shipped. Detected from (any of):
//   • a requested task name containing "release" (assembleRelease, bundleRelease,
//     linkReleaseFramework*, assembleSharedReleaseXCFramework, …)
//   • a requested BARE lifecycle-aggregate task name — "build" or "assemble" (at
//     any project path, e.g. ":androidApp:build") — because for every module in
//     this build, `build` depends on `assemble`, and `assemble` depends on
//     `assembleRelease` alongside `assembleDebug`: there is no way to run either
//     aggregate WITHOUT also compiling+assembling the release variant. This is
//     the specific gap (`./gradlew build`, documented in
//     the build docs as "compile + test + lint", silently produced a release APK
//     carrying the dev onion) — closed structurally, not by guessing.
//   • Xcode script phases (CONFIGURATION=Release) — reliable for iOS: Xcode sets
//     this env var for every invocation of embedAndSignAppleFrameworkForXcode,
//     Debug or Release, so this is not a heuristic on that platform.
//   • an explicit STRIP_DEV_RELAY=1 override
// Known limitation: Gradle camel-case
// abbreviations (`./gradlew aR` for assembleRelease, `bR` for bundleRelease, …)
// are expanded against the FULL task graph only, which this project cannot
// safely introspect here: closing it precisely needs either the task-execution
// GRAPH (gradle.taskGraph.whenReady) or per-Android-variant source generation
// (androidComponents.onVariants + Sources.addGeneratedSourceDirectory) — and
// this module runs with org.gradle.configuration-cache=true PLUS the documented
// "temporary" com.android.library + kotlin.multiplatform coexistence (see
// gradle.properties / this file's plugin block), so an unverified change to
// either mechanism risks silently breaking the build in a way only a real
// Gradle invocation would reveal, and Gradle must not be invoked to develop
// this fix. Belt-and-braces instead: scripts/verify-release-artifact.sh greps
// the ACTUAL BUILT ARTIFACT for the configured dev onion and fails the release
// gate regardless of how the artifact was produced — that check is invocation-
// shape-independent and closes this residual gap unconditionally.
val releaseArtifactIntent: Boolean =
    gradle.startParameter.taskNames.any { taskName ->
        taskName.contains("release", ignoreCase = true) ||
        taskName.substringAfterLast(":").equals("build", ignoreCase = true) ||
        taskName.substringAfterLast(":").equals("assemble", ignoreCase = true)
    } ||
    providers.environmentVariable("CONFIGURATION").orNull.equals("Release", ignoreCase = true) ||
    providers.environmentVariable("STRIP_DEV_RELAY").orNull == "1"
// FAIL-CLOSED (2026-09-15): a DEBUG artifact requested in the SAME invocation as
// anything that flips releaseArtifactIntent is compiled with the dev constant
// EMPTY, and RelayConfig then falls back to the production slot — so a debug
// APK/framework built that way silently talks to the PRODUCTION relay from a
// test phone. Seen live: `./gradlew :androidApp:assembleDebug
// :androidApp:compileReleaseKotlin` put three test Androids on prod for a whole
// gate run (their sends 404ed on dev, prod rejected their telemetry). Refuse
// the invocation instead of guessing which variant the caller wanted; run the
// debug artifact and the release compilation as two separate invocations.
val debugArtifactRequested: Boolean =
    gradle.startParameter.taskNames.any { taskName ->
        Regex("(assemble|install|package|bundle|copy|link)[A-Za-z]*Debug", RegexOption.IGNORE_CASE)
            .containsMatchIn(taskName.substringAfterLast(":"))
    }
val bareAggregateRequested: Boolean =
    gradle.startParameter.taskNames.any { taskName ->
        taskName.substringAfterLast(":").equals("build", ignoreCase = true) ||
        taskName.substringAfterLast(":").equals("assemble", ignoreCase = true)
    }
if (bareAggregateRequested) {
    throw GradleException(
        "Bare `build` / `assemble` builds BOTH variants in one invocation, so its " +
        "Debug APK would carry an EMPTY dev relay constant and fall back to the " +
        "PRODUCTION relay. Request the variants explicitly and separately: " +
        "`./gradlew test lint` then `./gradlew :androidApp:assembleRelease` and, in " +
        "its own invocation, `./gradlew :androidApp:assembleDebug`. Requested: " +
        gradle.startParameter.taskNames.joinToString(" ")
    )
}
if (releaseArtifactIntent && debugArtifactRequested) {
    throw GradleException(
        "A Debug artifact task and a release-intent task (a task name containing " +
        "\"release\", a bare build/assemble, CONFIGURATION=Release or STRIP_DEV_RELAY=1) " +
        "were requested in ONE Gradle invocation: the release scrub would empty the " +
        "dev relay constant and the Debug artifact would fall back to the PRODUCTION " +
        "relay. Run them separately, e.g. `./gradlew :androidApp:assembleDebug` and " +
        "then `./gradlew :androidApp:compileReleaseKotlin`. Requested: " +
        gradle.startParameter.taskNames.joinToString(" ")
    )
}
// Build-time-only test knob for the in-app store-review prompt
// (ReviewPromptPolicy.kt): REVIEW_PROMPT_TEST=1 compiles a binary whose
// thresholds are 2 unlocks / 0 contacts / 0 days instead of 5 / 1 / 3 days,
// so a RELEASE-configuration device build can prove the OS review sheet
// wiring in minutes (debug builds never prompt at all). Nothing sets this
// env var in any shipping path (Xcode Cloud, the pre-push .aab, fastlane).
// Refused for ANY release compilation this
// invocation resolves — reuses releaseArtifactIntent above (assembleRelease,
// bundleRelease, linkReleaseFramework*, a bare `build`/`assemble`, CONFIGURATION
// =Release, STRIP_DEV_RELAY=1) — not just `bundle*`, since the repo also ships
// assembleRelease .apk builds for direct distribution (.githooks/pre-push).
val reviewPromptTestThresholds: Boolean =
    providers.environmentVariable("REVIEW_PROMPT_TEST").orNull == "1"
if (reviewPromptTestThresholds) {
    if (releaseArtifactIntent) throw GradleException("REVIEW_PROMPT_TEST=1 is a device-test knob and must never reach a distributable (any release compilation: assembleRelease / bundleRelease / linkReleaseFramework* / a bare build|assemble / CONFIGURATION=Release / STRIP_DEV_RELAY=1)")
    logger.warn("*** REVIEW_PROMPT_TEST=1: review-prompt thresholds are TEST values (2 unlocks / 0 contacts / 0 days) — never ship this artifact ***")
}

val generateRelayUrl = tasks.register("generateRelayUrl") {
    val relayPropsPath = rootProject.file("relay.properties").absolutePath
    val reviewTest = reviewPromptTestThresholds
    inputs.property("reviewPromptTestThresholds", reviewTest)
    val outputDir = layout.buildDirectory.dir("generated/relay")
    val urlFromEnv = relayUrlEnv.orNull
    val devUrlFromEnv = relayDevUrlEnv.orNull
    // Local copy: doLast must not capture the top-level script val (config-cache
    // forbids serializing script object references).
    val releaseIntent = releaseArtifactIntent
    inputs.property("relayUrlEnv", relayUrlEnv.orElse(""))
    inputs.property("relayDevUrlEnv", relayDevUrlEnv.orElse(""))
    inputs.property("releaseArtifactIntent", releaseIntent)
    // Use inputs.files (plural) not inputs.file: the relay.properties dev
    // fallback is gitignored, so on a fresh clone (e.g. Xcode Cloud) it does
    // NOT exist. inputs.file().optional(true) still fails validation for a
    // set-but-missing path; inputs.files() simply skips absent entries while
    // still re-running the task when the file is present and changes.
    inputs.files(relayPropsPath).withPropertyName("relayProperties")
    outputs.dir(outputDir)
    doLast {
        val relayProps = File(relayPropsPath)
        val props = Properties().apply {
            if (relayProps.exists()) load(relayProps.inputStream())
        }
        // Each value is a COMMA-SEPARATED list (one entry = today's single
        // address): trimmed, empty items dropped, list order = slot order.
        fun splitList(raw: String?): List<String> =
            raw.orEmpty().split(',').map { it.trim() }.filter { it.isNotEmpty() }
        // Env var wins (when it holds at least one entry); otherwise the
        // gitignored local file. Per LIST — never mixed entry by entry.
        fun pick(env: String?, key: String): List<String> =
            splitList(env).ifEmpty { splitList(props.getProperty(key, "")) }
        // Values are never echoed into an exception message — a build log is not
        // a place for them.
        val v3OnionUrl = Regex("^(https?://)?[a-z2-7]{56}\\.onion(:[0-9]{1,5})?/?$", RegexOption.IGNORE_CASE)
        val maxAddresses = 3
        fun validatedList(entries: List<String>, label: String): List<String> {
            if (entries.size > maxAddresses) {
                throw GradleException(
                    "$label lists ${entries.size} relay addresses; at most $maxAddresses are supported " +
                    "(comma-separated, slot 1 first)."
                )
            }
            if (entries.size >= 2) {
                if (!v3OnionUrl.matches(entries[0])) {
                    throw GradleException(
                        "$label lists several relay addresses but entry 1 is not a v3 .onion URL. " +
                        "Several addresses only exist for an onion relay."
                    )
                }
                for ((i, entry) in entries.withIndex()) {
                    if (!v3OnionUrl.matches(entry)) {
                        throw GradleException("$label: entry ${i + 1} is not a v3 .onion URL.")
                    }
                }
            }
            // Duplicates collapse (an address listed twice races against itself).
            return entries.distinctBy { it.lowercase().trimEnd('/') }
        }
        val prodUrls = validatedList(pick(urlFromEnv, "relayOnionUrl"), "relayOnionUrl / RELAY_ONION_URL")
        val configuredDevUrls = validatedList(pick(devUrlFromEnv, "relayDevOnionUrl"), "relayDevOnionUrl / RELAY_DEV_ONION_URL")
        val url = prodUrls.firstOrNull() ?: ""
        // HARD GUARD: the dev/test relay must never occupy the production slot.
        // The RelayConfig actuals compile-gate the dev constant to debug binaries,
        // so the only way a dev relay could reach a production device is via the
        // production slot itself — refuse to build if the two values collide.
        // Checked against the CONFIGURED dev value, BEFORE the release scrub
        // empties it — release builds are where this check matters most.
        // Lists (2026-10-23): ANY dev entry equal to ANY prod entry (compared
        // case-insensitively, trailing slash ignored) is refused.
        fun norm(u: String) = u.trim().lowercase().trimEnd('/')
        val prodNorm = prodUrls.map(::norm).toSet()
        if (configuredDevUrls.any { norm(it) in prodNorm }) {
            throw GradleException(
                "relayDevOnionUrl / RELAY_DEV_ONION_URL equals the production " +
                "relayOnionUrl / RELAY_ONION_URL. The dev relay must NEVER be " +
                "the production relay — fix relay.properties or the environment. " +
                "(Checked for every entry of both comma-separated lists.)"
            )
        }
        // Release-artifact scrub (see releaseArtifactIntent above): ship no trace
        // of the dev relay address, not even as an unused constant — the WHOLE dev
        // list is emptied.
        val devUrls = if (releaseIntent) emptyList() else configuredDevUrls
        val devUrl = devUrls.firstOrNull() ?: ""
        // Escape the value for a Kotlin string literal so a malicious or malformed
        // relay.properties (or RELAY_URL env) cannot inject source into the
        // generated RelayUrl.kt — a string break, a $-template, or trailing
        // statements compiled straight into the APK + iOS framework. Control
        // chars are dropped.
        fun escapeForKotlinLiteral(raw: String) = buildString {
            for (c in raw) when (c) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '$' -> { append('\\'); append('$') }
                in '\u0000'..'\u001f', '\u007f', ' ' -> { /* drop ALL C0 controls + DEL + space — a relay .onion URL needs none; makes the "control chars dropped" guarantee actually true and removes a raw NUL byte from source */ }
                else -> append(c)
            }
        }
        val safeUrl = escapeForKotlinLiteral(url)
        val safeDevUrl = escapeForKotlinLiteral(devUrl)
        fun kotlinList(values: List<String>) =
            values.joinToString(", ", prefix = "listOf(", postfix = ")") { "\"${escapeForKotlinLiteral(it)}\"" }
        val safeUrls = kotlinList(prodUrls)
        val safeDevUrls = kotlinList(devUrls)
        // Identifier-free build-log line (counts and the source only): lets a CI or Xcode Cloud
        // build log answer "how many relay addresses did this artifact get, and from where" when
        // the configured value itself cannot be read back (Xcode Cloud hides secret environment
        // variables). Added 2026-11-08 after a stale single-address RELAY_ONION_URL in a shell
        // profile had shipped 1 of the 3 configured addresses in every Mac-built store artifact.
        logger.lifecycle(
            "generateRelayUrl: ${prodUrls.size} production relay address(es) from " +
                (if (urlFromEnv.isNullOrBlank()) "relay.properties" else "RELAY_ONION_URL") +
                ", ${devUrls.size} dev address(es) (" + (if (releaseIntent) "release scrub" else "debug") + ")"
        )
        val pkgDir = outputDir.get().asFile.resolve("com/vg/run")
        pkgDir.mkdirs()
        pkgDir.resolve("RelayUrl.kt").writeText(
            """
            package com.vg.run

            internal const val RELAY_URL_FROM_PROPERTIES: String = "$safeUrl"

            // Every configured address of the production relay, slot 1 first
            // (== RELAY_URL_FROM_PROPERTIES; empty when no relay is configured).
            internal val RELAY_URLS_FROM_PROPERTIES: List<String> = $safeUrls

            // Dev/test relay — referenced ONLY behind BuildConfig.DEBUG /
            // Platform.isDebugBinary gates in the RelayConfig actuals; release
            // builds are structurally pinned to RELAY_URLS_FROM_PROPERTIES.
            internal const val RELAY_DEV_URL_FROM_PROPERTIES: String = "$safeDevUrl"

            // Every configured address of the dev/test relay, slot 1 first. Same
            // gates; emptied by the release scrub.
            internal val RELAY_DEV_URLS_FROM_PROPERTIES: List<String> = $safeDevUrls

            // Review-prompt device-test knob (REVIEW_PROMPT_TEST=1 at build time
            // ONLY — see shared/build.gradle.kts). False in every shipping build.
            internal const val REVIEW_PROMPT_TEST_THRESHOLDS: Boolean = $reviewTest
            """.trimIndent() + "\n"
        )
    }
}

kotlin {
    androidTarget {
        // Align the Android Kotlin JVM target with compileOptions (11) — matches
        // androidApp. Required once buildConfig=true adds a Java compile task:
        // otherwise Kotlin (default 17) and Java (11) mismatch and the build fails.
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
        }
    }

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    val xcf = XCFramework("shared")
    listOf(iosArm64(), iosSimulatorArm64(), iosX64()).forEach { target ->
        target.binaries.framework {
            baseName = "shared"
            isStatic = true
            xcf.add(this)
        }
        target.compilations["main"].cinterops {
            val runcrypto by creating {
                defFile(file("src/iosMain/cinterop/runcrypto.def"))
            }
        }
    }

    sourceSets {
        commonMain {
            kotlin.srcDir(generateRelayUrl)
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
            }
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
        }

        androidMain.dependencies {
            // Tink (AEAD + the Android Keystore master key). PINNED EXACTLY and
            // COUPLED to the UnifiedPush connector pin in gradle/libs.versions.toml:
            // the connector's published runtime metadata requires the JVM artifact
            // `com.google.crypto.tink:tink` at the SAME version (connector 3.3.5 →
            // tink 1.23.0), which :androidApp excludes in favour of this one. See the
            // long COUPLING comment on the connector dependency in
            // androidApp/build.gradle.kts before moving either version.
            implementation("com.google.crypto.tink:tink-android:1.23.0")
            // Argon2id (vault KDF_VERSION_3). Low-level BC generator only —
            // R8 strips the unused remainder in release.
            implementation("org.bouncycastle:bcprov-jdk18on:1.86")
            // Vault engine. KEEP IN LOCKSTEP with iOS swift-sqlcipher (project.pbxproj
            // `exactVersion`): the wrapper versions differ but BOTH must wrap the same
            // SQLCipher CORE — 1.13.0 wraps core 4.19.0, which is what this pin is.
            // Stay on the 4.x line: SQLCipher 5.0 changes the defaults an existing file
            // is read with (AES-GCM, 512K KDF iterations, 8192-byte pages), so moving
            // there is a migration, not a bump (see scripts/security-deps-report.sh).
            implementation("net.zetetic:sqlcipher-android:4.19.0")
            implementation("androidx.sqlite:sqlite:2.7.1")
            // Android relay transport (PlatformHttpClient.android.kt) — OkHttp over
            // the embedded Tor's SOCKS port. 5.x is a Kotlin-Multiplatform module, so
            // this coordinate is a metadata redirect: Gradle resolves the Android
            // variant to `com.squareup.okhttp3:okhttp-android:5.5.0` (and the JVM one
            // to okhttp-jvm), which is why verification-metadata.xml now pins those
            // artifacts rather than a single okhttp-5.5.0.jar.
            //
            // REMOTE-DNS INVARIANT (re-verified against the 5.5.0 sources before this
            // bump): a `.onion` must never be resolved locally. OkHttp achieves this
            // structurally, not via a custom Dns — `RouteSelector.nextRoutes` still
            // short-circuits `Proxy.Type.SOCKS` to a single Route built from
            // `InetSocketAddress.createUnresolved(host, port)` and returns BEFORE the
            // `dnsLookup(...)` branch, so the hostname travels to the proxy as a SOCKS5
            // DOMAINNAME (ATYP 0x03) and Tor resolves it. 4.12.0 did exactly the same.
            // PlatformHttpClientSocksDnsTest proves it end-to-end against a loopback
            // SOCKS5 server; `onionTransportGuard` + scripts/check-network-api-usage.sh
            // are the other two layers.
            //
            // NEW TRANSITIVE (5.x only): okhttp-android pulls androidx.startup and
            // merges an `androidx.startup` InitializationProvider entry
            // (okhttp3.internal.platform.PlatformInitializer) into our manifest. Unlike
            // the androidx.work initializer removed on 2026-07-30 (see the
            // note in androidApp/build.gradle.kts) this one only stashes the
            // application Context in PlatformRegistry — it opens no database and
            // leaves no at-rest artifact, so it is accepted.
            implementation("com.squareup.okhttp3:okhttp:5.5.0")
            // Embedded Tor binary (libtor.so), Guardian Project. Replaces the
            // dead kmp-tor 1.x line (frozen at Tor 0.4.8.10). We only consume
            // the binary — TorManager runs it via ProcessBuilder — so no Tor
            // Kotlin/Java API or control lib (jtorctl) is needed. Tor 0.4.9.13,
            // matching the iOS side (tor.xcframework rebuilt to 0.4.9.13).
            implementation("info.guardianproject:tor-android:0.4.9.14")
        }
    }
}

// Native Argon2id (librunargon2.so, src/androidMain/cpp/ → the vendored iosApp/Argon2
// sources). The NDK is resolved OUTSIDE the Android SDK on purpose: the SDK here sits
// behind a path containing a SPACE, which CMake/ndk-build toolchains mishandle, so the
// default is the Homebrew NDK r30 (`brew install --cask android-ndk`). Override with the
// RUN_NDK_PATH env var or `run.ndkPath=` in the gitignored local.properties — keep it
// space-free. The version pin below must match that NDK's source.properties.
val runNdkVersion = "30.0.16248370"
val runNdkPath: String = providers.environmentVariable("RUN_NDK_PATH").orNull?.takeIf { it.isNotBlank() }
    ?: rootProject.file("local.properties").takeIf { it.isFile }?.let { f ->
        Properties().apply { f.inputStream().use { load(it) } }.getProperty("run.ndkPath")
    }?.takeIf { it.isNotBlank() }
    ?: "/opt/homebrew/share/android-ndk"
val runNdkPresent: Boolean = File(runNdkPath, "source.properties").isFile
// Fail the NATIVE tasks (only) with an actionable message when the NDK is absent —
// configuration stays NDK-free so the iOS framework build (Xcode Cloud has no NDK)
// is unaffected.
// Xcode Cloud 2026-10-07 (build of 1.6.37 FAILED): an unconditional `ndkVersion` made AGP
// try to auto-install NDK r30 into the SDK during the iOS "Build Kotlin Framework"
// phase. So the ENTIRE native wiring (ndkVersion, ndkPath, externalNativeBuild) is
// declared only when the NDK is present; without it the module configures exactly as
// before the native Argon2 existed — and the ANDROID variant tasks below fail closed,
// so no APK/.aab can ship without librunargon2.so while iOS builds stay NDK-free.
tasks.matching {
    it.name in setOf("preDebugBuild", "preReleaseBuild", "assembleDebug", "assembleRelease", "bundleDebugAar", "bundleReleaseAar")
}.configureEach {
    val present = runNdkPresent
    val path = runNdkPath
    val version = runNdkVersion
    doFirst {
        if (!present) throw GradleException(
            "Android NDK $version not found at '$path' (needed to build librunargon2.so, " +
            "the native vault Argon2id). Install it (`brew install --cask android-ndk`) or " +
            "point RUN_NDK_PATH / `run.ndkPath=` in local.properties at a space-free NDK $version."
        )
    }
}

android {
    namespace = "com.vg.run.shared"
    if (runNdkPresent) {
        ndkVersion = runNdkVersion
        ndkPath = runNdkPath
    }
    // 37.1 (minor release) required by tor-android 0.4.9.12+ (now 0.4.9.14) — keep in step with androidApp.
    compileSdk {
        version = release(37) { minorApiLevel = 1 }
    }

    defaultConfig {
        // Temporarily 29 for the closed-testing window (keep in sync with :androidApp).
        // API>29 calls are SDK_INT-guarded; Lever B is gated to API 30+ (see
        // AuthBoundKeyStore / BiometricGate / CryptoManager). Bump back to 33 when done.
        minSdk = 30
        if (runNdkPresent) externalNativeBuild {
            cmake {
                // Pure C (no STL). -O3 / visibility / link flags live in CMakeLists.txt.
                arguments += listOf("-DANDROID_STL=none")
                // The same four ABIs the shipped native deps carry (tor-android and
                // sqlcipher-android both ship arm64-v8a, armeabi-v7a, x86, x86_64): a
                // device whose ABI dir lacks librunargon2.so would silently take the
                // slow BouncyCastle fallback.
                abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
            }
        }
    }
    if (runNdkPresent) externalNativeBuild {
        cmake {
            path = file("src/androidMain/cpp/CMakeLists.txt")
            // Minimum, not exact ("+"): the Homebrew CMake here (cmake.dir in local.properties),
            // the Debian/Ubuntu CMake on CI and on F-Droid's build servers all qualify. The
            // generated flags come from the NDK's toolchain file, not from the CMake version, so
            // the .so stays byte-identical across them (checked by the reproducible-build job).
            version = "3.22.1+"
        }
    }
    buildTypes {
        debug {
            // Emit JaCoCo .exec for this module's JVM unit tests so :androidApp's
            // jacocoFullReport can fold shared/ unit coverage (MessageManager,
            // DoubleRatchet, …) in alongside the instrumented coverage.
            enableUnitTestCoverage = true
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    // Generate BuildConfig so RelayConfig.android can gate the
    // emulator cleartext-loopback override on BuildConfig.DEBUG — a release build
    // must never flip BASE_URL to http://10.0.2.2 just because an OEM device's
    // Build.* fields happen to match the emulator heuristic.
    buildFeatures {
        buildConfig = true
    }
}
