import com.google.gms.googleservices.GoogleServicesPlugin.MissingGoogleServicesStrategy
import com.google.gms.googleservices.GoogleServicesTask
import java.io.File
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    // See the googleServices{} config below for how a missing (gitignored)
    // google-services.json is handled without failing debug builds.
    alias(libs.plugins.google.services)
    jacoco
}

jacoco {
    // Match AGP's default JaCoCo (already sha256-pinned in
    // gradle/verification-metadata.xml), so the coverage tooling adds no new
    // dependency-verification entries.
    toolVersion = "0.8.14"
}

// Load signing credentials from keystore.properties.
//
// Signing material lives OUTSIDE the repo tree: keeping the
// keystore and its password inside the working dir means any archive/backup of
// the repo captures both together. Resolution order:
//   1. $RUN_SIGNING_DIR/keystore.properties (explicit override)
//   2. ~/.run-signing/keystore.properties   (default out-of-tree location)
//   3. <repo root>/keystore.properties      (legacy in-tree fallback)
// `storeFile` is resolved relative to whichever keystore.properties is found
// (or used as-is if absolute), so the .jks lives next to its properties file.
// On machines without any keystore (e.g. a Mac building only the iOS
// framework) the release build falls back to unsigned.
val signingDir: File =
    System.getenv("RUN_SIGNING_DIR")?.takeIf { it.isNotBlank() }?.let { File(it) }
        ?: File(System.getProperty("user.home"), ".run-signing")
val keystorePropsFile: File =
    signingDir.resolve("keystore.properties").takeIf { it.exists() }
        ?: rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropsFile.exists()) load(keystorePropsFile.inputStream())
}
val resolvedStoreFile: File? =
    keystoreProperties.getProperty("storeFile", "").takeIf { it.isNotEmpty() }?.let { sf ->
        val f = File(sf)
        if (f.isAbsolute) f else keystorePropsFile.parentFile.resolve(sf)
    }
val hasSigningConfig = resolvedStoreFile?.exists() == true

// Unified app version — single source of truth shared with iOS, in the
// repo-root version.properties. The patch + build number auto-increment on
// every git push (.githooks/pre-push); major/minor are edited there by hand.
val versionProperties = Properties().apply {
    rootProject.file("version.properties").inputStream().use { load(it) }
}
val runVersionName: String = versionProperties.getProperty("versionName")
val runVersionCode: Int = versionProperties.getProperty("versionCode").trim().toInt()

android {
    namespace = "com.vg.run"
    compileSdk {
        // 37.1 (minor release) required by info.guardianproject:tor-android 0.4.9.12+
        // (the Tor binary); 37.0 was required by 0.4.9.11.
        version = release(37) { minorApiLevel = 1 }
    }

    defaultConfig {
        applicationId = "com.vg.run"
        // minSdk 30: Lever B (hardware auth-bound key) needs API-30 BiometricPrompt, so it
        // is available on every supported device. API-30..32 call sites stay SDK_INT-guarded
        // (AuthBoundKeyStore / BiometricGate / CryptoManager); StrongBox is API 31+.
        minSdk = 30
        targetSdk = 36
        versionCode = runVersionCode
        versionName = runVersionName

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Two distribution flavours (reintroduced 2026-11-08 for F-Droid; supersedes the
    // 2026-08-04 collapse to one universal build):
    //  - google: the store build. Both notification transports ship in it — FCM when Play
    //    Services is present, UnifiedPush otherwise, selected at runtime via
    //    VendorPush.isAvailable() — plus Play Billing (tip jar) and Play In-App Review.
    //  - foss:   zero Google code (F-Droid). UnifiedPush only; the "Support Rún" modal shows
    //    the crypto address only; no store review sheet.
    // F-Droid's scanner reads this file: every Google artefact in dependencies{} is
    // `googleImplementation`-scoped, which the scanner skips when it builds `foss`. The seams
    // (VendorPush, VendorBilling, VendorReview, TipJarBody, RunFcmService + its manifest
    // entries) live in src/google and src/foss; main code reads them flavour-blind.
    flavorDimensions += "distribution"
    productFlavors {
        create("foss") { dimension = "distribution" }
        create("google") {
            dimension = "distribution"
            isDefault = true
        }
    }

    if (hasSigningConfig) {
        signingConfigs {
            create("release") {
                storeFile = resolvedStoreFile
                storePassword = keystoreProperties.getProperty("storePassword", "")
                keyAlias = keystoreProperties.getProperty("keyAlias", "")
                keyPassword = keystoreProperties.getProperty("keyPassword", "")
            }
        }
    }

    buildTypes {
        debug {
            // Coverage instrumentation for BOTH local JVM unit tests and on-device
            // instrumented tests. The merged jacocoFullReport task below folds the
            // instrumented .ec (which Kover cannot collect) together with the unit
            // .exec so the vault code — exercised almost entirely by instrumented
            // tests (VaultSelectorTest, PinAttemptsStoreSplitTest) — shows its real
            // coverage rather than the ~0-15% a unit-only report would report.
            enableUnitTestCoverage = true
            enableAndroidTestCoverage = true
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (hasSigningConfig) {
                signingConfig = signingConfigs.getByName("release")
            }
            // No META-INF/version-control-info.textproto: the public repo is a one-commit
            // snapshot, so the private commit SHA AGP embeds by default would match nothing
            // public and would leak where the private history stands.
            vcsInfo { include = false }
            ndk {
                // Kept NONE deliberately. The native .so we ship (SQLCipher, Tor) are
                // prebuilt + stripped, so there are NO symbols to extract — FULL + a
                // clean bundleRelease produced 0 symbol entries (verified 2026-06-19).
                // Play's "missing native debug symbols" notice is therefore expected
                // and harmless: our own Kotlin/Java frames still symbolicate via the
                // bundled proguard.map; only stripped third-party native frames don't.
                debugSymbolLevel = "NONE"
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    // l10n (scripts/l10n/gen-l10n.mjs is the generator; androidApp/src/main/res/xml/
    // locales_config.xml + the manifest's android:localeConfig carry the same list by
    // hand — AGP does not read localeFilters back into the manifest merger). Confirmed
    // present in the AGP DSL (com.android.build.api.dsl.ApplicationAndroidResources,
    // @Incubating but shipped) via `javap` on gradle-api-9.3.1.jar — no fallback needed.
    androidResources {
        localeFilters += listOf("en", "sv", "de", "fr", "es", "nb", "da", "fi", "ar", "fa", "so", "ru", "mk")
    }
}

dependencies {
    implementation(project(":shared"))

    // Android / Compose UI
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation("androidx.navigation:navigation-compose:2.10.1")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0")
    // Otherwise arrives only transitively via activity-compose (pinned at 2.9.4), skewing
    // behind the other lifecycle artifacts above; LocalLifecycleOwner lives here.
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")

    // The Tier-1 WorkManager background poll (a periodic worker that peeked
    // every inbox on a timer) was REMOVED — notifications are FCM-only now,
    // matching iOS. The androidx.work dependencies went with it;
    // do NOT re-add them without reading the next paragraph.
    //
    // They were previously kept on the grounds that no source file referenced
    // them, which is true and is NOT sufficient: work-runtime ships an
    // androidx.startup InitializationProvider + WorkManagerInitializer in its
    // OWN manifest, which merges into ours (verified in the merged release
    // manifest) and runs at process start regardless of app code. That
    // initialization opens the Room database androidx.work.workdb in
    // databases/ on every launch — an at-rest artifact of a feature that no
    // longer exists, in an app whose wipe is meant to leave nothing behind.
    // See WipeRoutine's databaseList() sweep, which cleans it up for installs
    // that already have the file.

    // ---- `google` flavour only (googleImplementation, NEVER plain implementation: the
    // `foss` flavour must link no Google class, and F-Droid's scanner checks exactly this).
    // Google Play Billing — the "Support Rún" tip jar (consumable one-time tips).
    // On devices without Play Services the tip tab degrades at runtime
    // (VendorBilling/TipJar); DonateModal keeps the crypto tab either way.
    "googleImplementation"(libs.billing.ktx)

    // Play In-App Review — the privacy-respecting store-review nudge
    // (ReviewPromptPolicy.kt in commonMain gates WHEN; VendorReview in
    // src/google calls ReviewManagerFactory). Same graceful-degrade posture as
    // Billing above: no Play Services / not a Play install ⇒ the returned
    // Task fails and the caller silently no-ops, no custom dialog fallback.
    "googleImplementation"(libs.play.review.ktx)

    // Vendor push (FCM) — the Vendor-push NotificationLevel tier
    // (notification-levels-plan.md §2b). VendorPush.kt/RunFcmService.kt (src/google) are
    // the only callers; on devices without Play Services the runtime gate
    // (VendorPush.isAvailable) routes to UnifiedPush instead.
    "googleImplementation"(platform("com.google.firebase:firebase-bom:34.19.0"))
    "googleImplementation"("com.google.firebase:firebase-messaging")  // -ktx artifacts left the BoM in 34.0.0; the main module carries the same API
    "googleImplementation"("com.google.android.gms:play-services-base")
    // ---- end of the `google`-only block

    // UnifiedPush connector — the Google-free wake transport (a distributor app
    // such as ntfy holds one socket and delivers contentless wakes to
    // RunPushService). Pure Apache-2.0 with zero Google/Firebase transitives;
    // it is the transport for devices WITHOUT Play Services (no Play Services
    // ⇒ no FCM) — VendorPush.isAvailable is the first branch everywhere
    // (the connector's own Play-Services probe is a
    // PackageManager.getPackageInfo("com.google.android.gms") STRING lookup,
    // not a linked class — verified by disassembling connector-3.3.5.aar).
    //
    // The `tink` exclusion is load-bearing, not hygiene. The connector's
    // published runtime metadata requires `com.google.crypto.tink:tink` (the
    // JVM artifact) for the RFC 8291 WebPush decryption its bundled
    // `com.google.crypto.tink.apps.fixed_webpush.*` classes perform. `:shared`
    // ALREADY ships `com.google.crypto.tink:tink-android`, so the two are pinned
    // to the SAME version and the JVM one is excluded.
    //
    // RE-VERIFIED for the 3.3.3 → 3.3.5 / Tink 1.21.0 → 1.23.0 pair (2026-09-16),
    // because the coupling is the reason Tink carries an exact pin at all:
    //  - connector 3.3.5's POM requires `com.google.crypto.tink:tink:1.23.0`
    //    exactly, so 1.23.0 is the version the connector needs — the coupling
    //    permits this bump, it does not forbid it.
    //  - at the identical 1.23.0 the two artifacts overlap on 1312 of `tink`'s
    //    1321 classes (tink-android ships 1878). The 9 that differ are six JWT
    //    proto inner classes plus `util.KeysDownloader` — none of them on the
    //    WebPush path.
    //  - disassembling connector-3.3.5.aar's classes.jar shows it references
    //    exactly five Tink classes — subtle.Bytes / EllipticCurves (+ its
    //    CurveType, PointFormatType) / EngineFactory / Hkdf / Random — and all
    //    five are present in tink-android 1.23.0. (The
    //    `apps.fixed_webpush.WebPush*` classes are bundled INSIDE the connector
    //    AAR itself, not pulled from either Tink artifact.)
    // Keeping both would duplicate the whole of Tink in the dex and additionally
    // drag protobuf-java 4.33.6 (~2 MB) behind it — tink-android needs none of it.
    // So: exclude the JVM artifact and let tink-android satisfy it.
    //
    // COUPLING — do NOT drop `tink-android` from shared/build.gradle.kts
    // without re-adding `tink` here. The connector would then call classes no
    // artifact provides and every incoming push would fail to decrypt,
    // surfacing as `PushMessage.decrypted == false` — which RunPushService
    // drops by design, i.e. a SILENT loss of notifications, not a crash.
    // UnifiedPushSupport.isWebPushCryptoLinked + UnifiedPushTinkRuntimeTest
    // exist to make that failure loud instead. The other direction of the same
    // coupling: move this connector pin and the `tink-android` pin in
    // shared/build.gradle.kts TOGETHER, to the version the connector's POM asks
    // for — never one without re-checking the other.
    implementation(libs.unifiedpush.connector) {
        exclude(group = "com.google.crypto.tink", module = "tink")
    }

    // QR code scanning
    implementation("com.google.zxing:core:3.5.4")
    // CameraX: native libimage_processing_util_jni.so must be 16 KB-page aligned (>=1.4 is the floor)
    // 1.3.x shipped a 4 KB-aligned .so that fails the Android 15+ 16 KB check.
    implementation("androidx.camera:camera-camera2:1.6.2")
    implementation("androidx.camera:camera-lifecycle:1.6.2")
    implementation("androidx.camera:camera-view:1.6.2")

    // CameraX transitively drags in older androidx.appcompat/fragment; fragment 1.1.0 was
    // flagged as an unsafe version. Pin both transitives up to current, mutually-compatible
    // releases without coupling them to the CameraX (QR-scanner) version.
    constraints {
        implementation("androidx.fragment:fragment:1.9.0") {
            because("camera-view pulls an older fragment; 1.1.0 was flagged as unsafe")
        }
        implementation("androidx.appcompat:appcompat:1.8.0") {
            because("camera-view pulls an older appcompat; align with the pinned fragment 1.8.x")
        }
    }

    // Testing
    androidTestImplementation("com.squareup.okhttp3:mockwebserver:5.5.0")
    // compileOnly: VaultSchemaParityTest opens the vault DB files
    // raw to compare sqlite_master. The class is provided at runtime by the app
    // process (:shared bundles it), so it must NOT be packaged into the test APK
    // (that would duplicate net.zetetic classes → checkDuplicateClasses failure).
    androidTestCompileOnly("net.zetetic:sqlcipher-android:4.19.0") // keep == the :shared pin
    androidTestCompileOnly("androidx.sqlite:sqlite:2.7.1") // SupportSQLiteDatabase supertype, runtime-provided by the app
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}

// ---------------------------------------------------------------------------
// Unified coverage report: JVM unit tests + Android instrumented tests, across
// :androidApp AND :shared (the vault/protocol code lives in :shared but is
// compiled into this app's APK, so the on-device instrumented .ec carries its
// coverage). Kover cannot ingest instrumented coverage, so this is a plain
// JaCoCo report that merges both execution-data formats.
//
//   ./gradlew :androidApp:testGoogleDebugUnitTest \
//             :androidApp:connectedGoogleDebugAndroidTest jacocoFullReport
//
// connectedGoogleDebugAndroidTest needs a device/emulator; if you skip it the report
// still builds from whatever .exec/.ec are present (unit-only in that case).
// ---------------------------------------------------------------------------
tasks.register<JacocoReport>("jacocoFullReport") {
    group = "verification"
    description = "Merged JVM-unit + instrumented coverage for :androidApp and :shared."
    // A "full" report folds in instrumented coverage, which only
    // connectedDebugAndroidTest can produce — so depend on it explicitly (also
    // satisfies Gradle's output-overlap validation, since this task reads that
    // task's coverage dir). This therefore REQUIRES a connected device/emulator.
    // For a unit-only report, run the two unit-test tasks + this without the
    // device — but the instrumented columns will then be empty.
    // The `google` flavour carries the full code (both push transports, Billing, Review).
    dependsOn("testGoogleDebugUnitTest", ":shared:testDebugUnitTest", "connectedGoogleDebugAndroidTest")

    val coverageExcludes = listOf(
        "**/R.class", "**/R\$*.class", "**/BuildConfig.*", "**/Manifest*.*",
        "**/*_Factory*.*", "**/*_Impl*.*", "**/Dagger*.*", "**/Hilt_*.*",
        "**/ComposableSingletons*", "**/*\$\$serializer.*",
        "**/databinding/**", "**/generated/**", "**/*ComposableKt*.*",
    )
    val shared = project(":shared")

    // Compiled Kotlin bytecode for the debug variant of each module.
    classDirectories.setFrom(
        fileTree(layout.buildDirectory.dir("tmp/kotlin-classes/googleDebug")) { setExcludes(coverageExcludes) },
        fileTree(shared.layout.buildDirectory.dir("tmp/kotlin-classes/debug")) { setExcludes(coverageExcludes) },
    )
    sourceDirectories.setFrom(
        files("src/main/java", "src/main/kotlin", "src/google/kotlin"),
        shared.files("src/commonMain/kotlin", "src/androidMain/kotlin"),
    )
    // Execution data: unit tests (.exec) + instrumented tests (.ec), both modules.
    // Rooted at specific output dirs (not the whole build dir) to keep the input
    // footprint tight and avoid spurious overlap with other tasks' outputs.
    executionData.setFrom(
        fileTree(layout.buildDirectory.dir("outputs/unit_test_code_coverage/googleDebugUnitTest")) { include("*.exec") },
        fileTree(layout.buildDirectory.dir("outputs/code_coverage/googleDebugAndroidTest/connected")) { include("**/*.ec") },
        fileTree(shared.layout.buildDirectory.dir("outputs/unit_test_code_coverage/debugUnitTest")) { include("*.exec") },
    )
    reports {
        html.required.set(true)
        xml.required.set(true)
    }
}

// ---------------------------------------------------------------------------
// Single-source runestone assets. The canonical PNGs live once under
// assets/runestone/; this task fans them out to res/drawable (and the iOS
// imagesets) so the two platforms' copies can never drift. Idempotent — a no-op
// when already in sync. Runs before every Android build; the pre-push hook runs
// it too (for the iOS build), and you can run it by hand for local Xcode:
//     ./scripts/sync-runestone-assets.sh
// ---------------------------------------------------------------------------
val syncRunestoneAssets by tasks.registering(Exec::class) {
    workingDir = rootDir
    commandLine("sh", "scripts/sync-runestone-assets.sh")
}
tasks.named("preBuild") { dependsOn(syncRunestoneAssets) }

// ---------------------------------------------------------------------------
// google-services.json is GITIGNORED and lives under the `google` FLAVOUR's source
// set (androidApp/src/google/debug/ = the dev Firebase project,
// androidApp/src/google/release/ = prod), so it is legitimately absent on a fresh
// clone or CI runner. IGNORE keeps such machines building (the plugin's
// process<Variant>GoogleServices task quietly no-ops instead of failing); the
// per-variant guard below decides where that absence is acceptable. The `foss`
// variants never find a json (the plugin searches src/<flavour>/<buildType>,
// src/<buildType>/<flavour>, src/<flavour>, src/<buildType> — none of which carry one
// for `foss`), so no google_app_id or other Firebase resource is ever generated
// into the F-Droid build; scripts/verify-release-artifact.sh asserts that.
// ---------------------------------------------------------------------------
googleServices {
    missingGoogleServicesStrategy = MissingGoogleServicesStrategy.IGNORE
}

// ---------------------------------------------------------------------------
// Per-variant fail-closed guard on top of the IGNORE above. Without it,
// `bundleGoogleRelease` on a json-less machine would succeed and quietly ship an
// artifact with no Firebase config at all — FCM push silently dead in
// production, with no build failure to flag it. Policy (`google` flavour only;
// `foss` has no Firebase and is skipped):
//   - release variants: missing/invalid json FAILS the build (fail closed —
//     never ship an FCM-dead artifact).
//   - debug variants: WARN only, so a fresh clone / CI runner without the
//     gitignored json still compiles and runs unit suites. A debug APK built
//     that way has FCM unconfigured (falls back like a no-Play-Services
//     device); dev machines doing push work carry the json anyway.
//
// Hooked onto each variant's OWN process<Variant>GoogleServices task — found
// via the task TYPE (GoogleServicesTask), not a hand-rolled name string —
// and verified AFTER it runs, so it never fails at CONFIGURATION time and
// checks the task's OWN generated output resource, not just the input json:
// a present-but-malformed/placeholder json (parses, but doesn't yield a real
// google_app_id) is caught too, not only an outright-missing file.
// `tasks.withType<GoogleServicesTask>().matching { ... }.configureEach { }`
// is lazy and order-independent — unlike `tasks.named(name)`, it doesn't
// require the google-services plugin to have already registered the task by
// the time this onVariants callback runs.
androidComponents.onVariants { variant ->
    if (variant.flavorName != "google") return@onVariants
    val variantName = variant.name
    val failClosed = variant.buildType == "release"
    val processTaskName = variant.computeTaskName("process", "GoogleServices")
    val searchedPaths = listOf(
        "androidApp/src/google/${variant.buildType}/google-services.json",
        "androidApp/src/${variant.buildType}/google/google-services.json",
        "androidApp/src/google/google-services.json",
        "androidApp/src/${variant.buildType}/google-services.json",
        "androidApp/google-services.json",
    )
    tasks.withType<GoogleServicesTask>().matching { it.name == processTaskName }.configureEach {
        val outputDirProvider = outputDirectory
        // Under MissingGoogleServicesStrategy.IGNORE the plugin's own action()
        // silently returns without writing (or clearing) its output when the
        // json is absent — Gradle does NOT auto-delete that declared
        // @OutputDirectory's stale contents in this case (verified: a
        // values.xml from an earlier successful run survives untouched
        // across a later run where the json was removed). Without this
        // doFirst cleanup, the doLast check below could pass on a LEFTOVER
        // file from a previous build instead of this execution's real
        // result — clear the directory first so "the file exists and has
        // google_app_id afterward" can only mean THIS run's action() wrote
        // it fresh.
        doFirst {
            outputDirProvider.get().asFile.deleteRecursively()
        }
        doLast {
            val valuesFile = outputDirProvider.get().asFile.resolve("values/values.xml")
            val hasRealFirebaseConfig = valuesFile.exists() && valuesFile.readText().contains("google_app_id")
            if (!hasRealFirebaseConfig) {
                val message =
                    "google-services.json is missing or invalid for variant " +
                    "`$variantName`. FCM vendor-push needs it.\n" +
                    "Searched:\n" +
                    searchedPaths.joinToString("\n") { "  - $it" }
                if (failClosed) {
                    throw GradleException(
                        message + "\nRelease builds fail closed rather than " +
                        "silently ship without Firebase config."
                    )
                } else {
                    logger.warn(
                        "WARNING: $message\nDebug build continues; FCM will be " +
                        "unconfigured in this APK (UnifiedPush is unaffected)."
                    )
                }
            }
        }
    }
}

// Kotlin JVM target for the app module — mirrors compileOptions (11) above. The
// `kotlinOptions {}` DSL this replaced was removed in Kotlin 2.4 (KT-85509).
kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}
