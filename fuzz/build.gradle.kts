import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

// ---------------------------------------------------------------------------
// :fuzz — Jazzer fuzzing harnesses for Rún's UNTRUSTED-INPUT parsers.
//
// See fuzz/README.md for how to run these and how to add a harness.
//
// WHY A SEPARATE MODULE. A fuzz run is minutes of CPU per harness, so it must be
// opt-in; but the harnesses are also ordinary JUnit 5 tests replaying a seed +
// crash corpus, which CI should keep. Keeping them out of
// `shared/src/androidUnitTest` leaves `./gradlew test` (and the pre-push gate)
// exactly as fast as it was.
//
// WHY AN ANDROID LIBRARY AND NOT `kotlin("jvm")`. `:shared` is a Kotlin
// Multiplatform module whose only JVM-shaped target is `androidTarget()`. It
// publishes an AAR, which a `java-library`/`kotlin("jvm")` project cannot consume
// (no `java-api` / `java-runtime` variant). A `com.android.library` module
// resolves it natively and its unit tests run on the plain JVM — exactly where
// Jazzer needs to be.
// ---------------------------------------------------------------------------

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

// Opt-in gate: a bare `./gradlew test` at the root must NOT drag the fuzz module
// in. `:fuzz:test`, `:fuzz:fuzz` and `-Pfuzz=1` all do.
val fuzzModuleRequested: Boolean =
    gradle.startParameter.taskNames.any { it.contains("fuzz", ignoreCase = true) } ||
        providers.gradleProperty("fuzz").isPresent

android {
    namespace = "com.vg.run.fuzz"
    compileSdk = 37

    defaultConfig {
        minSdk = 30
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}

// The release variant would force a RELEASE compilation of :shared for no
// benefit (the harnesses are variant-agnostic) — and a release compilation in an
// invocation that also builds debug artifacts is exactly what
// shared/build.gradle.kts refuses. Debug only.
androidComponents {
    beforeVariants(selector().withBuildType("release")) { variant ->
        variant.enable = false
    }
}

dependencies {
    // The module under test. The friend-path wiring below is what unlocks its
    // `internal` API (which is most of the parser surface) for the harnesses.
    testImplementation(project(":shared"))

    testImplementation("com.code-intelligence:jazzer-junit:0.30.0")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.14.4")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.14.4")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.14.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.14.4")
}

// ---------------------------------------------------------------------------
// `internal` access to :shared via -Xfriend-paths.
//
// Nearly every parser worth fuzzing here is `internal` to :shared — DoubleRatchet,
// decodeRatchetWire, RatchetManager, parseTopLevelJson, jsonStringField,
// parseStringArrayField, GroupInviteStore.decode, MigJson — and `internal` is
// module-scoped, so from another Gradle module they do not merely fail a
// visibility check, they do not resolve at all ("Unresolved reference").
//
// `-Xfriend-paths` is the supported escape hatch: it is the same mechanism the
// Kotlin Gradle plugin uses to let a module's own test source set see the
// module's `internal` API. The catch is that the friend path must be the EXACT
// classpath entry the compiler reads those classes from. Deriving it from the
// KotlinCompile task's own `libraries` is the only reliable way:
//
//   * a raw directory dependency on shared/build/tmp/kotlin-classes/debug does
//     not work at all — a DIRECTORY file-dependency carries
//     `artifactType=directory`, which AGP never requests, so it is silently
//     dropped from the compile classpath and NOTHING from :shared resolves;
//   * an `artifactView` over debugUnitTestCompileClasspath fails variant
//     selection unless the artifactType attribute is replicated exactly.
//
// In practice the entry is
// shared/build/intermediates/compile_library_classes_jar/debug/bundleLibCompileToJarDebug/classes.jar,
// but filtering `libraries` by the :shared project directory keeps this correct
// if AGP relocates it.
// ---------------------------------------------------------------------------
val sharedProjectPathPrefix: String = File(rootDir, "shared").absolutePath + File.separator

tasks.withType<KotlinCompile>().configureEach {
    val libraryJars = libraries
    compilerOptions.freeCompilerArgs.addAll(
        provider {
            val friends = libraryJars.files.filter { it.absolutePath.startsWith(sharedProjectPathPrefix) }
            if (friends.isEmpty()) emptyList()
            else listOf("-Xfriend-paths=" + friends.joinToString(",") { it.absolutePath })
        },
    )
}

// Diagnostics: `./gradlew :fuzz:fuzzFriendPaths` prints what -Xfriend-paths will
// carry. NO output means `internal` access is not wired, and every `internal`
// symbol will fail to compile with a bare "Unresolved reference".
tasks.register("fuzzFriendPaths") {
    group = "help"
    description = "Print the -Xfriend-paths entries that unlock :shared's internal API."
    val libraryJars = tasks.named<KotlinCompile>("compileDebugUnitTestKotlin").map { it.libraries }
    val prefix = sharedProjectPathPrefix
    doLast {
        libraryJars.get().files
            .filter { it.absolutePath.startsWith(prefix) }
            .forEach { println("FRIEND_PATH " + it.absolutePath) }
    }
}

// ---------------------------------------------------------------------------
// Test tasks.
//
// `:fuzz:test`  — REGRESSION mode. Jazzer replays every file in each harness's
//                 seed/crash corpus as an ordinary JUnit test. Seconds, not
//                 minutes; this is what CI should run.
// `:fuzz:fuzz`  — FUZZING mode. An aggregate over one Test task per harness
//                 (see "ONE JVM PER HARNESS" below); libFuzzer drives each for
//                 its @FuzzTest(maxDuration=…) budget (default 60s, overridable
//                 with -PfuzzDuration=…), writing findings into the corpus.
// ---------------------------------------------------------------------------
// The whole unit-test variant is switched off unless the module was asked for,
// so a root `./gradlew test` neither compiles nor runs the harnesses. (AGP 9's
// VariantBuilder has no `enableUnitTest` any more, so this is done at the task
// level — `test`, `testDebugUnitTest` AND the two compile tasks behind them.)
if (!fuzzModuleRequested) {
    tasks.configureEach {
        if (name.contains("UnitTest", ignoreCase = true) || name == "test") enabled = false
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
    enabled = fuzzModuleRequested
    maxHeapSize = "2g"
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

val fuzzDuration: String = providers.gradleProperty("fuzzDuration").getOrElse("60s")

// ---------------------------------------------------------------------------
// ONE JVM PER HARNESS — this is not an optimisation, it is a correctness
// requirement.
//
// Jazzer fuzzes only the FIRST @FuzzTest a JVM encounters: libFuzzer's driver is
// initialised once per process, so every later @FuzzTest in the same JVM quietly
// degrades to REGRESSION mode (its corpus replays, the "Fuzzing..." phase is
// skipped) with no error and no warning. A single `Test` task over all the
// harnesses therefore looks like a clean 19-harness run while having fuzzed
// exactly one of them — observed here before this fan-out existed.
//
// So each harness METHOD gets its own Test task, hence its own forked JVM. The
// list is derived from the sources rather than hand-maintained, so a new
// @FuzzTest is picked up automatically.
// ---------------------------------------------------------------------------
val harnessSourceDir = layout.projectDirectory.dir("src/test/kotlin/com/vg/run/fuzz").asFile
val fuzzTestIds: List<Pair<String, String>> =
    (harnessSourceDir.listFiles() ?: emptyArray())
        .filter { it.isFile && it.name.endsWith("FuzzTest.kt") }
        .sortedBy { it.name }
        .flatMap { file ->
            val className = "com.vg.run.fuzz." + file.name.removeSuffix(".kt")
            Regex("""@FuzzTest[^\n]*\n\s*fun\s+(\w+)\s*\(""")
                .findAll(file.readText())
                .map { className to it.groupValues[1] }
                .toList()
        }

fun Test.configureAsFuzzRun() {
    val unitTest = tasks.named<Test>("testDebugUnitTest")
    dependsOn(unitTest.map { it.taskDependencies })
    testClassesDirs = files(unitTest.map { it.testClassesDirs })
    classpath = files(unitTest.map { it.classpath })
    useJUnitPlatform()
    enabled = true
    // Jazzer's JUnit integration switches on this environment variable: unset ⇒
    // replay the corpus only; set ⇒ actually fuzz.
    environment("JAZZER_FUZZ", "1")
    // Overrides every harness's @FuzzTest(maxDuration=…) in one place.
    systemProperty("jazzer.max_duration", fuzzDuration)
    maxHeapSize = "2g"
    // A finding is a FAILED test, not a broken build step — keep going so one
    // invocation reports every harness.
    ignoreFailures = true
    outputs.upToDateWhen { false }
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

val perHarnessFuzzTasks = fuzzTestIds.map { (className, method) ->
    tasks.register<Test>(method) {
        group = "verification"
        description = "Fuzz $className.$method for $fuzzDuration."
        configureAsFuzzRun()
        filter {
            isFailOnNoMatchingTests = true
            includeTestsMatching("$className.$method")
        }
    }
}

tasks.register("fuzz") {
    group = "verification"
    description =
        "Fuzz every harness, each in its OWN JVM (Jazzer fuzzes only the first " +
            "@FuzzTest per JVM). See fuzz/README.md."
    dependsOn(perHarnessFuzzTasks)
    // Locals, not the TaskProvider list: a doLast closure is serialized into the
    // configuration cache, and a captured TaskProvider is not serializable.
    val harnessCount = perHarnessFuzzTasks.size
    val duration = fuzzDuration
    doLast {
        logger.lifecycle("Fuzzed $harnessCount harnesses for $duration each.")
    }
}

// Ad-hoc single run with an arbitrary filter:
//   ./gradlew :fuzz:fuzzOne --tests 'com.vg.run.fuzz.RatchetWireFuzzTest.fuzzDecodeRatchetWire'
// Remember the one-fuzz-test-per-JVM rule: a filter that matches more than one
// @FuzzTest will only actually FUZZ the first of them.
tasks.register<Test>("fuzzOne") {
    group = "verification"
    description = "Fuzz a single harness selected with --tests (see fuzz/README.md)."
    configureAsFuzzRun()
}
