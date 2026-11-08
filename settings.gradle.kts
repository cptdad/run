pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
// No foojay toolchain resolver: JVM toolchain auto-download is disabled in
// gradle.properties, and no module configures a `jvmToolchain`/`toolchain {}`
// (builds use the JDK on JAVA_HOME), so the resolver was inert — removing it
// eliminates the un-checksummed auto-provision code path entirely. CI provisions
// its JDK via the SHA-256-pinned ci_post_clone.sh. (security audit 2026-06-11.)
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        // info.guardianproject:tor-android (the embedded Tor binary) is served by Maven
        // Central; gradle/verification-metadata.xml pins its checksums as computed from
        // repo1.maven.org. The Guardian Project raw-GitHub mirror (gpmaven) was removed
        // 2026-11-08: F-Droid's scanner only accepts known repositories.
        mavenCentral()
    }
}

rootProject.name = "Run"
include(":shared")
include(":androidApp")
include(":fuzz")
