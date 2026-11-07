// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.compose) apply false
    // Classpath-only here (`apply false`) — actually applied unconditionally
    // in androidApp/build.gradle.kts, which also configures
    // missingGoogleServicesStrategy = IGNORE so the `foss` flavor (no
    // google-services.json, by design) doesn't fail the build.
    alias(libs.plugins.google.services) apply false
}
