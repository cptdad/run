# Rún — ProGuard rules for release builds

# Keep stack traces readable for crash reports
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Keep annotation metadata (used by Tink, Kotlin serialization, etc.)
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod

# -------------------------------------------------------------------------
# SQLCipher — JNI callbacks require keeping native method declarations
# and the SQLiteDatabase/SQLiteOpenHelper public API.
# -------------------------------------------------------------------------
-keep class net.zetetic.database.sqlcipher.SQLiteDatabase { public *; }
-keep class net.zetetic.database.sqlcipher.SQLiteOpenHelper { public protected *; }
-keep class net.zetetic.database.sqlcipher.SQLiteConnection { *; }
-keep class net.zetetic.database.sqlcipher.SQLiteStatement { *; }
-keepclassmembers class net.zetetic.database.** { native <methods>; }

# -------------------------------------------------------------------------
# Native Argon2id (librunargon2.so, :shared src/androidMain/cpp/argon2_jni.c).
# The JNI symbol Java_com_vg_run_NativeArgon2_argon2idRaw is resolved BY NAME:
# renaming the class or the method makes the call throw UnsatisfiedLinkError and
# silently drops every unlock onto the slow BouncyCastle fallback (3.79 s on an A13).
# -------------------------------------------------------------------------
-keep class com.vg.run.NativeArgon2 {
    public static native byte[] argon2idRaw(byte[], byte[], int, int, int, int);
}

# -------------------------------------------------------------------------
# Google Tink — only keep public API used by CryptoManager.
# Internal implementation classes are obfuscated.
# -------------------------------------------------------------------------
-keep class com.google.crypto.tink.Aead { *; }
-keep class com.google.crypto.tink.KeyTemplates { *; }
-keep class com.google.crypto.tink.aead.AeadConfig { *; }
-keep class com.google.crypto.tink.integration.android.AndroidKeysetManager { *; }
-keep class com.google.crypto.tink.integration.android.AndroidKeysetManager$Builder { *; }
# Tink uses reflection to register key types
-keep class com.google.crypto.tink.aead.** { *; }
-keep class com.google.crypto.tink.proto.** { *; }
-keep class com.google.crypto.tink.shaded.protobuf.** { *; }
-keepclassmembers class com.google.crypto.tink.** {
    static void register();
    static *** get*();
}
-dontwarn com.google.crypto.tink.**

# Tink uses protobuf-lite internally
-keep class com.google.protobuf.** { *; }
-dontwarn com.google.protobuf.**

# -------------------------------------------------------------------------
# OkHttp / Okio — keep public API, obfuscate internals
# -------------------------------------------------------------------------
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.OkHttpClient { *; }
-keep class okhttp3.OkHttpClient$Builder { *; }
-keep class okhttp3.Request { *; }
-keep class okhttp3.Request$Builder { *; }
-keep class okhttp3.Response { *; }
-keep class okhttp3.RequestBody { *; }
-keep class okhttp3.MediaType { *; }
-keep class okhttp3.MediaType$Companion { *; }
-keep class okhttp3.RequestBody$Companion { *; }
# OkHttp uses reflection for platform detection
-keepnames class okhttp3.internal.platform.** { *; }
-keep class okio.ByteString { *; }
-keep class okio.Buffer { *; }

# OkHttp platform-specific classes
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**

# -------------------------------------------------------------------------
# ZXing — QR code processing.
#
# B6: narrowed from the whole library to the QR decode/encode path this app
# actually uses. The reflective part is the format-specific reader/writer lookup
# driven by BarcodeFormat, so the qrcode packages plus the shared core entry
# points stay; every other symbology (Aztec, PDF417, OneD, …) is now shrinkable.
# -------------------------------------------------------------------------
-keep class com.google.zxing.BarcodeFormat { *; }
-keep class com.google.zxing.MultiFormatReader { *; }
-keep class com.google.zxing.MultiFormatWriter { *; }
-keep class com.google.zxing.qrcode.** { *; }
-keep class com.google.zxing.common.** { *; }

# -------------------------------------------------------------------------
# Kotlin / Kotlinx Coroutines
# -------------------------------------------------------------------------
-dontwarn kotlinx.coroutines.**

# ServiceLoader pattern used by coroutines on Android
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}

# -------------------------------------------------------------------------
# Kotlin Metadata (needed at runtime for sealed classes, data classes)
# -------------------------------------------------------------------------
-dontwarn kotlin.reflect.jvm.internal.**
-keep class kotlin.Metadata { *; }


# -------------------------------------------------------------------------
# AndroidX CameraX — used only by the QR scanner.
#
# B6: narrowed from four blanket `**` keeps to the ONE genuinely reflective
# surface. CameraX resolves its config provider by name at init
# (CameraXConfig.Provider, and the camera2 implementation it names); everything
# else is called directly from our code and is safe to shrink/obfuscate. CameraX
# also ships consumer rules for its own internals.
# -------------------------------------------------------------------------
-keep class * implements androidx.camera.core.CameraXConfig$Provider { *; }
-keep class androidx.camera.camera2.Camera2Config { *; }
-dontwarn androidx.camera.**

# -------------------------------------------------------------------------
# Jetpack Compose
#
# the blanket `-keep class androidx.compose.runtime.**`
# is GONE. Compose ships its own consumer ProGuard rules in the AAR, which keep
# exactly what its runtime needs; a blanket keep on top of that only defeats
# shrinking. Same reasoning for Navigation below — routes here are plain strings
# (see MainActivity's NavHost), not reflectively resolved types.
# -------------------------------------------------------------------------
-dontwarn androidx.compose.**

# -------------------------------------------------------------------------
# App classes — keep public API used across module boundaries.
# Internal methods are obfuscated.
# -------------------------------------------------------------------------

# Data classes passed between modules
-keep class com.vg.run.ContactRecord { *; }
-keep class com.vg.run.InboxIdRecord { *; }
-keep class com.vg.run.MessageRecord { *; }
-keep class com.vg.run.HttpResult { *; }
-keep class com.vg.run.ReceivedMessage { *; }

# In-app log buffer — must survive R8 for the log viewer to work
-keep class com.vg.run.LogBuffer { *; }
-keep class com.vg.run.LogEntry { *; }

# Shared module public API
-keep class com.vg.run.CryptoManager { public *; }
-keep class com.vg.run.DatabaseManager { public protected *; }
-keep class com.vg.run.TorManager { public *; }
-keep class com.vg.run.TorManager$ConnectionState { *; }
-keep class com.vg.run.TorManager$ConnectionState$* { *; }
-keep class com.vg.run.PlatformHttpClient { public *; }
-keep class com.vg.run.PlatformHttpClient$Companion { public *; }
-keep class com.vg.run.KeyValueStore { public *; }
-keep class com.vg.run.VaultFactory { *; }
-keep class com.vg.run.VaultSelector { public *; }
-keep class com.vg.run.VaultSelector$UnlockResult { *; }
-keep class com.vg.run.VaultSelector$UnlockResult$* { *; }
-keep class com.vg.run.VaultDatabase { public *; }
-keep class com.vg.run.MessageManager { public *; }
-keep class com.vg.run.RelayConfig { *; }

# Android components referenced by manifest
-keep class com.vg.run.RunApplication { *; }

# -------------------------------------------------------------------------
# UnifiedPush connector — the wipe path closes the connector's cached
# SQLiteOpenHelper singleton VIA REFLECTION before unlinking its database
# (UnifiedPushSupport.closeConnectorDbHandle): without the close, the unlink
# pins the cached handle in SQLITE_READONLY_DBMOVED and the fall-through wipe
# paths (which re-onboard in the same process) can never enable UnifiedPush
# again. The class and field are resolved BY NAME at runtime, so R8 must not
# rename them. keepnames/keepclassmembernames (not keep): the connector uses
# both anyway, we only pin the NAMES — no shrinking exemption. Pinned together
# with the reflection call by UnifiedPushWipeWedgeSourceTest so the rule and
# the code cannot drift apart.
# -------------------------------------------------------------------------
-keepnames class org.unifiedpush.android.connector.internal.DBStore
-keepclassmembernames class org.unifiedpush.android.connector.internal.DBStore {
    org.unifiedpush.android.connector.internal.DBStore instance;
}

# -------------------------------------------------------------------------
# R8 full-mode compatibility
# -------------------------------------------------------------------------
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
