package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The delayed-clear decision of [SensitiveClipboard]. An unreadable clipboard is
 * exactly the backgrounded case on Android 10+ (getPrimaryClip() returns null
 * without input focus), so it must clear rather than silently keep a pairing code
 * or transfer handle.
 */
class SensitiveClipboardTest {

    @Test
    fun aReadableClipThatIsStillOurs_isCleared() {
        assertTrue(SensitiveClipboard.shouldClear(readable = true, currentText = "code", ours = "code"))
    }

    @Test
    fun aReadableClipTheUserReplaced_isLeftAlone() {
        assertFalse(SensitiveClipboard.shouldClear(readable = true, currentText = "something else", ours = "code"))
        assertFalse(SensitiveClipboard.shouldClear(readable = true, currentText = null, ours = "code"))
    }

    @Test
    fun anUnreadableClipboard_isCleared() {
        assertTrue(SensitiveClipboard.shouldClear(readable = false, currentText = null, ours = "code"))
    }

    @Test
    fun theAlarmPath_matchesByFingerprint_only() {
        val fp = SensitiveClipboard.fingerprint("code")
        assertTrue(SensitiveClipboard.shouldClearFingerprint(readable = true, currentText = "code", oursFingerprint = fp))
        assertFalse(SensitiveClipboard.shouldClearFingerprint(readable = true, currentText = "other", oursFingerprint = fp))
        assertFalse(SensitiveClipboard.shouldClearFingerprint(readable = true, currentText = null, oursFingerprint = fp))
        assertTrue(SensitiveClipboard.shouldClearFingerprint(readable = false, currentText = null, oursFingerprint = fp))
    }

    @Test
    fun theFingerprint_isASha256Hex_andNeverTheText() {
        val fp = SensitiveClipboard.fingerprint("secret-handle")
        assertTrue(Regex("^[0-9a-f]{64}$").matches(fp))
        assertFalse(fp.contains("secret"))
    }

    /**
     * Source pins for review 2026-11-06 S2 F3 / S5: the sensitive flag is set on
     * every API level, the delayed clear has an AlarmManager backstop that
     * survives process death, the alarm carries only the fingerprint, and the
     * receiver is not exported.
     */
    @Test
    fun source_flagOnEveryApi_alarmBackstop_receiverNotExported() {
        val src = stripComments(SourcePins.text("androidApp/src/main/java/com/vg/run/SensitiveClipboard.kt"))
        assertTrue(src.contains("putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)"))
        assertFalse("the sensitive flag must not be gated on the API level", src.contains("SDK_INT"))
        assertTrue(src.contains("setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP"))
        assertTrue(src.contains("putExtra(EXTRA_FINGERPRINT, fingerprint)"))
        assertFalse("the alarm intent must never carry the clip text", Regex("""putExtra\([^)]*\btext\b""").containsMatchIn(src))
        val manifest = SourcePins.text("androidApp/src/main/AndroidManifest.xml")
        val at = manifest.indexOf("android:name=\".ClipboardClearReceiver\"")
        assertTrue("the receiver must be declared", at >= 0)
        val decl = manifest.substring(at, manifest.indexOf("/>", at))
        assertTrue("the receiver must not be exported", decl.contains("android:exported=\"false\""))
    }
}
