package com.vg.run

// iOS: the app-switcher snapshot and screen-recording/AirPlay are covered, but
// iOS exposes no API to block a MANUAL hardware screenshot — so the copy must not
// claim screenshots are blocked. The app instead detects a
// screenshot and warns (ScreenshotProtection).
internal actual val screenPrivacyBody: String
    get() = platformString("about_screen_privacy_body_ios")
