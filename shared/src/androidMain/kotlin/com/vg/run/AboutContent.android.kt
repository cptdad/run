package com.vg.run

// Android: in RELEASE, FLAG_SECURE (MainActivity) blocks screenshots AND the
// recent-apps preview AND screen recording, so the strong claim below is accurate
// DEBUG builds drop FLAG_SECURE for e2e screen-recording, so this
// text overstates there — but debug builds are never shipped.
internal actual val screenPrivacyBody: String
    get() = platformString("about_screen_privacy_body_android")
