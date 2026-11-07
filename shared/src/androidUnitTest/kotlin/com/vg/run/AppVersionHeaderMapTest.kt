package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Update-nudge: unit coverage for the pure header-allowlist
 * function the Android actual builds [HttpResult.headers] from
 * (`appVersionHeaderMap` in PlatformHttpClient.android.kt). Extracted so this
 * doesn't need a live/mocked OkHttp response — the call site
 * (`response.header("android-version")`) is a thin, well-understood OkHttp
 * primitive (single-value, case-insensitive, last-wins) that isn't itself
 * worth re-testing here.
 */
class AppVersionHeaderMapTest {

    @Test
    fun absent_header_yields_empty_map() {
        assertEquals(emptyMap(), appVersionHeaderMap(null))
    }

    @Test
    fun present_header_within_cap_is_stored_under_the_common_key() {
        val result = appVersionHeaderMap("1.2.3")
        assertEquals(mapOf(APP_VERSION_HEADER_KEY to "1.2.3"), result)
        assertEquals("app-version", APP_VERSION_HEADER_KEY)
    }

    @Test
    fun header_exactly_at_the_cap_is_kept() {
        val exactlyFourteen = "1234.5678.9012" // 14 chars, matches the wire grammar's max
        assertEquals(14, exactlyFourteen.length)
        assertEquals(mapOf(APP_VERSION_HEADER_KEY to exactlyFourteen), appVersionHeaderMap(exactlyFourteen))
    }

    @Test
    fun header_one_over_the_cap_is_dropped_not_truncated() {
        val fifteen = "12345.6789.0123"
        assertEquals(15, fifteen.length)
        assertTrue(appVersionHeaderMap(fifteen).isEmpty())
    }

    @Test
    fun a_hostile_multi_kilobyte_value_is_dropped() {
        val huge = "9".repeat(4096)
        assertTrue(appVersionHeaderMap(huge).isEmpty())
    }

    @Test
    fun empty_string_header_is_kept_as_is_cap_only_bounds_length() {
        // appVersionHeaderMap only enforces the length cap; grammar validation
        // (UpdateCheck.parseVersion, owned by a different phase of this work)
        // is the client's next gate before anything is shown to the user.
        assertEquals(mapOf(APP_VERSION_HEADER_KEY to ""), appVersionHeaderMap(""))
    }
}
