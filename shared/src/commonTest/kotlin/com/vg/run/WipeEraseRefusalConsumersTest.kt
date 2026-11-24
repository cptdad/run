package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * RÚN-02: while a wipe's erase is unresolved, a device key that would have to be
 * MINTED is refused with KeyUnavailableException (iOS getOrCreateKey, Android
 * CryptoManager init). This pins that every pre-unlock / background consumer of the
 * device key in commonMain absorbs that refusal instead of letting it escape — on
 * iOS an exception crossing a non-@Throws bridge call aborts the process.
 *
 * The cipher here throws KeyUnavailableException on BOTH seal and open, which is
 * exactly what the refused mint looks like to a consumer.
 */
class WipeEraseRefusalConsumersTest {

    private val refused = FakeDeviceKeyCipher(throwOnOpen = true, throwOnSeal = true)

    private class MapStore : DebugModeStore {
        val values = mutableMapOf<String, String>()
        override fun get(key: String): String? = values[key]
        override fun putSync(key: String, value: String) { values[key] = value }
        override fun remove(key: String): Boolean { values.remove(key); return true }
    }

    private class NotifStore : NotifLevelStore {
        val values = mutableMapOf<String, String>()
        override fun get(key: String): String? = values[key]
        override fun putSync(key: String, value: String) { values[key] = value }
        override fun putAllSync(values: Map<String, String>) { this.values.putAll(values) }
        override fun remove(key: String) { values.remove(key) }
    }

    private class Marker(var value: Long? = 1L) : NotifConsentMarker {
        override fun epoch(): Long? = value
        override fun recordEpoch(epoch: Long): Boolean = true
    }

    @Test
    fun debugModeFlag_absorbsTheRefusal() {
        // A flag sealed under the (now refused) key is on file.
        val store = MapStore().apply { values[DebugMode.KEY] = SealedPref.seal(FakeDeviceKeyCipher(), DebugMode.SLOT, "1") }
        assertFalse(DebugMode.isEnabledIn(store, refused), "unreadable reads as OFF, never a throw")
        DebugMode.applyAtStartupIn(store, refused)        // RunApp.init / RunApplication: must not throw
        DebugMode.setEnabledIn(store, refused, true)       // the Settings write path
        DebugMode.setEnabledIn(store, refused, false)
        DebugMode.reapplyPersistedIn(store, refused)
        DebugMode.reapplyPersistedTriStateIn(store, refused)
    }

    @Test
    fun externalProxySetting_absorbsTheRefusal() {
        val store = MapStore().apply { values[ExternalTorProxy.PREF_KEY] = SealedPref.seal(FakeDeviceKeyCipher(), "x", "127.0.0.1:9050") }
        val read = ExternalTorProxy.readStoredIn(store, refused)   // RunViewModel init, pre-unlock (Android)
        assertEquals(null, read.config, "no address is dialled from an unreadable value")
        ExternalTorProxy.writeStoredIn(store, refused, null)               // the Settings write path
    }

    @Test
    fun notificationLevel_absorbsTheRefusal() {
        val store = NotifStore()
        assertEquals(
            NotificationLevel.OFF,
            NotificationLevelStore.provenLevelIn(store, refused, Marker(), legacyPlaintext = null),
            "push consent unreadable ⇒ OFF, never a throw",
        )
        NotificationLevelStore.clearLevelIn(store, refused, Marker())      // clearWipeResidue / push services
        NotificationLevelStore.setLevelIn(store, refused, Marker(), NotificationLevel.OFF)
        NotificationLevelStore.setConsentProofIn(store, refused, Marker(null), NotificationLevel.OFF)
    }
}
