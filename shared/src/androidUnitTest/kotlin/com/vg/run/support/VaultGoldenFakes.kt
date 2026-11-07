package com.vg.run

// Fakes for VaultSelectorGoldenTest. They live in androidUnitTest (not commonTest) so
// the bare iOS simulator runner, which has no AesGcm/Argon2 bridge registered, gains
// no new failure; androidUnitTest still sees commonTest's internal fakes
// (FakeDeviceKeyCipher, support/InMemoryVault).

/** One store WRITE, as the golden records it. Reads are deliberately not recorded. */
internal sealed class StoreOp {
    data class Put(val key: String) : StoreOp()
    data class Batch(val keys: List<String>) : StoreOp()
    data class Remove(val key: String) : StoreOp()
}

/**
 * In-memory [SelectorStore] recording every ISSUED write in order (a remove of an
 * absent key is still recorded — the golden pins what VaultSelector asks for, not
 * what the platform store would elide). [droppedPuts] models the iOS locked-keybag
 * `kvPut` no-op (the write is recorded as issued but does not land), which is the
 * failure every read-back gate in VaultSelector exists for.
 */
internal class RecordingSelectorStore : SelectorStore {
    val kv = linkedMapOf<String, String>()
    val ops = mutableListOf<StoreOp>()
    val droppedPuts = mutableSetOf<String>()

    override fun getString(key: String): String? = kv[key]
    override fun contains(key: String): Boolean = key in kv
    override fun putStringSync(key: String, value: String) {
        ops += StoreOp.Put(key)
        if (key !in droppedPuts) kv[key] = value
    }
    override fun putStringsSync(values: Map<String, String>) {
        ops += StoreOp.Batch(values.keys.toList())
        for ((k, v) in values) if (k !in droppedPuts) kv[k] = v
    }
    override fun remove(key: String): Boolean {
        ops += StoreOp.Remove(key)
        kv.remove(key)
        return true
    }

    /** The writes since the last drain, then clear. */
    fun drain(): List<StoreOp> = ops.toList().also { ops.clear() }
}

/**
 * Plain layer = [DeviceKeyCipher] under the DB-key context (what
 * CryptoProviderDbKeyProtector does). Auth-bound layer = a numbered "hardware key":
 * [deleteAuthBoundKeyBeforeEnable] drops it, the next authBound wrap mints generation
 * n+1, and an unwrap under a dropped or [invalidateHardwareKey]'d generation throws
 * [KeyPermanentlyInvalidException] — the strict-invalidate-on-re-enrolment behaviour
 * the recovery code exists for. Every auth-bound unwrap counts one biometric
 * [prompts]. Both forms go through the real [DbKeyScheme.tagged].
 */
internal class FakeDbKeyProtector(private val cipher: DeviceKeyCipher) : DbKeyProtector {
    var supportsAuth = true
    var prompts = 0
    val events = mutableListOf<String>()
    private var generation = 0          // 0 = no hardware key exists
    private var nextGeneration = 1
    private var invalidated = false
    private val plainCtx = VaultCryptoContexts.DBKEY_INNER.encodeToByteArray()
    private fun abCtx(gen: Int) = "fake-auth-bound:$gen".encodeToByteArray()

    fun invalidateHardwareKey() { invalidated = true }

    override fun supportsAuthBinding(): Boolean = supportsAuth
    override fun isAuthBoundBlob(stored: String): Boolean = DbKeyScheme.isAuthBound(stored)
    override fun deleteAuthBoundKeyBeforeEnable() {
        events += "delete-key"; generation = 0; invalidated = false
    }
    override fun wrap(inner: ByteArray, authBound: Boolean): String {
        if (!authBound) {
            return DbKeyScheme.tagged(DbKeyScheme.TAG_CRYPTO_PROVIDER, encodeBase64(cipher.seal(inner, plainCtx)))
        }
        if (generation == 0) { generation = nextGeneration++; events += "mint-key" }
        val sealed = byteArrayOf(generation.toByte()) + cipher.seal(inner, abCtx(generation))
        return DbKeyScheme.tagged(DbKeyScheme.TAG_AUTH_BOUND, encodeBase64(sealed))
    }
    override fun unwrap(stored: String): ByteArray {
        val payload = decodeBase64(DbKeyScheme.payloadOf(stored))
        if (!DbKeyScheme.isAuthBound(stored)) return cipher.open(payload, plainCtx)
        prompts++
        val gen = payload[0].toInt()
        if (invalidated || gen != generation) throw KeyPermanentlyInvalidException("fake hardware key gone")
        return cipher.open(payload.copyOfRange(1, payload.size), abCtx(gen))
    }
}

/**
 * One "file", identified by the key it is encrypted with. create() on unlock never
 * creates (mirrors isProvision=false) and a wrong key throws (NOTADB). [adopts] gives
 * the Android raw-key adoption surface, with K' = sha256(R ‖ "fake-salt");
 * [refuseFirstDerive] makes the PROVISION-time derive fail once so the first unlock is
 * the one that adopts (T14).
 */
internal class FakeVaultFactory(
    private val adopts: Boolean = false,
    private var refuseFirstDerive: Boolean = false,
) : VaultFactory {
    var fileKey: ByteArray? = null
    val opens = mutableListOf<String>()

    private fun kPrime(r: ByteArray) = sha256(r + "fake-salt".encodeToByteArray())

    override fun create(dbKey: ByteArray, isProvision: Boolean): VaultDatabase {
        val fk = fileKey
        if (fk == null) {
            check(isProvision) { "unlock must never create a file" }
            fileKey = dbKey.copyOf()
        } else {
            check(fk.contentEquals(dbKey)) { "file is not a database (wrong key)" }
        }
        opens += if (isProvision) "create(provision)" else "create"
        return InMemoryVault()
    }
    override fun vaultFileExists(): Boolean = fileKey != null
    override fun deleteVaultFileAfterFailedProvision() { opens += "delete-file"; fileKey = null }
    override fun probeKey(dbKey: ByteArray): Boolean = fileKey?.contentEquals(dbKey) == true

    override fun supportsRawKeyAdoption(): Boolean = adopts
    override fun deriveAdoptedRawKey(dbKey: ByteArray): ByteArray? {
        if (!adopts) return null
        if (refuseFirstDerive) { refuseFirstDerive = false; return null }
        return kPrime(dbKey)
    }
    override fun createWithRawKey(rawKey: ByteArray): VaultDatabase {
        val fk = checkNotNull(fileKey)
        check(kPrime(fk).contentEquals(rawKey)) { "wrong raw key" }
        opens += "raw"
        return InMemoryVault()
    }
    override fun probeRawKey(rawKey: ByteArray): Boolean =
        fileKey?.let { kPrime(it).contentEquals(rawKey) } == true
}

/** The live handle a tier-upgrade rotation re-keys: moves the fake file to the new key. */
internal class RekeyableVault(private val factory: FakeVaultFactory) : InMemoryVault() {
    override fun rekey(newDbKey: ByteArray): Boolean {
        factory.fileKey = newDbKey.copyOf()
        return true
    }
}
