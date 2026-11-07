package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The vault store-key table and the crypto-context table are PERSISTED FORMAT:
 * every value below is a key name some existing vault stores its credential under,
 * or the exact AEAD context / KDF label its blobs were sealed with. The 2026-11
 * readability pass moved and RENAMED these constants (out of the VaultSelector
 * companion into [VaultStoreKeys] / [VaultCryptoContexts] / [VaultFiles]); this test
 * pins that no VALUE moved with them. Changing a literal here is never a
 * refactor — it orphans or bricks every provisioned vault, and needs a legacy read
 * path plus a migration instead.
 */
class VaultStoreKeysPinTest {

    @Test
    fun storeKeyNamesAreFrozen() {
        assertEquals("vlt_a", VaultStoreKeys.CREDENTIAL_VERIFIER)
        assertEquals("vlt_c", VaultStoreKeys.WRAPPED_DBKEY)
        assertEquals("vlt_c", VAULT_DBKEY_STORAGE_KEY)
        assertEquals("vlt_cn", VaultStoreKeys.PENDING_DBKEY)
        assertEquals("vlt_m", VaultStoreKeys.CREDENTIAL_MODE)
        assertEquals("vlt_lvl", VaultStoreKeys.PROTECTION_LEVEL)
        assertEquals("vlt_rc", VaultStoreKeys.RECOVERY_BLOB)
        assertEquals("vlt_rp", VaultStoreKeys.RECOVERY_PENDING)
        assertEquals("vlt_abk", VaultStoreKeys.AUTHBOUND_SCHEME)
        assertEquals("vlt_txn_journal", VaultStoreKeys.BATCH_JOURNAL)
        assertEquals("real_credential_hash", VaultStoreKeys.LEGACY_CREDENTIAL)
        assertEquals("real_db_wrapped", VaultStoreKeys.LEGACY_DBKEY)
        assertEquals("vlt_b", VaultStoreKeys.REMOVED_DECOY_CREDENTIAL)
        assertEquals("vlt_d", VaultStoreKeys.REMOVED_DECOY_DBKEY)
        assertEquals("decoy_credential_hash", VaultStoreKeys.REMOVED_LEGACY_DECOY_CREDENTIAL)
        assertEquals("decoy_db_wrapped", VaultStoreKeys.REMOVED_LEGACY_DECOY_DBKEY)
        assertEquals("vlt_a", IosUserDefaultsKeys.CREDENTIAL_VERIFIER)
    }

    @Test
    fun legacyKeyNameMigrationStillMapsOldToNew() {
        assertEquals(
            listOf("real_credential_hash" to "vlt_a", "real_db_wrapped" to "vlt_c"),
            VaultStoreKeys.LEGACY_KEY_NAME_MIGRATIONS,
        )
    }

    @Test
    fun cryptoContextsAndLabelsAreFrozen() {
        assertEquals("vault-selector:real-credential", VaultCryptoContexts.CREDENTIAL)
        assertEquals("vault-dbkey:real", VaultCryptoContexts.DBKEY_INNER)
        assertEquals("vault-dbkey:recovery", VaultCryptoContexts.RECOVERY)
        assertEquals("vault:cred-verifier", VaultCryptoContexts.LABEL_VERIFIER)
        assertEquals("vault:dbkey-kek", VaultCryptoContexts.LABEL_DBKEY_KEK)
        assertEquals("vault:recovery-kek", VaultCryptoContexts.LABEL_RECOVERY_KEK)
        // The selector-meta context used to be the template "vault-selector-meta:$key";
        // the prefix constant must reproduce it byte-for-byte for every slot.
        for (key in listOf("vlt_m", "vlt_lvl", "vlt_rp", "vlt_abk")) {
            assertEquals("vault-selector-meta:$key", VaultCryptoContexts.SELECTOR_META_PREFIX + key)
        }
    }

    @Test
    fun selectorMetaTokensAreFrozen() {
        assertEquals("pin", SelectorMetaPolicy.MODE_PIN)
        assertEquals("phrase", SelectorMetaPolicy.MODE_PASSPHRASE)
        assertEquals("2", SelectorMetaPolicy.AUTHBOUND_SCHEME_STRICT)
        assertEquals("1", RecoveryBlobPolicy.RECOVERY_PENDING_ARMED)
        assertEquals(16, SelectorMetaPolicy.SELECTOR_META_PADDED_LEN)
        assertEquals(20, RecoveryBlobPolicy.RECOVERY_SECRET_LENGTH)
    }

    @Test
    fun vaultFileNamesAreFrozen() {
        assertEquals("run.db", VaultFiles.DB)
        assertEquals("run_b.db", VaultFiles.REMOVED_DECOY_DB)
        assertEquals(listOf("", "-wal", "-shm", "-journal"), VaultFiles.SIDECAR_SUFFIXES)
    }

    @Test
    fun provisionRollbackOrderIsUnchangedByTheMove() {
        // Journal FIRST, then the credential pair (crypto-erase before the file),
        // then the metadata. ProvisionWriteGuardTest pins the semantics; this pins
        // the literal order survived the move into VaultWriteProofs.
        assertEquals(
            listOf("vlt_txn_journal", "vlt_a", "vlt_c", "vlt_m", "vlt_lvl"),
            VaultWriteProofs.PROVISION_ROLLBACK_KEYS,
        )
        assertEquals(
            listOf("vlt_txn_journal", "vlt_a", "vlt_c"),
            VaultWriteProofs.PROVISION_FILE_DELETE_BLOCKERS,
        )
    }
}
