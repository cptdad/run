package com.vg.run

import android.content.Context

/**
 * The one Android [VaultFactory].
 *
 * Every call site used to inline its own `VaultFactory { dbKey, isProvision ->
 * DatabaseManager(...) }` lambda. That was fine while the interface had a single
 * method, but the provision guard added [VaultFactory.vaultFileExists], and a
 * factory whose probe and whose open disagree about which file they mean is worse
 * than no guard at all — it would report "no vault" while the destructive
 * isProvision+NOTADB branch deletes a real one. Constructing both halves in one
 * place makes that impossible to get wrong at a call site.
 */
fun androidVaultFactory(context: Context): VaultFactory = object : VaultFactory {
    override fun create(dbKey: ByteArray, isProvision: Boolean): VaultDatabase =
        DatabaseManager(context, dbKey, isProvision = isProvision)

    override fun vaultFileExists(): Boolean =
        DatabaseManager.vaultFileExists(context)

    // PROVISION-1: same reason again — the rollback must unlink the file the guard
    // probed and [create] opened, never a differently-resolved path. See the
    // interface kdoc for the (single, narrow) legal caller.
    override fun deleteVaultFileAfterFailedProvision() =
        DatabaseManager.deleteVaultFiles(context)

    // Same reason as vaultFileExists: the probe must resolve the same file
    // [create] would open, so it is built here rather than at a call site.
    override fun probeKey(dbKey: ByteArray): Boolean =
        DatabaseManager.probeKey(context, dbKey)

    // Raw-key adoption (2026-10-07) — all three resolve the SAME run.db as
    // [create]/[probeKey] (DatabaseManager.DATABASE_NAME via getDatabasePath),
    // for the same reason: a K' derived from one file's salt must only ever be
    // probed and opened against that file.
    override fun supportsRawKeyAdoption(): Boolean = true

    override fun deriveAdoptedRawKey(dbKey: ByteArray): ByteArray? =
        DatabaseManager.deriveAdoptedRawKey(context, dbKey)

    override fun createWithRawKey(rawKey: ByteArray): VaultDatabase =
        DatabaseManager(context, rawKey, isProvision = false, rawKey = true)

    override fun probeRawKey(rawKey: ByteArray): Boolean =
        DatabaseManager.probeKey(context, rawKey, rawKey = true)
}
