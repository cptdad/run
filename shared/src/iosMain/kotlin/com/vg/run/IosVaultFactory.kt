package com.vg.run

/**
 * The one iOS [VaultFactory] — see [androidVaultFactory] for why both halves are
 * built together rather than inlined at each call site: the provision guard's
 * probe and the open it guards must resolve the same path, and here they both go
 * through [iosVaultDbPath].
 */
fun iosVaultFactory(): VaultFactory = object : VaultFactory {
    override fun create(dbKey: ByteArray, isProvision: Boolean): VaultDatabase =
        IosVaultDatabase(dbKey, isProvision)

    override fun vaultFileExists(): Boolean = iosVaultFileExists()

    // PROVISION-1: same reason again — the rollback must unlink the file the guard
    // probed and [create] opened (both resolve through [iosVaultDbPath]), never a
    // differently-resolved path. See the interface kdoc for the single legal caller.
    override fun deleteVaultFileAfterFailedProvision() = iosDeleteVaultFiles()

    // Same reason as vaultFileExists: the probe must resolve the same path
    // [create] would open, so it is built here rather than at a call site.
    override fun probeKey(dbKey: ByteArray): Boolean = iosProbeVaultKey(dbKey)
}
