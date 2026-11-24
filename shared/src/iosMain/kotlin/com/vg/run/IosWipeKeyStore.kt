@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlinx.cinterop.BetaInteropApi::class)

package com.vg.run

import kotlinx.cinterop.ObjCObjectVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import platform.Foundation.NSApplicationSupportDirectory
import platform.Foundation.NSCachesDirectory
import platform.Foundation.NSCocoaErrorDomain
import platform.Foundation.NSError
import platform.Foundation.NSFileManager
import platform.Foundation.NSPOSIXErrorDomain
import platform.Foundation.NSSearchPathForDirectoriesInDomains
import platform.Foundation.NSUnderlyingErrorKey
import platform.Foundation.NSUserDomainMask
import kotlin.concurrent.Volatile

// ---------------------------------------------------------------------------
// IosWipeKeyStore — the iOS [WipeKeyStore] (RÚN-02): the Swift Keychain / Secure
// Enclave bridges for the keys and the credential items, NSFileManager for the vault
// files. Every outcome comes back checked; a missing bridge holder is UNRESOLVED,
// never a silent skip (the old `bridge?.deleteKey()` skipped with no signal).
// ---------------------------------------------------------------------------

/**
 * `UIApplication.isProtectedDataAvailable`, as last reported by Swift
 * (`IosAppController.noteProtectedDataAvailable`, called on the main thread at launch,
 * on `protectedDataWillBecomeUnavailable` / `…DidBecomeAvailable`, and right before
 * every wipe and retry). A snapshot so the off-main provision path can read it; it
 * starts FALSE, so an adapter used before Swift has spoken never trusts "absent".
 */
internal object IosProtectedData {
    @Volatile var available: Boolean = false
}

/** Vault database files every searched directory may hold. `run_b.db` is the removed
 *  decoy file, still deleted for installs provisioned before the removal. */
internal val VAULT_DB_FILE_NAMES = listOf("run.db", "run_b.db")

/** SQLite sidecars deleted after each base file (`-journal` is iOS's own since the
 *  rollback-journal change; `-wal`/`-shm` are what older builds leave). */
internal val SQLITE_SIDECAR_SUFFIXES = listOf("-wal", "-shm", "-journal")

/** Application Support and Caches — every directory the vault can live in
 *  ([iosVaultBaseDir]'s preference and its fallback). Null = unresolvable. Never creates. */
internal fun iosVaultSearchDirs(): List<String?> = listOf(NSApplicationSupportDirectory, NSCachesDirectory).map { dir ->
    NSSearchPathForDirectoriesInDomains(dir, NSUserDomainMask, true).firstOrNull() as? String
}

/** True present, false CONFIRMED absent (ENOENT), null unknowable. */
internal fun iosPathPresence(path: String): Boolean? = memScoped {
    val err = alloc<ObjCObjectVar<NSError?>>()
    val attrs = NSFileManager.defaultManager.attributesOfItemAtPath(path, err.ptr)
    if (attrs != null) return@memScoped true
    val e = err.value ?: return@memScoped null
    if (isNoSuchFile(e)) false else null
}

private fun isNoSuchFile(e: NSError): Boolean {
    // NSFileReadNoSuchFileError (260) / NSFileNoSuchFileError (4) / POSIX ENOENT (2).
    if (e.domain == NSCocoaErrorDomain && (e.code == 260L || e.code == 4L)) return true
    if (e.domain == NSPOSIXErrorDomain && e.code == 2L) return true
    val underlying = e.userInfo[NSUnderlyingErrorKey] as? NSError ?: return false
    return underlying.domain == NSPOSIXErrorDomain && underlying.code == 2L
}

/** Removes [path]; returns null on success, else the NSError code. */
private fun removePath(path: String): Int? = memScoped {
    val err = alloc<ObjCObjectVar<NSError?>>()
    if (NSFileManager.defaultManager.removeItemAtPath(path, err.ptr)) null else (err.value?.code?.toInt() ?: -1)
}

/**
 * RÚN-02 R2/R3 input: is a vault database (`run.db`) present in ANY directory the
 * vault can live in? true = present somewhere; false = CONFIRMED absent in every
 * directory AND every directory resolved; null = cannot tell. Only `false` is ever
 * acted on — and only by the rules that need "no vault file" as positive evidence.
 */
internal fun iosVaultFilesPresence(dirs: List<String?> = iosVaultSearchDirs()): Boolean? {
    var unknown = false
    for (dir in dirs) {
        if (dir == null) { unknown = true; continue }
        when (iosPathPresence("$dir/${VaultFiles.DB}")) {
            true -> return true
            null -> unknown = true
            false -> Unit
        }
    }
    return if (unknown) null else false
}

/**
 * Deletes every vault file and sidecar in [dirs] and proves each gone. DELETED when
 * something was removed, ALREADY_ABSENT when nothing was there, UNRESOLVED when any
 * path is still present or unknowable afterwards. An unresolvable directory holds no
 * file at a path this app can form, so it is skipped.
 */
internal fun iosDeleteAllVaultFiles(dirs: List<String?>): EraseResult {
    var removedSomething = false
    var unresolvedStatus: Int? = null
    for (dir in dirs) {
        if (dir == null) continue
        for (name in VAULT_DB_FILE_NAMES) for (suffix in listOf("") + SQLITE_SIDECAR_SUFFIXES) {
            val path = "$dir/$name$suffix"
            val before = iosPathPresence(path)
            val removeStatus = if (before != false) removePath(path) else null
            if (iosPathPresence(path) == false) {
                if (before != false) removedSomething = true
            } else if (unresolvedStatus == null) {
                unresolvedStatus = removeStatus ?: EraseResult.STATUS_STILL_PRESENT
            }
        }
    }
    return when {
        unresolvedStatus != null -> EraseResult.unresolved(unresolvedStatus)
        removedSomething -> EraseResult(EraseOutcome.DELETED, 0)
        else -> EraseResult(EraseOutcome.ALREADY_ABSENT, 0)
    }
}

internal class IosWipeKeyStore(
    private val protectedData: () -> Boolean = { IosProtectedData.available },
    private val vaultDirs: () -> List<String?> = { iosVaultSearchDirs() },
) : WipeKeyStore {

    override fun protectedDataAvailable(): Boolean = protectedData()

    override fun erase(item: WipeItem): EraseResult = when (item) {
        WipeItem.DEVICE_KEY -> KeychainBridgeHolder.bridge?.deleteKeyChecked()?.toEraseResult() ?: noBridge()
        WipeItem.HARDWARE_KEY -> SecureEnclaveBridgeHolder.bridge?.deleteKeyChecked()?.toEraseResult() ?: noBridge()
        WipeItem.KV_SWEEP -> KeychainBridgeHolder.bridge?.kvDeleteAllChecked()?.toEraseResult() ?: noBridge()
        WipeItem.BLOCK_LIST -> KeychainBridgeHolder.bridge?.deleteBlockListChecked()?.toEraseResult() ?: noBridge()
        WipeItem.VAULT_FILES -> iosDeleteAllVaultFiles(vaultDirs())
    }

    private fun noBridge() = EraseResult.unresolved(EraseResult.STATUS_NO_BRIDGE)
}
