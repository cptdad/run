package com.vg.run

import kotlinx.coroutines.flow.StateFlow

/**
 * "Move to new device" — the shared API contract (docs/device-move.md).
 *
 * This file is the seam between three implementation areas that are built in parallel:
 *   - MigrationBundle.kt   codec + sealing + QR handle codec (pure, no I/O)
 *   - VaultSnapshotIo.kt   export/import against [VaultDatabase] (one transaction, idempotent)
 *   - MoveManager.kt       orchestration over the relay transport + session control
 * Nothing here does I/O. Keep the types here stable; extend, don't rename.
 */

/** Everything that persists in the vault and travels with the user. Header fields live in the bundle. */
data class VaultSnapshot(
    val contacts: List<ContactRecord>,
    val inboxes: List<InboxIdRecord>,
    val groups: List<GroupRecord>,
    val members: List<GroupMemberRecord>,
    /** `_meta` rows, ALREADY filtered through [MoveMetaPolicy.isAllowedKey] by the exporter. */
    val meta: Map<String, String>,
)

/** What the QR / pasted text carries. `code` is the 32-symbol Base32 one-time code (20 CSPRNG bytes). */
data class MoveHandle(
    val inboxId: String,
    val readCap: String,
    val code: String,
    val bundleId: String,
) {
    /** Never leak the cap or the code through logs / crash reports. */
    // Every field redacted: no id fragment may reach a log line or crash report.
    override fun toString() = "MoveHandle([redacted])"
}

/** Meta-key policy shared by exporter, importer and tests. Source of truth for the `dr*` set is `ratchetMetaKeysForContact`. */
object MoveMetaPolicy {
    val allowedPrefixes: List<String> = listOf(
        "dr/", "dr-rxc/", "dr-on", "dr-intent", "dr-rxseen", "dr-rxlock", "dr-legacyfb",
        // The role-collision detectors travel WITH the ratchet state they
        // describe. The new phone imports the same `dr/…/text` blob, so it inherits the
        // same role and the same collision; leaving these behind would silently hand it
        // a fresh 8-send window of no-forward-secrecy traffic (and hide a refusal the
        // user was already told to re-pair out of).
        "dr-rat-unacked/", "dr-refused/",
        // The role INPUTS must travel with the ratchet state, or the new
        // phone would fall back to the id-order rule the moment it has to re-init
        // (onCorruptReinit) and could land the OPPOSITE role from the peer — the
        // collision this rule exists to remove. Neither holds key material: the order
        // key is one bit of ordering, the v2 key is a boolean.
        "dr-roleord/", "dr-rolerv2/",
        // `cap-pend/` is per (contact, DIRECTION) and the prefix covers every
        // direction in MessageManager.OWNED_READ_DIRECTIONS — including the v10
        // group inbox (`cap-pend/<id>/inbound-grp`). The THIRD inbox pair itself
        // needs no entry here at all: inbox rows are table rows, not `_meta`, so
        // they travel verbatim through `VaultSnapshotIo.export`'s `getAllInboxIds()`
        // exactly as the v7 control pair does, and `MoveManager`'s D4 pass rotates
        // their read caps because it iterates OWNED_READ_DIRECTIONS
        // (MoveManager.kt:764). The inbox pair itself therefore needs no entry.
        //
        // `grp-ann/` (`MessageManager.groupBackfillKey`) is the group-inbox
        // backfill throttle and it TRAVELS — deliberately, and note the HYPHEN:
        // `grp_` above does NOT match it, which is why it is spelled out. It is a
        // BOUND, not a cache: it records how much of a per-contact budget of PoW
        // mints + announces has been spent, and only two things may re-arm that
        // budget (a re-pair, and the pairing actually converging). A move is
        // neither, so dropping it would hand the new phone a fresh budget for every
        // contact that never converged — a burst of grinds and announces on exactly
        // the launch that is already paying for the D4 read-cap rotations.
        "m2-chseen", "ib-bound-seen/", "cap-pend/", "grp-ann/", "grp_", "ref_", "ssn:",
        // The Maximum shield's two per-contact rows (`MaximumShieldPolicy`): the peer's
        // remembered claim and the last level we announced. Contact ids survive the move,
        // so both stay meaningful; dropping the marker would only make the new phone
        // re-announce to every contact once.
        "plvl-peer/", "plvl-sent/",
        // The anti-eclipse tombstone
        // (`group_admin:<groupId>`, GroupManager.adminMetaKey) — the ONLY key in the
        // vault whose prefix is `group_` rather than `grp_`, which is exactly why it
        // fell through this list. It records the FIRST admin-of-record for a group
        // and deliberately outlives `deleteGroup` (it is in neither residue
        // classifier), so that a LATER invite to the same groupId from a DIFFERENT
        // contact is flagged as an eclipse attempt. A move that dropped it handed the
        // new phone a blank slate for every group it had ever left: the attacker who
        // was refused on the old phone is silently accepted on the new one. Its value
        // is a contactId (or SELF_ADMIN_MARKER) and contact ids are preserved by the
        // bundle, so it is meaningful on arrival; it carries no key material.
        "group_admin:",
    )
    val deniedPrefixes: List<String> = listOf(
        "vlt_", "pin_", "inactivity_", "change_pin_", "run.crypto", "review_prompt", "update_nudge",
        "onboard_push_prompt", MoveMetaKeys.PREFIX,
        // The persisted group unread attribution (`grp-unread/<contactId>`,
        // GroupUnreadMarkerStore) is the ONE per-contact purge-list key that does NOT
        // travel, and it is denied here explicitly so a future broad allow prefix cannot
        // pick it up. It is a ≤ 24 h display hint, not state anything depends on: the
        // new phone imports the same inbox rows, re-derives the group-inbox depth with
        // its first peek and falls back to the presence bump (+1 on every shared group)
        // until the first open/drain — exactly today's pre-fix behaviour, for at most
        // one day. Carrying it would add per-contact "N group texts in group G at time T"
        // metadata to a bundle that crosses devices, for no correctness gain.
        GroupUnreadMarkerStore.PREFIX,
    )
    fun isAllowedKey(key: String): Boolean =
        deniedPrefixes.none { key.startsWith(it) } && allowedPrefixes.any { key.startsWith(it) }
}

/** `_meta` keys owned by the move feature. All of them are wipe residue and belong in the purge tests. */
object MoveMetaKeys {
    const val PREFIX = "mig_"
    /** "1" while this device is the OLD phone of a move: never poll, never send. */
    const val FROZEN = "mig_frozen"
    /** `inboxId|readCap|bundleId|chunkCount` for the outstanding transfer inbox (code is RAM-only). */
    const val HANDLE = "mig_handle"
    /** bundleId of the import that completed on this (NEW) phone. Written LAST in the import transaction. */
    const val IMPORTED = "mig_imported"
}

enum class MoveError {
    NOT_UNLOCKED, MINT_FAILED, UPLOAD_FAILED, TOO_LARGE, RELAY_UNREACHABLE,
    BUNDLE_GONE, BAD_CODE, BUNDLE_CORRUPT, SCHEMA_TOO_NEW, IMPORT_FAILED, CANCEL_REFUSED, ALREADY_IMPORTED,
}

/** Old-phone side state machine. */
sealed class MoveExportState {
    data object Idle : MoveExportState()
    data class Preparing(val step: MoveExportStep) : MoveExportState()
    /** Bundle is on the relay; show the QR. `handle` includes the code (RAM-only). */
    data class Ready(val handle: MoveHandle, val chunkCount: Int) : MoveExportState()
    /** The new phone drained the bundle. Offer wipe / keep-off. */
    data object Moved : MoveExportState()
    /** Frozen, but the code is gone (process death) — only "show again" (re-issue) or wipe. */
    data object FrozenNoCode : MoveExportState()
    data class Failed(val error: MoveError, val retryable: Boolean) : MoveExportState()
}

enum class MoveExportStep { UNREGISTER_PUSH, FREEZE, MINT, UPLOAD }
enum class MoveImportStep { FETCHING, IMPORTING, SECURING }

sealed class MoveImportResult {
    data class Success(val contacts: Int, val groups: Int) : MoveImportResult()
    data class Failure(val error: MoveError) : MoveImportResult()
}

/**
 * Relay operations the move needs, on an inbox that belongs to no contact.
 * Implemented by `RelayMoveTransport` (RelayMoveTransport.kt): thin wrappers over MessageManager's mint / POST / GET-drain / DELETE / read-cap rotate.
 * All calls suspend, run over Tor, and throw [MoveTransportException] on I/O failure.
 */
interface MoveTransport {
    /** Mints a fresh inbox (PoW). Uses the existing [MintedInbox] (readCapability = owner cap, writeCapability). */
    suspend fun mintTransferInbox(): MintedInbox
    /** POST one sealed chunk with `?ttl=` and X-No-Push. */
    suspend fun postChunk(inboxId: String, writeCap: String, sealedChunk: ByteArray, ttlSeconds: Long)
    /** Non-destructive: number of blobs pending, or null when the inbox answers 404. */
    suspend fun peekPending(inboxId: String, readCap: String): Int?
    /** Destructive drain: every blob currently in the inbox, in relay order. Empty list on 404. */
    suspend fun drain(inboxId: String, readCap: String): List<ByteArray>
    suspend fun deleteInbox(inboxId: String, readCap: String)
    /** Rotates the READ (owner) cap of an inbox this device owns; returns the new cap. */
    suspend fun rotateReadCap(inboxId: String, currentReadCap: String): String
}


class MoveTransportException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * What the platform session layer (RunViewModel / IosAppController) lends the manager.
 * [quiesce] only has to stop the poll loops and the control sweep — the MessageManager itself STAYS
 * ALIVE (the transfer inbox needs Tor and the HTTP client) and is gated INTERNALLY against every
 * contact-facing send/poll/peek from the moment `mig_frozen` is written, so no ratchet step can
 * happen afterwards even on the 1:1 paths that hold it directly;
 * [resume] restarts them (only used by a successful cancel). Both are idempotent.
 */
interface MoveSessionControl {
    suspend fun unregisterPushBestEffort()
    suspend fun quiesce()
    suspend fun resume()
    /** The live transport, or null when Tor / the session is not up. */
    fun transport(): MoveTransport?
}

/** Public surface used by both UIs. Implemented by MoveManager (MoveManager.kt). */
interface MoveManagerApi {
    val exportState: StateFlow<MoveExportState>

    /** True when this vault carries [MoveMetaKeys.FROZEN]. Cheap; safe to call right after unlock. */
    fun isFrozen(): Boolean

    /** Old phone: steps a–e of the protocol. Idempotent per state; drives [exportState]. */
    suspend fun beginExport()

    /** Old phone, frozen: build a fresh bundle under a fresh code (the vault is unchanged since the freeze). */
    suspend fun reissueExport()

    /** Old phone: peek the transfer inbox and move Ready → Moved when the new phone has drained it. */
    suspend fun refreshTransferState()

    /** Old phone: delete the bundle and unfreeze. Returns false (and leaves the state) when the bundle was already drained. */
    suspend fun cancelExport(): Boolean

    /** New phone, after its own provision + unlock: fetch, import (+counter jump), rotate read caps. */
    suspend fun importFromHandle(handle: MoveHandle, onProgress: (MoveImportStep) -> Unit): MoveImportResult
}

object MoveConstants {
    const val CODE_BYTES = 20
    const val CHUNK_PLAINTEXT_BYTES = 60_000
    const val MAX_CHUNKS = 200
    const val TRANSFER_TTL_SECONDS = 1_800L
    const val COUNTER_JUMP = 10_000L
    const val HKDF_INFO = "run:migrate:v1"
    const val CHUNK_AAD_LABEL = "run:migrate:chunk:v1"
    const val QR_VERSION = "1"
}
