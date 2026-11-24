package com.vg.run

// ---------------------------------------------------------------------------
// Fixtures for the move read-cap rotation tests (MoveRotationBoundaryTest,
// MoveRotationObligationsTest). Synthetic ids and caps only.
// ---------------------------------------------------------------------------

/** A valid, unique 32-char inbox id: a direction tag, a number, padding. */
internal fun rotId(tag: Char, n: Int): String = (tag.toString() + n.toString().padStart(8, '0')).padEnd(32, 'Q')

/** A valid, unique 43-char capability derived from [seed]. */
internal fun rotCap(seed: String): String = ("k$seed").take(43).padEnd(43, 'A')

/** The owned inbox ids [seedMoveContacts] creates for contact [n], in insertion order. */
internal fun ownedIdsFor(n: Int): List<String> = listOf(rotId('T', n), rotId('C', n), rotId('G', n))

/**
 * [n] contacts, each with the three OWNED inbound rows (text, control, group) and
 * one outbound row. Returns every owned id in insertion order.
 */
internal fun seedMoveContacts(vault: VaultDatabase, n: Int, startAt: Int = 0): List<String> {
    val owned = mutableListOf<String>()
    for (i in startAt until startAt + n) {
        val contactId = "contact-$i"
        vault.insertContact(
            ContactRecord(
                contactId = contactId, sharedSecret = ByteArray(32) { 3 }, trustLevel = 2,
                alias = "A$i", aliasLastRotated = 10L,
            )
        )
        val dirs = listOf(
            'T' to "inbound",
            'C' to MessageManager.DIR_INBOUND_CTL,
            'G' to MessageManager.DIR_INBOUND_GRP,
        )
        for ((tag, dir) in dirs) {
            val id = rotId(tag, i)
            vault.insertInboxId(InboxIdRecord(id, contactId, 10L, 20L, dir, rotCap(id)))
            owned.add(id)
        }
        val out = rotId('O', i)
        vault.insertInboxId(InboxIdRecord(out, contactId, 10L, 20L, "outbound", rotCap(out)))
    }
    return owned
}

/** Thrown by [RollbackMoveVault] AFTER a transaction committed: models a process death at that instant. */
internal class SimulatedDeathAfterCommit : Error("simulated process death right after a commit")

/**
 * [MoveFakeVault] with REAL transaction semantics (a throw restores every map), so a
 * test can look at the store "after a reopen" on either side of a commit:
 *
 *  - [throwOnPutMetaKey] / [throwOnInsertContact] inject a failure inside a write;
 *  - [dieAfterNextCommit] lets the next transaction COMMIT and then throws
 *    [SimulatedDeathAfterCommit] (once), i.e. the process dies right after the commit;
 *  - [metaWrites] records which transaction (0 = none) every `_meta` write ran in.
 */
internal open class RollbackMoveVault : MoveFakeVault() {
    var throwOnPutMetaKey: String? = null
    var throwOnInsertContact = false
    var dieAfterNextCommit = false
    var transactions = 0
        private set
    private var currentTx = 0
    val metaWrites = mutableListOf<Pair<Int, String>>()

    override fun putMeta(key: String, value: String) {
        if (key == throwOnPutMetaKey) throw RuntimeException("injected meta write failure")
        metaWrites.add(currentTx to key)
        super.putMeta(key, value)
    }

    override fun insertContact(contact: ContactRecord): Long {
        if (throwOnInsertContact) throw RuntimeException("injected contact write failure")
        return super.insertContact(contact)
    }

    override fun withTransaction(block: () -> Unit) {
        val c = contacts.toMap()
        val i = inboxes.toList()
        val g = groups.toMap()
        val gm = groupMembers.toList()
        val m = meta.toMap()
        val w = metaWrites.toList()
        transactions++
        currentTx = transactions
        try {
            block()
        } catch (e: Throwable) {
            contacts.clear(); contacts.putAll(c)
            inboxes.clear(); inboxes.addAll(i)
            groups.clear(); groups.putAll(g)
            groupMembers.clear(); groupMembers.addAll(gm)
            meta.clear(); meta.putAll(m)
            metaWrites.clear(); metaWrites.addAll(w)
            throw e
        } finally {
            currentTx = 0
        }
        if (dieAfterNextCommit) {
            dieAfterNextCommit = false
            throw SimulatedDeathAfterCommit()
        }
    }
}

/**
 * A relay double that models read-capability state per inbox, which is all the
 * crash-safe rotation path ([MessageManager.rotateOwnedInboxReadCap]) talks to:
 * `PUT …/read-capability` (needs the current cap), `GET …/peek` (200 only for the
 * current cap), `DELETE …/push` (200).
 */
internal class CapRotatingRelay : RelayHttp {
    /** inboxId → the cap the relay currently honours. */
    val caps = mutableMapOf<String, String>()
    /** inboxId → how many more PUTs answer 503 without changing anything. */
    val failPutsFor = mutableMapOf<String, Int>()
    /** Inbox ids of every PUT, in order. */
    val puts = mutableListOf<String>()
    val calls = mutableListOf<String>()
    var onPut: ((String) -> Unit)? = null

    private fun idOf(url: String) = url.substringAfter("/inbox/").substringBefore('/').substringBefore('?')

    override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        val id = idOf(url)
        calls.add("PUT $id")
        if (!url.endsWith("/read-capability")) return HttpResult(code = 404, body = "{}", isSuccess = false)
        puts.add(id)
        onPut?.invoke(id)
        val left = failPutsFor[id] ?: 0
        if (left > 0) {
            failPutsFor[id] = left - 1
            return HttpResult(code = 503, body = "{}", isSuccess = false)
        }
        if (caps[id] == null || caps[id] != headers["X-Read-Capability"]) return HttpResult(code = 404, body = "{}", isSuccess = false)
        caps[id] = headers["X-New-Read-Capability"] ?: return HttpResult(code = 400, body = "{}", isSuccess = false)
        return HttpResult(code = 200, body = "{}", isSuccess = true)
    }

    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        val id = idOf(url)
        calls.add("GET $id")
        if (url.endsWith("/peek") && caps[id] != null && caps[id] == headers["X-Read-Capability"]) {
            return HttpResult(code = 200, body = """{"pending":0}""", isSuccess = true)
        }
        return HttpResult(code = 404, body = "{}", isSuccess = false)
    }

    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        calls.add("POST ${idOf(url)}")
        return HttpResult(code = 404, body = "{}", isSuccess = false)
    }

    override fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        calls.add("DELETE ${idOf(url)}")
        return HttpResult(code = 200, body = "{}", isSuccess = true)
    }

    /** Mirrors every owned row's current cap into the relay, as the real relay would hold it. */
    fun adoptCapsFrom(vault: VaultDatabase) {
        for (r in vault.getAllInboxIds()) {
            if (r.direction in MessageManager.OWNED_READ_DIRECTIONS && !r.cap.isNullOrEmpty()) caps[r.inboxId] = r.cap!!
        }
    }
}

/** An import-side [MoveTransport]: drains [chunks]; [rotate] decides each rotation (null = not confirmed). */
internal class RotationTestTransport(private val chunks: List<ByteArray>) : MoveTransport {
    var rotate: suspend (inboxId: String, cap: String) -> String? = { _, _ -> null }
    val rotated = mutableListOf<String>()
    val attempts = mutableListOf<String>()
    val deleted = mutableListOf<String>()

    override suspend fun mintTransferInbox(): MintedInbox = throw MoveTransportException("not used")
    override suspend fun postChunk(inboxId: String, writeCap: String, sealedChunk: ByteArray, ttlSeconds: Long) =
        throw MoveTransportException("not used")
    override suspend fun peekPending(inboxId: String, readCap: String): Int? = throw MoveTransportException("not used")
    override suspend fun drain(inboxId: String, readCap: String): List<ByteArray> = chunks.map { it.copyOf() }
    override suspend fun deleteInbox(inboxId: String, readCap: String) { deleted.add(inboxId) }
    override suspend fun rotateReadCap(inboxId: String, currentReadCap: String): String {
        attempts.add(inboxId)
        val r = rotate(inboxId, currentReadCap) ?: throw MoveTransportException("scripted: not confirmed")
        rotated.add(inboxId)
        return r
    }
}

internal class RotationTestSession(private val transport: MoveTransport?) : MoveSessionControl {
    override suspend fun unregisterPushBestEffort() {}
    override suspend fun quiesce() {}
    override suspend fun resume() {}
    override fun transport(): MoveTransport? = transport
}

internal const val ROT_TRANSFER_INBOX = "MoVeInBoX0000000000000000000002x"
internal const val ROT_TRANSFER_RCAP = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR2"

/** encode → seal, returning the handle the new phone scans and the chunks the relay holds. */
internal fun sealForRotationTest(snapshot: VaultSnapshot): Pair<MoveHandle, List<ByteArray>> {
    val bundleId = MoveHandleCodec.newBundleId()
    val plaintext = MigrationBundleCodec.encode(
        MigrationBundle(
            schema = MigrationBundleCodec.exportSchemaFor(snapshot),
            from = MigrationBundle.FROM_IOS,
            createdMs = 1_700_000_000_000L,
            bundleId = bundleId,
            snapshot = snapshot,
        )
    )
    val code = MigrationSeal.newCode()
    val chunks = MigrationSeal.seal(plaintext, code, ROT_TRANSFER_INBOX, bundleId)
    val handle = MoveHandle(ROT_TRANSFER_INBOX, ROT_TRANSFER_RCAP, MigrationSeal.encodeCode(code), bundleId)
    code.secureWipe()
    plaintext.secureWipe()
    return handle to chunks
}

internal fun rotationTestManager(vault: VaultDatabase?, transport: MoveTransport?) =
    MoveManager({ vault }, RotationTestSession(transport), MigrationBundle.FROM_ANDROID, exportAuthGate = TestGrantedGate()) {
        1_700_000_000_000L
    }

/** A realistic pending-introduction (`ref_p`) record whose three minted inboxes have NO row yet. */
internal fun pendingReferralRecord(mi: String, ci: String, gi: String): String =
    encodeStoredAccept(
        StoredAccept(
            introducerContactId = "contact-0",
            peerAlias = "Bee",
            privateKey = ByteArray(32) { 1 },
            publicKey = ByteArray(32) { 2 },
            minted = MintedInboxPair(
                MintedInbox(mi, rotCap(mi), rotCap("w$mi"), 0L),
                MintedInbox(ci, rotCap(ci), rotCap("w$ci"), 0L),
                MintedInbox(gi, rotCap(gi), rotCap("w$gi"), 0L),
            ),
            sent = true,
            attempts = 1,
            createdAt = 1_700_000_000_000L,
        )
    )

/** The stored rotation list, decoded the way every build reads it. */
internal fun listedRotations(vault: VaultDatabase): List<String> =
    vault.getMeta("mig_rotate_pending")?.split(',')?.filter { it.isNotEmpty() } ?: emptyList()

/** Runs the control-sweep entry point up to [maxSweeps] times or until the list is gone. */
internal fun sweepUntilDrained(vault: VaultDatabase, mm: MessageManager, maxSweeps: Int = 400): Int {
    var n = 0
    while (n < maxSweeps) {
        retryPendingMoveRotations(vault, mm)
        n++
        if (vault.getMeta("mig_rotate_pending").isNullOrEmpty() && vault.getMeta("mig_rot_v") != null) return n
        if (vault.getMeta("mig_rotate_pending").isNullOrEmpty() && n > 2) return n
    }
    return n
}
