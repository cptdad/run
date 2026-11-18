package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals

// ---------------------------------------------------------------------------
// The one cross-file coupling area 1 cannot express in commonMain.
//
// A migration bundle stamps the vault SCHEMA it was exported from, and the
// importer refuses a bundle whose schema is newer than its own vault
// ("update Rún on the new phone"). The schema number lives in
// DatabaseManager.DATABASE_VERSION (androidMain) — iOS has no schema counter at
// all, it migrates additively — so commonMain has to carry a copy.
//
// If someone bumps DATABASE_VERSION for a new column and forgets
// MigrationBundleCodec.CURRENT_SCHEMA, every bundle a new build exports claims
// the OLD schema, and the new phone happily imports it without the importer ever
// getting the chance to notice the mismatch. This test is the only thing that
// catches that, and it lives here because androidUnitTest is the only test
// source set that can see both constants.
// ---------------------------------------------------------------------------
class MigrationSchemaPinTest {

    @Test
    fun bundleSchemaMatchesTheVaultDatabaseVersion() {
        assertEquals(
            DatabaseManager.DATABASE_VERSION,
            MigrationBundleCodec.CURRENT_SCHEMA,
            "MigrationBundleCodec.CURRENT_SCHEMA must be bumped with DatabaseManager.DATABASE_VERSION",
        )
    }

    /**
     * Owner decision D4 (docs/ratchet-bootstrap-plan.md §4.3): a vault with no v3
     * contact is exported at the schema the PREVIOUS build reads (v10), so a move to
     * an older build keeps working until the first v3 pairing. If a later schema step
     * moves DATABASE_VERSION again, this pin forces a decision about what a
     * "no new feature in use" bundle should claim instead of silently keeping 10.
     */
    @Test
    fun legacyExportSchema_isTheSchemaBeforeTheV3Step() {
        assertEquals(11, DatabaseManager.DATABASE_VERSION, "revisit LEGACY_EXPORT_SCHEMA with the next schema step")
        assertEquals(10, MigrationBundleCodec.LEGACY_EXPORT_SCHEMA)
    }
}
