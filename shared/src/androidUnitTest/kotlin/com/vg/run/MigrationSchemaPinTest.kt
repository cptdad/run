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
}
