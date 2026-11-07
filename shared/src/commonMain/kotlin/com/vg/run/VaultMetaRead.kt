package com.vg.run

// ---------------------------------------------------------------------------
// The ONE "never delete on an ambiguous read" rule for `_meta` GC paths.
//
// A garbage-collecting caller (a store pruning expired / undecodable rows) must
// keep two null-shaped outcomes apart:
//  - [MetaRead.Unreadable]: the READ ITSELF failed (a transient vault error, a
//    closed handle). Ambiguous absence: the row is left strictly alone — never
//    deleted, never acted on — and read again next time.
//  - [MetaRead.Read]: the vault answered. A null [MetaRead.Read.raw] (the row is
//    gone) or a value the caller's decoder refuses is POSITIVE evidence the row
//    can never be used, so the caller may delete it as residue.
// Used by GroupInviteStore and ScreenshotNoticeStore; each keeps its own decode.
// ---------------------------------------------------------------------------
internal sealed interface MetaRead {
    object Unreadable : MetaRead
    class Read(val raw: String?) : MetaRead
}

// Reads [key] for a GC path. A throw is logged as
// "<what> read failed — left intact: <ExceptionClass>" (class name only) and
// answered [MetaRead.Unreadable]; never throws.
internal fun VaultDatabase.readMetaForGc(key: String, tag: String, what: String): MetaRead =
    try {
        MetaRead.Read(getMeta(key))
    } catch (e: Exception) {
        platformLogWarn(tag, "$what read failed — left intact: ${e::class.simpleName}")
        MetaRead.Unreadable
    }
