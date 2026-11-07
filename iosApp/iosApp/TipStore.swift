import StoreKit
import SwiftUI

// ---------------------------------------------------------------------------
// TipStore — StoreKit 2 "tip jar" for iOS (the Android counterpart is the
// Play Billing tab in DonateModal).
//
// Four CONSUMABLE products (so a supporter can tip again and again). The app
// only references the product IDs below; the products + localized prices live
// in App Store Connect (and in Run.storekit for simulator/Xcode testing).
// Apple is processor + bank — no server, no payment entitlement.
//
// Consumables have no entitlement to restore: a purchase is just verified and
// finished. We never call it a "donation" in the UI (Apple reserves donations
// for registered nonprofits) — it's a "tip"/"Support".
// ---------------------------------------------------------------------------

@MainActor
final class TipStore: ObservableObject {

    /// Tip product IDs — must match App Store Connect (and Run.storekit). Order =
    /// display order. Same IDs as the Android tip jar. Priced in SEK (base
    /// currency; Apple auto-converts other regions): tip_small 19, tip_medium 49,
    /// tip_large 99, tip_xl 999. The LIVE price comes from App Store Connect.
    static let tierIds = ["tip_small", "tip_medium", "tip_large", "tip_xl"]

    @Published var products: [Product] = []
    @Published var loading = true
    /// True once a load attempt finished with no purchasable products (not
    /// configured yet / StoreKit unavailable) — drives the graceful empty state.
    @Published var unavailable = false
    /// The product ID currently mid-purchase (drives the per-row spinner).
    @Published var purchasing: String? = nil
    /// Set after a verified, finished tip — drives the thank-you state.
    @Published var thanked = false

    func load() async {
        loading = true
        unavailable = false
        await finishUnfinishedTransactions()
        do {
            let fetched = try await Product.products(for: Self.tierIds)
            // Preserve tier order regardless of StoreKit's response order.
            products = Self.tierIds.compactMap { id in fetched.first { $0.id == id } }
            unavailable = products.isEmpty
        } catch {
            products = []
            unavailable = true
        }
        loading = false
    }

    func purchase(_ product: Product) async {
        purchasing = product.id
        defer { purchasing = nil }
        do {
            let result = try await product.purchase()
            switch result {
            case .success(let verification):
                // Only thank on a CRYPTOGRAPHICALLY VERIFIED transaction — an
                // unverified (jailbroken/forged) receipt is ignored, not finished.
                if case .verified(let transaction) = verification {
                    await transaction.finish()
                    thanked = true
                }
            case .userCancelled, .pending:
                break            // backed out / Ask-to-Buy deferred — no thanks yet
            @unknown default:
                break
            }
        } catch {
            // Transient StoreKit error — leave the tiers up so the user can retry.
        }
    }

    /// iOS sibling of the Play `queryPurchasesAsync`
    /// reconcile: sweep transactions StoreKit has completed but this app never
    /// finished. `listenForTransactions` only runs while the Support view is on
    /// screen, so a purchase completed just as the view went away — or as the app
    /// was killed — is never finished there; StoreKit then keeps re-delivering it
    /// and the user sees no thanks for money that already moved. Finishing is
    /// idempotent, so re-running this on every load is safe.
    private func finishUnfinishedTransactions() async {
        for await result in Transaction.unfinished {
            // Same rule as the purchase path: only a cryptographically verified
            // transaction is finished and thanked; forged receipts are ignored.
            if case .verified(let transaction) = result {
                await transaction.finish()
                thanked = true
            }
        }
    }

    /// Drains StoreKit transaction updates (e.g. an Ask-to-Buy approval that
    /// lands later) and finishes them. Bound to the view's lifetime via .task,
    /// so it's cancelled when Support closes — no manual teardown.
    func listenForTransactions() async {
        for await update in Transaction.updates {
            if case .verified(let transaction) = update {
                await transaction.finish()
                thanked = true
            }
        }
    }
}
