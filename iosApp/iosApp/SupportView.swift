import SwiftUI
import StoreKit

// ---------------------------------------------------------------------------
// SupportView — the iOS "Support Rún" tip jar (StoreKit 2). Presented as a
// sheet from the contact-list cogwheel. iOS is tip-only by design: this is the
// whole iOS support UI, with no crypto donate surface. (Android's DonateModal
// has a Tip tab + a Crypto tab; iOS deliberately does not — Apple is stricter
// about non-IAP payment surfaces than Google's tips carve-out.)
//
// Wording is deliberately "tip"/"Support", never "donation" — Apple reserves
// donations for registered nonprofits, and a for-profit tip must go through IAP.
// ---------------------------------------------------------------------------

struct SupportView: View {
    let onClose: () -> Void

    @StateObject private var store = TipStore()

    /// Friendly tier names (the App Store product title carries the app name).
    private func tierLabel(_ productID: String) -> String {
        switch productID {
        case "tip_small":  return L10n.tipTierSmall
        case "tip_medium": return L10n.tipTierMedium
        case "tip_large":  return L10n.tipTierLarge
        case "tip_xl":     return L10n.tipTierXl
        default:           return L10n.donateTabTip
        }
    }

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Color.runBackground.ignoresSafeArea()

            VStack(spacing: 16) {
                Text(L10n.donateTitle)
                    .font(.system(.title, design: .serif))
                    .fontWeight(.bold)
                    .foregroundColor(Color.runTextPrimary)
                    .padding(.top, 40)

                Text(L10n.tipAppeal)
                    .font(.runeSubheadline)
                    .foregroundColor(Color.runTextSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 28)

                Spacer().frame(height: 8)

                content

                Spacer()

                Text(L10n.tipStoreDisclosure)
                    .font(.runeCaption2)
                    .foregroundColor(Color.runTextSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 28)
                    .padding(.bottom, 20)
            }
            .frame(maxWidth: .infinity)

            Button(action: onClose) {
                Image(systemName: "xmark")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundColor(Color.runTextPrimary)
                    .padding(12)
            }
            .accessibilityIdentifier("support_close")
            .padding(.top, 8)
            .padding(.trailing, 8)
        }
        .accessibilityIdentifier("support_modal")
        .preferredColorScheme(.dark)
        .task { await store.load() }
        .task { await store.listenForTransactions() }
    }

    @ViewBuilder
    private var content: some View {
        if store.thanked {
            VStack(spacing: 8) {
                Text(L10n.tipThankYou)
                    .font(.runeTitle3).fontWeight(.bold)
                    .foregroundColor(Color.runTextPrimary)
                    .accessibilityIdentifier("tip_thanks")
                Text(L10n.tipThankYouBody)
                    .font(.runeFootnote)
                    .foregroundColor(Color.runTextSecondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal, 28)
        } else if store.loading {
            ProgressView()
                .tint(Color.runTextSecondary)
                .accessibilityIdentifier("tip_loading")
        } else if store.unavailable {
            Text(L10n.tipUnavailableFallback)
                .font(.runeSubheadline)
                .foregroundColor(Color.runTextSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 28)
                .accessibilityIdentifier("tip_unavailable")
        } else {
            VStack(spacing: 10) {
                ForEach(store.products, id: \.id) { product in
                    tierRow(product)
                }
            }
            .padding(.horizontal, 20)
        }
    }

    private func tierRow(_ product: Product) -> some View {
        Button {
            Task { await store.purchase(product) }
        } label: {
            HStack {
                Text(tierLabel(product.id))
                    .font(.runeBody)
                    .foregroundColor(Color.runTextPrimary)
                Spacer()
                if store.purchasing == product.id {
                    ProgressView().tint(Color.runBackground)
                        .frame(width: 64)
                } else {
                    Text(product.displayPrice)
                        .font(.runeSubheadline).fontWeight(.semibold)
                        .foregroundColor(Color.runBackground)
                        .padding(.horizontal, 18)
                        .padding(.vertical, 8)
                        .background(Color.runTextPrimary)
                        .clipShape(Capsule())
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
            .background(Color.runSurface)
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
        .disabled(store.purchasing != nil)
        .accessibilityIdentifier("tip_tier_\(product.id)")
    }
}
