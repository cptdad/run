import SwiftUI

// ---------------------------------------------------------------------------
// TermsContactView — App Store Guideline 1.2 bullet 8: an in-app surface,
// reachable at any time from the settings (cogwheel) menu, that re-shows the
// Terms of Use in read-only form (no Agree/Decline — that gate already ran at
// first launch, see EulaView in UserSafety.swift) alongside our support
// contact address and a one-line statement of how reports are handled.
//
// Before this, the support address appeared ONLY inside the first-launch
// EULA and the report-fallback alert (AbuseReport.presentFallback) — there
// was no way to find it again once the EULA was accepted.
// ---------------------------------------------------------------------------

struct TermsContactView: View {
    let onClose: () -> Void

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Color.runBackground.ignoresSafeArea()

            VStack(spacing: 0) {
                Text(L10n.menuTermsContact)
                    .font(.runeHeadline)
                    .foregroundColor(Color.runTextPrimary)
                    .padding(.top, 20)
                    .padding(.bottom, 12)

                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        Text(L10n.eulaTermsOfUseTitle)
                            .font(.runeSubheadline).fontWeight(.semibold)
                            .foregroundColor(Color.runTextSecondary)

                        // Same body the first-launch gate shows (EulaView) —
                        // read-only here, no Agree/Decline.
                        Text(L10n.eulaBody(EulaConsent.supportEmail))
                            .font(.runeFootnote)
                            .foregroundColor(Color.runTextPrimary)
                            .accessibilityIdentifier("terms_contact_eula_text")

                        Divider().background(Color.runDivider)

                        Button {
                            // Reuses AbuseReport's mailto-open + copy fallback
                            // (UserSafety.swift) rather than a contact-scoped
                            // report, since this row isn't tied to any contact.
                            AbuseReport.openSupportEmail()
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(L10n.termsContactReportLine)
                                    .font(.runeSubheadline).fontWeight(.semibold)
                                    .foregroundColor(Color.runTextPrimary)
                                // Support email shown verbatim, as a tappable
                                // mailto link.
                                Text(verbatim: EulaConsent.supportEmail)
                                    .font(.runeFootnote)
                                    .foregroundColor(Color.runAccent)
                                    .underline()
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .accessibilityIdentifier("terms_contact_email_link")

                        Text(L10n.termsContactEnforcement)
                            .font(.runeCaption)
                            .foregroundColor(Color.runTextSecondary)
                            .accessibilityIdentifier("terms_contact_enforcement_text")
                    }
                    .padding(.horizontal, 20)
                    .padding(.bottom, 28)
                }
            }

            Button(action: onClose) {
                Image(systemName: "xmark")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundColor(Color.runTextPrimary)
                    .padding(12)
            }
            .accessibilityLabel(L10n.commonClose)
            .accessibilityIdentifier("terms_contact_close")
            .padding(.top, 8)
            .padding(.trailing, 8)
        }
        .preferredColorScheme(.dark)
        .accessibilityIdentifier("terms_contact_modal")
    }
}
