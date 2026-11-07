import SwiftUI
import UIKit
import shared

// ---------------------------------------------------------------------------
// Notification names for cross-view communication.
// ---------------------------------------------------------------------------

extension Notification.Name {
    static let contactsChanged = Notification.Name("contactsChanged")
}

// ---------------------------------------------------------------------------
// App-wide typeface — Metamorphous (bundled, OFL — assets/fonts/), the
// carved-stone face matching the runestone art. Single Regular weight; the
// rune* statics mirror the semantic styles they replace, sized to the system
// defaults and scaling with Dynamic Type via relativeTo. Deliberately NOT
// applied: `.system(...)` call sites (SF Symbol / icon sizing, the forensic
// panel's terminal look), `design: .monospaced` (log viewer, codes), and
// `design: .serif` (the runic "ᚱ" / "Rún" wordmark).
// ---------------------------------------------------------------------------

extension Font {
    static func rune(_ size: CGFloat, relativeTo style: Font.TextStyle) -> Font {
        .custom("Metamorphous", size: size, relativeTo: style)
    }
    static let runeLargeTitle  = rune(34, relativeTo: .largeTitle)
    static let runeTitle       = rune(28, relativeTo: .title)
    static let runeTitle2      = rune(22, relativeTo: .title2)
    static let runeTitle3      = rune(20, relativeTo: .title3)
    static let runeHeadline    = rune(17, relativeTo: .headline)
    static let runeBody        = rune(17, relativeTo: .body)
    static let runeCallout     = rune(16, relativeTo: .callout)
    static let runeSubheadline = rune(15, relativeTo: .subheadline)
    static let runeFootnote    = rune(13, relativeTo: .footnote)
    static let runeCaption     = rune(12, relativeTo: .caption)
    static let runeCaption2    = rune(11, relativeTo: .caption2)
}

// ---------------------------------------------------------------------------
// UIComponents — shared view primitives used across PIN and setup screens.
// ---------------------------------------------------------------------------

// MARK: - Color hex initializer

extension Color {
    init(hex: Int, alpha: Double = 1.0) {
        self.init(
            red:     Double((hex >> 16) & 0xFF) / 255.0,
            green:   Double((hex >>  8) & 0xFF) / 255.0,
            blue:    Double( hex        & 0xFF) / 255.0,
            opacity: alpha
        )
    }
    
    // MARK: - Rún Design System Colors
    static let runBackground    = Color(hex: 0x0D0D0D)
    static let runSurface       = Color(hex: 0x1A1A1A)
    static let runSentBubble    = Color(hex: 0x2A2A2A)
    static let runReceivedBubble = Color(hex: 0x1E1E1E)
    static let runAccent        = Color(hex: 0x4CAF50) // Green accent
    static let runTextPrimary   = Color(hex: 0xF0F0F0)
    static let runTextSecondary = Color(hex: 0x666666)
    static let runError         = Color(hex: 0xCF6679)
    static let runDivider       = Color(hex: 0x222222)
}

// MARK: - ShakeModifier

struct ShakeModifier: ViewModifier {
    var amount: Double
    func body(content: Content) -> some View {
        content.offset(x: amount)
    }
}

// MARK: - PinDots

/// A row of filled/empty circles representing how many PIN digits have been entered.
struct PinDots: View {
    let filled: Int
    let total:  Int
    let error:  Bool

    var body: some View {
        HStack(spacing: 16) {
            ForEach(0..<total, id: \.self) { i in
                Circle()
                    .fill(dotColor(at: i))
                    .frame(width: 14, height: 14)
            }
        }
        .animation(.easeInOut(duration: 0.1), value: filled)
        .accessibilityIdentifier("pin_dots")
        // Invisible entered-digit count, exposed as a queryable element's text so
        // e2e can verify each keypad tap registered — deterministic PIN entry,
        // no digit-drop flakiness. The dots already show this visually; reveals
        // the count, never the digits. #if DEBUG-gated so it does NOT ship in
        // release (parity with Android's BuildConfig.DEBUG-gated equivalent;
        // keep the count off the release a11y tree).
        #if DEBUG
        .overlay(
            Text("\(filled)")
                .foregroundColor(.clear)
                .accessibilityIdentifier("pin_count")
        )
        #endif
    }

    private func dotColor(at index: Int) -> Color {
        guard index < filled else { return Color(hex: 0x333333) }
        return error ? Color(hex: 0xCF6679) : Color(hex: 0xF0F0F0)
    }
}

// MARK: - PinKeypad

/// A 3×4 numeric keypad.  Row 4: blank | 0 | ⌫
struct PinKeypad: View {
    let onDigit:  (String) -> Void
    let onDelete: () -> Void

    private let rows: [[String]] = [
        ["1", "2", "3"],
        ["4", "5", "6"],
        ["7", "8", "9"],
        ["",  "0", "⌫"]
    ]

    var body: some View {
        VStack(spacing: 12) {
            ForEach(rows.indices, id: \.self) { r in
                HStack(spacing: 20) {
                    ForEach(rows[r].indices, id: \.self) { c in
                        let key = rows[r][c]
                        if key.isEmpty {
                            Spacer().frame(width: 76, height: 76)
                        } else {
                            PinKey(label: key) {
                                if key == "⌫" { onDelete() }
                                else           { onDigit(key) }
                            }
                            .accessibilityIdentifier(key == "⌫" ? "key_delete" : "key_\(key)")
                        }
                    }
                }
            }
        }
        // A numeric keypad is direction-agnostic (like the system dialer);
        // auto-mirroring the VStack/HStack under an RTL locale (ar/fa) would
        // scramble the 1-2-3 / 4-5-6 / 7-8-9 layout. Forced only on this
        // view — shared by PinEntry/PinSetup/ChangePin.
        .environment(\.layoutDirection, .leftToRight)
    }
}

private struct PinKey: View {
    let label:  String
    let action: () -> Void

    var body: some View {
        Button(action: {
            // Haptic feedback on keypress
            let generator = UIImpactFeedbackGenerator(style: .light)
            generator.impactOccurred()
            action()
        }) {
            Group {
                if label == "⌫" {
                    Image(systemName: "delete.left")
                        .font(.runeTitle2)
                } else {
                    Text(label)
                        .font(.runeTitle)
                        .fontWeight(.light)
                }
            }
            .foregroundColor(Color(hex: 0xF0F0F0))
            .frame(width: 76, height: 76)
            .background(Color(hex: 0x1A1A1A))
            .clipShape(Circle())
        }
    }
}

// MARK: - Passphrase input (high-risk mode — Lever A)

/// Secure free-text credential field for passphrase mode.
///
/// Security: SecureField masks input and stays out of QuickType/autocorrect
/// learning; the explicit modifiers make that discipline load-bearing rather
/// than incidental (same no-IME-learning treatment as contact mnemonics).
struct PassphraseField: View {
    let placeholder: String
    @Binding var text: String
    let identifier: String
    var disabled = false
    var onSubmit: (() -> Void)? = nil

    var body: some View {
        SecureField(placeholder, text: $text)
            .textFieldStyle(.plain)
            .autocorrectionDisabled(true)
            .textInputAutocapitalization(.never)
            .textContentType(.oneTimeCode)  // suppress password-manager save prompts
            .foregroundColor(Color.runTextPrimary)
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(Color.runSurface.opacity(0.6))
            .cornerRadius(10)
            .disabled(disabled)
            .onSubmit { onSubmit?() }
            .onChange(of: text) { value in
                let cap = Int(CredentialPolicy.shared.MAX_PASSPHRASE_LENGTH)
                if value.count > cap { text = String(value.prefix(cap)) }
            }
            .accessibilityIdentifier(identifier)
    }
}

/// Strength meter for a candidate passphrase: four segments driven by the
/// SHARED CredentialPolicy estimator, so iOS and Android enforce the same
/// floor and display the same buckets.
struct PassphraseStrengthMeter: View {
    let passphrase: String

    var body: some View {
        let bits = CredentialPolicy.shared.estimateBits(passphrase: passphrase)
        let bucket = Int(CredentialPolicy.shared.strengthBucket(bits: bits))
        let meetsFloor = CredentialPolicy.shared.meetsFloor(passphrase: passphrase)
        let fillColor: Color = meetsFloor ? Color(hex: 0x66BB6A) : Color.runError

        VStack(spacing: 6) {
            HStack(spacing: 4) {
                ForEach(0..<4, id: \.self) { i in
                    RoundedRectangle(cornerRadius: 2)
                        .fill(
                            (!passphrase.isEmpty && i <= bucket && (i < 2 || meetsFloor))
                                ? fillColor
                                : Color(hex: 0x333333)
                        )
                        .frame(width: 40, height: 4)
                }
            }
            if !passphrase.isEmpty {
                Text(label(bucket: bucket))
                    .font(.runeCaption)
                    .foregroundColor(meetsFloor ? Color(hex: 0x66BB6A) : Color.runError)
                    .accessibilityIdentifier("passphrase_strength")
            }
        }
    }

    private func label(bucket: Int) -> String {
        switch bucket {
        case 0:  return L10n.pinStrengthTooWeak
        case 1:  return L10n.pinStrengthStillWeak
        case 2:  return L10n.pinStrengthStrong
        default: return L10n.pinStrengthExcellent
        }
    }
}

// MARK: - Contact Name Generator

/// Thin wrapper over the SHARED ContactAliasGenerator (KMP commonMain) — the
/// single source of truth for alias formats and word pools on both platforms.
/// The old local verb/animal lists had silently drifted from
/// Android's.
struct ContactNameGenerator {
    static func generate() -> String {
        ContactAliasGenerator.shared.generate()
    }
}

// MARK: - Rune dialog chrome (artist mock 2026-07-20)
//
// The single modal look for every popup: a dark stone card with a worn light
// border, centered uppercase Metamorphous text in parchment, a full-width
// hairline, and a divider-split action row. Android mirrors this in
// RuneDialog.kt; keep the two in visual lockstep.
//
// ACTION ORDER IS A SAFETY RULE, not a style choice. Actions render left→right
// in array order, and:
//
//   * A DESTRUCTIVE action (delete / leave / block / reduce-protection) must
//     ALWAYS be LAST — never the leftmost cell. Muscle memory from every other
//     app puts Cancel on the left, so a destructive action there gets tapped by
//     reflex. In this app the leftmost cell is NEVER destructive.
//   * When a dialog HAS a destructive action, the dismissive one ("Cancel",
//     "Keep current") goes FIRST, so the reflex tap lands on the safe choice.
//   * Otherwise follow the mock: the affirmative action first (left), the
//     dismissive one second (e.g. APPROVE | DECLINE).
//   * STACKED fallback (2026-09-29, see RuneActionRow below): when the row
//     can't fit side by side, actions render top→bottom in the SAME array
//     order instead of left→right. The safe slot is still index 0 — it just
//     moves from "leftmost" to "topmost", because a reflex tap on a vertical
//     list lands on the first row exactly like it lands on the first column.

extension Color {
    static let runeCardFill     = Color(hex: 0x161515)   // dialog card fill
    static let runeBorderBright = Color(hex: 0x73706A)   // worn border, top edge
    static let runeBorderDim    = Color(hex: 0x45423E)   // worn border, bottom edge
    static let runeParchment    = Color(hex: 0xF0E7D5)   // dialog body text
    static let runeGold         = Color(hex: 0xD3A878)   // primary action
    static let runeAsh          = Color(hex: 0xA0A0A0)   // secondary action
    static let runeHairline     = Color(hex: 0x413F3C)   // dialog hairline dividers
    // Destructive action. A warm ember red, NOT runError (#CF6679) — that rose
    // is a Material-derived tone and reads cold against the parchment/gold chrome.
    static let runeDanger       = Color(hex: 0xD4463A)
}

/// One action cell in the divider-split row. Mirrors Android RuneDialogAction.
struct RuneDialogAction: Identifiable {
    let id = UUID()
    let label: String
    var color: Color = .runeGold
    var enabled: Bool = true
    var a11yId: String? = nil
    // Opt-in id for the LABEL text itself, distinct from [a11yId] (the whole
    // button). Nil at every existing call site (unchanged behavior — a plain
    // SwiftUI `Button` is always a single LEAF accessibility element on iOS,
    // confirmed empirically: its label never appears as a separately
    // queryable child, unlike Android's Compose Text, which survives a
    // clickable ancestor's merge). Only when this is non-nil does
    // [RuneActionRow] mark the button as an a11y CONTAINER (same
    // `accessibilityElement(children: .contain)` idiom as
    // [OptionalContainerA11yId]) so the label becomes its own element with
    // its own rect — needed by update-nudge-layout.spec.ts's geometry checks
    // (is the label clipped by / shrunk relative to its sibling). Android
    // sibling: RuneDialog.kt's `RuneDialogAction.testTag` + the `_label`
    // suffix `RuneActionCell` tags its Text with.
    var labelA11yId: String? = nil
    let action: () -> Void

    init(_ label: String, color: Color = .runeGold, enabled: Bool = true,
         a11yId: String? = nil, labelA11yId: String? = nil, action: @escaping () -> Void) {
        self.label = label
        self.color = color
        self.enabled = enabled
        self.a11yId = a11yId
        self.labelA11yId = labelA11yId
        self.action = action
    }

    /// Convenience secondary ("cancel"-flavoured) action in ash grey.
    static func secondary(_ label: String, a11yId: String? = nil,
                          action: @escaping () -> Void) -> RuneDialogAction {
        RuneDialogAction(label, color: .runeAsh, a11yId: a11yId, action: action)
    }
}

/// The bare bordered stone card — shared by dialogs and custom overlays.
struct RuneCard<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        VStack(spacing: 0) { content }
            .background(Color.runeCardFill)
            .clipShape(RoundedRectangle(cornerRadius: 22))
            .overlay(
                RoundedRectangle(cornerRadius: 22)
                    .strokeBorder(
                        LinearGradient(colors: [.runeBorderBright, .runeBorderDim],
                                       startPoint: .top, endPoint: .bottom),
                        lineWidth: 2
                    )
            )
    }
}

/// Centered uppercase dialog title in parchment.
struct RuneDialogTitle: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text.uppercased())
            .font(.rune(19, relativeTo: .headline))
            .kerning(1.5)
            .foregroundColor(.runeParchment)
            .multilineTextAlignment(.center)
    }
}

/// Centered uppercase dialog body text in parchment, mock line spacing.
struct RuneDialogMessage: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text.uppercased())
            .font(.rune(13, relativeTo: .body))
            .kerning(0.4)
            .lineSpacing(7)
            .foregroundColor(.runeParchment)
            .multilineTextAlignment(.center)
    }
}

/// Hairline + action cells, side by side (equal-width columns) when every
/// label fits at the readable floor, else STACKED (full-width rows) when one
/// doesn't.
///
/// 2026-09-29: the update nudge's store label ("Öppna Google Play" / "Открыть
/// Google Play" / … — long in every locale, see ContactListView.swift's nudge
/// call site) doesn't fit a half-width cell even at a heavily shrunk scale
/// factor, so it clipped on Android's equivalent layout ("ÖPPNA GOOGLE PLA").
/// Shrinking further isn't the fix — the old `minimumScaleFactor(0.5)` (down
/// to ~9.5pt off a 19pt base) is already below comfortable reading size, and
/// the mid-word-break alternative was already rejected (2026-09-11, see the
/// ordering-rule comment above). Instead we MEASURE each label (uppercased,
/// actual kerning, at the READABLE FLOOR) against its real equal-width cell
/// before committing to the side-by-side row; if any label wouldn't fit
/// there, the whole row falls back to a STACKED layout — one full-width cell
/// per action, hairlines between rows instead of columns — where the same
/// floor always fits.
///
/// Deliberately NOT a `ViewThatFits(in: .horizontal)` over an HStack: that API
/// judges fit from the row's OWN ideal/reported size, but a
/// `minimumScaleFactor` text always successfully reports whatever size it's
/// given (that's the whole point of the modifier) — so a plain ViewThatFits
/// candidate would never actually detect an overflow, and a `.fixedSize()`
/// candidate would report the SUM of the labels' natural widths, which can
/// look like it fits (a short "Later" plus a long "Open Google Play" can sum
/// to less than the dialog's width) even though the long label overflows its
/// own EQUAL-width half — exactly this bug's pair.
///
/// Also deliberately NOT a `GeometryReader`/`PreferenceKey` read-back of the
/// row's rendered width: that round-trip needs an extra layout pass before
/// `@State` catches up, and in practice (device-verified 2026-09-29) the
/// dialog can render — and get screenshotted, and sit there — on the STALE
/// first pass, which defaults to "fits", silently reintroducing the exact
/// clip this fix exists to remove. Instead we compute the row's width the
/// same way [RuneDialogOverlay]'s own `maxBodyHeight` already does: from
/// `UIScreen.main.bounds` minus that overlay's fixed `.padding(.horizontal,
/// 32)` (this row is only ever hosted there) — deterministic on the very
/// first render, no timing dependency — then measure each label against its
/// actual per-cell share with `NSAttributedString`, matching Android's
/// `rememberTextMeasurer` approach cell-for-cell.
///
/// Labels are NEVER broken mid-word in either layout; the scale factor still
/// ranges up to the full size when there's room. Android sibling:
/// RuneDialog.kt's RuneActionRow.
struct RuneActionRow: View {
    let actions: [RuneDialogAction]
    var topHairline = true

    // Readable floor/ceiling — kept numerically in lockstep with
    // RuneDialog.kt's RuneActionLabelFloor/Ceiling (14/19) so a label that
    // reads comfortably on one platform reads the same on the other.
    private let minFontSize: CGFloat = 14
    private let maxFontSize: CGFloat = 19
    private let cellHorizontalPadding: CGFloat = 8
    private let hairlineWidth: CGFloat = 1
    // RuneDialogOverlay's own horizontal inset around the RuneCard — see the
    // "Deliberately NOT a GeometryReader" note above.
    private let dialogHorizontalInset: CGFloat = 32

    @Environment(\.sizeCategory) private var sizeCategory

    private var rowWidth: CGFloat {
        max(0, UIScreen.main.bounds.width - dialogHorizontalInset * 2)
    }

    var body: some View {
        VStack(spacing: 0) {
            if topHairline {
                Rectangle().fill(Color.runeHairline).frame(height: 1)
            }
            if fitsSideBySide {
                sideBySideRow
            } else {
                stackedColumn
            }
        }
    }

    private var sideBySideRow: some View {
        HStack(spacing: 0) {
            ForEach(Array(actions.enumerated()), id: \.element.id) { idx, a in
                if idx > 0 {
                    Rectangle().fill(Color.runeHairline).frame(width: hairlineWidth)
                }
                actionButton(a)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    private var stackedColumn: some View {
        VStack(spacing: 0) {
            ForEach(Array(actions.enumerated()), id: \.element.id) { idx, a in
                if idx > 0 {
                    Rectangle().fill(Color.runeHairline).frame(height: hairlineWidth)
                }
                actionButton(a)
            }
        }
        // Same `.fixedSize` as [sideBySideRow] (mirrors the pre-fix HStack's
        // own `.fixedSize(horizontal: false, vertical: true)`, git history) —
        // without it this VStack reports itself as vertically flexible, and
        // RuneCard's outer VStack then lets the WHOLE card (including the
        // ScrollView sibling above holding the title/message) stretch to fill
        // available height instead of hugging its content: a full-height card
        // with a huge empty gap above the buttons (device-verified 2026-09-29
        // regression, fixed same day). Stacking must never change the card's
        // height behavior, only the row's internal arrangement.
        .fixedSize(horizontal: false, vertical: true)
    }

    /// One action cell — `.frame(maxWidth: .infinity)` makes it an equal-width
    /// column in [sideBySideRow] and a full-width row in [stackedColumn]
    /// without needing separate modifiers per layout.
    private func actionButton(_ a: RuneDialogAction) -> some View {
        Button(action: a.action) {
            // ONE line, never a mid-word break (2026-09-11:
            // "Understood" rendered as "UNDERSTO / OD" on a half-width
            // button): shrink to fit instead. Android sibling: RuneDialog.kt's
            // action Text (autoSize).
            Text(a.label.uppercased())
                .font(.rune(maxFontSize, relativeTo: .headline))
                .kerning(1.5)
                .lineLimit(1)
                .minimumScaleFactor(minFontSize / maxFontSize)
                .allowsTightening(true)
                .foregroundColor(a.enabled ? a.color : a.color.opacity(0.4))
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 18)
                .padding(.horizontal, cellHorizontalPadding)
                .contentShape(Rectangle())
                .modifier(OptionalA11yId(id: a.labelA11yId))
        }
        .disabled(!a.enabled)
        .modifier(ButtonA11yId(id: a.a11yId, labelId: a.labelA11yId))
    }

    /// Decides the layout by measuring every label against [rowWidth] — see
    /// the "Deliberately NOT a GeometryReader" note above for why [rowWidth]
    /// is a deterministic computed property rather than a delayed read-back.
    private var fitsSideBySide: Bool {
        guard rowWidth > 0 else { return true }
        let n = actions.count
        guard n > 0 else { return true }
        let cellWidth = (rowWidth - hairlineWidth * CGFloat(n - 1)) / CGFloat(n)
        let availableTextWidth = max(0, cellWidth - cellHorizontalPadding * 2)
        let font = scaledFloorFont()
        return actions.allSatisfy { action in
            measuredWidth(of: action.label.uppercased(), font: font) <= availableTextWidth
        }
    }

    /// The floor size (14pt), scaled the same way `.rune(_, relativeTo: .headline)`
    /// scales with Dynamic Type, so the fit check matches what will actually render.
    private func scaledFloorFont() -> UIFont {
        let base = UIFont(name: "Metamorphous", size: minFontSize) ?? UIFont.systemFont(ofSize: minFontSize)
        let traits = UITraitCollection(preferredContentSizeCategory: UIContentSizeCategory(sizeCategory))
        let metrics = UIFontMetrics(forTextStyle: .headline)
        return metrics.scaledFont(for: base, compatibleWith: traits)
    }

    private func measuredWidth(of text: String, font: UIFont) -> CGFloat {
        (text as NSString).size(withAttributes: [.font: font, .kern: 1.5]).width
    }
}

private struct OptionalA11yId: ViewModifier {
    let id: String?
    func body(content: Content) -> some View {
        if let id { content.accessibilityIdentifier(id) } else { content }
    }
}

/// The action button's own OUTER identifier — upgraded to an a11y CONTAINER
/// (`accessibilityElement(children: .contain)`, same idiom as
/// [OptionalContainerA11yId] below) ONLY when [labelId] is non-nil. A plain
/// SwiftUI `Button` is otherwise always a single LEAF accessibility element
/// (empirically confirmed: XCUITest reports NO child for a Button's label,
/// unlike Android's Compose clickable, whose merged descendants still expose
/// a tagged child — see RuneDialog.kt's `contact_name_${id}` precedent), so
/// [RuneDialogAction.labelA11yId] is the opt-in that turns it into a
/// container whose label Text becomes separately queryable/measurable.
/// EVERY existing call site passes `labelId: nil` and takes the plain
/// [OptionalA11yId] branch — unchanged behavior.
private struct ButtonA11yId: ViewModifier {
    let id: String?
    let labelId: String?
    func body(content: Content) -> some View {
        if labelId != nil {
            content
                .accessibilityElement(children: .contain)
                .modifier(OptionalA11yId(id: id))
        } else {
            content.modifier(OptionalA11yId(id: id))
        }
    }
}

/// Container variant of [OptionalA11yId] for the dialog CARD. A bare
/// `.accessibilityIdentifier` on a card whose content is simple enough (no
/// title — just a message + action row) lets SwiftUI flatten the subtree into
/// one accessibility group, and the XCUITest snapshot then reports the CARD's
/// id on the message AND on every button — the buttons' own identifiers
/// (push_prompt_yes/_no was the discovering case) never surface, so e2e can't
/// tap them. `children: .contain` pins the card as a CONTAINER whose children
/// stay individually exposed. Titled dialogs already behaved (the title kept
/// the subtree complex enough) — this makes it explicit for all of them.
private struct OptionalContainerA11yId: ViewModifier {
    let id: String?
    func body(content: Content) -> some View {
        if let id {
            content
                .accessibilityElement(children: .contain)
                .accessibilityIdentifier(id)
        } else { content }
    }
}

/// Non-optional entry point for [OptionalContainerA11yId], usable from any
/// file (localization PHASE 0: iOS a11y-container gaps). Screens outside this
/// file that root a gate/screen in a ZStack/VStack whose content is simple
/// enough for SwiftUI to flatten the subtree (EulaView, the no-device-passcode
/// warning gate, ...) hit the exact same shadowing bug RuneDialogOverlay's card
/// already works around: a bare `.accessibilityIdentifier` on the container
/// makes XCUITest report the CONTAINER's id on every child too, so the
/// children's own ids never surface. `.containerA11yId(_:)` applies
/// `accessibilityElement(children: .contain)` + the identifier in one call,
/// reusing this same modifier — existing `.runeDialog`/`RuneDialogOverlay`
/// call sites are untouched.
extension View {
    func containerA11yId(_ id: String) -> some View {
        modifier(OptionalContainerA11yId(id: id))
    }
}

/// The full dialog overlay: near-black scrim + centered RuneCard. Drop into a
/// ZStack/.overlay for item-driven state, or use `.runeDialog(isPresented:)`.
/// `onScrimTap == nil` makes it a consent gate (no tap-outside dismissal).
struct RuneDialogOverlay: View {
    var title: String? = nil
    var message: String? = nil
    var a11yId: String? = nil
    // Optional a11y id for the MESSAGE text node itself, distinct from
    // [a11yId] (the whole card container). Nil at every existing call site
    // (unchanged behavior); the update nudge is the first caller to need one
    // — there is no separate title on that dialog, and geometry-review e2e
    // (update-nudge-layout.spec.ts) needs the message's own rendered rect.
    // Android sibling: RuneDialog.kt's `RuneDialog(messageTestTag:)`.
    var messageA11yId: String? = nil
    var onScrimTap: (() -> Void)? = nil
    var actions: [RuneDialogAction] = []

    // Bounded + scrollable, mirroring ConnectionLogPanel's cap. A
    // dialog message can embed a peer-supplied string (e.g. a group's
    // eclipse-warning message interpolates the inviter's claimed group name)
    // that is capped in CHARACTERS but not in rendered height — isolating it
    // only stops it reversing the sentence, not growing it — so without a
    // bound it could push a trailing safety clause, or the action row below,
    // out of the visible dialog. Android mirrors this in RuneDialog.kt's
    // RuneCardBody; the cap only engages once content actually exceeds it, so
    // an ordinary short dialog renders exactly as before.
    private var maxBodyHeight: CGFloat { UIScreen.main.bounds.height * 0.55 }

    var body: some View {
        ZStack {
            Color.black.opacity(0.8)
                .ignoresSafeArea()
                .onTapGesture { onScrimTap?() }
            RuneCard {
                ScrollView {
                    VStack(spacing: 14) {
                        if let title { RuneDialogTitle(title) }
                        if let message {
                            RuneDialogMessage(message)
                                .modifier(OptionalA11yId(id: messageA11yId))
                        }
                    }
                    .padding(.horizontal, 24)
                    .padding(.vertical, 26)
                    .frame(maxWidth: .infinity)
                }
                .frame(maxHeight: maxBodyHeight)
                // `.fixedSize(vertical: true)` (device-verified 2026-09-29 —
                // PRE-EXISTING, present on git HEAD before any RuneActionRow
                // change, reproduced on both iOS 18.6 and 26.5 simulators with
                // zero local edits, so unrelated to that fix): without it,
                // ScrollView is greedy — inside this full-screen ZStack it
                // accepts whatever height its ancestor offers and grows all
                // the way to `maxBodyHeight` regardless of how little the
                // title/message actually need, leaving a large empty gap
                // above the action row. `.fixedSize` makes it report its own
                // content's natural height instead (still clamped by
                // `.frame(maxHeight:)` when content is actually long) — this
                // is exactly the behavior the comment above already claims
                // ("the cap only engages once content actually exceeds it, so
                // an ordinary short dialog renders exactly as before").
                // Android's RuneCardBody (a plain Column, not a
                // greedy-by-default container) never had this failure mode.
                .fixedSize(horizontal: false, vertical: true)
                if !actions.isEmpty {
                    RuneActionRow(actions: actions)
                }
            }
            .padding(.horizontal, 32)
            .modifier(OptionalContainerA11yId(id: a11yId))
        }
    }
}

/// Bool-binding replacement for `.alert`: buttons dismiss automatically (set
/// the binding false) before running their action, matching alert semantics.
struct RuneDialogModifier: ViewModifier {
    @Binding var isPresented: Bool
    var title: String? = nil
    var message: String? = nil
    var a11yId: String? = nil
    var messageA11yId: String? = nil
    var dismissable = true
    var actions: [RuneDialogAction] = []

    func body(content: Content) -> some View {
        content.overlay {
            if isPresented {
                RuneDialogOverlay(
                    title: title,
                    message: message,
                    a11yId: a11yId,
                    messageA11yId: messageA11yId,
                    onScrimTap: dismissable ? { isPresented = false } : nil,
                    actions: actions.map { a in
                        RuneDialogAction(a.label, color: a.color, enabled: a.enabled,
                                         a11yId: a.a11yId, labelA11yId: a.labelA11yId) {
                            isPresented = false
                            a.action()
                        }
                    }
                )
            }
        }
    }
}

extension View {
    func runeDialog(isPresented: Binding<Bool>, title: String? = nil,
                    message: String? = nil, a11yId: String? = nil,
                    messageA11yId: String? = nil,
                    dismissable: Bool = true,
                    actions: [RuneDialogAction]) -> some View {
        modifier(RuneDialogModifier(isPresented: isPresented, title: title,
                                    message: message, a11yId: a11yId,
                                    messageA11yId: messageA11yId,
                                    dismissable: dismissable, actions: actions))
    }
}

// MARK: - Clipboard copy for sensitive values

/// The app's one clipboard discipline for anything sensitive (pairing code, move
/// handle, abuse report, debug log): `.localOnly` keeps the item off Universal
/// Clipboard / Handoff (no off-device sync), and `expiresAfter` is the backstop that
/// still drops it if the app is killed or suspended before the timed clear fires.
/// `clearAfter` (nil = no timed clear) empties the pasteboard only while OUR value is
/// still on it, so it never destroys something the user copied in the meantime.
/// Each call site keeps its own numbers. Main thread only (UIPasteboard).
enum SensitivePasteboard {
    static func copy(_ value: String, expiresAfter: TimeInterval, clearAfter: TimeInterval?) {
        UIPasteboard.general.setItems(
            [["public.utf8-plain-text": value]],
            options: [
                .localOnly: true,
                .expirationDate: Date().addingTimeInterval(expiresAfter),
            ]
        )
        guard let clearAfter else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + clearAfter) {
            if UIPasteboard.general.string == value {
                UIPasteboard.general.items = []
            }
        }
    }
}

// MARK: - Navigation bar chrome

extension View {
    /// The app's navigation-bar look: opaque run background + dark bar content.
    func runNavigationBarChrome() -> some View {
        self
            .toolbarBackground(Color.runBackground, for: .navigationBar)
            .toolbarColorScheme(.dark, for: .navigationBar)
    }
}

// MARK: - Message composer field

extension View {
    /// The shared look AND keyboard policy of both message composers (1:1 and group),
    /// so the anti-learning setting cannot drift between them.
    ///
    /// Autocorrection + autocapitalization OFF suppress inline correction UI only —
    /// they do NOT stop the system keyboard's QuickType engine from learning typed
    /// words into its on-device lexicon (which lives outside the app sandbox and
    /// survives an app wipe). `.password` is the recognized content type that actually
    /// excludes the field from learning (matches PassphraseField's SecureField
    /// treatment and Android's no-learning flag on the composer). iOS keeps it at
    /// EVERY tier: unlike Gboard, the iOS keyboard keeps its emoji key in this mode.
    /// The hint governs Apple's keyboard only; third-party keyboards are refused
    /// app-wide in AppDelegate (shouldAllowExtensionPointIdentifier).
    /// The call site keeps `.onSubmit` and `.accessibilityIdentifier`.
    func noLearningComposerStyle() -> some View {
        self
            .font(.runeBody)
            .foregroundColor(Color.runTextPrimary)
            .tint(Color.runAccent)
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(Color.runSurface)
            .clipShape(Capsule())
            .autocorrectionDisabled(true)
            .textInputAutocapitalization(.never)
            .textContentType(.password)
    }
}
