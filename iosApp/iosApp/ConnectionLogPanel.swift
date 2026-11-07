import SwiftUI
import UIKit
import shared

// ---------------------------------------------------------------------------
// ConnectionLogPanel — the inline, live connection log (iOS).
//
// Triple-tapping the "Connecting to…" caption on the contact list expands this
// panel; tapping the panel (or triple-tapping the caption again) collapses it.
// Unlike LogViewerView it ships in RELEASE builds: a user stuck on
// "Connecting…" can read out exactly which phase is failing.
//
// Content comes from `ConnectionLog` (commonMain). Its producers emit fixed
// phrases + numbers only, and `ConnectionLog.redact()` is the belt-and-braces
// net — no inbox ids, no capabilities, no onion hosts, no message content, no
// contact names.
//
// Why polling and not the Kotlin StateFlow: a `StateFlow` does not cross the
// ObjC bridge without a collector shim, so the panel reads the coroutine-free
// `ConnectionLog.shared.snapshotFormatted()` on a 1 Hz timer — the same
// `Timer.publish` cadence ContactListView already uses for the Tor percent.
// The timer only runs while the panel is expanded.
//
// Android sibling: androidApp/src/main/java/com/vg/run/ConnectionLogPanel.kt
// (same accessibility ids `connect_log_panel` / `connect_log_line`, same 40 %
// -of-screen cap). The Copy button (`connect_log_copy`) is iOS-only for now.
// ---------------------------------------------------------------------------

struct ConnectionLogPanel: View {

    /// Collapsed renders nothing, so the caller can place it unconditionally.
    let expanded: Bool

    @State private var lines: [String] = []

    /// ~40 % of the screen: tall enough to read the last dozen phases, short
    /// enough that the caption and the Add-contact button stay visible.
    private var maxHeight: CGFloat { UIScreen.main.bounds.height * 0.4 }

    var body: some View {
        if expanded {
            VStack(alignment: .leading, spacing: 4) {
                // The title is English-only for now; `/l10n` folds
                // `connect_log_title` into L10n.swift with the other locales.
                HStack {
                    Text(NSLocalizedString("connect_log_title", value: "Connection log", comment: ""))
                        .font(.runeCaption2)
                        .foregroundColor(Color.runTextSecondary)
                    Spacer()
                    // Explicit copy, never system text selection: a plain selection
                    // copy lands on UIPasteboard.general with Universal Clipboard and
                    // no expiry. This goes through SensitivePasteboard (local-only,
                    // 60 s OS expiry + in-process clear) and copies RELATIVE times
                    // only — no wall-clock stamp leaves the panel.
                    Button(L10n.commonCopy) {
                        SensitivePasteboard.copy(
                            ConnectionLogPanel.copyableText(lines),
                            expiresAfter: 60,
                            clearAfter: 60
                        )
                    }
                    .font(.runeCaption2)
                    .foregroundColor(Color.runTextSecondary)
                    .disabled(lines.isEmpty)
                    .accessibilityIdentifier("connect_log_copy")
                }

                ScrollViewReader { proxy in
                    ScrollView {
                        VStack(alignment: .leading, spacing: 1) {
                            ForEach(Array(lines.enumerated()), id: \.offset) { idx, line in
                                Text(line)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(Color.runTextPrimary)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id(idx)
                                    .accessibilityIdentifier("connect_log_line")
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: maxHeight)
                    // Newest line at the bottom, always.
                    .onChange(of: lines.count) { count in
                        guard count > 0 else { return }
                        proxy.scrollTo(count - 1, anchor: .bottom)
                    }
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.runBackground)
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .accessibilityIdentifier("connect_log_panel")
            .onAppear { lines = ConnectionLog.shared.snapshotFormatted() }
            .onReceive(Timer.publish(every: 1, on: .main, in: .common).autoconnect()) { _ in
                lines = ConnectionLog.shared.snapshotFormatted()
            }
        }
    }

    /// The copied form of the panel: each line's leading `HH:mm:ss.SSS` UTC
    /// time-of-day (ConnectionLog's `formatClock`) is replaced by the offset from
    /// the FIRST line, `+SSSSS.mmm` — the same relative shape the debug upload
    /// uses (DebugMode toRelativeTime). A line without a parsable stamp is
    /// copied as is. Pure, so it is safe to call from the button closure.
    static func copyableText(_ lines: [String]) -> String {
        var origin: Int?
        var out: [String] = []
        out.reserveCapacity(lines.count)
        for line in lines {
            guard let parsed = splitClock(line) else {
                out.append(line)
                continue
            }
            let (msOfDay, rest) = parsed
            let base = origin ?? msOfDay
            origin = base
            var delta = msOfDay - base
            if delta < 0 { delta += 86_400_000 }   // the log crossed UTC midnight
            out.append(String(format: "+%05ld.%03ld", delta / 1000, delta % 1000) + rest)
        }
        return out.joined(separator: "\n")
    }

    /// `HH:mm:ss.SSS…` → (milliseconds of day, the remainder after the stamp).
    private static func splitClock(_ line: String) -> (Int, Substring)? {
        let chars = Array(line.utf8.prefix(12))
        guard chars.count == 12, chars[2] == UInt8(ascii: ":"), chars[5] == UInt8(ascii: ":"),
              chars[8] == UInt8(ascii: ".") else { return nil }
        func num(_ r: Range<Int>) -> Int? {
            var v = 0
            for i in r {
                let c = chars[i]
                guard c >= UInt8(ascii: "0"), c <= UInt8(ascii: "9") else { return nil }
                v = v * 10 + Int(c - UInt8(ascii: "0"))
            }
            return v
        }
        guard let h = num(0..<2), let m = num(3..<5), let s = num(6..<8), let ms = num(9..<12) else { return nil }
        let rest = line.dropFirst(12)
        return (((h * 60 + m) * 60 + s) * 1000 + ms, rest)
    }
}

extension View {
    /// Three taps toggles the connection-log panel. Attach to the
    /// "Connecting to…" caption. SwiftUI owns the inter-tap window here, which
    /// is why there is no Swift sibling of Android's `TripleTapDetector`.
    ///
    /// Deliberately adds no accessibility traits or label: the caption keeps
    /// its existing identity (`tor_progress_caption`), which the e2e suite
    /// keys on.
    func tripleTapToggle(_ onToggle: @escaping () -> Void) -> some View {
        self.onTapGesture(count: 3, perform: onToggle)
    }
}
