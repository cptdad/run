import SwiftUI
import shared

// ---------------------------------------------------------------------------
// LogViewerView — in-app log viewer for debugging.
//
// Shows the shared LogBuffer contents in a scrollable list with
// copy-to-clipboard support. Opened by a hidden 5-tap gesture (within 3 s) on
// the contact-list bottom-left stone (ContactListView), not a PIN-gated tab.
//
// TEMPORARY: remove when beta testing is complete.
// ---------------------------------------------------------------------------

struct LogViewerView: View {
    @State private var logs: [LogEntry] = []
    @State private var filter: String = ""
    @State private var copied = false

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()

                VStack(spacing: 0) {
                    // Filter bar
                    HStack {
                        Image(systemName: "magnifyingglass")
                            .foregroundColor(.gray)
                        TextField("Filter logs...", text: $filter)
                            .foregroundColor(.white)
                            .autocorrectionDisabled(true)
                            .textInputAutocapitalization(.never)
                    }
                    .padding(8)
                    .background(Color(white: 0.15))
                    .cornerRadius(8)
                    .padding(.horizontal, 12)
                    .padding(.top, 8)

                    // Log list
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 2) {
                                ForEach(Array(filteredLogs.enumerated()), id: \.offset) { idx, entry in
                                    Text(entry.formatted())
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundColor(colorForLevel(entry.level))
                                        .id(idx)
                                }
                            }
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                        }
                        .onChange(of: logs.count) { _ in
                            if let last = filteredLogs.indices.last {
                                proxy.scrollTo(last, anchor: .bottom)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Logs")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(Color.black, for: .navigationBar)
            .toolbarColorScheme(.dark, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Text("\(filteredLogs.count) entries")
                        .font(.runeCaption)
                        .foregroundColor(.gray)
                }
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    Button {
                        // Keep buffered metadata off Universal Clipboard /
                        // Handoff; auto-expire after 60 s. No timed clear here
                        // (unchanged behaviour; DEBUG-only screen).
                        SensitivePasteboard.copy(LogBuffer.shared.asText(), expiresAfter: 60, clearAfter: nil)
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false }
                    } label: {
                        Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    }
                    .foregroundColor(copied ? .green : .white)

                    Button {
                        LogBuffer.shared.clear()
                        logs = []
                    } label: {
                        Image(systemName: "trash")
                    }
                    .foregroundColor(.red)
                }
            }
            .onAppear { logs = LogBuffer.shared.getAll() }
        }
    }

    private var filteredLogs: [LogEntry] {
        if filter.isEmpty { return logs }
        let f = filter.lowercased()
        return logs.filter {
            $0.tag.lowercased().contains(f) || $0.message.lowercased().contains(f)
        }
    }

    private func colorForLevel(_ level: String) -> Color {
        switch level {
        case "E": return .red
        case "W": return .yellow
        default:  return Color(white: 0.7)
        }
    }
}
