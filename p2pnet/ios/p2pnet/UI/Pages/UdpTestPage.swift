import SwiftUI

struct UdpTestPage: View {
    let page: Page
    @ObservedObject var viewModel: LoginViewModel

    private var targetUsername: String {
        if case .udpTest(let name, _, _, _, _, _, _) = page { return name }
        if case .videoCall(let name) = page { return name }
        if case .chat(let name) = page { return name }
        if case .wireGuard(let name, _, _, _, _) = page { return name }
        return ""
    }

    private var pageMyLocalIp: String {
        if case .udpTest(_, _, _, let ip, _, _, _) = page { return ip }
        return ""
    }

    private var pageMyLocalPort: Int {
        if case .udpTest(_, _, _, _, let port, _, _) = page { return port }
        return 0
    }

    private var pageMyIp: String {
        if case .udpTest(_, let ip, _, _, _, _, _) = page { return ip }
        return ""
    }

    private var pageMyPublicPort: Int {
        if case .udpTest(_, _, let port, _, _, _, _) = page { return port }
        return 0
    }

    private var pagePeerIp: String {
        if case .udpTest(_, _, _, _, _, let ip, _) = page { return ip }
        return ""
    }

    private var pagePeerPort: Int {
        if case .udpTest(_, _, _, _, _, _, let port) = page { return port }
        return 0
    }

    var body: some View {
        VStack(spacing: 8) {
            addressCard
            messageHistoryCard
        }
        .padding(.horizontal, 4)
        .padding(.vertical, 8)
    }

    private var addressCard: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("UDP - \(targetUsername)")
                .font(.title3)
                .fontWeight(.medium)

            Divider()

            Text("mylocaladdr  \(pageMyLocalIp):\(pageMyLocalPort)")
                .font(.system(size: 12, design: .monospaced))
            Text("mypublicaddr \(pageMyIp):\(pageMyPublicPort)")
                .font(.system(size: 12, design: .monospaced))
            Text("peerpublicaddr \(pagePeerIp):\(pagePeerPort)")
                .font(.system(size: 12, design: .monospaced))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color(.systemBackground))
        .cornerRadius(12)
        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
    }

    private var messageHistoryCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("消息历史")
                    .font(.subheadline)
                    .fontWeight(.medium)

                Spacer()

                if !viewModel.udpSockMessages.isEmpty {
                    Button("清空") {
                        viewModel.clearUdpSockMessages()
                    }
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
                }

                Button(action: {
                    let text = viewModel.udpSockMessages.joined(separator: "\n")
                    UIPasteboard.general.string = text
                    showingCopied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                        showingCopied = false
                    }
                }) {
                    Text("📋复制")
                        .font(.system(size: 10))
                }
                .foregroundColor(.secondary)

                if showingCopied {
                    Text("已复制")
                        .font(.system(size: 10))
                        .foregroundColor(.blue)
                }
            }

            Divider()

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(viewModel.udpSockMessages.enumerated()), id: \.offset) { _, msg in
                            Text(msg)
                                .font(.system(size: 7, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
        }
        .padding(12)
        .background(Color(.systemBackground))
        .cornerRadius(12)
        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
    }

    @State private var showingCopied = false
}
