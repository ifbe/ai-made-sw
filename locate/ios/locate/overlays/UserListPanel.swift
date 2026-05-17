import SwiftUI
import CoreLocation

/// 右侧队友列表面板
/// 每行左侧点→飞到此人位置，右侧有🎯→飞到此人目标
struct UserListPanel: View {
    let otherUsers: [User]
    let panelWidth: CGFloat
    var onSelectUser: (CLLocationCoordinate2D) -> Void
    var onSelectTarget: (CLLocationCoordinate2D) -> Void

    // 动态高度：标题 + 分隔线 + 用户行
    private var panelHeight: CGFloat {
        let rowHeight: CGFloat = 36
        let titleHeight: CGFloat = 30
        let contentHeight = CGFloat(otherUsers.count) * rowHeight
        return titleHeight + contentHeight + 16
    }

    var body: some View {
        VStack(spacing: 0) {
            Text("同服人数：\(otherUsers.count)")
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(.secondary)
                .padding(.vertical, 6)

            Divider()

            VStack(spacing: 16) {
                ForEach(otherUsers, id: \.username) { user in
                    UserListRow(
                        name: user.nickname ?? user.username,
                        color: colorFor(username: user.username),
                        hasTarget: user.targetLat != nil,
                        onTapUser: {
                            onSelectUser(CLLocationCoordinate2D(latitude: user.lat, longitude: user.lng))
                        },
                        onTapTarget: {
                            if let tlat = user.targetLat, let tlng = user.targetLng {
                                onSelectTarget(CLLocationCoordinate2D(latitude: tlat, longitude: tlng))
                            }
                        }
                    )
                }
            }
            .padding(.vertical, 6)
        }
        .frame(width: panelWidth, height: panelHeight)
        .background(Color(.systemBackground).opacity(0.95))
        .cornerRadius(10)
        .shadow(color: .black.opacity(0.15), radius: 8, x: 0, y: 2)
    }

    private func colorFor(username: String) -> Color {
        let colors: [Color] = [
            Color(red: 0.0, green: 0.6, blue: 1.0),
            Color(red: 0.6, green: 0.0, blue: 1.0),
            Color(red: 0.0, green: 0.8, blue: 0.6),
            Color(red: 1.0, green: 0.4, blue: 0.6),
            Color(red: 0.4, green: 0.8, blue: 1.0),
            Color(red: 1.0, green: 0.6, blue: 0.2),
            Color(red: 0.8, green: 0.4, blue: 0.0),
            Color(red: 0.6, green: 0.6, blue: 0.6),
        ]
        return colors[abs(username.hashValue) % colors.count]
    }
}

struct UserListRow: View {
    let name: String
    let color: Color
    let hasTarget: Bool
    let onTapUser: () -> Void
    let onTapTarget: () -> Void

    var body: some View {
        HStack(spacing: 0) {
            // 左侧：名字 → 飞到此人位置
            Button(action: onTapUser) {
                HStack(spacing: 6) {
                    Circle()
                        .fill(color)
                        .frame(width: 10, height: 10)
                    Text(name)
                        .font(.system(size: 13))
                        .foregroundColor(.primary)
                        .lineLimit(1)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .buttonStyle(.plain)

            // 右侧：🎯 → 飞到此人目标
            Button(action: onTapTarget) {
                Image(systemName: "target")
                    .font(.system(size: 12))
                    .foregroundColor(hasTarget ? .orange : .gray.opacity(0.4))
                    .frame(width: 24)
            }
            .buttonStyle(.plain)
            .disabled(!hasTarget)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(Color(.systemGray6).opacity(0.6))
        .cornerRadius(8)
    }
}

/// 左上角本地设置面板
struct LocalSettingsPanel: View {
    let localPosition: CLLocationCoordinate2D?
    let hasTarget: Bool
    var onTapMyLocation: () -> Void
    var onTapMyTarget: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            Text("本地")
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(.secondary)
                .padding(.vertical, 6)

            Divider()

            VStack(spacing: 16) {
                // 我的位置
                Button(action: onTapMyLocation) {
                    HStack {
                        Image(systemName: "location.fill")
                            .font(.system(size: 10))
                            .foregroundColor(Color(red: 1.0, green: 0.8, blue: 0.0))
                        Text("我的位置")
                            .font(.system(size: 11))
                            .foregroundColor(.primary)
                        Spacer()
                    }
                    .padding(.vertical, 6)
                    .background(Color(.systemGray6).opacity(0.6))
                    .cornerRadius(8)
                }
                .buttonStyle(.plain)

                // 我的目标
                Button(action: onTapMyTarget) {
                    HStack {
                        Image(systemName: hasTarget ? "target" : "scope")
                            .font(.system(size: 10))
                            .foregroundColor(hasTarget ? .orange : .blue)
                        Text(hasTarget ? "取消目标" : "设目标")
                            .font(.system(size: 11))
                            .foregroundColor(hasTarget ? .orange : .blue)
                        Spacer()
                    }
                    .padding(.vertical, 6)
                    .background(Color(.systemGray6).opacity(0.6))
                    .cornerRadius(8)
                }
                .buttonStyle(.plain)
            }
            .padding(.vertical, 6)
        }
        .padding(.horizontal, 10)
        .background(Color(.systemBackground).opacity(0.95))
        .cornerRadius(10)
        .shadow(color: .black.opacity(0.15), radius: 8, x: 0, y: 2)
    }
}