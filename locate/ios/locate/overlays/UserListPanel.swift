import SwiftUI
import CoreLocation

/// 右侧队友列表面板
/// 每行左侧点→飞到此人位置，右侧有靶心按钮→飞到此人目标
struct UserListPanel: View {
    let otherUsers: [User]
    /// 自己的账号名和本地 GPS 坐标
    let selfUsername: String
    let selfCoordinate: CLLocationCoordinate2D?
    let panelWidth: CGFloat
    var onSelectUser: (CLLocationCoordinate2D) -> Void
    var onSelectTarget: (CLLocationCoordinate2D) -> Void

    /// 点这一行该飞到哪。
    /// - 自己那一行用本地 GPS：服务器上那份可能还是登录时占位的 (0,0)，
    ///   或者被同账号的另一个客户端覆盖过
    /// - 还是 (0,0) 的人（从没上报过位置）不给飞，免得飞到几内亚湾
    private func flyTarget(for user: User) -> CLLocationCoordinate2D? {
        if user.username == selfUsername, let selfCoord = selfCoordinate {
            return selfCoord
        }
        guard !(user.lat == 0 && user.lng == 0) else { return nil }
        return CLLocationCoordinate2D(latitude: user.lat, longitude: user.lng)
    }

    var body: some View {
        VStack(spacing: 0) {
            Text("同服人数：\(otherUsers.count)")
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(.secondary)
                .padding(.vertical, 5)

            Divider()

            VStack(spacing: 5) {
                ForEach(otherUsers, id: \.username) { user in
                    UserListRow(
                        name: user.nickname ?? user.username,
                        color: colorFor(username: user.username),
                        hasTarget: user.targetLat != nil,
                        onTapUser: {
                            if let coord = flyTarget(for: user) {
                                onSelectUser(coord)
                            }
                        },
                        onTapTarget: {
                            guard let tlat = user.targetLat,
                                  let tlng = user.targetLng,
                                  !(tlat == 0 && tlng == 0) else { return }
                            onSelectTarget(CLLocationCoordinate2D(latitude: tlat, longitude: tlng))
                        }
                    )
                }
            }
            .padding(.vertical, 5)
        }
        // 高度交给内容自己撑（原来按行数硬算，字号一改就会被裁）
        .frame(width: panelWidth)
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

            // 右侧：靶心按钮 → 飞到此人目标。
            // 做成实心色块：有目标时橙底白靶心，没目标时灰底灰靶心，一眼能分清
            Button(action: onTapTarget) {
                Image(systemName: "target")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(hasTarget ? .white : Color(.systemGray))
                    .frame(width: 30, height: 22)
                    .background(hasTarget ? Color.orange : Color(.systemGray5))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(hasTarget ? Color.orange : Color(.systemGray4), lineWidth: 1)
                    )
                    .shadow(color: .black.opacity(hasTarget ? 0.25 : 0), radius: 1, x: 0, y: 1)
            }
            .buttonStyle(.plain)
            .disabled(!hasTarget)
            .padding(.leading, 6)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(Color(.systemGray6).opacity(0.6))
        .cornerRadius(8)
    }
}

/// 左上角本地设置面板
/// 标题行最右边是「退出登录」，下面两行是「我的位置」和「我的目标」
struct LocalSettingsPanel: View {
    let localPosition: CLLocationCoordinate2D?
    let hasTarget: Bool
    var onTapMyLocation: () -> Void
    var onTapMyTarget: () -> Void
    var onTapLogout: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            // 标题行：左边「本地」，同一行最右边「退出登录」
            HStack(spacing: 6) {
                Text("本地")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(.secondary)
                Spacer(minLength: 0)
                Button(action: onTapLogout) {
                    Text("退出登录")
                        .font(.system(size: 12))
                        .foregroundColor(Color(red: 0.898, green: 0.224, blue: 0.208))
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 5)

            Divider()

            VStack(spacing: 5) {
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
                    .padding(.vertical, 5)
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
                    .padding(.vertical, 5)
                    .background(Color(.systemGray6).opacity(0.6))
                    .cornerRadius(8)
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
        }
        .background(Color(.systemBackground).opacity(0.95))
        .cornerRadius(10)
        .shadow(color: .black.opacity(0.15), radius: 8, x: 0, y: 2)
    }
}