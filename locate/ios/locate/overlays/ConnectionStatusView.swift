import SwiftUI

/// 右上角连接状态图标
/// 对应 Android 的 ConnectionStatusView
struct ConnectionStatusView: View {
    let status: Int   // 0=连接中(橙), 1=已连接(绿), 2=断开(红)
    let onlineCount: Int

    var body: some View {
        ZStack {
            Circle()
                .fill(statusColor)
                .frame(width: 68, height: 68)

            Circle()
                .stroke(Color.white.opacity(0.6), lineWidth: 3)
                .frame(width: 68, height: 68)

            if status == 1 {
                // 绿色：纯色圆，仅表示已连接
            } else if status == 2 {
                // 红色：显示感叹号
                Text("!")
                    .font(.system(size: 38, weight: .bold))
                    .foregroundColor(.white)
            }
        }
    }

    private var statusColor: Color {
        switch status {
        case 0: return Color(red: 1.0, green: 0.596, blue: 0.0)        // 橙色
        case 1: return Color(red: 0.298, green: 0.686, blue: 0.314)   // 绿色
        default: return Color(red: 0.957, green: 0.263, blue: 0.212) // 红色
        }
    }
}