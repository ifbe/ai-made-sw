import SwiftUI

/// 目标设置按钮（连接图标下方）
/// 对应 Android 的 TargetButtonView
struct TargetButtonView: View {
    let hasTarget: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(hasTarget ? "已设目标，点我取消" : "未设目标，点我设置")
                .font(.system(size: 14))
                .foregroundColor(.white)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(hasTarget ? Color.orange : Color.blue.opacity(0.8))
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.white.opacity(0.6), lineWidth: 1)
                )
        }
    }
}