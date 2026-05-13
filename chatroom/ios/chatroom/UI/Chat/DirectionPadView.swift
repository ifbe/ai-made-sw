import SwiftUI

/// 3×3 方向键网格（对应 Android fragment_chat.xml 中的 GridLayout remoteGrid）
struct DirectionPadView: View {
    let onTap: (String) -> Void

    private let directions: [(String, String)] = [
        ("↖", "btnRemoteUpLeft"),
        ("↑", "btnRemoteUp"),
        ("↗", "btnRemoteUpRight"),
        ("←", "btnRemoteLeft"),
        ("◉", "btnRemoteCenter"),
        ("→", "btnRemoteRight"),
        ("↙", "btnRemoteDownLeft"),
        ("↓", "btnRemoteDown"),
        ("↘", "btnRemoteDownRight")
    ]

    var body: some View {
        VStack(spacing: 2) {
            ForEach(0..<3, id: \.self) { row in
                HStack(spacing: 2) {
                    ForEach(0..<3, id: \.self) { col in
                        let index = row * 3 + col
                        let (label, _) = directions[index]
                        RemoteButton(label: label) {
                            onTap(label)
                        }
                    }
                }
            }
        }
    }
}

/// 数字键盘 3×3（对应 Android numPadGrid）
struct NumPadView: View {
    let onTap: (String) -> Void

    private let numbers = ["1", "2", "3", "4", "5", "6", "7", "8", "9"]

    var body: some View {
        VStack(spacing: 2) {
            ForEach(0..<3, id: \.self) { row in
                HStack(spacing: 2) {
                    ForEach(0..<3, id: \.self) { col in
                        let index = row * 3 + col
                        let label = numbers[index]
                        RemoteButton(label: label, fontSize: 22, color: Color(hex: "#333333")) {
                            onTap(label)
                        }
                    }
                }
            }
        }
    }
}

/// 方向键按钮（对应 Android bg_remote_btn）
struct RemoteButton: View {
    let label: String
    var fontSize: CGFloat = 20
    var color: Color = Color(hex: "#2196F3")
    var bgColor: Color = Color(hex: "#2196F3")
    var isSolid: Bool = false
    var width: CGFloat = 48
    var height: CGFloat = 48
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.system(size: fontSize))
                .foregroundColor(isSolid ? .white : color)
                .frame(width: width, height: height)  // 固定尺寸
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(isSolid ? bgColor : Color.clear)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(isSolid ? Color.clear : color, lineWidth: 2)
                )
        }
    }
}