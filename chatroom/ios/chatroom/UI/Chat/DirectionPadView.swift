import SwiftUI

/// 遥控模式左 / 右边 3×3 网格（iOS 端镜像 Android `inputBarRemote` 的 `remoteGrid` + `numPadGrid`）。
///
/// 大小策略（与 Android 对齐）：父容器是 HStack 的 weight=1 部分；
/// 3×3 网格在父容器内**居中**，每个 cell 是 `min(parentW, parentH) / 3` 的正方形。
/// 父容器变大/变小，整个 3×3 跟着等比缩放。
///
/// 之前是固定 48×48 cell 排成 3×3——父容器大了右边空白，父容器小了被裁切。

/// 遥控模式左边 9 宫格：q/w/e/a/s/d/z/x/c（PC WASD 左手位）
struct DirectionPadView: View {
    let onTap: (String) -> Void

    /// 与 Android `btnRemoteUpLeft` 等 ID 对齐，便于排查
    private let directions: [(String, String)] = [
        ("q", "btnRemoteUpLeft"),
        ("w", "btnRemoteUp"),
        ("e", "btnRemoteUpRight"),
        ("a", "btnRemoteLeft"),
        ("s", "btnRemoteCenter"),
        ("d", "btnRemoteRight"),
        ("z", "btnRemoteDownLeft"),
        ("x", "btnRemoteDown"),
        ("c", "btnRemoteDownRight")
    ]

    var body: some View {
        FlexibleGrid3x3(
            labels: directions.map { $0.0 },
            textColor: Color(hex: "#2196F3"),
            onTap: onTap
        )
    }
}

/// 遥控模式右边数字键盘 3×3：1-9
struct NumPadView: View {
    let onTap: (String) -> Void

    private let numbers = ["1", "2", "3", "4", "5", "6", "7", "8", "9"]

    var body: some View {
        FlexibleGrid3x3(
            labels: numbers,
            textColor: Color(hex: "#333333"),
            onTap: onTap
        )
    }
}

// MARK: - FlexibleGrid3x3 共享控件

/// 撑满父容器的 3×3 正方形网格。
/// - 父容器大小任意；网格在父容器内**居中**
/// - cell 边长 = `min(parentW, parentH) / 3`，cells 永远是正方形
/// - 字体大小按 cell 边长自动算（cell 的 50%）
///
/// `DirectionPadView` / `NumPadView` 都用这个；`ArrowPadView`（dim3 模式）
/// 因为外面有 +/- 按钮所以 inline 写、不复用这个，但同款 cell 边长算法。
struct FlexibleGrid3x3: View {
    /// 长度 9，从上到下、从左到右
    let labels: [String]
    /// 文字+描边颜色（数字键盘用深色，方向键用蓝）
    var textColor: Color = Color(hex: "#2196F3")
    let onTap: (String) -> Void

    private let spacing: CGFloat = 2

    var body: some View {
        GeometryReader { geo in
            let side = min(geo.size.width, geo.size.height) / 3
            VStack(spacing: spacing) {
                ForEach(0..<3, id: \.self) { row in
                    HStack(spacing: spacing) {
                        ForEach(0..<3, id: \.self) { col in
                            let index = row * 3 + col
                            RemoteButton(
                                label: labels[index],
                                fontSize: side * 0.5,
                                color: textColor
                            ) {
                                onTap(labels[index])
                            }
                            .frame(width: side, height: side)
                        }
                    }
                }
            }
            .frame(width: side * 3 + spacing * 2, height: side * 3 + spacing * 2)
            .position(x: geo.size.width / 2, y: geo.size.height / 2)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - 键帽样式

/// 通用 3×3 网格里的 cell 样式。**不再有默认固定尺寸**——尺寸由外层 `.frame(...)` 决定。
struct RemoteButton: View {
    let label: String
    var fontSize: CGFloat = 20
    var color: Color = Color(hex: "#2196F3")
    var bgColor: Color = Color(hex: "#2196F3")
    var isSolid: Bool = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.system(size: fontSize))
                .foregroundColor(isSolid ? .white : color)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(isSolid ? bgColor : Color.clear)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(isSolid ? Color.clear : color, lineWidth: 2)
                )
        }
        .buttonStyle(.plain)
    }
}