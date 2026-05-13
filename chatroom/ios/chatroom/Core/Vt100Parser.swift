import SwiftUI

/// ANSI/VT100 SGR escape sequence 解析器
enum Vt100Parser {

    // MARK: - Color Map

    private static let ansiFg: [Int: Color] = [
        30: .black,
        31: Color(hex: "#D32F2F"),
        32: Color(hex: "#388E3C"),
        33: Color(hex: "#F57C00"),
        34: Color(hex: "#1565C0"),
        35: Color(hex: "#7B1FA2"),
        36: Color(hex: "#00838F"),
        37: .white,
        39: .black  // default
    ]

    private static let ansiBg: [Int: Color] = [
        40: .black,
        41: Color(hex: "#D32F2F"),
        42: Color(hex: "#388E3C"),
        43: Color(hex: "#F57C00"),
        44: Color(hex: "#1565C0"),
        45: Color(hex: "#7B1FA2"),
        46: Color(hex: "#00838F"),
        47: .white,
        49: .clear
    ]

    // MARK: - Public

    /// 解析完整字符串，返回 (纯文本, 样式列表，每段一个样式)
    static func parse(_ text: String) -> [(String, Vt100Style)] {
        var result: [(String, Vt100Style)] = []
        var currentStyle = Vt100Style()
        var buffer = StringBuilder()

        var i = text.startIndex
        while i < text.endIndex {
            let c = text[i]
            if c == "\u{001B}" && text.index(after: i) < text.endIndex && text[text.index(after: i)] == "[" {
                // 保存当前 buffer
                if !buffer.isEmpty {
                    result.append((buffer.string, currentStyle))
                    buffer.clear()
                }

                // 找到 CSI 序列，找到非字母数字结束
                var j = text.index(after: text.index(after: i))
                while j < text.endIndex && !text[j].isLetter {
                    j = text.index(after: j)
                }
                let seqStart = text.index(after: text.index(after: i))
                let seqEnd = j
                let seq = String(text[seqStart..<seqEnd])
                currentStyle = applySGR(seq, currentStyle)
                i = text.index(after: j)
            } else {
                buffer.append(c)
                i = text.index(after: i)
            }
        }

        if !buffer.isEmpty {
            result.append((buffer.string, currentStyle))
        }

        return result
    }

    // MARK: - AttributedString

    /// 将 VT100 样式文本转为 AttributedString
    /// iOS 15 兼容版本（不依赖 iOS 16+ API）
    static func attributedString(from text: String) -> AttributedString {
        let segments = parse(text)
        var result = AttributedString()

        for (segmentText, style) in segments {
            var attr = AttributedString(segmentText)
            if style.bold {
                // iOS 15 不支持在 AttributedString 上直接设 bold，
                // 用 Text 加在 SwiftUI 层处理
            }
            if style.underline {
                attr.underlineStyle = .single
            }
            if style.fgColor != .black {
                if let fg = ansiFg.first(where: { $0.value == style.fgColor })?.key {
                    // 通过 foregroundColor 关键字设颜色
                    attr.foregroundColor = style.fgColor
                } else {
                    attr.foregroundColor = style.fgColor
                }
            }
            if style.bgColor != .clear {
                attr.backgroundColor = style.bgColor
            }
            result.append(attr)
        }

        if result.characters.isEmpty {
            result = AttributedString(text)
        }
        return result
    }

    // MARK: - Private

    private static func applySGR(_ params: String, _ style: Vt100Style) -> Vt100Style {
        if params.isEmpty || params == "0" { return Vt100Style() }

        var s = style
        let codes = params.split(separator: ";").compactMap { Int($0) }

        for code in codes {
            switch code {
            case 0: s = Vt100Style()
            case 1: s.bold = true
            case 4: s.underline = true
            case 7: s.reverse = true
            default:
                if ansiFg[code] != nil {
                    s.fgColor = ansiFg[code]!
                } else if ansiBg[code] != nil {
                    s.bgColor = ansiBg[code]!
                }
            }
        }

        return s
    }
}

// MARK: - StringBuilder helper

private struct StringBuilder {
    private(set) var string: String = ""

    mutating func append(_ c: Character) {
        string.append(c)
    }

    mutating func clear() {
        string = ""
    }

    var isEmpty: Bool { string.isEmpty }
}

// MARK: - Color hex extension

extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let r, g, b: UInt64
        switch hex.count {
        case 6:
            (r, g, b) = ((int >> 16) & 0xFF, (int >> 8) & 0xFF, int & 0xFF)
        default:
            (r, g, b) = (0, 0, 0)
        }
        self.init(
            .sRGB,
            red: Double(r) / 255,
            green: Double(g) / 255,
            blue: Double(b) / 255,
            opacity: 1
        )
    }
}
