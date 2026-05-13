import SwiftUI

/// ANSI/VT100 SGR 样式
struct Vt100Style: Equatable {
    var fgColor: Color = .black
    var bgColor: Color = .clear
    var bold: Bool = false
    var underline: Bool = false
    var reverse: Bool = false
}
