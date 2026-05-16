import SwiftUI

enum AppFont {
    static func bodyLarge() -> Font { .body }
    static func titleLarge() -> Font { .title }
    static func titleMedium() -> Font { .title2 }
    static func titleSmall() -> Font { .subheadline }
    static func labelMedium() -> Font { .footnote }
    static func labelSmall() -> Font { .caption }
    static func monospaced(_ size: CGFloat) -> Font { .system(size: size, design: .monospaced) }
}