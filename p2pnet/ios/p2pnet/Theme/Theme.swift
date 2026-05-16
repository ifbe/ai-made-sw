import SwiftUI

// MARK: - Color + Hex init

extension Color {
    init(hex: UInt) {
        self.init(
            red: Double((hex >> 16) & 0xFF) / 255.0,
            green: Double((hex >> 8) & 0xFF) / 255.0,
            blue: Double(hex & 0xFF) / 255.0
        )
    }
}

// MARK: - App Colors (matches Android Material 3)

enum AppColors {
    static let purple80 = Color(hex: 0xD0BCFF)
    static let purpleGrey80 = Color(hex: 0xCCC2DC)
    static let pink80 = Color(hex: 0xEFB8C8)
    static let purple40 = Color(hex: 0x6650a4)
    static let purpleGrey40 = Color(hex: 0x625b71)
    static let pink40 = Color(hex: 0x7D5260)
}

// MARK: - MaterialColorScheme

struct MaterialColorScheme {
    let primary: Color
    let onPrimary: Color
    let primaryContainer: Color
    let onPrimaryContainer: Color
    let secondary: Color
    let onSecondary: Color
    let secondaryContainer: Color
    let onSecondaryContainer: Color
    let tertiary: Color
    let onTertiary: Color
    let tertiaryContainer: Color
    let onTertiaryContainer: Color
    let surface: Color
    let onSurface: Color
    let surfaceVariant: Color
    let onSurfaceVariant: Color
    let background: Color
    let onBackground: Color
    let error: Color
    let onError: Color
    let outline: Color

    static let light = MaterialColorScheme(
        primary: AppColors.purple40,
        onPrimary: .white,
        primaryContainer: Color(hex: 0xEADDFF),
        onPrimaryContainer: Color(hex: 0x21005D),
        secondary: AppColors.purpleGrey40,
        onSecondary: .white,
        secondaryContainer: Color(hex: 0xE8DEF8),
        onSecondaryContainer: Color(hex: 0x1D192B),
        tertiary: AppColors.pink40,
        onTertiary: .white,
        tertiaryContainer: Color(hex: 0xFFD8E4),
        onTertiaryContainer: Color(hex: 0x31111D),
        surface: Color(hex: 0xFFFFFBFE),
        onSurface: Color(hex: 0xFF1C1B1F),
        surfaceVariant: Color(hex: 0xFFE7E0EC),
        onSurfaceVariant: Color(hex: 0xFF49454F),
        background: Color(hex: 0xFFFFFBFE),
        onBackground: Color(hex: 0xFF1C1B1F),
        error: Color(hex: 0xFFB3261E),
        onError: .white,
        outline: Color(hex: 0xFF79747E)
    )

    static let dark = MaterialColorScheme(
        primary: AppColors.purple80,
        onPrimary: Color(hex: 0x381E72),
        primaryContainer: Color(hex: 0x4F378B),
        onPrimaryContainer: Color(hex: 0xEADDFF),
        secondary: AppColors.purpleGrey80,
        onSecondary: Color(hex: 0x332D41),
        secondaryContainer: Color(hex: 0x4A4458),
        onSecondaryContainer: Color(hex: 0xE8DEF8),
        tertiary: AppColors.pink80,
        onTertiary: Color(hex: 0x492532),
        tertiaryContainer: Color(hex: 0x633B48),
        onTertiaryContainer: Color(hex: 0xFFD8E4),
        surface: Color(hex: 0xFF1C1B1F),
        onSurface: Color(hex: 0xFFE6E1E5),
        surfaceVariant: Color(hex: 0xFF49454F),
        onSurfaceVariant: Color(hex: 0xFFCAC4D0),
        background: Color(hex: 0xFF1C1B1F),
        onBackground: Color(hex: 0xFFE6E1E5),
        error: Color(hex: 0xFFF2B8B5),
        onError: Color(hex: 0xFF601410),
        outline: Color(hex: 0xFF938F99)
    )
}

// MARK: - Environment Key

private struct MaterialColorSchemeKey: EnvironmentKey {
    static let defaultValue: MaterialColorScheme = .light
}

extension EnvironmentValues {
    var material: MaterialColorScheme {
        get { self[MaterialColorSchemeKey.self] }
        set { self[MaterialColorSchemeKey.self] = newValue }
    }
}

// MARK: - P2pnetTheme Modifier

struct P2pnetThemeModifier: ViewModifier {
    @Environment(\.colorScheme) var scheme
    func body(content: Content) -> some View {
        content
            .environment(\.material, scheme == .dark ? MaterialColorScheme.dark : MaterialColorScheme.light)
    }
}

extension View {
    func p2pnetTheme() -> some View {
        modifier(P2pnetThemeModifier())
    }
}