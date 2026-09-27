//
//  GameKind.swift
//  chess
//
//  对照 Android: game/share/protocol/GameKind.kt
//

import Foundation

/// 四种棋。id 是上线到报文里的稳定名字，不要随便改。
enum GameKind: String, CaseIterable, Codable {
    case xiangqi
    case intlChess = "intl_chess"
    case weiqi
    case wuziqi

    /// 报文里的棋种 id。
    var id: String { rawValue }

    static func fromId(_ id: String) -> GameKind? { GameKind(rawValue: id) }

    /// 界面上标签栏的文案（§5.5）。
    var label: String {
        switch self {
        case .xiangqi: return "象棋"
        case .intlChess: return "国际象棋"
        case .weiqi: return "围棋"
        case .wuziqi: return "五子棋"
        }
    }
}
