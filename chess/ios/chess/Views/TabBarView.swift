//
//  TabBarView.swift
//  chess
//
//  左上角四个页面标签（对照 design.md §4.3）。顺序固定：象棋 / 国际象棋 / 围棋 / 五子棋。
//

import SwiftUI

struct TabBarView: View {

    let selected: GameKind
    let onSelect: (GameKind) -> Void

    var body: some View {
        HStack(spacing: Theme.tabSpacing) {
            ForEach(GameKind.allCases, id: \.self) { kind in
                Button {
                    onSelect(kind)
                } label: {
                    Text(kind.label)
                        .modifier(TabButtonModifier(active: kind == selected))
                }
                .buttonStyle(.plain)
            }
        }
    }
}
