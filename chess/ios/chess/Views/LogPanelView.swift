//
//  LogPanelView.swift
//  chess
//
//  右下角可折叠日志框（对照 design.md §4.6）。
//  默认折叠成一个「日志」小按钮，点一下展开成 280 × 170 的面板，按钮文案变「收起」。
//

import SwiftUI

struct LogPanelView: View {

    @State private var expanded = false
    @State private var lines: [String] = []
    @State private var listenerID: UUID?

    var body: some View {
        VStack(alignment: .trailing, spacing: Theme.logToggleGap) {
            if expanded {
                panel
            }

            Button {
                toggle()
            } label: {
                Text(expanded ? Theme.Text.logHide : Theme.Text.logButton)
                    .tabButton()
            }
            .buttonStyle(.plain)
        }
        .onAppear {
            lines = AppLog.snapshot()
            // 监听回调可能在网络线程，界面自己切主线程
            listenerID = AppLog.addListener { newLines in
                DispatchQueue.main.async {
                    lines = newLines
                }
            }
        }
        .onDisappear {
            if let listenerID {
                AppLog.removeListener(listenerID)
            }
            listenerID = nil
        }
    }

    private var panel: some View {
        ScrollViewReader { proxy in
            ScrollView(.vertical) {
                Text(lines.joined(separator: "\n"))
                    .font(.system(size: Theme.logFontSize, design: .monospaced))
                    .foregroundColor(Theme.logText)
                    .lineSpacing(Theme.logLineSpacing)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .id(Self.bottomID)
            }
            // 8pt 内边距 + 280 × 170 总尺寸（内边距在框内，和 Android 的 ScrollView 一致）
            .padding(Theme.logPanelPadding)
            .frame(width: Theme.logPanelWidth, height: Theme.logPanelHeight)
            .background(
                RoundedRectangle(cornerRadius: Theme.logPanelCornerRadius)
                    .fill(Theme.logPanelBackground)
            )
            .overlay(
                RoundedRectangle(cornerRadius: Theme.logPanelCornerRadius)
                    .strokeBorder(Theme.logPanelBorder, lineWidth: 1)
                    // 描边 Shape 的命中区是整个矩形，不关掉会挡住日志的滚动 / 选中复制。
                    .allowsHitTesting(false)
            )
            .onChange(of: lines) { _ in
                // 每次追加后自动滚到底
                proxy.scrollTo(Self.bottomID, anchor: .bottom)
            }
        }
    }

    private static let bottomID = "log-bottom"

    private func toggle() {
        expanded.toggle()
        if expanded {
            lines = AppLog.snapshot()
        }
    }
}
