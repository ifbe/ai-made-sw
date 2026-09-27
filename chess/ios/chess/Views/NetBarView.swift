//
//  NetBarView.swift
//  chess
//
//  左下角联机条 `[服/客][地址][开始/状态]`（对照 design.md §4.5）。
//

import SwiftUI

enum NetMode {
    case server
    case client
}

struct NetBarView: View {

    let mode: NetMode
    let address: Binding<String>
    let hint: String
    let actionTitle: String
    let onToggleMode: () -> Void
    let onAction: () -> Void

    var body: some View {
        HStack(spacing: 0) {
            // 模式按钮：连着呢不准切（由调用方判断）
            Button(action: onToggleMode) {
                Text(mode == .server ? Theme.Text.netModeServer : Theme.Text.netModeClient)
                    .tabButton()
            }
            .buttonStyle(.plain)
            .padding(.trailing, Theme.netSpacing)

            addressField

            Button(action: onAction) {
                Text(actionTitle)
                    .tabButton()
            }
            .buttonStyle(.plain)
            .padding(.leading, Theme.netSpacing)
        }
    }

    /// 地址框：宽 130pt、`bg_tab` 样式、单行、URI 键盘、占位色 #80FFFFFF。
    private var addressField: some View {
        ZStack(alignment: .leading) {
            if address.wrappedValue.isEmpty {
                Text(hint)
                    .font(.system(size: Theme.addressFontSize))
                    .foregroundColor(Theme.placeholder)
                    .padding(.horizontal, Theme.addressPaddingH)
                    .padding(.vertical, Theme.addressPaddingV)
                    .allowsHitTesting(false)
            }

            TextField("", text: address)
                .textFieldStyle(.plain)
                .font(.system(size: Theme.addressFontSize))
                .foregroundColor(Theme.tabText)
                .keyboardType(.URL)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .padding(.horizontal, Theme.addressPaddingH)
                .padding(.vertical, Theme.addressPaddingV)
        }
        .frame(width: Theme.addressWidth)
        .background(
            RoundedRectangle(cornerRadius: Theme.tabCornerRadius)
                .fill(Theme.tabBackground)
        )
        .overlay(
            RoundedRectangle(cornerRadius: Theme.tabCornerRadius)
                .strokeBorder(Theme.tabBorder, lineWidth: 1)
                // ★ 必须关掉命中测试：描边 Shape 的命中区是整个矩形，否则它会盖在
                //   上面的 TextField 之上，点地址框时收不到触摸、弹不出键盘。
                .allowsHitTesting(false)
        )
    }
}
