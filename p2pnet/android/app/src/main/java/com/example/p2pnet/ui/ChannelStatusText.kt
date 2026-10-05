package com.example.p2pnet.ui

/**
 * 配置卡首行的状态文案 —— 两个**同风格的兄弟函数**，按页面的词汇用，别混用：
 *
 * - **vpn / proxy**：说的是"通道"（洞）→ 用 [channelStatusText]：空 `未接线` / 非空 `已接 N 条`；
 * - **switch**：说的是"网口"（插线）→ 用 [portStatusText]：空 `未插线` / 非空 `已插 N 个`。
 *
 * 为什么是两个函数而不是一个带"词汇"参数的函数：switch 页**同一页内**的用词是网口/插线
 * （拓扑卡里也是 `已插 N 个` / `未插线` / `点网口 = 拔线`），如果和 vpn/proxy 共用一套字符串，
 * 以后很容易被"顺手统一"成另一套，导致同页前后不一致。**两套词汇各自独立演进。**
 */

/** vpn / proxy：通道数文案（空 → `未接线`，非空 → `已接 N 条`） */
internal fun channelStatusText(count: Int): String =
    if (count <= 0) "未接线" else "已接 $count 条"

/** switch：网口数文案（空 → `未插线`，非空 → `已插 N 个`），与拓扑卡的用词保持一致 */
internal fun portStatusText(count: Int): String =
    if (count <= 0) "未插线" else "已插 $count 个"
