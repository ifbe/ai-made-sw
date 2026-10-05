#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
p2pnet 桌面端 —— Phase 1：自定义标题栏外壳（先做效果）

==========================================================================================
这个文件做什么
==========================================================================================
一个无边框窗口 + Chrome 式单行标题栏（左侧 6 个 tab，右侧三个窗口按钮）
+ 6 个页面 + 右下角日志浮层 + 操作系统托盘常驻 + 单实例，**全部深色**。

引擎部分：**进程内导入 `client.py` 并调用它的函数**（`EngineBridge`）——
不开 `client.py` 子进程（用户明确要求）。`client.py` 是单线程 select 循环写的，
所以所有调用都串行化到一条"引擎线程"，GUI 只往队列投命令；日志靠重定向 `sys.stdout`
（tee）汇入面板，**不改 client.py**。5 个配置页仍是界面骨架（Phase 3 接各自的用法）。

"用法"程序（`app/vpn.py` / `app/switch.py` 等）本来就是独立程序，仍由 `client.py`
自己按原样后台拉起，不属于本文件的范围。

界面形态、tab 顺序与文案，一律对齐手机端：
  - 安卓：android/app/src/main/java/com/example/p2pnet/ui/
  - iOS ：ios/p2pnet/
其中 tab 顺序固定为：主页 / media / proxy / wireguard / vpn / switch（小写，都不可关闭）。

==========================================================================================
许可与可移植性（重要）
==========================================================================================
本机装的是 **PyQt6（GPL-3.0）**，所以本文件：
  - 只用 **PyQt6 与 PySide6 都有** 的 API；
  - 枚举一律写 fully-scoped（如 Qt.WindowType.FramelessWindowHint），两边都对；
  - 信号用 pyqtSignal / pyqtSlot。

**换成 LGPL 的 PySide6 时只需要改两处**：
  1) 所有 `from PyQt6.* import ...` → `from PySide6.* import ...`
  2) `pyqtSignal` → `Signal`，`pyqtSlot` → `Slot`
（将来要发闭源二进制时再切，见仓库根目录的讨论。）

==========================================================================================
怎么验证（本机不许弹真窗口）
==========================================================================================
    python3 -m py_compile client/client-gui.py
    QT_QPA_PLATFORM=offscreen python3 client/client-gui.py --self-test

`--self-test` 除了打印布局摘要，还会断言：导入的是 `client` 模块（不是脚本）、
本文件里**一处起子进程的调用都没有**（严格到连那个词的字面量都不许出现，断言会自己扫源文件）、
桩 socket 下发 `list` / `udp bob` 得到的 JSON 正确、`client.log()` 能汇入面板、
以及深色 palette/样式表真的接上了。全程不联网、不弹窗。

`--self-test` 会构建完整界面（含各页、日志浮层、托盘判定），**不进入事件循环**、
不显示窗口，打印一段布局摘要后 exit(0)。托盘在 offscreen 下 isSystemTrayAvailable()
返回 False，这正好覆盖"托盘不可用 → ✕ 真退出"的降级路径。
"""

from __future__ import annotations

import json
import os
import queue
import random
import re
import select
import socket
import sys
import threading
import time
from dataclasses import dataclass

from PyQt6.QtCore import (
    QEasingCurve,
    QTimer,
    QEvent,
    QPointF,
    QObject,
    QPoint,
    QRect,
    Qt,
    QVariantAnimation,
    pyqtSignal,
    pyqtSlot,
)
from PyQt6.QtGui import (
    QAction,
    QColor,
    QPalette,
    QFont,
    QFontDatabase,
    QIcon,
    QMouseEvent,
    QPainter,
    QPen,
    QPixmap,
    QResizeEvent,
)
from PyQt6.QtNetwork import QLocalServer, QLocalSocket
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QAbstractButton,
    QCheckBox,
    QComboBox,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QSystemTrayIcon,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QSizePolicy,
)

# ==========================================================================================
# 1. 常量与配色（**全黑暗色**：窗口与卡片都是黑，靠"高亮描边"区分层次）
# ==========================================================================================

APP_NAME = "p2pnet"
IS_MAC = sys.platform == "darwin"
IS_WINDOWS = sys.platform.startswith("win")

TITLE_BAR_H = 38          # 标题栏高度（Chrome 大约 40，这里略紧一点更省纵向空间）
RESIZE_MARGIN = 5         # 边缘缩放热区（题目要求 4~6px）
LOG_PANEL_RATIO = 0.9     # 日志面板 = 内容区的 90%（与手机端一致）
LOG_BTN_W, LOG_BTN_H = 76, 32
LOG_ANIM_MS = 260         # 与手机端 260ms 对齐


# 6 个固定 tab：顺序与标题必须和手机端一致（小写、都不可关闭）
TABS = [
    ("main", "主页"),
    ("media", "media"),
    ("proxy", "proxy"),
    ("wireguard", "wireguard"),
    ("vpn", "vpn"),
    ("switch", "switch"),
]

# 打洞步骤行（hole/core.py 的输出格式）：
#   [12:00:00][client] [洞 #1 bob] [2/6] 正在等服务器要求发给 udp  （✓）127.0.0.1:10000
_STEP_LINE_RE = re.compile(r"\[洞 #(\d+)[^\]]*\]\s*\[(\d+)/(\d+)\][^\n]*?（([✓✗])）")
# direct 的可达地址行（hole/direct.py）：[direct] bob 可达地址: 1.2.3.4, 5.6.7.8
_DIRECT_NOTE_RE = re.compile(r"\[direct\]\s+(\S+)\s+可达地址:\s*(.+)$")

# 连接状态（驱动托盘图标颜色 + tooltip + 日志浮层标题旁的状态）
STATE_UNCONNECTED = "unconnected"
STATE_CONNECTING = "connecting"
STATE_LOGGED_IN = "logged_in"
STATE_TEXT = {
    STATE_UNCONNECTED: "未连接",
    STATE_CONNECTING: "连接中",
    STATE_LOGGED_IN: "已登录",
}
STATE_COLOR = {
    STATE_UNCONNECTED: "#9AA0A6",   # 灰
    STATE_CONNECTING: "#FBBC04",    # 黄
    STATE_LOGGED_IN: "#34A853",     # 绿
}

# ── 深色配色（集中在这里，方便以后调）────────────────────────────────────────────────
# 设计：**窗口和卡片都是黑的**，靠"边缘亮"来区分层次（不再跟系统浅色调色板走 —— 那正是
# 之前"窗口黑、控件白"两套配色打架、看不清的根因）。配合 apply_dark_theme() 用 Fusion
# 风格 + 深色 QPalette，三个平台的渲染就完全一致了。

C_WINDOW = "#000000"          # 窗口 / 内容区底色：纯黑
C_CARD = "#0a0a0a"            # 卡片填充：也是黑（比窗口极轻微提亮一点，避免和背景糊在一起）

# 卡片/控件的"高亮描边"。默认用亮蓝（用户要的"边缘亮"那版）；
# 觉得每条蓝边太吵的话，把下面这行换成 C_BORDER_DIM 即可（低调版）。
C_BORDER_ACCENT = "#4a9eff"   # ← 高亮版（默认）
C_BORDER_DIM = "#4a4a4a"      # ← 低调版（想换就改 CardBorder 这一行）
BORDER_CARD = C_BORDER_ACCENT

C_TEXT = "#e6e6e6"            # 主文字
C_TEXT_DIM = "#8a8a8a"        # 次要文字 / 说明
C_PLACEHOLDER = "#6a6a6a"     # 输入框占位符
C_WARN = "#e0b341"            # 提示/注意（暗黄，白底上的红字在暗色下不可读）
C_DISABLED_TEXT = "#5a5a5a"   # 禁用态文字
C_DISABLED_BG = "#3a3a3a"      # 禁用态的开关轨道（比 C_BORDER 更暗、比正常蓝更灰）
C_PRESSED = "#161616"         # 按钮按下时的填充
C_HOVER_BG = "#141414"        # 悬停时的填充（很淡，主要靠描边变亮）

C_TITLE_BG = "#0a0a0a"        # 标题栏底色
C_BORDER = "#2a2a2a"          # 标题栏/分隔线的暗描边（不抢卡片的亮边）
C_TAB_OFF = "#9a9a9a"         # tab 未选中
C_TAB_HOVER = "#d0d0d0"       # tab 悬停
C_TAB_ON = "#ffffff"          # tab 选中

# macOS 左上角三颗原生习惯的红黄绿（用户要求保留：它不属于"卡片"，不进深色改写）
C_MAC_CLOSE = "#FF5F57"
C_MAC_MIN = "#FEBC2E"
C_MAC_MAX = "#28C840"

# 兼容旧名字（内部还有引用，统一指向新的深色值）
C_BG = C_WINDOW
C_CARD_BG = C_CARD
C_ACCENT = C_BORDER_ACCENT
C_HOVER = C_HOVER_BG

UI_FONT_FAMILIES = [
    "PingFang SC",            # macOS 中文
    "Microsoft YaHei UI",     # Windows 中文
    "Noto Sans CJK SC",       # Linux 中文
    "Helvetica Neue",
    "Sans Serif",
]
UI_FONT_SIZE = 12
MONO_FONT_FAMILIES = ["SF Mono", "Menlo", "Consolas", "DejaVu Sans Mono", "Monospace"]


def apply_dark_theme(app: QApplication) -> QPalette:
    """
    统一深色主题：**Fusion 风格 + 自设深色 QPalette**。

    为什么必须显式设 palette：光靠 QSS 刷黑，控件内部（下拉弹层、滚动条、提示框、
    选中高亮…）仍会拿系统浅色调色板去画，就出现"窗口黑、控件白"的两套配色。
    Fusion 是 Qt 自带的、三平台渲染一致的风格，配深色 palette 后不会再跟系统主题走。
    """
    app.setStyle("Fusion")
    pal = QPalette()
    black = QColor(C_WINDOW)
    card = QColor(C_CARD)
    text = QColor(C_TEXT)
    dim = QColor(C_DISABLED_TEXT)

    pal.setColor(QPalette.ColorRole.Window, black)
    pal.setColor(QPalette.ColorRole.WindowText, text)
    pal.setColor(QPalette.ColorRole.Base, card)
    pal.setColor(QPalette.ColorRole.AlternateBase, black)
    pal.setColor(QPalette.ColorRole.ToolTipBase, card)
    pal.setColor(QPalette.ColorRole.ToolTipText, text)
    pal.setColor(QPalette.ColorRole.Text, text)
    pal.setColor(QPalette.ColorRole.Button, black)
    pal.setColor(QPalette.ColorRole.ButtonText, text)
    pal.setColor(QPalette.ColorRole.BrightText, QColor("#ff5555"))
    pal.setColor(QPalette.ColorRole.Link, QColor(C_BORDER_ACCENT))
    pal.setColor(QPalette.ColorRole.Highlight, QColor(C_BORDER_ACCENT))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor("#000000"))
    pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(C_PLACEHOLDER))

    # 禁用态：别让它退回系统浅灰
    for role in (QPalette.ColorRole.WindowText, QPalette.ColorRole.Text,
                 QPalette.ColorRole.ButtonText):
        pal.setColor(QPalette.ColorGroup.Disabled, role, dim)
    for role in (QPalette.ColorRole.Base, QPalette.ColorRole.Button,
                 QPalette.ColorRole.Window):
        pal.setColor(QPalette.ColorGroup.Disabled, role, card if role != QPalette.ColorRole.Window else black)

    app.setPalette(pal)
    return pal


def make_font(size: int = UI_FONT_SIZE, mono: bool = False, bold: bool = False) -> QFont:
    """
    按平台给一套中文字体候选，并**先用 QFontDatabase 过滤掉本机没装的**：
    直接把不存在的 family 交给 Qt，它会花几百毫秒去找别名（offscreen 下实测 265ms），
    过滤后既没警告也更快。全都不可用时就退回 Qt 默认字体。
    """
    f = QFont()
    candidates = MONO_FONT_FAMILIES if mono else UI_FONT_FAMILIES
    if QApplication.instance() is not None:
        installed = set(QFontDatabase.families())
        usable = [name for name in candidates if name in installed]
        if usable:
            f.setFamilies(usable)
    else:
        f.setFamilies(candidates)
    f.setPointSize(size)
    f.setBold(bold)
    return f


# ==========================================================================================
# 2. 小工具：状态点图标（代码画，不新增 png 文件）、卡片/表单辅助
# ==========================================================================================

def make_state_icon(state: str, size: int = 64) -> QIcon:
    """
    用代码画一个"状态点"托盘图标（题目要求：别新增 png 文件）。

    TODO(macOS)：macOS 菜单栏更规范的做法是**单色 template 图**（自动适配浅色/深色主题），
    这里为了"一眼看出状态"先用彩色圆点；真发版时再按平台出 template 版本。
    """
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    color = QColor(STATE_COLOR.get(state, STATE_COLOR[STATE_UNCONNECTED]))
    margin = size * 0.14
    # 外圈：半透明同色，做出"呼吸"的观感
    halo = QColor(color)
    halo.setAlpha(70)
    p.setBrush(halo)
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(QRect(0, 0, size, size))

    # 内圆：实心状态点
    p.setBrush(color)
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(
        QRect(int(margin), int(margin), int(size - 2 * margin), int(size - 2 * margin))
    )
    p.end()
    return QIcon(pm)


def card(parent: QWidget, title: str) -> tuple[QFrame, QVBoxLayout]:
    """通用卡片：标题 + 竖排内容。返回 (卡片, 内容布局)。"""
    frame = QFrame(parent)
    frame.setObjectName("card")
    outer = QVBoxLayout(frame)
    outer.setContentsMargins(12, 10, 12, 12)
    outer.setSpacing(6)

    if title:                      # 空标题 = 不渲染标题行（标题文字由卡片首行承担）
        lab = QLabel(title, frame)
        lab.setObjectName("cardTitle")
        outer.addWidget(lab)

    body = QVBoxLayout()
    body.setContentsMargins(0, 0, 0, 0)
    body.setSpacing(2)          # 行与行几乎贴住（用户要求"没有间距或很小"）
    outer.addLayout(body)
    return frame, body


def row_fixed(row: QWidget) -> QWidget:
    """
    行容器一律**不许纵向长高**。

    为什么：行容器是裸 QWidget，默认纵向策略是 Preferred —— 父布局（卡片的 body）**没有尾部弹簧**时
    Qt 会把"卡片多余的高度"平均摊给每一行：窗口 1080×720 时每行被拉到 107px、1400 高时 243px，
    视觉上就是"每一行间隔特别大"（用户实机报的 bug）。设成 Fixed 后行高永远 = `sizeHint().height()`。
    （和 `card_head_row` 里固定 CARD_HEAD_H 是同一类问题的两处防线。）
    """
    row.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
    return row


class ToggleSwitch(QAbstractButton):
    """
    小开关（自绘：圆角轨道 + 圆钮），纯 PyQt6 绘制、**不引新依赖**。

    为什么不用 `QCheckBox`：勾选框在深色卡片上只是一个小方块，看不出"开 / 关"；
    用户要求"这一行文字右边要有个开关"，用来显隐「嵌入 DHCP 服务器」整张卡。
    """

    TRACK_H = 20      # 轨道只有 20px 高；控件本身跟字段控件同高（28），轨道垂直居中

    def __init__(self, parent: QWidget | None = None, *, w: int = 38, h: int = 28):
        super().__init__(parent)
        self.setCheckable(True)
        self.setFixedSize(w, h)          # 与 field_row 里 QLineEdit 的 setFixedHeight(28) 对齐 → 行高一致
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)

    def paintEvent(self, event) -> None:      # noqa: N802 (Qt 命名)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        on = self.isChecked()
        enabled = self.isEnabled()                           # 禁用态要看得出来（否则"看着正常却点不动"）
        th = min(self.TRACK_H, self.height())
        y0 = (self.height() - th) // 2       # 轨道在控件里垂直居中（整数：drawRoundedRect 没有 int+float 重载）
        r = th / 2
        p.setPen(Qt.PenStyle.NoPen)
        if not enabled:
            track = C_DISABLED_BG if on else C_BORDER
        else:
            track = C_ACCENT if on else C_BORDER              # 开 = 高亮蓝，关 = 暗描边色
        p.setBrush(QColor(track))
        p.drawRoundedRect(0, y0, self.width(), th, r, r)
        d = th - 4
        p.setBrush(QColor(C_DISABLED_TEXT if not enabled else "#ffffff"))   # 圆钮
        p.drawEllipse(self.width() - d - 2 if on else 2, y0 + 2, d, d)


def field_row(
    parent: QWidget,
    label: str,
    widget: QWidget | None = None,
    *,
    label_w: int = 84,
    hint: str = "",
    enabled: bool = False,
) -> tuple[QWidget, QWidget | None, QLineEdit | None]:
    """
    一行「标签 + 控件」。widget=None 时自动给一个占位 QLineEdit（Phase 1 全是示意，默认 disabled）。
    返回 (行容器, 控件, 若控件是 QLineEdit 则一并返回)。
    """
    row = row_fixed(QWidget(parent))
    h = QHBoxLayout(row)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(6)

    lab = QLabel(label, row)
    lab.setObjectName("fieldLabel")
    lab.setFixedWidth(label_w)
    h.addWidget(lab)

    if widget is None:
        widget = QLineEdit(row)
        widget.setPlaceholderText(hint)
        widget.setFixedHeight(28)
    widget.setEnabled(enabled)
    h.addWidget(widget, 1)
    return row, widget, (widget if isinstance(widget, QLineEdit) else None)


def choice_buttons(parent: QWidget, ids: list[str], current: str | None = None) -> tuple[QWidget, QButtonGroup]:
    """一排二选一/多选一的按钮（对应手机端的 ChoiceRow）。Phase 1 只是示意，点了只记日志。"""
    box = row_fixed(QWidget(parent))
    h = QHBoxLayout(box)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(4)
    grp = QButtonGroup(box)
    grp.setExclusive(True)
    for i, one in enumerate(ids):
        b = QPushButton(one, box)
        b.setObjectName("choice")
        b.setCheckable(True)
        b.setFixedHeight(26)
        b.setChecked(one == (current or ids[0]))
        h.addWidget(b)
        grp.addButton(b, i)
    h.addStretch(1)
    return box, grp


CARD_HEAD_H = 26      # 卡片首行的标准高度（= 启停按钮高度），两行必须等高


def ports_state_text(n: int) -> str:
    """switch 页首行状态的统一文案（与同页「拓扑」卡用词一致）：0 = `未插线`，非空 = `已插 N 个`。

    口径（三端统一）：**vpn/proxy 看通道数**（`channels_state_text`），**switch 看网口数**（本函数）。
    """
    return "未插线" if not n else f"已插 {n} 个"


def channels_state_text(n: int) -> str:
    """通道状态的统一文案（三端一致）：空 = `未接线`，非空 = `已接 N 条`。

    vpn / proxy 页的首行状态都用它（switch 页的状态是"已插 N 个"，是另一个指标）。
    """
    return "未接线" if not n else f"已接 {n} 条"


def card_head_row(parent: QWidget, text: str,
                  state_widget: QWidget | None = None,
                  control: QWidget | None = None,
                  label_object: str = "cardTitle",
                  label_fixed_w: int = 0) -> QWidget:
    """
    卡片首行的**唯一**构造入口（卡片标题也走这里，所以卡片不再画标题行）。

    左边文字 + 弹簧 + 可选状态 + 可选控件，右侧全部顶到同一个右边界。
    `setContentsMargins(0,0,0,0)`：任何一侧都不许多出 margin/indent ——
    这是"配置卡首行和 DHCP 卡首行必须等宽"那条要求的落点（self-test 里真量像素断言）。
    """
    row = row_fixed(QWidget(parent))
    h = QHBoxLayout(row)
    h.setContentsMargins(0, 0, 0, 0)
    h.setSpacing(6)
    lab = QLabel(text, row)
    # 默认按"卡片标题"样式（首行承担标题时用）；开关行那种"跟字段标签一样"的行传 label_object="fieldLabel"
    lab.setObjectName(label_object)
    if label_fixed_w:
        lab.setFixedWidth(label_fixed_w)
    h.addWidget(lab)
    h.addStretch(1)
    if state_widget is not None:
        h.addWidget(state_widget)
    if control is not None:
        h.addWidget(control)

    # 高度统一固定成 CARD_HEAD_H（= 启停按钮高度）：
    #   · 不固定的话，**父布局会把"卡片多余的高度"摊给这一行** —— DHCP 卡内容少、卡片被纵向拉伸时
    #     首行涨到 38/69px，而配置卡首行只有 26px（用户报的"嵌入 dhcp 服务器那一行高度特别高"）；
    #   · 也**不能**用 `sizeHint()` 现算：构造这一刻 QSS/字体还没生效（offscreen 下是 fallback 字体），
    #     带按钮的那行会算出 27、只有文字的那行算出 26 —— 两行又不等高了（这个坑我真踩了一次）。
    # 两行都用同一个常量，必然等高；下面 self-test 还会断言"文字塞得下"（防大字号被裁）。
    row.setFixedHeight(CARD_HEAD_H)
    return row


def section_note(parent: QWidget, text: str) -> QLabel:
    """小字说明（手机端那些 9sp 的灰字说明）。"""
    lab = QLabel(text, parent)
    lab.setObjectName("note")
    lab.setWordWrap(True)
    return lab


# ==========================================================================================
# 3. 标题栏：左侧 6 个 tab，右侧三个窗口按钮（macOS 分叉见 IS_MAC）
# ==========================================================================================

class WindowButton(QPushButton):
    """自绘窗口按钮：Windows/Linux 用符号，macOS 用圆形红黄绿。"""

    def __init__(self, kind: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.kind = kind  # "min" / "max" / "close"
        self.setObjectName("winBtn")
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        if IS_MAC:
            # macOS：12px 圆点，颜色照系统（红黄绿），放在左边
            self.setText("")
            self.setFixedSize(12, 12)
            self.setToolTip({"min": "最小化", "max": "缩放", "close": "关闭"}[kind])
            color = {"min": C_MAC_MIN, "max": C_MAC_MAX, "close": C_MAC_CLOSE}[kind]
            # 顺序按 macOS 习惯：关闭在最左，这里用圆点顺序由调用方决定
            self.setStyleSheet(
                f"QPushButton#winBtn {{ background: {color}; border: none; border-radius: 6px; }}"
                f"QPushButton#winBtn:hover {{ background: {color}; }}"
            )
        else:
            self.setText({"min": "—", "max": "▢", "close": "✕"}[kind])
            self.setFixedSize(46, TITLE_BAR_H - 8)
            self.setToolTip({"min": "最小化", "max": "最大化/还原", "close": "关闭"}[kind])


class TitleBar(QWidget):
    """
    Chrome 式单行标题栏。

    布局分叉（这是 Phase 1 唯一需要"拍板"的地方，理由见报告）：
      - macOS：**没有 pyobjc 可用**（不能装），Qt 自己也拿不到
        `NSWindow.titlebarAppearsTransparent` / `fullSizeContentView`，所以做不到
        "把 tab 画进原生标题栏还保留原生红黄绿"。最终选择：仍然 Frameless + 自绘，
        但按 macOS 习惯把三个**圆形**按钮放**左侧**（红黄绿顺序），tab 紧随其后。
      - Windows/Linux：自绘 `— ▢ ✕` 放右侧，tab 在左（和 Chrome 一致）。

    拖动：空白区域按下 → `windowHandle().startSystemMove()`（交给系统，手感才对）。
    点 tab 或窗口按钮**不会**触发拖动：子控件自己会吃掉按下事件，这里再兜一层 childAt 判断。
    """

    tab_clicked = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("titleBar")
        # QWidget 子类的 QSS 背景默认不画 → 不设这个属性，标题栏就是透明的（会透出别的程序）
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedHeight(TITLE_BAR_H)
        self.setMouseTracking(True)
        self._press_pos: QPoint | None = None

        h = QHBoxLayout(self)
        h.setContentsMargins(8, 0, 8, 0)
        h.setSpacing(2)

        # ── 窗口按钮 ──
        self.btn_min = WindowButton("min", self)
        self.btn_max = WindowButton("max", self)
        self.btn_close = WindowButton("close", self)

        # ── 6 个 tab ──
        self.tab_group = QButtonGroup(self)
        self.tab_group.setExclusive(True)
        self.tab_buttons: list[QPushButton] = []
        for i, (_key, title) in enumerate(TABS):
            b = QPushButton(title, self)
            b.setObjectName("tab")
            b.setCheckable(True)
            b.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            b.setFixedHeight(28)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setChecked(i == 0)
            self.tab_group.addButton(b, i)
            self.tab_buttons.append(b)
        self.tab_group.idClicked.connect(self.tab_clicked.emit)

        if IS_MAC:
            # macOS 习惯：左 = 红黄绿（关闭在最左），右 = 空
            h.addWidget(self.btn_close)
            h.addWidget(self.btn_min)
            h.addWidget(self.btn_max)
            h.addSpacing(10)
            for b in self.tab_buttons:
                h.addWidget(b)
            h.addStretch(1)
        else:
            for b in self.tab_buttons:
                h.addWidget(b)
            h.addStretch(1)          # 中间是拖动区
            h.addWidget(self.btn_min)
            h.addWidget(self.btn_max)
            h.addWidget(self.btn_close)

        self.setStyleSheet(self._stylesheet())

    def _stylesheet(self) -> str:
        mac_tab_extra = "padding: 0 12px;" if IS_MAC else "padding: 0 14px;"
        # 只有 Windows 才指定符号字体（其它平台写不存在的 family 会让 Qt 白扫一遍字体别名）
        win_font = 'font-family: "Segoe UI Symbol";' if IS_WINDOWS else ""
        return f"""
        QWidget#titleBar {{ background: {C_TITLE_BG}; border-bottom: 1px solid {C_BORDER}; }}
        QPushButton#tab {{
            background: transparent; border: none; border-bottom: 2px solid transparent;
            color: {C_TAB_OFF}; {mac_tab_extra}
        }}
        QPushButton#tab:hover {{ background: transparent; color: {C_TAB_HOVER}; }}
        QPushButton#tab:checked {{
            background: transparent; color: {C_TAB_ON}; border-bottom: 2px solid {C_BORDER_ACCENT};
        }}
        QPushButton#winBtn {{
            background: transparent; border: none; color: {C_TEXT};
            {win_font}
        }}
        QPushButton#winBtn:hover {{ background: {C_HOVER_BG}; }}
        """

    # ── 拖动 / 双击最大化 ──

    def mousePressEvent(self, e) -> None:  # noqa: N802 (Qt 命名)
        if e.button() != Qt.MouseButton.LeftButton:
            return super().mousePressEvent(e)
        # 点在子控件（tab / 按钮）上时交给子控件，不拖窗口
        if self.childAt(e.position().toPoint()) is not None:
            return super().mousePressEvent(e)
        self._press_pos = e.position().toPoint()
        win = self.window().windowHandle()
        if win is not None:
            win.startSystemMove()     # 交给系统做移动，手感/贴边/跨屏才对
        super().mousePressEvent(e)

    def mouseDoubleClickEvent(self, e) -> None:  # noqa: N802
        # 双击标题栏空白 = 最大化 / 还原（和 Chrome、各系统一致）
        if self.childAt(e.position().toPoint()) is None:
            self.window().toggle_maximize()
        super().mouseDoubleClickEvent(e)


# ==========================================================================================
# 4. 六个页面（主页要有服务器卡 + 自由层占位；5 个配置页做卡片骨架）
# ==========================================================================================

class Page(QWidget):
    """页面基类：统一背景 + 可滚（配置页内容比窗口高时要能滚）。"""

    def __init__(self, host: "MainWindow", parent: QWidget | None = None):
        super().__init__(parent)
        self.host = host
        self.kind = "page"

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.scroll = QScrollArea(self)
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(self.scroll)

        inner = QWidget()
        inner.setObjectName("pageBody")
        inner.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setObjectName("page")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.scroll.viewport().setObjectName("pageViewport")
        self.scroll.viewport().setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.scroll.setWidget(inner)
        self.body = QVBoxLayout(inner)
        self.body.setContentsMargins(12, 12, 12, 12)
        self.body.setSpacing(10)

    def card_titles(self) -> list[str]:
        """子类覆盖：self-test 里打印各页有哪些卡片骨架。"""
        return []


# ==========================================================================================
# 4a. 主页 —— 逐块对齐安卓 MainPage.kt（服务器卡 + 自由层：我卡 / 其他人卡 / socket 卡 / 连线）
#
# 对齐来源：android/.../ui/login/MainPage.kt
#   ConnectionCard 204-286 / MeCard 290-410 / CompactField 414-520 /
#   FreeLayer 524-809 / UdpSocketCardView 812-941 / PeerNode 1013-1058 / dragHandle 1083-1092
# 安卓取 dp，桌面取逻辑像素，按 **1dp ≈ 1 逻辑像素** 处理。
# ==========================================================================================

# ── 常量（安卓 MainPage.kt 68-104，数值逐一对应）──
PEER_NODE_W = 220.0          # 只作为"量到真实宽度之前"的估算值
PEER_NODE_H = 58.0           # 其他人卡片高度固定
PEER_ACTION_H = 32.0         # 那一排 direct/upnp/udp/tcp 按钮的高度
PEER_ACTION_W = 44.0         # 单个按钮宽度（比均分窄）
PEER_TITLE_CENTER_Y = 10.0   # 「名字(ip:port)」那一行中心距卡顶（连线连到这里）
ME_CARD_MARGIN = 0.0         # 「我」卡片：默认**竖直居中**；这个 margin 同时是拖动时与自由层上下边的留白
SERVER_CARD_MARGIN_X = 4.0   # 服务器卡片左右留白（竖屏满宽时左右各 4）
SERVER_CARD_MARGIN_TOP = 8.0 # 服务器卡片距自由层顶边（沿用原来 wrap_row 的 8px 上边距）
SERVER_CARD_GAP = 12.0       # 其它卡片与服务器卡片之间的避让间距
PEER_Y_RANGE = 0.5           # 其他人卡片只落在上半区（相对可用高度）
SOCKET_CARD_W = 190.0        # socket 卡片估算宽（真实宽度实测）
SOCKET_CARD_H = 48.0         # socket 卡片估算高
SOCKET_GAP = 24.0            # socket 卡与所属 peer 卡的间距
DIRECT_NOTE_MAX_W = 240.0    # direct 可达地址列表的最大宽度
COMPACT_FIELD_MIN_W = 140.0  # 「我」卡片里输入框的最小宽度
COMPACT_FIELD_H = 28.0       # 紧凑输入框高度（安卓把 Material 默认 56 砍半）
FIELD_LABEL_W = 40.0         # 框外标签的固定宽度
SCHEME_BTN_W = 62            # ws/wss 切换按钮宽度
HOST_FIELD_MAX_W = 300       # 服务器地址框最大宽度（别被 stretch 拉太长）
HOST_FIELD_MIN_W = 200       # 服务器地址框最小宽度（去掉框内前缀后自然宽只剩 ~154，域名会挤）
PORT_FIELD_W = 118           # 端口框宽度：要能完整显示 10000（含"端口"前缀标签）

LINK_GREEN = "#4CAF50"       # 我/peer 的连线：绿色
LINK_STROKE_W = 2.0          # 线宽统一，不加粗
LINK_DASH_ON = 8.0           # 虚线 on
LINK_DASH_OFF = 6.0          # 虚线 off
DIVIDER_ALPHA = 0.35         # 屏幕中线：onSurfaceVariant 35%（暗色下取我们的次要文字色）

# socket 卡片第 5 行的六个用法（顺序即安卓 MainPage.kt 931-936）
USAGE_IDS = ["udptest", "tun", "switch", "wg", "proxy", "media"]

# 用法 → client.py 的 REPL 命令。
# 注意两处与安卓不同的地方（报告里说明）：
#   · tun / switch 在 client.py 里不是独立命令，而是"角色 + 模式"设定，带洞标识即可立刻拉起；
#   · proxy 需要目标 host:port（Phase 3 从 proxy 页取），这里先不给命令。
USAGE_COMMANDS: dict[str, str | None] = {
    "udptest": "udptest {hole}",
    "tun": "onholefromself tun {hole}",
    "switch": "onholefromself switch {hole}",
    "wg": "wg-py {peer}",
    "proxy": None,          # Phase 3：`proxy {hole} <host:port>`
    "media": "ffmpeg {hole}",
}


def node_label(name: str, ip: str, port: int) -> str:
    """安卓 nodeLabel()：有 ip/port 时显示成「我(1.2.3.4:5678)」"""
    if ip or port:
        return f"{name}({ip}:{port})"
    return name


def random_peer_positions(
    names: list[str], area_w: float, area_h: float, rng: random.Random
) -> dict[str, tuple[float, float]]:
    """
    安卓 FreeLayer 的随机摆放（相对坐标 x∈[0,1]、y∈[0, PeerYRange]）：
    与已放置的若 |Δx|<0.3 且 |Δy|<0.2 就重摇，最多 12 次。
    """
    placed: list[tuple[float, float]] = []
    out: dict[str, tuple[float, float]] = {}
    for name in names:
        cand = (rng.random(), rng.random() * PEER_Y_RANGE)
        attempt = 0
        while attempt < 12 and any(
            abs(p[0] - cand[0]) < 0.3 and abs(p[1] - cand[1]) < 0.2 for p in placed
        ):
            cand = (rng.random(), rng.random() * PEER_Y_RANGE)
            attempt += 1
        placed.append(cand)
        out[name] = cand
    return out


def peer_base(rel: tuple[float, float], area_w: float, area_h: float,
              peer_w: float, peer_h: float,
              top_limit: float = 0.0) -> tuple[float, float]:
    """
    其他人卡片的基准左上角（未拖动时）= 相对坐标 × (可活动范围)。

    `top_limit` = 这一列**允许的最小 top**（服务器卡片进了自由层之后，
    不在它左右两侧空白带里的卡片就得从它下面开始）；相对分布的形状不变，只是可用区被抬高了。
    """
    max_x = max(0.0, area_w - peer_w)
    lo = max(0.0, float(top_limit))
    hi = max(lo, max(0.0, area_h - peer_h))
    return (max_x * rel[0], lo + (hi - lo) * rel[1])


def socket_base(area_w: float, area_h: float, sock_w: float, sock_h: float,
                peer_tl: tuple[float, float] | None, peer_w: float, peer_h: float,
                gap: float = SOCKET_GAP, top_limit: float = 0.0) -> tuple[float, float]:
    """
    socket 卡片的基准位置（安卓 udpSocketBase）：挂在对应 peer 卡片正下方、**至少在下半屏**；
    x 与 peer 卡水平中心对齐。只在卡片刚出现时算一次，之后冻结。
    """
    max_x = max(0.0, area_w - sock_w)
    max_y = max(0.0, area_h - sock_h)
    if peer_tl is None:
        return (max(0.0, (area_w - sock_w) / 2.0), max(0.0, area_h / 2.0))
    base_x = peer_tl[0] + (peer_w - sock_w) / 2.0
    base_y = max(area_h / 2.0, peer_tl[1] + peer_h + gap, float(top_limit))
    return (min(max(base_x, 0.0), max_x), min(max(base_y, 0.0), max_y))


@dataclass
class Segment:
    """一条要画的线（抽成纯数据，方便 self-test 直接断言，不靠截图比对）"""
    kind: str                       # divider / server_me / server_peer / peer_socket
    x1: float
    y1: float
    x2: float
    y2: float
    color: str
    width: float
    dash: tuple[float, float] | None = None   # None = 实线
    alpha: float = 1.0


def link_segments(
    *,
    area_w: float,
    area_h: float,
    divider_y: float | None,
    show_link: bool,
    logged_in: bool,
    me_center: tuple[float, float] | None,
    peers: list[tuple[str, float, float, float, float]],
    sockets: list[tuple[int, str, float, float, float, float]],
    server_bottom: float = 0.0,
) -> list[Segment]:
    """
    算出自由层要画的全部线段（纯函数，安卓 FreeLayer 的 Canvas 那段）：

      1. 屏幕几何中线（1px、灰 35% 透明、贯通左右）
      2. 服务器 ↔ 我：未登录=白色虚线，已登录=绿色实线
      3. 服务器 ↔ 每个 peer：绿色实线，终点是 peer 标题行中心
      4. peer ↔ 它的 socket 卡：白色虚线
    """
    segs: list[Segment] = []
    if divider_y is not None:
        segs.append(Segment("divider", 0.0, divider_y, area_w, divider_y,
                            C_TEXT_DIM, 1.0, None, DIVIDER_ALPHA))

    peer_by_name = {name: (x, y, w, h) for name, x, y, w, h in peers}

    if show_link and me_center is not None:
        segs.append(Segment(
            "server_me", me_center[0], server_bottom, me_center[0], me_center[1],
            LINK_GREEN if logged_in else "#FFFFFF",
            LINK_STROKE_W,
            None if logged_in else (LINK_DASH_ON, LINK_DASH_OFF),
        ))

    for name, x, y, w, h in peers:
        segs.append(Segment("server_peer", x + w / 2.0, server_bottom,
                            x + w / 2.0, y + PEER_TITLE_CENTER_Y,
                            LINK_GREEN, LINK_STROKE_W, None))

    for hid, target, sx, sy, sw, sh in sockets:
        pt = peer_by_name.get(target)
        if pt is None:
            continue
        px, py, pw, ph = pt
        segs.append(Segment("peer_socket", px + pw / 2.0, py + ph,
                            sx + sw / 2.0, sy, "#FFFFFF", LINK_STROKE_W,
                            (LINK_DASH_ON, LINK_DASH_OFF)))
    return segs


# ── 紧凑输入框（安卓 CompactField / CompactFieldBox）──

class CompactField(QWidget):
    """
    安卓 CompactField 的对应物：
      - `outside=True`（「我」卡片）：标签在框外左侧，固定 40 宽；
      - `outside=False`（默认）：标签作为灰色前缀放在框内左侧；
      - `inline_label=False`：**框内不放任何标签**（服务器卡改成三行后就是这种：
        标签只在第一行的标签行里出现，别两处都显示）。此时框内只有 QLineEdit。
    高度固定 28，文字上下不留边距。
    """

    def __init__(self, label: str, *, outside: bool = False, password: bool = False,
                 inline_label: bool = True, parent: QWidget | None = None):
        super().__init__(parent)
        self.outside = outside
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6 if outside else 0)

        if outside:
            lab = QLabel(label, self)
            lab.setObjectName("fieldLabel")
            lab.setFixedWidth(int(FIELD_LABEL_W))
            row.addWidget(lab)

        self.edit = QLineEdit(self)
        self.edit.setFixedHeight(int(COMPACT_FIELD_H))
        if password:
            self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        if outside:
            row.addWidget(self.edit, 1)
        elif not inline_label:
            # 框内不要标签（服务器卡：标签在第一行）——直接放输入框
            row.addWidget(self.edit, 1)
        else:
            # 框内前缀标签：用占位符左边塞一个灰色标签，视觉与安卓一致
            holder = QWidget(self)
            holder.setObjectName("inlineField")
            holder.setFixedHeight(int(COMPACT_FIELD_H))
            hl = QHBoxLayout(holder)
            hl.setContentsMargins(8, 0, 8, 0)
            hl.setSpacing(6)
            pre = QLabel(label, holder)
            pre.setObjectName("inlineLabel")
            hl.addWidget(pre)
            hl.addWidget(self.edit, 1)
            row.addWidget(holder, 1)

    def value(self) -> str:
        return self.edit.text()

    def set_value(self, text: str) -> None:
        self.edit.setText(text)


# ── 拖动把手（安卓 dragHandle：只有挂了它的那一行能拖动卡片）──

class DragLabel(QLabel):
    """
    拖动把手（安卓 dragHandle）。

    ⚠️ 关键点：只按"相对上一次的位移"累加是不够的 —— 这个标签只有二十来像素高，
    鼠标一快就滑出标签范围，Qt 不再给它发 move 事件，手感就变成"卡卡的、不跟手"。
    所以这里：① `grabMouse()` 抓住鼠标，光标移出标签也照样收 move；
    ② 传**全局坐标**出去，由 FreeLayer 用"按下点 → 卡片左上角"的固定偏移量反算位置，
    做到和光标 1:1（不会累积误差）。
    """

    drag_pressed = pyqtSignal(QPoint)
    drag_moved = pyqtSignal(QPoint)
    drag_released = pyqtSignal()

    def __init__(self, text: str, parent: QWidget | None = None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.SizeAllCursor)

    def mousePressEvent(self, e) -> None:  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton:
            self.grabMouse()
            self.drag_pressed.emit(e.globalPosition().toPoint())
            e.accept()
            return
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e) -> None:  # noqa: N802
        self.drag_moved.emit(e.globalPosition().toPoint())
        e.accept()

    def mouseReleaseEvent(self, e) -> None:  # noqa: N802
        self.releaseMouse()
        self.drag_released.emit()
        super().mouseReleaseEvent(e)


def style_fl_card(w: QWidget, radius: int = 12) -> None:
    """
    自由层里三种卡片（我卡 / peer 卡 / socket 卡）共用同一套外框：
    **黑底 + 高亮描边**。安卓那边靠 Card 的默认 elevation，桌面用描边（沿用本轮的暗色规则）。
    ⚠️ 必须显式 setObjectName + setStyleSheet：QFrame 子类不这么做就只是一块普通背景，
    看起来"没有边缘高亮"。
    """
    w.setObjectName("flCard")
    w.setStyleSheet(
        f"QFrame#flCard {{ background: {C_CARD}; border: 1px solid {BORDER_CARD};"
        f" border-radius: {radius}px; }}"
    )


# ── 服务器卡片（安卓 ConnectionCard）──

class ServerCard(QFrame):
    def __init__(self, host: "MainWindow", parent: QWidget | None = None):
        super().__init__(parent)
        self.host = host
        self.setObjectName("serverCard")
        self.setStyleSheet(
            f"QFrame#serverCard {{ background: {C_CARD}; border: 1px solid {BORDER_CARD};"
            f" border-radius: 12px; }}"
        )
        col = QVBoxLayout(self)
        col.setContentsMargins(12, 12, 12, 12)
        col.setSpacing(8)

        # ── 三行：标签行 / 控件行 / 连接按钮 ──
        # 第一行：小字标签，只提示；**位置按下面控件的实际宽度对齐**（见 _sync_label_widths）
        self.row_labels = QWidget(self)
        lab_row = QHBoxLayout(self.row_labels)
        lab_row.setContentsMargins(0, 0, 0, 0)
        lab_row.setSpacing(8)
        self.lab_scheme = QLabel("协议", self.row_labels)
        self.lab_host = QLabel("服务器", self.row_labels)
        self.lab_port = QLabel("端口", self.row_labels)
        for lab in (self.lab_scheme, self.lab_host, self.lab_port):
            lab.setObjectName("colLabel")
            lab.setFixedHeight(14)
            lab_row.addWidget(lab, 0)
        lab_row.addStretch(1)

        # 第二行：ws/wss 一个按钮 + 地址框 + 端口框（框内不再有前缀标签）
        self.row_inputs = QWidget(self)
        row = QHBoxLayout(self.row_inputs)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        # ws / wss：**一个按钮**，点一下切换（按钮上的字就是当前协议），默认 ws
        self.btn_scheme = QPushButton("ws", self.row_inputs)
        self.btn_scheme.setObjectName("schemeBtn")
        self.btn_scheme.setFixedWidth(SCHEME_BTN_W)
        self.btn_scheme.setToolTip("点击切换 ws / wss")
        self.btn_scheme.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_scheme.clicked.connect(self._toggle_scheme)
        row.addWidget(self.btn_scheme, 0)

        # 地址框限制最大宽度（原来 stretch=1 会把它拉得特别长），端口框加宽到能完整显示 10000
        self.f_host = CompactField("服务器", inline_label=False, parent=self.row_inputs)
        self.f_host.setMinimumWidth(HOST_FIELD_MIN_W)
        self.f_host.setMaximumWidth(HOST_FIELD_MAX_W)
        self.f_port = CompactField("端口", inline_label=False, parent=self.row_inputs)
        self.f_port.setFixedWidth(PORT_FIELD_W)
        row.addWidget(self.f_host, 0)
        row.addWidget(self.f_port, 0)
        row.addStretch(1)          # 剩下的空白留在右边，别灌进输入框

        head = QWidget(self)
        head_col = QVBoxLayout(head)
        head_col.setContentsMargins(0, 0, 0, 0)
        head_col.setSpacing(2)     # 标签紧贴它提示的控件
        head_col.addWidget(self.row_labels)
        head_col.addWidget(self.row_inputs)
        col.addWidget(head)

        # 标签宽度要等布局把控件量出来之后再对齐（构造期控件宽度还是默认值）
        QTimer.singleShot(0, self._sync_label_widths)

        self.btn_toggle = QPushButton("未连接，点我连接", self)
        self.btn_toggle.setFixedHeight(32)
        self.btn_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        col.addWidget(self.btn_toggle)

    def values(self) -> tuple[str, int, bool]:
        host = self.f_host.value().strip() or "127.0.0.1"
        try:
            port = int(self.f_port.value().strip() or "10000")
        except ValueError:
            port = 10000
        return host, port, self.btn_scheme.text() == "wss"

    def _sync_label_widths(self) -> None:
        """
        第一行三个标签的宽度 = 下面对应控件的**实际宽度**（左边缘对齐）。

        ⚠️ 不能照抄常量：`f_host` 是"自然宽度 + 上限 300"（实测 224），
        写死 300 会让 `端口` 标签对不齐。控件宽度为 0（还没布局）时跳过，等下一次 resize 再对。
        """
        for lab, ctl in ((self.lab_scheme, self.btn_scheme),
                         (self.lab_host, self.f_host),
                         (self.lab_port, self.f_port)):
            w = ctl.width()
            if w > 0:
                lab.setFixedWidth(w)

    def resizeEvent(self, e) -> None:  # noqa: N802
        self._sync_label_widths()
        super().resizeEvent(e)

    def _toggle_scheme(self) -> None:
        """ws ⇄ wss（按钮文字即状态，默认 ws）"""
        self.btn_scheme.setText("wss" if self.btn_scheme.text() == "ws" else "ws")
        self.host.log(f"服务器卡：协议切到 {self.btn_scheme.text()}")

    def apply_state(self, connected: bool, logged_in: bool) -> None:
        self.btn_toggle.setText("已连接，点我断开" if connected else "未连接，点我连接")


# ── 「我」卡片（安卓 MeCard）──

class MeCard(QFrame):
    drag_requested = pyqtSignal(str, QPoint)

    def __init__(self, host: "MainWindow", parent: QWidget | None = None):
        super().__init__(parent)
        self.host = host
        style_fl_card(self, 12)          # 黑底 + 高亮描边（我卡）
        col = QVBoxLayout(self)
        col.setContentsMargins(10, 8, 10, 8)
        col.setSpacing(6)

        self.title = DragLabel(node_label("我", "", 0), self)
        self.title.setObjectName("flTitle")
        self.title.setMinimumWidth(int(COMPACT_FIELD_MIN_W))
        self.title.drag_pressed.connect(lambda gp: self.drag_requested.emit("begin", gp))
        self.title.drag_moved.connect(lambda gp: self.drag_requested.emit("move", gp))
        self.title.drag_released.connect(lambda: self.drag_requested.emit("end", QPoint()))
        col.addWidget(self.title)

        self.f_user = CompactField("用户名", outside=True, parent=self)
        self.f_pass = CompactField("密码", outside=True, password=True, parent=self)
        self.f_user.setMinimumWidth(int(COMPACT_FIELD_MIN_W))
        self.f_pass.setMinimumWidth(int(COMPACT_FIELD_MIN_W))
        col.addWidget(self.f_user)
        col.addWidget(self.f_pass)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self.btn_login = QPushButton("登录", self)
        self.btn_login.setFixedHeight(30)
        self.btn_login.setCursor(Qt.CursorShape.PointingHandCursor)
        # 应用层 ping（服务端已支持 {"type":"ping","seq":N} → {"type":"pong","seq":N}，不需要登录）
        self.btn_ping = QPushButton("ping", self)
        self.btn_ping.setFixedHeight(30)
        self.btn_ping.setToolTip("发一条应用层 ping，报文会进 App 内日志")
        self.btn_ping.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_list = QPushButton("list", self)
        self.btn_list.setFixedHeight(30)
        self.btn_list.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_row.addWidget(self.btn_login, 1)
        btn_row.addWidget(self.btn_ping, 1)      # 位置：登录/退出 与 list 之间
        btn_row.addWidget(self.btn_list, 1)
        self.btn_row = btn_row                   # 留着给 self-test 断言顺序
        col.addLayout(btn_row)

    def apply_state(self, connected: bool, logged_in: bool, loading: bool = False) -> None:
        self.btn_login.setText("退出" if logged_in else "登录")
        # 只要连着就能按（安卓 371-373 行：避免"按钮灰着点不了"的死状态）
        self.btn_login.setEnabled(not loading and (logged_in or connected))
        self.btn_ping.setEnabled(connected)      # ping 要有连接才发得出去

    def set_me(self, ip: str, port: int) -> None:
        self.title.setText(node_label("我", ip, port))


# ── 其他人卡片（安卓 PeerNode）──

class PeerCard(QFrame):
    drag_requested = pyqtSignal(str, QPoint)

    def __init__(self, peer: dict, on_action, parent: QWidget | None = None):
        super().__init__(parent)
        self.peer = peer
        style_fl_card(self, 12)
        self.setFixedHeight(int(PEER_NODE_H))
        col = QVBoxLayout(self)
        col.setContentsMargins(10, 6, 10, 6)
        col.setSpacing(6)

        self.title = DragLabel(
            node_label(peer.get("username", ""), peer.get("ip", ""), int(peer.get("port") or 0)), self
        )
        self.title.setObjectName("flTitle")
        self.title.drag_pressed.connect(lambda gp: self.drag_requested.emit("begin", gp))
        self.title.drag_moved.connect(lambda gp: self.drag_requested.emit("move", gp))
        self.title.drag_released.connect(lambda: self.drag_requested.emit("end", QPoint()))
        col.addWidget(self.title)

        row = QHBoxLayout()
        row.setSpacing(4)
        for text in ("direct", "upnp", "udp", "tcp"):
            b = QPushButton(text, self)
            b.setFixedSize(int(PEER_ACTION_W), int(PEER_ACTION_H))
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _=False, t=text: on_action(t, peer.get("username", "")))
            row.addWidget(b)
        row.addStretch(1)
        col.addLayout(row)


# ── socket 卡片（安卓 UdpSocketCardView：udp / direct / tcp·upnp 三种形态）──

class SocketCard(QFrame):
    drag_requested = pyqtSignal(str, QPoint)
    close_requested = pyqtSignal(int)

    def __init__(self, card: dict, on_use, parent: QWidget | None = None):
        super().__init__(parent)
        self.card = card
        style_fl_card(self, 10)          # 安卓 socket 卡用 10dp 圆角
        self.hole_id = int(card.get("id") or 0)
        self.kind = card.get("kind") or "udp"
        col = QVBoxLayout(self)
        col.setContentsMargins(8, 6, 8, 6)
        col.setSpacing(2)

        head = QHBoxLayout()
        head.setSpacing(4)
        title = DragLabel(self._title_text(card), self)
        title.setObjectName("flTitle")
        title.drag_pressed.connect(lambda gp: self.drag_requested.emit("begin", gp))
        title.drag_moved.connect(lambda gp: self.drag_requested.emit("move", gp))
        title.drag_released.connect(lambda: self.drag_requested.emit("end", QPoint()))
        head.addWidget(title, 1)
        self.btn_close = QPushButton("✕", self)
        self.btn_close.setObjectName("socketClose")
        self.btn_close.setFixedSize(24, 22)
        self.btn_close.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_close.clicked.connect(lambda: self.close_requested.emit(self.hole_id))
        head.addWidget(self.btn_close, 0)
        col.addLayout(head)

        self.usage_buttons: dict[str, QPushButton] = {}
        if self.kind == "udp":
            self._build_udp(col, card, on_use)
        else:
            self._build_plan(col, card)

    @staticmethod
    def _title_text(card: dict) -> str:
        kind = card.get("kind") or "udp"
        if kind in ("tcp", "upnp"):
            return f"{kind} 流程预览"
        if kind == "direct":
            return f"direct 直连探测 · {card.get('target', '')}"
        return "UDP socket"

    def _step_row(self, text: str, done: bool, parent_layout) -> None:
        row = QHBoxLayout()
        row.setSpacing(4)
        mark = QLabel("✓" if done else "○", self)
        mark.setObjectName("stepDone" if done else "stepTodo")
        mark.setFixedWidth(12)
        lab = QLabel(text, self)
        lab.setObjectName("stepDone" if done else "stepTodo")
        row.addWidget(mark)
        row.addWidget(lab, 1)
        parent_layout.addLayout(row)

    def _info_row(self, text: str, parent_layout) -> None:
        lab = QLabel(text, self)
        lab.setObjectName("infoRow")
        parent_layout.addWidget(lab)

    def _build_plan(self, col, card: dict) -> None:
        for step in card.get("plan") or []:
            self._step_row(step.get("text", ""), bool(step.get("done")), col)
            if step.get("detail"):
                self._info_row(step["detail"], col)
        if card.get("note"):
            note = QLabel(card["note"], self)
            note.setObjectName("noteRow")
            if card["note"].startswith("可达"):
                note.setStyleSheet(f"color: {LINK_GREEN};")
            note.setWordWrap(True)
            note.setMaximumWidth(int(DIRECT_NOTE_MAX_W))
            col.addWidget(note)
        tail = QLabel(card.get("tail_note") or "", self)
        tail.setObjectName("infoRow")
        col.addWidget(tail)

    def _build_udp(self, col, card: dict, on_use) -> None:
        local = QLabel(
            f"本机绑定 {format_host_port(card.get('local_ip', ''), int(card.get('local_port') or 0))}",
            self,
        )
        local.setObjectName("infoRow")
        col.addWidget(local)

        self._step_row("发给服务器", bool(card.get("sent_to_server")), col)
        self._step_row("收到服务器回复", bool(card.get("server_replied")), col)
        if card.get("server_replied"):
            self._info_row(
                "公网 " + format_host_port(card.get("my_public_ip", ""),
                                           int(card.get("my_public_port") or 0)), col)
            self._info_row(
                "对方 " + format_host_port(card.get("peer_public_ip", ""),
                                           int(card.get("peer_public_port") or 0)), col)
        self._step_row("发给对端", bool(card.get("sent_to_peer")), col)
        self._step_row("收到对端回复", bool(card.get("peer_replied")), col)

        row = QHBoxLayout()
        row.setSpacing(4)
        enabled = bool(card.get("peer_replied"))
        for usage in USAGE_IDS:
            b = QPushButton(usage, self)
            b.setObjectName("usageBtn")
            b.setFixedHeight(24)
            b.setEnabled(enabled)          # 第 4 步打勾后才可点
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            if card.get("handed_to") == usage:
                b.setProperty("selected", True)
                b.setStyleSheet(
                    f"QPushButton#usageBtn {{ border: 1px solid {LINK_GREEN};"
                    f" color: {LINK_GREEN}; }}"
                )
            b.clicked.connect(lambda _=False, u=usage: on_use(self.hole_id, u))
            self.usage_buttons[usage] = b
            row.addWidget(b)
        row.addStretch(1)
        col.addLayout(row)


def format_host_port(ip: str, port: int) -> str:
    """和安卓 formatHostPort 一致：v6 加方括号，端口为 0 时不显示"""
    if not ip:
        return f":{port}" if port else ""
    host = f"[{ip}]" if ":" in ip else ip
    return f"{host}:{port}" if port else host


# ── 自由层（安卓 FreeLayer）：连线 + 我卡 + 其他人卡 + socket 卡，全部可拖 ──

class FreeLayer(QWidget):
    def __init__(self, host: "MainWindow", parent: QWidget | None = None):
        super().__init__(parent)
        self.host = host
        self.peers: list[dict] = []
        self.holes: list[dict] = []
        self.connected = False
        self.logged_in = False

        self._rng = random.Random()
        self._peer_rel: dict[str, tuple[float, float]] = {}
        self._peer_drag: dict[str, tuple[float, float]] = {}
        self._peer_cards: dict[str, PeerCard] = {}
        self._socket_drag: dict[int, tuple[float, float]] = {}
        self._socket_base: dict[int, tuple[float, float]] = {}
        self._socket_cards: dict[int, SocketCard] = {}

        self.me_card = MeCard(host, self)
        self.me_card.drag_requested.connect(
            lambda phase, gp: self._on_drag("me", "", phase, gp))
        self._grab: dict[tuple[str, str], tuple[float, float]] = {}
        self._me_drag = (0.0, 0.0)
        self._me_size = (0.0, 0.0)
        # 服务器卡片**在自由层里**（由 HomePage 建好后交进来）：顶部对齐、不可拖动
        self.server_card: "ServerCard | None" = None

        # 自由层自己也要画黑底（QWidget 子类必须开 WA_StyledBackground，否则会透）
        self.setObjectName("freeLayer")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setMouseTracking(True)
        self._sync_me_size()

    # ── 数据入口（由 MainWindow 从引擎信号接过来）──
    def set_peers(self, peers: list[dict]) -> None:
        self.peers = list(peers or [])
        names = [p.get("username", "") for p in self.peers]
        # 只为新出现的 peer 摇位置；已有的保持不动（比安卓整批重摇更稳，报告里说明）
        for name in names:
            if name not in self._peer_rel:
                single = random_peer_positions([name], self.width(), self.height(), self._rng)
                self._peer_rel[name] = single[name]
        for gone in [n for n in self._peer_rel if n not in names]:
            self._peer_rel.pop(gone, None)
            self._peer_drag.pop(gone, None)
        self._rebuild_cards()
        self._relayout()

    def set_holes(self, holes: list[dict]) -> None:
        self.holes = list(holes or [])
        self._rebuild_cards()
        self._relayout()

    def set_me(self, ip: str, port: int) -> None:
        self.me_card.set_me(ip, port)
        self._sync_me_size()        # 内容变了才重量尺寸
        self._relayout()

    def apply_state(self, connected: bool, logged_in: bool) -> None:
        self.connected = connected
        self.logged_in = logged_in
        self.me_card.apply_state(connected, logged_in)
        self._sync_me_size()
        self._relayout()

    # ── 卡片构建 ──
    def _rebuild_cards(self) -> None:
        wanted = {p.get("username", "") for p in self.peers}
        for name in list(self._peer_cards):
            if name not in wanted:
                self._peer_cards.pop(name).deleteLater()
        for peer in self.peers:
            name = peer.get("username", "")
            if name not in self._peer_cards:
                c = PeerCard(peer, self._peer_action, self)
                c.drag_requested.connect(
                    lambda phase, gp, n=name: self._on_drag("peer", n, phase, gp))
                self._peer_cards[name] = c
                c.adjustSize()          # 宽度按内容自适应（安卓的 IntrinsicSize.Max）
                c.show()

        wanted_ids = {int(h.get("id") or 0) for h in self.holes}
        for hid in list(self._socket_cards):
            if hid not in wanted_ids:
                self._socket_cards.pop(hid).deleteLater()
                self._socket_base.pop(hid, None)
                self._socket_drag.pop(hid, None)
        for hole in self.holes:
            hid = int(hole.get("id") or 0)
            fresh = self.hole_to_card(hole)
            old_card = self._socket_cards.get(hid)
            if old_card is not None and old_card.card == fresh:
                continue                    # 数据没变：复用同一张卡
            if old_card is not None:
                old_card.deleteLater()      # 数据变了（比如 handed_to / 步骤）：重建这张卡
                self._socket_cards.pop(hid, None)
            c = SocketCard(fresh, self._use_socket, self)
            c.drag_requested.connect(
                lambda phase, gp, i=hid: self._on_drag("socket", str(i), phase, gp))
            c.close_requested.connect(self._close_socket)
            self._socket_cards[hid] = c
            c.adjustSize()
            c.show()
        # socket 卡最后 raise：保证压在其他卡片之上、✕ 始终可点
        for c in self._socket_cards.values():
            c.raise_()

    def hole_to_card(self, hole: dict) -> dict:
        """
        洞（client.py 的 hole dict）→ 卡片数据（对齐安卓 UdpSessionInfo 的字段含义）。

        字段对应：hole['my_ip'/'my_port'] = 本机绑定；hole['peer_ip'/'peer_port'] = 对端；
        步骤优先用结构化字段（status / handed_to），再用被中继的步骤行补精确打勾。
        """
        proto = (hole.get("proto") or "udp").lower()
        target = hole.get("peer") or ""
        steps = self.host.step_done(hole.get("id"))
        status = hole.get("status") or ""
        confirmed = status == "已打通" or steps.get(6, False)
        got_peer = bool(hole.get("peer_ip")) or steps.get(4, False)
        if proto == "udp":
            return {
                "id": hole.get("id"), "kind": "udp", "target": target,
                "local_ip": hole.get("my_ip") or "", "local_port": hole.get("my_port") or 0,
                "my_public_ip": hole.get("my_ip") or "", "my_public_port": hole.get("my_port") or 0,
                "peer_public_ip": hole.get("peer_ip") or "", "peer_public_port": hole.get("peer_port") or 0,
                "sent_to_server": bool(steps.get(1)) or bool(hole.get("my_port")) or confirmed,
                "server_replied": bool(steps.get(2)) or bool(hole.get("my_port")) or confirmed,
                "sent_to_peer": bool(steps.get(3)) or got_peer or confirmed,
                "peer_replied": bool(confirmed),
                "handed_to": hole.get("handed_to") or "",
            }
        if proto == "direct":
            done = [bool(steps.get(n)) for n in (1, 2, 3)]
            return {
                "id": hole.get("id"), "kind": "direct", "target": target,
                "plan": [
                    {"text": "枚举本机地址", "done": done[0]},
                    {"text": "和服务器交换地址", "done": done[1]},
                    {"text": "并发 ping 可达性", "done": done[2]},
                ],
                "note": self.host.engine.direct_notes.get(target, ""),
                "tail_note": "（direct 只证明地址可达，不建隧道）",
            }
        # tcp / upnp：安卓那边是"流程预览"。tcp 在 Python 端有真实现（5 步），
        # 所以尾注据实改写（报告里说明这处措辞差异）。
        # tcp 尾注不再显示（原来是"Python 端 tcp 打洞已实现…"这种实现现状说明，按"不占屏幕"去掉）；
        # upnp 那句是安卓原文、三端一致，保留。
        tail = "（仅流程预览，尚未实现真实握手）" if proto == "upnp" else ""
        return {
            "id": hole.get("id"), "kind": proto, "target": target,
            "plan": [{"text": t, "done": False} for t in
                     (["建立三个 socket", "同时发起连接", "任一条成功即用"] if proto == "tcp"
                      else ["和路由器协商", "添加端口映射", "回读外部地址"])],
            "note": "", "tail_note": tail,
        }

    # ── 交互 ──
    def _peer_action(self, action: str, username: str) -> None:
        cmd = {"direct": "direct", "udp": "udp", "tcp": "tcp", "upnp": "upnp"}.get(action)
        if cmd is None:
            return
        line = cmd if cmd == "upnp" else f"{cmd} {username}"
        self.host.log(f"主页：{action} {username} → client.py 命令 {line!r}")
        self.host.engine.command(line)

    def _use_socket(self, hole_id: int, usage: str) -> None:
        template = USAGE_COMMANDS.get(usage)
        if template is None:
            self.host.log(f"主页：{usage} 需要目标地址，Phase 3 从 proxy 页取（洞 #{hole_id}）")
            return
        line = template.format(hole=f"#{hole_id}", peer=self._hole_peer(hole_id))
        self.host.log(f"主页：把洞 #{hole_id} 交给 {usage} → client.py 命令 {line!r}")
        self.host.engine.command(line)

    def _hole_peer(self, hole_id: int) -> str:
        for h in self.holes:
            if int(h.get("id") or 0) == hole_id:
                return h.get("peer") or ""
        return ""

    def _close_socket(self, hole_id: int) -> None:
        self.host.log(f"主页：关闭洞 #{hole_id}")
        self._socket_cards.pop(hole_id, None)
        self._socket_base.pop(hole_id, None)
        self._socket_drag.pop(hole_id, None)
        self.host.engine.command(f"del hole=#{hole_id}")
        self.holes = [h for h in self.holes if int(h.get("id") or 0) != hole_id]
        self._relayout()
        self.update()

    # ── 服务器卡片：几何（随尺寸实时算）+ 其它卡片的避让 ──
    def set_server_card(self, card: "ServerCard") -> None:
        """HomePage 建好服务器卡片后交进来：它成为自由层内的元素（顶部对齐、不参与拖动）。"""
        self.server_card = card
        card.lower()                 # 压到最底层：其它卡片永远在它上面（限位也保证不重叠）
        self._relayout()

    def server_rect(self) -> tuple[float, float, float, float]:
        """
        服务器卡片在自由层里的矩形 (x, y, w, h) —— **每次按当前尺寸算**（resize/最大化都会跟着变）：

          · 竖屏（自由层高 > 宽）→ **满宽**（左右各留 SERVER_CARD_MARGIN_X）
          · 横屏（宽 > 高）→ **占一半宽、水平居中**（左右各留出 1/4 宽的空白带）

        注意：判据用的是**自由层**（= 整个内容区）的宽高比，等价于窗口的宽高比（只差标题栏那点高）。
        """
        card = self.server_card
        if card is None:
            return (0.0, 0.0, 0.0, 0.0)
        area_w, area_h = float(self.width()), float(self.height())
        m = SERVER_CARD_MARGIN_X
        full = max(0.0, area_w - 2.0 * m)
        w = full if area_h > area_w else full / 2.0
        x = (area_w - w) / 2.0            # 横屏"居中占一半"；竖屏满宽时 x = m
        h = float(card.sizeHint().height())
        return (x, SERVER_CARD_MARGIN_TOP, w, h)

    def _position_server_card(self) -> None:
        card = self.server_card
        if card is None:
            return
        x, y, w, h = self.server_rect()
        r = QRect(int(x), int(y), int(w), int(h))
        if card.geometry() != r:          # 只有真的变了才 setGeometry（拖动时每帧都会走到这里）
            card.setGeometry(r)

    def avoid_top(self, x: float, w: float) -> float:
        """
        某张卡（左上角 x、宽 w）**允许的最小 top**：

          · 完全落在服务器卡片**左右两侧的空白带**里 → 0（纵向可以一直用到自由层顶部）
          · 否则 → 服务器卡片底边 + SERVER_CARD_GAP（不许压住服务器卡片）

        横屏时服务器卡片居中占一半 → 空白带是左右各 1/4 宽。
        """
        sx, sy, sw, sh = self.server_rect()
        if sw <= 0.0 or sh <= 0.0:
            return 0.0
        left_band = x + w <= sx - SERVER_CARD_GAP
        right_band = x >= sx + sw + SERVER_CARD_GAP
        if left_band or right_band:
            return 0.0
        return sy + sh + SERVER_CARD_GAP

    # ── 拖动（三种卡片同一套：按下时记住"按下点 → 卡片左上角"的偏移，之后按全局光标 1:1 跟随）──
    def _card_of(self, kind: str, name: str) -> QWidget | None:
        if kind == "me":
            return self.me_card
        if kind == "peer":
            return self._peer_cards.get(name)
        if kind == "socket":
            return self._socket_cards.get(int(name or 0))
        return None

    def _base_of(self, kind: str, name: str) -> tuple[float, float]:
        if kind == "me":
            me_w, me_h = self._me_size
            # 默认位置：水平居中 + **竖直居中**；但"不许压住服务器卡片"优先 ——
            # 横屏窗口很矮时会把它推到服务器卡片下方（报告里说明）
            x = (float(self.width()) - me_w) / 2.0
            y = (float(self.height()) - me_h) / 2.0
            return (x, max(y, self.avoid_top(x, me_w)))
        if kind == "peer":
            return self.peer_base_of(name)
        if kind == "socket":
            return self.socket_base_of(int(name or 0))
        return (0.0, 0.0)

    def _offset_of(self, kind: str, name: str) -> tuple[float, float]:
        if kind == "me":
            return self._me_drag
        if kind == "peer":
            return self._peer_drag.get(name, (0.0, 0.0))
        if kind == "socket":
            return self._socket_drag.get(int(name or 0), (0.0, 0.0))
        return (0.0, 0.0)

    def _set_offset(self, kind: str, name: str, val: tuple[float, float]) -> None:
        if kind == "me":
            self._me_drag = val
        elif kind == "peer":
            self._peer_drag[name] = val
        elif kind == "socket":
            self._socket_drag[int(name or 0)] = val

    def _on_drag(self, kind: str, name: str, phase: str, gp: QPoint) -> None:
        if phase == "begin":
            card = self._card_of(kind, name)
            if card is not None:
                tl = card.mapToGlobal(QPoint(0, 0))
                self._grab[(kind, name)] = (gp.x() - tl.x(), gp.y() - tl.y())
        elif phase == "move":
            self._move_drag(kind, name, gp)
        else:
            self._grab.pop((kind, name), None)

    def _move_drag(self, kind: str, name: str, gp: QPoint) -> None:
        off = self._grab.get((kind, name))
        card = self._card_of(kind, name)
        if off is None or card is None:
            return
        want_tl = self.mapFromGlobal(QPoint(gp.x() - off[0], gp.y() - off[1]))
        bx, by = self._base_of(kind, name)
        w, h = float(card.width()), float(card.height())
        max_x = max(0.0, float(self.width()) - w)
        max_y = max(0.0, float(self.height()) - h)
        # x 先 clamp，再按"最终落在哪一列"决定 top 的下限（服务器卡片左右两侧空白带可到顶）
        off_x = _clamp(want_tl.x() - bx, -bx, max_x - bx)
        lo = self.avoid_top(bx + off_x, w)
        if kind == "me":
            lo = max(lo, ME_CARD_MARGIN)          # 我卡另外还留 ME_CARD_MARGIN
            hi = max(lo, max_y - ME_CARD_MARGIN)
        else:
            hi = max(lo, max_y)
        self._set_offset(kind, name, (off_x, _clamp(want_tl.y(), lo, hi) - by))
        self._relayout()

    def drag_by(self, kind: str, name: str, dx: float, dy: float) -> None:
        """程序化拖动（self-test 用）：从卡片左上角出发相对移动 (dx, dy)，走的是同一条路径"""
        card = self._card_of(kind, name)
        if card is None:
            return
        tl = card.mapToGlobal(QPoint(0, 0))
        self._on_drag(kind, name, "begin", tl)
        self._on_drag(kind, name, "move", QPoint(int(tl.x() + dx), int(tl.y() + dy)))
        self._on_drag(kind, name, "end", QPoint())

    # 兼容旧名字（self-test 里在用）
    def _drag_me(self, dx: float, dy: float) -> None:
        self.drag_by("me", "", dx, dy)

    def _drag_peer(self, name: str, dx: float, dy: float) -> None:
        self.drag_by("peer", name, dx, dy)

    def _drag_socket(self, hole_id: int, dx: float, dy: float) -> None:
        self.drag_by("socket", str(hole_id), dx, dy)

    # ── 几何 ──
    def peer_base_of(self, name: str) -> tuple[float, float]:
        rel = self._peer_rel.get(name)
        if rel is None:
            return (0.0, 0.0)
        card = self._peer_cards.get(name)
        pw = float(card.width()) if card is not None else PEER_NODE_W
        area_w = float(self.width())
        x = max(0.0, area_w - pw) * rel[0]
        return peer_base(rel, area_w, float(self.height()), pw, PEER_NODE_H,
                         top_limit=self.avoid_top(x, pw))

    def peer_top_left(self, name: str) -> tuple[float, float]:
        bx, by = self.peer_base_of(name)
        dx, dy = self._peer_drag.get(name, (0.0, 0.0))
        return (bx + dx, by + dy)

    def socket_base_of(self, hole_id: int) -> tuple[float, float]:
        """socket 卡的基准位置：算到一次就冻结（安卓 frozenSocketBases）。"""
        if hole_id in self._socket_base:
            return self._socket_base[hole_id]
        card = self._socket_cards.get(hole_id)
        sw = float(card.width()) if card is not None else SOCKET_CARD_W
        sh = float(card.height()) if card is not None else SOCKET_CARD_H
        target = ""
        for h in self.holes:
            if int(h.get("id") or 0) == hole_id:
                target = h.get("peer") or ""
                break
        peer_tl = self.peer_top_left(target) if target in self._peer_rel else None
        peer_card = self._peer_cards.get(target)
        peer_w = float(peer_card.width()) if peer_card is not None else PEER_NODE_W
        # socket 卡的 x 与 peer 卡中心对齐（peer 不在时水平居中）——先算出 x，再问它那一列允许的最小 top
        guess_x = ((peer_tl[0] + (peer_w - sw) / 2.0) if peer_tl is not None
                   else (float(self.width()) - sw) / 2.0)
        base = socket_base(float(self.width()), float(self.height()), sw, sh,
                           peer_tl, peer_w, PEER_NODE_H,
                           top_limit=self.avoid_top(guess_x, sw))
        self._socket_base[hole_id] = base
        return base

    def socket_top_left(self, hole_id: int) -> tuple[float, float]:
        bx, by = self.socket_base_of(hole_id)
        dx, dy = self._socket_drag.get(hole_id, (0.0, 0.0))
        return (bx + dx, by + dy)

    def me_center(self) -> tuple[float, float]:
        area_h = float(self.height())
        me_h = self._me_size[1]
        bx, by = self._base_of("me", "")
        return (bx + self._me_size[0] / 2.0 + self._me_drag[0],
                by + me_h / 2.0 + self._me_drag[1])

    def divider_y(self) -> float | None:
        """
        屏幕几何中线在自由层坐标系里的 y（安卓 FreeLayer 675 行）：
        `窗口top + 窗口高/2 - 自由层top`。桌面这里窗口就是我们的无边框窗口，
        用 mapTo(window) 取自由层顶边在窗口里的位置；量不到就不画。
        """
        win = self.window()
        if win is None:
            return None
        top_in_win = float(self.mapTo(win, QPoint(0, 0)).y())
        y = float(win.height()) / 2.0 - top_in_win
        return y if 0.0 <= y <= float(self.height()) else None

    def segments(self) -> list[Segment]:
        peers = []
        for p in self.peers:
            name = p.get("username", "")
            card = self._peer_cards.get(name)
            w = float(card.width()) if card is not None else PEER_NODE_W
            x, y = self.peer_top_left(name)
            peers.append((name, x, y, w, PEER_NODE_H))
        sockets = []
        for h in self.holes:
            hid = int(h.get("id") or 0)
            card = self._socket_cards.get(hid)
            w = float(card.width()) if card is not None else SOCKET_CARD_W
            hh = float(card.height()) if card is not None else SOCKET_CARD_H
            x, y = self.socket_top_left(hid)
            sockets.append((hid, h.get("peer") or "", x, y, w, hh))
        _sx, _sy, _sw, _sh = self.server_rect()
        return link_segments(
            area_w=float(self.width()), area_h=float(self.height()),
            divider_y=self.divider_y(), show_link=self.connected, logged_in=self.logged_in,
            me_center=self.me_center() if self._me_size[1] > 0 else None,
            peers=peers, sockets=sockets,
            server_bottom=(_sy + _sh) if _sh > 0 else 0.0,
        )

    # ── 摆放 ──
    def resizeEvent(self, e) -> None:  # noqa: N802
        # 窗口尺寸变了：没被拖过的 socket 卡重新按 peer 位置算基准（拖过的保留位移再 clamp）
        for hid in list(self._socket_base):
            if self._socket_drag.get(hid, (0.0, 0.0)) == (0.0, 0.0):
                self._socket_base.pop(hid, None)
        self._relayout()
        super().resizeEvent(e)

    def _sync_me_size(self) -> None:
        self.me_card.adjustSize()
        self._me_size = (float(self.me_card.width()), float(self.me_card.height()))

    def _relayout(self) -> None:
        area_w, area_h = float(self.width()), float(self.height())
        self._position_server_card()      # 服务器卡片：随尺寸实时重算（竖屏满宽 / 横屏居中一半）
        # ⚠️ 这里**不要**再 adjustSize()：拖动时每帧都会走到这儿，
        # 每帧都跑一次布局计算就是"卡卡的"的主因。尺寸只在内容变化时更新（见 set_me/apply_state）。
        me_w, me_h = self._me_size if self._me_size[0] > 0 else (
            float(self.me_card.sizeHint().width()), float(self.me_card.sizeHint().height()))
        # 默认位置统一走 _base_of：水平居中 + 竖直居中，但"不许压住服务器卡片"优先
        me_bx, me_by = self._base_of("me", "")
        self.me_card.move(
            int(me_bx + self._me_drag[0]),
            int(me_by + self._me_drag[1]),
        )
        self.me_card.raise_()

        for name, card in self._peer_cards.items():
            x, y = self.peer_top_left(name)
            card.move(int(x), int(y))

        for hid, card in self._socket_cards.items():
            x, y = self.socket_top_left(hid)
            card.move(int(x), int(y))
            card.raise_()

        self.update()

    def paintEvent(self, e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        for seg in self.segments():
            color = QColor(seg.color)
            if seg.alpha < 1.0:
                color.setAlphaF(seg.alpha)
            pen = QPen(color, seg.width)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            if seg.dash:
                pen.setStyle(Qt.PenStyle.CustomDashLine)
                # Qt 的 dashPattern 单位是"线宽倍数"，安卓那边是像素 → 除一下线宽
                pen.setDashPattern([seg.dash[0] / seg.width, seg.dash[1] / seg.width])
            p.setPen(pen)
            p.drawLine(int(seg.x1), int(seg.y1), int(seg.x2), int(seg.y2))
        p.end()


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


# ── 主页 = 自由层填满内容区（服务器卡片是自由层里的一个元素，顶部对齐）──

class HomePage(QWidget):
    """
    主页。**注意：不是 Page 的子类** —— 自由层填满整个内容区、要能任意摆放卡片，
    所以不能套在滚动区里；服务器卡片是**自由层里的**一个元素（顶部对齐、不可拖动）。
    """

    def __init__(self, host: "MainWindow", parent: QWidget | None = None):
        super().__init__(parent)
        self.host = host
        self.kind = "主页"
        self.setObjectName("homePage")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        col = QVBoxLayout(self)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(0)

        # 自由层**填满整个内容区**（"自由层正中"从此 = 整个内容区的正中）
        self.free_layer = FreeLayer(host, self)
        col.addWidget(self.free_layer, 1)

        # 服务器卡片**在自由层里**：顶部对齐、不可拖动；宽度随窗口比例实时变
        # （竖屏满宽 / 横屏居中占一半，见 FreeLayer.server_rect）
        self.server_card = ServerCard(host, self.free_layer)
        self.server_card.btn_toggle.clicked.connect(self._toggle_connection)
        self.free_layer.set_server_card(self.server_card)

        # 「我」卡片的两个按钮（用户名/密码在自由层里，服务器卡没有它们）
        self.free_layer.me_card.btn_login.clicked.connect(self._toggle_login)
        self.free_layer.me_card.btn_list.clicked.connect(lambda: self.host.engine.command("list"))
        self.free_layer.me_card.btn_ping.clicked.connect(self._send_ping)

        # 记住密码：方便用户重连（安卓的密码输入框也在「我」卡上）
        self.free_layer.me_card.f_user.edit.textChanged.connect(self._remember)

    def _remember(self, *_a) -> None:
        self.host.log("主页：用户名/密码已更新")

    def _send_ping(self) -> None:
        """「我」卡片的 ping 按钮 → 和别的命令一样投给引擎线程执行 `ping`（实现在 client.py）"""
        self.host.log("主页：发出应用层 ping（走 client.py 的 ping 命令）")
        self.host.engine.command("ping")

    def _toggle_connection(self) -> None:
        if self.host.is_connected():
            self.host.log("主页：断开（服务器卡）")
            self.host.engine.disconnect()
        else:
            self.host.connect_engine()

    def _toggle_login(self) -> None:
        card = self.free_layer.me_card
        if self.host.is_logged_in():
            self.host.log("主页：退出登录（我卡）")
            self.host.engine.logout()
            return
        user, pw = card.f_user.value().strip(), card.f_pass.value()
        if not user or not pw:
            self.host.log("主页：用户名/密码没填全，不登录")
            return
        self.host.log(f"主页：登录 {user}（预置 ARGS_PASS，避免 client.py 阻塞等输入）")
        self.host.engine.login(user, pw)

    # ── 引擎信号 → 界面 ──
    def set_peers(self, peers: list) -> None:
        self.free_layer.set_peers(peers)

    def set_holes(self, holes: list) -> None:
        self.free_layer.set_holes(holes)

    def set_me(self, ip: str, port: int) -> None:
        self.free_layer.set_me(ip, port)

    def apply_state(self, connected: bool, logged_in: bool, loading: bool = False) -> None:
        self.server_card.apply_state(connected, logged_in)
        self.free_layer.apply_state(connected, logged_in)
        self.free_layer.me_card.apply_state(connected, logged_in, loading)

    def card_titles(self) -> list[str]:
        return ["服务器", "自由层（我卡 / 其他人卡 / socket 卡 / 连线）"]


class ConfigPage(Page):
    """
    配置页骨架基类。子类只需要在 `build()` 里摆卡片；Phase 1 所有控件都 disabled（只是示意），
    按钮只写日志——**不做存盘、不做逻辑**。
    """

    # 各页对应的 python 端实现（只做代码注释，不再作为界面文案显示）：
    #   media     → client/app/media.py（RTMP 收/推）+ app/ffmpeg.sh（P2P 那段是 mpegts over UDP）
    #   proxy     → client/app/proxy.py
    #   wireguard → client/app/wg-python.py（自己实现）/ app/wg-calltool.py → app/wghelp.sh（调系统 wg）
    #   vpn       → client/app/vpn.py
    #   switch    → client/app/switch.py
    def __init__(self, host: "MainWindow", kind: str, parent: QWidget | None = None):
        super().__init__(host, parent)
        self.kind = kind
        self._titles: list[str] = []

    def add_card(self, title: str, *, render_title: bool = True) -> tuple[QFrame, QVBoxLayout]:
        """加一张卡。`render_title=False` = 卡片不画标题行，标题文字由首行 `card_head_row()` 承担
        （这样"配置卡首行"和"DHCP 卡首行"能走**同一个容器**、内边距完全一致）。"""
        frame, body = card(self, title if render_title else "")
        self._titles.append(title)
        self.body.addWidget(frame)
        return frame, body

    def finish_layout(self) -> None:
        """
        页面构建完统一收尾（`MainWindow` 建页时调一次）：

        每张卡的 `body` 末尾、以及页面 `body` 末尾各补一个弹簧 —— 多余高度落到"底部空白"，
        卡片与行都贴合自身内容高度（和手机端一样**内容顶对齐**），不再被父布局拉伸。
        """
        for i in range(self.body.count()):
            card = self.body.itemAt(i).widget()
            if card is None or card.layout() is None:
                continue
            outer = card.layout()
            body = None
            for j in range(outer.count()):
                if outer.itemAt(j).layout() is not None:
                    body = outer.itemAt(j).layout()
            if body is not None and body.count() and not body.itemAt(body.count() - 1).spacerItem():
                body.addStretch(1)
        if self.body.count() and not self.body.itemAt(self.body.count() - 1).spacerItem():
            self.body.addStretch(1)

    def set_ports(self, n: int) -> None:
        """网口数变化 → 首行状态（0 = 未插线，非空 = 已插 N 个）。switch 用。"""
        lab = getattr(self, "lab_ports", None)
        if lab is not None:
            lab.setText(ports_state_text(n))

    def set_channels(self, n: int) -> None:
        """通道数变化 → 首行状态（0 = 未接线，非空 = 已接 N 条）。vpn / proxy 用同一套文案。"""
        lab = getattr(self, "lab_state", None)
        if lab is not None:
            lab.setText(channels_state_text(n))

    def add_dhcp_toggle(self, body: QVBoxLayout, dhcp_card: QFrame) -> ToggleSwitch:
        """
        配置卡**最后一行**：`内嵌 DHCP` 开关（默认关闭）。

        行为：勾上 → DHCP 整卡显示；取消 → 整卡隐藏（不是 disable）。
        `dhcpEnabled` 默认必须是 false，所以这里显式 `setChecked(False)` + `setVisible(False)`。
        """
        sw = ToggleSwitch(self)                   # 自绘开关（非勾选框）
        sw.setChecked(False)                      # dhcpEnabled 默认 false
        sw.toggled.connect(dhcp_card.setVisible)  # 整卡显隐（不是 setEnabled）
        # **字段行版式**（和「路由老化」那几行同构）：标签在标签列（label_w=84）→ 开关紧跟其后 → 右边留空。
        # 不用 card_head_row 的"右侧控件"位置（那个会把控件顶到卡片最右边，用户不要）。
        # ⚠️ 必须显式 enabled=True：field_row 的 enabled 默认是 False（Phase 1 的占位控件默认禁用），
        # 不传的话开关会被禁用 —— 用户点了没反应、DHCP 卡也永远出不来（实机 bug）。
        row, _, _ = field_row(self, "内嵌 DHCP", sw, enabled=True)   # 自带 row_fixed() + fieldLabel 样式
        row.layout().addStretch(1)                       # 右边留空（开关不许被顶到最右）
        body.addWidget(row)
        dhcp_card.setVisible(False)               # 默认关闭 → 整卡隐藏
        return sw

    def card_titles(self) -> list[str]:
        return list(self._titles)


class MediaPage(ConfigPage):
    """media 页：收流 / 推流 / 拉起应用（对齐安卓 MediaPage，地址端口只读，来自打洞结果）。"""

    def __init__(self, host, parent=None):
        super().__init__(host, "media", parent)

        _f, body = self.add_card("收流（对端 → 本机）")
        row, grp = choice_buttons(self, ["rtmp", "rtsp", "srt", "udp"])
        body.addWidget(field_row(self, "协议", row)[0])
        body.addWidget(field_row(self, "本机地址", hint="打洞后自动带出")[0])
        body.addWidget(field_row(self, "本机端口", hint="打洞后自动带出")[0])

        _f, body = self.add_card("推流（本机 → 对端）")
        row, grp = choice_buttons(self, ["rtmp", "rtsp", "srt", "udp"])
        body.addWidget(field_row(self, "协议", row)[0])
        body.addWidget(field_row(self, "对端地址", hint="打洞后自动带出")[0])
        body.addWidget(field_row(self, "对端端口", hint="打洞后自动带出")[0])
        row, grp = choice_buttons(self, ["mic", "camera", "both"], "both")
        body.addWidget(field_row(self, "采集", row)[0])
        body.addWidget(section_note(self, "对方路由器公网地址:端口（对方内网地址不用管）"))

        _f, body = self.add_card("拉起应用")
        body.addWidget(field_row(self, "应用包名", hint="留空 = 只按 action 找")[0])
        body.addWidget(field_row(self, "Action", hint="com.p2pnet.action.MEDIA_CHAT")[0])
        btn = QPushButton("拉起应用", self)
        btn.setFixedHeight(30)
        btn.clicked.connect(lambda: self.host.log("media：拉起应用（Phase 1 只写日志）"))
        body.addWidget(btn)


class ProxyPage(ConfigPage):
    """proxy 页：端口转发（-L 本机 listen / -R 本机 connect）。"""

    def __init__(self, host, parent=None):
        super().__init__(host, "proxy", parent)

        # 配置卡首行：和 vpn / switch 完全一致（「配置」+ 状态 + 弹簧 + 启停），卡片不画标题行
        _f, cfg_body = self.add_card("配置", render_title=False)
        self.lab_state = QLabel(channels_state_text(0), self)      # 空态 = 未接线
        self.lab_state.setObjectName("note")
        self.btn_toggle = QPushButton("启动", self)
        self.btn_toggle.setFixedHeight(CARD_HEAD_H)                # 与 vpn/switch 首行同高
        self.btn_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_toggle.clicked.connect(lambda: self.host.log("proxy：启动（Phase 1 只写日志）"))
        self.row_cfg = card_head_row(self, "配置",
                                     state_widget=self.lab_state, control=self.btn_toggle)
        cfg_body.addWidget(self.row_cfg)

        # ↓ 以下字段行、模式选择、按钮行为全部保持原样（只是把"状态 + 启停"搬进了首行行尾）
        row, grp = choice_buttons(self, ["正向 -L", "反向 -R"], "反向 -R")
        cfg_body.addWidget(field_row(self, "模式", row)[0])
        row, grp = choice_buttons(self, ["tcp", "udp"])
        cfg_body.addWidget(field_row(self, "协议", row)[0])
        cfg_body.addWidget(field_row(self, "保活间隔", hint="20")[0])
        cfg_body.addWidget(field_row(self, "洞地址", hint="0.0.0.0")[0])
        cfg_body.addWidget(field_row(self, "洞端口", hint="留空 = 用 session 的实际端口")[0])
        # 原来配置卡里还有一行 `通道：还没有` 的空态说明，以及一个独立的「启动」按钮：
        # 空态三端一致删掉（由首行状态表达），按钮搬到了上面的首行行尾。
        # 将来有真实通道数据时，在这里按 `if channels:` 条件渲染列表（含洞号/地址，那才是真信息）。

        # 标题就是「代理」（三端一致）；原来的括号里那句
        # "-R：本机连出去；-L：本机 listen" 是用法解释，按"界面不写说明"去掉（-L/-R 语义见上面的模式选择行）
        _f, body = self.add_card("代理")
        body.addWidget(field_row(self, "目标地址", hint="127.0.0.1")[0])
        body.addWidget(field_row(self, "目标端口", hint="留空 = 运行时再填")[0])


class WireGuardPage(ConfigPage):
    """wireguard 页：实现三档 + My Interface + Peer 列表（Phase 1 骨架）。"""

    def __init__(self, host, parent=None):
        super().__init__(host, "wireguard", parent)

        _f, body = self.add_card("实现")
        row, grp = choice_buttons(self, ["自己实现", "官方库", "调系统程序"], "调系统程序")
        body.addWidget(field_row(self, "实现", row)[0])

        _f, body = self.add_card("My Interface")
        body.addWidget(field_row(self, "IP/掩码", hint="10.0.0.2/24")[0])
        body.addWidget(field_row(self, "端口", hint="51820")[0])
        body.addWidget(field_row(self, "私钥", hint="（生成）")[0])
        btn = QPushButton("生成", self)
        btn.setFixedHeight(28)
        btn.clicked.connect(lambda: self.host.log("wireguard：生成密钥对（Phase 1 只写日志）"))
        body.addWidget(btn)

        _f, body = self.add_card("Peer 1")
        body.addWidget(field_row(self, "Endpoint", hint="IP:Port")[0])
        body.addWidget(field_row(self, "Peer公钥", hint="")[0])
        body.addWidget(field_row(self, "Preshared", hint="（可选）")[0])
        body.addWidget(field_row(self, "AllowedIPs", hint="0.0.0.0/0")[0])
        row = QWidget(self)
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        b1 = QPushButton("+ 添加 Peer", row)
        b2 = QPushButton("启动 WireGuard", row)
        b3 = QPushButton("外部 VPN 应用", row)
        for b in (b1, b2, b3):
            b.setFixedHeight(28)
            b.clicked.connect(lambda _=False, n=b.text(): self.host.log(f"wireguard：{n}（Phase 1 只写日志）"))
            h.addWidget(b)
        h.addStretch(1)
        body.addWidget(row)


class VpnPage(ConfigPage):
    """vpn 页：一对一（= switch 去掉拓扑卡；状态与启停并进配置卡首行，内嵌 DHCP 开关也在配置卡）。

    一对一 = 一个洞 ↔ 一块 tun/tap（这句原来显示在配置卡首行，按"界面不写说明"的要求改成注释）。
    """

    def __init__(self, host, parent=None):
        super().__init__(host, "vpn", parent)

        # 配置卡：不画标题行，「配置」这个标题由首行承担（= 与 DHCP 卡首行同一套容器/内边距）
        _f, cfg_body = self.add_card("配置", render_title=False)
        self.lab_state = QLabel(channels_state_text(0), self)      # 空态 = 未接线
        self.lab_state.setObjectName("note")
        self.btn_toggle = QPushButton("启动", self)
        self.btn_toggle.setFixedHeight(CARD_HEAD_H)
        self.btn_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_toggle.clicked.connect(lambda: self.host.log("vpn：启动（Phase 1 只写日志）"))
        # 首行左侧固定是「配置」（三端一致）。原来这里放的是
        # "一对一：一个洞 ↔ 一块 tun/tap" —— 那是"删说明"那轮该删的啰嗦说明，已改成注释（见类 docstring）。
        self.row_cfg = card_head_row(self, "配置",
                                     state_widget=self.lab_state, control=self.btn_toggle)
        cfg_body.addWidget(self.row_cfg)

        row, grp = choice_buttons(self, ["none", "tun", "tap"], "tun")
        cfg_body.addWidget(field_row(self, "card 设备", row)[0])
        cfg_body.addWidget(field_row(self, "tun 地址", hint="10.0.0.2/24")[0])
        row, grp = choice_buttons(self, ["l2", "l3", "auto"], "l3")
        cfg_body.addWidget(field_row(self, "交换模式", row)[0])
        cfg_body.addWidget(field_row(self, "MTU", hint="1400")[0])
        cfg_body.addWidget(field_row(self, "路由老化", hint="300 s")[0])
        # 原来这里有一行 `通道：还没有`：空态已经由本卡首行右侧的状态（`未接线`）表达，重复 → 三端一致删掉。
        # 将来有真实通道数据时，在这里按 `if channels:` 条件渲染列表。

        # 内嵌 DHCP 卡（默认隐藏，由配置卡最后一行那个开关控制显隐）
        self.f_dhcp, dhcp_body = self.add_card("嵌入 DHCP 服务器", render_title=False)
        lab_ni = QLabel("尚未实现", self)
        lab_ni.setObjectName("note")
        self.row_dhcp = card_head_row(self, "嵌入 DHCP 服务器", state_widget=lab_ni)
        dhcp_body.addWidget(self.row_dhcp)
        dhcp_body.addWidget(field_row(self, "地址池", hint="10.0.0.100-10.0.0.200")[0])
        dhcp_body.addWidget(field_row(self, "网关", hint="10.0.0.1")[0])
        dhcp_body.addWidget(field_row(self, "DNS", hint="10.0.0.1")[0])
        dhcp_body.addStretch(1)     # 卡片被纵向拉伸时，多余高度落到弹簧上（别摊给首行）

        # 配置卡**最后一行**：内嵌 DHCP 开关（放在 DHCP 卡前面，视觉上"这行开启下面那张卡"）
        self.sw_dhcp = self.add_dhcp_toggle(cfg_body, self.f_dhcp)


class SwitchPage(ConfigPage):
    """
    switch 页：m 对 n（对应 client/app/switch.py）。

    版式（三端一致）：**配置卡（首行最右侧是启停按钮）→ 嵌入 DHCP 服务器 → 拓扑卡（放最后）**。
    「拓扑」卡画的是这台虚拟交换机的**连接拓扑**：一行"网口"格子，每插进来一个洞就多一格；
    0 个时留一个虚线空位表示空槽位（点格子 = 拔线，Phase 3 接线后生效）。
    """

    def __init__(self, host, parent=None):
        super().__init__(host, "switch", parent)

        # ── 配置卡：首行 = 标题 + 状态 + 弹簧 + 启停（和 DHCP 卡首行同一套容器）──
        _f, cfg_body = self.add_card("配置", render_title=False)
        self.lab_ports = QLabel(ports_state_text(0), self)      # 空态 = 未插线
        self.lab_ports.setObjectName("note")
        self.btn_toggle = QPushButton("启动", self)
        self.btn_toggle.setFixedHeight(26)
        self.btn_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_toggle.clicked.connect(lambda: self.host.log("switch：启动（Phase 1 只写日志）"))
        # 首行左侧固定是「配置」（三端一致）；"虚拟交换机"这个说法只在注释/docstring 里
        self.row_cfg = card_head_row(self, "配置",
                                     state_widget=self.lab_ports, control=self.btn_toggle)
        cfg_body.addWidget(self.row_cfg)

        row, grp = choice_buttons(self, ["none", "tun", "tap"], "tun")
        cfg_body.addWidget(field_row(self, "card 设备", row)[0])
        cfg_body.addWidget(field_row(self, "tun 地址", hint="192.168.250.55/24")[0])
        row, grp = choice_buttons(self, ["l2", "l3", "auto"], "l3")
        cfg_body.addWidget(field_row(self, "交换模式", row)[0])
        cfg_body.addWidget(field_row(self, "MTU", hint="1400")[0])
        cfg_body.addWidget(field_row(self, "路由老化", hint="300 s")[0])

        # ── 嵌入 DHCP 卡（默认隐藏，由配置卡最后一行那个开关控制显隐）──
        self.f_dhcp, dhcp_body = self.add_card("嵌入 DHCP 服务器", render_title=False)
        lab_ni = QLabel("尚未实现", self)
        lab_ni.setObjectName("note")
        self.row_dhcp = card_head_row(self, "嵌入 DHCP 服务器", state_widget=lab_ni)
        dhcp_body.addWidget(self.row_dhcp)
        dhcp_body.addWidget(field_row(self, "地址池", hint="192.168.250.100-192.168.250.200")[0])
        dhcp_body.addWidget(field_row(self, "网关", hint="192.168.250.55")[0])
        dhcp_body.addWidget(field_row(self, "DNS", hint="192.168.250.55")[0])
        dhcp_body.addStretch(1)     # 卡片被纵向拉伸时，多余高度落到弹簧上（别摊给首行）

        # 配置卡最后一行：内嵌 DHCP 开关
        self.sw_dhcp = self.add_dhcp_toggle(cfg_body, self.f_dhcp)

        # ── 拓扑卡（放最后）：只有可视化，不再放启停按钮 ──
        _f, body = self.add_card("拓扑")
        ports = row_fixed(QWidget(self))
        hp = QHBoxLayout(ports)
        hp.setContentsMargins(0, 0, 0, 0)
        hp.setSpacing(4)
        empty = QLabel(ports_state_text(0), ports)   # 空位也用同一个词：未插线
        empty.setObjectName("portEmpty")
        empty.setFixedHeight(28)
        empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty.setStyleSheet(
            f"border: 1px dashed {C_BORDER_DIM}; color: {C_TEXT_DIM};"
            f" border-radius: 6px; padding: 0 12px;"
        )
        hp.addWidget(empty)
        hp.addStretch(1)
        body.addWidget(ports)
        body.addWidget(section_note(self, "点网口 = 拔线"))


PAGE_CLASSES = [HomePage, MediaPage, ProxyPage, WireGuardPage, VpnPage, SwitchPage]


# ==========================================================================================
# 5. 日志浮层（右下角「日志」胶囊 + 90% 面板 + 从按钮长出来的动画；折叠时不吞点击）
# ==========================================================================================

class LogOverlay(QWidget):
    """
    应用级日志浮层，盖在**所有页面之上**（对应手机端的 ui/AppLogOverlay.kt）。

    - 折叠：整层 `hide()`（**不是**靠 WA_TransparentForMouseEvents —— 那个属性会连子控件一起
      禁用鼠标事件，胶囊按钮自己就点不动了），只留右下角那颗「日志」胶囊；
      胶囊因此必须是本浮层的**兄弟**节点（挂在 ContentArea 上），否则会跟着一起被隐藏；
    - 展开：深色遮罩 + 居中 90% 面板（标题 "App 内日志" + 清空 / 📋复制 / ✕）；
    - 动画：Qt 的 QWidget 没有 QTransform 缩放，所以用
      **QVariantAnimation 插值几何矩形**（从胶囊的矩形长到目标矩形）+ QGraphicsOpacityEffect 淡入，
      视觉上就是"从右下角按钮放大出来"，和手机端 260ms 的观感一致。
    """

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.expanded = False
        self.progress = 0.0
        self.pill: QPushButton | None = None   # 由 attach_pill() 挂进来（是兄弟节点，见类注释）

        # ── 遮罩 ──
        self.scrim = QWidget(self)
        self.scrim.setStyleSheet("background: rgba(0, 0, 0, 140);")
        self.scrim_effect = QGraphicsOpacityEffect(self.scrim)
        self.scrim_effect.setOpacity(0.0)
        self.scrim.setGraphicsEffect(self.scrim_effect)

        # ── 面板 ──
        self.panel = QFrame(self)
        self.panel.setObjectName("logPanel")
        self.panel.setStyleSheet(
            f"QFrame#logPanel {{ background: {C_WINDOW}; border: 1px solid {BORDER_CARD};"
            f" border-radius: 12px; }}"
        )
        self.panel_effect = QGraphicsOpacityEffect(self.panel)
        self.panel_effect.setOpacity(0.0)
        self.panel.setGraphicsEffect(self.panel_effect)

        pv = QVBoxLayout(self.panel)
        pv.setContentsMargins(12, 10, 12, 12)
        pv.setSpacing(6)
        head = QWidget(self.panel)
        ph = QHBoxLayout(head)
        ph.setContentsMargins(0, 0, 0, 0)
        title = QLabel("App 内日志", head)
        title.setObjectName("panelTitle")
        ph.addWidget(title)
        ph.addStretch(1)
        self.btn_clear = QPushButton("清空", head)
        self.btn_copy = QPushButton("📋复制", head)
        self.btn_close = QPushButton("✕", head)
        for b in (self.btn_clear, self.btn_copy, self.btn_close):
            b.setFixedHeight(26)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            ph.addWidget(b)
        pv.addWidget(head)

        self.text = QTextEdit(self.panel)
        self.text.setReadOnly(True)
        self.text.setFont(make_font(11, mono=True))
        self.text.setPlaceholderText("暂无日志")
        self.text.setStyleSheet(
            f"QTextEdit {{ background: {C_WINDOW}; color: {C_TEXT};"
            f" border: 1px solid {C_BORDER_DIM}; border-radius: 6px; }}"
        )
        pv.addWidget(self.text, 1)

        self.btn_clear.clicked.connect(self.clear)
        self.btn_copy.clicked.connect(self.copy_all)
        self.btn_close.clicked.connect(self.collapse)

        # 折叠状态起步（一开始就隐藏，页面点击不会被挡）
        self.hide()

        # ── 动画 ──
        self.anim = QVariantAnimation(self)
        self.anim.setStartValue(0.0)
        self.anim.setEndValue(1.0)
        self.anim.setDuration(LOG_ANIM_MS)
        self.anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.anim.valueChanged.connect(self.apply_progress)
        self.anim.finished.connect(self._on_anim_finished)

    def attach_pill(self, pill: QPushButton) -> None:
        """
        挂上右下角那颗「日志」胶囊。

        它必须是浮层的**兄弟**（父是 ContentArea），因为折叠时浮层会 hide()，
        挂在浮层下面的话胶囊会跟着消失。位置仍由本类的 relayout() 负责摆。
        """
        self.pill = pill
        pill.clicked.connect(self.toggle)
        self.relayout()

    # ── 几何：overlay 铺满内容区，每次 resize（或内容区主动调用）重算 ──
    def relayout(self) -> None:
        """按当前尺寸摆好：遮罩铺满、胶囊贴右下角、面板按 progress 插值。"""
        self.scrim.setGeometry(0, 0, self.width(), self.height())
        if self.pill is not None:
            self.pill.move(
                self.width() - LOG_BTN_W - 16,
                self.height() - LOG_BTN_H - 16,
            )
        self._layout_panel(self.progress)

    def resizeEvent(self, e) -> None:  # noqa: N802
        self.relayout()
        super().resizeEvent(e)

    def _target_rect(self) -> QRect:
        w = int(self.width() * LOG_PANEL_RATIO)
        h = int(self.height() * LOG_PANEL_RATIO)
        return QRect((self.width() - w) // 2, (self.height() - h) // 2, w, h)

    def _start_rect(self) -> QRect:
        # 从胶囊的矩形"长出来"（右下角），视觉上和手机端的 scale 原点(1,1) 等价
        if self.pill is not None:
            return QRect(self.pill.x(), self.pill.y(), LOG_BTN_W, LOG_BTN_H)
        return QRect(self.width() - LOG_BTN_W - 16, self.height() - LOG_BTN_H - 16,
                     LOG_BTN_W, LOG_BTN_H)

    def _layout_panel(self, p: float) -> None:
        s, t = self._start_rect(), self._target_rect()
        r = QRect(
            int(s.x() + (t.x() - s.x()) * p),
            int(s.y() + (t.y() - s.y()) * p),
            int(s.width() + (t.width() - s.width()) * p),
            int(s.height() + (t.height() - s.height()) * p),
        )
        self.panel.setGeometry(r)

    def apply_progress(self, p: float) -> None:
        """
        动画每一帧：插值面板几何 + 遮罩/面板透明度。

        **不碰** WA_TransparentForMouseEvents：那个属性在 Qt 里会连**子控件**一起禁用鼠标事件
        （官方文档原文："disables the delivery of mouse events to the widget and its children"），
        用它就会把胶囊/面板上的按钮一起点不动。所以"折叠不挡点击"是靠**整层 hide()** 实现的。
        """
        self.progress = float(p)
        self._layout_panel(self.progress)
        self.panel_effect.setOpacity(self.progress)
        self.scrim_effect.setOpacity(0.55 * self.progress)

    def _on_anim_finished(self) -> None:
        if not self.expanded:
            # 收起完把**整层**藏掉：这样内容区里就只剩胶囊一个可点控件，页面完全不受影响
            self.hide()

    # ── 交互 ──
    def toggle(self) -> None:
        self.set_expanded(not self.expanded)

    def collapse(self) -> None:
        self.set_expanded(False)

    def set_expanded(self, want: bool) -> None:
        self.expanded = want
        if want:
            self.show()          # 折叠时整层是 hide 的，展开要先显出来
            self.scrim.show()
            self.panel.show()
            self.panel.raise_()  # 面板在遮罩之上
            if self.pill is not None:
                self.pill.raise_()   # 胶囊始终可点（点它收起）
        self.anim.stop()
        self.anim.setStartValue(self.progress)
        self.anim.setEndValue(1.0 if want else 0.0)
        self.anim.start()

    def append(self, line: str) -> None:
        self.text.append(line)
        self.text.verticalScrollBar().setValue(self.text.verticalScrollBar().maximum())

    def clear(self) -> None:
        self.text.clear()

    def copy_all(self) -> None:
        QApplication.clipboard().setText(self.text.toPlainText())
        self.append("desktop: 已复制到剪贴板")

    def summary(self) -> str:
        return (
            f"日志浮层：{'展开' if self.expanded else '折叠'}"
            f"（整层 {'hidden' if self.isHidden() else 'visible'}） progress={self.progress:.2f}，"
            f"胶囊={LOG_BTN_W}x{LOG_BTN_H} @ 右下角（父={type(self.pill.parent()).__name__ if self.pill else '未挂'}），"
            f"面板目标=内容区 {int(LOG_PANEL_RATIO*100)}% "
            f"（{self._target_rect().width()}x{self._target_rect().height()}），动画={LOG_ANIM_MS}ms"
        )


# ==========================================================================================
# 6. 系统托盘常驻（QSystemTrayIcon，0 额外安装；不可用时优雅降级）
# ==========================================================================================

class Tray(QObject):
    """
    操作系统托盘/菜单栏常驻图标。

    - 图标**用代码画**（make_state_icon），不新增 png 文件；灰/黄/绿对应 未连接/连接中/已登录；
    - tooltip：`p2pnet · 未连接` 这类一行摘要；
    - 右键菜单：显示主窗口 / 连接 / 断开 / 退出登录 / 查看日志 / 退出（Phase 1 都写日志）；
    - `isSystemTrayAvailable() == False` 时**优雅降级**：不建图标，并把"✕ 收托盘"关掉
      （改成真退出），否则窗口一关用户就找不回来了。
    """

    def __init__(self, host: "MainWindow"):
        super().__init__(host)
        self.host = host
        self.available = QSystemTrayIcon.isSystemTrayAvailable()
        self.icon: QSystemTrayIcon | None = None
        self.state = STATE_UNCONNECTED
        self._build()

    def _build(self) -> None:
        if not self.available:
            return
        self.icon = QSystemTrayIcon(make_state_icon(self.state), self.host)
        self.icon.setToolTip(self.tooltip_text())

        menu = QMenu(self.host)
        acts = [
            ("显示主窗口", self.host.show_from_tray),
            ("连接", lambda: (self.tray_note("托盘：连接"), self.host.connect_engine())),
            ("断开", lambda: (self.tray_note("托盘：断开"), self.host.engine.disconnect())),
            ("退出登录", lambda: (self.tray_note("托盘：退出登录"), self.host.engine.logout())),
            ("查看日志", self.host.open_log),
            (None, None),
            ("退出", self.host.quit_app),
        ]
        for label, slot in acts:
            if label is None:
                menu.addSeparator()
                continue
            act = QAction(label, menu)
            act.triggered.connect(slot)
            menu.addAction(act)
        self.icon.setContextMenu(menu)
        self.icon.activated.connect(self._on_activated)
        self.icon.show()

    def _on_activated(self, reason) -> None:
        # 左键单击/双击图标 = 显示主窗口（Windows/Linux 常见习惯）
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self.host.show_from_tray()

    def tray_note(self, text: str) -> None:
        self.host.log(text)

    def tooltip_text(self) -> str:
        return f"{APP_NAME} · {STATE_TEXT[self.state]}"

    def set_state(self, state: str) -> None:
        self.state = state
        if self.icon is not None:
            self.icon.setIcon(make_state_icon(state))
            self.icon.setToolTip(self.tooltip_text())

    def notify(self, text: str) -> None:
        """系统通知（Win10+ 是 toast、macOS 进通知中心）；不可用时退回日志。"""
        if self.icon is not None and QSystemTrayIcon.supportsMessages():
            self.icon.showMessage(APP_NAME, text, QSystemTrayIcon.MessageIcon.Information, 2500)
        else:
            self.host.log(f"（无法弹系统通知，改为日志）{text}")

    def summary(self) -> str:
        if not self.available:
            return "托盘：不可用 → 降级为「✕ 真退出」（offscreen 下正常现象）"
        return f"托盘：可用（{self.icon.toolTip()}），右键菜单 6 项 + 分隔线"


# ==========================================================================================
# 7. 引擎桥（**导入 client.py 调它的函数**，不开 client.py 子进程）
# ==========================================================================================

class _StreamRelay:
    """
    把 client.py 的 stdout / stderr 接进 Qt 信号 —— **tee**：终端照旧有输出，同时进日志浮层。

    为什么用重定向而不是 monkeypatch `client.log`：`log()` 内部还有
    `hole_core.finish_open()` 的副作用，覆盖它会破坏打洞步骤行的收尾；
    而 client.py 的日志、hole/ 的打洞步骤、所有 `print` 最终都走 stdout，
    所以重定向 stdout 是最干净的一刀 —— **不用改 client.py，也不用正则解析子进程输出**。
    """

    def __init__(self, emit, fallback_stream):
        self._emit = emit
        self._fallback = fallback_stream
        self._buf = ""
        self.encoding = "utf-8"

    def write(self, text: str) -> int:
        try:
            self._fallback.write(text)
            self._fallback.flush()
        except Exception:
            pass
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line.strip():
                self._emit(line.rstrip())
        return len(text)

    def flush(self) -> None:
        try:
            self._fallback.flush()
        except Exception:
            pass


class EngineBridge(QObject):
    """
    进程内引擎桥：**导入 client.py 直接调它的函数**，不启动 client.py 子进程。

    为什么这么接（三条约束决定的）：
      1) 全部 client.py 调用串行化到**一条引擎线程**：client.py 原本是单线程 select 循环写的，
         `ws_send` / `process_input_line` 都不是线程安全的；GUI 只往 `queue.Queue` 投命令，
         由引擎线程取出后调 `process_input_line(...)`（= REPL 的等价物）。
      2) **日志汇流**靠重定向 sys.stdout（tee），不改 client.py。
      3) 收帧照抄 client.py `main()` 里那四步：`recv` → `recv_buf += data` →
         `while ws_recv()` → `handle_server_message(obj)`。

    "用法"程序（`app/vpn.py` / `app/switch.py` 等）仍由 client.py 自己按原样后台拉起，
    它们本来就是独立程序，不属于本桥的范围。
    """

    line = pyqtSignal(str)             # client.py（含 hole/ 与所有 print）的每一行输出
    state_changed = pyqtSignal(str)    # STATE_UNCONNECTED / STATE_CONNECTING / STATE_LOGGED_IN
    engine_stopped = pyqtSignal(str)   # 引擎线程结束的原因
    peers_changed = pyqtSignal(list)   # list_result 里解析出的在线用户
    holes_changed = pyqtSignal(list)   # cli.holes 的快照（洞表）
    me_changed = pyqtSignal(str, int)  # 服务器眼里我的公网 ip/port（我卡标题用）

    def __init__(self, host: "MainWindow"):
        super().__init__(host)
        self.host = host
        self.cli = None                    # 被导入的 client 模块
        self.sock = None
        self.thread: threading.Thread | None = None
        self.running = False
        self.cmd_queue: "queue.Queue[str]" = queue.Queue()
        self._relay: _StreamRelay | None = None
        self._saved_streams: tuple = ()
        # 步骤打勾：{洞号: {步序: 是否完成}}。来源是被中继的步骤行
        # （形如 `[洞 #1 bob] [1/6] 正在通知服务器  （✓）`）—— 这是进程内文本，不是子进程输出。
        self.hole_steps: dict[int, dict[int, bool]] = {}
        # direct 的"可达地址"结果行（hole/direct.py 319 行：`[direct] bob 可达地址: 1.2.3.4, …`）
        self.direct_notes: dict[str, str] = {}

        # 输入过的用户名（list 过滤自己时，作为 cli.logged_in_user 的兜底，对齐安卓 ifBlank{username}）
        self.login_user: str | None = None
        self._holes_sig: tuple = ()
        # ── WS 自动重连（带熔断）状态 ──
        self._host: str | None = None        # 记下连接参数，重连要用
        self._port: int = 0
        self._debug = False
        self._manual_disconnect = False      # 用户点过"断开" → 不自动重连
        self._closing = False                # shutdown() → 停止一切重连
        self._reconnect_thread: threading.Thread | None = None
        self._connected_at = 0.0             # 本次连接建立时刻（稳定 60s → 计数重置）

    # ── 装载：只导入 + 接线，不联网 ──
    def load(self) -> bool:
        """导入 client.py（同目录）、注入 hole/ 钩子、把 stdout 接过来。全程不联网。"""
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)      # client.py 要 `from hole import ...`，必须能 import 到
        # 不让 import 在源码树里撒 __pycache__/*.pyc（导入 client 会连带导入 hole/*）
        sys.dont_write_bytecode = True
        import client as cli               # noqa: PLC0415  （故意延迟到运行时导入）
        self.cli = cli
        cli._hole_configure()             # 把日志/WS/建洞记录/回调注入 hole/（惰性闭包，未连接也安全）
        cli.NEW_WINDOW = False            # 用法子进程别开新终端窗口
        cli.CLOSE_WINDOW = False
        self._install_relay()
        self.line.emit(
            f"desktop: 已导入 client.py（__name__={cli.__name__}），调用它的函数，不开子进程"
        )
        return True

    def _install_relay(self) -> None:
        real_out, real_err = sys.stdout, sys.stderr
        self._saved_streams = (real_out, real_err)
        self._relay = _StreamRelay(self._on_engine_line, real_out)
        sys.stdout = self._relay
        sys.stderr = self._relay

    def _on_engine_line(self, text: str) -> None:
        """每一行引擎输出：① 顺手解析打洞步骤行 ② 转发给日志浮层"""
        m = _DIRECT_NOTE_RE.search(text)
        if m:
            self.direct_notes[m.group(1)] = "可达地址: " + m.group(2).strip()
        m = _STEP_LINE_RE.search(text)
        if m:
            hole_id, step, total, ok = int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4) == "✓"
            per = self.hole_steps.setdefault(hole_id, {})
            if per.get(step) != ok:
                per[step] = ok
        self.line.emit(text)

    def step_done(self, hole_id) -> dict:
        return dict(self.hole_steps.get(int(hole_id or 0), {}))

    def _restore_streams(self) -> None:
        if self._saved_streams:
            sys.stdout, sys.stderr = self._saved_streams

    # ── 命令派发（引擎线程与 self-test 都走这一条路）──
    def dispatch(self, line: str) -> bool:
        """真正调用 client.py 的 REPL 等价物；返回 keep（False = 该退出）。"""
        if self.cli is None:
            return False
        try:
            keep = self.cli.process_input_line(line)
        except Exception as exc:           # client.py 抛错不该把界面带崩
            self.line.emit(f"desktop: 调用 client.py 出错（{line!r}）：{exc!r}")
            return True
        return keep is not False

    def command(self, line: str | tuple) -> None:
        """
        GUI 侧接口：只投队列（字符串 = REPL 命令；元组 = 内部动作，如应用层 ping）。
        引擎线程没在跑时（--self-test）直接同步派发，走的是同一条处理路径。
        """
        if self.thread is not None and self.thread.is_alive():
            self.cmd_queue.put(line)
        else:
            self.dispatch_item(line)

    def dispatch_item(self, item: str | tuple) -> bool:
        """引擎线程里真正的入口。现在只有字符串命令（心跳和 ping 都下沉到 client.py 了）。"""
        if isinstance(item, tuple):     # 兜底：留着旧元组命令不至于炸
            return self._dispatch_internal(item)
        return self.dispatch(item)

    def _dispatch_internal(self, item: tuple) -> bool:
        self.line.emit(f"desktop: 未知的内部动作 {item[0]!r}（GUI 已不再自己实现 ping）")
        return True

    # ── 连接 / 引擎线程 ──
    def connect(self, host: str, port: int, debug: bool = False) -> None:
        if self.thread is not None and self.thread.is_alive():
            self.line.emit("desktop: 已经在连着/连上了，先断开再重连")
            return
        if self.cli is None and not self.load():
            return
        self._host, self._port, self._debug = host, int(port), debug
        self._manual_disconnect = False
        if self.cli is not None:
            self.cli.mark_user_connect()       # 手动连接：清"被踢/主动退出"状态 + 清零计数（实现在 client.py）
        self.thread = threading.Thread(
            target=self._run, args=(host, int(port), debug), name="p2pnet-engine", daemon=True
        )
        self.thread.start()

    def _connect_once(self, host: str, port: int, debug: bool) -> bool:
        """建 socket + WS 握手（握手成功后 client.py 自己会起心跳）。成功返回 True。"""
        cli = self.cli
        cli.SERVER_IP, cli.SERVER_PORT, cli.DEBUG = host, port, debug
        self.state_changed.emit(STATE_CONNECTING)
        try:
            sock = socket.create_connection((host, port), timeout=10)
        except Exception as exc:
            self.line.emit(f"desktop: 连接 {host}:{port} 失败：{exc}")
            self.state_changed.emit(STATE_UNCONNECTED)
            return False
        sock.settimeout(None)
        self.sock = sock
        # 照 client.py main() 的做法把全局状态接上
        cli.ws_sock = sock
        cli.recv_buf = b""
        cli.connected = True
        try:
            # 握手成功后 **client.py 自己会起 WS 心跳**（start_ws_heartbeat 在 ws_handshake 里），
            # GUI 不需要也不应该自己发 ping。
            cli.ws_handshake(sock, host, port)
        except Exception as exc:
            self.line.emit(f"desktop: WebSocket 握手失败：{exc}")
            self._close_sock()
            self.state_changed.emit(STATE_UNCONNECTED)
            return False
        self._connected_at = time.time()
        self.line.emit(f"desktop: 已连接 {host}:{port}（ws{'' if not debug else ' + debug'}），等待登录")
        return True

    def _run(self, host: str, port: int, debug: bool) -> None:
        """引擎线程入口（首次连接 / 用户手动连接）。首次连接失败**不**自动重连。"""
        if not self._connect_once(host, port, debug):
            self.engine_stopped.emit("连接失败")
            return
        self.thread = threading.current_thread()
        self._serve_until_disconnect()

    def _serve_until_disconnect(self, reason: str = "引擎线程结束") -> None:
        """
        跑读循环，直到断开/判死/被停；收尾后按策略决定要不要自动重连。

        ⚠️ 必须 try/finally：循环里任何未预期异常（消息处理、socket 层…）如果直接逃出，
        引擎线程会**静默死掉** → `_teardown` 与 `_maybe_reconnect` 都不执行 →
        UI 就一直显示"已连接"、也永不重连（用户报过的那类现象）。
        """
        self.running = True
        try:
            self._engine_loop(self.sock)
        except Exception as exc:
            self.line.emit(f"desktop: 引擎循环异常（按断开处理）：{exc!r}")
        finally:
            self._teardown(reason)
            self._maybe_reconnect()

    # ── WS 自动重连（带熔断）── 实现全在 client.py（`ws_auto_reconnect`），GUI 只负责起线程 + 收尾。
    def _reconnect_plan(self, now: float):
        """决策（第 N 次, 等待秒数）或 None（= 熔断）。直接问 client.py，别在这里重复一套策略。"""
        if self.cli is None:
            return None
        return self.cli.ws_reconnect_plan(now)

    def _maybe_reconnect(self) -> None:
        """断开收尾后被调用：该不该自动重连由 client.py 决定，这里只做"起一条重连线程"。"""
        if self._closing or self._manual_disconnect:
            return
        if self._host is None or self.cli is None:
            return
        if not self.cli.reconnect_allowed():
            # ② 被服务器踢下线 / ① 用户主动断开：不起重连线程
            return
        if self._reconnect_plan(time.time()) is None:
            # 熔断：正常路径下这行日志由 client.py 的 ws_auto_reconnect 打；
            # 但"重连成功之后又掉线、而窗口已经用满"这种情况下 worker 不会再进循环，
            # 所以这里补一次（同一份文案，不会重复，因为那条路径已经 return 了）
            self.line.emit(self.cli.WS_RECONNECT_GIVEUP_TEXT)
            return
        if self._reconnect_thread is not None and self._reconnect_thread.is_alive():
            return
        self._reconnect_thread = threading.Thread(
            target=self._reconnect_worker, args=(self._host, self._port, self._debug),
            name="p2pnet-reconnect", daemon=True,
        )
        self._reconnect_thread.start()

    def _reconnect_worker(self, host: str, port: int, debug: bool) -> None:
        """重连线程：循环/退避/熔断/日志全部由 `client.py` 的 `ws_auto_reconnect()` 负责。"""
        cli = self.cli
        cli.SERVER_IP, cli.SERVER_PORT, cli.DEBUG = host, port, debug
        ok = cli.ws_auto_reconnect(
            host, port,
            should_stop=lambda: self._closing or self._manual_disconnect,
        )
        if not ok or self._closing or self._manual_disconnect:
            return
        self.thread = threading.current_thread()      # 这条线程接着当引擎线程
        self.sock = cli.ws_sock
        self._connected_at = time.time()
        self._restore_login()
        self._serve_until_disconnect("重连后的引擎线程结束")

    def _restore_login(self) -> None:
        """重连成功后恢复登录 —— 直接调 `client.py` 的 `resume_login()`（命令行走同一份）。"""
        if self.cli is not None:
            self.cli.resume_login()

    def _engine_loop(self, sock: "socket.socket") -> None:
        cli = self.cli
        while self.running:
            # 0) 判活交给 client.py 的 WS 心跳：它判死后会把 cli.connected 置 False
            if not getattr(cli, "connected", True):
                self.line.emit("desktop: 连接已断开（client.py 心跳判定）")
                break
            # 1) 先处理 GUI 投进来的命令（串行化：client.py 只被这一条线程调用）
            while True:
                try:
                    cmd = self.cmd_queue.get_nowait()
                except queue.Empty:
                    break
                if self.dispatch_item(cmd) is False:
                    self.running = False
                    break
                self._emit_holes()
            if not self.running:
                break
            # 2) 收数据（50ms 超时，保证命令响应及时、也能干净退出）
            try:
                ready, _, _ = select.select([sock], [], [], 0.05)
            except Exception:
                break
            if not ready:
                continue
            try:
                data = sock.recv(65536)
            except Exception as exc:
                self.line.emit(f"desktop: 收包出错：{exc!r}")
                break
            if not data:
                self.line.emit("desktop: 连接已被对端/服务器关闭")
                break
            # 判活只看"有没有字节进来"：通知一声 client.py 的心跳（pong 帧也算）。
            # ⚠️ 这是 GUI 为心跳**唯一**要做的接线，心跳实现全在 client.py 里。
            cli.note_ws_rx()
            cli.recv_buf = cli.recv_buf + data
            while True:
                msg = cli.ws_recv()
                if msg is None:
                    break
                try:
                    obj = json.loads(msg)
                except Exception:
                    obj = {"raw": msg}
                try:
                    self._observe(obj)
                    cli.handle_server_message(obj)
                    self._emit_holes()
                except Exception as exc:
                    # 单条消息/单次 UI 更新出错不该断开连接，更不该静默打死引擎线程
                    self.line.emit(f"desktop: 处理服务器消息出错（已跳过这条）：{exc!r}")

    def _emit_holes(self) -> None:
        """cli.holes 的快照 → 界面（只在真的变了才发，别每 50ms 刷一次界面）"""
        holes = getattr(self.cli, "holes", None) if self.cli else None
        if holes is None:
            return
        sig = tuple((h.get("id"), h.get("status"), h.get("handed_to"), h.get("my_port"),
                     h.get("peer"), h.get("peer_port")) for h in holes)
        if sig == self._holes_sig:
            return
        self._holes_sig = sig
        self.holes_changed.emit([dict(h) for h in holes])

    def _observe(self, obj: dict) -> None:
        """
        在调用 handle_server_message 之前先看一眼 type —— 这样不用 monkeypatch 任何东西。

        应用层 pong **不在这里**处理：client.py 的 handle_server_message 会打日志（含 RTT）。
        """
        t = obj.get("type")
        if t == "login_ok":
            self.state_changed.emit(STATE_LOGGED_IN)
        elif t == "kicked":
            # ② 被踢 = 登录被取消，**连接还在**：所以状态回"已连接/未登录"，而不是未连接
            self.state_changed.emit(STATE_CONNECTING)
            self.peers_changed.emit([])
            self.me_changed.emit("", 0)
        elif t == "logout_ok":
            # 仍连着 WebSocket，只是不再处于登录态。
            # 照安卓 onLogout：peers 清空、myIp/myPort 归零（否则别人卡片会留在屏幕上）。
            self.state_changed.emit(STATE_CONNECTING)
            self.peers_changed.emit([])
            self.me_changed.emit("", 0)
            self.login_user = None
        elif t == "list_result":
            # 照安卓 LoginViewModel.tryParseListResult（922-954）：
            #   用户名等于自己的那条 → 「我」卡片的 ip/port；其余才生成其他人的卡片。
            users = obj.get("users") or []
            entries = [
                {"username": u.get("username", ""), "ip": u.get("ip", ""),
                 "port": int(u.get("port") or 0), "udp_port": int(u.get("udp_port") or 0)}
                for u in users if isinstance(u, dict) and u.get("username")
            ]
            me_name = (getattr(self.cli, "logged_in_user", None)
                       or self.login_user or "")
            mine = next((e for e in entries if e["username"] == me_name), None)
            if mine is not None:
                self.me_changed.emit(mine["ip"], mine["port"])
            self.peers_changed.emit([e for e in entries if e["username"] != me_name])
        elif t == "thisisyourpeer_udp":
            # 服务器眼里我的公网地址（「我」卡片标题用它）
            self.me_changed.emit(obj.get("my_ip", ""), int(obj.get("my_port") or 0))

    def login(self, username: str, password: str) -> None:
        """
        登录：把账号密码预置到 client.py 的 ARGS_USER / ARGS_PASS。

        为什么必须预置：`challenge` 到达时 client.py 会看 `ARGS_PASS`，没有就 `input("密码: ")`
        —— 那会在引擎线程里**阻塞等键盘**。预置后它直接取用（并且用完即清，见 client.py 1527-1531）。
        """
        if self.cli is None:
            return
        self.login_user = username
        self.cli.ARGS_USER = username
        self.cli.ARGS_PASS = password
        self.command(f"login {username}")

    def logout(self) -> None:
        self.command("logout")

    def disconnect(self) -> None:
        self._manual_disconnect = True     # 用户主动断开 → 不触发自动重连
        self.running = False
        self._close_sock()
        self.state_changed.emit(STATE_UNCONNECTED)
        # 安卓 onDisconnect：peers / 我的地址一起清掉，别留过期的卡片
        self.peers_changed.emit([])
        self.me_changed.emit("", 0)

    def shutdown(self) -> None:
        """退出前清理：停 hello 线程、关所有洞、关连接、恢复 stdout。"""
        cli = self.cli
        self._closing = True               # 退出 → 停止一切自动重连
        self.running = False
        try:
            if cli is not None:
                cli.hole_udp.stop_all_hellos()
                cli.close_all_holes("退出")
        except Exception:
            pass
        self._close_sock()
        t = self._reconnect_thread
        if t is not None and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=2.0)
        if self.thread is not None and self.thread.is_alive():
            self.thread.join(timeout=1.0)
        self._restore_streams()

    # ── 内部 ──
    def _close_sock(self) -> None:
        sock, self.sock = self.sock, None
        if sock is None:
            return
        try:
            if self.cli is not None:
                self.cli.connected = False
        except Exception:
            pass
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass

    def _teardown(self, reason: str) -> None:
        self.running = False
        # 会话收尾统一交给 client.py（记"断开前是否已登录"、稳定 60s 清零、清会话态、关 socket）
        if self.cli is not None:
            self.cli.mark_disconnected()
        self._close_sock()
        self.state_changed.emit(STATE_UNCONNECTED)
        self.peers_changed.emit([])
        self.me_changed.emit("", 0)
        self.engine_stopped.emit(reason)


# ==========================================================================================
# 8. 主窗口：无边框 + 标题栏 + 页面栈 + 日志浮层 + 边缘缩放
# ==========================================================================================

class ContentArea(QWidget):
    """
    内容区：里面是页面栈（QStackedWidget），**日志浮层覆盖在它之上**。

    浮层故意不放进布局（否则会被布局挤成一条），所以这里跟着自己的尺寸把它铺满：
    不这么做的话，浮层会永远停在 QWidget 的默认 100x30，看不见也点不到。
    """

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.overlay: "LogOverlay | None" = None
        # 「日志」胶囊：**故意挂在内容区**（浮层的兄弟），因为折叠时浮层整层 hide()，
        # 挂在浮层下面会跟着一起消失。样式/位置由 LogOverlay 负责。
        self.log_pill = QPushButton("日志", self)
        self.log_pill.setObjectName("logPill")
        self.log_pill.setFixedSize(LOG_BTN_W, LOG_BTN_H)
        self.log_pill.setCursor(Qt.CursorShape.PointingHandCursor)
        # 胶囊跟着新的深色规则走：黑底 + 高亮描边（原来那个亮蓝实心块在暗色里太吵）
        self.log_pill.setStyleSheet(
            f"QPushButton#logPill {{ background: {C_WINDOW}; color: {C_TEXT};"
            f" border: 1px solid {BORDER_CARD}; border-radius: 16px; }}"
            f"QPushButton#logPill:hover {{ border: 1px solid {C_BORDER_ACCENT}; color: {C_TAB_ON}; }}"
            f"QPushButton#logPill:pressed {{ background: {C_PRESSED}; }}"
        )

    def resizeEvent(self, e) -> None:  # noqa: N802
        if self.overlay is not None:
            self.overlay.setGeometry(0, 0, self.width(), self.height())
            # 隐藏状态下 setGeometry **不会**给子控件发 resize 事件（Qt 要到 show 才发），
            # 所以这里再补一次摆放，别指望事件顺序。
            self.overlay.relayout()
            self.log_pill.raise_()   # 胶囊永远在最上层（浮层展开时也要能点它收起）
        super().resizeEvent(e)


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        # 注意：下面的 setWindowFlag 会**立刻**触发 changeEvent，那时 title_bar 还没建好，
        # 所以先把属性占成 None，所有 override 里都判空（自绘窗口最容易踩这个构造期顺序坑）。
        self.title_bar = None
        # 无边框窗口必须自己保证"每个容器都真的画了背景"，否则未绘制区域会透出后面的程序：
        # QSS 的 background 对 QWidget 子类默认不生效，要配 WA_StyledBackground。
        self.setObjectName("mainWindow")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setWindowTitle(f"{APP_NAME} 桌面端")
        self.setMinimumSize(760, 520)
        self.resize(1080, 720)

        # 无边框：Windows/Linux 全靠自绘；macOS 同样自绘（理由见 TitleBar 的注释）
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        self.setMouseTracking(True)

        self._tray_hint_shown = False

        # ── 根布局：留出 RESIZE_MARGIN 的边，自己吃掉 → 边缘能触发 startSystemResize ──
        root = QVBoxLayout(self)
        root.setContentsMargins(RESIZE_MARGIN, RESIZE_MARGIN, RESIZE_MARGIN, RESIZE_MARGIN)
        root.setSpacing(0)

        self.title_bar = TitleBar(self)
        root.addWidget(self.title_bar)

        # 内容区（日志浮层盖在这一层之上 → 浮在**所有页面**之上）
        self.content = ContentArea(self)
        self.content.setObjectName("content")
        self.content.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.content.setStyleSheet(f"QWidget#content {{ background: {C_WINDOW}; }}")
        cv = QVBoxLayout(self.content)
        cv.setContentsMargins(0, 0, 0, 0)
        cv.setSpacing(0)
        self.stack = QStackedWidget(self.content)
        cv.addWidget(self.stack)
        # 浮层**不参与布局**（要能浮起来、能动画），所以由 ContentArea 跟着自己的尺寸手动铺满
        self.overlay = LogOverlay(self.content)
        self.overlay.attach_pill(self.content.log_pill)
        self.content.overlay = self.overlay
        root.addWidget(self.content, 1)

        # 全局样式（卡片、说明字、表单）
        self.setStyleSheet(self._stylesheet())

        # ── 6 个页面 ──
        self.pages: list[Page] = []
        for cls in PAGE_CLASSES:
            page = cls(self)
            if hasattr(page, "finish_layout"):
                page.finish_layout()     # 卡 body + 页 body 末尾补弹簧（内容顶对齐，不被拉伸）
            self.pages.append(page)
            self.stack.addWidget(page)
        self.title_bar.tab_clicked.connect(self.switch_page)

        # ── 托盘（offscreen / 无托盘环境下会自己降级）──
        self.tray = Tray(self)

        # ── 窗口按钮接线 ──
        self.title_bar.btn_min.clicked.connect(self.showMinimized)
        self.title_bar.btn_max.clicked.connect(self.toggle_maximize)
        self.title_bar.btn_close.clicked.connect(self.close)

        # ── 引擎桥：导入 client.py 调函数（不开子进程）──
        self.engine = EngineBridge(self)
        self.engine.line.connect(self.overlay.append)
        self.engine.state_changed.connect(self.set_state)
        self.engine.engine_stopped.connect(lambda why: self.log(f"引擎线程结束：{why}"))
        self.engine.load()

        # 引擎 → 主页：peers / 洞 / 我的地址 三条流水都推进自由层
        # （主页自己的按钮在 HomePage 里接线，这里只负责把数据接过去）
        self.home: HomePage = self.pages[0]  # type: ignore[assignment]
        self.engine.peers_changed.connect(self.home.set_peers)
        self.engine.holes_changed.connect(self.home.set_holes)
        self.engine.me_changed.connect(self.home.set_me)
        self._connected = False
        self._logged_in = False

        self.log(f"{APP_NAME} 桌面端 Phase 1 启动（自定义标题栏外壳）")
        self.log(f"平台：{sys.platform}｜托盘：{'可用' if self.tray.available else '不可用（已降级）'}")
        self.set_state(STATE_UNCONNECTED)

    # ── 样式 ──
    def _stylesheet(self) -> str:
        return f"""
        /* 全局：只设文字色。
           ⚠️ 这里**绝对不能**给 QWidget 设"透明背景" —— 顶层窗口自己也是 QWidget，
           那样会把整个窗口刷透（无边框窗口未绘制的区域会直接透出后面的程序，
           标题栏就是被这条坑掉的）。子控件默认不画背景，父窗口的黑色自然透上来，不需要它。 */
        QWidget {{ color: {C_TEXT}; }}
        /* 下面这几个容器都是 QWidget 子类：QSS 背景对它们默认不生效，
           必须同时 setAttribute(WA_StyledBackground)（见各 __init__），否则同样会透。 */
        QWidget#mainWindow, QWidget#titleBar, QWidget#content, QWidget#pageBody,
        QScrollArea, QScrollArea > QWidget > QWidget, QWidget#pageViewport {{
            background: {C_WINDOW}; }}
        QWidget#titleBar {{ background: {C_TITLE_BG}; }}

        /* 卡片：填充黑 + 1px 高亮描边（去掉边框就和背景糊在一起了） */
        QFrame#card {{ background: {C_CARD}; border: 1px solid {BORDER_CARD}; border-radius: 8px; }}
        QLabel#cardTitle {{ font-weight: 600; color: {C_TEXT}; }}
        QLabel#fieldLabel {{ color: {C_TEXT_DIM}; }}
        QLabel#note {{ color: {C_TEXT_DIM}; font-size: 11px; }}
        /* 服务器卡第一行的小字标签（只提示，位置与下面控件对齐） */
        QLabel#colLabel {{ color: {C_TEXT_DIM}; font-size: 11px; }}
        QLabel#panelTitle {{ font-weight: 600; color: {C_TEXT}; }}

        /* 自由层：和内容区同色（卡片靠高亮描边浮在它上面；它自己也要真的画，别留透的） */
        QWidget#freeLayer {{ background: {C_WINDOW}; }}

        /* 输入框 / 下拉框：黑底暗描边，聚焦转强调色 */
        QLineEdit, QComboBox, QSpinBox {{
            background: {C_WINDOW}; color: {C_TEXT};
            border: 1px solid {C_BORDER_DIM}; border-radius: 6px; padding: 0 6px;
            selection-background-color: {C_BORDER_ACCENT}; selection-color: #000000;
        }}
        QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{ border: 1px solid {C_BORDER_ACCENT}; }}
        QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {{
            background: {C_CARD}; color: {C_DISABLED_TEXT}; border: 1px solid {C_BORDER};
        }}
        /* 下拉弹层也要黑底浅字，否则弹出来还是白的 */
        QComboBox QAbstractItemView {{
            background: {C_WINDOW}; color: {C_TEXT};
            border: 1px solid {C_BORDER_ACCENT};
            selection-background-color: {C_BORDER_ACCENT}; selection-color: #000000;
            outline: none;
        }}

        /* 按钮：黑底 + 亮描边 + 浅字 */
        QPushButton {{
            background: {C_WINDOW}; color: {C_TEXT};
            border: 1px solid {BORDER_CARD}; border-radius: 6px; padding: 0 10px;
        }}
        QPushButton:hover {{ border: 1px solid {C_BORDER_ACCENT}; color: {C_TAB_ON}; }}
        QPushButton:pressed {{ background: {C_PRESSED}; }}
        QPushButton:disabled {{ color: {C_DISABLED_TEXT}; border: 1px solid {C_BORDER}; }}
        QPushButton#choice:checked {{ border: 1px solid {C_BORDER_ACCENT};
                                      color: {C_BORDER_ACCENT}; background: {C_PRESSED}; }}

        /* 勾选框 */
        QCheckBox {{ color: {C_TEXT}; }}
        QCheckBox:disabled {{ color: {C_DISABLED_TEXT}; }}

        /* 滚动条：压成暗色，别留白块 */
        QScrollBar:vertical, QScrollBar:horizontal {{
            background: {C_WINDOW}; border: none; width: 10px; height: 10px; margin: 0;
        }}
        QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
            background: {C_BORDER_DIM}; border-radius: 5px; min-height: 24px; min-width: 24px;
        }}
        QScrollBar::handle:hover {{ background: {C_BORDER_ACCENT}; }}
        QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{
            background: {C_WINDOW}; height: 0; width: 0; border: none;
        }}

        /* 文本域（日志正文） */
        QTextEdit {{ background: {C_WINDOW}; color: {C_TEXT};
                     border: 1px solid {C_BORDER_DIM}; border-radius: 6px;
                     selection-background-color: {C_BORDER_ACCENT}; selection-color: #000000; }}

        /* 工具提示 / 消息框 / 菜单：一律暗色 */
        QToolTip {{ background: {C_CARD}; color: {C_TEXT};
                    border: 1px solid {BORDER_CARD}; padding: 4px; }}
        QMessageBox {{ background: {C_CARD}; }}
        QMenu {{ background: {C_CARD}; color: {C_TEXT}; border: 1px solid {BORDER_CARD}; }}
        QMenu::item:selected {{ background: {C_BORDER_ACCENT}; color: #000000; }}
        QMenu::separator {{ background: {C_BORDER}; height: 1px; margin: 4px 6px; }}
        """

    # ── 页面切换 / 状态 ──
    @pyqtSlot(int)
    def switch_page(self, idx: int) -> None:
        self.stack.setCurrentIndex(idx)
        self.log(f"切到 {TABS[idx][1]} 页")

    def is_connected(self) -> bool:
        return self._connected

    def is_logged_in(self) -> bool:
        return self._logged_in

    def step_done(self, hole_id) -> dict:
        """洞的步骤打勾情况（由引擎中继的步骤行解析出来），主页 socket 卡用"""
        return self.engine.step_done(hole_id)

    def set_state(self, state: str) -> None:
        self.tray.set_state(state)
        self._connected = state in (STATE_CONNECTING, STATE_LOGGED_IN)
        self._logged_in = state == STATE_LOGGED_IN
        if hasattr(self, "home"):
            self.home.apply_state(self._connected, self._logged_in)

    # ── 日志 ──
    def log(self, text: str) -> None:
        """系统级日志：桌面端沿用手机端的 `android:` 前缀位置，这里用 `desktop:`。"""
        self.overlay.append(f"desktop: {text}")

    def connect_engine(self) -> None:
        host, port, use_wss = self.home.server_card.values()
        self.log(f"连接 {host}:{port}（{'wss' if use_wss else 'ws'}）…")
        if use_wss:
            # 据实说明：client.py 的 ws_handshake 是明文 WebSocket，没有 TLS 分支
            self.log("服务器卡：选了 wss，但 client.py 目前只有明文 ws —— 这次按 ws 连（Phase 3 再补 TLS）")
        self.engine.connect(host, port)

    def open_log(self) -> None:
        if not self.overlay.expanded:
            self.overlay.set_expanded(True)

    # ── 最大化 / 还原 ──
    def is_maximized(self) -> bool:
        return bool(self.windowState() & Qt.WindowState.WindowMaximized)

    def toggle_maximize(self) -> None:
        if self.is_maximized():
            self.showNormal()
        else:
            self.showMaximized()
        self.title_bar.btn_max.setText("❐" if self.is_maximized() and not IS_MAC else "▢")

    # ── 托盘相关 ──
    def show_from_tray(self) -> None:
        self.show()
        self.raise_()
        self.activateWindow()
        self.log("从托盘唤回主窗口")

    def quit_app(self) -> None:
        self.log("退出 p2pnet")
        self.engine.shutdown()
        if self.tray.icon is not None:
            self.tray.icon.hide()
        QApplication.instance().quit()

    def closeEvent(self, e) -> None:  # noqa: N802
        """
        ✕ 的语义：
          - 托盘可用 → **收进托盘**（不退出），第一次给一句提示，别让用户以为没关掉；
          - 托盘不可用 → 真退出（否则窗口一没，进程还占着端口，用户找不回来）。
        """
        if self.tray.available:
            e.ignore()
            self.hide()
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self.tray.notify("已最小化到托盘，仍在后台运行；退出请用托盘菜单的「退出」")
            self.log("已收进托盘（仍在后台运行；退出请用托盘菜单的「退出」）")
        else:
            e.accept()
            self.quit_app()

    # ── 边缘缩放（4~6px 热区；最大化时禁用）──
    def _edges_at(self, pos: QPoint) -> Qt.Edge:
        m = RESIZE_MARGIN + 1
        left = pos.x() <= m
        right = pos.x() >= self.width() - m
        top = pos.y() <= m
        bottom = pos.y() >= self.height() - m
        edges = Qt.Edge(0)
        if left:
            edges |= Qt.Edge.LeftEdge
        if right:
            edges |= Qt.Edge.RightEdge
        if top:
            edges |= Qt.Edge.TopEdge
        if bottom:
            edges |= Qt.Edge.BottomEdge
        return edges

    def _cursor_for(self, edges: Qt.Edge) -> Qt.CursorShape:
        left = bool(edges & Qt.Edge.LeftEdge)
        right = bool(edges & Qt.Edge.RightEdge)
        top = bool(edges & Qt.Edge.TopEdge)
        bottom = bool(edges & Qt.Edge.BottomEdge)
        if (left and top) or (right and bottom):
            return Qt.CursorShape.SizeFDiagCursor
        if (right and top) or (left and bottom):
            return Qt.CursorShape.SizeBDiagCursor
        if left or right:
            return Qt.CursorShape.SizeHorCursor
        if top or bottom:
            return Qt.CursorShape.SizeVerCursor
        return Qt.CursorShape.ArrowCursor

    def mouseMoveEvent(self, e) -> None:  # noqa: N802
        if self.is_maximized():
            self.setCursor(Qt.CursorShape.ArrowCursor)
            return super().mouseMoveEvent(e)
        edges = self._edges_at(e.position().toPoint())
        self.setCursor(self._cursor_for(edges))
        super().mouseMoveEvent(e)

    def mousePressEvent(self, e) -> None:  # noqa: N802
        if e.button() == Qt.MouseButton.LeftButton and not self.is_maximized():
            edges = self._edges_at(e.position().toPoint())
            if edges:
                win = self.windowHandle()
                if win is not None:
                    win.startSystemResize(edges)   # 交给系统缩放，边缘/贴边行为才对
                    return
        super().mousePressEvent(e)

    def changeEvent(self, e) -> None:  # noqa: N802
        # 最大化状态变化时同步按钮字形（也覆盖系统快捷键/双击）。
        # 构造期（setWindowFlag 会触发本方法）title_bar 还没建好，必须判空。
        if self.title_bar is not None:
            self.title_bar.btn_max.setText("❐" if self.is_maximized() and not IS_MAC else "▢")
        super().changeEvent(e)

    # ── self-test 用的摘要 ──
    def summary_lines(self) -> list[str]:
        ctrl = "左（红黄绿圆形）" if IS_MAC else "右（— ▢ ✕）"
        lines = [
            f"平台            : {sys.platform}（PyQt6 / Qt {QT_VERSION}，platform plugin = "
            f"{QApplication.instance().platformName()}）",
            f"窗口            : 无边框（FramelessWindowHint），{self.width()}x{self.height()}，"
            f"最小 {self.minimumWidth()}x{self.minimumHeight()}，缩放热区 {RESIZE_MARGIN}px",
            f"标题栏          : 高 {TITLE_BAR_H}px，窗口按钮在{ctrl}，tab 在"
            f"{'其后' if IS_MAC else '左'}，拖动=startSystemMove，双击=最大化",
            f"tab             : {len(TABS)} 个 → " + " / ".join(t for _k, t in TABS),
            f"页面            : {self.stack.count()} 个（QStackedWidget），当前索引 {self.stack.currentIndex()}",
        ]
        for i, (_k, title) in enumerate(TABS):
            page = self.pages[i]
            lines.append(f"  - [{i}] {title:10s} 卡片骨架：{'、'.join(page.card_titles()) or '（无）'}")
        lines.append("  " + self.tray.summary())
        lines.append("  " + self.overlay.summary())
        lines.append(f"  ✕ 语义         : {'收进托盘（后台常驻）' if self.tray.available else '真的退出（托盘不可用时的降级）'}")
        cli_name = getattr(self.engine.cli, "__name__", "（未导入）")
        lines.append(
            f"  引擎桥         : {type(self.engine).__name__}"
            f"（进程内，导入的模块 __name__={cli_name}；不开子进程）"
        )
        return lines


# ==========================================================================================
# 9. 单实例（QLocalServer / QLocalSocket：第二次启动唤起已有窗口，而不是起第二个进程）
# ==========================================================================================

SINGLE_INSTANCE_KEY = "p2pnet-desktop-gui"


def try_raise_existing_instance() -> bool:
    """
    已有实例在跑？→ 通知它把窗口显示出来并返回 True（调用方随即退出）。
    否则占住这个 socket 名并返回 False。
    """
    sock = QLocalSocket()
    sock.connectToServer(SINGLE_INSTANCE_KEY)
    if sock.waitForConnected(200):
        sock.write(b"show\n")
        sock.flush()
        sock.waitForBytesWritten(500)
        sock.disconnectFromServer()
        return True
    # 没人应答：清掉可能残留的 socket 文件（上次异常退出会留）
    QLocalServer.removeServer(SINGLE_INSTANCE_KEY)
    return False


def install_single_instance(app: QApplication, window: "MainWindow") -> QLocalServer:
    """占位 + 收到 "show" 就把窗口唤出来。"""
    server = QLocalServer(app)
    server.listen(SINGLE_INSTANCE_KEY)

    def on_new_connection() -> None:
        conn = server.nextPendingConnection()
        if conn is None:
            return
        conn.readyRead.connect(lambda: window.show_from_tray())
        conn.disconnected.connect(conn.deleteLater)

    server.newConnection.connect(on_new_connection)
    return server


# ==========================================================================================
# 10. main()
# ==========================================================================================

QT_VERSION = ""  # 由 main() 填（self-test 摘要里要打印）


def run_self_test(app: QApplication) -> int:
    """
    --self-test：构建完整界面、**不显示窗口**、不进事件循环，打印布局摘要后返回 0。
    托盘不可用时（offscreen）走的就是降级路径，这里把它一并打出来。
    """
    global QT_VERSION
    from PyQt6.QtCore import QT_VERSION_STR as _QT

    QT_VERSION = _QT

    win = MainWindow()
    # 不 show() 也要把布局跑一遍，否则子控件还是默认尺寸（面板目标会算成 90x27 这种没意义的数）。
    # 注意：**隐藏的 widget 收不到 resize 事件**（Qt 要到 show 时才发），所以这里显式把
    # resize 事件喂给 ContentArea —— 走的就是生产代码里那条路径（ContentArea.resizeEvent → 铺满浮层）。
    win.resize(1080, 720)
    win.layout().activate()
    app.processEvents()
    _size = win.content.size()
    win.content.resizeEvent(QResizeEvent(_size, _size))
    app.processEvents()

    print("===== p2pnet 桌面端 self-test（未显示窗口，未进入事件循环）=====")
    for line in win.summary_lines():
        print(line)

    # 日志浮层的动画数学：不靠事件循环，手动喂 progress 验证插值与"折叠不吞点击"
    ov = win.overlay
    print("===== 日志浮层动画（手动喂 progress）=====")
    for p in (0.0, 0.5, 1.0):
        ov.apply_progress(p)
        r = ov.panel.geometry()
        print(f"  progress={p:.1f} → 面板 {r.width()}x{r.height()} @ ({r.x()},{r.y()})"
              f"（起点=胶囊 ({ov.pill.x()},{ov.pill.y()})，终点=居中 90%），"
              f"遮罩 alpha={ov.scrim_effect.opacity():.2f}，面板 alpha={ov.panel_effect.opacity():.2f}")

    print("===== 折叠态不挡点击（真实机制：整层 hide，而不是那个会禁掉子控件的透明属性）=====")
    ov.apply_progress(0.0)
    ov.set_expanded(False)
    ov.anim.setCurrentTime(LOG_ANIM_MS)   # 直接把动画推到结尾，不依赖事件循环
    ov._on_anim_finished()
    print(f"  折叠后：浮层 isHidden={ov.isHidden()}，面板 isHidden={ov.panel.isHidden()}")
    assert ov.isHidden(), "折叠时浮层必须整层隐藏，否则它会盖住页面的点击"
    assert ov.pill.parent() is win.content, "胶囊必须是浮层的兄弟（挂在内容区上），否则会跟着被隐藏"
    assert ov.pill.isVisible() or not win.isVisible(), "胶囊在折叠时也应保持在（窗口显示后）"
    print("  断言通过：浮层整层隐藏 ✓　胶囊父节点 = ContentArea（兄弟节点，不会被连带隐藏）✓")

    win.log("self-test：这行是日志浮层的第一条日志")
    print(f"===== 日志内容行数：{len(ov.text.toPlainText().splitlines())} =====")

    # ────────────────────────────────────────────────────────────────────────────────
    # 架构断言：确认是"导入 client.py 调函数"，不是"起 client.py 子进程"
    # ────────────────────────────────────────────────────────────────────────────────
    print("===== 架构：导入 client.py 而不是开子进程 =====")
    import client as _cli_mod                      # 同一个模块对象（引擎桥已导入过）
    assert _cli_mod.__name__ == "client", "必须是 import 进来的 client 模块，不能是当脚本跑"
    assert win.engine.cli is _cli_mod, "引擎桥持有的必须是同一个 client 模块对象"
    print(f"  import 的模块 __name__ = {_cli_mod.__name__!r}"
          f"（is 引擎桥持有的对象 = {win.engine.cli is _cli_mod}）")

    own_src = open(os.path.abspath(__file__), encoding="utf-8").read()
    # 自己构造关键词，免得"断言里出现的字面量"把断言自己绊倒
    needle = "sub" + "process"
    popen_needle = "Po" + "pen"
    assert needle not in own_src, f"本文件里不该再出现 {needle}"
    assert popen_needle not in own_src, f"本文件里不该出现 {popen_needle}（不许起子进程）"
    print(f"  本文件 grep：{needle!r} 出现 {own_src.count(needle)} 次，"
          f"{popen_needle!r} 出现 {own_src.count(popen_needle)} 次（都应为 0）")
    imp_line = next(
        (f"第 {i+1} 行: {l.strip()}" for i, l in enumerate(own_src.splitlines())
         if "import client as cli" in l), "（没找到运行时 import 行）"
    )
    print(f"  运行时导入：{imp_line}")
    print(f"  client.py 位置：{_cli_mod.__file__}")

    # ────────────────────────────────────────────────────────────────────────────────
    # 桩 socket：证明"真的在调 client.py 的函数"（不联网）
    # ────────────────────────────────────────────────────────────────────────────────
    print("===== 桩 socket 验证命令真的走到 client.py =====")

    class _StubSocket:
        """只把发出去的 WebSocket 帧记下来；用 client.py 自己的 ws_recv() 解码回去。"""

        def __init__(self):
            self.frames = b""

        def send(self, framed: bytes) -> int:
            self.frames += framed
            return len(framed)

        def sendall(self, framed: bytes) -> None:
            self.frames += framed

        def take(self) -> bytes:
            out, self.frames = self.frames, b""
            return out

    stub = _StubSocket()
    _cli_mod.ws_sock = stub            # 引擎桥的 ws_send 闭包会取这个全局
    _cli_mod.recv_buf = b""

    win.engine.command("list")          # 引擎线程没跑 → 同步派发，走真正的 dispatch()
    _cli_mod.recv_buf = stub.take()     # 把发出去的帧喂回 client.py 自己的解码器
    got_list = json.loads(_cli_mod.ws_recv() or "{}")
    print(f"  process_input_line('list')     → 发出去 {got_list}")
    assert got_list.get("type") == "list", f"list 应该发出 {{'type':'list'}}，实际 {got_list}"

    win.engine.command("udp bob")
    _cli_mod.recv_buf = stub.take()
    got_udp = json.loads(_cli_mod.ws_recv() or "{}")
    print(f"  process_input_line('udp bob')  → 发出去 {got_udp}")
    assert got_udp.get("type") == "p2pudp" and got_udp.get("target") == "bob", \
        f"udp bob 应该发出 p2pudp/target=bob，实际 {got_udp}"
    print("  两条断言通过 → 确实在调 client.py 的 process_input_line / hole_udp.start（未联网）")

    # ────────────────────────────────────────────────────────────────────────────────
    # 日志汇流：client.py 的 log() 必须出现在 App 内日志里
    # ────────────────────────────────────────────────────────────────────────────────
    print("===== 日志汇流（重定向 stdout，不改 client.py）=====")
    marker = "自检标记-来自client.py的log"
    _cli_mod.log(marker)
    tail = ov.text.toPlainText().splitlines()[-3:]
    print(f"  调用 client.log({marker!r}) 之后，日志尾部：")
    for one in tail:
        print(f"    {one}")
    assert any(marker in one for one in ov.text.toPlainText().splitlines()), \
        "client.py 的 log() 没有汇进 App 内日志"
    assert sys.stdout is win.engine._relay, "sys.stdout 应该被换成中继（tee）"
    print("  断言通过：client.py 的 print/log 全部汇入面板，且 stdout 被中继接管（tee 到终端）")

    # 收尾：把桩 socket 撤掉，别留下假状态
    _cli_mod.ws_sock = None
    _cli_mod.recv_buf = b""
    _cli_mod.connected = False

    # ────────────────────────────────────────────────────────────────────────────────
    # 配色：断言"常量真的被用上了"，不是只改了常量
    # ────────────────────────────────────────────────────────────────────────────────
    print("===== 暗色主题接线 =====")
    pal = app.palette()
    win_col = pal.color(QPalette.ColorRole.Window).name()
    base_col = pal.color(QPalette.ColorRole.Base).name()
    text_col = pal.color(QPalette.ColorRole.WindowText).name()
    print(f"  style = {app.style().objectName()!r}")
    print(f"  palette：Window={win_col} Base={base_col} WindowText={text_col} "
          f"Button={pal.color(QPalette.ColorRole.Button).name()} "
          f"Highlight={pal.color(QPalette.ColorRole.Highlight).name()} "
          f"PlaceholderText={pal.color(QPalette.ColorRole.PlaceholderText).name()}")
    assert app.style().objectName().lower() == "fusion", "必须用 Fusion（否则会跟系统主题走）"
    assert win_col == C_WINDOW.lower(), f"窗口底色应是 {C_WINDOW}，实际 {win_col}"
    assert base_col == C_CARD.lower(), f"输入框底色应是 {C_CARD}，实际 {base_col}"
    assert text_col == C_TEXT.lower(), f"主文字应是 {C_TEXT}，实际 {text_col}"

    qss = win.styleSheet()
    checks = {
        "卡片填充黑": f"QFrame#card {{ background: {C_CARD};",
        "卡片高亮描边": f"border: 1px solid {BORDER_CARD};",
        "输入框暗描边": f"border: 1px solid {C_BORDER_DIM};",
        "输入框聚焦转强调色": f"QLineEdit:focus",
        "下拉弹层黑底": f"QComboBox QAbstractItemView",
        "按钮亮描边": f"QPushButton {{",
        "滚动条暗色": f"QScrollBar::handle:vertical",
        "工具提示暗色": f"QToolTip {{",
        "菜单暗色": f"QMenu {{",
    }
    for name, frag in checks.items():
        ok = frag in qss
        print(f"  {'✓' if ok else '✗'} {name:16s} ← {frag[:52]}")
        assert ok, f"全局样式里缺少：{name}（{frag}）"

    pill_qss = win.content.log_pill.styleSheet()
    panel_qss = ov.panel.styleSheet()
    print(f"  胶囊样式：{pill_qss}")
    print(f"  日志面板：{panel_qss}")
    assert C_BORDER_ACCENT in pill_qss, "胶囊必须是黑底+亮描边（不再用亮蓝实心块）"
    assert C_WINDOW in pill_qss, "胶囊底色应是窗口黑"
    assert C_BORDER_ACCENT in panel_qss, "日志面板也要高亮描边"
    print("  断言通过：palette（Fusion+黑）+ 样式表关键项 + 胶囊/面板 都已接线")

    # ────────────────────────────────────────────────────────────────────────────────
    # 背景必须"真的画出来"（曾经踩过：标题栏透明，透出后面别的程序）
    # 成因是两个叠加：① QSS 的 background 对 QWidget 子类默认不生效（要 WA_StyledBackground）；
    # ② 全局 QWidget{background:transparent} 把顶层窗口自己的背景也关了 → 没有兜底。
    # ────────────────────────────────────────────────────────────────────────────────
    print("===== 背景不透明（防「标题栏透出别的程序」回归）=====")
    gss = win.styleSheet()
    assert "background: transparent" not in gss, "全局样式里不能有 background: transparent（会把窗口刷透）"
    print("  全局样式里 'background: transparent' 出现 0 次 ✓")

    # 主页现在**不是** Page 的子类（它没有滚动区，自由层要能任意摆放卡片），
    # 所以"页面内层"这条拿一个配置页来验。
    config_page = win.pages[2]          # proxy 页（Page 子类）
    must_bg = [
        ("主窗口", win), ("标题栏", win.title_bar), ("内容区", win.content),
        ("主页", win.pages[0]), ("配置页", config_page),
        ("页面内层", config_page.scroll.widget()),
        ("自由层", win.pages[0].free_layer),
    ]
    for name, w in must_bg:
        has = w.testAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        print(f"  {'✓' if has else '✗'} {name:8s} WA_StyledBackground = {has}（QSS 背景要靠它才画）")
        assert has, f"{name} 缺 WA_StyledBackground，它的 QSS 背景不会画 → 会透"

    win.ensurePolished()
    app.processEvents()
    shot = win.grab().toImage()
    step = 9
    xs = range(0, shot.width(), step)
    ys = range(0, shot.height(), step)
    total = len(list(xs)) * len(list(ys))
    opaque_bad = sum(
        1 for y in range(0, shot.height(), step) for x in range(0, shot.width(), step)
        if shot.pixelColor(x, y).alpha() != 255
    )
    bar = shot.pixelColor(500, TITLE_BAR_H // 2)
    content_px = shot.pixelColor(6, shot.height() - 6)
    print(f"  渲染采样：{total} 点，其中非不透明 {opaque_bad} 点（应为 0）")
    print(f"  标题栏中段像素 = {bar.name()}（应为 {C_TITLE_BG}）｜页面左下 = {content_px.name()}（应为 {C_WINDOW}）")
    assert opaque_bad == 0, f"有 {opaque_bad} 个采样点是半透明/透明的（窗口会透出后面的程序）"
    assert bar.name() == C_TITLE_BG.lower(), f"标题栏应为 {C_TITLE_BG}，实际 {bar.name()}"
    assert content_px.name() == C_WINDOW.lower(), f"页面底色应为 {C_WINDOW}，实际 {content_px.name()}"
    print("  断言通过：整窗不透明、标题栏是标题栏色、页面是纯黑 ✓")

    # ────────────────────────────────────────────────────────────────────────────────
    # 主页（对齐安卓 MainPage.kt）：布局 / 连线 / 拖动 / 数据驱动
    # ────────────────────────────────────────────────────────────────────────────────
    print("===== 主页布局（3 个 peer + 我卡 + 1 张 socket 卡）=====")
    home: HomePage = win.home
    fl = home.free_layer
    fl._rng = random.Random(42)                 # 固定随机源，结果可复现
    fl.resize(1000, 600)
    fake_peers = [
        {"username": "alice", "ip": "10.0.0.2", "port": 50001},
        {"username": "bob", "ip": "10.0.0.3", "port": 50002},
        {"username": "carol", "ip": "10.0.0.4", "port": 50003},
    ]
    fake_hole = {
        "id": 1, "proto": "udp", "peer": "alice", "my_ip": "192.168.1.5", "my_port": 40001,
        "peer_ip": "1.2.3.4", "peer_port": 50001, "status": "打洞中", "handed_to": None,
        "candidates": [], "rtt": None,
    }
    fl.set_peers(fake_peers)
    fl.set_me("5.6.7.8", 40001)
    fl.set_holes([fake_hole])
    fl._relayout()

    area_w, area_h = float(fl.width()), float(fl.height())
    print(f"  自由层 {int(area_w)}x{int(area_h)}；卡片数：peer={len(fl._peer_cards)} "
          f"socket={len(fl._socket_cards)} me=1")
    assert len(fl._peer_cards) == 3, "应该有 3 张 peer 卡"
    assert len(fl._socket_cards) == 1, "应该有 1 张 socket 卡"
    for name, card in fl._peer_cards.items():
        x, y = fl.peer_top_left(name)
        upper = area_h * PEER_Y_RANGE
        print(f"  peer {name:6s} 左上=({x:.0f},{y:.0f}) 宽={card.width()} 高={card.height()}"
              f"（y 上限 {upper:.0f}）")
        assert y >= 0 and y <= upper, f"{name} 的 y 应落在上半区"
        assert abs(card.height() - PEER_NODE_H) < 1, "peer 卡高度应固定 58"

    me_x, me_y = home.free_layer.me_card.x(), home.free_layer.me_card.y()
    me_w, me_h = fl.me_card.width(), fl.me_card.height()
    print(f"  我卡 左上=({me_x},{me_y}) {me_w}x{me_h}；**默认居中**检查："
          f"中心x={me_x + me_w/2:.0f}（区域中心 {area_w/2:.0f}），"
          f"中心y={me_y + me_h/2:.0f}（区域中心 {area_h/2:.0f}）")
    print(f"    → me_y={me_y}｜me_h={me_h:.0f}｜area_h={area_h:.0f}"
          f"（(area_h-me_h)/2 = {(area_h - me_h) / 2:.1f}）")
    assert abs((me_x + me_w / 2) - area_w / 2) <= 1, "我卡应水平居中"
    assert abs((me_y + me_h / 2) - area_h / 2) <= 1, "我卡默认应竖直居中"

    sock_id = 1
    sx, sy = fl.socket_top_left(sock_id)
    sc = fl._socket_cards[sock_id]
    px, py = fl.peer_top_left("alice")
    ac = fl._peer_cards["alice"]
    print(f"  socket 卡 左上=({sx:.0f},{sy:.0f}) {sc.width()}x{sc.height()}；"
          f"所属 peer alice 左上=({px:.0f},{py:.0f})，peer 底边={py + PEER_NODE_H:.0f}"
          f"（socket y 应 ≥ 区域高一半 {area_h/2:.0f}）")
    assert sy >= area_h / 2 - 1, "socket 卡应落在下半屏"
    print(f"  socket 卡与 peer 卡水平居中对齐差 = "
          f"{abs((sx + sc.width()/2) - (px + ac.width()/2)):.1f}px")
    assert sy >= py + PEER_NODE_H, "socket 卡应在所属 peer 卡下方"

    top_in_win = float(fl.mapTo(win, QPoint(0, 0)).y())
    expect_divider = win.height() / 2.0 - top_in_win
    got_divider = fl.divider_y()
    print(f"  中线 y={got_divider:.1f}（自由层顶边在窗口里 y={top_in_win:.0f}，"
          f"窗口高 {win.height()} → 期望 {expect_divider:.1f}）")
    assert got_divider is not None and abs(got_divider - expect_divider) <= 1, \
        "中线应落在窗口几何中心（不是内容区中心）"

    print("===== 连线（纯函数 link_segments，逐条断言颜色/端点/虚线）=====")
    fl.apply_state(connected=True, logged_in=False)
    segs = fl.segments()
    by_kind = {}
    for sg in segs:
        by_kind.setdefault(sg.kind, []).append(sg)
    me_seg = by_kind["server_me"][0]
    print(f"  未登录：server_me 颜色={me_seg.color} 虚线={me_seg.dash} 从 y={me_seg.y1} 到 y={me_seg.y2:.0f}")
    assert me_seg.color == "#FFFFFF" and me_seg.dash == (LINK_DASH_ON, LINK_DASH_OFF), \
        "未登录时 服务器↔我 应是白色虚线"
    _srx, _sry, _srw, _srh = fl.server_rect()
    _srv_bottom = _sry + _srh
    print(f"  服务器卡片矩形 = ({_srx:.0f},{_sry:.0f}) {_srw:.0f}x{_srh:.0f} → 底边 y={_srv_bottom:.0f}"
          f"（连线起点应从它底边开始，不再是自由层顶边）")
    assert abs(me_seg.x1 - (me_x + me_w / 2)) <= 1, "连线起点应是 我卡中心 x"
    assert abs(me_seg.y1 - _srv_bottom) <= 1, "连线起点应在服务器卡片底边"

    fl.apply_state(connected=True, logged_in=True)
    segs = fl.segments()
    by_kind = {}
    for sg in segs:
        by_kind.setdefault(sg.kind, []).append(sg)
    me_seg = by_kind["server_me"][0]
    print(f"  已登录：server_me 颜色={me_seg.color} 虚线={me_seg.dash} 线宽={me_seg.width}")
    assert me_seg.color == LINK_GREEN and me_seg.dash is None, "已登录时 服务器↔我 应是绿色实线"

    peer_segs = by_kind["server_peer"]
    print(f"  server_peer 条数={len(peer_segs)}，颜色={ {s.color for s in peer_segs} }，"
          f"终点 y={ {round(s.y2) for s in peer_segs} }（应 = peer卡y+{PEER_TITLE_CENTER_Y:.0f}）")
    assert len(peer_segs) == 3 and all(sg.color == LINK_GREEN and sg.dash is None for sg in peer_segs)
    for sg in peer_segs:
        assert abs(sg.y1 - _srv_bottom) <= 1, "peer 连线起点应在服务器卡片底边"
    assert any(abs(sg.y2 - (fl.peer_top_left("alice")[1] + PEER_TITLE_CENTER_Y)) <= 1
               for sg in peer_segs), "peer 连线终点应是标题行中心"

    sock_segs = by_kind["peer_socket"]
    print(f"  peer_socket 条数={len(sock_segs)}，颜色={ {s.color for s in sock_segs} }，"
          f"虚线={sock_segs[0].dash}")
    assert len(sock_segs) == 1 and sock_segs[0].color == "#FFFFFF"
    assert sock_segs[0].dash == (LINK_DASH_ON, LINK_DASH_OFF), "peer↔socket 应是白色虚线"
    assert abs(sock_segs[0].x1 - (px + ac.width() / 2)) <= 1, "起点应是 peer 卡底边中点"

    div = by_kind["divider"][0]
    print(f"  divider 颜色={div.color} alpha={div.alpha} 宽={div.width} 贯通 x={div.x1}→{div.x2:.0f}")
    assert div.alpha == DIVIDER_ALPHA and abs(div.x1) < 1e-6 and abs(div.x2 - area_w) < 1e-6

    print("===== 拖动：clamp 在边界内 =====")
    fl._drag_peer("alice", 100000.0, 100000.0)
    ax, ay = fl.peer_top_left("alice")
    print(f"  把 alice 往右下拖 100000 → 左上=({ax:.0f},{ay:.0f})，卡右={ax + ac.width():.0f}"
          f"（区域宽 {area_w:.0f}）")
    assert ax >= 0 and ay >= 0 and ax + ac.width() <= area_w + 1 and ay + PEER_NODE_H <= area_h + 1
    fl._drag_peer("alice", -100000.0, -100000.0)
    ax, ay = fl.peer_top_left("alice")
    print(f"  再往左上拖 100000 → 左上=({ax:.0f},{ay:.0f})")
    assert ax >= -1 and ay >= -1

    fl._drag_me(-100000.0, -100000.0)
    print(f"  我卡拖到左上极限 → 左上=({fl.me_card.x()},{fl.me_card.y()})（应 ≥0）")
    assert fl.me_card.x() >= -1 and fl.me_card.y() >= -1
    fl._drag_me(100000.0, 100000.0)
    print(f"  我卡拖到右下极限 → 左上=({fl.me_card.x()},{fl.me_card.y()})，"
          f"右={fl.me_card.x() + fl.me_card.width()}（≤ {area_w:.0f}），底={fl.me_card.y() + fl.me_card.height()}")
    assert fl.me_card.x() + fl.me_card.width() <= area_w + 1
    assert fl.me_card.y() + fl.me_card.height() <= area_h + 1

    fl._drag_socket(sock_id, 100000.0, 100000.0)
    sx2, sy2 = fl.socket_top_left(sock_id)
    print(f"  socket 卡拖到右下极限 → 左上=({sx2:.0f},{sy2:.0f})，"
          f"右={sx2 + sc.width():.0f} 底={sy2 + sc.height():.0f}（≤ {area_w:.0f},{area_h:.0f}）")
    assert sx2 + sc.width() <= area_w + 1 and sy2 + sc.height() <= area_h + 1

    # ────────────────────────────────────────────────────────────────────────────────
    # 服务器卡片：搬进自由层 + 宽度随窗口比例**实时**变（竖屏满宽 / 横屏居中占一半）
    # ────────────────────────────────────────────────────────────────────────────────
    print("===== 服务器卡片：在自由层里 + 宽度规则（真量像素）=====")
    scard = home.server_card

    def _overlap(a: tuple[float, float, float, float], b: tuple[float, float, float, float]) -> bool:
        """两个矩形是否相交（用于"不许压住服务器卡片"）"""
        return not (a[0] + a[2] <= b[0] or b[0] + b[2] <= a[0]
                    or a[1] + a[3] <= b[1] or b[1] + b[3] <= a[1])

    def _measure_server(tag: str):
        win.grab()
        app.processEvents()
        fw, fh = float(fl.width()), float(fl.height())
        print(f"  [{tag}] 自由层 {fw:.0f}x{fh:.0f}（{'竖屏 高>宽' if fh > fw else '横屏 宽>高'}）"
              f" → 服务器卡 x={scard.x()} y={scard.y()} w={scard.width()} h={scard.height()}"
              f"（自由层宽的 {scard.width() / fw * 100:.0f}%）")
        return fw, fh, float(scard.x()), float(scard.width())

    assert scard.parent() is fl, "服务器卡片必须是自由层的子控件"
    win.resize(800, 1000)
    p1 = _measure_server("800x1000 竖屏")
    assert abs(p1[3] - (p1[0] - 2 * SERVER_CARD_MARGIN_X)) <= 2, "竖屏应**满宽**"
    win.resize(1200, 800)
    p2 = _measure_server("1200x800 横屏")
    assert abs(p2[3] - (p2[0] - 2 * SERVER_CARD_MARGIN_X) / 2) <= 2, "横屏应占**一半宽**"
    assert abs(p2[2] - (p2[0] - p2[3]) / 2.0) <= 2, "横屏应**水平居中**占一半"
    win.resize(800, 1000)
    p3 = _measure_server("再切回 800x1000")
    print(f"    → 竖屏宽 {p1[3]:.0f} → 横屏宽 {p2[3]:.0f} → 再竖屏宽 {p3[3]:.0f}"
          f"（跟着 resize 变，证明不是构造时算一次）")
    assert abs(p3[3] - p1[3]) <= 2, "切回竖屏宽度必须变回满宽"
    assert abs(p3[2] - SERVER_CARD_MARGIN_X) <= 2 or abs(p3[2] - (p3[0] - p3[3]) / 2) <= 2

    # 「我」卡默认**居中**（竖屏：没有冲突，正好居中）
    me_w, me_h = float(fl.me_card.width()), float(fl.me_card.height())
    fl._me_drag = (0.0, 0.0)
    fl._relayout()
    win.grab()
    app.processEvents()
    cx = fl.me_card.x() + me_w / 2.0
    cy = fl.me_card.y() + me_h / 2.0
    print(f"  [竖屏 800x1000] 我卡 左上=({fl.me_card.x()},{fl.me_card.y()}) {me_w:.0f}x{me_h:.0f}"
          f" → 中心=({cx:.1f},{cy:.1f})；自由层中心=({fl.width()/2:.1f},{fl.height()/2:.1f})"
          f"｜me_y={fl.me_card.y()} me_h={me_h:.0f} area_h={fl.height()}")
    assert abs(cx - fl.width() / 2.0) <= 1, "我卡应水平居中"
    assert abs(cy - fl.height() / 2.0) <= 1, "竖屏我卡默认应**竖直居中**"

    # 很矮的横屏（直接压自由层高度，让冲突真的发生）：
    # 默认居中会压住服务器卡片 → **限位优先**（正好被推到服务器卡片下方）
    fl.resize(1200, 340)
    fl._me_drag = (0.0, 0.0)
    fl._relayout()
    app.processEvents()
    _sx, _sy, _sw, _sh = fl.server_rect()
    me_top = fl.me_card.y()
    limit = fl.avoid_top(float(fl.me_card.x()), me_w)
    centered_y = (fl.height() - me_h) / 2.0
    print(f"  [很矮横屏 1200x340] 服务器卡=({_sx:.0f},{_sy:.0f}) {_sw:.0f}x{_sh:.0f}"
          f"（底边 {_sy + _sh:.0f}，限位 {limit:.0f}）；我卡 top={me_top}"
          f"（居中会是 {centered_y:.0f}，但被限位推下来了）"
          f"｜我卡底={me_top + me_h:.0f} ≤ 自由层高 {fl.height()}")
    assert me_top >= limit - 1, "限位优先：我卡必须被推到服务器卡片下方"
    assert me_top <= limit + 2, "冲突时应正好贴在限位上（不是随便乱放）"
    assert me_top + me_h <= fl.height() + 1, "仍要落在自由层内"
    assert not _overlap((float(fl.me_card.x()), float(me_top), me_w, me_h),
                        fl.server_rect()), "冲突解完仍不许压住服务器卡片"
    win.resize(1080, 720)
    fl.resize(1000, 600)
    fl._me_drag = (0.0, 0.0)
    fl._relayout()

    # 不压服务器卡片：默认位置 + 拖到上下极限都验一遍
    print("===== 卡片限位：不许压住服务器卡片 =====")

    srv = fl.server_rect()
    for name in ("alice", "bob", "carol"):
        c = fl._peer_cards[name]
        x, y = fl.peer_top_left(name)
        rect = (x, y, float(c.width()), float(c.height()))
        print(f"  peer {name:6s} 左上=({x:.0f},{y:.0f}) 底={y + c.height():.0f}"
              f"｜服务器卡底边={srv[1] + srv[3]:.0f}｜重叠={_overlap(rect, srv)}")
        assert not _overlap(rect, srv), f"{name} 压住了服务器卡片"
    sy_ = fl.socket_top_left(sock_id)
    srect = (sy_[0], sy_[1], float(sc.width()), float(sc.height()))
    assert not _overlap(srect, srv), "socket 卡压住了服务器卡片"

    fl._drag_me(-100000.0, -100000.0)
    print(f"  我卡拖到**上**极限 → 左上=({fl.me_card.x()},{fl.me_card.y()})"
          f"（限位 ≥ {fl.avoid_top(float(fl.me_card.x()), me_w):.0f}）"
          f"｜重叠={_overlap((float(fl.me_card.x()), float(fl.me_card.y()), me_w, me_h), srv)}")
    assert not _overlap((float(fl.me_card.x()), float(fl.me_card.y()), me_w, me_h), srv), \
        "我卡拖到上极限也不许压住服务器卡片"
    assert fl.me_card.y() >= -1 and fl.me_card.x() >= -1
    fl._drag_me(100000.0, 100000.0)
    print(f"  我卡拖到**下**极限 → 左上=({fl.me_card.x()},{fl.me_card.y()})，"
          f"底={fl.me_card.y() + me_h:.0f}（≤ {fl.height()}）")
    assert fl.me_card.y() + me_h <= fl.height() + 1, "下极限仍要落在自由层内"
    fl._drag_me(-100000.0, 100000.0)
    fl._me_drag = (0.0, 0.0)
    fl._relayout()

    print("===== 数据：list_result → peer 卡；洞状态 → 五步 + 用法按钮 =====")
    recorder: list[str] = []
    real_command = win.engine.command
    win.engine.command = lambda line: recorder.append(line)   # 别真把命令投给 client.py

    win.engine._observe({"type": "list_result", "users": [
        {"username": "dave", "ip": "10.0.0.9", "port": 50009, "udp_port": 50009}]})
    names = sorted(fl._peer_cards)
    print(f"  喂一条 list_result(dave) → peer 卡 = {names}")
    assert "dave" in fl._peer_cards, "list_result 里的用户应生成 peer 卡"

    win.engine._observe({"type": "thisisyourpeer_udp", "my_ip": "5.6.7.8", "my_port": 40001})
    print(f"  喂 thisisyourpeer_udp → 我卡标题 = {fl.me_card.title.text()!r}")
    assert fl.me_card.title.text() == "我(5.6.7.8:40001)"

    hole_done = dict(fake_hole)
    hole_done["status"] = "已打通"
    fl.set_holes([hole_done])
    card_data = fl._socket_cards[1].card
    steps5 = (card_data["sent_to_server"], card_data["server_replied"],
              card_data["sent_to_peer"], card_data["peer_replied"], bool(card_data["handed_to"]))
    btns = fl._socket_cards[1].usage_buttons
    print(f"  洞 status=已打通 handed_to=None → 五步={steps5}，"
          f"用法按钮 {len(btns)} 个，全部可点={all(b.isEnabled() for b in btns.values())}")
    assert steps5 == (True, True, True, True, False), "前四步应打勾、第五步（交给用法）未打勾"
    assert len(btns) == 6 and all(b.isEnabled() for b in btns.values()), \
        "第 4 步打勾后 6 个用法按钮都可点"

    hole_used = dict(hole_done)
    hole_used["handed_to"] = "udptest"
    fl.set_holes([hole_used])
    card_data = fl._socket_cards[1].card
    btns = fl._socket_cards[1].usage_buttons
    steps5 = (card_data["sent_to_server"], card_data["server_replied"],
              card_data["sent_to_peer"], card_data["peer_replied"], bool(card_data["handed_to"]))
    sel = btns["udptest"].styleSheet()
    print(f"  改成 handed_to=udptest → 五步={steps5}；udptest 按钮样式={sel}")
    assert steps5 == (True, True, True, True, True), "第五步（交给用法）应打勾"
    assert LINK_GREEN in sel, "已选用法按钮应是绿色"

    done_card = fl._socket_cards[1]
    done_card.btn_close.click()
    print(f"  点 socket 卡 ✕ → 卡片还在吗={'是' if 1 in fl._socket_cards else '否'}，"
          f"发给 client.py 的命令={recorder}")
    assert 1 not in fl._socket_cards, "✕ 应该把这张卡片移除"
    assert recorder and recorder[-1] == "del hole=#1", "✕ 应发 `del hole=#1`"

    # 三个打洞按钮 → 真命令
    recorder.clear()
    fl._peer_action("udp", "alice")
    fl._peer_action("direct", "bob")
    fl._peer_action("upnp", "")
    print(f"  peer 卡按钮 → client.py 命令 = {recorder}")
    assert recorder == ["udp alice", "direct bob", "upnp"], "四个打洞按钮的命令名要对"

    win.engine.command = real_command
    fl.set_holes([])

    # ────────────────────────────────────────────────────────────────────────────────
    # 四个 bug 的回归断言（拖动手感 / 卡片描边 / list 过滤自己 / 登出清卡片）
    # ────────────────────────────────────────────────────────────────────────────────
    print("===== 拖动 1:1（跟手）：按下点→卡片的偏移固定，光标移多少卡片走多少 =====")
    fl.set_peers(fake_peers)
    fl.set_holes([])
    fl._relayout()
    before = fl.peer_top_left("bob")
    fl.drag_by("peer", "bob", 37.0, -21.0)
    after = fl.peer_top_left("bob")
    print(f"  bob 相对拖动 (37,-21)：{tuple(round(v) for v in before)} → "
          f"{tuple(round(v) for v in after)}（位移 {tuple(round(a-b) for a,b in zip(after,before))}）")
    assert abs((after[0] - before[0]) - 37) <= 1 and abs((after[1] - before[1]) + 21) <= 1, \
        "拖动应 1:1 跟手（不跟手/发飘就是偏移量算错了）"
    # 抓偏移：按在卡片中心（不是左上角）也要 1:1
    card_bob = fl._peer_cards["bob"]
    tl = card_bob.mapToGlobal(QPoint(0, 0))
    press = QPoint(tl.x() + card_bob.width() // 2, tl.y() + card_bob.height() // 2)
    b1 = fl.peer_top_left("bob")
    fl._on_drag("peer", "bob", "begin", press)
    fl._on_drag("peer", "bob", "move", QPoint(press.x() + 60, press.y() + 25))
    fl._on_drag("peer", "bob", "end", QPoint())
    b2 = fl.peer_top_left("bob")
    print(f"  按在卡片中心再拖 (60,25)：位移 {tuple(round(a-b) for a,b in zip(b2,b1))}（应 = (60,25)）")
    assert abs((b2[0] - b1[0]) - 60) <= 1 and abs((b2[1] - b1[1]) - 25) <= 1
    # 走**真 Qt 鼠标事件**再验一遍：程序化的 drag_by 会绕过"卡片信号 → FreeLayer"这段接线，
    # 之前就是这里把 pyqtSignal 当函数调用（应该 .emit），只有真事件路径才暴露得出来。
    lab = fl._peer_cards["bob"].title
    gl = lab.mapToGlobal(QPoint(3, 3))
    b0 = fl.peer_top_left("bob")

    def _send(kind, gx, gy, btn) -> None:
        gp = QPoint(gx, gy)
        lab.event(QMouseEvent(kind, QPointF(lab.mapFromGlobal(gp)), QPointF(gp),
                              btn, btn, Qt.KeyboardModifier.NoModifier))

    _send(QEvent.Type.MouseButtonPress, gl.x(), gl.y(), Qt.MouseButton.LeftButton)
    grabbed = lab.mouseGrabber() is lab
    _send(QEvent.Type.MouseMove, gl.x() + 60, gl.y() + 30, Qt.MouseButton.NoButton)
    _send(QEvent.Type.MouseButtonRelease, gl.x() + 60, gl.y() + 30, Qt.MouseButton.LeftButton)
    b1 = fl.peer_top_left("bob")
    print(f"  真 Qt 事件拖动 (60,30)：按下时 grabMouse={grabbed}，位移="
          f"{tuple(round(a-b) for a,b in zip(b1,b0))}，松开后已释放={lab.mouseGrabber() is not lab}")
    assert grabbed, "按下时应 grabMouse（否则光标移出标签就丢 move，手感卡）"
    assert abs((b1[0] - b0[0]) - 60) <= 2 and abs((b1[1] - b0[1]) - 30) <= 2, \
        "真事件路径下拖动必须 1:1 跟手"
    print("  拖动把手已 grabMouse（光标移出标签也继续收 move），_relayout 里不再每帧 adjustSize")

    print("===== 服务器卡：三行结构（标签行 / 控件行 / 连接按钮）=====")
    scard = home.server_card
    # 真跑时靠 resizeEvent + 构造后的 singleShot(0) 对齐；隐藏时不发 resize 事件，这里手动触发一次
    scard._sync_label_widths()
    pairs = (("协议", scard.lab_scheme, scard.btn_scheme),
             ("服务器", scard.lab_host, scard.f_host),
             ("端口", scard.lab_port, scard.f_port))
    for name, lab, ctl in pairs:
        top_lab = lab.mapTo(scard, QPoint(0, 0))
        top_ctl = ctl.mapTo(scard, QPoint(0, 0))
        print(f"  {name:4s} 标签 x={top_lab.x():4d} 宽={lab.width():4d} 底={top_lab.y() + lab.height():3d}"
              f"  ←→  控件 x={top_ctl.x():4d} 宽={ctl.width():4d} 顶={top_ctl.y():3d}")
        assert abs(top_lab.x() - top_ctl.x()) <= 1, f"{name} 标签与控件左边缘没对齐"
        assert lab.width() == ctl.width(), f"{name} 标签宽度应等于控件实际宽度"
        assert top_lab.y() + lab.height() <= top_ctl.y(), f"{name} 标签应在控件上方"
    lab_px = scard.lab_host.fontMetrics().height()
    edit_px = scard.f_host.edit.fontMetrics().height()
    print(f"  标签字号像素高={lab_px}，输入框正文像素高={edit_px}（标签必须更小）")
    assert lab_px < edit_px, "第一行标签要明显小于输入框正文（小字提示级别）"
    print(f"  第二行的 QLabel = {[l.text() for l in scard.row_inputs.findChildren(QLabel) if l.text()]}")
    assert [l.text() for l in scard.row_inputs.findChildren(QLabel) if l.text()] == [], \
        "第二行不该再有 服务器/端口 前缀标签（标签只在第一行）"

    print("===== 服务器卡：ws/wss 一个按钮 + 输入框宽度 =====")
    print(f"  默认协议按钮 = {scard.btn_scheme.text()!r}（应 'ws'）")
    assert scard.btn_scheme.text() == "ws", "默认应是 ws"
    assert scard.values()[2] is False, "默认 useWss 应为 False"
    scard.btn_scheme.click()
    print(f"  点一下 → {scard.btn_scheme.text()!r}，values()[2]={scard.values()[2]}")
    assert scard.btn_scheme.text() == "wss" and scard.values()[2] is True
    scard.btn_scheme.click()
    print(f"  再点一下 → {scard.btn_scheme.text()!r}，values()[2]={scard.values()[2]}")
    assert scard.btn_scheme.text() == "ws" and scard.values()[2] is False

    fm = scard.f_port.edit.fontMetrics()
    need = fm.horizontalAdvance("10000")
    avail = scard.f_port.edit.width()
    host_w = scard.f_host.width()
    print(f"  端口框 总宽={scard.f_port.width()} 输入区宽={avail}（'10000' 需要 {need}px，"
          f"含左右各 6px 内边距 → 需要 {need + 12}px）")
    print(f"  地址框 宽={host_w}（上限 {HOST_FIELD_MAX_W}），协议按钮 宽={scard.btn_scheme.width()}")
    assert avail - 12 >= need, f"端口框太窄：'10000' 需要 {need}px，输入区只有 {avail}px"
    assert host_w <= HOST_FIELD_MAX_W + 1, "地址框不该被拉得比上限还长"

    print("===== 卡片边缘高亮（三种卡片都要有描边）=====")
    for name, w in (("我卡", fl.me_card), ("peer 卡", fl._peer_cards["bob"]),
                    ("socket 卡", sc)):
        qss = w.styleSheet()
        ok = f"border: 1px solid {BORDER_CARD}" in qss and C_CARD in qss
        print(f"  {'✓' if ok else '✗'} {name:10s} objectName={w.objectName()!r} qss={qss[:66]}…")
        assert ok, f"{name} 缺高亮描边"

    print("===== list 过滤自己（照安卓 tryParseListResult）=====")
    win.engine.login_user = "alice"
    win.engine._observe({"type": "list_result", "users": [
        {"username": "alice", "ip": "5.6.7.8", "port": 40001},
        {"username": "dave", "ip": "10.0.0.9", "port": 50009}]})
    names = sorted(fl._peer_cards)
    title = fl.me_card.title.text()
    print(f"  users=[alice(自己), dave] → peer 卡={names}，我卡标题={title!r}")
    assert names == ["dave"], "自己的那条必须被过滤掉，不能长出一张'自己'的卡片"
    assert title == "我(5.6.7.8:40001)", "自己那条应更新到「我」卡片上"

    print("===== 退出登录 / 断开：别人卡片要消失（照安卓 onLogout / onDisconnect）=====")
    fl.set_peers(fake_peers)
    print(f"  登出前 peer 卡 = {sorted(fl._peer_cards)}")
    win.engine._observe({"type": "logout_ok"})
    print(f"  喂 logout_ok 之后 peer 卡 = {sorted(fl._peer_cards)}，我卡标题 = {fl.me_card.title.text()!r}")
    assert fl._peer_cards == {}, "退出登录后别人卡片必须清空"
    assert fl.me_card.title.text() == "我", "退出登录后我卡标题应退回只有「我」"

    fl.set_peers(fake_peers)
    win.engine.disconnect()
    print(f"  调 disconnect() 之后 peer 卡 = {sorted(fl._peer_cards)}")
    assert fl._peer_cards == {}, "断开连接后别人卡片也必须清空"

    # ────────────────────────────────────────────────────────────────────────────────
    # 3b) 「我」卡片的 ping 按钮（心跳与 ping 的实现都已下沉到 client.py）
    # ────────────────────────────────────────────────────────────────────────────────
    print("===== 「我」卡片 ping 按钮（3b，实现已下沉到 client.py）=====")
    mc = fl.me_card
    row = mc.btn_row
    order = [row.itemAt(i).widget().text() for i in range(row.count())]
    print(f"  按钮行顺序 = {order}（ping 必须在 登录/退出 与 list 之间）")
    assert order == ["登录", "ping", "list"], "ping 按钮位置不对"

    mc.apply_state(connected=False, logged_in=False)
    off = mc.btn_ping.isEnabled()
    mc.apply_state(connected=True, logged_in=False)
    on = mc.btn_ping.isEnabled()
    print(f"  ping 可点：未连接={off}，已连接={on}（应 False / True）")
    assert off is False and on is True

    queued: list = []
    real_dispatch = win.engine.dispatch_item
    win.engine.dispatch_item = lambda item: (queued.append(item), real_dispatch(item))[1]
    for _ in range(3):
        mc.btn_ping.click()
    print(f"  点 3 次 ping → 投给引擎的命令 = {queued}")
    assert queued == ["ping", "ping", "ping"], "ping 按钮应该只投 `ping` 命令（实现在 client.py）"
    win.engine.dispatch_item = real_dispatch

    print("===== GUI 不再自己实现 ping（源码自检）=====")
    own = open(os.path.abspath(__file__), encoding="utf-8").read()
    # 关键词在断言里自己拼出来，免得"断言里出现的字面量"把自己绊倒（和上面"不许起子进程"那条同一个套路）
    # 禁的是"在 GUI 里**定义/实现**"，不是"提到" —— 比如 self-test 会读
    # client.py 的 WS_HEARTBEAT_INTERVAL 来断言间隔是 20s，那是允许的。
    banned = ["def ws_" + "ping_frame", "def heartbeat_" + "action",
              "def _send_ws_" + "ping",
              "\nWS_HEARTBEAT_" + "INTERVAL" + " = "]   # 行首才算"定义"，行内提到允许
    cli_src = open(_cli_mod.__file__, encoding="utf-8").read()
    for needle in banned:
        n = own.count(needle)
        print(f"  {'✓' if n == 0 else '✗'} {needle:26s} 在 client-gui.py 里出现 {n} 次（应为 0）")
        assert n == 0, f"GUI 不该再自己实现 {needle}"
    for needle, where in (("ws_" + "ping_frame", "帧构造"), ("start_ws_" + "heartbeat", "心跳线程"),
                          ("note_ws_" + "rx", "读方通知"), ("send_app_" + "ping", "ping 命令")):
        n = cli_src.count(needle)
        print(f"  ✓ {needle:22s} 在 client.py 里出现 {n} 次（{where}）")
        assert n > 0, f"{needle} 应该已经下沉到 client.py"

    print("===== ping 命令真的走 client.py（桩 socket）=====")
    stub2 = _StubSocket()
    _cli_mod.ws_sock = stub2
    _cli_mod._app_ping_seq = 0
    _cli_mod._app_ping_sent.clear()
    for _ in range(3):
        _cli_mod.process_input_line("ping")
    sent_pings: list = []
    _cli_mod.recv_buf = stub2.take()
    while True:
        one = _cli_mod.ws_recv()
        if one is None:
            break
        sent_pings.append(json.loads(one))
    print(f"  process_input_line('ping') ×3 → 发出去 {sent_pings}，"
          f"seq 计数器={_cli_mod._app_ping_seq}")
    assert sent_pings == [{"type": "ping", "seq": 1}, {"type": "ping", "seq": 2},
                          {"type": "ping", "seq": 3}], "client.py 的 ping 命令应从 seq=1 递增"
    logs = ov.text.toPlainText()
    sent_log = [l for l in logs.splitlines() if "发出应用层 ping" in l]
    print(f"  日志里的发送行（client.py 打的）= {sent_log[-3:]}")
    assert any('"seq": 3' in l for l in sent_log), "发出的 ping 报文必须进日志"

    _cli_mod.handle_server_message({"type": "pong", "seq": 3})
    logs = ov.text.toPlainText()
    recv_log = [l for l in logs.splitlines() if "收到应用层 pong" in l]
    print(f"  日志里的 pong 行（含 RTT）= {recv_log[-1:]}")
    assert recv_log and "RTT" in recv_log[-1], "收到 pong 必须进日志并给出 RTT"
    _cli_mod.ws_sock = None
    _cli_mod.recv_buf = b""

    # ────────────────────────────────────────────────────────────────────────────────
    # 协议级心跳：间隔 20s + "发之前打一行"（三端逐字一致）——不起真线程、不连服务器
    # ────────────────────────────────────────────────────────────────────────────────
    print("===== WS 心跳：间隔与日志文案（client.py）=====")
    print(f"  WS_HEARTBEAT_INTERVAL = {_cli_mod.WS_HEARTBEAT_INTERVAL}（应为 20.0）"
          f"｜WS_HEARTBEAT_TIMEOUT = {_cli_mod.WS_HEARTBEAT_TIMEOUT}（应为 10.0，本轮不动）")
    assert _cli_mod.WS_HEARTBEAT_INTERVAL == 20.0, "心跳间隔必须统一成 20s"
    assert _cli_mod.WS_HEARTBEAT_TIMEOUT == 10.0, "判活超时保持 10s"
    expect1 = "WS 心跳：发出协议级 ping（第 1 次，间隔 20s）"
    got1 = _cli_mod.ws_heartbeat_log_text(1)
    print(f"  第 1 次文案 = {got1!r}")
    print(f"  第 3 次文案 = {_cli_mod.ws_heartbeat_log_text(3)!r}")
    assert got1 == expect1, f"文案必须逐字一致：期望 {expect1!r}"
    assert _cli_mod.ws_heartbeat_log_text(3) == "WS 心跳：发出协议级 ping（第 3 次，间隔 20s）"

    print("  驱动一轮心跳（_ws_heartbeat_tick，不起线程）：")
    hb_sock = _StubSocket()
    t0 = 1000.0

    def _unmask(masked: bytes, mask: bytes) -> bytes:
        """本地解掩码（GUI 已不再有 ws_unmask —— 那是随心跳实现一起删掉的）"""
        return bytes(b ^ mask[i % 4] for i, b in enumerate(masked))

    def _hb_log_lines():
        """只数**真正的日志行**（带 [时间][client] 前缀）——
        self-test 自己的 print 也会被 tee 进日志浮层，不能算进去。"""
        return [l for l in ov.text.toPlainText().splitlines()
                if l.startswith("[") and "WS 心跳：发出协议级 ping" in l]

    def _hb_set(last_tx, last_rx, ping_at=0.0):
        """人工摆好心跳状态（用合成时钟，别等真 20s）"""
        _cli_mod.ws_sock = hb_sock
        _cli_mod.connected = True
        _cli_mod._hb_stop.clear()
        _cli_mod._hb_count = 0
        _cli_mod._hb_last_tx = last_tx
        _cli_mod._hb_last_rx = last_rx
        _cli_mod._hb_ping_sent_at = ping_at

    _hb_set(last_tx=t0, last_rx=t0)
    r_idle = _cli_mod._ws_heartbeat_tick(t0 + 5)      # 才过 5s：只检查，不发也不打日志
    print(f"    now-{t0:.0f}=5s    → {r_idle!r}，计数={_cli_mod._hb_count}（应 0），"
          f"socket 收到 {len(hb_sock.take())} 字节（应 0）")
    assert r_idle == "idle" and _cli_mod._hb_count == 0

    r_sent = _cli_mod._ws_heartbeat_tick(t0 + 20.5)   # 到点：打日志 + 发帧
    frame1 = hb_sock.take()
    payload1 = _cli_mod.ws_heartbeat_payload(1)
    hb_lines = _hb_log_lines()
    print(f"    now-{t0:.0f}=20.5s → {r_sent!r}，计数={_cli_mod._hb_count}（应 1），"
          f"socket 收到 {len(frame1)} 字节 byte0={frame1[0]:#04x}，日志={hb_lines[-1:]}")
    assert r_sent == "sent" and _cli_mod._hb_count == 1
    assert frame1 and frame1[0] == 0x89, "到点必须真发 0x9 掩码帧"
    assert len(frame1) == 6 + len(payload1), "帧长应是 2 字节头 + 4 字节 mask + payload"
    assert frame1[6:] != payload1 and _unmask(frame1[6:], frame1[2:6]) == payload1, \
        "心跳 payload 必须带序号（p2pnet#N）且是掩码后的"
    print(f"    心跳 payload = {payload1!r}（带序号，服务端原样回）")
    assert hb_lines and hb_lines[-1].endswith(expect1), "发之前必须打那行日志"

    _cli_mod._hb_last_rx = t0 + 20.6                  # 模拟服务端的协议级 pong 到了
    r_idle2 = _cli_mod._ws_heartbeat_tick(t0 + 21.0)  # 刚发完：不该再发
    n_lines_2 = len(_hb_log_lines())
    print(f"    now-{t0:.0f}=21s   → {r_idle2!r}，计数={_cli_mod._hb_count}（应仍 1），"
          f"心跳日志行数={n_lines_2}（应仍 1，即「没发就不打」）")
    assert r_idle2 == "idle" and _cli_mod._hb_count == 1 and n_lines_2 == 1

    _cli_mod._hb_last_rx = t0 + 40.9                  # 模拟这段时间一直在收字节
    r_sent2 = _cli_mod._ws_heartbeat_tick(t0 + 41.0)  # 再过 20s：第 2 次
    frame2 = hb_sock.take()
    hb_lines = _hb_log_lines()
    print(f"    now-{t0:.0f}=41s   → {r_sent2!r}，计数={_cli_mod._hb_count}（应 2），"
          f"socket 收到 {len(frame2)} 字节 byte0={frame2[0]:#04x}，日志={hb_lines[-1:]}")
    assert r_sent2 == "sent" and _cli_mod._hb_count == 2
    assert frame2 and frame2[0] == 0x89
    assert hb_lines[-1].endswith("WS 心跳：发出协议级 ping（第 2 次，间隔 20s）")

    print("  收到协议级 pong（真喂 0xA 帧进 ws_recv，返回契约仍是 None）：")
    def _feed_pong(payload_bytes):
        _cli_mod.recv_buf = bytes([0x8A, len(payload_bytes)]) + payload_bytes  # 服务端→客户端不掩码
        ret = _cli_mod.ws_recv()
        return ret

    before = len([l for l in ov.text.toPlainText().splitlines()
                  if l.startswith("[") and "收到协议级 pong" in l])
    _cli_mod._hb_ping_sent_at = t0 + 20.5      # 先摆成"正在等应答"
    ret1 = _feed_pong(_cli_mod.ws_heartbeat_payload(1))
    pong_lines = [l for l in ov.text.toPlainText().splitlines()
                  if l.startswith("[") and "收到协议级 pong" in l]
    print(f"    喂 payload={_cli_mod.ws_heartbeat_payload(1)!r} → ws_recv() 返回 {ret1!r}（契约：必须 None），"
          f"日志={pong_lines[-1:]}")
    assert ret1 is None, "ws_recv() 对 pong 的返回契约必须保持 None"
    print(f"    应答到达后 _hb_ping_sent_at={_cli_mod._hb_ping_sent_at}（应 0.0 = 不再等应答）")
    assert _cli_mod._hb_ping_sent_at == 0.0, "收到自己的心跳 pong 后应清掉等待状态"
    assert len(pong_lines) == before + 1, "真读到 0xA 才该多一行日志"
    assert pong_lines[-1].endswith("WS 心跳：收到协议级 pong（第 1 次）"), "文案必须逐字一致"

    ret2 = _feed_pong(_cli_mod.ws_heartbeat_payload(7))
    pong_lines2 = [l for l in ov.text.toPlainText().splitlines()
                   if l.startswith("[") and "收到协议级 pong" in l]
    print(f"    喂 payload={_cli_mod.ws_heartbeat_payload(7)!r} → 日志={pong_lines2[-1:]}"
          f"（N 应等于 payload 里的序号 7）")
    assert pong_lines2[-1].endswith("WS 心跳：收到协议级 pong（第 7 次）"), "N 必须等于 payload 里的序号"

    ret3 = _feed_pong(b"someone-elses-pong")
    pong_lines3 = [l for l in ov.text.toPlainText().splitlines()
                   if l.startswith("[") and "收到协议级 pong" in l]
    print(f"    喂一个非心跳 payload={b'someone-elses-pong'!r} → 日志行数不变="
          f"{len(pong_lines3) == len(pong_lines2)}（不该误报成第 N 次）")
    assert ret3 is None and len(pong_lines3) == len(pong_lines2)

    print(f"  文案 helper：{_cli_mod.ws_heartbeat_pong_log_text(5)!r}")
    assert _cli_mod.ws_heartbeat_pong_log_text(5) == "WS 心跳：收到协议级 pong（第 5 次）"

    print("  判死条件（回归：必须「ping 之后一直没收到任何字节」才判死）")
    def _hb_die_case(name, last_rx, ping_at, now, want_dead):
        _hb_set(last_tx=ping_at, last_rx=last_rx, ping_at=ping_at)   # last_tx=ping_at：像刚发过 ping
        r = _cli_mod._ws_heartbeat_tick(now)
        print(f"    {name:36s} last_rx-ping={last_rx - ping_at:+.1f}s，"
              f"now-ping={now - ping_at:+.1f}s → {r!r}，connected={_cli_mod.connected}")
        assert (r == "dead") is want_dead, \
            f"{name}：期望 {'dead' if want_dead else '不判死'}，实际 {r!r}"
        return r

    t_ping = t0 + 41.0
    _hb_die_case("① pong 已到达（last_rx=ping+0.1s）", t_ping + 0.1, t_ping, t_ping + 10.5, False)
    _hb_die_case("② 真没回（last_rx=ping-0.1s）", t_ping - 0.1, t_ping, t_ping + 10.5, True)
    _hb_die_case("③ 边界 last_rx == ping_at", t_ping, t_ping, t_ping + 10.5, False)
    _hb_die_case("④ 还没到超时（ping+9.5s）", t_ping - 0.1, t_ping, t_ping + 9.5, False)
    print(f"    ①③④ 都不判死、② 判死 → 这条曾写错的判死条件已被钉住"
          f"（旧写法 now-last_rx>=10 会让 ① 在 ping+10s 稳定误判）")
    tail_dead = [l for l in ov.text.toPlainText().splitlines() if "pong 超时" in l]
    assert tail_dead, "② 应该留下判死那一行日志"

    # 复位（别把假状态留给后面的断言）
    _cli_mod.stop_ws_heartbeat()
    _cli_mod._hb_stop.clear()
    _cli_mod._hb_ping_sent_at = 0.0
    _cli_mod._hb_count = 0
    _cli_mod.connected = True
    _cli_mod.ws_sock = None

    # ────────────────────────────────────────────────────────────────────────────────
    # 【1】WS 自动重连：策略纯函数 + 熔断/重置 + 文案
    # ────────────────────────────────────────────────────────────────────────────────
    print("===== WS 自动重连（带熔断）策略 =====")
    delays = [_cli_mod.ws_reconnect_delay(i) for i in range(1, 5)]
    print(f"  退避表（第 1/2/3/4 次）= {delays}（应 [1.0, 2.0, 4.0, None]）")
    assert delays == [1.0, 2.0, 4.0, None], "退避必须是 1s→2s→4s，第 4 次熔断"

    T = 10000.0
    W = _cli_mod.WS_RECONNECT_WINDOW
    L = _cli_mod.WS_RECONNECT_MAX
    print(f"  滑窗 = {W}s，窗口内上限 = {L} 次")
    assert (W, L) == (60.0, 3)

    three = [T - 50, T - 30, T - 1]         # 3 次都在 60s 窗口内
    print(f"  窗口内 3 次尝试 → allowed={_cli_mod.ws_reconnect_allowed(three, T)}（应 False = 第 4 次不许）")
    assert _cli_mod.ws_reconnect_allowed(three, T) is False
    pruned = _cli_mod.ws_reconnect_prune(three + [T - 61, T - 70], T)
    print(f"  滑窗外（-61s/-70s）被丢掉 → 剩下 {len(pruned)} 条（应 3）")
    assert len(pruned) == 3
    print(f"  时间滑过去 61s 后 → allowed={_cli_mod.ws_reconnect_allowed(three, T + 61)}（应 True）")
    assert _cli_mod.ws_reconnect_allowed(three, T + 61) is True
    print(f"  空列表（= 手动连接/稳定 60s 后清零）→ allowed="
          f"{_cli_mod.ws_reconnect_allowed([], T)}（应 True）")
    assert _cli_mod.ws_reconnect_allowed([], T) is True

    print(f"  文案：{_cli_mod.ws_reconnect_log_attempt_text(1)!r}")
    print(f"  文案：{_cli_mod.ws_reconnect_log_ok_text(3)!r}")
    print(f"  文案：{_cli_mod.WS_RECONNECT_GIVEUP_TEXT!r}")
    assert _cli_mod.ws_reconnect_log_attempt_text(1) == "WS 自动重连：第 1 次（60 秒窗口内）"
    assert _cli_mod.ws_reconnect_log_ok_text(3) == "WS 自动重连成功（第 3 次）"
    assert _cli_mod.WS_RECONNECT_GIVEUP_TEXT == (
        "WS 自动重连已放弃：60 秒内已重连 3 次仍失败（不再自动重连，请手动连接）")

    print("  桥的决策 _reconnect_plan（不起线程、不联网）：")
    _cli_mod._rc_attempts = []
    print(f"    空计数        → {win.engine._reconnect_plan(T)}（应 (1, 1.0)）")
    assert win.engine._reconnect_plan(T) == (1, 1.0)
    _cli_mod._rc_attempts = [T - 30]
    print(f"    窗口内 1 次    → {win.engine._reconnect_plan(T)}（应 (2, 2.0)）")
    assert win.engine._reconnect_plan(T) == (2, 2.0)
    _cli_mod._rc_attempts = [T - 30, T - 20]
    print(f"    窗口内 2 次    → {win.engine._reconnect_plan(T)}（应 (3, 4.0)）")
    assert win.engine._reconnect_plan(T) == (3, 4.0)
    _cli_mod._rc_attempts = [T - 30, T - 20, T - 10]
    print(f"    窗口内 3 次    → {win.engine._reconnect_plan(T)}（应 None = 放弃，且之后不再尝试）")
    assert win.engine._reconnect_plan(T) is None
    assert win.engine._reconnect_plan(T + 5) is None, "放弃后（窗口没滑过去）不应再尝试"
    _cli_mod._rc_attempts = [T - 30, T - 20, T - 10]
    _cli_mod._rc_attempts = []               # 模拟『计数重置①：用户手动连接』
    print(f"    计数清零后     → {win.engine._reconnect_plan(T)}（应 (1, 1.0)）")
    assert win.engine._reconnect_plan(T) == (1, 1.0)
    # 真跑一次"放弃"路径：窗口已满 → client.py 的 ws_auto_reconnect 直接打日志并放弃（**不联网**）
    caught: list = []
    now_real = time.time()
    win.engine.line.connect(caught.append)
    _cli_mod._rc_attempts = [now_real - 30, now_real - 20, now_real - 10]   # 窗口内已 3 次
    _cli_mod._last_connected_at = 0.0
    ok = _cli_mod.ws_auto_reconnect("127.0.0.1", 1)
    gave_up = [l for l in caught if "自动重连已放弃" in l]
    print(f"    窗口内已用满 3 次 → ws_auto_reconnect 返回 {ok}（应 False），"
          f"打出 {len(gave_up)} 行放弃日志：{gave_up[-1:]}")
    assert ok is False and gave_up and gave_up[-1].endswith(_cli_mod.WS_RECONNECT_GIVEUP_TEXT)
    win.engine.line.disconnect(caught.append)
    _cli_mod._rc_attempts = []

    # 手动断开 / 退出 都不该重连
    win.engine._manual_disconnect = True
    print(f"    手动断开标记 → _maybe_reconnect() 是否会起线程："
          f"{'会' if (win.engine._host is not None) else '不会'}（_host=None 时也不会）")
    win.engine._manual_disconnect = False

    # ────────────────────────────────────────────────────────────────────────────────
    # 【2】界面里不该再有啰嗦说明（机器证据：源码里的字符串字面量里没有那些字样）
    # ────────────────────────────────────────────────────────────────────────────────
    # ────────────────────────────────────────────────────────────────────────────────
    # 四端统一：① 主动断开 / ② 被踢 → 都不重连、不重登；③ 被动断开 → 都允许
    # ────────────────────────────────────────────────────────────────────────────────
    print("===== 自动重连/重登规则（只看断开前的最后状态）=====")
    t1 = _cli_mod.should_reconnect("manual")
    t2 = _cli_mod.should_relogin("manual", True)
    t3 = _cli_mod.should_reconnect("passive")
    t4 = _cli_mod.should_relogin("passive", True)
    t5 = _cli_mod.should_relogin("passive", False)
    print(f"  1) 用户主动断开                        → 重连={t1} 重登={t2}（应 False/False）")
    print(f"  2) 被动断开 + 断开前已登录              → 重连={t3} 重登={t4}（应 True/True）")
    print(f"  3) 被动断开 + 断开前未登录              → 重连={t3} 重登={t5}（应 True/False）")
    assert (t1, t2) == (False, False), "① 主动断开：都不做"
    assert (t3, t4) == (True, True), "② 被动断开 + 已登录：都做"
    assert (t3, t5) == (True, False), "③ 被动断开 + 未登录：只重连"

    # 4) 被踢 → 状态变成"已连接未登录" → 掉线 → 重连 ✅ / 重登 ❌
    _cli_mod._user_quit = False
    _cli_mod.logged_in_user = "e2e"          # 先假装已登录
    _cli_mod.handle_server_message({"type": "kicked", "message": "re-login from another connection"})
    kicked_state = _cli_mod.logged_in_user
    _cli_mod.mark_disconnected()             # 之后连接被动断开（收尾记下"断开前是否已登录"）
    kicked_rc, kicked_rl = _cli_mod.reconnect_allowed(), _cli_mod.relogin_allowed()
    print(f"  4) 被踢（logged_in_user={kicked_state!r}）后掉线 → 重连={kicked_rc} 重登={kicked_rl}"
          f"（应 True/False；_was_logged_in={_cli_mod._was_logged_in}）")
    assert (kicked_rc, kicked_rl) == (True, False), "被踢后掉线：要重连、不要自动重登"

    # 5) 被踢后用户手动 login 成功（状态回到已登录）→ 再掉线 → 重连 ✅ / **重登 ✅**
    #    （证明"状态本身就是真相"，不需要任何"被踢标记"）
    _cli_mod.mark_user_connect()             # 手动连接/登录时调
    _cli_mod.logged_in_user = "e2e"          # 手动 login 成功
    _cli_mod.mark_disconnected()             # 再掉线
    relogin_after_manual = _cli_mod.relogin_allowed()
    print(f"  5) 被踢 → 手动 login → 再掉线 → 重连={_cli_mod.reconnect_allowed()} "
          f"重登={relogin_after_manual}（应 True/True）｜_was_logged_in={_cli_mod._was_logged_in}")
    assert _cli_mod.reconnect_allowed() is True and relogin_after_manual is True, \
        "手动登录后状态回到已登录 → 再掉线应当又能自动重登（说明不需要清什么标记）"

    # 6) 被踢本身：不产生断开、不排重连、**不停心跳**；只取消登录态 + 打统一文案
    _cli_mod._hb_stop.clear()
    _cli_mod.logged_in_user = "e2e"
    _cli_mod.session_key = b"x"
    before_kick = ov.text.toPlainText()
    _cli_mod.handle_server_message({"type": "kicked", "message": "re-login from another connection"})
    kicked_log = ov.text.toPlainText()[len(before_kick):]
    print(f"  6) kicked 之后：登录态已清={_cli_mod.logged_in_user is None and _cli_mod.session_key is None}"
          f"｜心跳是否被停={_cli_mod._hb_stop.is_set()}（应 False）"
          f"｜日志={[l for l in kicked_log.splitlines() if l.startswith('[')][-1:]}")
    assert _cli_mod.logged_in_user is None and _cli_mod.session_key is None
    assert _cli_mod._hb_stop.is_set() is False, "被踢不是断开：不许停心跳"
    assert "被服务器踢下线（re-login from another connection）：登录已取消，不会自动重新登录" in kicked_log

    # 7) resume_login 的两行统一文案 + "只发一次登录"（不循环重试）
    caught2: list = []
    sent: list = []
    real_send = _cli_mod.ws_send
    _cli_mod.ws_send = lambda sock, obj: sent.append(obj)
    win.engine.line.connect(caught2.append)

    _cli_mod._was_logged_in = False
    _cli_mod.resume_login()
    text_not_logged_in = list(caught2)

    caught2.clear()
    _cli_mod._was_logged_in = True
    _cli_mod._saved_login_user = _cli_mod._saved_login_pass = None
    _cli_mod.resume_login()
    text_no_cred = list(caught2)

    caught2.clear()
    _cli_mod._user_quit = False
    _cli_mod._was_logged_in = True
    _cli_mod._saved_login_user, _cli_mod._saved_login_pass = "e2e", "pw"
    _cli_mod.resume_login()
    text_relogin = list(caught2)
    n_login_sent = len(sent)
    _cli_mod.ws_send = real_send
    win.engine.line.disconnect(caught2.append)

    print(f"  7) 断开前未登录      → {[l for l in text_not_logged_in if '自动重连' in l][-1:]}")
    print(f"     已登录但没凭据    → {[l for l in text_no_cred if '自动重连' in l][-1:]}")
    print(f"     已登录且有凭据    → {[l for l in text_relogin if '自动重连' in l][-1:]}"
          f"｜实际发出的 login 条数={n_login_sent}（只发一次，不循环重试）")
    assert any("连接已恢复，断开前未登录，不自动重新登录" in l for l in text_not_logged_in)
    assert any("连接已恢复，但没有可用的凭据，需要手动重新登录" in l for l in text_no_cred)
    assert any("用保存的凭据重新登录" in l for l in text_relogin)
    assert n_login_sent == 1, f"三种情况里只有「有凭据」那次该发 login，实际发了 {n_login_sent} 次"

    # 8) 主动断开：连试都不试（不联网）
    _cli_mod._user_quit = True
    ok_manual = _cli_mod.ws_auto_reconnect("127.0.0.1", 1)
    print(f"  8) 用户主动断开时 ws_auto_reconnect() = {ok_manual}（应 False，且不联网）")
    assert ok_manual is False

    # 复位
    _cli_mod.mark_user_connect()
    _cli_mod._was_logged_in = False
    _cli_mod._saved_login_user = _cli_mod._saved_login_pass = None
    _cli_mod.logged_in_user = None
    _cli_mod.session_key = None

    print("===== 界面文案净化（AST 抽字符串字面量，排除 docstring）=====")
    import ast as _ast
    tree = _ast.parse(open(os.path.abspath(__file__), encoding="utf-8").read())
    docstrings = set()
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.Module, _ast.ClassDef, _ast.FunctionDef, _ast.AsyncFunctionDef)):
            doc = _ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)
    ui_strings = [n.value for n in _ast.walk(tree)
                  if isinstance(n, _ast.Constant) and isinstance(n.value, str)
                  and n.value not in docstrings]
    # ⚠️ 用拼接构造：否则这些字样本身就是"字符串字面量"，会被断言自己扫到（踩过两次）
    banned_ui = ["python" + " 端", "python" + "端", "第 5 行" + "点", "第5行" + "点",
                 "参数" + "一一对应", "media" + ".py", "switch" + ".py", "vpn" + ".py",
                 "proxy" + ".py", "wg-python" + ".py", "wg-calltool" + ".py",
                 "ffmpeg" + ".sh", "client/" + "app/",
                 # 空态废话：空态已由首行状态表达，不该再单独占一行（有通道时要渲染的是动态列表）
                 "通道：" + "还没有"]
    print(f"  扫了 {len(ui_strings)} 个界面字符串字面量；被禁字样：{banned_ui}")
    hits = [(b, t) for b in banned_ui for t in ui_strings if b in t]
    for b, t in hits:
        print(f"    ✗ {b!r} 出现在 {t[:60]!r}")
    assert not hits, f"界面文案里还有啰嗦说明：{hits}"
    print("  ✓ 0 处命中（这些信息现在只在代码注释/docstring 里）")

    # 界面说明行清单（白名单）：**只剩这两条**，且都不属于"空态重复"
    #   · 字段语义：填哪个地址（不是教学，也不是空态）
    #   · 最短操作提示：网口可点（别处没有表达）
    # 空态文案（如 `通道：还没有`）已删 —— 空态由首行状态表达；有通道时该渲染的是动态列表。
    own_src2 = open(os.path.abspath(__file__), encoding="utf-8").read()
    note_texts = re.findall(r'section_note\(self,\s*"([^"]+)"', own_src2)
    expected_notes = ["对方路由器公网地址:端口（对方内网地址不用管）", "点网口 = 拔线"]
    print(f"  界面说明行清单（section_note）共 {len(note_texts)} 条：")
    for t in note_texts:
        print(f"    · {t}")
    assert note_texts == expected_notes, \
        f"界面说明行清单变了（{note_texts}）：新增说明行要先过'是否啰嗦/空态重复'这一关"

    # ────────────────────────────────────────────────────────────────────────────────
    # 【3】switch 页版式：配置（含启停）→ DHCP → 拓扑（最后）
    # ────────────────────────────────────────────────────────────────────────────────
    print("===== switch / vpn 页版式 + DHCP 卡显隐 + 首行等宽（真量像素）=====")

    def _card_body(card_frame):
        """取卡片的内容布局（卡片可能没有标题行，所以不能假设固定层号）"""
        outer = card_frame.layout()
        for i in range(outer.count()):
            if outer.itemAt(i).layout() is not None:
                return outer.itemAt(i).layout()
        raise AssertionError("卡片里没有取到内容布局")

    def _measure_row(page, row):
        """
        把页面切到当前页并**强制跑一次布局/渲染**（win.grab()），再量这一行在页面坐标里的 x/宽度。

        ⚠️ 不 grab 的话，控件全是 100×30 的默认尺寸（父 agent 也踩过这个坑）——
        这样量出来的"等宽"毫无意义。所以这里断言宽度必须接近页面可用宽度。
        """
        win.stack.setCurrentWidget(page)
        win.grab()
        app.processEvents()
        tl = row.mapTo(page, QPoint(0, 0))
        return tl.x(), row.width(), row.height()

    def _card_direct_rows(card_frame):
        body = _card_body(card_frame)
        return [body.itemAt(i).widget() for i in range(body.count())
                if body.itemAt(i).widget() is not None]

    vpn_page = next(p for p in win.pages if getattr(p, "kind", "") == "vpn")
    sw_page = next(p for p in win.pages if getattr(p, "kind", "") == "switch")
    proxy_page = next(p for p in win.pages if getattr(p, "kind", "") == "proxy")

    for page, name in ((vpn_page, "vpn"), (sw_page, "switch"), (proxy_page, "proxy")):
        titles = page.card_titles()
        print(f"  [{name}] 卡片顺序 = {titles}")
        assert titles[0] == "配置", f"{name}: 配置卡必须是第一张"
        if name == "switch":
            assert titles == ["配置", "嵌入 DHCP 服务器", "拓扑"]
        elif name == "vpn":
            assert titles == ["配置", "嵌入 DHCP 服务器"]
        # proxy 第二张卡的标题还带着 -L/-R 说明（三端一致的老文案，等父 agent 统一，这里不钉死）

        have_dhcp = hasattr(page, "f_dhcp")
        if have_dhcp:
            # dhcpEnabled 默认必须是 false，且 DHCP 整卡默认隐藏
            print(f"  [{name}] dhcpEnabled 默认 = {page.sw_dhcp.isChecked()}（必须 False）"
                  f"｜DHCP 卡默认 isHidden = {page.f_dhcp.isHidden()}（必须 True）")
            assert page.sw_dhcp.isChecked() is False, "dhcpEnabled 默认必须是 false"
            assert page.f_dhcp.isHidden() is True, "默认不启用时 DHCP 卡必须整卡隐藏"
            # ⚠️ 必须先让 DHCP 卡**可见**再量：隐藏控件的几何是未布局的 sizeHint（会量出 x=13 w=74 h=0）
            page.sw_dhcp.setChecked(True)
            win.grab()
            app.processEvents()

        x1, w1, h1 = _measure_row(page, page.row_cfg)
        usable = page.width() - 2 * 12 - 2 * 1          # 卡片左右各 12 margin + 1px 边框
        print(f"  [{name}] 页面宽={page.width()}（可用内宽≈{usable}）")
        print(f"  [{name}] 配置卡首行： x={x1:4d}  w={w1:4d}  右边界={x1 + w1:4d}  h={h1}")
        assert w1 > 500, f"没量到真实尺寸（{w1}px 说明页面没被激活/布局）"
        assert h1 == CARD_HEAD_H, f"{name}: 配置卡首行高度应 = CARD_HEAD_H={CARD_HEAD_H}，实际 {h1}"

        if have_dhcp:
            x2, w2, h2 = _measure_row(page, page.row_dhcp)
            page.sw_dhcp.setChecked(False)      # 量完立刻复位成"默认关闭"
            win.grab()
            app.processEvents()
            print(f"  [{name}] DHCP 卡首行：x={x2:4d}  w={w2:4d}  右边界={x2 + w2:4d}  h={h2}")
            assert x1 == x2, f"{name}: 两行左边界不一致（配置 x={x1} vs DHCP x={x2}）"
            assert w1 == w2, f"{name}: 两行宽度不一致（配置 w={w1} vs DHCP w={w2}）"
            assert h1 == h2, f"{name}: 两行高度不一致（配置 h={h1} vs DHCP h={h2}）"
            print(f"  [{name}] ✓ 两行 x/宽度/高度完全一致（x={x1}, w={w1}, h={h1}）")
            assert h1 == CARD_HEAD_H == h2
            # 勾上开关 → DHCP 整卡显示；取消 → 又隐藏
            page.sw_dhcp.setChecked(True)
            app.processEvents()
            shown = not page.f_dhcp.isHidden()
            page.sw_dhcp.setChecked(False)
            app.processEvents()
            hidden_again = page.f_dhcp.isHidden()
            print(f"  [{name}] 开关打开 → DHCP 卡显示={shown}；再关闭 → 隐藏={hidden_again}")
            assert shown is True and hidden_again is True, "开关必须控制整卡显隐"

        # 防呆：固定高度别把文字/控件裁掉（连 minimumHeight 一起看，30px 的按钮也会被抓）
        for row in [page.row_cfg] + ([page.row_dhcp] if have_dhcp else []):
            for i in range(row.layout().count()):
                w = row.layout().itemAt(i).widget()
                if w is not None:
                    need = max(w.sizeHint().height(), w.minimumHeight())
                    assert need <= row.height(), \
                        f"{name}: {type(w).__name__} 需要 {need}px > 行高 {row.height()}px（会被裁）"

        # 首行左标签固定「配置」；状态与启停都必须在这一行里
        cfg_title = next(l for l in page.row_cfg.findChildren(QLabel)
                         if l.objectName() == "cardTitle")
        state_lab = getattr(page, "lab_state", None) or getattr(page, "lab_ports", None)
        print(f"  [{name}] 配置卡首行左标签 = {cfg_title.text()!r}（必须 '配置'）"
              f"｜右状态 = {state_lab.text()!r}｜按钮 = {page.btn_toggle.text()!r}"
              f"（按钮高={page.btn_toggle.height()}px）")
        assert cfg_title.text() == "配置", f"{name}: 首行左标签必须是「配置」（三端一致）"
        assert page.btn_toggle.parent() is page.row_cfg, "启停按钮必须在首行里"
        assert state_lab is not None and state_lab.parent() is page.row_cfg, \
            "状态标签必须在首行里（vpn/proxy=lab_state，switch=lab_ports）"

        # 状态文案两态：**口径三端统一** —— vpn/proxy 看通道数，switch 看网口数（词不同，别被"统一"掉）
        if name in ("vpn", "proxy"):
            assert state_lab.text() == "未接线", f"{name}: 空态应为「未接线」"
            page.set_channels(3)
            mid = state_lab.text()
            page.set_channels(0)
            print(f"  [{name}] 状态文案两态（通道数）：空={state_lab.text()!r}，N=3 → {mid!r}")
            assert mid == "已接 3 条" and state_lab.text() == "未接线"
        elif name == "switch":
            assert state_lab.text() == "未插线", "switch: 空态应为「未插线」（与同页拓扑卡同词）"
            page.set_ports(3)
            mid = state_lab.text()
            page.set_ports(0)
            print(f"  [{name}] 状态文案两态（网口数）：空={state_lab.text()!r}，N=3 → {mid!r}")
            assert mid == "已插 3 个" and state_lab.text() == "未插线"

        # 至少一张卡的页面，第二张卡的标题行也量一下（仅供参考，不参与等宽/等高断言）
        if not have_dhcp:
            print(f"  [{name}] 页内卡片：{titles}（无 DHCP 卡，故只断言配置首行 h={h1}）")


    # ────────────────────────────────────────────────────────────────────────────────
    # 行高/行间隙：**必须在高窗口下量**（bug 只在"卡片独吞高度"时明显）
    # ────────────────────────────────────────────────────────────────────────────────
    # switch 页尾部结构 + 「内嵌 DHCP」行（开关 + 标签样式）—— 这三条在上一轮大块替换时被我弄丢过，补回
    cfg_card = sw_page.body.itemAt(0).widget()
    head_row = _card_body(cfg_card).itemAt(0).widget()
    head_widgets = [head_row.layout().itemAt(i).widget().__class__.__name__
                    for i in range(head_row.layout().count())]
    print(f"  [switch] 配置卡第一行控件 = {head_widgets}｜文案 = {sw_page.btn_toggle.text()!r}")
    assert sw_page.btn_toggle in head_row.findChildren(QPushButton), "启停按钮必须在配置卡首行"
    assert sw_page.lab_ports in head_row.findChildren(QLabel), "状态文本也应在首行"
    topo_card = sw_page.body.itemAt(2).widget()
    print(f"  [switch] 拓扑卡里的按钮数 = {len(topo_card.findChildren(QPushButton))}（应 0）")
    assert not topo_card.findChildren(QPushButton), "拓扑卡里不该再放启停按钮"

    for page, name in ((sw_page, "switch"), (vpn_page, "vpn"), (proxy_page, "proxy")):
        win.stack.setCurrentWidget(page)
        if hasattr(page, "sw_dhcp"):
            default_checked = page.sw_dhcp.isChecked()      # 新页面的**默认**值（应为 False）
            default_hidden = page.f_dhcp.isHidden()         # 默认 DHCP 卡隐藏
            page.sw_dhcp.setChecked(True)                   # 量可见几何时临时打开（下面会复位）
        win.grab()
        app.processEvents()
        cfg = page.body.itemAt(0).widget()
        rows = _card_direct_rows(cfg)
        if not hasattr(page, "sw_dhcp"):
            win.grab()
            continue
        toggle_row = rows[-1]
        sw = toggle_row.findChildren(ToggleSwitch)[0]
        t_lab = toggle_row.findChildren(QLabel)[0]
        ref_row = next(r for r in rows
                       if any(l.text() == "路由老化" for l in r.findChildren(QLabel)))
        ref_lab = next(l for l in ref_row.findChildren(QLabel) if l.text() == "路由老化")
        ref_ctl = ref_row.findChildren(QLineEdit)[0]        # 同卡片「路由老化」那行的输入框
        title_lab = next(l for l in rows[0].findChildren(QLabel) if l.objectName() == "cardTitle")
        sw_x = sw.mapTo(page, QPoint(0, 0)).x()
        ctl_x = ref_ctl.mapTo(page, QPoint(0, 0)).x()
        right_inner = cfg.mapTo(page, QPoint(0, 0)).x() + cfg.width() - 13   # 卡片内容右边界（12 margin + 1 边框）
        print(f"  [{name}] 内嵌 DHCP 行：开关 {type(sw).__name__} {sw.width()}x{sw.height()}，"
              f"x={sw_x}（同行控件「路由老化」输入框 x={ctl_x}）"
              f"｜开关右边界={sw_x + sw.width()} vs 卡片内容右边界={right_inner}")
        print(f"  [{name}] 行高：内嵌 DHCP={toggle_row.height()}，路由老化={ref_row.height()}"
              f"（应相等；开关不再贴最右，右边留空 {right_inner - sw_x - sw.width()}px）")
        print(f"  [{name}] 新页面默认：checked={default_checked}（应 False）／DHCP 卡默认隐藏={default_hidden}"
              f"（应 True）｜本次测量为临时打开")
        assert sw in toggle_row.findChildren(ToggleSwitch), "内嵌 DHCP 开关应是配置卡最后一行"
        assert sw_x == ctl_x, f"开关必须落在字段标签列之后（x={sw_x} vs 同行控件 x={ctl_x}）"
        assert toggle_row.height() == ref_row.height(), \
            f"该行高度必须与相邻字段行相同（{toggle_row.height()} vs {ref_row.height()}）"
        assert right_inner - (sw_x + sw.width()) > 300, \
            f"开关不该被顶到最右（右边只剩 {right_inner - sw_x - sw.width()}px）"
        assert t_lab.objectName() == "fieldLabel", "「内嵌 DHCP」标签必须跟字段标签同样式（别用 cardTitle）"
        assert t_lab.font().weight() == ref_lab.font().weight(), "字重必须和「路由老化」一致（不许加粗）"
        assert t_lab.font().weight() < title_lab.font().weight(), "应比卡片标题细（标题才是加粗白）"
        assert default_checked is False and default_hidden is True, "新页面必须默认关闭且 DHCP 卡隐藏"
        assert sw.isChecked() is True and not page.f_dhcp.isHidden(), "开关打开时 DHCP 卡应可见"
        sw.setChecked(False)
        app.processEvents()
        assert page.f_dhcp.isHidden(), "开关关闭时 DHCP 卡应隐藏"
        win.grab()

        # ⚠️ **真鼠标事件**路径（上面只用 setChecked，漏掉过实机 bug：开关被 field_row 的
        #    `enabled=False` 默认值禁用 → 点了没反应、DHCP 卡永远出不来）
        def _click(widget):
            c = widget.rect().center()
            g = widget.mapToGlobal(c)
            for kind in (QEvent.Type.MouseButtonPress, QEvent.Type.MouseButtonRelease):
                widget.event(QMouseEvent(kind, QPointF(c), QPointF(g),
                                         Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton,
                                         Qt.KeyboardModifier.NoModifier))

        assert sw.isEnabled() is True, \
            "开关必须可点（field_row 的 enabled 默认 False，构造时别忘 enabled=True）"
        _click(sw)
        app.processEvents()
        win.grab()
        app.processEvents()
        on_ok = sw.isChecked() and not page.f_dhcp.isHidden() and page.f_dhcp.height() > 0
        geo = page.f_dhcp.geometry()
        _click(sw)
        app.processEvents()
        off_ok = (not sw.isChecked()) and page.f_dhcp.isHidden()
        print(f"  [{name}] 真鼠标点击开关：开 → checked={sw.isChecked() is False} "
              f"卡可见/几何={geo}；再点 → 关={off_ok}")
        assert on_ok, f"真点击必须能打开并显示 DHCP 卡（几何={geo}）"
        assert off_ok, "真点击必须能关回去"

        # 点完开关以后页面还得能响应别的控件（用户报过"点其他东西也没反应"）
        before = len(ov.text.toPlainText())
        _click(page.btn_toggle)
        app.processEvents()
        after_txt = ov.text.toPlainText()
        assert len(after_txt) > before and f"{name}：启动" in after_txt, \
            "切换开关后，页面上的其它按钮仍须有反应（应打出启动日志）"
        win.grab()

    # 自绘开关的**禁用态必须看得出来**（否则"看着正常却点不动"，正是实机那个 bug 的体感）
    probe_sw = ToggleSwitch()
    probe_sw.setChecked(True)

    def _accent_pixels(w) -> int:
        img = w.grab().toImage()
        want = QColor(C_ACCENT)
        n = 0
        for y in range(img.height()):
            for x in range(img.width()):
                col = img.pixelColor(x, y)
                if (abs(col.red() - want.red()) < 30 and abs(col.green() - want.green()) < 30
                        and abs(col.blue() - want.blue()) < 30):
                    n += 1
        return n

    probe_sw.setEnabled(True)
    n_on = _accent_pixels(probe_sw)
    probe_sw.setEnabled(False)
    n_off = _accent_pixels(probe_sw)
    print(f"===== 自绘开关的禁用态 =====\n  启用时高亮蓝像素={n_on}，禁用时={n_off}（禁用必须明显不同）")
    assert n_on > 20, "启用+打开时轨道应画出高亮蓝"
    assert n_off == 0, "禁用时不该还有高亮蓝（否则看不出被禁用）"

    print("===== 行高/行间隙（720 与 1400 两种窗口高度）=====")

    cfg_pages = [p for p in win.pages if hasattr(p, "finish_layout")]
    for wh in (720, 1400):
        win.resize(1080, wh)
        print(f"  ── 窗口 1080x{wh} ──")
        for page in cfg_pages:
            name = getattr(page, "kind", "?")
            win.stack.setCurrentWidget(page)
            if hasattr(page, "sw_dhcp"):
                page.sw_dhcp.setChecked(True)     # DHCP 卡也一起参与（量完复位）
            win.grab()
            app.processEvents()
            for ci in range(page.body.count()):
                card = page.body.itemAt(ci).widget()
                if card is None:
                    continue
                rows = _card_direct_rows(card)
                if not rows:
                    continue
                heights = [r.height() for r in rows]
                hints = [r.sizeHint().height() for r in rows]
                gaps = []
                for a, b in zip(rows, rows[1:]):
                    ya = a.mapTo(card, QPoint(0, 0)).y()
                    yb = b.mapTo(card, QPoint(0, 0)).y()
                    gaps.append(yb - (ya + a.height()))
                print(f"    [{name}] 卡{ci} 高={card.height():4d} 行高={heights} 间隙={gaps}")
                for r, h, hint in zip(rows, heights, hints):
                    # 上界 = "行里每个控件真正需要的高度"（sizeHint 与 minimumHeight 取大）。
                    # 行**因为内容要求**（比如 30px 的按钮）而高是正当的；
                    # 被父布局摊高度（sizeHint 26 → 实际 107）才是 bug。
                    if r.layout() is None:          # 有些 body 项本身就是控件（如直接加进去的按钮）
                        bound = max(hint, r.minimumHeight())
                    else:
                        kids = [r.layout().itemAt(k).widget() for k in range(r.layout().count())]
                        kids = [k for k in kids if k is not None]
                        bound = max([hint, r.minimumHeight()] +
                                    [max(k.sizeHint().height(), k.minimumHeight()) for k in kids])
                    assert h <= bound + 2, \
                        f"[{name}] 卡{ci}: 行被纵向拉伸（实际 {h}px > 内容需要 {bound}px + 2）"
                for g in gaps:
                    assert g <= 4, f"[{name}] 卡{ci}: 相邻行间隙 {g}px > 4px（没贴合）"
            if hasattr(page, "sw_dhcp"):
                page.sw_dhcp.setChecked(False)
                win.grab()
                app.processEvents()
    win.resize(1080, 720)

    win.stack.setCurrentWidget(win.pages[0])   # 复位到主页（fl 是自由层，不在 stack 里，别传它）
    win.grab()

    # ────────────────────────────────────────────────────────────────────────────────
    # ffmpeg 这条路：脚本路径必须真的存在 + 拉起时不再报"找不到脚本" + 发送端 URL 形式
    # ────────────────────────────────────────────────────────────────────────────────
    SH = "ffmpeg" + ".sh"        # 拼接：这些字样在"界面文案禁字样"清单里，别让断言自己扫到自己
    print(f"===== {SH} 脚本路径 / 发送端 URL =====")
    sp = _cli_mod._ffmpeg_script_path()
    print(f"  _ffmpeg_script_path() = {sp}")
    print(f"  文件存在 = {os.path.exists(sp)}｜大小 = "
          f"{os.path.getsize(sp) if os.path.exists(sp) else 0} 字节")
    assert os.path.basename(sp) == SH, "文件名必须是 " + SH
    assert os.path.basename(os.path.dirname(sp)) == "app", "必须放在 app/ 目录下"
    assert os.path.exists(sp), "脚本不存在：" + sp

    script_txt = open(sp, encoding="utf-8").read()
    # 只看**非注释行**：注释里可以提到旧写法（脚本里就有解释那段坑的注释）
    code_txt = "\n".join(l for l in script_txt.splitlines() if not l.lstrip().startswith("#"))
    print(f"  发送端用 localport= 指定本机端口：{'localport=$MY_PORT' in code_txt}")
    print(f"  代码里还残留非法的 '@$MY_IP' 写法：{'@$MY_IP' in code_txt}")
    assert "localport=$MY_PORT" in code_txt, "发送端必须用 localport= 指定洞里那个本机端口"
    assert "@$MY_IP" not in code_txt, "`@local` 不是 ffmpeg 的合法写法（包会发错地方 + 源端口随机）"

    # 真跑 _launch_ffmpeg()，但把"开新终端"这一步换成记录器（不然会真弹终端窗口）
    launched: list = []
    real_launch = _cli_mod.launch_in_new_terminal
    _cli_mod.launch_in_new_terminal = lambda argv, **kw: launched.append((argv, kw)) or {"pid": 1}
    fake_hole = {"id": 1, "peer": "bob", "peer_ip": "127.0.0.1", "peer_port": 50002,
                 "my_ip": "127.0.0.1", "my_port": 50001, "candidates": []}
    before_log = len(ov.text.toPlainText())
    ok_launch = _cli_mod._launch_ffmpeg(fake_hole)
    _cli_mod.launch_in_new_terminal = real_launch
    new_log = ov.text.toPlainText()[before_log:]
    print(f"  _launch_ffmpeg() 返回 = {ok_launch}｜拉起的命令行 = {launched[0][0] if launched else None}")
    assert ok_launch is True and launched, "应该成功拉起（不再因路径失败）"
    assert launched[0][0][:2] == ["bash", sp], "必须用 bash 跑真实路径的脚本"
    assert launched[0][0][2:] == ["127.0.0.1", "50001", "127.0.0.1", "50002"], "4 个位置参数不变"
    print(f"  日志里有没有旧报错：{'不在当前目录' in new_log}（必须 False）")
    assert "不在当前目录" not in new_log, "不该再出现旧的路径报错"

    print("SELF-TEST OK")
    return 0


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(f"{APP_NAME} 桌面端")
    app.setFont(make_font(UI_FONT_SIZE))
    apply_dark_theme(app)      # Fusion + 深色 QPalette：三平台一致，不再跟系统主题走
    # 收进托盘后不能因为"没有可见窗口"就退出
    app.setQuitOnLastWindowClosed(False)

    if "--self-test" in sys.argv:
        return run_self_test(app)

    if try_raise_existing_instance():
        print(f"{APP_NAME} 已经在运行，已唤起已有窗口。")
        return 0

    win = MainWindow()
    install_single_instance(app, win)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
