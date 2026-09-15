# Chatroom Android 平台细节

Android 端专属实现细节。**通用架构 / 跨端概念**（数据模型 / 气泡布局 / VOICE mode / FILE mode / AI STT / Binary dispatch 等）见 [`readme.md`](./readme.md)，**变更日志**见 [`change.md`](./change.md)，**踩坑汇总**见 [`gotchas.md`](./gotchas.md)。

---

## Android 目录结构

```
android/app/src/main/java/com/example/chatroom/
├── MainActivity.kt
├── core/
│   ├── Models.kt
│   └── SessionManager.kt
├── participants/
│   ├── PtyNative.kt / ptmx.c           # JNI /dev/ptmx
│   ├── SerialNative.kt / serial.c      # JNI /dev/tty*
│   ├── SocketParticipant.kt
│   ├── TelnetParticipant.kt
│   ├── AiParticipant.kt                # HTTP OpenAI API（text/stt/tts 三 subType）+ companion.fetchModels(GET /v1/models)
│   ├── EchoParticipant.kt              # 自测复读机（postDelayed）
│   └── BluetoothParticipant.kt
├── ui/
│   ├── home/SessionMenuView.kt + SessionCardData.kt + EditingCardData.kt
│   ├── chat/ChatFragment.kt + MessageAdapter.kt + FullscreenImageActivity.kt
│   └── common/SessionPagerAdapter.kt + EditingCardBinder.kt
└── vt100/Vt100Parser.kt
```

---

## 菜单页（主页）+ 聊天页叠加层（2026-09）

主页不再是「参与者编辑卡片列表 + 顶部创建按钮」，而是一个**菜单页**：所有会话竖列成一级卡片，
展开是二级卡片，最底下钉一个大加号。同一份菜单页也出现在聊天页左上角 ☰ 打开的叠加层里。

### 结构

```
SessionMenuView（自定义 LinearLayout，菜单页本体）
├── MaterialToolbar「会话」（蓝底白字，?attr/actionBarSize）
└── ScrollView → LinearLayout#cardContainer
│     └── item_session_card.xml × N        ← 一级卡片（一个会话）
│           ├── cardHeader = [×] [几排字] [一颗按钮]
│           │     ×   2609-1301-4310        [回到会话]
│           │       🌐🤖 (2)                            ← 中间几排字 = 展开/折叠热区
│           └── cardContent（展开时才出现）
│                 ╭──────────────────────────────╮
│                 │ 比卡片窄一圈的「详情矩形」      │   ← 左右各留 12dp 外边距
│                 │  × [参与者二级卡片]            │   ← 每个参与者的 × 在它自己左上角
│                 │        [+ 添加参与者]（居中窄条）
│                 ╰──────────────────────────────╯
└── btnAddSession（大加号，**在滚动区里紧贴最后一张卡片**）
```

展开时 `cardHeader` 里的元素**原样不动**，只是在下方多出那块矩形。

菜单页里有四个「加号 / 删除」，刻意做成不同形态避免误认：

| 元素 | 位置 | 长什么样 | 作用 |
|---|---|---|---|
| `btnCardDelete` | 一级卡片**左上角** | 红色 `×` | 草稿 = 丢弃卡片；已有会话 = 关掉整个会话 |
| `btnCancel` | 每个参与者二级卡片**左上角** | 灰色 `×` | 删掉这个参与者 |
| `item_add_participant` | 详情矩形内，**水平居中** | **窄条**（`wrap_content` + 小一号字） | 给本会话加一个参与者 |
| `btnAddSession` | 紧贴最后一张会话卡片（滚动区内） | **通栏**大卡，34sp `+` | 新建一个会话卡片 |

折叠态的会话卡片和「+ 新建会话」卡片**等高**：两处都引用 `@dimen/session_card_height`（72dp，
见 `res/values/dimens.xml`），改一处两边一起变。会话卡片是把 `cardHeader` 钉成这个高度、内容靠
`gravity="center_vertical"` 居中；加号卡片是内层 LinearLayout 钉成这个高度。

`btnAddSession` 点下去是「原地变身」而不是「在末尾追加」：

- 它插在 `cardContainer` 之后、同一个滚动区内，所以视觉上紧跟着最后一张会话卡片
- 点击 → 新建一张 `SessionCardData` 草稿 + `expandedKeys.add()` **直接展开** → `reload()`
- `reload()` 里**已有会话先渲染、草稿后渲染**，所以草稿落在列表末尾 = 大加号原来的位置。
  顺序反了的话草稿会跑到最顶上，看起来像「凭空在最上面插了一张卡」
- `reload()` 里按「有没有草稿」决定它的显隐：**有草稿就藏起来**，所以看起来就是「加号变成了会话卡片」
- 草稿被「创建会话」消化掉、或被 `×` 丢弃后，它重新出现
- 正因如此，同一时刻最多只有一张草稿卡片（`addDraftCard()` 里有 `isNotEmpty()` 兜底）

出现位置：**全 App 只有一份**——`activity_main.xml` 里 `menuOverlay` 包着的那份 `SessionMenuView`。
启动时整页显示它；在会话里点左上角 ☰ 也是把它整页叠到 ViewPager 上面（底下的会话内容不动）。
早期是「首页一份 + 每个 ChatFragment 各一份」，现在合成一份，草稿卡片 / 展开状态天然一致，
`SessionDraftStore` 只用来扛 Activity 重建。

**顶栏做在 SessionMenuView 内部**（`view_session_menu.xml` 的第一个子 View），
所以不管以哪种方式显示，顶栏都是同一个。

`menuOverlay` 的 `elevation` 必须**高于** ChatFragment 里 ☰ 的 6dp（现在是 8dp）：
按 FrameLayout 的 Z 序绘制，低于 6dp 的话 ☰ 会浮在菜单页上面。

### 卡片数据

| 类型 | 判定 | 数据来源 | 折叠行最右边的主按钮 |
|---|---|---|---|
| **草稿卡片** | `sessionId == null` | `SessionDraftStore.drafts`（多实例共享） | 「创建会话」→ 才真正建会话 |
| **已有会话** | `sessionId != null` | 每次 `reload()` 从 `SessionManager` 重建 | 「回到会话」→ 切到该会话 |

- 那颗按钮**钉在折叠行最右边**（不是展开内容里），折叠和展开时都能直接点；左上角的 `×` 同理。
  中间几排字是 `weight=1`，吃掉全部余量，所以标题再长也挤不动它
- **没有单独的展开/折叠按钮**：中间那几排字（`sessionTitleBlock`）自己就是热区，点它切换展开
- 点按钮 / `×` 不会触发「展开/折叠」：Android 的触摸分发本来就是子 View 优先拿到点击

| 按钮 | 位置 | 作用 |
|---|---|---|
| `×` | 一级卡片最左 | 草稿=丢弃卡片；已有会话=关掉整个会话 |
| `×` | 参与者二级卡片左上角 | 删掉这个参与者 |
| `+ 添加参与者` | 详情矩形内居中窄条 | 给本会话加一个参与者 |
| `+ 新建会话` | 紧贴最后一张卡片 | 新建一张草稿会话卡片 |
| 主按钮 | 折叠行最右 | 见下 |

**折叠行右边只有一颗按钮，文案同时承担状态提示和动作**（「合并成一个按钮」的结果）：

| 卡片状态 | 按钮文案 | 点击动作 |
|---|---|---|
| 草稿（`sessionId == null`） | 创建会话 | 真正建会话 + 落盘 + 出 tab |
| 已有会话、**不正常**（`!isSessionUp`） | **恢复连接** | 断开现有参与者 → 按配置重连 → 切过去（`ChatFragment.onClickReconnect()`） |
| 已有会话、正常 | 回到会话 | 只切过去 |

所以**连接状态不写字也不靠显隐**，就是按钮文案本身：折叠行第二排只显示参与者图标串
（`🌐🤖 (2)`，没有参与者时「还没有参与者」）。看到「恢复连接」= 这个会话需要恢复。状态一变必须刷卡片：
`ChatFragment.notifyConnectionStateChanged()` → `MainActivity.refreshMenuConnectionStates()` →
`SessionMenuView.refreshConnectionStates()`（只重刷折叠行，不重建二级表单，避免输入焦点丢失）。

- 展开只是一个**比卡片窄一圈的矩形**（`bg_card_detail`，左右各 12dp 外边距）里装参与者详情
- ⚠️ 一级卡片的 `×` **没有二次确认**，误触会直接删掉整个会话（含参与者配置）

- `SessionCardData`（一级卡片）持有 `MutableList<EditingCardData>`（二级卡片）
- 草稿放 `SessionDraftStore`（object）：菜单页现在只有一份实例，但 Activity 重建时 View 会没，
  草稿还没进 `SessionManager`，只放在 View 里会丢
- 已有会话**不缓存**：每次 `reload()` 用 `editingCardFromConfig()` 从 `SessionManager` 反建表单，
  保证多份实例看到的一致（重进页面 = 自动同步）

### 「编辑即改即存」（已有会话）

`EditingCardBinder` 把 `item_editing_card.xml` 的绑定逻辑抽成可复用组件（原来埋在
`ParticipantAdapter.EditingViewHolder` 里，那个 adapter 已删）。绑定约定：

1. **先灌值、后挂监听**：`setText` / `setSelection` 全在挂 listener 之前做完，
   否则恢复数据本身就会触发一轮改动回调
2. 任何改动 → `onEdited()` → 已有会话调 `SessionManager.updateParticipant(sid, card.toConfig())`
   （靠 `ParticipantConfig.id == EditingCardData.id` 定位），草稿只留在内存
3. `updateParticipant` 只改内存 + **防抖落盘**（500ms）：表单是逐字符改的，每个字符都
   `commit()` 一次会把主线程写卡。收起卡片 / 离开页面 / 创建会话时调 `persistNow()` 立即刷
4. 往**已有会话**里点「+ 添加参与者」会立刻 `addParticipant()` 落一条空配置，
   否则之后这个表单的编辑找不到对象可更新（会被静默丢弃）

### 菜单页怎么显示（☰）

- 菜单页是 `activity_main.xml` 里 `menuOverlay`（`match_parent` + 白色底 + `elevation=8dp`）中的
  `SessionMenuView`，**整个 App 只有这一份实例**
- `MainActivity.showMenu(animate = true)`：`reload()` + `visibility = VISIBLE` + **从屏幕外（左侧）
  向右滑进屏幕到目标位置**（`translationX: -屏宽 → 0`，200ms）；启动那一次传 `animate = false`
  （它就是初始界面，从外面滑进来反而怪）
- `MainActivity.hideMenu(animate = true)`：刷一次防抖落盘 + **向左滑出屏幕**
  （`translationX: 0 → -屏宽`，200ms）再 `visibility = GONE` 并把 `translationX` 复位；
  点「创建会话 / 回到会话 / 恢复连接」都是这个效果。`withEndAction` 里会再判一次 `menuShown`——
  退场动画期间又 `showMenu()` 的话不能把菜单页藏掉；两个方法开头都 `animate().cancel()`
  防止上次动画没跑完叠加。
  **`pagerAdapter.itemCount == 0` 时直接 return**——一个会话都没有还收起菜单，只会露出一片空白，
  而且没有 ☰ 能再打开，用户就卡死了（菜单页上的「+ 新建会话」是唯一出口）
- `fragment_chat.xml` 里只剩聊天内容 + 左上角 ☰（`btnChatMenu`）；☰ 只做一件事：
  `onMenuRequested?.invoke()` → `MainActivity.showMenu()`。fragment 里**不再有叠加层、抽屉、
  返回键回调、动画**这些状态
- 底下的会话内容不重新布局、状态不变，只是被盖住；☰ 也不需要手动隐藏——它在 `elevation` 上是输给
  `menuOverlay` 的
- 返回键在 **Activity** 层处理：菜单盖着且至少有一个会话 → 收菜单；否则交回系统
- 收起菜单的入口：卡片上的「回到会话 / 恢复连接」（`openSession` / `reconnectSession` 里都会
  `hideMenu()`）、系统返回键。没有遮罩也没有关闭按钮

### 没有底部 tabbar（2026-09-15 删除）

原先底部的 `SessionTabBar`（`[ⓘ] 时间戳 [×]`）已整体删掉——菜单页卡片上的
「回到会话 / 恢复连接 / ×」覆盖了它的全部功能（切会话 / 重连 / 删会话），
`SessionTabBar.kt`、`drawable/bg_tab*.xml`、`colors.xml` 里的 `tab_*` 颜色一并删除。

连带影响：

- `MainActivity` 不再有 `tabBar` / `onHomeTabClick` / `onSessionTabClick` / `onSessionInfoClick` /
  `applyTabName` / `refreshAllTabNames`，只剩 `refreshMenuConnectionStates()`（刷菜单卡片按钮文案）
- 切会话的唯一入口 = 菜单页卡片的按钮 → `openSession()` / `reconnectSession()`
- **ViewPager 里不再有首页那一页**（`SessionPagerAdapter` 只装会话，position 0 = 第一个会话），
  菜单页搬到 Activity 层；所以 position ↔ sessionId 的映射整体前移了一位，`removeSession()` 的
  `position < 1` 守卫也跟着去掉了
- `HomeFragment` / `fragment_home.xml` 删除；`ChatFragment` 里的**重连面板整块删除**
  （`reconnectPanel` 布局、`toggleReconnectPanel/expand/collapse/refreshReconnectPanel`、
  `pendingReconnectPanelOpen`、`MaxHeightScrollView.kt`、`item_participant_card.xml`）——
  参与者列表和重连现在完全由菜单页卡片承担

### 关闭 / 新建的接线（MainActivity）

| 入口 | 路径 |
|---|---|
| 菜单「创建会话」 | `SessionMenuView.createFromDraft()` → `createSession()` + `addParticipant()` → `onSessionCreated` → `MainActivity.addSessionTab(select = true)` → 切过去 + `hideMenu()` |
| 菜单「回到会话」 | `MainActivity.openSession(sessionId)`（没页就补一个）→ 切页 + `hideMenu()` |
| 菜单「恢复连接」 | `MainActivity.reconnectSession()`：`setSessionConnected(true)` + 切页 + `ChatFragment.reconnectNow()` + `hideMenu()`（view 没建好就先记下，`onViewCreated` 补）；连接逻辑只在 ChatFragment 里，菜单页自己连不了 |
| 菜单「删除」 | `MainActivity.closeSession()`：断连接 → 清 `SessionManager` → 移除会话页 → `menuSessionList.reload()`（菜单一直开着） |
| 会话显示名 | `sessionTimeLabel()`（`ui/home/SessionCardData.kt`） |

---

## 当前输入区设计（Android，2026-07 重构）

输入区是**上下分割，不是浮层 overlay**。根容器是 `LinearLayout vertical`，聊天列表 `weight=1`，输入区是一个高度可调的子节点 `LinearLayout id=inputArea`。

### 顶部 handle 行：spinner + 拖拽 + 最大化

`inputArea` 顶部 36dp 高的 handle 行（背景 `#F5F5F5`）：

```
[Spinner 📝文 ▾]   [拖拽（整片中段可拖）]   [⤢ / ⤡]
```

- **Spinner**：6 种模式选择器（从原始 5 个内嵌收敛到这一处，唯一一个）
- **"拖拽"标签**：`match_parent_width` × `match_parent_height` 的 TextView，整片中段接收 `MotionEvent`，ACTION_DOWN 记起点，ACTION_MOVE 实时改 inputArea 高度，ACTION_UP 收尾。命中区域 ≥ 240dp × 36dp（主流 ListView touch target ~48dp 的好几倍）
- **`⤢` / `⤡` 按钮**：右侧最大化 toggle。当前状态图标 + view 切换逻辑在 `applyMaximizeState()` 里。

### 下面一个 `FrameLayout` 装 6 种 inputBar

`FrameLayout id=visibleInputBar` 下面叠 6 个 `match_parent_width` × `match_parent_height` 的 `LinearLayout`，任一时刻只有 `currentInputMode` 那个 `VISIBLE`、其余 `GONE`。

| enum 顺序 | spinner label | 内容 |
|---|---|---|
| `EMPTY`（第 0 位） | `⬜空白` | 中央一个 TextView，实时显示 `{width}dp × {height}dp`。拖拽 inputArea 高度时文本同步跳。 |
| `TEXT` | `📝文` | `EditText`（多行 `maxLines=6` + `gravity=top`）+ 发送按钮 |
| `REMOTE` | `🎮遥` | 左 9 宫格字母键 `q w e / a s d / z x c` + 中间 1dp 灰线 + 右 9 宫格数字 `1-9` |
| `DIM3` | `📐三` | 油门 `±` + 中央 9 宫格方向键 + 中间 1dp 线 + 右 `AxisView`（6 轴） |
| `VOICE` | `🎤语` | 单按钮"未在录音，点我开始"→ 录音中切"取消/发送"双按钮；16 kHz / mono / 16-bit PCM |
| `FILE` | `📁文` | `📁 选择文件发送`按钮（任意文件，SAF `*/*` mime 通配；API 33+ 起步位置为 `/sdcard/`，旧版本 fallback 默认） |

### 拖拽上下限（per mode）

| 模式 | 最小高度 (dp) Android | 最小高度 (pt) iOS |
|---|---|---|
| TEXT | 110 | 44 |
| REMOTE | 200 | 120 |
| DIM3 | 280 | 160 |
| VOICE | 80 | 44 |
| FILE | 80 | 44 |
| EMPTY | 80 | 0 |

计算公式：handle (36dp) + 该模式内容所需的 padding。上限 = `screenH − 60dp(一行 chat) − 36dp(handle)`，保证聊天列表**始终留一行**。

拖动到模式最小值后**不再缩**、不放宽到固定档位。最大化后拖拽也被锁。

### 遥控 9 宫格字母布局说明

中间一列 `w / a / s / d` 是 PC 玩家的 **WASD 左手位**（w 前进 / a 左 / s 倒 / d 右），用来接盘控制小车：

- 按字母键发出去的**是方向**字符串（`↑↓←→↖↗↙↘◉`）
- 按 `1`-`9` 发对应数字串

之前这一格是 `↖↑↗/←◉→/↙↓↘`，2026-07 重做成字母键，进离车玩家更顺手。

### 三维 `AxisView` 标签变化

`AxisView.kt` 6 个旋转按钮原画 `⟲`/`⟳`（顺/逆时针符号），重做成纯文字：

| 回调 | 显示 | 发送 |
|---|---|---|
| `onXRotateCW` (X+ 红) | `x+` | `x` |
| `onXRotateCCW` (X− 红) | `x−` | `X` |
| `onYRotateCW` (Y+ 绿) | `y+` | `y` |
| `onYRotateCCW` (Y− 绿) | `y−` | `Y` |
| `onZRotateCW` (Z+ 蓝) | `z+` | `z` |
| `onZRotateCCW` (Z− 蓝) | `z−` | `Z` |

> 小写 = 正方向转，大写 = 反方向转。`btnText.textSize` 从 48 降到 28 适配 2 字符宽度。Z 轴原来把 `onZRotateCW` 画成 `⟲`（调转了顺逆），这次顺手修。

### 最大化行为

点 `⤢` 后：

1. `handleLabel.isEnabled = false` → 按下/禁用变深灰，触摸返回 `false` → **拖拽被锁**
2. `recyclerView.visibility = GONE`
3. `inputArea.layoutParams.height = MATCH_PARENT` → 撑满整个窗口
4. 按钮本身变 `⤡`

点 `⤡` 还原：

1. `handleLabel.isEnabled = true`
2. `recyclerView.visibility = VISIBLE`
3. `inputArea.height` 还原到上次拖出来的高度（`lastNonMaximizedHeightPx`）；首次进入则还原到当前模式 min

### `EMPTY` 模式的尺寸文本实时更新

`updateEmptySize()`：读 `emptyText.parent.width` / `.height`，换算 dp 后写到 TextView。

- 拖拽时：`setInputAreaHeightPx()` 里 `inputArea.post { updateEmptySize() }` —— `requestLayout()` 只排队，等下个 frame 再读才拿到新值
- 切模式时同样 `post` 一帧

用途：调试观察"inputArea 在不同模式 + 不同拖拽下到底是多大"。

---

## 气泡布局细节（Android）

| 位置 | margin | padding | 字体大小 |
|------|--------|---------|---------|
| 右侧（自己） | marginEnd=1dp | paddingHorizontal=14dp | 15sp |
| 左侧（PTY/SSH） | marginStart=1dp, marginEnd=4dp | paddingHorizontal=4dp | **7sp** |
| 左侧（其他） | marginStart=1dp, marginEnd=32dp | paddingHorizontal=14dp | 15sp |

---

## 数据模型 Android

```kotlin
// Models.kt
enum class ParticipantType(val icon: String) {
    ECHO("🔁"), SERIAL("🔌"), PTY("🖥️"), SSH("🔐"), TELNET("📡"),
    SOCKET("🌐"), BBS("💬"), AI("🤖"), AGENT("🦞"),
    BLUETOOTH("📱"), INFRARED("💡"), SMART_DEVICE("🏠")
}

data class Message(
    val id: String,
    val senderId: String,
    val senderType: ParticipantType,
    val senderName: String,
    val content: String,
    val isInfo: Boolean = false,
    val imageBytes: ByteArray? = null,   // 二进制复用字段
    val timestamp: Long = System.currentTimeMillis()
)
```

---

## 会话持久化 + 菜单页卡片重连（2026-09）

### 背景

`SessionManager` 是纯内存 object。进程被系统杀掉（后台 LMK / 用户强杀 / OEM 省电策略）后重建时，
会话和参与者配置全丢，之前建的会话再也找不回来，也没有任何重连入口。

### `core/SessionStore.kt`（SharedPreferences + JSON）

- 存储 key：`chatroom_sessions` / `sessions_json_v1`，内容形如
  `[{ id, createdAt, participants: [{ id, type, name, params }] }]`
- **落盘时机**：`SessionManager.createSession / restoreSession / removeSession / addParticipant /
  removeParticipant` 每次变更都调 `SessionManager.persist()`；写盘用 `commit()` 而不是 `apply()`，
  保证「会话刚创建完进程就被杀」时数据已经在磁盘上
- **不落盘**：聊天消息（`imageBytes` 体积不可控）、连接状态、输入模式 / 拖出来的输入区高度
- 解析容错：整段 JSON 坏掉 → 当作没有历史会话；单个 participant 类型枚举不认识 → 跳过该条，
  不让整条会话丢

### 恢复流程

1. `MainActivity.onCreate` → `SessionStore.init(applicationContext)` + `SessionManager.restoreFromStore()`
2. 恢复出来的会话 `connected = false`（`SessionManager.isSessionConnected`），消息列表为空
3. 按 `SessionManager.getSessionOrder()`（单独的创建顺序列表；`ConcurrentHashMap` 本身无序）
   逐个 `addSessionTab(select = false)`，页顺序 = 会话创建顺序
4. `ChatFragment.onViewCreated`：`isSessionConnected` 为 true → `connectParticipants()`；
   为 false → 只贴一条「已从本地恢复，当前未连接」的提示，**不自动连**
5. 会话显示名 = 创建时间 `YYMM-DDhh-mmss`（年月-日时-分秒，例 `2609-1301-2716`），
   直接从 `sessionId` 里的 epoch 毫秒解析（`sessionTimeLabel()`，菜单页卡片和原来的 tab 共用）。
   **连接是否正常不写字，靠卡片右边那颗按钮的文案**（不正常显示「恢复连接」）。
   重连 / 连上 / 断线经 `SessionManager.setSessionLinkUp()` + `linkStateCallbacks`
   回调 `ChatFragment.notifyConnectionStateChanged()` → `MainActivity.refreshMenuConnectionStates()`
   → `SessionMenuView.refreshConnectionStates()`（只重刷折叠行，不重建表单）
6. 找 fragment 走 `MainActivity.chatFragmentFor(sessionId)`：优先
   `supportFragmentManager.findFragmentByTag("f" + itemId)`（进程被杀后系统恢复出来的实例），
   找不到才退回 `pagerAdapter.fragments[position]`（本次进程新建、可能还没 attach）。
   注意 tag 里的 **itemId 是由会话 id 派生的稳定值，不是 position**（见 gotchas #12），
   否则回调会设在没挂载的实例上——菜单点「回到会话」没反应、重连后菜单按钮文案不刷新

### 关闭会话

`MainActivity.closeSession` 先调 `ChatFragment.shutdownSession()`（此刻 `SessionManager` 里配置还在，
能正确移除 service 里的网络 participant），再 `SessionManager.removeSession()`（同时从磁盘删掉）。
`ChatFragment.onDestroy` 兜底再调一次；未连接的恢复会话直接跳过，避免误触 `TcpForegroundService.stopSelf()`。

### service 启动的 5s 约束（崩溃修复）

`startForegroundService()` 拉起的服务必须在 5s 内调 `startForeground()`，否则系统抛
`ForegroundServiceDidNotStartInTimeException` 直接崩进程（真机踩过：恢复出来未连接的会话一打开就崩）。
旧代码 `ChatFragment.onStart` 无条件 `startForegroundService`，而**恢复出来还没重连的会话**
（以及纯 ECHO/PTY/AI 会话）永远不会加入网络 participant → 必崩。两边都修：

- 客户端：`ChatFragment.shouldStartForegroundService()` —— 只有「已连接 + 至少一个 SOCKET 参与者」
  才 `startForegroundService`，否则只 `bindService`
- 服务端：`onStartCommand` 开头**无条件** `startInForeground()` 满足 5s 约束；若此时
  `networkParticipantsCount == 0`，延迟 `EMPTY_CHECK_DELAY_MS`（2s，给 `onServiceConnected` 里
  的 addXxx 留时间，也避免通知闪一下）后再判断，仍为 0 才 `stopInForeground() + stopSelf()`
- `ensureStarted()`：第一个网络 participant 加入时 `startService` 把自己重新标记成 started；
  否则上面那次 `stopSelf()` 之后，`unbind` 会把带着 socket 的 service 一起销毁

## 后台保活（按 Home / 锁屏后连接不断）（2026-09）

目标：按 Home / 锁屏很久后再切回来，TCP/WS/UDP 连接都还在。

### 1. 任何 fragment 销毁路径都不能断网络连接

之前 `ChatFragment.onDestroy()` 会调 `shutdownSession()` 清掉 service 里的网络 participant。
但 fragment 的 onDestroy **不代表用户关了会话**：

- 按 Home 后 MIUI 之类的 ROM 很快回收 Activity → fragment onDestroy，但进程和 service 还活着
- `ViewPager2` 的 `offscreenPageLimit = 2`，离得远的会话 fragment 也会被销毁

结果就是「一按 Home 连接就断」。现在**只有用户点菜单卡片上的 ×**（`MainActivity.closeSession`）
才清连接；fragment 销毁不再碰网络 participant。

### 2. wake lock 不再设超时

原来 `acquire(10min)` 且只在 `onStartCommand` 里续期 —— 后台时没机会调 onStartCommand，
10 分钟后锁自动释放 → CPU 能睡 → socket 静默断。
现在只要还有网络 participant 就一直持有（`isHeld` 判断保证幂等、不叠引用计数），
count 归零 / service 销毁时释放。**代价是耗电**，这是为「后台不断连」付的成本。

### 3. Doze 白名单（`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`）

设备静止 + 未充电进入 Doze 后系统会挂起网络，前台服务也救不回来。
`MainActivity.maybeRequestIgnoreBatteryOptimizations()` 首次启动弹一次，引导用户去系统设置里
允许 chatroom 忽略电池优化（拒绝后不再弹）。厂商 ROM 的「自启动 / 后台运行」白名单仍需手动加，
见 [`gotchas.md`](./gotchas.md) 第 6 条。

### 4. WS 加协议级 ping（OkHttp `pingInterval(30s)`）

`WsParticipant` 的共享 OkHttpClient 加了 `pingInterval(30s)`：发的是 **WebSocket 协议 ping 帧**
（对端 WS 库自动 pong），不是应用数据，不污染业务流。作用是让 NAT / 运营商侧别回收空闲连接，
同时 ping 失败能及时发现对端已死。

### 5. 关 tab 的兜底清理

fragment 被回收 / 没绑定时 `shutdownSession()` 返回 false，`MainActivity.closeSession` 退回
`startService(ACTION_REMOVE_SESSION) + EXTRA_SESSION_ID`，让 service 自己按 sessionId 清
（结合 `TcpForegroundService.isRunning` 判断，避免为了清理白拉一个服务起来）。

### 已知限制

- 原生 TCP 只能靠 `Socket.keepAlive = true`（OS 默认 ~2h 才开始发探针）。Android 公共 SDK
  **不给 app 调 TCP keepalive 间隔**——`ConnectivityManager.createSocketKeepalive(Socket)` 是
  @hide，公开的只有 IpSec UDP 那个重载（`javap android.jar` 验证过）。长时间完全空闲的裸 TCP
  仍可能被中间 NAT 回收，这是协议层面限制；WS 有 `pingInterval` 兜着。
- 国内厂商（MIUI/EMUI/ColorOS…）不守前台服务约定直接杀进程时连接一定断，代码层面无法规避，
  只能让用户加系统白名单（gotchas.md 第 6 条）。

---

## 自动滚动（贴底跟随，Android RecyclerView）

`ChatFragment` 加了一个状态机：

- `messageList: MutableList<Message>` —— RecyclerView 实际数据源，不再 `SessionManager.getMessages(...).toList()` + DiffUtil 全量重算
- `autoScroll: Boolean` —— 是否贴底
- `RecyclerView.OnScrollListener` 每次滚重算 `autoScroll = isAtBottom()`（容差 3 项）

新消息到达（**ListAdapter + submitList 时序正确**）：

```kotlin
adapter.submitList(messageList.toList()) {
    // submitList 是异步的，itemCount 要等 diff commit 到主线程后才更新，
    // 所以 scrollToPosition 必须放 commitCallback 里，否则滚到旧 size-1
    if (autoScroll && messageList.isNotEmpty()) {
        recyclerView.scrollToPosition(messageList.size - 1)
    }
}
```

**坑**：`MessageAdapter` 继承自 `ListAdapter<Message, …>`（`AsyncListDiffer`）。不能用 `notifyItemInserted(pos)`——只通知 RecyclerView UI，内部 list 不变 → **渲染空白**。必须 `submitList(newList)`。

效果：在底部 → 自动跟随新消息；上滑看历史 → 新消息安静进来不打断；滑回到底又重新跟随。

### Fragment 重建后拉历史

`loadMessages()` 从 `SessionManager` 拉跨 fragment 重建前的消息。ViewPager2 销毁/重建 ChatFragment 时需要。

**支持追加**（不 clear 已有）：
- `messageList.isEmpty()` → clear + addAll（首次创建）
- `messageList` 已有 → 按 `id` 去重，只 add 不在的（**切回前台时拉新**——service 写的诊断消息也能拉到）

切回前台时 `onStart` 会调 `loadMessages()`，所以 service 在后台写的 `❌` 灰色诊断消息切回 app 后会出现在聊天区。

---

## VOICE mode（Android 部分）

### `core/VoiceRecorder.kt`

- `AudioRecord`（API 24+ 走 `MediaRecorder.AudioSource.VOICE_RECOGNITION`，关闭 AGC/NS；低版本回退 `MIC`）
- 后台线程持续读 PCM 到 `ByteArrayOutputStream`
- `stop()` 把 PCM 包成 WAV（44 字节 RIFF/fmt/data header，little-endian）
- `release()` 释放 `AudioRecord` + 反激活 `AVAudioSession`
- `Manifest.permission.RECORD_AUDIO` 检查 + `ContextCompat.checkSelfPermission`

### 播放（Android 部分）

- `AudioMessagePlayer`（单例 `MediaPlayer` + cacheDir 临时 WAV）
- 音频气泡用 `MaterialButton`，点按钮调 `AudioMessagePlayer.play(...)`

---

## AI STT subtype（Android 部分）

### 主页 UI

- `item_editing_card.xml` `layoutAiModels` 后加 `layoutAiSubType`（一行 LinearLayout + Spinner，display=`["文本", "语音转文字"]` / value=`["text", "stt"]`）
- `EditingCardData` 加 `aiSubType: String = "text"`，`toConfig()` 写 `subType=...`

### AiParticipant：`subType="stt"` 时多一个 `sendVoice(wavData)` API

- Android：用 **OkHttp**（已在 deps）做 `MultipartBody` 上传 + SSE 流式响应（`response.body?.source()?.readUtf8Line()`），每段贴 `📥 STT: <chunk>` info、最后贴 AI reply
- `model.ifBlank { "Qwen3-ASR-0.6B-4bit" }` 做默认值

---

## FILE mode（Android 部分）

- Launcher 从 `ActivityResultContracts.GetContent()`（image/*）改成 `OpenDocument` + `arrayOf("*/*")`
- 按钮文案 `📷 选择图片发送` → `📁 选择文件发送`
- 自定义 `OpenDocumentAtSdCard` ActivityResultContract（包在 ChatFragment 内 `private class`）：API 33+ 通过 `DocumentsContract.EXTRA_INITIAL_URI` 把系统选择器起步位置强制到 `/sdcard/`；低版本（项目 `minSdk=28`）fallback 默认（通常是 Downloads/Recent）

---

## Binary dispatch（Android 代码）

```kotlin
private fun broadcastBinaryToParticipants(bytes: ByteArray) {
    val configs = SessionManager.getParticipants(sessionId)
    configs.forEach { config ->
        when (config.type) {
            ParticipantType.SOCKET -> { /* WS / TCP / UDP */ }
            ParticipantType.AI -> {
                val subType = config.params["subType"] ?: "text"
                if (subType == "stt") {
                    (activeParticipants[config.id] as? AiParticipant)?.sendVoice(bytes)
                }
            }
            else -> { /* PTY/SERIAL/SSH/TELNET/BLUETOOTH：no-op */ }
        }
    }
}
```