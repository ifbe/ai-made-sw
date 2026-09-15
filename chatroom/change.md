# Chatroom 变更日志

按倒序排列（最新在最上面）。详细的项目说明见 [`readme.md`](./readme.md)。

---

## 2026-09-15 Android 主页改造成「菜单页」+ 聊天页 80% 叠加菜单

**摘要**：主页从「参与者编辑卡片 + 顶部创建按钮」变成**菜单页**——所有会话竖列成一级大卡片
（默认折叠，只显示时间名 / 连接状态 / 参与者图标串，点一下展开、再点折叠），展开后原本的主页内容
作为二级卡片放在卡片内部，最底下钉一个大加号新建会话。聊天页左上角加 ☰，点开把同一份菜单页
以 **80% 屏宽**盖在原画面上方，底下的会话内容不重新布局、状态不变。`./gradlew :app:assembleDebug` 通过。

### 改动

| 文件 | 内容 |
|---|---|
| `ui/home/SessionMenuView.kt`（新增） | 菜单页本体：一级卡片折叠/展开、二级表单、底部大加号；`onSessionCreated` / `onEnterSession` / `onDeleteSession` 三个回调 |
| `ui/home/SessionCardData.kt`（新增） | 一级卡片数据（`sessionId == null` = 草稿）+ `SessionDraftStore` 草稿共享容器 + `sessionTimeLabel()`（tab 名字和卡片名字共用） |
| `ui/home/EditingCardData.kt`（新增） | 从 `HomeFragment` 抽出的表单数据 + `toConfig()` / `toParams()` / `editingCardFromConfig()`（已有参与者 → 可编辑表单） |
| `ui/common/EditingCardBinder.kt`（新增） | 从 `ParticipantAdapter.EditingViewHolder` 抽出的表单绑定，改完即回调；20+ 段匿名 `TextWatcher` 收成一个 `EditText.onChanged` |
| `ui/common/ParticipantAdapter.kt`（删除） | 旧主页列表专用，已被 `SessionMenuView` + `EditingCardBinder` 取代 |
| `core/SessionManager.kt` | 新增 `updateParticipant()`（就地替换，靠 config id 定位）+ `persistDebounced()` / `persistNow()`（逐字符编辑不能每次都 `commit()`） |
| `res/layout/item_session_card.xml`（新增） | 一级卡片：折叠行（箭头 + 名字/关键信息 + 主按钮）+ 展开时那块比卡片窄一圈的详情矩形 |
| `res/layout/view_session_menu.xml`（新增） | 菜单页内容：**顶栏**（蓝底「会话」）+ 滚动卡片区 + 紧跟最后一张卡片的大加号 |
| `res/values/dimens.xml`（新增） | `session_card_height`：折叠态会话卡片与大加号卡片共用同一行高（72dp），保证两者等高 |
| `res/layout/fragment_home.xml` | 整个主页就是 SessionMenuView（顶栏也搬进 SessionMenuView，见下），去掉顶部「创建」按钮和空状态文案 |
| `res/layout/fragment_chat.xml` | 外层包 `FrameLayout`：原内容 + 左上角 ☰ + 全屏遮罩 + 左对齐抽屉（宽度代码里设 80%） |
| `res/drawable/bg_menu_button.xml`（新增） | ☰ 按钮底（半透明白 + 圆角 + 描边），压住消息时仍看得清 |
| `ui/home/HomeFragment.kt` | 重写成菜单页壳：只做 `reload()` + 三个回调接线 + `onResume` 重建 / `onPause` 落盘 |
| `ui/chat/ChatFragment.kt` | 新增 `setupMenuDrawer()` / `toggleMenu()` / `openMenu()` / `closeMenu()`：抽屉宽度、滑入动画、遮罩点击关闭、返回键关闭、`onStop` 收起 |
| `ui/common/SessionPagerAdapter.kt` | **重写 `getItemId` / `containsItem` 改用会话派生的稳定 id**：默认实现是「item id = position」，删掉中间某个会话会让后面所有 fragment 的 id 错位，`gcFragments()` 会把还活着的 fragment（甚至当前页）当过期删掉 → 崩溃。连带把 fragment tag 从 `"f<position>"` 变成 `"f<稳定 id>"`，`MainActivity` 找 fragment 的方式跟着改 |
| `MainActivity.kt` | 新增 `openSession()` / `reconnectSession()`；`chatFragmentAt(position)` → `chatFragmentFor(sessionId)`；`closeSession()` 改公开并在删完后 `homeFragment().refresh()`；`addSessionTab()` 里接线 ChatFragment 的四个菜单回调；删掉私有 `sessionTimeLabel`（改用共享的） |

### 交互约定（跟用户确认过的四条）

1. 折叠行 = `[×] [几排字] [恢复连接] [创建会话/回到会话]`。**没有单独的展开/折叠按钮**——
   点中间那几排字就展开/折叠；展开时折叠行**原样不动**，只在下方多一块**比卡片窄一圈**的矩形装参与者详情
2. 折叠行第二排只显示参与者图标串（`🌐🤖 (2)`，没有参与者时「还没有参与者」），**不再写连接状态**：
   状态完全靠右边那颗按钮的**文案**体现（不正常才显示「恢复连接」），
   为此 `applyTabName()` 会顺带 `refreshConnectionStates()` 只重刷折叠行，不重建表单
3. 折叠行右边**只有一颗按钮**（做小：28dp 高 / 11sp），文案同时承担状态提示和动作：
   草稿=「创建会话」、已有会话不正常=「恢复连接」、正常=「回到会话」。
   中间几排字 `weight=1` 吃掉余量，标题再长也挤不动它
4. 一级卡片**左上角红色 `×`** 删除（草稿=丢弃卡片，已有会话=关掉整个会话）；
   每个参与者二级卡片的**左上角灰色 `×`** 删除该参与者
5. 「+ 添加参与者」收成**居中窄条**（`wrap_content` + 小一号字），跟「+ 新建会话」通栏大卡区分开
6. 已有会话的二级卡片是**可编辑表单，改完即存**（内存即时 + 500ms 防抖落盘）
7. 「新建会话」大加号在**滚动区内紧贴最后一张卡片**（不是钉在页面底部），点它**原地变成一张展开的草稿卡片**
   并把自己隐藏（有草稿就不再显示），草稿被创建 / 丢弃后重新出现；同一时刻最多一张草稿。
   实现上 `reload()` 必须**先渲染已有会话、后渲染草稿**，否则草稿会跑到列表最顶上
8. 大加号建出来的是**草稿卡片**，卡片内点「创建会话」才真正建会话 / 落盘 / 出 tab（空草稿不污染 tabbar）
9. 菜单里点卡片只**展开/折叠**，要进会话得点「回到会话」；抽屉点遮罩关闭

### 追加：删掉底部 tabbar + 菜单页改成整页

- **底部 `SessionTabBar` 整体删除**（`[ⓘ] 时间戳 [×]`），切会话 / 重连 / 删会话全部由菜单页卡片承担；
  `SessionTabBar.kt`、`drawable/bg_tab*.xml`、`colors.xml` 的 `tab_*` 颜色一并删掉
- `MainActivity` 相应删掉 `tabBar` / `onHomeTabClick` / `onSessionTabClick` / `onSessionInfoClick` /
  `applyTabName` / `refreshAllTabNames`，只留下 `refreshMenuConnectionStates()`
- 聊天页 ☰ 打开的菜单**从 80% 宽抽屉改成整页 100%**（`menuDrawer` = `match_parent`），
  遮罩层随之删除（整页盖满后没有可点的空白区），关闭靠「回到会话」按钮或返回键
- **重连面板整块删除**（`reconnectPanel` 布局、`toggleReconnectPanel/expand/collapse/refreshReconnectPanel`、
  `pendingReconnectPanelOpen`、`MaxHeightScrollView.kt`、`item_participant_card.xml`）——
  它失去入口后成了死 UI，参与者列表和重连完全由菜单页卡片承担
- **菜单页从「每个 ChatFragment 一份」收敛成「全 App 一份」**：搬到 `activity_main.xml`
  的 `menuOverlay` 里，启动时整页显示；会话里 ☰ 只是 `MainActivity.showMenu()` 把它整页叠上来。
  于是 `ChatFragment` 里的叠加层 / 抽屉 / 返回键回调 / 动画状态全部删除，只剩 `onMenuRequested`
- 菜单页滑入 / 滑出动画：点 ☰ **从屏幕外（左侧）向右滑进到目标位置**，点
  「创建会话 / 回到会话 / 恢复连接」**向左滑出屏幕**（`translationX ± 屏宽`，200ms，启动那一次不动画）
- `SessionPagerAdapter` 不再装首页，只装会话（position 0 = 第一个会话）；`HomeFragment` /
  `fragment_home.xml` 删除，`MainActivity` 多出 `showMenu()` / `hideMenu()`（后者在没有任何会话时
  拒绝收起，否则会露出空白且没有 ☰ 能回来）

### 效果 / 限制

- 菜单页在主页和每个 ChatFragment 抽屉里各有一份实例，因此用「草稿共享容器 + 已有会话每次重建」
  保证多份实例一致；代价是会话/参与者很多时每次打开抽屉都要重建表单
- 二级表单是完整编辑表单（含 Spinner / 查询模型），卡片内没有嵌套 RecyclerView，直接 inflate 进
  `LinearLayout`，靠 ScrollView 滚动
- 进程重启恢复出来的会话仍然是「未连接」状态，卡片上同样显示未连接

---

## 2026-09-13 iOS 底栏对齐 Android：会话恢复 + ⓘ 重连面板 + 删除线

**摘要**：把 Android 那套会话 tabbar 行为搬到 iOS——App 重启后恢复已打开的会话（未连接、参与者还在）；
tab 结构改成 `[ⓘ] 时间戳 [×]`，点 `ⓘ` 在输入区下方展开重连面板（参与者卡片样式对齐主页 + 重连按钮），
再点一次收起；tab 名字用创建时间 `YYMM-DDhh-mmss`（无 emoji、无状态符号），**未连接 / 链路失败时整串加删除线**。

### 改动

| 文件 | 内容 |
|---|---|
| `Core/SessionStore.swift`（新增） | 会话落盘：`Application Support/chatroom_sessions.json`，`.atomic` 写（等价 Android `SessionStore` 的 `commit()`）；容错解析，未知 `ParticipantType` 只跳过该参与者、不丢整条会话 |
| `Core/SessionManager.swift` | 加 `sessionOrder`（tab 顺序）/ `connected`（本进程是否激活过）/ `linkUp`（链路聚合，仅内存）；新增 `restoreFromStore()` / `persist()` / `isSessionUp()` / `setSessionConnected()` / `setSessionLinkUp()` / `clearSessionLinkUp()`；`createSession/addParticipant/removeParticipant/removeSession` 都落盘 |
| `Participants/SocketParticipant.swift` | 加 `onStateChange(Bool)`：TCP/UDP 连上 → `true`，`.failed` / 读错误 / 被动关闭 → `false`；**主动 `disconnect()` 不上报**（`running` 先置 false）；`running` 由裸 `var` 换成 `NSLock` 保护（Swift 没有 `@Volatile`） |
| `Participants/WsParticipant.swift` | 同款 `onStateChange`：`didOpen` → `true`，`didClose` / receive 失败 → `false`，主动关闭静默；`running` 同样加锁 |
| `UI/Chat/ParticipantCardView.swift`（新增） | 重连面板用的只读参与者卡片，外壳对齐主页 `EditingCardView`（白底 + 12 圆角 + 阴影 + 蓝描边），显示「图标 + 名称 + 参数 · 已连接/未连接」 |
| `UI/Chat/ChatView.swift` | 新增 `showReconnectPanel` 绑定 + 面板（标题按链路状态、列表 `maxHeight 200` 对应 Android `dp(200)`、`🔁 重新连接` / `🔌 重连`）；`onAppear` 改成「已激活才连，恢复出来的只贴一次提示」；SOCKET/WS 参与者注册 `onStateChange` 聚合到会话级 |
| `UI/MainContainerView.swift` | tab 结构改为 `[ⓘ] 名字 [×]`，`ⓘ` 切到该会话并展开/收面板；tab 名 = 创建时间，`!isSessionUp` 时 `strikethrough`；启动时 `restoreFromStore()` 并用 `sessionOrder` 建 tab |
| `android/.../ChatFragment.kt` | 顺手修掉恢复提示里的过期文案（「再次点击底部该会话标签」→「点该会话标签左边的 ⓘ」，tab 点击语义早已简化） |
| `ios/.gitignore`（新增） | 与 `waterinbox/ios/.gitignore` 同一约定，忽略 `/build` 等产物 |

### 效果 / 限制

- 杀进程重启 → tab 还在、名字带删除线，点 `ⓘ` 能看到参与者，点重连即恢复
- iOS 没有 Android 的 `TcpForegroundService`，后台只能靠 `beginBackgroundTask` 撑 ~30s，删除线会在系统挂断连接后由链路回调亮起
- 聊天消息仍然不落盘（`imageBytes` 体积不可控），限制同 Android；见 [`readme.md`](./readme.md) 已知限制
- `ⓘ` / `×` 与 tab 本体的点击分流：用 `contentShape + onTapGesture` 承载「切 tab」，两个按钮各自独立，避免 Button 套 Button 被外层吞点击

---

## 2026-09-13 Android 后台保活加固：按 Home / 锁屏后连接不断

**摘要**：用户反馈「按下 home 会被断开 tcp，或者被系统杀掉」。主因是 `ChatFragment.onDestroy()`
把 service 里的网络 participant 删了（进后台后 ROM 回收 Activity、`ViewPager2` 回收 offscreen
fragment 都会触发 onDestroy），另外 wake lock 10 分钟超时后后台没续期、Doze 会挂起网络。

### 改动

| 文件 | 内容 |
|---|---|
| `ui/chat/ChatFragment.kt` | `onDestroy()` **不再**调 `shutdownSession()`（fragment 销毁 ≠ 用户关会话）；`shutdownSession()` 返回 Boolean 表示是否处理完 |
| `service/TcpForegroundService.kt` | wake lock 改为「有连接就一直持有、不设超时」（`isHeld` 幂等，不叠引用计数）；新增 `ACTION_REMOVE_SESSION` + `removeSessionParticipants()` + `isRunning` 作为关 tab 的兜底清理 |
| `MainActivity.kt` | 首次启动弹一次「忽略电池优化」引导（Doze 白名单）；关 tab 时 fragment 处理不了就发 Intent 让 service 自己清 |
| `participants/WsParticipant.kt` | 共享 OkHttpClient 加 `pingInterval(30s)`：WS 协议级 ping，不污染业务数据 |
| `AndroidManifest.xml` | 加 `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` |

### 效果 / 限制

- 按 Home / 锁屏 → 进程 + 前台服务 + socket 都保持；切回来时 service 后台写入
  `SessionManager` 的消息由 `loadMessages()` 补进聊天区
- 裸 TCP 的 keepalive 间隔 app 改不了（`ConnectivityManager.createSocketKeepalive(Socket)`
  是 @hide，公开的只有 IpSec UDP 重载），长时间全空闲仍可能被 NAT 回收
- 厂商 ROM（MIUI 等）强杀进程无法用代码规避，仍需系统白名单；详见 [`gotchas.md`](./gotchas.md) 第 6 / 10 / 11 条

---

## 2026-09-13 Android 会话持久化 + 重连面板

**摘要**：解决「进程被杀 → 会话全丢、tab 里也看不到参与者 / 没法重连」。新增 `core/SessionStore.kt`
把会话 + 参与者配置落盘，下次启动恢复成**未连接**状态；点 tab 名字左边的 **ⓘ** 会在
输入区下方展开一块重连面板（参与者卡片 + 重连按钮），再点一次收起。`./gradlew :app:assembleDebug` 通过。

### 现象 / 原因

1. `SessionManager` 是纯内存 object，进程重建后 `sessions` / `messages` 全空，之前建的会话再也回不来
2. 会话已经建过之后，界面上看不到该会话的参与者，也没有任何重连入口
3. `ChatFragment.onViewCreated` 无条件 `connectParticipants()`，没有「配置在但未连接」这个中间态

### 改动

| 文件 | 内容 |
|---|---|
| `core/SessionStore.kt`（新增） | SharedPreferences + JSON 持久化；`commit()` 保证落盘；坏数据 / 未知 ParticipantType 跳过不炸 |
| `core/SessionManager.kt` | 新增有序 `order`（tab / 落盘顺序）、`connected` 标记、`restoreSession / restoreFromStore / isSessionConnected / setSessionConnected / getSessionOrder / persist`；会话 / 参与者变更即落盘 |
| `MainActivity.kt` | 启动 `restoreFromStore()` + 恢复 tab；tab 本体点击 = 切会话，ⓘ = 展开 / 收起重连面板；tab 文案 = 创建时间 `YYMM-DDhh-mmss`（未连接 / 链路失败加删除线）；关会话先 `shutdownSession()` 再从磁盘删 |
| `participants/SocketParticipant.kt` `WsParticipant.kt` | 新增 `onStateChange(up)` 上报链路状态；主动 disconnect 不上报（`abnormal` / `intentionalClose` + `@Volatile running`） |
| `service/TcpForegroundService.kt` | `upConfigs` + `linkStateCallbacks`：把 participant 链路状态聚合到会话级并回调 UI |
| `core/SessionManager.kt` | 新增 `linkUp` + `setSessionLinkUp()` / `isSessionUp()`（= 已激活 且 链路没失败） |
| `ui/chat/ChatFragment.kt` | 新增 `toggle / expand / collapseReconnectPanel`、`refreshReconnectPanel`、`onClickReconnect`、`showRestoredHintIfNeeded`；未连接会话不再自动 `connectParticipants`；`closeSession` 改名公开为 `shutdownSession` |
| `ui/common/MaxHeightScrollView.kt`（新增） | `onMeasure` 里夹最大高度（`android:maxHeight` 原生不生效） |
| `res/layout/fragment_chat.xml` | `inputArea` 之后加 `reconnectPanel`（标题行 + 卡片列表 + 重连按钮） |
| `ui/common/SessionTabBar.kt` | tab 改成 `[ⓘ] 名字 [×]`（新增 `onInfo` 回调 + `nameViews` 映射）；新增 `updateTabName()`；tab 加长（padding 14dp / minimumWidth 128dp，容纳 14 字符时间戳） |
| `service/TcpForegroundService.kt` | 新增 `hasNetworkParticipant(configId)`，重连时只移除确实存在的 participant；修 `startForegroundService` 5s 崩溃（见下） |

### 修复：打开「恢复出来未连接的会话」必崩

真机崩溃 `ForegroundServiceDidNotStartInTimeException`（`/tmp/logcat.txt`）。原因是
`ChatFragment.onStart` 原来无条件 `startForegroundService()`，而恢复出来未连接的会话不会 add 任何网络
participant，`TcpForegroundService` 因此永远不调 `startForeground()`，5s 后被系统干掉。修法：

- `ChatFragment.shouldStartForegroundService()`：只有「已连接 + 至少一个 SOCKET 参与者」才
  `startForegroundService`，否则只 `bindService`
- `TcpForegroundService.onStartCommand`：开头无条件 `startInForeground()` 满足 5s 契约；
  `count == 0` 时延迟 2s 再确认，仍为 0 才 `stopInForeground() + stopSelf()`
- `ensureStarted()`：第一个网络 participant 加入时 `startService` 补回 started 状态

细节见 [`gotchas.md`](./gotchas.md) 第 9 条。

### 交互

- tabbar 单个 tab：`[ⓘ] 名字 [×]`，名字是会话创建时间 `YYMM-DDhh-mmss`（如 `2609-1301-2716`），不带 emoji；首页 tab 是 `首页`。tab 本体点击 = 切到该会话；点名字左边的 **ⓘ** = 展开 / 收起该会话的重连面板；点 **×** = 关闭会话
- **未连接**（程序重启恢复后还没重连）或**链路失败**（连不上 / 连接掉了）→ tab 名字整串加删除线；正常状态名字不变
- 展开时面板位于输入区下方、tabbar 上方（本会话参与者信息 + 重连按钮），把输入区往上挤；再点一次 ⓘ 收起，回到会话
- 点非当前会话的 ⓘ 会先切过去再展开（view 没建好时由 fragment 记下，建好补展开）
- 每次创建会话立即落盘；进程杀掉重开后历史会话以未连接状态恢复，参与者信息齐全，走上面的流程即可重连

### 说明

- 只持久化会话 + 参与者配置，**聊天消息不落盘**（`imageBytes` 体积不可控），恢复出来的会话聊天区只有重连后的新消息
- iOS 端尚未实现对应能力，本次只改 Android

---

## 2026-09-02 iOS 三个 UI 小问题 + Echo sendBinary 静态分派修复

**摘要**：今天四件事——三个 UI 小问题（AI subType picker 选中色 / 文本框白底白字 / 录音选文件按钮居中），加一个被 DEBUG 定位出来的 Swift 经典坑（`sendBinary` 静态分派导致 Echo 接收图片/wav 不回）。iOS 端 `xcodebuild` 通过。

### 1. AI subType picker 选中色不明显

主页 AI 卡片 subType picker 原用 SwiftUI `.pickerStyle(.segmented)`，系统 segmented control 选中后颜色对比度低，不如 SOCKET 协议字段那个自定义按钮明显。

**修法**：删 Picker，改成跟 SOCKET 协议同款 3 个自定义 Button（选中 `#4CAF50` / 未选 `#CCCCCC` / 白字 / `height: 26`，宽度 `64/80/80` 按文案长度分配）。SOCKET 协议那段不用动，本来就是这风格。

### 2. textInputBar 白底白字看不见

聊天界面切到文字输入模式，TextField `.textFieldStyle(.plain)` + `.background(Color(hex: "#F5F5F5"))` + `.cornerRadius(20)`，但用户反馈**背景和文字都是白色**。

**根因**：iOS 在 dark mode 下，`.background(Color)` modifier 在 plain style TextField 上经常被内部 UITextField 的 background view 覆盖掉；foreground 默认是 system label color，dark mode 下是白色，所以白字落在没生效的灰底上看不见。

**修法**：
- `.foregroundColor(Color(hex: "#333333"))` 强制前景色（不依赖 system label）
- `.accentColor(Color(hex: "#2196F3"))` 显式光标色
- `.background { RoundedRectangle(cornerRadius: 20).fill(Color(hex: "#F5F5F5")) }` 替换 `.background(Color(...)) + .cornerRadius(20)`——`RoundedRectangle.fill()` 是 view shape，不走系统 background view 覆盖路径

发送按钮也同款 `.background { RoundedRectangle(cornerRadius: 20).fill(Color(hex: "#2196F3")) }` 保持风格一致。

### 3. voiceInputBar / fileInputBar 按钮靠左

两个 inputBar 用 `HStack { Button(...); Spacer() }`，按钮在第一个位置靠左。改成「`Spacer() + Button + Spacer()`」让按钮居中。录音态「取消 / 发送」两个按钮也都居中。

### 4. Echo sendBinary 不回（Swift 静态分派坑）

**现象**：echo session 发文字正常回包，发图片 / wav 不回——没有「📥 Echo 接收 type=blob」info 行、没有 imageBytes 接收气泡。

**DEBUG 流程**（用小灰字贴在聊天界面里，不走 os_log）：
1. `broadcastBinaryToParticipants` 入口 → 打 `🔍 DEBUG broadcastBinaryToParticipants data.count=N configs=N types=[...]`
2. 每个 `case .xxx` 之前 → 打 `🔍 case .xxx id=... dictHit=ECHO/nil 即将调 sendBinary`
3. `EchoParticipant.sendBinary` 函数体第一行 → 打 `🔍 DEBUG Echo sendBinary 入口 data.count=N onMessage!=nil=...`
4. 闭包内 `guard let self else` 后 → 打 `🔍 DEBUG Echo 闭包执行 self != nil onMessage!=nil=...`
5. `onMessage?(msg)` 之前 → 打 `🔍 DEBUG Echo 发 imageBytes 消息 len=N`
6. `onMessage?(msg)` 之后 → 打 `🔍 DEBUG Echo onMessage 调用返回`
7. weak self nil 分支 → 打 `⚠️ DEBUG Echo 闭包执行时 self 已被 release（weak self = nil）`

**实测输出**：
```
1. 📤 发送 type=audio/wav          ← sendVoiceRecording 末尾贴的
2. 🔍 DEBUG broadcastBinaryToParticipants ...  ← 入口
3. 🔍 case .echo id=2bae7dd7-2cdc-... dictHit=ECHO 即将调 sendBinary
4. 🔍 DEBUG broadcastBinaryToParticipants 结束    ← 结尾
```

`case .echo` 进了、`dictHit=ECHO`（字典 lookup 拿到的是 EchoParticipant 实例），但**sendBinary 入口的 postInfo 完全没出现**。

**根因**：

`Participants/Participant.swift` 协议定义长这样：

```swift
protocol Participant: AnyObject {
    func connect()
    func sendInput(_ text: String)   // ← required method
    func disconnect()
    ...
}

extension Participant {
    func sendBinary(_ data: Data) {  // ← extension only, NOT required
        // no-op
    }
}
```

`sendBinary` 是 **protocol extension method**，不是 protocol requirement。Swift 对 extension method **静态分派**——`activeParticipants[config.id]?.sendBinary(data)` 调用时，Swift 看的是变量声明类型 `Participant?`，不是实际类型 EchoParticipant，**永远调到 Participant extension 的 default no-op**，**调不到 EchoParticipant.sendBinary override**。

这就是 sendInput 工作、sendBinary 不工作的原因：
- `sendInput` 是 protocol **required**，**dynamic dispatch**，调到 EchoParticipant.sendInput override
- `sendBinary` 是 protocol **extension only**，**static dispatch**，调到 Participant.sendBinary no-op

**顺带影响**：`case .socket` 分支的 `activeParticipants[config.id]?.sendBinary(data)` 也走 static dispatch——**WS 发图片这条路径之前从来没 work 过**，只是没人专门测过。今天顺带修。

**修法**：把 `sendBinary` 从 extension 升格到 protocol requirement：

```swift
protocol Participant: AnyObject {
    func connect()
    func sendInput(_ text: String)
    func sendBinary(_ data: Data)   // ← 加进 requirement
    func disconnect()
    ...
}

extension Participant {
    func sendBinary(_ data: Data) { }  // ← extension 保留 default no-op，给 AI/PTY/Serial/Socket/Telnet/Bluetooth 用
}
```

- `sendBinary` 升格到 requirement → dynamic dispatch → EchoParticipant / WsParticipant override 被调到
- extension 保留 default no-op → 不需要 override 的类（AI/PTY/Serial/Socket/Telnet/Bluetooth）自动用 default → 不用每个类都加空实现

**为什么之前没踩这个坑**：8-26 加 EchoParticipant.sendBinary 时，调用方 `activeParticipants[config.id]?.sendBinary(data)` 已经在 8-26 之前的代码里写好了。`sendBinary` extension 在更早（甚至项目最初）就存在，但从来没人测试过 echo 发图片/wav 这条路径（**echo 是 8-26 才加的**）。

### 5. DEBUG log 是临时的，问题定位完全部删掉

确认根因后，删除：
- `ChatView.swift` `_debug` 辅助函数（10 行）
- `ChatView.swift` `broadcastBinaryToParticipants` 里的 6 条 _debug 调用
- `EchoParticipant.swift` `sendBinary` 里的 5 条 DEBUG postInfo

### Build 结果

- iOS：`xcodebuild -project chatroom.xcodeproj -scheme chatroom -sdk iphonesimulator -configuration Debug -destination 'generic/platform=iOS Simulator' build CODE_SIGNING_ALLOWED=NO` → **BUILD SUCCEEDED**

---

## 2026-08-27 模型查询弹框 + AI HTTP 整合到 `AiParticipant`

**摘要**：今天两件事——主页 AI 卡片的「查询模型」交互从「点查询多出一行 Spinner」改成「点查询 → 查不到不弹 / 查到弹 AlertDialog 点选回填」；同时把主页查询用的 HTTP（GET `/v1/models`）从 UI 层 / 独立服务文件搬进 `AiParticipant`，让「查询 / 发送 / 结果解析」三段 AI HTTP 逻辑全部集中在同一个文件。Android + iOS 对齐，`xcodebuild` + `./gradlew assembleDebug` 都过。

### 1. 模型查询从「多出一行 Spinner」改为「弹框点选回填」」

之前主页 AI 卡片查模型：点「查询模型」按钮 → 下面多出一行「模型列表：」 + Spinner，用户从 Spinner 里选一个 → 自动回填到模型输入框。**冗余**（多一个 layout 行 + 多一次选择步骤）。

现在：点按钮 → 查得到 → 弹框列出所有模型 → 点选 → 回填 + 关弹框；查不到 → 只 Toast「未查到模型」/「查询失败」，不弹任何框。

- **Android**：`item_editing_card.xml` 删 `layoutAiModels`（模型列表 + Spinner 整行）；`ParticipantAdapter.kt` `btnQueryModels.setOnClickListener` 里 `models.isEmpty()` 只 Toast、`else` 走 `AlertDialog.Builder.setItems(...) { _, which -> inputAiModel.setText(models[which]) }`
- **iOS**：`HomeView.swift` `aiFields` 尾部挂 `.confirmationDialog("选择模型", isPresented: $showModelPicker)`（iOS 15+ 行动面板，iOS 16+ 默认 slide-up，从下往上出）+ `.alert("查询模型", isPresented: $showQueryAlert)`（仅查不到 / 失败时出，点「知道了」返回）

### 2. AI HTTP 全部进 `AiParticipant`

之前查询 HTTP 散落两处（Android 在 UI `ParticipantAdapter.kt`，iOS 在 `Core/ModelQueryService.swift`），跟 send / parse 同名却不在一起，改协议要翻三个文件。今天收拢：

| 端点 | Android | iOS |
|---|---|---|
| GET `/v1/models` | `AiParticipant.Companion.fetchModels` | `AiParticipant.queryModels`（static） |
| POST `/v1/chat/completions` | `AiParticipant.sendChatCompletion` | `AiParticipant.doChatRequest` |
| POST `/v1/audio/transcriptions` | `AiParticipant.sendVoiceToText` | `AiParticipant.doSttRequest` |
| POST `/v1/audio/speech` | `AiParticipant.sendTextToSpeech` | `AiParticipant.doTtsRequest` |

具体改动：

- **Android** `participants/AiParticipant.kt`：`companion object` 加 `fetchModels(ip, port, apiKey, callback)`，background 跑网络、main thread 回调（callback 签名 `(httpCode, models, errorMsg)`，errorMsg != null 表示网络异常）。`ui/common/ParticipantAdapter.kt` 加 import，click handler 内联 HTTP 全删，改成调 `AiParticipant.fetchModels(...)`，handler 只剩 UI 关注点（按钮 enable / Toast / AlertDialog / 回填）
- **iOS** `Participants/AiParticipant.swift`：文件顶部加 `enum ModelQueryError: LocalizedError`（invalidURL / nonHTTPResponse / http(Int) / network(String) / parseFailed 五个 case，错误描述走 `errorDescription`）；类内加 `static func queryModels(ip:port:apiKey:) async -> Result<[String], ModelQueryError>`（URLSession + JSONSerialization）。`UI/Home/HomeView.swift` 调 `ModelQueryService.fetch(...)` → `AiParticipant.queryModels(...)`，UI 代码不动。`Core/ModelQueryService.swift` **删除**

这样「OpenAI 兼容的所有 HTTP 调用」全部集中在 `AiParticipant`——Android 是 class + companion，iOS 是 class + static。主页查询弹框 / Toast 这类 UI 关注点仍然留在 adapter / view 里，这是有意为之：**HTTP 归 `AiParticipant`，UI 归 UI 层**。

### 3. iOS 端踩坑记录

第一次 build 报 `type 'String' does not conform to protocol 'Error'`，因为 `Result<[String], String>` 的 failure 必须是 `Error` 协议。**修法**：定义 `enum ModelQueryError: LocalizedError`，callback caller 走 `error.errorDescription ?? "未知错误"`。

### Build 结果

- Android：`./gradlew assembleDebug` → **BUILD SUCCESSFUL**（5s）
- iOS：`xcodebuild -project chatroom.xcodeproj -scheme chatroom -sdk iphonesimulator -configuration Debug -destination 'generic/platform=iOS Simulator' build CODE_SIGNING_ALLOWED=NO` → **BUILD SUCCEEDED**

---

## 2026-08-26 同步（TTS 子类型 + ECHO 复读机 + 图片全屏 + 收方 audio bubble + 移除 USER）

**摘要**：今天主要把 Android 端已有的 chat 增强（WS audio bubble / 图片全屏 / TTS / ECHO 主类型）镜像到 iOS 端，同时重构两个细节（音频气泡只按钮可点、移除 `ParticipantType.USER` + 修 spinner 错位）。Android + iOS 行为对齐，`xcodebuild` + `./gradlew assembleDebug` 都过。

### 1. WS binary receive 现在 `image/*` 和 `audio/*` 都贴气泡

之前 `WsParticipant.dispatchBinary` 只给 image 贴气泡，audio 收到只贴 info 灰字。今天扩到两个都贴（adapter 靠 `BlobSniffer.detectType` 分流）。

```swift
// iOS WsParticipant.swift
let isImage = detected.hasPrefix("image/")
let isAudio = detected.hasPrefix("audio/")
if isImage || isAudio {
    let mediaMsg = Message(..., imageBytes: data)
    onMessage?(mediaMsg)
}
```

Android 端 `WsParticipant.kt` 同款改动。

### 2. 图片全屏查看器

- **Android**：新建 `ui/chat/FullscreenImageActivity.kt`，黑底 + `ImageView.ScaleType.FIT_CENTER`，状态栏 / 导航栏涂黑，点任意位置（ImageView）→ `finish()` 回到 chat。在 `AndroidManifest.xml` 注册（`@android:style/Theme.Black.NoTitleBar.Fullscreen`）
- **iOS**：`MessageRowView.swift` 内嵌 `FullscreenImageView`，用 SwiftUI 原生 `.fullScreenCover(isPresented:)`，**不需 Info.plist 额外配置**。点击流程：
```swift
Image(...).onTapGesture { showFullscreen = true }
    .fullScreenCover(isPresented: $showFullscreen) {
        FullscreenImageView(imageData: data)
    }
```

适配器层面：`MessageAdapter.kt`（Android）/ `MessageRowView.swift`（iOS）的 image 分支都加 `imgContent.setOnClickListener` / `.onTapGesture`。**音频气泡的播放按钮走原生 Button（iOS） / MaterialButton（Android）**，本身就可点，不需要额外包装

### 3. 音频气泡点击行为

最初我把整个 `audioContent` 行（按钮 + 时长 + 空白）都做成可点，结果用户纠正：「不是点气泡播放 / 点气泡放大，是点音频播放，点图片放大」 → **只让按钮是触发器，时长文字 / 气泡空白不响应点击**。

Android：`MessageAdapter.kt` 删掉 `audioContent.setOnClickListener`，只留 `btnAudioPlay.setOnClickListener`
iOS：音频气泡已经是 `Button { AudioMessagePlayer.shared.play(...) }`，天然只按钮可点，无需改

### 4. AI TTS 子类型（text → stt → tts）

之前 AI 卡片 subType 只有 `text` / `stt`，今天加 `tts`，实现文字转语音。

- **路径**：`POST http://<ip>:<port>/v1/audio/speech`，Body `{model, input, voice}`，Bearer Token。**OpenAI 兼容**，用户已用 `Qwen3-TTS-12Hz-0.6B-Base-4bit` + `voice=alloy` 测过
- **AiParticipant 重构**：`sendInput(text)` 拆成 dispatcher，`subType==tts` → `sendTextToSpeech()`，否则 → `sendChatCompletion()`。**stt 走 sendVoice 不走 sendInput**
- **返回音频字节**塞进 `Message.imageBytes`，adapter 用 BlobSniffer 嗅探成 `audio/*` → 音频气泡，跟 WS / STT 那条路径对齐
- **Info 灰字**：`🔄 TTS 合成中...` → `📥 TTS 接收 type=<mime> len=N hex=...` → 音频气泡

两端 `subTypesDisplay` / `subTypesValue` 都扩成 `["文本", "语音转文字", "文字转语音"]` / `["text", "stt", "tts"]`。

### 5. AI TTS 的 voice 输入框

之前 voice 字段硬编码 `alloy`。今天让用户在首页 AI 卡片填值，仅在 `subType=tts` 时显示：

- `item_editing_card.xml` 加 `layoutAiVoice` + `inputAiVoice` EditText（紧跟 `layoutAiSubType`）
- `HomeView.swift` 在 `aiFields` 里 tts 时多显示 `voice:` 输入（SwiftUI `if card.aiSubType == "tts" { ... }`）
- `EditingCardData` 加 `aiVoice: String = "alloy"`；`toConfig()` 写 `voice=...`（仅 tts 且非默认才写，保持 params 简洁）
- `ChatFragment.kt` / `ChatView.swift` 抽 `val voice = config.params["voice"] ?? "alloy"` 传给 AiParticipant 构造
- `AiParticipant` 构造加 `voice: String = "alloy"` 参数，`sendTextToSpeech` 用 `voice.ifBlank { "alloy" }`

### 6. ECHO 主类型（自测复读机）

新主类型 `ECHO("🔁")`，纯客户端复读机，**用来测试 chat 页面 + 消息广播链路时不用起真实服务**：

- 用户发什么文本，它把同样的文本作为一条消息贴回来
- 文本输入 → `sendInput`；二进制输入 → `sendBinary`（image / audio / 其他都原样回吐，adapter 嗅探 mime 决定渲染）
- 不需要任何配置（ip / port / apiKey 都不需要）
- Android：`Participants/EchoParticipant.kt` 用 `Handler.postDelayed`；iOS：`Participants/EchoParticipant.swift` 用 `DispatchQueue.main.asyncAfter`
- 主页 spinner 选 ECHO 后整张卡片只剩「类型 +取消按钮」（通用参数 / IP / 端口那些 layout 全 GONE）
- `ParticipantType` enum 加在 `.user` 之前的位置，icon `🔁`（repeat/loop 箭头，直白对应「原样回吐」）

### 7. ECHO binary 支持

EchoParticipant 实现 `sendBinary(bytes)`：跟 WS `dispatchBinary` 同款贴 `📥 Echo 接收 type=blob len=N hex=...` + `🔍 Echo 检测 type=...` + imageBytes 消息。**不管 mime 都返**——PDF / ZIP / 任意 binary 也走 self-test 链路

ChatFragment / ChatView 的 `broadcastBinaryToParticipants` switch 加 `case .echo → activeParticipants[config.id]?.sendBinary(data)`

### 8. ECHO 延迟（自测节奏控制）

让 ECHO 不立即回吐，方便看到「发送完还在加载」的中间态，验证 inputArea 不被对方消息顶走：

- **单位 1s，默认 0.5，可输入浮点数**
- Android：`EditingCardData.echoDelay: Float = 0.5f` + `layoutEchoDelay`（`numberDecimal` 输入框，仅 ECHO 时显示）+ `postDelayed(..., (delaySeconds * 1000).toLong().coerceAtLeast(0L))`
- iOS：`EditingCardData.echoDelay: Float = 0.5` + `echoFields` 视图（`.decimalPad` 键盘）+ `DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(Int((delaySeconds * 1000).rounded())))`
- `toConfig()` 写 `delay=...`（仅非默认 0.5 才写，保持简洁）
- `EchoParticipant` 加 `delaySeconds: Float = 0.5` 构造参数
- `connect()` 提示文案带延迟值：`🔁 Echo 已连接（自测模式 · 延迟 默认 0.5s）` 或 `延迟 1.5s`

### 9. ParticipantType.USER 移除 + spinner 错位修复

**根因**：重排 enum（USER 挪到第一位）后，`HomeFragment` 的 `typeSpinner.setSelection(pos)` 用的 `ParticipantType.entries.indexOf(it)` 拿到**全枚举下标**，但 spinner adapter 是 filter 过（去 USER）的列表——**差 1 位**，SOCKET 默认跑到了 BBS，3 个类型 params 字段都错位（ECHO 显示 host:port user:xxx、SERIAL 显示 延迟(s)、等等）

**修法**：
- `Models.kt` / `ParticipantType.swift` 直接删 `USER("👤")`（它只在内部用来标 `Message.senderType` 内部字段「self」，`SelfViewHolder` / `SelfMessageRow` 根本不渲染 senderType）
- iOS 端 `selectableCases = allCases`（去 `.user` 的 filter 没意义了）
- `ChatFragment.kt` / `ChatView.swift` 那 8 处 `senderType = ParticipantType.USER` / `.user` 全部换成 `.socket`（占位，纯文本复读机时改成 .echo 同理）
- 删除后下标自动对齐，spinner 选择逻辑不再 off-by-one

iOS 端本身用 `Picker.tag(type)`（不是 index），本来就没 bug；删 `.user` 是为了**和 Android 行为对齐 + 简化 enum**

### iOS 端文件登记（特殊处理）

iOS 端 Xcode 项目用了 **`PBXFileSystemSynchronizedRootGroup`**（Xcode 16+ 特性，pbxproj line 12-16 + 51-53），整个 `chatroom/` 目录被自动同步进编译。**新增 `EchoParticipant.swift` 不需要手动改 pbxproj**，只要放进 `chatroom/Participants/` 就行。

### Build 结果

- Android：`./gradlew assembleDebug` → **BUILD SUCCESSFUL**（4 次：TTS 完后、ECHO 完后、删 USER 完后、最终压缩前）
- iOS：`xcodebuild -project chatroom.xcodeproj -scheme chatroom -sdk iphonesimulator -configuration Debug -destination 'generic/platform=iOS Simulator' build CODE_SIGNING_ALLOWED=NO` → **`** BUILD SUCCEEDED **`**
- Android APK：`xcodebuild` 等价的产物在 `android/app/build/outputs/apk/debug/app-debug.apk`，xz -9 压到 7.6MB（33MB → 23%）后通过 `send-file-to-feishu.sh` 发飞书