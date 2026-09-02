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
│   ├── home/HomeFragment.kt + EditingCardData.kt
│   ├── chat/ChatFragment.kt + MessageAdapter.kt + FullscreenImageActivity.kt
│   └── common/SessionPagerAdapter.kt + SessionTabBar.kt + ParticipantAdapter.kt
└── vt100/Vt100Parser.kt
```

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