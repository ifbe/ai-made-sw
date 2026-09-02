# Chatroom 变更日志

按倒序排列（最新在最上面）。详细的项目说明见 [`readme.md`](./readme.md)。

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