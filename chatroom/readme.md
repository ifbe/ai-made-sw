# Chatroom - 各种平台/各种参与者通信工具

## 项目概述

多 Tab 聊天终端 App，每个 Session 是一个多参与者聊天室，支持：

| 类型 | 图标 | Android | iOS | 说明 |
|------|------|---------|-----|------|
| **SERIAL** | 🔌 | ✅ 完整实现 | ⚠️ UI stub（iOS 不支持 USB 串口） | 串口通信 |
| **PTY** | 🖥️ | ✅ 完整实现 | ⚠️ stub（iOS 沙盒限制） | 本地伪终端 |
| **SSH** | 🔐 | ⚠️ UI 配置 | ⚠️ UI 配置 | SSH 连接 |
| **TELNET** | 📡 | ✅ 完整实现 | ✅ 完整实现 | TELNET 连接 |
| **SOCKET** | 🌐 | ✅ 完整实现 | ✅ 完整实现 | TCP/UDP socket 客户端 |
| **BBS** | 💬 | ⚠️ UI 配置 | ⚠️ UI 配置 | 论坛/BBS |
| **AI** | 🤖 | ✅ 完整实现 | ✅ 完整实现 | OpenAI 兼容 API；subType `text`（chat）/ `stt`（audio transcriptions） |
| **OPENCLAW** | 🦞 | ⚠️ UI 配置 | ⚠️ UI 配置 | 本地 OpenClaw gateway |
| **BLUETOOTH** | 📱 | ⚠️ UI stub（Android Central） | ⚠️ UI stub（iOS Peripheral） | BLE 直接通信（无中转） |
| **INFRARED** | 💡 | ⚠️ UI 配置 | ⚠️ UI 配置 | 红外遥控 |
| **SMART_DEVICE** | 🏠 | ⚠️ UI 配置 | ⚠️ UI 配置 | 智能家居设备 |

**消息路由**：用户发一条 → 广播给 Session 内所有参与者 → 各参与者自行处理并回复 → 回复也广播给所有人。

**iOS 项目路径**：`/Users/ifbe/Desktop/code/ifbe/ai-made-sw/chatroom/ios/`
**Android 项目路径**：`/Users/ifbe/Desktop/code/ifbe/ai-made-sw/chatroom/android/`

**变更日志**：见 [`change.md`](./change.md)（按倒序，最新在最上面）
**踩坑汇总**：见 [`gotchas.md`](./gotchas.md)（按主题组织）
**平台细节**：iOS 见 [`ios.md`](./ios.md)，Android 见 [`android.md`](./android.md)

---

## 架构（Android + iOS 共用）

### 核心原则
- 所有参与者类型共用同一套 UI 层
- UI 通过统一接口与底层通信，不感知对方类型
- 系统消息（连接状态等）用 `isInfo=true` 小灰字居中显示，不带气泡
- 用户发的消息广播给所有参与者（类似群聊）

### 数据模型契约

- `ParticipantType`：枚举，标识参与者类型（socket / ai / echo / telnet ...）。具体值见 [`ios.md`](./ios.md) / [`android.md`](./android.md)。
- `Message`：包含 `id` / `senderId` / `senderType` / `senderName` / `content` / `isInfo` / `imageBytes`（二进制复用字段，adapter 用 BlobSniffer 分流 image/audio/text）

### 气泡布局（iOS 与 Android 一致）

| 位置 | padding | 字体 | 说明 |
|------|---------|------|------|
| 右侧（自己） | 14pt horizontal, 10pt vertical | 15pt, 白色 | 蓝色气泡 |
| 左侧（PTY/SSH） | 4pt horizontal, 10pt vertical | **7pt monospace** | 容纳 80 字符 |
| 左侧（其他） | 4pt horizontal, 10pt vertical | 15pt | 白色气泡 |
| Info 灰字 | 8pt horizontal, 4pt vertical | 12pt, #AAAAAA, 居中 | 调试信息 |

**Info 灰字格式**（调试关键）：
- 收到消息：`📥 接收 len=X hex=XX XX XX...`（hex 只显示前 8 字节）
- 收到 WS binary blob：`📥 接收 type=blob len=N hex=XX XX XX...`，紧跟 `🔍 检测 type=<mime> size=<W>x<H>`（image/* 才有 size），最后 image/audio/* 额外贴气泡
- 发送文本：`📤 发送: xxx`
- 发送音频（含录音 / 选 wav 文件）：`📤 发送 type=audio/wav len=N duration=X.XXXs`（**单位是秒，3 位小数**；之前是 ms，去掉 ms 单位是用户要求）
- STT 流式响应（每个 chunk 一条）：`📥 STT: <chunk>`（`<asr_text>...</asr_text>` 是 Qwen3-ASR 服务端 marker，不去它，原样显示）
- TTS 合成中（用户发文本 → AI 走 /v1/audio/speech）：`🔄 TTS 合成中...` → 服务端响应后 `📥 TTS 接收 type=<detected> len=N hex=...` → 音频气泡
- ECHO 自测复读机：`🔁 Echo 已连接（自测模式 · 延迟 <label>）`，`<label>` 是 `默认 0.5s` 或 `Ns`（默认 0.5 简化显示）；binary 接收同 WS 那两条
- 发送图片（含其他 binary）：`📤 发送 type=<detected> size=<W>x<H> len=N`
- **系统错误**（Service 启动失败 / onDestroy / OEM 强杀）:
  - `❌ 前台服务启动失败: SecurityException: ...`
  - `❌ TcpForegroundService.onDestroy count=1 原因=前台服务被系统强杀（startedFlag=true）→ TCP 连接被主动断开`

  Service 内部走 `SessionManager.addMessage` + 当前活跃 callback，ChatFragment 下次 `onStart` 拉历史时**显示在聊天区**。

---






## AI STT subtype（Android + iOS 同步）

主页参与卡类型 = AI 时新增 `aiSubType` 字段（编辑卡 + `toConfig()`），可选 `"text"`（默认）/ `"stt"`。

### HTTP 接口（两端一致）

```
POST http://{ip}:{port}/v1/audio/transcriptions
Headers: Authorization: Bearer {apiKey}
Form: model=<text> + stream=true + file=voice.wav (audio/wav)
stream=true  → SSE: data: {"text": "<chunk>"} ...
stream=false → {"text": "<full>"}
```

`<asr_text>...</asr_text>` 是 Qwen3-ASR 服务端给文本内容包的 marker，**不去它，原样显示**（用户明确要求"只是提问，不是让你过滤掉"）。

## Binary dispatch 架构（重要，Android + iOS 对称）

**调用方只调一句 `broadcastBinaryToParticipants(bytes)`，分发逻辑集中**：

```
handlePickedImage / sendVoiceRecording / handlePickedURL / handlePickedData
        │
        ▼
broadcastBinaryToParticipants(bytes)
        │
        ├─→ .socket  → Participant.sendBinary
        │             （WS override 真正发 binary frame；TCP/UDP TODO no-op）
        ├─→ .ai      → subType=="stt" ? AiParticipant.sendVoice : no-op
        │             （接 /v1/audio/transcriptions，SSE 流式响应）
        ├─→ .agent   → break
        │             （openclaw 暂无 binary 行为；架构位置已留）
        ├─→ .echo    → EchoParticipant.sendBinary(bytes)
        │             （复读机：原样回吐收到的 bytes，adapter 按 mime 决定渲染分支）
        └─→ default  → break
                     （PTY/SERIAL/SSH/TELNET/BLUETOOTH：binary no-op）
```

**设计要点**：
- caller **不** 也不应该知道哪些参与者类型对 binary 敏感 —— 加新参与者类型只改 broadcast 一个函数
- 2026-08-11 用户拍板 dispatch 行为"AI 给 AI 发，WS 给 WS 发，两个都在就给两者都发，各自 onMessage 处理不一样"，落到代码就是上面这个 switch
- 之前 STT dispatch 散在 `sendVoiceRecording` + `handlePickedImage` 两个 caller 里手动循环 `SessionManager.getParticipants`，违反 DRY；refactor 后完全集中

## 蓝牙协议与平台支持

| 协议 | Android | iOS | Windows | macOS | Linux | 说明 |
|------|---------|-----|---------|-------|-------|------|
| **Classic Bluetooth (BT)** | ✅ | ❌ | ✅ | ✅ | ✅ | 传统蓝牙，支持 SPP/RFCOMM |
| **SPP (Serial Port Profile)** | ✅ | ❌ | ✅ | ✅ | ✅ | 蓝牙串口透传，RFCOMM 通道 |
| **RFCOMM** | ✅ | ❌ | ✅ | ✅ | ✅ | Classic BT L2CAP 之上的串口封装 |
| **BLE Central** | ✅ | ✅ | ✅ | ✅ | ⚠️ | 主设备，扫描连接 Peripheral |
| **BLE Peripheral** | ❌ | ✅ | ⚠️ | ✅ | ⚠️ | 从设备，广播被连接（Android 6.0+ 有 Location 限制） |
| **Nordic UART Service (NUS)** | ✅ | ✅ | ✅ | ✅ | ✅ | BLE GATT 透传，跨平台通用 |
| **BLE SPP 替代方案** | ✅ | ✅ | ✅ | ✅ | ✅ | 通过 NUS 或自定义 GATT 实现 BLE 串口透传 |

**iOS 不支持 Classic Bluetooth / SPP / RFCOMM**，只能使用 BLE。

**Android 不支持 BLE Peripheral 模式**，只能当 Central。

### 跨平台 BLE 直接通信方案

| 组合 | 可行？ | 方案 |
|------|--------|------|
| Android ↔ Android | ✅ | Classic BT SPP，或双方 BLE Central ↔ BLE Peripheral |
| iOS ↔ iOS | ✅ | 双方 BLE Central ↔ BLE Peripheral |
| **Android ↔ iOS** | ✅ | **Android Central + iOS Peripheral**（BLE，无中转） |
| Android ↔ Windows | ✅ | Classic BT SPP |
| iOS ↔ Windows | ⚠️ | Windows 不支持连接 iOS Peripheral，需要第三方工具或 BLE dongle |
| macOS ↔ iOS | ✅ | 双方均支持 BLE Peripheral |

### chatroom 蓝牙设计

**最终目标**：Android Central ↔ iOS Peripheral BLE 直接通信，无第三方中转。

架构：
- iOS: `CBPeripheralManager` 充当 Peripheral，广播自定义 GATT Service
- Android: `BluetoothAdapter` 充当 Central，扫描并连接 iOS Peripheral
- 数据透传：自定义 GATT characteristic 读写（替代 SPP/RFCOMM）

限制：
- iOS Peripheral 模式只能在 App 前台运行
- Android 扫描 BLE 设备需要地理位置权限

---
---

## 已知限制

- **iOS PTY**: iOS 沙盒禁止访问 `/dev/ptmx`，真机无法使用；Simulator 上可用 `Process.forkpty()`
- **iOS SERIAL**: iOS 不支持 USB Host API，无法访问 USB 串口
- **SSH**: 仅有 UI 配置，无实际连接实现（Android/iOS）
- **BLUETOOTH 直接通信架构**：iOS Peripheral（CBPeripheralManager）广播 ↔ Android Central（BluetoothAdapter）连接，无需第三方中转。iOS App 必须在前台运行。Android 扫描 iOS 设备需要地理位置权限（6.0+）。
- **图片/视频消息**: 未实现
- **PTY/SERIAL**: Android 需要 root
- **Android TCP 后台保活 vs OEM 省电策略**：`TcpForegroundService` 能在标准设备上后台保持 TCP socket。但**国内厂商（华为/小米/OPPO/vivo/一加）有自家省电策略**，可能直接杀主进程，不走 `onTaskRemoved` 路径。**用户需在系统设置给 chatroom 加白名单**：
  - 华为/荣耀：设置 → 电池 → 启动管理 → 关掉 chatroom "自动管理"
  - 小米/红米：设置 → 电池 → 应用电池节省 → chatroom 选"无限制"
  - OPPO/realme：设置 → 电池 → 后台高耗电 → 允许 chatroom
  - vivo/iQOO：设置 → 电池 → 后台高耗电 → 允许 chatroom
  - 一加：设置 → 电池 → 电池优化 → chatroom 选"不优化"
  - 三星：设置 → 电池 → 后台使用限制 → chatroom 选"不优化"

  加完白名单后切到桌面 netcat 不再断。**chatroom 不会绕过系统**——`android:process=":tcp_service"` 试过会引入 SessionManager 跨进程不一致 + LocalBinder 跨进程失效问题，已撤。代码层面只走前台服务。