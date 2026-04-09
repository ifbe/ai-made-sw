# chatroom - Android 终端聊天 App

## 项目概述

多 Tab 聊天终端 App，支持与以下目标聊天：

1. **PTY** - 本地伪终端（/dev/ptmx）
2. **SSH** - 远程 SSH 连接
3. **AI** - 各种 AI Provider（OpenAI / Ollama 等）
4. **Serial** - 串口通信
5. **SmartDevice** - 智能设备（如智能灯），发消息有响应，协议不限
6. **Human** - 人与人聊天（类似群聊）

每个会话独立一个 Tab，支持多开。

---

## 核心设计：Session 是多参与者的聊天室

Session 不再是 1 对 1，而是一个**多参与者聊天室**：

- 会话里可以没有人（空会话）
- 可以有 1 个人、2 个人、任意人数
- 可以是：人 + 终端、人 + AI、人 + 智能设备
- 可以是：AI + 终端、AI + 智能设备
- 可以混搭：人 + 终端 + 智能设备 + AI 一起聊
- **任意组合，任意混合**

### 消息路由
用户发一条消息 → 广播给 Session 内所有"东西" → 各"东西"自行处理并可能回复 → 回复也广播给所有人。

### Session 接口
```kotlin
interface Participant {
    val id: String
    val type: ParticipantType  // PTY / SSH / AI / Serial / SmartDevice / Human
    val displayName: String
    val icon: Drawable?

    fun send(text: String)                          // 发给这个参与者
    fun onReceive(from: String, style: Vt100Style, text: String)  // 收到消息
    fun disconnect()
}

class Session(val id: String) {
    val participants = mutableListOf<Participant>()

    fun broadcast(senderId: String, style: Vt100Style, text: String) {
        // 广播给除发送者外的所有参与者
        participants.forEach { if (it.id != senderId) it.onReceive(...) }
    }
}
```

---

## 架构

### 核心原则
- 所有类型（PTY/SSH/AI/Serial/SmartDevice/Human）共用同一套 UI 层
- UI 通过统一接口 `Participant` 与底层通信，不感知对方类型
- VT100 escape sequence 贯穿所有终端类型，控制聊天气泡样式

---

## 目录结构

```
app/src/main/java/com/chatterbox/app/
├── MainActivity.kt              # 首页 + ViewPager2 TabLayout
├── core/
│   ├── SessionManager.kt        # 管理所有活跃 Session
│   ├── Message.kt               # data class Message(fromId, content, style)
│   └── Vt100Style.kt            # 颜色、粗体、下划线等样式
├── participants/
│   ├── Participant.kt           # 接口定义
│   ├── PtyParticipant.kt        # /dev/ptmx
│   ├── SshParticipant.kt        # ProcessBuilder ssh
│   ├── SerialParticipant.kt     # 串口
│   ├── SmartDeviceParticipant.kt # 智能设备
│   ├── AiParticipant.kt         # AI provider
│   └── HumanParticipant.kt       # 真人
├── ai/
│   ├── AiProvider.kt            # interface
│   ├── OpenAiProvider.kt        # OpenAI compatible /v1/chat/completions
│   └── OllamaProvider.kt        # /api/chat
├── vt100/
│   └── Vt100Parser.kt           # 解析 ANSI escape → Vt100Style
└── ui/
    ├── HomeFragment.kt           # 主界面：创建会话页面
    ├── ParticipantCard.kt         # 单个参与者卡片（图标+名字+参数）
    ├── AddParticipantCard.kt      # 加号卡片，点击弹出类型选择
    ├── SessionPagerAdapter.kt     # ViewPager2 TabLayout 适配器
    └── ChatFragment.kt           # 单个 Tab 聊天内容
```

---

## 主界面（创建会话）

```
┌─────────────────────────────┐
│  chatroom          [+ 创建] │  ← 状态栏 + 创建按钮
├─────────────────────────────┤
│                             │
│  ┌─────────────────────┐    │
│  │  + 添加参与者        │    │  ← 加号卡片（点击弹出类型选择浮窗）
│  └─────────────────────┘    │
│                             │
│  ┌─────────────────────┐    │
│  │ 🖥️ SSH: user@host   │    │  ← 参与者卡片（可上下滚动）
│  └─────────────────────┘    │
│  ┌─────────────────────┐    │
│  │ 🤖 AI: OpenAI      │    │
│  └─────────────────────┘    │
│  ┌─────────────────────┐    │
│  │ 💡 智能灯: 192.168.x │    │
│  └─────────────────────┘    │
│                             │
└─────────────────────────────┘
```

- **顶部**：App 名称 + "创建"按钮
  - 点"创建" → 创建新 Session Tab → 主界面恢复默认状态（空参与者列表）
- **主体**：可上下滚动的参与者卡片列表
  - 每张卡片显示：类型图标 + 名字 + 关键参数 + 删除按钮
  - 最后一个是 `+` 卡片，点它弹出类型选择（PTY/SSH/AI/Serial/SmartDevice/Human）
  - 选完类型后弹出参数填写框（SSH 填 host/port/user，AI 选 provider 填 key，etc.）
- **最简流程**：一个参与者都不加直接创建 → 空会话 Tab，可以后续再往里加东西

---

## 聊天 Tab 界面

每个 Session Tab 内是微信聊天风格：

```
┌── Session: SSH+AI+灯 ──────┐
│                             │
│  🤖 AI: 这是一条AI的回复     │
│                             │
│  💡 智能灯: 已开灯           │
│                             │
│            我: ls -la        │  → 发给所有参与者
│                             │
│  🖥️ SSH: total 128         │
│                             │
│  🤖 AI: 看起来像是...        │
│                             │
├─────────────────────────────┤
│ [输入框...            ] [➤]│
└─────────────────────────────┘
```

- 消息气泡带发送者头像
- 收到消息自动追加，AI/Human/终端/SmartDevice 各有不同图标
- 输入框发送 → `session.broadcast(myId, style, text)` → 所有参与者收到
- VT100 SGR 样式（颜色、粗体等）渲染到对应气泡

---

## 各参与者类型说明

### 1. PTY
- Android `/dev/ptmx` + `ProcessBuilder`
- 无第三方库依赖

### 2. SSH
- `ProcessBuilder` 调用系统 `ssh` 命令
- 参数：host, port, user
- 无第三方库依赖

### 3. AI
- 主页选择 Provider 子类型（OpenAI / Ollama / 其他）
- 每个 Tab 独立配置 API Key
- OpenAI compatible：`/v1/chat/completions`
- Ollama：`/api/chat`

### 4. Serial
- 串口通信（android-serialport-api 或 jSSC）
- 参数：波特率、数据位、停止位、校验位

### 5. SmartDevice
- 智能设备（灯、插座、传感器等）
- 发消息对方有响应
- 协议先不定，支持 TCP/UDP/串口/ HTTP 等

### 6. Human（"我"）
- 真人用户，通过其他渠道加入（如 WebSocket）
- 支持多人在同一 Session 聊天

#### "我"的输入模式

**文字模式**：调用系统输入法输入文字，发送后 broadcast

**文件模式**：选择图片/视频上传，发送文件消息

**控制按钮模式**：自定义按钮布局，触发时发送对应字符串
- 例：玩具车 → 切换为十字键，按下发 `w/a/s/d` 控制局域网玩具车
- 例：舵机控制 → 切换为滑块，拖动发角度值

---

## 图片 / 视频显示

### 通用规则
- 图片显示缩略图气泡，点击全屏预览
- 视频显示封面 + 播放按钮 + 时长，点击直接播放
- 图片最大边 1920px，超过压缩；视频大小有限制

### 发送方
- "我"发出图片/视频 → "我"的气泡内显示缩略图/封面

### 接收方
- Human 发来的图片/视频 → 对方气泡内显示缩略图/封面，点击全屏
- SmartDevice（如摄像头）发来的图片 → 同上处理
- AI 发来的图片（如多模态模型生成）→ 同上处理

### 发给不支持的参与者
VT100、SSH 纯终端、Serial 等文本类参与者不识别图片。
发给它们时：
- 文本参与者看到 `[图片: xxx.jpg]` 这样的文件名占位符，而非图片本身
- 图片只路由给支持显示的参与者（Human / SmartDevice / AI）

### 示例
```
我: [图片缩略图]  ──────────────────────────────────┐
                                                      │ broadcast
🖥️ SSH: [图片: photo.jpg]   (文本占位符)            │
🤖 AI: [图片缩略图]  (能显示图片)                    │
💡 智能灯: [图片: snapshot.jpg] (文本占位符)         │
```

---

## VT100 样式系统

- `Vt100Parser` 扫描输入流，遇到 `ESC[...m`（SGR）更新当前 `Vt100Style`
- 支持：前景色、背景色、粗体、下划线、反显等
- **你发的消息也经过同一层解析**
  - 对方发来红色文字 → 对方气泡变红
  - 你发 `\e[31mhello` → 你这边也显示红色 hello
- 样式跟随单条消息，不累积
