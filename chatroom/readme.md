# Chatroom - Android 终端聊天 App

## 项目概述

多 Tab 聊天终端 App，每个 Session 是一个多参与者聊天室，支持：

| 类型 | 图标 | 说明 | 状态 |
|------|------|------|------|
| **SERIAL** | 🔌 | 串口通信 | ✅ 完整实现 |
| **PTY** | 🖥️ | 本地伪终端 | ✅ 完整实现 |
| **SSH** | 🔐 | SSH 连接 | ⚠️ 仅 UI 配置，逻辑未实现 |
| **TELNET** | 📡 | TELNET 连接 | ⚠️ 仅 UI 配置，逻辑待实现 |
| **SOCKET** | 🌐 | TCP/UDP socket 客户端 | ✅ 完整实现 |
| **BBS** | 💬 | 论坛/BBS（Telnet 文本协议） | ⚠️ 仅 UI 配置，逻辑未实现 |
| **AI** | 🤖 | OpenAI 兼容 API | ✅ 完整实现 |
| **OPENCLAW** | 🦞 | 本地 OpenClaw gateway 聊天 | ⚠️ 仅 UI 配置，逻辑未实现 |
| **BLUETOOTH** | 📱 | 蓝牙 SPP/RFCOMM 串口 | ⚠️ 仅 UI 配置，逻辑待实现 |
| **INFRARED** | 💡 | 红外遥控（电视/空调等） | ⚠️ 仅 UI 配置，逻辑未实现 |
| **SMART_DEVICE** | 🏠 | 智能家居设备 | ⚠️ 仅 UI 配置，逻辑未实现 |

**消息路由**：用户发一条 → 广播给 Session 内所有参与者 → 各参与者自行处理并回复 → 回复也广播给所有人。

**核心文件**：`/Users/ifbe/Desktop/code/ifbe/ai-made-sw/chatroom/android/`

---

## 架构

### 核心原则
- 所有参与者类型共用同一套 UI 层
- UI 通过统一接口与底层通信，不感知对方类型
- 系统消息（连接状态等）用 `isInfo=true` 小灰字居中显示，不带气泡
- 用户发的消息广播给所有参与者（类似群聊）

### 目录结构
```
app/src/main/java/com/example/chatroom/
├── MainActivity.kt               # 首页 + ViewPager2 + TabLayout
├── core/
│   ├── Models.kt                 # ParticipantType / Message / ParticipantConfig
│   └── SessionManager.kt         # 管理所有 Session 和消息
├── participants/
│   ├── PtyNative.kt              # JNI wrapper（loadLibrary "pty"）
│   ├── PtyParticipant.kt         # PTY：/dev/ptmx + forkpty
│   ├── SocketParticipant.kt      # SOCKET：TCP + UDP（SocketType 枚举）
│   ├── SerialNative.kt           # JNI wrapper
│   ├── SerialParticipant.kt      # SERIAL：termios 串口
│   ├── AiParticipant.kt         # AI：HTTP OpenAI 兼容 API
│   ├── BluetoothParticipant.kt   # BLUETOOTH：SPP/RFCOMM（stub）
│   ├── TelnetParticipant.kt      # TELNET：TCP 登录（stub）
│   └── SocketType.kt             # TCP / UDP 枚举
├── ui/
│   ├── home/
│   │   ├── HomeFragment.kt       # 主界面：会话创建 + 编辑卡片
│   │   └── EditingCardData.kt    # 编辑卡片数据类
│   ├── chat/
│   │   ├── ChatFragment.kt       # 聊天界面
│   │   └── MessageAdapter.kt     # 消息列表适配器
│   └── common/
│       ├── SessionPagerAdapter.kt # ViewPager 适配器
│       ├── SessionTabBar.kt       # 底部 TabBar
│       └── ParticipantAdapter.kt  # 编辑卡片列表适配器
└── vt100/
    └── Vt100Parser.kt            # ANSI escape → Vt100Style

app/src/main/jni/
├── Android.mk                    # ndk-build 配置
├── ptmx.c                        # PTY JNI（openPtmx / forkPty / readPty / writePty / closePty）
└── serial.c                      # SERIAL JNI（openSerial / readSerial / writeSerial / closeSerial）
```

---

## 数据模型

### ParticipantType（Models.kt）
```kotlin
enum class ParticipantType(val icon: String) {
    SERIAL("🔌"),
    PTY("🖥️"),
    SSH("🔐"),
    TELNET("📡"),
    SOCKET("🌐"),
    BBS("💬"),
    AI("🤖"),
    OPENCLAW("🦞"),
    BLUETOOTH("📱"),
    INFRARED("💡"),
    SMART_DEVICE("🏠"),
    USER("👤")   // 内部使用，不显示在类型选择列表
}
```

### Message（Models.kt）
```kotlin
data class Message(
    val id: String = UUID.randomUUID().toString(),
    val senderId: String,        // 发送者标识
    val senderType: ParticipantType,
    val senderName: String,
    val content: String,
    val timestamp: Long = System.currentTimeMillis(),
    val style: Vt100Style = Vt100Style(),
    val imageUri: String? = null,  // 图片消息
    val isInfo: Boolean = false    // true = 小灰字居中，不显示气泡
)
```

### EditingCardData（HomeFragment.kt 内联类）
```kotlin
data class EditingCardData(
    val id: String = UUID.randomUUID().toString(),
    var type: ParticipantType = ParticipantType.SOCKET,  // 默认 SOCKET
    var name: String = "",
    var params: String = "",
    // SOCKET
    var socketIp: String = "",
    var socketPort: String = "",
    var sockType: String = "TCP",     // TCP 或 UDP
    // PTY
    var ptyDevice: String = "/dev/ptmx",
    var ptyShell: String = "/system/bin/sh",
    // SERIAL
    var serialDevice: String = "/dev/ttyS0",
    var serialBaud: String = "115200",
    // SSH
    var sshIp: String = "",
    var sshPort: String = "22",
    var sshUser: String = "",
    var sshPassword: String = "",
    // TELNET
    var telnetIp: String = "",
    var telnetPort: String = "23",
    var telnetUser: String = "",
    var telnetPassword: String = "",
    // AI
    var aiIp: String = "",
    var aiPort: String = "",
    var aiApiKey: String = "",
    var aiModel: String = "",
    // BLUETOOTH
    var bluetoothDevice: String = "",
    var bluetoothProtocol: String = "SPP"  // SPP 或 RFCOMM
)
```

---

## UI 界面

### 主界面（HomeFragment）
- 顶部 App 名称 + 创建按钮
- 参与者编辑卡片列表（所见即所得）
- 底部 TabBar：Home / Sessions 切换
- 点击大加号 → 新增 SOCKET 类型卡片（默认类型）
- 每个卡片可切换类型（11 种），填写对应参数
- 右上角 × 删除卡片

各类型字段：

| 类型 | 字段 |
|------|------|
| SOCKET | IP / 端口 / 协议（TCP/UDP） |
| PTY | ptmx 路径 / shell |
| SERIAL | 串口设备 / 波特率 |
| SSH | IP / 端口 / 用户 / 密码 |
| TELNET | IP / 端口 / 用户 / 密码（独立于 SSH） |
| AI | IP / 端口 / Key / 模型 |
| BBS | 通用 params 输入框 |
| OPENCLAW | 通用 params 输入框 |
| BLUETOOTH | 设备 Spinner（刷新获取已配对设备）/ 协议 Spinner（SPP/RFCOMM） |
| INFRARED | 通用 params 输入框 |
| SMART_DEVICE | 通用 params 输入框 |

### 聊天界面（ChatFragment）
- RecyclerView 消息列表，`stackFromEnd=true`
- 用户消息：右对齐白色气泡，marginEnd=1dp，paddingHorizontal=14dp
- 参与者消息：左对齐气泡，marginStart=1dp，paddingHorizontal=4dp
- **PTY/SSH 发来的消息**：7sp 等宽字体（其他保持 15sp），以容纳 80 字符宽度
- 系统消息（isInfo=true）：小灰字居中，无气泡
- **接收信息灰字**：PTY/SOCKET/SERIAL/AI 收到消息时，先显示一行 📥 接收 len=X hex=XX...（hex 只显示前 8 字节），再显示气泡内容
- **发送信息灰字**：用户发送时同步显示 📤 发送: xxx
- **输入栏**：5 种输入模式通过 Spinner 切换
  - 📝文字：EditText + 发送按钮（默认）
  - 🎮遥控：Spinner + 3×3 方向键网格，点击直接发送 ↑↓←→
  - 🎮三维：3×3 方向键（↖↑↗←◉→↙↓↘）+ 油门 ± 按钮，左侧；中间 1dp 分割线；右侧 3D 坐标轴（红X 绿Y 蓝Z），+方向末端有箭头和旋转按钮 ⟳，-方向末端有旋转按钮 ⟲，点击发送 X+/X-/Y+/Y-/Z+/Z- 旋转指令
  - 🎤语音：（TODO）
  - 📁文件：（TODO）
- 消息广播：用户发送 → 所有参与者收到

---

## 各参与者实现细节

### SOCKET（SocketParticipant）
- `SocketType.TCP`：Java `Socket(ip, port)`，阻塞读 `\n` 分行
- `SocketType.UDP`：Java `DatagramSocket()` 随机端口，`sendto` / `recvfrom` 显式地址
- UDP 接收用 `Charset.forName("UTF-8")` 解码
- 每个 `receive()` 或每次 `read()` 直接出一个气泡
- `soTimeout` 避免永久阻塞

### PTY（PtyParticipant）
- JNI C 代码操作 `/dev/ptmx`
- `openPtmx()` → 打开 `/dev/ptmx` 获取 master fd
- `forkPty(masterFd, slaveName)` → fork 出子进程，子进程 exec shell
- `readPty(masterFd, buf, timeoutMs)` → select 超时读取
- 读取后用 `Charset.forName("UTF-8")` 解码（不再逐字节 `.toChar()`，解决中文乱码）
- `writePty(masterFd, text)` → 写给 shell
- `closePty(masterFd)` → 关闭 master fd
- 需要 root Android

### SERIAL（SerialParticipant）
- JNI C 代码操作 `/dev/tty*`
- `openSerial(device, baud)` → `open()` + `termios` 配置（8N1, raw, 波特率转换）
- 读取后用 `Charset.forName("UTF-8")` 解码
- `readSerial(fd, buf, timeoutMs)` → `select` 超时读取
- `writeSerial(fd, data)` → `write()`
- `closeSerial(fd)` → `close()`

### AI（AiParticipant）
- HTTP POST `http://ip:port/v1/chat/completions`
- 请求体：
  ```json
  {
    "model": "Qwen3-35B-A3B-4bit",
    "stream": false,
    "messages": [{"role": "user", "content": "用户输入"}]
  }
  ```
- Header：`Authorization: Bearer {apiKey}`
- 读取 `choices[0].message.content` 作为回复
- 收到 AI 响应时：先显示 📥 接收 len=X hex=XX...，再显示气泡内容
- 模型列表：`GET http://ip:port/v1/models` 查到后填充 Spinner

### SSH、TELNET、BBS、OPENCLAW、INFRARED、SMART_DEVICE
- 仅 UI 配置，连接逻辑未实现

### BLUETOOTH
- UI 配置已就绪：设备 Spinner + 协议 Spinner（SPP/RFCOMM）
- stub 实现：BluetoothParticipant.kt，连接逻辑待实现
- 参数：`device`（设备名）、`protocol`（SPP/RFCOMM）
- 设计思路：
  - 每个设备同时开 `BluetoothServerSocket` 监听 + 作为客户端连接其他设备
  - 连接 n 个 peers = n 个 `BluetoothSocket`
  - 发消息时广播给所有已连接 peers
  - 配对在系统设置里完成，app 只从已配对列表选择设备
- 跨平台：蓝牙 SPP/RFCOMM 可跨 win/mac/linux/android，但 iOS 不支持 RFCOMM

---

## NDK 编译

```bash
cd $PROJECT/android
$ANDROID_NDK_HOME/ndk-build
# 输出：libs/armeabi-v7a/libpty.so (包含 ptmx.c + serial.c)
```

---

## 权限

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.BLUETOOTH" />
<uses-permission android:name="android.permission.BLUETOOTH_ADMIN" />
<!-- PTY/SERIAL 需要 root -->
```

AndroidManifest 设置 `android:usesCleartextTraffic="true"`（AI HTTP 明文）。

---

## 气泡布局细节

| 位置 | margin | padding | 字体大小 |
|------|--------|---------|---------|
| 右侧（自己） | marginEnd=1dp | paddingHorizontal=14dp | 15sp |
| 左侧（PTY/SSH） | marginStart=1dp, marginEnd=4dp | paddingHorizontal=4dp | **7sp** |
| 左侧（其他） | marginStart=1dp, marginEnd=32dp | paddingHorizontal=14dp | 15sp |

PTY/SSH 用 7sp 等宽字体，约 4.9dp/字符，340dp 可用宽度约显示 69 字符。通过调整 left margin 和 padding 可容纳 80 字符满行。

---

## 已知限制

- SSH、TELNET、BBS、OPENCLAW、INFRARED、SMART_DEVICE：仅有 UI，无实际连接实现
- Bluetooth：UI 就绪，连接逻辑待实现
- 图片/视频消息：未实现
- PTY/SERIAL：需要 root Android 权限
