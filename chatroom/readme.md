# Chatroom - Android 终端聊天 App

## 项目概述

多 Tab 聊天终端 App，每个 Session 是一个多参与者聊天室，支持：

| 类型 | 说明 | 实现方式 |
|------|------|----------|
| **SOCKET** | TCP/UDP socket 客户端 | Java Socket / DatagramSocket |
| **PTY** | 本地伪终端 | JNI /dev/ptmx + forkpty |
| **SERIAL** | 串口通信 | JNI termios |
| **SSH** | SSH 连接（仅 UI 配置） | 参数：ip/port/user/password |
| **AI** | OpenAI 兼容 API | HTTP POST |
| **SMART_DEVICE** | 智能设备 | 类型预留 |

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
│   ├── Models.kt                 # ParticipantType / Message / EditingCardData
│   └── SessionManager.kt         # 管理所有 Session 和消息
├── participants/
│   ├── PtyNative.kt              # JNI wrapper（loadLibrary "pty"）
│   ├── PtyParticipant.kt         # PTY：/dev/ptmx + forkpty
│   ├── SocketParticipant.kt      # SOCKET：TCP + UDP（SocketType 枚举）
│   ├── SerialNative.kt           # JNI wrapper
│   ├── SerialParticipant.kt      # SERIAL：termios 串口
│   ├── AiParticipant.kt          # AI：HTTP OpenAI 兼容 API
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
    PTY("🖥️"),
    SSH("🖥️"),
    AI("🤖"),
    SERIAL("🔌"),
    SMART_DEVICE("💡"),
    SOCKET("👤")
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
    val isInfo: Boolean = false  // true = 小灰字居中，不显示气泡
)
```

### EditingCardData（HomeFragment.kt 内联类）
```kotlin
data class EditingCardData(
    val id: String = UUID.randomUUID().toString(),
    var type: ParticipantType = ParticipantType.SOCKET,  // 默认 SOCKET
    var name: String = "",
    var params: String = "",
    var socketIp: String = "",
    var socketPort: String = "",
    var sockType: String = "TCP",     // TCP 或 UDP
    var ptyDevice: String = "/dev/ptmx",
    var ptyShell: String = "/system/bin/sh",
    var serialDevice: String = "/dev/ttyS0",
    var serialBaud: String = "115200",
    var sshIp: String = "",
    var sshPort: String = "22",
    var sshUser: String = "",
    var sshPassword: String = "",
    var aiIp: String = "",
    var aiPort: String = "",
    var aiApiKey: String = "",
    var aiModel: String = ""
)
```

### ParticipantConfig（创建会话时从 EditingCardData 序列化）
```kotlin
data class ParticipantConfig(
    val id: String = UUID.randomUUID().toString(),
    val type: ParticipantType,
    val name: String,
    val params: Map<String, String> = emptyMap()  // 各类型自有参数
)
```

---

## UI 界面

### 主界面（HomeFragment）
- 顶部 App 名称 + 创建按钮
- 参与者编辑卡片列表（所见即所得）
- 底部 TabBar：Home / Sessions 切换
- 点击大加号 → 新增 SOCKET 类型卡片（默认类型）
- 每个卡片可切换类型，填写对应参数
- 右上角 × 删除卡片
- **SOCKET** 卡片字段：IP / 端口 / 协议（TCP/UDP 下拉）
- **PTY** 卡片字段：ptmx 路径 / shell
- **SERIAL** 卡片字段：串口设备 / 波特率
- **SSH** 卡片字段：IP / 端口 / 用户 / 密码
- **AI** 卡片字段：IP / 端口 / Key / 模型（手动输入 + 查询模型按钮 + 模型列表 Spinner）

### 聊天界面（ChatFragment）
- RecyclerView 消息列表
- 用户消息：右对齐气泡
- 参与者消息：左对齐气泡，带类型图标
- 系统消息（isInfo=true）：小灰字居中，无气泡
- **输入栏**：4 种输入模式通过 Spinner 切换，四个 Spinner 同步
  - 📝文字：EditText + 发送按钮（默认）
  - 🎮遥控：Spinner + 3×3 方向键网格，点击直接发送 ↑↓←→
  - 🎤语音：（TODO）
  - 📁文件：（TODO）
- 消息广播：用户发送 → 所有参与者收到

---

## 各参与者实现细节

### SOCKET（SocketParticipant）
- `SocketType.TCP`：Java `Socket(ip, port)`，阻塞读 `\n` 分行
- `SocketType.UDP`：Java `DatagramSocket()` 随机端口，`sendto` / `recvfrom` 显式地址
- 每个 `receive()` 或每次 `read()` 直接出一个气泡（原样显示，不做行处理）
- `soTimeout` 避免永久阻塞
- 连接/发送都在后台线程

### PTY（PtyParticipant）
- JNI C 代码操作 `/dev/ptmx`
- `openPtmx()` → 打开 `/dev/ptmx` 获取 master fd
- `forkPty(masterFd, slaveName)` → fork 出子进程，子进程 exec shell
- `readPty(masterFd, buf, timeoutMs)` → select 超时读取
- `writePty(masterFd, text)` → 写给 shell
- `closePty(masterFd)` → 关闭 master fd
- 需要 root Android

### SERIAL（SerialParticipant）
- JNI C 代码操作 `/dev/tty*`
- `openSerial(device, baud)` → `open()` + `termios` 配置（8N1, raw, 波特率转换）
- `readSerial(fd, buf, timeoutMs)` → `select` 超时读取
- `writeSerial(fd, data)` → `write()`
- `closeSerial(fd)` → `close()`
- 支持波特率：9600 / 19200 / 38400 / 57600 / 115200 / 230400 / 460800 / 921600

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
- 模型列表：`GET http://ip:port/v1/models` 查到后填充 Spinner

### SSH
- 仅 UI 配置（ip/port/user/password），连接逻辑未实现

---

## NDK 编译

```bash
cd $PROJECT/android
$ANDROID_NDK_HOME/ndk-build
# 输出：libs/armeabi-v7a/libpty.so (包含 ptmx.c + serial.c)
```

Android.mk 配置：
```makefile
LOCAL_MODULE := pty
LOCAL_SRC_FILES := ptmx.c serial.c
```

---

## 权限

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<!-- PTY/SERIAL 需要 root -->
```

AndroidManifest 设置 `android:usesCleartextTraffic="true"`（AI HTTP 明文）。

---

## 消息类型设计

| 类型 | senderId | 说明 |
|------|----------|------|
| SOCKET TCP | `"socket"` | TCP socket 消息 |
| SOCKET UDP | `"socket"` | UDP socket 消息 |
| PTY | `"pty"` | 终端输出 |
| SERIAL | `"serial"` | 串口数据 |
| AI | `"ai"` | API 回复 |
| 系统 | `"system"` | isInfo=true 小灰字 |

---

## 已知限制

- SSH 参与者：仅有 UI，无实际连接实现
- Bluetooth：未实现
- 图片/视频消息：未实现
- PTY/SERIAL：需要 root Android 权限
