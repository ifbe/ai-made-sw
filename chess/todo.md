# TODO / 已知缺口

按「现在缺什么 + 大概怎么做」记，优先级从高到低。

「联机 / 规则 / 体验」三节是 **Android + iOS 两端共用**的缺口（个别平台相关的已就地标注）；
iOS 独有的在最后两节。两端现状见 [android.md](android.md) / [ios.md](ios.md)。

## 联机

- [ ] **前台服务 + partial wakelock**：现在只有「联机期间屏幕常亮」，息屏或切后台久了系统会冻结
      App，socket 就没人处理了（症状见 [gotcha.md](gotcha.md) 第 6 条）。
      做法可参考同目录的 `chatroom` 工程：有网络连接时 `startForeground`（`connectedDevice` 类型）
      + `PARTIAL_WAKE_LOCK`，全部断开后 `stopForeground + stopSelf`；再引导用户加电池优化白名单。
      **iOS 侧无解**（系统不允许后台常驻监听，见 [ios/design.md](ios/design.md) §14.3），
      只能前台用 + 提示用户别切后台。
- [ ] **断线自动重连 + 心跳**：服务端主动 ping/pong，客户端断线后按退避重连，并在重连时用服务端缓存的
      最后一包 `board` 对齐盘面（服务端已经有 `lastBoard` 缓存了）。
- [ ] **房间号 / 口令 / 鉴权**：现在只要连上端口就能发事件，也能发任意盘面。
      至少加一个房间码 + 服务端丢弃不合法/越权的消息。
- [ ] **座位分配**：服务端告诉每个客户端「你是哪一方」，据此限制谁能动子（现在只按本地轮次判断）。
- [ ] **每台设备朝自己那一方**：现在棋子文字是「朝当前该走的一方」转，适合单机面对面。
      联机时应该固定朝设备主人那一侧。
- [ ] **观众模式**：只收不发的连接（服务器广播时已经区分发送者，加个角色即可）。
- [ ] **局域网发现**：现在要手输对方 IP。Android 用 `NsdManager`、iOS 用 `NWBrowser`（Bonjour，
      届时 iOS 还要补 `NSBonjourServices` 和 multicast entitlement）来自动发现房间，省掉手输。
- [ ] **地址记忆持久化**：现在服 / 客的地址只在**本次 App 启动**内记忆（重开恢复默认），
      要跨启动记住就存一份：Android 用 `SharedPreferences`，iOS 用 `UserDefaults`（各加几行即可）。
- [ ] **IPv6**：现在显式绑 `0.0.0.0`（仅 IPv4），发给对端的也是 IPv4 地址。
- [ ] **加密（wss）**：现在只有明文 `ws://`。iOS 侧 `NetAddress` 已认 `wss://`、
      客户端也会切到 `NWParameters.tls`，但**从没测过**；Android 侧要换库才行。
- [ ] **跨平台真机互通实测**：协议已经过 272 行「黄金向量」逐字节比对，但
      **一台 iOS + 一台 Android 真机互相连**还没实际跑过（见 [ios.md](ios.md) 的验证方法）。

## 规则（目前完全没有）

- [ ] 走法校验：象棋（马腿/象眼/炮翻山/过河/九宫）、国际象棋（含易位、吃过路兵、升变）。
- [ ] 吃子与胜负：将军 / 将死 / 困毙，国际象棋的和棋规则。
- [ ] 围棋：提子、禁着点、打劫、数目；五子棋：连五判定。
- [ ] 悔棋 / 回放：事件流（`MoveEvent`）已经是完整的棋谱，配合 `AppLog` / `LocalSession` 的流水就能做，
      顺便能加「一步一动画」的复盘。
- [ ] 存档 / 读档：`BoardSnapshot` 已经是可序列化的全量盘面。

## 体验

- [ ] 棋盘可配置：围棋 13 / 9 路（`BoardGeometry.starPoints(lines)` 已支持），配色主题。
- [ ] 落子细节：吸附容差、长按提起、拖动时的震动/音效反馈、落子动画（现在松手直接吸附）。
- [ ] 联机时的「对方正在拖」视觉区分（现在本地和对端拖拽画得一模一样）。
- [ ] 联机中切换服/客模式现在是**直接忽略点击**，可以改成弹一句提示。
- [ ] 日志框可以加「清空 / 复制全部」两个小操作（现在只能手动选中复制）。
- [ ] 国际象棋计时器（可选）。
- [ ] 多语言 / 英文界面（现在文案全是中文硬编码在 `strings.xml` 和几个 View 里）。

## iOS（复刻版）

已实现并编译通过（30 个 Swift 文件 / 5048 行，见 [ios.md](ios.md)），下面是还没做完的部分：

- [ ] **按 [design.md](ios/design.md) §15 清单逐条真机验收**：现在真机确认过的是
      「连接 / 拖动 / 更新局面可用」+「界面能起来」，清单里的**画面像素、托盘上下/左右切换、
      牌子朝向、悬停配色、日志框滚动选中**这些还没逐条看。
- [ ] **iOS ↔ Android 真机互通**：协议层已逐字节对齐（黄金向量 272 行一致），
      但两台真机互连还没跑过。
- [ ] **把验证脚本挪出被忽略的目录**：`ios/.build/verify/` 里那三套脚本
      （`run-android.sh` / `run-ios.sh` / `run-ws-smoke.sh`）很有用，但 `ios/.gitignore`
      忽略了 `.build`，所以它们**不在版本管理里**、别人 clone 下去没有。
      建议挪到 `ios/verify/`（或加 `!.build/verify` 例外）。
- [ ] **启动提速（不是代码问题）**：Debug 在 iPad6,7 上冷启动 2.2 秒，其中 1400ms 是
      Debug 专属的 `chess.debug.dylib` 加载、506ms 里含 Metal API Validation。
      见 [gotcha.md](gotcha.md) 第 20 条，改 Scheme / Build Settings 即可。
- [ ] **方向锁（可选）**：现在四种方向全开（棋盘转不转只看宽高比，所以不会错乱）。
      Android 侧锁了自然方向，iOS 要一致就配 `INFOPLIST_KEY_UISupportedInterfaceOrientations_*`。
- [ ] **XCTest target（可选）**：iOS 侧现在没有单元测试 target，靠黄金向量 + WS 冒烟脚本
      覆盖纯逻辑；要更正规可以补一个 test target，把那 272 行向量拆成断言。

## 其它

- [ ] 单元测试：Android 侧留了 9 个纯 JVM 的逻辑/几何/协议测试；
      网络层（`WsSession`）没有测试（Android 那个真开 socket 的测试因为慢且容易 flaky 被删了）。
      iOS 侧等价的覆盖就是 `ios/.build/verify/run-ws-smoke.sh`（在 macOS 上真起服务端 + 客户端）。
