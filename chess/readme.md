# chess

棋类对弈 App：**象棋 / 国际象棋 / 围棋 / 五子棋** 四个页面，可以单机面对面下，也可以两台设备局域网联机。
**Android 和 iOS 两个版本**功能一致、协议逐字节相同，可以跨平台互相连。

## 功能

- 左上角四个标签切换页面，右上角「重置」把当前这一页摆回开局
- 拖拽下棋：象棋 / 国际象棋直接拖开局棋子；围棋 / 五子棋从棋盘外侧的托盘把棋子拖到交叉点上（数量 `x180` 同步递减）
- **只判断轮次**，不做走法 / 胜负校验：不该自己走时松手会弹回原位；吃子＝走到对方子上（象棋 / 国际象棋）或把子拖出棋盘（四种棋都行）
- 局域网联机：左下角 `[服/客][地址][开始/状态]`，一台开服务、另一台填地址连过去；拖动过程实时同步，落子后同步整盘状态
  - 服 / 客两个模式**各记各的地址**；某个模式没输入过就填默认的「本机 192 地址 : 8765」
  - 第一次联机会申请**「本地网络」权限**（Android 16+ / iOS 14+ 都要，见 [gotcha.md](gotcha.md) 第 1、16 条）
- 右下角可折叠的**特殊日志框**（连接 / 断开 / 出错），同一份日志也写到 logcat（tag `ChessApp`）

## 文档

- [android.md](android.md) —— Android 工程结构、怎么构建、UI / 权限 / 日志、怎么加一种新棋
- [ios.md](ios.md) —— iOS 工程结构、怎么构建、怎么验证（黄金向量 / 联机冒烟）、与设计文档的出入
- [ios/design.md](ios/design.md) —— iOS 复刻规格（逐像素 / 逐行为的对照表）
- [gotcha.md](gotcha.md) —— 踩过的坑（本地网络权限、WebSocket 手测、SwiftUI 命中测试、emoji 化的 ♟……）
- [todo.md](todo.md) —— 已知缺口与下一步

## 构建

```bash
# Android
cd android && ./gradlew :app:assembleDebug
#   → android/app/build/outputs/apk/debug/app-debug.apk
#   （本工程用 toolchainVersion=21，本机已有、零下载；细节见 android.md）

# iOS（详情见 ios.md；真机安装请用 Xcode）
cd ios && xcodebuild -project chess.xcodeproj -scheme chess -sdk iphonesimulator \
  -configuration Debug -derivedDataPath .build/DerivedData CODE_SIGNING_ALLOWED=NO build
```
