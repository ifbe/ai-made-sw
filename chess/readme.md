# chess

Android 棋类对弈 App：**象棋 / 国际象棋 / 围棋 / 五子棋** 四个页面，可以单机面对面下，也可以两台设备局域网联机。

## 功能

- 左上角四个标签切换页面，右上角「重置」把当前这一页摆回开局
- 拖拽下棋：象棋 / 国际象棋直接拖开局棋子；围棋 / 五子棋从棋盘外侧的托盘把棋子拖到交叉点上（数量 `x180` 同步递减）
- **只判断轮次**，不做走法 / 胜负校验：不该自己走时松手会弹回原位；吃子＝走到对方子上（象棋 / 国际象棋）或把子拖出棋盘（四种棋都行）
- 局域网联机：左下角 `[服/客][地址][开始/状态]`，一台开服务、另一台填地址连过去；拖动过程实时同步，落子后同步整盘状态
- 右下角可折叠的**特殊日志框**（连接 / 断开 / 出错），同一份日志也写到 logcat（tag `ChessApp`）

## 文档

- [android.md](android.md) —— Android 工程结构、怎么构建、UI / 权限 / 日志、怎么加一种新棋
- [gotcha.md](gotcha.md) —— 踩过的坑（Android 16 本地网络权限、WebSocket 怎么手测、Gradle JDK 25……）
- [todo.md](todo.md) —— 已知缺口与下一步

## 构建

```bash
cd android && ./gradlew :app:assembleDebug \
  -Dorg.gradle.java.installations.paths="/Applications/Android Studio.app/Contents/jbr/Contents/Home" \
  -Dorg.gradle.java.installations.auto-download=false
```

产物：`android/app/build/outputs/apk/debug/app-debug.apk`（细节见 [android.md](android.md)）

## 目录

```
android/   Android 客户端（目前唯一的实现）
ios/       iOS 工程（Xcode 空壳，还没写）
```
