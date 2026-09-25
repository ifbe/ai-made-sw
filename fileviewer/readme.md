# fileviewer

浏览器里的 **KiCad 文件 + 3D 模型查看器**。

打开 `index.html` 就能用：没有构建步骤、没有 `package.json`、没有任何第三方库，
所有文件都在本地解析，不上传任何东西。

## 目标

让 KiCad 工程和它的 3D 元件模型，不需要装 KiCad 就能在浏览器里看。

- PCB / 原理图的 **2D 查看** 和 **3D 查看**（顶部按钮切换）
- 独立 3D 模型文件（STEP / VRML / STL）直接预览
- 把元件模型**铺到 PCB 上**——拖入模型库目录即可

## 能做什么

| 拖进来的东西 | 结果 |
|---|---|
| `.kicad_pcb` | 2D 视图（板框/走线/焊盘/过孔/丝印）↔ 3D 视图（可旋转缩放、点击选中看详情） |
| `.kicad_sch` | 2D 原理图（导线/符号/标签/节点） |
| `.step` / `.stp` | 3D 模型，直接显示 |
| `.wrl` | 3D 模型，直接显示 |
| `.stl` | 3D 模型，直接显示（二进制与 ASCII 都支持） |
| `.3mf` | **尚未实现**，会给出明确提示 |
| 一个**目录** | 登记为"模型库"，供 PCB 里的 `(model ...)` 引用解析 |
| `http(s)://` 地址 | 按 URL 后缀判断类型后加载 |

模型库只服务 PCB —— 直接拖单个 3D 文件进来时不查库。

## 怎么用

1. 打开 `index.html`
2. 拖一个 `.kicad_pcb` 进去 → 点顶部「3D 视图」
3. 想让元件模型真的出现：先把 `3dmodels` 目录（或项目目录）拖进去，
   底部工具条会显示已登记的文件数，再拖 PCB

## 文件结构

按职责分成四族，`index.html` 里的 `<script>` 顺序**就是依赖顺序**：

```
render2d-*   2D 渲染（viewport / hittest / pcb / sch）        Canvas 2D
render3d-*   3D 渲染管线（triangulate / math / camera /        WebGL
             models / mesh / pick / webgl）
parser-*     格式解析（sexpr / kicad_pcb / kicad_sch /         → 元素数据或三角网格
             step / wrl / stl / 3mf）
panel-*      UI 面板（properties / layers）
app.js       唯一的控制器：事件绑定 + 状态机（2D/3D 模式、选中、模型库）
```

两条渲染路径互不干扰：2D 走 Canvas 2D，3D 走 WebGL，用顶部按钮切换。
`parser-*` 产出的三角网格格式是统一的，所以 3D 渲染管线与文件格式无关。

## 边界

- 只做**查看**，不编辑、不保存
- 3D 模型文件的**外部引用**需要用户提供模型库（浏览器读不到任意文件系统路径）
- STEP 的曲面面（约占 16%）目前只有线框，见 `todo.md`
- 丝印文字、铜皮（zone）、内层铜在 3D 里暂未渲染

已知的坑与注意事项见 `gotcha.md`，待办见 `todo.md`。
