# todo

按"离可用最近"到"可以慢慢来"排。每条尽量写清**做什么 / 为什么 / 大致怎么下手**。

---

## 0. 先修：已知但未解决的问题

### 0.1 两处厂商 offset 放不到板上

J5 / J16（`offset z = -128`）与 J7（`offset z = 154.4`）用任何约定都落不到板上，
详见 `gotcha.md` 第 5 条。目前只能显示成飞在板外的占位方块。

下手的办法：找一块**确认在 KiCad 里显示正常**的板子，用同样的模型复现，
再拿 KiCad 官方 3D 查看器的实际渲染结果反推约定。
如果确认是厂商封装的问题，就在 UI 上明确标出来（比如把这些方块染成警告色），
而不是让用户以为是我们的 bug。

### 0.2 背面封装镜像没有验证过

`gotcha.md` 第 6 条。需要一个背面带 3D 模型的板子做样本。
找一块双面贴装的板子（比如手机主板类的开源工程）即可。

---

## 1. 把 3D 模型加载收尾

### 1.1 模型几何缓存与实例化

**现状**：同一模型被引用几十次时，每次都重新变换顶点。
CM5IO 26 个唯一模型 → 66 个实例，实测模型贡献 **159562 个三角形**，
其中有大量重复几何。

**要做的**：按（模型文件 + 变换矩阵）缓存已变换的顶点缓冲，
相同变换直接复用（GPU 侧可以用同一 VBO + 不同 uniform）。

**收益**：板上几十个同样的 0402 电阻，几何只算一次。

### 1.2 模型加载放进 Worker

**现状**：26 个模型解析实测 **1100–1200ms**，期间主线程完全阻塞。
大板子上百个模型会更久。

**要做的**：`parser-*` 的解析放进 Web Worker，
主线程只接收 `Float32Array`（用 transferable 避免拷贝）。

注意：`parser-step`/`parser-wrl`/`parser-stl` 都已经是纯函数、不碰 DOM，
搬进 Worker 的成本不高。`parser-3mf` 要用 `DecompressionStream`，Worker 里也有。

### 1.3 加载进度提示

现在拖入 PCB 后有一段黑屏（模型解析期间），用户不知道发生了什么。
应该在底部工具条或画布上显示 `解析模型 12/26…`。

### 1.4 建库本身的耗时

登记 12386 个模型文件（`kicad-packages3D` + 项目目录）实测 **70–90ms**，
可接受，不需要优化；瓶颈在后面的文件解析。

### 1.5 模型库的持久化

用 File System Access API 的 `showDirectoryPicker()` 可以把目录句柄存进 IndexedDB，
下次打开不用重新拖。Chrome/Edge 支持，Safari/Firefox 不支持 —— 需要优雅降级。

### 1.6 HTTP 模型库前缀

现在底部工具条是只读显示。可以加一个可输入的模式：
让用户填 `http://127.0.0.1:8000/3dmodels/`，然后按
`前缀 + 库内相对路径` 去 fetch。这是**文本框唯一真正有用的场景**（见 `gotcha.md` 第 8 条）。

好处是用户可以用任意静态服务器提供模型库，不用每次拖目录。

---

## 2. STEP 解析的后续阶段

### 2.1 参数曲面（剩下约 16% 的面）

**现状**：只做平面面（PLANE）。其余曲面面的**边界线框**会画出来，但没有实体。

**实测的曲面分布**（官方库 300 个文件、105623 个面）：

| 曲面类型 | 占比 |
|---|---:|
| PLANE | 83.3%（已做） |
| CYLINDRICAL_SURFACE | 7.8% |
| SPHERICAL_SURFACE | 1.4% |
| B_SPLINE_SURFACE_WITH_KNOTS | 0.6% |
| CONICAL_SURFACE | 0.3% |
| TOROIDAL_SURFACE | 0.2% |
| SURFACE_OF_REVOLUTION | 0.1% |
| SURFACE_OF_LINEAR_EXTRUSION | 0.0% |

**下手的顺序**：柱面 → 锥面 → 球面 → 环面 → 旋转/拉伸面 → B 样条。
前面五种都有闭式参数方程，在 (u,v) 上打网格求值即可，
**难点在用面的边界环裁剪** —— 实用妥协是：用边界边的 (u,v) 端点求包围盒，
按此生成网格，再对网格点做内外测试。CAD 导出的旋转体边界在参数域里通常就是矩形，
能覆盖绝大多数实际模型。

**验证手段**：继续用 `.step` vs `.wrl` 的包围盒交叉验证（现在 12/12 通过），
曲面做完后这个数字应该更准 —— 特别是那些平面覆盖率低的模型
（如 `TestPoint_Loop_D2.50mm` 现在 STEP 给 2.18mm、WRL 给 2.50mm，
而零件名里的 2.50mm 说明 **WRL 才是对的**，STEP 偏小正是因为曲面没渲染）。

### 2.2 B 样条曲线求值

**现状**：`B_SPLINE_CURVE` 用**弦**代替，会损失圆角精度。
实测 105 个文件里 **33 个**会走到这条路径（`stats.curveFallback`）。

**要做的**：实现 de Boor 算法（约 80 行），处理节点向量与权重（有理情形）。

### 2.3 装配件

**现状**：遍历所有 `ADVANCED_FACE`，不区分实例。
13/300 的官方模型用 `NEXT_ASSEMBLY_USAGE_OCCURRENCE` + `ITEM_DEFINED_TRANSFORMATION`
表达多实例，现在会把所有实例**重叠渲染在基础位置**。

**要做的**：走 `SHAPE_REPRESENTATION` + `ITEM_DEFINED_TRANSFORMATION` 的装配树，
给每个实例合成变换。

**注意**：第三方厂商的 STEP 变异更大 —— 已见过
`SHELL_BASED_SURFACE_MODEL`、`FACE_SURFACE`、`SEAM_CURVE`、`ELLIPSE`，
官方库里都没有，测试时要拿真实厂商文件当素材
（`~/Downloads/RP-008099-.../CM5IO.3dshapes/` 里有 8 个）。

### 2.4 用 STEP 的显式法线

STEP 曲面带的 `Normal` 信息现在没用，全靠面绕序算。做曲面后可能需要。

---

## 3. 3MF 解析器（唯一剩下的空占位）

**现状**：`parser-3mf.js` 32 行占位，拖 `.3mf` 会提示"尚未实现"。

**已经查清的结构**（本机 37 个样本，全是 Bambu/PrusaSlicer 拆文件结构）：

```
3dmodel.3mf（其实是个 ZIP）
├── [Content_Types].xml
├── _rels/.rels                         ← 从这里找 3dmodel 关系拿到主模型路径
├── 3D/3dmodel.model                    ← 主模型：<resources> + <build>
│   ├── <object id="2"><components>
│   │     <component p:path="/3D/Objects/object_22.model" objectid="1"/>
│   └── <build><item objectid="2" transform="m00 m01 ... m32"/>
├── 3D/Objects/object_*.model           ← 每个对象拆一个文件（production 扩展）
└── Metadata/plate_1.png
```

**要做的**：

1. **ZIP 读取**：EOCD → 中央目录 → 本地头 → inflate。
   解压用 `DecompressionStream('deflate-raw')`（浏览器与 Node 都有，零依赖）。
2. **跨文件组件解析**：`<component p:path=... objectid=...>` 要递归到对应文件里找 object，
   然后合成 4×3 变换矩阵（`transform` 属性是 12 个数）。
3. **单位**：根节点 `unit` 属性，默认 millimeter。
4. 多个 plate / 多个 build item 的处理（Bambu 的打印文件常有多个盘）。

**注意**：3MF 是 3D 打印格式，和 PCB 没关系，走的是**独立模型**那条路径
（直接进 3D，不查模型库）。

---

## 4. 3D 视图的功能补齐

### 4.1 元件模型可拾取

**现状**：`render3d-models.js` 里 `beginElement(b, null)` —— 模型**不参与拾取**。
点元件没反应。

**要做的**：给模型建 element（`kind: 'model'`，带上 `items.models` 的下标），
然后在 `app.js` 的 `getSelectedElement()` 加分支，
详情面板显示：模型路径、offset/scale/rotate、所属封装、解析到的是哪个文件
（以及是否做了后缀替换）。

**收益**：这会是排查模型摆放问题最趁手的工具 —— 现在只能靠猜。

### 4.2 丝印文字

**现状**：`items.texts` 在 3D 里完全不画。板子看起来偏素。

**要做的**：二选一 ——

- 用 Canvas 2D 把已有渲染结果画到离屏 canvas，当作板子顶面的贴图（复用现有代码，但要有 UV 对齐）
- 把字体轮廓转成三角面（复杂，但更"真"）

第一种更省事，而且能顺带把走线/焊盘的颜色也带上去。

### 4.3 铜皮（zone）

**现状**：`zone` 完全不解析。有铺铜的板子在 3D 里看不到铜皮。

**要做的**：解析 `zone` 的 `polygon`/`filled_polygon`，按层挤出。

### 4.4 内层铜

**现状**：`In1.Cu` / `In2.Cu` 的走线已经解析出来（CM5IO 有 115 + 183 条），
但 `buildBoard` 里只处理 `F.Cu` / `B.Cu`，内层**不渲染**。

**要做的**：按层号在板厚方向分配 Z（叠层），内层铜画在板体内部，
配合"半透明板体"或者"剖切视图"才有意义 —— 需要先想清楚交互。

### 4.5 铜层圆弧

**现状**：`F.Cu`/`B.Cu` 上的 `arc` 元素（弯曲走线）不解析。
CM5IO 有 **32 条 F.Cu 圆弧 + 40 条 B.Cu 圆弧**，2D/3D 都缺这段。

**注意**：这和板框的 `gr_arc` 是**不同的元素**，结构也不同。

### 4.6 `gr_rect` / `gr_poly` 板框

**现状**：只解析 `gr_line` / `gr_arc` / `gr_circle`。
如果板框用 `gr_rect` 或 `gr_poly` 画，会串不成环 → 退化到包围盒。

---

## 5. 2D 视图的缺口

### 5.1 原理图元素选中

**现状**：`app.js` 里明确写着 `// TODO: 原理图元素选中暂未实现`，
非 PCB 类型直接清空选中。`parser-kicad_sch.js` 的 `describe()` 也只返回"暂未实现"。

**要做的**：给原理图元素（导线/符号/标签/节点）补 hit test 和 describe。
`render2d-hittest.js` 现在直接 `if (type !== 'pcb') return null`。

### 5.2 符号引脚位置没算

`parser-kicad_sch.js` 解析了 `lib_symbols` 里的引脚（位置、长度、角度），
但 `render2d-sch.js` 画引脚时用的是**引脚原点**，没有按 symbol 的 `mirror`/`unit`
做完整变换。有些符号的引脚会画歪。

---

## 6. 性能与内存

### 6.1 模型缓存的淘汰策略

`app.js` 的 `modelFileCache` 是**无上限**的 `Map`。
连续打开多个工程，内存会一直涨。

**要做的**：加 LRU 上限（比如 300MB 或 200 个模型），或者切换工程时清空。

### 6.2 大工程的首屏

CM5IO 实测（多次运行有波动）：解析 + 提取 **150–220ms**、建模 **130–155ms**、
**模型解析 1100–1200ms**。
PCB 本身没问题，**瓶颈全在模型**。6.1 和 1.2 是主要手段。

参考上限：官方库最大的 STEP 模型有 **67651 个实体**，最慢 **1019ms**
（`Samtec_FMC_ASP-134602-01_10x40_P1.27mm_Vertical`）。

### 6.3 拾取的规模化

现在拾取用"元素 AABB 粗筛 + 三角形求交"，实测中位 **0.06ms**、
最大 **1.33ms**（CM5IO，4973 个可拾取元素）。目前够用。

如果以后要支持**悬停高亮**（每次 mousemove 都拾取）或元素数量上万，
需要考虑 BVH 或 GPU 颜色拾取（`readPixels`）。

---

## 7. 工程质量

### 7.1 `stats` 字段没有统一契约

各 parser 产出的 `stats` 结构不同：

- STEP：`faces` / `planar` / `skipped` / `curveFallback` / `polyArea` / `triArea`
- WRL：`shapes` / `faceSets` / `polygons` / `materials` / `transforms`
- STL：`format` / `triangles` / `colored`

`app.js` 现在靠逐项判断来兼容打印日志。再加格式会更乱。
**建议**：定一个公共字段子集（`format` / `triangles` / `warnings`），
其余放 `stats.extra`。

### 7.2 `app.js` 1012 行了

它承担了：DOM 事件、2D/3D 模式状态机、选中与详情面板、
模型库 UI、拖拽、异步加载。可以拆成：

- `app-shell.js` —— DOM 查找、初始化、事件绑定
- `app-viewmode.js` —— 2D/3D 模式与相机
- `app-selection.js` —— 选中、详情面板、拾取
- `app-loading.js` —— 文件/URL/目录的加载流程

### 7.3 命名空间命名不统一

- 文件名：`render2d-*` / `render3d-*` / `parser-*` / `panel-*`
- 命名空间：`KiPreview.Viewport` / `HitTest` / `PcbRenderer` / `SchRenderer` /
  `Math3D` / `Camera3D` / `Mesh3D` / `Models3D` / `Pick3D` / `GlRenderer` /
  `ParserStep` / `ParserWrl` / `ParserStl` / `Parser3mf`

一半按文件名、一半按用途。要不要统一（比如 `Render2DViewport` / `Render3DWebgl`）
取决于你更看重"文件名可猜命名空间"还是"名字短"。

### 7.4 `(model ...)` 的 `scale` 没测过

实测的板子里 `scale` 全是 `1 1 1`，所以非均匀缩放的路径**从未被真实数据走过**。
法线变换目前直接用同一矩阵（因为线性映射是正交的）——
一旦有非均匀缩放，法线就需要**逆转置矩阵**了。这是个埋着的雷。

---

## 8. 测试

现在有 **15 个**测试脚本（13 个断言型 + 2 个扫描型），共 **226 项**断言，
但目前都在临时目录，需要固化进项目：

| 脚本 | 覆盖 | 项数 |
|---|---|---:|
| `droptest.js` | 拖拽（含 Mac 失效场景复现） | 13 |
| `libtest.js` | 模型库解析 + 真实几何装配 | 14 |
| `modeltest.js` | 变换链不变量 + 占位方块 | 12 |
| `stltest.js` | STL 语法 + 真实文件 | 14 |
| `wrltest.js` | WRL 语法 + 与 STEP 交叉验证 | 23 |
| `steptest.js` | STEP 语法 | 12 |
| `wrlcheck2.js` | STEP 尺寸 vs WRL 基准 | 12 |
| `test3d.js` | 几何 / 矩阵 / 相机 | 31 |
| `projtest.js` | 相机投影 | 8 |
| `picktest.js` | 3D 拾取 | 22 |
| `arctest.js` | 2D 圆弧选中 | 13 |
| `smoke.js` | 端到端（桩 DOM + 桩 WebGL） | 30 |
| `smokemodel.js` | 端到端（模型文件） | 22 |
| `stepscan.js` / `wrlscan.js` | 官方库鲁棒性扫描 | — |

**要做的**：

- 把这些脚本从临时目录搬进项目（比如 `test/`），加一个 `run-all` 入口
- 固化几条**独立基准**，防止回归：
  - STEP 尺寸 vs WRL 基准（现在 12/12）
  - 平面面**面积守恒**（现在官方库 105 个文件全 0.00% 偏差）
  - 模型库在 **STEP-only 库**下的命中率（现在 65/66，54 个靠后缀替换）
- 补充：背面封装镜像（等 0.2 有样本）
- 补充：非均匀 `scale`（见 7.4）

### 8.1 无头测试的盲区

测试跑在 Node 里，**WebGL 的实际画面从来没被验证过**。
投影数学、着色器编译、缓冲上传、drawArrays 调用链都验过，
但"看起来对不对"（配色、光照、朝向）只能靠人眼。

可以考虑引入 `headless-gl` 做像素级校验，但那就破坏"零依赖"了 ——
至少可以让 `smoke.js` 把关键矩阵和三角形数打出来，方便对照。

---

## 9. 杂项

- **`.gitignore`**：这个目录当前没有，如果会提交，至少要忽略 `.DS_Store`
- **README 截图**：现在 readme 里没有图，补两张（2D 板子 + 3D 带元件模型）会直观很多
- **键盘快捷键**：3D 视图可以加 `R` 复位视角、`1`/`2`/`3` 切换标准视角（顶/前/侧）
- **视角预设**：现在只有双击复位，没有"正上方看板"这种快捷视角
- **导出截图**：`canvas.toDataURL()` 就能存 PNG，值得加一个按钮
- **URL 输入框**：现在 URL 加载只在顶层支持，模型库的 HTTP 前缀还没接（见 1.5）
