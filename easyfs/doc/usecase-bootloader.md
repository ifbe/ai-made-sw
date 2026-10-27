# 引导盘：把 EasyFS 当 loader 的存储（usecase · bootloader）

> **使用场景文档**：讲「把 **loader 代码 / 相关数据**放进一个 EasyFS 卷」怎么设计 ✓ ——
> 角色上类似 "BIOS boot partition / EFI system partition"（装 loader 和它的数据）✓，
> 但 EasyFS **不能替代它们** ✗（原因见 §1）✓。
>
> 相关：[`medium-parttable.md`](medium-parttable.md)（分区标识）、[`5-anchor.md`](5-anchor.md)（anchor 字段与一致性）、
> [`4-file.md`](4-file.md)（内联 / 直接指向 / 对象形态）、[`2-dir.md`](2-dir.md)（TLV 属性、目录链）。

---

## 1. 能当什么、不能当什么

| 想用它当 | 能不能 | 原因 |
|---|---|---|
| **UEFI 的 ESP** | ✗ | UEFI 固件**只读 FAT** ⇒ ESP 必须是 FAT |
| **BIOS boot partition（raw 区）** | ✗ | 那是**裸扇区区**，没有文件系统；BIOS 按扇区读 |
| **loader 的数据卷**（本用例 ✓）| ✓ | 固件 / ROM 里的小代码**自己实现一个极小的只读解析器**（§3）|
| **MCU / 裸机的固件 + 配置卷** | ✓ | 只要载体能"按偏移读" —— 裸机本来就只读 |
| **多份内核 / 主题 / 字体 / 语言包** | ✓ | 一个卷装多个文件；小文件还能**内联** |

**一句话**：EasyFS 适合当「**loader 自己的数据盘**」，而不是「**固件内置的文件系统**」✗。

---

## 2. 三种部署形态

| 形态 | 谁读 | 怎么放 |
|---|---|---|
| **A. UEFI 应用 + 数据卷** | ESP 里的 `boot*.efi`（FAT）| 它打开**另一个分区**上的 EasyFS 卷，读 loader 资源 |
| **B. BIOS 引导 + stage-2 卷** | MBR 里的 446 B 引导代码（或一个 raw 引导分区）| 按**扇区**读 EasyFS 分区里的 stage-2 文件 |
| **C. MCU ROM + flash 卷** | ROM 里的 stage-1 | 直接在 flash 的某个区域上挂 EasyFS（载体 = flash 区域）|

---

## 3. loader 的最小读路径（不需要位图、不需要写）

1. 读 **`[0, 0x200)`**（anchor 的 header + 几何 + 状态）；
2. 校验 `magic = "easypart"` + `hdrcrc`（覆盖 `[0, 0x200)`）；
3. 取 `reglen`（卷长）、`dlolog`（数据区起点）、`chunk`；
4. 取 `roottype` / `rootioff`：
   * `roottype = 1` ⇒ `rootioff` 就是**第一个 dir 块**的卷内偏移（**推荐**）；
   * `roottype = 2` ⇒ 先读那个**链接块**，再取它的内容块表（多一跳；boot 场景不必要）；
5. 扫 dir 块链（每块：通用头 → `payload_len` → TLV 属性），逐条比 `NAME`；
6. 目标条目的内容属性：
   * `DATA_TINY` ⇒ **数据就在条目里**（≤255 B，最适合配置）；
   * `DATA_PTR` ⇒ 一个**直接指针**（1 jump，单块文件 ≤ 4096 B，即一个裸数据块）；
   * `DATA_OBJECT` ⇒ 再一跳（对象形态；boot 场景**不用**）。

**明确不需要**：位图、`allotype`、`stateflg` 的 clean 位、`fsck`、**任何写操作** ✓。

> 这一条是这个用例最大的好处：**读路径完全不碰位图** ⇒ 卷是 dirty 也能读 ✓。

---

## 4. 给 loader 的格式约定（强烈建议）

| 约定 | 为什么 |
|---|---|
| **`roottype = 1`（链式根）** | 少一跳；`rootioff` 直接是 dir 块 |
| 文件用 **`DATA_TINY` / `DATA_PTR`**，**不用**对象形态 | 少一跳；对象形态还要读链接块 + 表 |
| **一个文件一个块**（≤ 4096 B）| 单次读；不用处理"多段拼接" |
| 每个文件加一条 **`CRC32`** | loader 自己就能校验内容，不依赖 `fsck` |
| 名字**短、固定、全大写**（如 `STAGE2`）| 比较简单；避免大小写 / 编码问题 |
| 目录里**文件数少**（几十个）| 查找是 O(n) |
| **不依赖时间戳 / `NLINK` / 权限** | boot 路径用不到 |
| `mkfs` 之后**不要 resize** | 几何一变 loader 就要跟着处理；真要做就重刷 |

---

## 5. 卷的参数怎么选

* `chunk = 4096`（默认）；
* 分区大小：引导 + 数据卷常见 **1–16 MiB**，与 ESP 并存的数据卷 **16–512 MiB**，MCU 看 flash；
* `bit_unit` 粗粒度起步（小卷收益不大，但省元数据）；
* 卷内**不需要** swap / 日志 / 临时文件；
* anchor 的 **head 在卷内偏移 0** ⇒ 在盘上它位于**分区起点**。

---

## 6. 校验与信任链（分工写清）

| 层 | 谁负责 |
|---|---|
| 块是否**完整** | 块头 CRC + `hdrcrc`（EasyFS）|
| 文件内容是否**完整** | 条目上的 `CRC32` 属性（写方加、loader 验）|
| 文件是否**可信**（签名）| **loader 自己**（EasyFS 不提供签名）|
| 卷是不是**我们的** | `magic` + 我们自己的分区类型（[`medium-parttable.md`](medium-parttable.md)）|

> **I9（head / tail 一致）** 是给"正常挂载"用的；boot 路径**只读 head** 就够。
> 想防"半写"，可以顺手把 tail 也校验一遍（代价是再读一次）。

---

## 7. 不要依赖的语义

| 不要依赖 | 原因 |
|---|---|
| "挂载即只读、不会写盘" | 卷**脏**时正常挂载会**重建位图**（写）；boot 路径必须自己实现**只读** |
| ESP 的 FAT 语义 | 见 §1 |
| 目录排序 / 快速查找 | 链式扫描，O(n) |
| 大文件（超过单块） | 要处理多段拼接；boot 场景建议切小 |
| 权限 / 属主 | 格式里没有 |

---

## 8. 建议的文件约定（可复用的一套）

| 路径 | 用途 |
|---|---|
| `/STAGE2` | 第二级 loader（≤ 4096 B，`DATA_PTR`）|
| `/CONFIG` | 启动配置（`DATA_TINY`，纯文本）|
| `/KERNEL/*` | 多套内核 / 镜像（大文件可拆成多个）|
| `/ASSET/*` | 字体 / 主题 / 语言包 |

---

## 9. 待定项

1. 要不要给 loader 一个**固定偏移的"引导入口"**（anchor 里还有预留段，或直接约定 `/STAGE2`）；
2. 要不要给**引导卷**一个**专用分区类型**（区别于数据卷；现在共用 `0x7F` / 我们的 GUID）；
3. GPT 的"**不自动挂载**"属性位（bit 63）该不该给引导卷默认打开（[`medium-parttable.md`](medium-parttable.md) 里还是 TODO）；
4. 引导卷要不要**禁止** `resize` / `optimize`（保持几何稳定）；
5. MCU 形态的具体尺寸与"擦除粒度"约定（NOR 直写需要 batched 提交模式，见 [`1-alloc.md`](1-alloc.md) 的 commit 模式一节）。
