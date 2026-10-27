# 卷布局

> 区域几何、数据区的逻辑坐标 `L`、设备接口。**anchor 的字段表与挂载 / 发现流程**见
> [`5-anchor.md`](5-anchor.md)；坐标约定见 [`detail-common.md`](detail-common.md)；
> 位图见 [`1-alloc.md`](1-alloc.md)；目录与属性见 [`2-dir.md`](2-dir.md)。

---

## 1. 区域几何

```
区域 = [start, start + region_len) start / region_len 由调用方给出
┌──────────────────────────────┐ ← start
│ head anchor   4 KiB          │
├──────────────────────────────┤ ← data_lo = start + 4096
│ 数据区（可分配）              │
├──────────────────────────────┤ ← data_hi = start + region_len − 4096
│ tail anchor   4 KiB          │
└──────────────────────────────┘ ← start + region_len
```

- `data_lo = start + 4096`，`data_hi = start + region_len − 4096`，**恒为 4096 的整数倍**。
- **约束**：
  - `region_len` 必须是 `chunk_size` 的整数倍；
  - **`chunk_size ≤ 4096`** —— 否则 `data_lo = start + 4096` 不是 `chunk_size` 的整数倍，chunk 与物理地址的对齐关系被破坏。
- 调用方（CLI / 后端）负责把 `[start, region_len)` 映射到设备：块设备偏移、容器文件内偏移、或内存块。

---

## 2. anchor 块（`block_type = 5`）

> **本节内容已搬到 [`5-anchor.md`](5-anchor.md)**（字段表、head/tail 一致性 I9）。
> 节号保留，便于已有引用继续可用。

## 3. 挂载 / 发现流程

> **本节内容已搬到 [`5-anchor.md`](5-anchor.md)**（读 head/tail、I9/I7′ 检查、尺寸守卫）。

## 4. 数据区的逻辑坐标 `L`

```
L(P) = data_lo_logical + (P − data_lo)
P(L) = data_lo + (L − data_lo_logical)
```

- `data_lo_logical` 由 `mkfs` 指定，**可以是任意 `chunk_size` 对齐的整数，默认 0**
  （相当于给这个卷一个"编号起点"；换个值只是换个起点，不影响任何行为）。
- **只存 `data_lo_logical`，不存 `data_hi_logical`**：上界是派生值
  `data_hi_logical = data_lo_logical + (data_hi − data_lo)`。存了就有第二个真相来源，
  而下面 6 种操作里它都能自动算对，没有什么需要它来校验（head/tail 一致性比的是
  `region_len` + `data_lo_logical`，不含上界）。

  > 对比：位图块的 `region_logical_start`（[`1-alloc.md`](1-alloc.md)）**是**存了的，
  > 那属于**故意冗余** —— 为了"每块自描述"以及 fsck 的双向校验
  > （`block_addr + region_delta == data_lo + (region_logical_start − data_lo_logical)`，
  > [`1-alloc.md`](1-alloc.md)）。`data_hi_logical` 连这个价值都没有，所以不存。

- **范围约束**：`L` 是 `i64`，所以 `data_lo_logical` **和派生出来的 `data_hi_logical`**
  都必须落在 `i64` 内。`mkfs` / 挂载都会用 `EINVAL` 拒绝越界（不要指望靠"不存上界"
  绕过去——越界的 `L` 会在写 `region_logical_start` 之类的字段时炸在 `struct` 层）。
- **已有数据的 `L` 永不改变**：

| 操作 | `data_lo` | `data_lo_logical` | 已有数据的 `L` | 新空间 |
|---|---|---|---|---|
| mkfs | D | 取值 R（默认 0） | — | `[R, R+size)` |
| 向右扩 N | 不变 | 不变 | 不变 | `[hi, hi+N)` |
| **向左扩 N** | −N | **−N** | **不变** | **`[lo−N, lo)`** |
| 向右缩 N | 不变 | 不变 | 不变 | 丢掉最高的 N |
| 向左缩 N | +N | **+N** | **不变** | 丢掉最低的 N |
| 整卷平移 Δ | +Δ | 不变 | 不变 | — |

  上界也跟着走：右扩把 `data_hi_logical` 往上顶，左扩把它留着不动、把 `data_lo_logical` 往下拽。

- 例：`R = 0`、初始数据区 `L ∈ [0, 1 GiB)`；向左扩 1 GiB 后 `L ∈ [−1 GiB, 1 GiB)`，
  老数据一个编号都不变，新空间拿到负数编号。
- **用途**：位图块的 `region_logical_start`（它管的区域的 L 起点，见 [`1-alloc.md`](1-alloc.md)）
  和目录属性 `DATA_OBJECT`（按 L 引用文件数据，见 [`2-dir.md`](2-dir.md)）。

---

## 5. 伸缩

> **本节内容已搬到 [`5-anchor.md`](5-anchor.md)**（扩容/缩容对 anchor 的规则）。

## 6. 设备接口

格式层**只要求载体提供五件事**：

| 成员 | 语义 |
|---|---|
| `size` | 可寻址字节数（= `region_len`） |
| `read_at(off, n)` | 读 `[off, off+n)`，**必须返回恰好 n 字节**（短读视为 `EIO`） |
| `write_at(off, data)` | 写 `[off, off+len(data))`，**必须整段生效**（不要求原子） |
| `flush()` | 尽最大努力落盘（`fsync` / 等待写完成） |
| `close()` | 释放句柄 |

要点：

* **只按偏移读写，没有"块号"**：所有坐标都是 `[0, region_len)` 里的字节偏移（§1）。
  换载体不需要改格式层一个字节 —— 这正是"卷内不含绝对地址"（[`detail-common.md`](detail-common.md)）
  在宿主侧的对应物。
* **不要求"块设备"语义**：扇区大小、对齐、擦除粒度都由**后端**负责，格式层只认字节。
  所以同一个格式既能放在 `/dev/sdaX`、也能放在镜像文件的一段、还能放在 RAM 里。
* **写不要求原子**：所有崩溃安全性靠 [`1-alloc.md`](1-alloc.md) 的写顺序 + dirty 重建，
  不依赖设备的原子写（4 KiB 目录块是"提交点"，但那说的是**逻辑**提交点，不是硬件原子性）。
* 已提供的实现：`FileDevice`（整文件）、`RegionDevice`（文件里的一段 / 分区）、
  `MemDevice`（内存）、`VhdDevice`（`.vhd`，fixed + dynamic，块按需分配）、
  `VmdkDevice`（`.vmdk`，单文件稀疏）。
  另有按内容识别容器（raw / vhd）与 MBR / GPT 分区解析。
* **裸机上要把这一层换掉**：例如 NOR flash 需要"读改写 + 擦除 + 磨损均衡"，
  NAND 需要坏块管理与 ECC。这些都在设备层之下，格式层不感知。
