# 公共约定

> 所有模块文档共用的坐标约定、块容器、块类型和不变量。读其它文档前先读这一份。
>
> 目录结构见 [`doc/2-dir.md`](2-dir.md)；空闲空间管理见 [`doc/1-alloc.md`](1-alloc.md)。

---

## 1. 坐标

EasyFS 用**两套卷内坐标**，它们之间是线性、无间接的映射：物理侧用**自相对 delta**，逻辑侧用 **`L`**。

### 1.1 物理侧

| 术语 | 含义 |
|---|---|
| `chunk` | 分配单位，默认 4096 字节（anchor 里的 tag `chunk` 存 `chunk_shift`）；**v0 约束 `chunk ≤ 4096`**（见 [`detail-layout.md`](detail-layout.md)） |
| `data_lo` / `data_hi` | 数据区起点 / 终点 = `start + 4096` / `start + len - 4096` |
| **delta** | **有符号 64 位**，基准是「**存放这个 delta 的那个块的起点**」。`0` = 空（NULL），不允许自指 |
| 元数据块 | **dir / link / bad** 恒 4 KiB，带 64 字节通用块头；**位图块变长**（≥ 4 KiB，见 [`doc/1-alloc.md`](1-alloc.md)），头 = 64 B 通用头 + 32 B 位图扩展（还可预留到 `header_bytes`）；**anchor** 恒 4 KiB，但用 **tag 布局**（见 [`5-anchor.md`](5-anchor.md)），不套这 64 字节头 |
| 裸数据块 | 文件内容，**没有块头**，整块 4 KiB 都是数据 |

### 1.2 逻辑侧：`L`

anchor 里存一个 `data_lo_logical`（i64）= **数据区起点的逻辑坐标**：

```
L(P) = data_lo_logical + (P − data_lo) 物理 → 逻辑
P(L) = data_lo + (L − data_lo_logical) 逻辑 → 物理
```

**只存下界**：`data_hi_logical = data_lo_logical + (data_hi − data_lo)` 是派生值，不落盘
（理由与范围约束见 [`detail-layout.md`](detail-layout.md)）。

- `L` 是**卷内逻辑坐标**，不是设备地址，与设备偏移无关。
- `mkfs` 时可任取一个 `chunk` 对齐的整数（**默认 0**）—— 相当于给这个卷一个"编号起点"。
- **已有数据的 `L` 永不改变**：左扩/左缩 N 时 `data_lo` 与 `data_lo_logical` 同步 ∓N，两项抵消；
  右扩/右缩/整卷平移时两者都不动（或一起动）。详见 [`detail-layout.md`](detail-layout.md)。
- 例：`L ∈ [0, size)` 起步，向左扩 1 GiB 后变成 `L ∈ [−1G, size)`，老数据编号一个不变。
- 用途：位图块的 `region_logical_start`（[`1-alloc.md`](1-alloc.md)）、
  目录属性 `DATA_OBJECT`（[`2-dir.md`](2-dir.md)）。

### 1.3 不含绝对地址

**格式内不含设备绝对地址**，只有两类卷内坐标：**自相对 delta** 和**逻辑坐标 `L`**。
因此把整个卷 memmove 到别处，元数据一个字都不用改 —— 连空闲位图也是：每个位图块用 `region_delta`
自描述它管理的那片区域（见 [`1-alloc.md`](1-alloc.md)），块和它管的区域一起搬，delta 不变。

---

## 2. 通用 4K 元数据块头（64 字节，小端）

| off | size | 字段 | 说明 |
|---|---|---|---|
| 0 | 8 | `magic` | **每类一个独立词**（共同前缀 `easy` ⇒ "是不是我们的块"一次前缀比较 ✓）；取值见 §3 的魔数表；`null` 不给、`file-data` 没有头 |
| 8 | 2 | `block_type` | 见 §3 |
| 10 | 2 | `version` | 格式版本 |
| 12 | 4 | `flags` | bit0 = `payload_crc32` 有效；bit1 = 链尾；bit2 保留（**pool 段由 `easypool` tag 判定**，见 [`5-anchor.md`](5-anchor.md)）；其余保留 |
| 16 | 8 | `prev_delta` | i64 自相对；0 = 无 |
| 24 | 8 | `next_delta` | i64 自相对；0 = 无 |
| 32 | 8 | `seq` | 同一条链内单调递增（允许空洞，用于断链检测） |
| 40 | 4 | `payload_len` | 类型专属区实际使用的字节数。dir / link 的载荷 ≤ 4032；位图块 = `block_bytes − header_bytes`；anchor 的 `payload_len = 0` |
| 44 | 4 | `payload_crc32` | 载荷 CRC（可选，由 flags.bit0 控制；位图块暂不启用） |
| 48 | 4 | `header_crc32` | **头部** CRC，覆盖 `[0, header_bytes)`（本字段按 0 计算）：dir / link / bad = 64 B；位图块 = `header_bytes`（≥ 96，含 32 B 类型扩展）；**anchor 的对应物是 tag `hdrcrc`**（覆盖 `[0,0x200)`，见 [`5-anchor.md`](5-anchor.md)） |
| 52 | 4 | `header_bytes` | **类型专属区起点**：dir / link / bad = 64；位图块 ≥ 96；**anchor 的对应物是 tag `hdrbytes` = `0x200`**（tag 布局，见 [`5-anchor.md`](5-anchor.md)） |
| 56 | 4 | `refcount` | **块级**引用计数（u32）。**v0 里必须为 0**（先把布局占住）；只对"**有 64 B 头、且可能被多重引用**"的块有意义（将来的目录块 ✓ / 共享的映射块 ✓）；**链接块的名字计数用 `NLINK` 属性**（见 [`3-link.md`](3-link.md)），不是这个字段；**裸数据块没有头 ⇒ 不适用**（靠可达性 + 延迟释放，见 [`feature-cow.md`](feature-cow.md)）|
| 60 | 4 | `owner_gen` | 该块的**出生世代**（u32，**v0 里必须为 0**）。将来配 COW/快照做"延迟释放"用（对应 ZFS 的 birth txg）|
| 64 | — | 类型专属区 | 从偏移 64 开始；位图块从 `header_bytes` 开始，长度由 `block_bytes` 决定 |

> **anchor 是例外**：它不套上表这 64 字节的头，而是 8 字节 tag 流（见 [`5-anchor.md`](5-anchor.md)）——
> 块类型 / 版本 / CRC / 状态分别在 tag `blktype ` / `easypart` 的版本串 / `hdrcrc` / `stateflg` 里。

**属性 vs 头**（判据）：TLV 属性是**条目 / 对象**的属性（`NAME` / `DATA_PTR` / `TMODIFY` …）；**通用头是"块自己"的属性** ✓ ⇒ **块级**计数（"这个块被引用几次"）一律放头里的 `refcount` ✓，**不要塞进 TLV** ✗。
CRC 算法：CRC-32/IEEE（与 Python `zlib.crc32` 一致）。

---

## 3. 块类型

块类型与文档**一一对应**（一种块 = 一个 `num-name.md`）：

| `block_type` | 名称 | 文档 | 载荷 / 说明 |
|---|---|---|---|
| **0** | `null` | [`0-null.md`](0-null.md) | **无效 / 未初始化**：写入方永不产出，读到一律当损坏 |
| **1** | `alloc` | [`1-alloc.md`](1-alloc.md) | 空闲位图（64 B 通用头 + 32 B 位图扩展）|
| **2** | `dir` | [`2-dir.md`](2-dir.md) | 属性流（目录条目）|
| **3** | `link` | [`3-link.md`](3-link.md) | **链接块**（`NLINK` + 时间 + 文件位置；硬链接共享 / COW 的提交点）|
| **4** | `file-data` | [`4-file.md`](4-file.md) | **文件数据 —— 裸块，没有块头**，所以盘上永远不会出现 `type=4` 这个字节 |
| **5** | `anchor` | [`5-anchor.md`](5-anchor.md) | head / tail anchor（**tag 布局**：卷头 `[0,0x200)` 由 `hdrcrc` 保护 + 可选 pool 段 `[0x200,0x3d0)` 由 `poolcrc` 保护；`[0x3d0,0x1000)` 留空）【pool 段是将来方向，见 [`feature-raid.md`](feature-raid.md)】|
| **6** | `bad` | [`6-bad.md`](6-bad.md) | 坏块标记 |
| 7–255 | 保留 | — | rsvd：将来可能分配 |
**块头魔数**（每类一个独立词 ✓；补到 8 字节用**尾部空格**，与 tag 名同一约定 ✓）：

| `block_type` | magic | 备注 |
|---|---|---|
| 0 `null` | **（无）** | 写入方永不产出；读到全零 magic 就当"未初始化" ✓ |
| 1 `alloc` | `easyallc` | |
| 2 `dir` | `easydir ` | 尾部空格补到 8 字节 ✓ |
| 3 `link` | `easylink` | |
| 4 `file-data` | **（裸块，没有头）** | 只能靠**父指针**认它 ✓ |
| 5 `anchor` | `easypart` | 卷 / 分区这一层的标记（**不变** ✓）|
| 6 `bad` | `easybad ` | 离线检查写 ✓ |
| 7–255 | 保留 | — |
**裸数据块没有块头，也没有 `block_type`**（上表里的 `4` 只是模块编号，不是盘上的值）。

---

## 4. 不变量

| # | 不变量 |
|---|---|
| I1 | 卷内坐标只有两类：**自相对 i64 delta** 与**逻辑坐标 `L`**。格式内不含设备绝对地址 |
| I2 | 元数据块的 `header_crc32` 必须校验（覆盖 `[0, header_bytes)`；**anchor 的对应物是 tag `hdrcrc`**，覆盖卷头 `[0,0x200)`）；载荷 CRC 可选（**dir / link 必须启用**） |
| I3 | 空闲位图是**派生数据**：恒等于「从根可达的块集合 **∪ 已知 bad 块 ∪ 位图链自身**」的补集，任何时候都能全量重建（区域布局是权威元数据，不是"派生"的部分）；有保留世代时改成「**从所有保留世代都不可达**」（**bad 块 / 位图链仍恒占用**，见 [`feature-snapshot.md`](feature-snapshot.md)） |
| I4 | 写顺序：**先占位后引用，先解引用后释放** |
| I5 | 没有任何持久指针指向 anchor → anchor 可以自由搬家（这是双向伸缩便宜的前提） |
| I6 | 目录块载荷紧凑（属性之间**没有隐式填充**）；`PADn` / `PAD1` 是**显式占位**、不属于任何条目；**NAME 属性是条目的分隔符** |
| I7 | 位图链的**同层**区域首尾相接、无洞无重叠；**子区域**落在父区域的**若干完整单位**内（不占半格）；**叶区域**的并集 = `[data_lo, data_hi)`（分层说法 = I7′，见 [`1-alloc.md`](1-alloc.md) 的混合粒度一节）|
| I8 | `L` 与物理地址在数据区内是**一一映射、差为常量**：`L(P₁) − L(P₂) = P₁ − P₂`；`data_lo_logical` 必须按 `chunk_size` 对齐 |
| I9 | head / tail anchor **每次提交都要写、两份必须一致**：非 delta 字段逐一相等，delta 字段**解算成绝对地址后**相等（`peer_delta` 例外）。**不一致 ⇒ `ESTALE` 拒绝**，不许猜（[`5-anchor.md`](5-anchor.md)）|
