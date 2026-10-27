# EasyFS

极简、可移植、可双向伸缩的文件系统。同一份 4 KiB 块格式：先用 Python 在 x86 上跑通，
再往 ESP32 / STM32 / 裸机移植。载体可以是块设备、内存块，或文件里的一段区域 ——
只要求载体能按偏移读、写（擦除 / 磨损均衡都在设备层之下）。命令行像 sftp（`ls`/`cd`/`put`/`get`）。

> **先读 [`detail-common.md`](detail-common.md)**：坐标、通用 4K 块头、块类型总表、不变量。

---

## 文档索引

按**六类**组织 ✓（先设计、后周边 ✓）：

1. **卷格式（`detail-*`）** —— 卷内的一切：坐标、块头、布局、不变量
2. **块类型（`num-name`）** —— 一种块一篇，与 `block_type` 一一对应
3. **功能（`feature-*`）** —— 我们提供的能力：要不要开、怎么开、代价
4. **使用场景（`usecase-*`）** —— 拿它来干什么：能当什么 / 不能当什么
5. **载体与分区（`medium-*`）** —— 盘是什么、卷放在哪，不属于卷格式
6. **其他** —— 对比、评估、术语、性能、移植之类

带前缀的文件名就是分类（`detail-*` / `feature-*` / `usecase-*` / `medium-*` / `num-name`（数字-名称））✓；
其余用无前缀的名字 ✓。

### 卷格式（`detail-*`：文件系统细节）

卷内的一切：坐标、通用块头、区域布局、不变量。

| 文档 | 内容 |
|---|---|
| [`doc/detail-common.md`](detail-common.md) | **公共约定**：坐标、通用 4K 块头、块类型总表、不变量 |
| [`doc/detail-layout.md`](detail-layout.md) | **卷布局**：区域几何、逻辑坐标 `L`、设备接口 |
| [`doc/detail-fsck.md`](detail-fsck.md) | **校验规范**：检查项清单（块头 / anchor / 分配 / 目录 / 文件 / 可达性 / 快照）、严重性分级（FATAL / ERROR / WARN）、修复策略 |

### 块类型文档（`num-name.md`）

与 `block_type` **一一对应**（总表见 [`detail-common.md`](detail-common.md)）：一种块 = 一篇。

| 文档 | 内容 |
|---|---|
| [`doc/0-null.md`](0-null.md) | **`block_type=0`**：无效 / 未初始化块 |
| [`doc/1-alloc.md`](1-alloc.md) | **模块 1 · 分配**：空闲位图、分配策略、提交、伸缩、扫描 |
| [`doc/2-dir.md`](2-dir.md) | **模块 2 · 目录**：目录块、TLV 属性、链、`PADn`、时间 |
| [`doc/3-link.md`](3-link.md) | **模块 3 · 链接块**：`NLINK`、copy-on-link、结构可插拔 |
| [`doc/4-file.md`](4-file.md) | **模块 4 · 文件**：四种模式（空 / 内联 / 直接指向 / 指向对象）+ 软链接 |
| [`doc/5-anchor.md`](5-anchor.md) | **模块 5 · anchor**：head / tail 字段表、一致性（I9）、挂载 |
| [`doc/6-bad.md`](6-bad.md) | **模块 6 · 坏块**：坏块标记、分配器如何永久排除它 |

### 功能文档（`feature-*.md`）

我们**提供的能力** —— 每篇讲一个特性：要不要开、怎么开、代价是什么。

| 文档 | 内容 |
|---|---|
| [`doc/feature-cow.md`](feature-cow.md) | **COW / 对象形态**（设计）：要不要 COW 由运行参数决定 |
| [`doc/feature-snapshot.md`](feature-snapshot.md) | **快照**（设计）：多世代根、根表住根链接块、延迟释放、存活判定、不变量 |
| [`doc/feature-raid.md`](feature-raid.md) | **RAID / 存储池**（初版 · 方向）|

### 使用场景文档（`usecase-*.md`）

拿 EasyFS 来**干什么** —— 每篇讲：能当什么 / 不能当什么、怎么集成、边界在哪。

| 文档 | 内容 |
|---|---|
| [`doc/usecase-memorymanage.md`](usecase-memorymanage.md) | **把 EasyFS 当内存管理用**（使用场景）|
| [`doc/usecase-database.md`](usecase-database.md) | **把 EasyFS 当数据库存储引擎用**（使用场景：提交点、页文件、影子文件、概念对照）|
| [`doc/usecase-bootloader.md`](usecase-bootloader.md) | **把 EasyFS 当 loader 的存储**（使用场景：loader 最小读路径、引导卷约定）|

### 载体与分区（`medium-*`）

**卷之外的那一层**：盘是什么（内存 / 文件 / 虚拟磁盘）、卷放在哪（分区表）—— 都不属于卷格式。

| 文档 | 内容 |
|---|---|
| [`doc/medium-parttable.md`](medium-parttable.md) | **分区表与分区标识**：我们的 MBR `0x7F` / GPT `easyparteasypart`；卷放在哪 / 坐标怎么算（命令见 [`python/README.md`](../python/README.md)） |
| [`doc/medium-virtualdisk.md`](medium-virtualdisk.md) | **虚拟磁盘**：`.img` / `.vhd` / `.vmdk` / `.dmg`；怎么当盘、怎么带分区表、稀疏与边界 |
| [`doc/medium-memdisk.md`](medium-memdisk.md) | **内存盘**：把卷放在内存里；用途、语义与边界、与其它载体对比 |

### 其他

**不属于以上任何一类**的东西：对比、评估、术语、性能、移植之类 ✓。

| 文档 | 内容 |
|---|---|
| [`doc/proscons.md`](proscons.md) | **pros / cons**：与 ext4 / XFS / Btrfs / ZFS / FAT / exFAT / NTFS / littlefs / SPIFFS 的对比 |

## 代码

代码分工、**实现现状**（哪些做了 / 哪些没做）、怎么跑、自检挂钩 ⇒
见 [`python/README.md`](../python/README.md) ✓；
**写代码踩过的坑** ⇒ 见 [`python/gotcha.md`](../python/gotcha.md) ✓；
怎么跑测试、每个子测试的流程、资源纪律 ⇒ 见 [`test/README.md`](../test/README.md) ✓。

`doc/` 里**只放设计层面**的东西 ✓：格式布局、字段语义、不变量、为什么这样设计、失败模式 ✓。
