# EasyFS

极简、可移植、可双向伸缩的文件系统。同一份 4 KiB 块格式：先用 Python 在 x86 上跑通，
再往 ESP32 / STM32 / 裸机移植。载体可以是块设备、内存块，或文件里的一段区域 ——
只要求载体提供一件事：按偏移读、写、擦除。命令行像 sftp（`ls`/`cd`/`put`/`get`）。

> **先读 [`common.md`](common.md)**：坐标、通用 4K 块头、块类型总表、不变量。

---

## 文档索引

### 通用文档（`name.md`）

跨模块的约定、取舍与专题分析。

| 文档 | 内容 |
|---|---|
| [`doc/common.md`](common.md) | **公共约定**：坐标、通用 4K 块头、块类型总表、不变量 |
| [`doc/layout.md`](layout.md) | **卷布局**：区域几何、逻辑坐标 `L`、设备接口 |
| [`doc/parttable.md`](parttable.md) | **分区表与分区标识**：我们的 MBR `0x7F` / GPT `easyparteasypart`；`mbr` / `gpt` 怎么用；坐标怎么算 |
| [`doc/proscons.md`](proscons.md) | **pros / cons**：与 ext4 / XFS / Btrfs / ZFS / FAT / exFAT / NTFS / littlefs / SPIFFS 的对比 |
| [`doc/cow.md`](cow.md) | **COW / 对象形态**（设计）：要不要 COW 由运行参数决定 |
| [`doc/raid.md`](raid.md) | **RAID / 存储池**（初版 · 方向）|
| [`doc/memorymanage.md`](memorymanage.md) | **把 EasyFS 当内存管理用**（讨论记录）|

### 块类型文档（`num-name.md`）

与 `block_type` **一一对应**（总表见 [`common.md`](common.md)）：一种块 = 一篇。

| 文档 | 内容 |
|---|---|
| [`doc/0-null.md`](0-null.md) | **`block_type=0`**：无效 / 未初始化块 |
| [`doc/1-alloc.md`](1-alloc.md) | **模块 1 · 分配**：空闲位图、分配策略、提交、伸缩、扫描 |
| [`doc/2-dir.md`](2-dir.md) | **模块 2 · 目录**：目录块、TLV 属性、链、`PADn`、时间 |
| [`doc/3-link.md`](3-link.md) | **模块 3 · 链接块**：`NLINK`、copy-on-link、结构可插拔 |
| [`doc/4-file.md`](4-file.md) | **模块 4 · 文件**：四种模式（空 / 内联 / 直接指向 / 指向对象）+ 软链接 |
| [`doc/5-anchor.md`](5-anchor.md) | **模块 5 · anchor**：head / tail 字段表、一致性（I9）、挂载 |
| [`doc/6-bad.md`](6-bad.md) | **模块 6 · 坏块**：坏块标记、分配器如何永久排除它 |
---

## 历史

**已删除的设计 / 已解决的坑**不放在正文里 ✗（会干扰后续编码 ✓）⇒ 见本目录的 [`gotcha.md`](gotcha.md) ✓。

## 代码

代码分工、**实现现状**（哪些做了 / 哪些没做）、怎么跑、自检挂钩 ⇒
见 [`python/README.md`](../python/README.md) ✓；
怎么跑测试、每个子测试的流程、资源纪律 ⇒ 见 [`test/README.md`](../test/README.md) ✓。

`doc/` 里**只放设计层面**的东西 ✓：格式布局、字段语义、不变量、为什么这样设计、失败模式 ✓。
