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
| [`doc/3-object.md`](3-object.md) | **模块 3 · 对象块**：`NLINK`、copy-on-link、结构可插拔 |
| [`doc/4-file.md`](4-file.md) | **模块 4 · 文件**：四种模式（空 / 内联 / 直接指向 / 指向对象）+ 软链接 |
| [`doc/5-anchor.md`](5-anchor.md) | **模块 5 · anchor**：head / tail 字段表、一致性（I9）、挂载 |
| [`doc/6-bad.md`](6-bad.md) | **模块 6 · 坏块**：坏块标记、分配器如何永久排除它 |

> 标记约定：文档里带 **【将来方向】** 的字段 / 规则**在 v0 不实现** ✓。

---

## 代码

| 文件 | 内容 |
|---|---|
| [`python/easyfs.py`](../python/easyfs.py) | **核心 · 格式层**：块头、anchor、位图、目录、对象、文件、mkfs / fsck / resize |
| [`python/easyfs_device.py`](../python/easyfs_device.py) | **核心 · 设备层**：`FileDevice` / `RegionDevice` / `MemDevice` / VHD、分区表 |
| [`python/easyfs_config.py`](../python/easyfs_config.py) | **唯一常量源**：块类型、属性号、anchor tag 表 |
| [`python/tool.py`](../python/tool.py) | **工具入口**：按路径加载 `tool-*.py` 并本进程分发 |
| [`python/tool-ctrl.py`](../python/tool-ctrl.py) | 工具：离线控制 / 诊断：`mkfs` / `probe` / `device` / `df` / `fsck` / `inspect` / `optimize` / `migrate` / `resize` / `shell` / `mbr` / `gpt` |
| [`python/tool-vdisk.py`](../python/tool-vdisk.py) | 工具：**虚拟磁盘**：`.vhd` / `.vmdk` / `.dmg` / `.img` 的新建与详情 |
| [`python/tool-sftpcli.py`](../python/tool-sftpcli.py) | 工具：sftp 风格**本地**命令行 |
| [`python/tool-server.py`](../python/tool-server.py) | 工具：**HTTP / WebDAV-lite 网络服务器** |
| [`test/README.md`](../test/README.md) | **测试**：怎么跑、每个子测试的流程、资源纪律 |

Python 3.6+，只依赖标准库 ✓。`tool.py <名字> <参数>` 与 `tool-<名字>.py <参数>` 等价 ✓；
`tool.py` 认不出的名字会转给 `tool-ctrl` ⇒ **子命令可以直接当顶层命令用** ✓
（下面的例子都用这种简写 ✓；完整写法是 `tool.py ctrl mkfs …` ✓）。

### 几条常用命令

```bash
python3 python/tool.py help                                    # 有哪些工具
python3 python/tool.py mkfs --file disk.img --size 64M          # 建卷（文件当载体）
python3 python/tool.py df -h --file disk.img                    # 空间用量
python3 python/tool.py sftpcli --file disk.img                  # 像 sftp 那样用
python3 python/tool.py server --mem 64M --mkfs --port 8080      # 内存卷 + 网络访问
python3 python/tool.py vdisk --file disk.vmdk --create --size 64M   # 新建虚拟磁盘
python3 python/tool.py mbr --vdisk disk.img --part 1 --seteasy  # 给分区打上我们的标识
```

细节都在各自的 `--help` 与文档里 ✓：「卷放在哪」/ 分区标识 / 保护措施见 [`parttable.md`](parttable.md) ✓；
伸缩与分配见 [`1-alloc.md`](1-alloc.md) ✓；目录 / 文件 / 对象 / anchor 见各自模块文档 ✓。
