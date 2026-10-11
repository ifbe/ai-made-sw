# 分区表与分区标识

> 状态：**已落地** ✓ —— 解析 / 写入在 `python/easyfs_device.py`，命令是 `tool mbr` / `tool gpt`。
> 相关：[`README.md`](README.md)（工具用法一览）、[`layout.md`](layout.md)（区域几何、设备接口）。

---

## 1. 我们的分区标识

| 表 | 值 |
|---|---|
| **MBR** | **`0x7F`** —— 类型名表里未列出 ⇒ 工具显示 `Unknown` ✓，不会被当成 ext4 / FAT 去试探挂载 ✓ |
| **GPT** | 盘上 16 字节 ASCII **`easyparteasypart`** ✓（规范串 `79736165-6170-7472-6561-737970617274`）|

规范串看不出是 ASCII，是因为 GPT 按 UEFI 规则**前三段存小端** ✓：

```
盘上（16 字节）: 65 61 73 79 70 61 72 74 65 61 73 79 70 61 72 74
                 e  a  s  y  p  a  r  t  e  a  s  y  p  a  r  t    ← "easyparteasypart" ✓

规范串        : 79736165-6170-7472-6561-737970617274
                 └─LE──┘ └LE┘ └LE┘ └BE┘ └───BE────┘
                 time_low  mid   hi   seq     node
```

（同样的玩法：BIOS boot 分区 = `Hah!IdontNeedEFI` → `21686148-6449-6E6F-744E-656564454649` ✓）
想让**人眼**一眼认出，靠分区名 `EasyFS` ✓（GPT 有名字字段 ✓，`lsblk` / `gdisk` 会显示 ✓）。

> 别用 `0x83` 或通用 Linux 文件系统 GUID ✗ —— 那会被别人（自动挂载、探测）当成通用 Linux
> 文件系统去试 ✓。

## 2. 命令

看 / 改合一 ✓：**不给 `--seteasy` 就只列出**（只读 ✓，并标出哪个"已经是我们的标识" ✓）；
**给 `--seteasy` 才改** ✓ —— **只动分区表，不碰任何数据** ✓。

```bash
python3 python/tool.py mbr --vdisk disk.img --part 1 --seteasy
python3 python/tool.py gpt --vdisk disk.img --part 1 --seteasy
python3 python/tool.py gpt --disk /dev/sdX --part 3 --seteasy          # 真盘：先打印盘信息，再问 [y/N]
python3 python/tool.py gpt --disk /dev/sdX --part 3 --seteasy --yes    # 脚本里免问
```

```
$ tool.py mbr --vdisk a.img --part 1 --seteasy
   MBR 分区 #1：类型 0x0C → 0x7F（我们的标识）
复核          分区 #1 类型 = 0x7F ✓

$ tool.py gpt --vdisk b.img --part 1 --seteasy
   GPT 分区 #1：类型 0FC63DAF-8483-4772-8E79-3D69D8477DE4 → 79736165-6170-7472-6561-737970617274
复核          主/备 GPT 自洽 ✓
```

**建表**（`--create` ✓）：在**空容器**上建一张表 + **一个占满的分区** ✓ —— 分区类型**直接写成
我们的标识** ✓（所以对新建的分区不用再 `--seteasy` ✓；`--seteasy` 是给**已有**分区用的 ✓）：

```bash
python3 python/tool.py vdisk --file disk.vmdk --create --size 64M   # ① 建虚拟磁盘
python3 python/tool.py gpt   --vdisk disk.vmdk --create             # ② 建 GPT 表 + 分区（类型 = 我们的）
python3 python/tool.py mkfs  --vdisk disk.vmdk --part 1             # ③ 在分区里建卷
```

* 容器里**已经有分区表 / 已经是我们的卷 / 开头不是空的** ⇒ `--create` **拒绝** ✓
  （要重建得显式 `--force` ✓）；
* `--offs` / `--size` 指定分区位置与大小 ✓（默认 **1 MiB** 起、到容器末尾 ✓）；`--part` 指定写第几个项 ✓；
* 真盘（`--disk`）先打印盘信息，**再问 `[y/N]`** ✓ —— 可写句柄是**问完才打开**的 ✓；
  * `--create` 会**重建整张分区表** ⇒ 确认语就是这句 ✓，而且**挂载中直接拒** ✓（要 `--force` ✓）；
  * `--seteasy` 只改类型 ⇒ 确认语是"只改分区类型，不动任何数据" ✓，挂载中也允许 ✓；
  * **只读命令**（`probe` / `df` / `fsck -n` / `inspect` / `device`）**不问** ✓；
* **`resize` 也一样会问** ✓ —— 不分载体（`--file` / `--vdisk` / `--disk` 都问 ✓，`--yes` 免问 ✓，
  `--dry-run` 不问 ✓ 因为它不写盘）；
* **`resize` 的"改前位置"可以用 `--part N`** ✓ 代替 `--offs/--size`（旧几何 = 那个分区的范围 ✓，
  新几何仍然用 `--newoffs/--newsize` ✓）；两者**不能混用** ✓。它只借分区的几何，**不动分区表** ✓。
* 真盘上的三步（每条都会问 ✓，脚本里加 `--yes` ✓）：`mbr --disk /dev/sdX --create` ⇒
  `mbr --disk /dev/sdX --part 1 --seteasy`（新建的分区已经是我们的标识 ✓ 这步可省）⇒
  `mkfs --disk /dev/sdX --part 1` ✓。
* **`vdisk` 没有 `--disk`** ✓ —— 它建的是**文件** ✓；物理盘不需要"新建" ✓。

**GPT 一次改动要写四处** ✓（否则主备不一致）：

| # | 写什么 |
|---|---|
| 1 | 主项数组里那一项的 16 字节类型 GUID ✓ |
| 2 | 主头的 `partition_entry_array_crc32` ✓ |
| 3 | 主头的 `header_crc32`（CRC 字段按 0 算 ✓）|
| 4 | 备份项数组 + 备份头 CRC ✓ |

写后自检 `verify_gpt()` ✓（主头 CRC / 备份头 CRC / 两份数组一致 ✓）。
形态不匹配直接拒 ✓：拿 `mbr --seteasy` 去改 GPT ⇒
`error: 这是 GPT 分区表，不是 MBR（用 gpt --seteasy）` ✓。

## 3. 「卷放在哪」与坐标怎么算

**四种载体**（四选一）：

| 载体 | 用途 | 说明 |
|---|---|---|
| `--file <路径>` | 普通文件；**也可以直接给分区设备节点**（如 `/dev/sda1`）| 整段就是卷；块设备容量由内核读（ioctl ✓，**绝不 truncate** ✓）|
| `--vdisk <镜像>` | `.img` / `.vhd`，**自动解析分区表** | 配 `--part N` 选分区 |
| `--mem <大小>` | 内存卷（演示 / 测试）| 不落盘 |
| `--disk <块设备>` | **真实磁盘**（如 `/dev/sda`）| 危险目标 ⇒ 见下一节 |

**新建容器**（`tool vdisk` ✓）：`.vhd`（动态 ✓ / 加 `--fixed` 固定 ✓）、`.vmdk`（单文件稀疏 ✓）、
`.dmg`（UDIF 未压缩 ✓）、`.img` / `.raw`（裸文件 ✓）——
**格式由后缀决定** ✓；不加 `--create` 就只显示详情 ✓（什么都不改 ✓）。

```bash
python3 python/tool.py vdisk --file disk.vmdk --create --size 64M   # 建
python3 python/tool.py vdisk --file disk.vmdk                       # 只看详情
```

`.vhd` / `.vmdk` / `.img` **都能当卷载体** ✓；**`.dmg` 只能建 / 看详情** ✗（UDIF 包，
`--vdisk` 会明确拒绝 ✓）。`.vmdk` 是单文件稀疏盘 ✓（64 MiB 空盘只占 ~5 KiB ✓）。

**不给区域时的规则** ✓：盘上**只有 1 个分区** ⇒ 自动选它 ✓；**多个分区** ⇒ **拒绝**并把分区表列出来
（不替你猜 ✓，更不会把分区表当垃圾吃掉 ✗）；**没有分区表** ⇒ 按整盘 ✓；要**明确**把带分区表的整盘
当卷 ⇒ 显式写 `--offs 0` ✓。`--part` 与 `--offs/--size` **互斥**（混用报错 ✓）。

**偏移是自动加的** ✓：`--part N` 会用分区的 `start / length` 包一层 `RegionDevice` ✓，它的 `read_at(off)` 就是
`dev.read_at(offset + off)` ✓ ⇒ 之后**所有** `--block` / `--path` / `--offs` 都是**卷内坐标** ✓。
`mkfs` 打印的 `anchor head @0` 是**卷内偏移 0** ✓ —— 在盘上它位于分区起点（例如绝对 1048576 ✓）。

反过来，**卷内不含任何绝对地址** ✓ ⇒ **卷不知道自己放在哪** ✓：把卷（连同分区）平移、或改分区表里的
起始扇区，**卷里一个字节都不用改** ✓，只要告诉工具新位置 ✓。

> `resize` **不接受 `--part`** ✓ ⇒ 扩缩真机分区内的卷：用 `--file /dev/sda1`（相对分区 ✓），
> 或自己把两个几何的绝对偏移算好 ✓。

## 4. 保护措施

**`--disk` 的三道保护**（改真实盘之前）：

1. **先亮出这个盘是什么** ✓ —— 设备名 / 容量 / 型号 / 厂商 / 序列 / 可移动 / 逻辑·物理扇区 /
   整盘还是分区 / **挂载在哪** / **`/` 是否就在这盘上**；
2. **拒绝危险目标** ✓ —— 这个盘（含它的分区）**正被挂载** ⇒ 拒绝；**根文件系统就在这盘上** ⇒ 拒绝；
   两者都要显式 `--force` 才越得过；
3. **要人确认** ✓ —— 打印"会销毁该盘上的全部分区表与数据"，然后问 `继续吗？[y/N]`（**回车 = 取消** ✓）；
   非交互环境**不给 `--yes` 就直接拒绝** ✓。

命令行给了 **`--yes`** ⇒ **不问你、直接继续** ✓（脚本 / 无人值守用 ✓）；它**不越过**第 2 条的危险拒绝 ✓（那要 `--force` ✓）。只读命令
（`probe` / `df` / `fsck -n` / `inspect` / `device`）**只打信息、不要求确认** ✓。

`mbr` / `gpt` 有**两处不同** ✓：

* `mbr` / `gpt` **只改分区类型、不动数据** ✓ ⇒ **挂载中也允许** ✓（只提示"正被挂载" ✓）；
* 它们是**会写盘的命令** ⇒ `--yes` / `--force` 由命令自己带 ✓（`tool-sftpcli` 的 `--force` 另有所指：
  覆盖已存在的远端文件 ✓ ⇒ 那个工具跑 `--disk` 时永远会问 ✓）。

## 5. 实现边界（现状）

| 事 | 现状 |
|---|---|
| 解析 | MBR 主分区（4 项）+ GPT ✓；**扩展分区只报告、不展开** ✗ |
| 写入 | 只改**已有**分区的**类型** ✓；不建分区 / 不删分区 / 不改大小 ✗ |
| GPT | 主项数组 + 主头 CRC + 备份项数组 + 备份头 CRC，**四处一起改** ✓ |
| 端序 | MBR 分区项**小端** ✓；**VHD 头是大端**（两码事 ✗）；GPT 混合端序 ✓ |
| 真机 | 三道保护 + 确认都有 ✓；**端到端（真 U 盘）尚未实测** ✗ |

## 6. 待定项

1. 目前只有"看 + `--seteasy`" ✓ —— 将来可加 `--new` / `--del` / `--resize` ✗；
   写分区表（不只是改类型）更危险 ⇒ 那类子命令要单独设计保护；
2. **扩展分区**（MBR 逻辑分区链）还没展开 ✗；
3. `0x7F` 是私有值 ✓ —— 撞车就改常量 `MBR_TYPE_EASYFS` ✓；
4. GPT 的"**不自动挂载**"属性位（bit 63）还没设 ✗（自定义 GUID 已经够用 ✓）；
5. 真机端到端验证 ✗。
