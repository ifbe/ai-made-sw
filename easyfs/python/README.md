# python/ —— 参考实现（Python 3.6+，只依赖标准库）

> **格式与语义看 [`../doc/`](../doc/README.md)** ✓ —— 这里只讲**代码**：
> 文件分工、**实现现状**（哪些做了 / 哪些没做）、怎么跑、自检怎么挂钩 ✓。

## 1. 文件

| 文件 | 内容 |
|---|---|
| [`easyfs_config.py`](easyfs_config.py) | **唯一常量源**：块类型与名字、块头魔数表、属性号、anchor tag / 段、各上界 |
| [`easyfs.py`](easyfs.py) | **核心 · 格式层**：块头、anchor、位图（分配）、目录、链接块、文件、fsck、resize、optimize |
| [`easyfs_device.py`](easyfs_device.py) | **核心 · 设备层**：`FileDevice` / `RegionDevice` / `MemDevice` / `VhdDevice` / `VmdkDevice`；分区表读写（MBR / GPT）；虚拟磁盘（`.vhd` / `.vmdk` / `.dmg` / `.img`）；破坏性操作的确认与保护 |
| [`tool.py`](tool.py) | **工具入口**：按名字加载 `tool-*.py` 并**本进程**分发（认不出的名字转给 `tool-ctrl`）|
| [`tool-ctrl.py`](tool-ctrl.py) | 离线控制 / 诊断：`mkfs` / `probe` / `device` / `df` / `fsck` / `optimize` / `hexdump` / `inspect` / `migrate` / `shell` / `resize` / `mbr` / `gpt` |
| [`tool-vdisk.py`](tool-vdisk.py) | 虚拟磁盘：新建与详情 |
| [`tool-sftpcli.py`](tool-sftpcli.py) | sftp 风格**本地**命令行 |
| [`tool-server.py`](tool-server.py) | **HTTP / WebDAV-lite 网络服务器** |

## 2. 怎么跑

Python 3.6+，只依赖标准库 ✓。`tool.py <名字> <参数>` 与 `tool-<名字>.py <参数>` 等价 ✓；
`tool.py` 认不出的名字会转给**控制工具**（`tool-ctrl.py` ✓ —— 它就是下面这些子命令的实现 ✓）⇒ **子命令可以直接当顶层命令用** ✓
（下面的例子都用这种简写 ✓；完整写法是 `tool.py ctrl mkfs …` ✓）。

```bash
python3 python/tool.py help                                    # 有哪些工具
python3 python/tool.py mkfs --file disk.img --size 64M          # 建卷（文件当载体）
python3 python/tool.py df -h --file disk.img                    # 空间用量
python3 python/tool.py sftpcli --file disk.img                  # 像 sftp 那样用
python3 python/tool.py server --mem 64M --mkfs --port 8080      # 内存卷 + 网络访问
python3 python/tool.py vdisk --file disk.vmdk --create --size 64M   # 新建虚拟磁盘
python3 python/tool.py mbr --vdisk disk.img --part 1 --seteasy  # 给分区打上我们的标识
```

「卷放在哪」/ 分区标识 / 保护措施见 [`../doc/parttable.md`](../doc/parttable.md) ✓；
伸缩与分配见 [`../doc/1-alloc.md`](../doc/1-alloc.md) ✓；目录 / 文件 / 链接块 / anchor 见各自模块文档 ✓。

## 3. 实现现状（逐模块）

> 这里记**代码做到了哪** ✓；格式与语义在 [`../doc/`](../doc/README.md) ✓。

| 模块 | 现状 |
|---|---|
| **0 null** | 写入方**永不产出** ✓；读到全零 magic 就当"未初始化" ✓ |
| **1 alloc** | 位图链 ✓（`allotype = 1`）；`commit_mode` **只实现了 `immediate`** ✓（每次操作后 `commit()` 写回脏区域），`batched` **未实现** ✗；位图 dirty 标志 + 重建**已实现** ✓；混合粒度 `bit_unit` 设计已定稿、**实现未做** ✗；`BIT_UNIT_MAX` 已放开（约束 = 2 的幂 + `chunk` 的整数倍）；`mkfs --bitmap-block` 可手工覆盖位图块大小 ✓ |
| **2 dir** | 读侧支持**条目跨块** ✓；写侧 v0 **未实现**"尾追加 + `PADn`" ✗ —— 单块放不下时抛 `EasyFSFragmented`，信息里给"要几段 / 上限几段 / 当前最大连续空闲"，并说明这是**写侧待实现项**、不是格式限制；**触发时已分配的段会回滚** ✓ |
| **3 link** | 硬链接（`link` / `unlink`，含 `NLINK` 递减与归零释放）与软链接（`symlink` / `readlink`，短目标 `SYMLINK_TINY`、长目标 `SYMLINK_PTR`）**都已实现** ✓；`DIR_OBJECT`（目录的对象形态）**只有读侧** ✓，写侧未实现 ✗（往对象形态目录里写 ⇒ `ENOTSUP`）；**创建**（`link()` / `symlink()` 与 copy-on-link 升格）**已实现** ✓（命令行要 `--object`）；**目录硬链接** ⇒ `ENOTSUP` ✓ |
| **4 file** | 四种模式**读侧全支持** ✓；**工具默认只写 ①②③**（`DATA_TINY` → `DATA_PTR` ✓）；只有命令行显式给 `--object` 才会尝试对象形态，而**对象写侧 v0 尚未实现** ✗（唯一已实现的对象写入是硬链接 `ln` ✓）|
| **5 anchor** | head / tail anchor 的写入与校验 ✓、`gen` / `stateflg` / `policy` ✓、resize 改 anchor 几何 ✓ |
| **6 bad** | 类型与语义已定义，但**产出与扫描都没实现** ✗（离线检查尚未做）；读取路径遇到 `block_type=6` 一律跳过 ✓ |
| **COW / 快照** | 「每个对象各自原子」已实现 ✓；根引用现在**只用 `roottype = 1`**（链式目录）✓；`2`（根 = 链接块）**只有读侧** ✓；**多世代根 / 快照未实现** ✗（设计上根表住在根对象块的一条属性里，不新增 `roottype` ✓）；`bitmap_OBJECT`（新一代分配器结构）**未实现** ✗ —— 现在始终 `allotype = 1` |
| **resize** | 区域内部伸缩 ✓（缩容的腾空阶段**只挪位图块**，遇到文件数据块 / dir 块就 `ENOTSUP` ✗）；`--part N` 可代替 `--offs/--size` 说"改前位置" ✓；**扩出来的新空间按 `chunk` 粒度** ✓；合并成粗粒度要等 `optimize` ✓ |
| **optimize** | `alloc` 已实现 ✓（合并全空子区域）；`dir` / `link` **明确 `ENOTSUP`** ✗ |

## 4. 代码层的坑

**已经删掉的实现 / 已经修掉的坑**不写在正文里 ✗ ⇒ 放本目录的 `gotcha.md` ✓（现在还没有 ✓，需要时再建 ✓；设计层的同类东西在 [`../doc/gotcha.md`](../doc/gotcha.md) ✓）。

## 5. 自检与测试挂钩

* `easyfs_config.BLOCK_MAGIC` 是**块头魔数的唯一权威表** ✓；`test/doccheck.py` 有一条规则
  逐行核对 `doc/common.md` 的魔数表 ↔ 这张表 ✓（还有一条禁止退役用词 ✓）。
* `test/run_all.py` 的子检查 1b–1k 覆盖：anchor tag 解析、容器 / 分区与 `--create`、
  真盘确认（`--yes` / `y/N`）、resize（`--part` / 确认）、块头魔数逐类核对 ✓。
* 完整清单与每个子测试的流程见 [`../test/README.md`](../test/README.md) ✓。

## 6. 命令与用法

### 5.1 卷放在哪（四种载体，四选一）

| 载体 | 用途 | 说明 |
|---|---|---|
| `--file <路径>` | 普通文件；**也可以直接给分区设备节点**（如 `/dev/sda1`）| 整段就是卷 |
| `--vdisk <镜像>` | `.img` / `.vhd` / `.vmdk`，**自动解析分区表** | 配 `--part N` 选分区 |
| `--mem <大小>` | 内存卷（演示 / 测试）| 不落盘 |
| `--disk <块设备>` | **真实磁盘**（如 `/dev/sda`）| 危险目标 ⇒ 见 §6.5 |

**不给区域时的规则** ✓：盘上只有 1 个分区 ⇒ 自动选它；多个分区 ⇒ **拒绝**（不替你猜，
更不会把分区表当垃圾吃掉）；没有分区表 ⇒ 按整盘；要把整盘当卷 ⇒ 显式写 `--offs 0`。
`--part` 与 `--offs/--size` **互斥**（混用报错 ✓）。

**偏移是自动加的** ✓：`--part N` 会用分区的 `start / length` 包一层 `RegionDevice`，
它的 `read_at(off)` = `dev.read_at(offset + off)` ⇒ 之后**所有** `--block` / `--path` /
`--offs` 都是**卷内坐标** ✓。`mkfs` 打印的 `anchor head @0` 是卷内偏移 0，在盘上它位于
分区起点（例如绝对 1 MiB 处）✓。

### 5.2 分区表：`mbr` / `gpt`

看 / 改合一 ✓：**不给 `--seteasy` 就只列出**（只读 ✓，并标出哪个"已经是我们的标识"）；
**给 `--seteasy` 才改** ✓ —— 只动分区表，不碰任何数据 ✓。

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
   GPT 分区 #1：类型 0FC63DAF-… → 79736165-6170-7472-6561-737970617274
复核          主/备 GPT 自洽 ✓
```

**建表**（`--create` ✓）：在**空容器**上建一张表 + **一个占满的分区**，分区类型**直接写成
我们的标识**（所以新建的分区不用再 `--seteasy`；`--seteasy` 是给**已有**分区用的）：

```bash
python3 python/tool.py vdisk --file disk.vmdk --create --size 64M   # ① 建虚拟磁盘
python3 python/tool.py gpt   --vdisk disk.vmdk --create             # ② 建 GPT 表 + 分区
python3 python/tool.py mkfs  --vdisk disk.vmdk --part 1             # ③ 在分区里建卷
```

* 容器里**已经有分区表 / 已经是我们的卷 / 开头不是空的** ⇒ `--create` **拒绝** ✓
  （要重建得显式 `--force` ✓）；
* `--offs` / `--size` 指定分区位置与大小（默认 1 MiB 起、到容器末尾）；`--part` 指定写第几个项；
* **GPT 一次改动要写四处**：主项数组里那一项的类型 GUID / 主头的
  `partition_entry_array_crc32` / 主头的 `header_crc32`（CRC 字段按 0 算）/ 备份项数组 + 备份头 CRC
  ⇒ 否则主备不一致；
* 写后自检 `verify_gpt()` ✓（主头 CRC / 备份头 CRC / 两份数组一致）；
* 形态不匹配直接拒 ✓：拿 `mbr --seteasy` 去改 GPT ⇒
  `error: 这是 GPT 分区表，不是 MBR（用 gpt --seteasy）`。

### 5.3 虚拟磁盘：`vdisk`

`.vhd`（动态 / 加 `--fixed` 固定）、`.vmdk`（单文件稀疏）、`.dmg`（UDIF 未压缩）、
`.img` / `.raw`（裸文件）—— **格式由后缀决定**；不加 `--create` 就只显示详情（什么都不改）。

```bash
python3 python/tool.py vdisk --file disk.vmdk --create --size 64M   # 建
python3 python/tool.py vdisk --file disk.vmdk                       # 只看详情
```

`.vhd` / `.vmdk` / `.img` 都能当卷载体 ✓；**`.dmg` 只能建 / 看详情** ✗（`--vdisk` 会明确拒绝）。
`.vmdk` 是单文件稀疏盘（64 MiB 空盘只占 ~5 KiB）。

### 5.4 `resize` / `migrate` / `optimize`

```bash
tool resize --file IMG \
    --offs 16M --size 64M \             # 旧几何：卷现在在哪（用来定位 + 校验）
    --newoffs 32M --newsize 48M \       # 新几何
    [--mode shrinkleft] [--dry-run] [--no-verify] [-v] [--yes]

tool migrate --file SRC [--offs A] [--size L] \
             --newfile DST [--newoffs B] [--newsize L2] [--keep-uuid] [--dry-run] [-v]

tool optimize --alloc-merge [--dry-run] [-v]     # 或 --dir / --link 看动作清单、--all 全跑
```

* 旧几何可以用 **`--part N`** 代替 `--offs/--size`（旧几何 = 那个分区的范围；新几何仍用
  `--newoffs/--newsize`）；两者**不能混用**；它只借几何，**不动分区表** ✓；
* `--offs` / `--size` 都不给 = 整个文件；`--newoffs` 省略 = 与 `--offs` 相同；
  `--dry-run` 只推导 + 检查 + 打印计划（0 次写）✓；`-v` 打印步骤与写入序列；
* **`resize` 会问一句** ✓ —— 不分载体（`--file` / `--vdisk` / `--disk` 都问，`--yes` 免问，
  `--dry-run` 不问因为它不写盘）；
* `optimize` 是**两级 flag** ✓（`--<family>` 打帮助 ✓、`--<family>-<action>` 执行 ✓）：
  ```bash
  tool optimize --alloc | --dir | --link     # 看某一族有哪些动作（只打帮助，不碰盘 ✓）
  tool optimize --alloc-merge [--dry-run]     # 执行：合并全空的子区域 ✓ 已实现
  tool optimize --dir-compact                   # 压实目录链 ✗ ENOTSUP
  tool optimize --link-merge                  # 合并链接块的内容块表 ✗ ENOTSUP
  tool optimize --all                        # 依次跑所有已实现的动作
  ```
  不带任何动作（或 `--help`）⇒ 打总帮助 ✓，**不需要载体** ✓；未实现的动作**不碰盘**直接 `ENOTSUP` ✓；
  `--dry-run` 只报告"能回收多少块 / 多少字节"，不写盘 ✓。

### 5.5 真盘上的保护（`--disk` 的三道）

1. **先亮出这个盘是什么** —— 设备名 / 容量 / 型号 / 厂商 / 序列 / 可移动 / 逻辑·物理扇区 /
   整盘还是分区 / 挂载在哪 / `/` 是否就在这盘上；
2. **拒绝危险目标** —— 盘（含它的分区）**正被挂载** ⇒ 拒绝；**根文件系统在这盘上** ⇒ 拒绝；
   两者都要显式 `--force` 才越得过；
3. **要人确认** —— 打印"会销毁该盘上的全部分区表与数据"，然后问 `继续吗？[y/N]`
   （脚本里加 `--yes` 就免问）；非交互环境**不给 `--yes` 就直接拒绝** ✓。

`mbr` / `gpt` 有两处不同：`--seteasy` **只改分区类型、不动数据** ⇒ **挂载中也允许**（只提示）；
而 `--create` 会重建整张表 ⇒ **挂载中直接拒** ✓。`--yes` / `--force` 由**会写盘的命令自己带** ✓
（`tool-sftpcli` 的 `--force` 是"覆盖已存在的远端文件" ⇒ 那个工具跑 `--disk` 时永远会问）。

只读命令（`probe` / `df` / `fsck -n` / `inspect` / `device`）**只打信息、不要求确认** ✓。

### 5.6 实现边界（现状）

* **`resize` 不接受 `--part` 作为"区域"**（它只用来取旧几何 ✓）⇒ 扩缩真机分区内的卷：
  用 `--file /dev/sda1`（相对分区 ✓），或自己把两个几何的绝对偏移算好；
* **`vdisk` 没有 `--disk`** ✓ —— 它建的是**文件**；物理盘不需要"新建"；
* 真盘上的三步（每条都会问，脚本里加 `--yes`）：`mbr --disk /dev/sdX --create` ⇒
  `mbr --disk /dev/sdX --part 1 --seteasy`（这步可省）⇒ `mkfs --disk /dev/sdX --part 1`；
* 工具默认只写文件模式 ①②③；对象形态要显式 `--object`（见 §3 现状表）。
