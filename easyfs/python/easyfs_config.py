#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EasyFS 的**全部格式定义与配置值**（唯一来源）。

这里**只放数字 / 字符串 / 名字表，不放逻辑**：块的字节布局、块类型编号、属性编号、
anchor 字段偏移、位图块头偏移、分配策略编号、各种上限、设备层常量。

* ``easyfs.py``（格式层）、``easyfs_device.py``（设备层）、``tool-*.py``（工具层）都从这里取值；
* 单独成文件还有一个现实好处：``easyfs_device.py`` 可以 import 它而**不必** import ``easyfs.py``
  （否则两边循环导入）；
* ``doc/`` 是**语义权威**，本文件的注释与之一一对应。改这里的值 = 改格式，
  必须同时改对应文档（``common.md`` / ``layout.md`` / ``1-alloc.md`` / ``2-dir.md`` / ``5-anchor.md``）。
"""

# ============================================================ 1. 卷 / 块基本量

BLOCK_4K = 4096                 # 元数据块的固定大小（common.md §2）
HDR_SIZE = 64                   # 通用块头大小；也是 dir / 链接块的载荷起点
MAX_PAYLOAD = BLOCK_4K - HDR_SIZE   # 4032：单块载荷上限（dir / 链接块）
POOL_MAGIC = b"easyraid"        # pool 段魔数（anchor [0x200,0x400)，【将来方向】）
VERSION = 1                     # 格式版本

I64_MIN = -(1 << 63)            # 逻辑坐标 L / 自相对 delta 都按有符号 64 位处理
I64_MAX = (1 << 63) - 1

# ============================================================ 2. 通用块头字段偏移
# common.md §2；`stamp_header` / `parse_header` 按这些偏移读写

HDR_OFF_MAGIC = 0               # 8 B  magic
HDR_OFF_TYPE = 8                # 2 B  block_type
HDR_OFF_VERSION = 10            # 2 B  version
HDR_OFF_FLAGS = 12              # 4 B  flags（bit0 = payload_crc32 有效；bit1 = 链尾；
                                #              bit2 = 本块含 pool 段）
HDR_OFF_PREV = 16               # 8 B  prev_delta
HDR_OFF_NEXT = 24               # 8 B  next_delta
HDR_OFF_SEQ = 32                # 8 B  seq
HDR_OFF_PAYLOAD_LEN = 40        # 4 B  payload_len
HDR_OFF_PAYLOAD_CRC = 44        # 4 B  payload_crc32
HDR_OFF_HEADER_CRC = 48         # 4 B  header_crc32（覆盖 [0, header_bytes)，本字段按 0 计）
HDR_OFF_HEADER_BYTES = 52       # 4 B  header_bytes（类型专属区起点）
HDR_OFF_RESERVED = 56           # 8 B  保留（必须 0）

# ============================================================ 3. 块类型（common.md §3）

BT_NULL = 0                     # 无效 / 未初始化：写入方永不产出，读到一律当损坏
BT_ALLOC = 1                    # 空闲位图块
BT_DIR = 2                      # 目录块
BT_LINK = 3                     # 链接块（NLINK + 时间 + 位置表）
BT_FILE = 4                     # 文件数据 —— **裸数据块，没有块头**，这个值不出现在任何字节里
BT_ANCHOR = 5                   # head / tail anchor
BT_BAD = 6                      # 坏块标记

BT_NAME = {
    BT_NULL: "null",
    BT_ALLOC: "alloc",
    BT_DIR: "dir",
    BT_LINK: "link",
    BT_FILE: "file-data",
    BT_ANCHOR: "anchor",
    BT_BAD: "bad",
}

# 块头魔数：**每类一个独立词**（共同前缀 `easy` ⇒ "是不是我们的块" 仍是一次前缀比较）
#   * `null` 不给魔数（写入方永不产出；读到全零 magic 就当未初始化）
#   * `file data`（BT_FILE）是**裸块、没有头** ⇒ 不在这里
#   * anchor 仍是 `easypart`（卷 / 分区这一层的标记，见 5-anchor.md）
#   * 补到 8 字节用**尾部空格**（与 tag 名同一约定：`blktype ` / `policy  `）
MAGIC_PREFIX = b"easy"          # "是不是我们的块"看这 4 个字节
BLOCK_MAGIC = {
    BT_ALLOC:  b"easyallc",
    BT_DIR:    b"easydir ",
    BT_LINK:   b"easylink",
    BT_ANCHOR: b"easypart",
    BT_BAD:    b"easybad ",
}

# ============================================================ 4. 属性类型（2-dir.md §2.1）
# 家族分段：0x00–0x0F 占位/未使用 · 0x10–0x1F dir · 0x20–0x2F symlink ·
#           0x30–0x3F data · 0x40–0x4F 名字/时间 · 0x50–0x5F 对象 · 0x60+ 保留

ATTR_TLV_HDR = 2                # 每个属性的 TLV 头：{u8 type}{u8 len}
ATTR_RESERVED_MAX = 0x0D        # 类型 ≤ 这个值 = 未使用/无效（读到一律当损坏）

# --- 占位（0x00–0x0F）---
ATTR_PAD1 = 0x0E                # 固定 1 字节占位（唯一不带 len 字节的类型）
ATTR_PADN = 0x0F                # TLV 占位：len 可为 0 ⇒ 最小 2 字节

# --- dir 家族（0x10–0x1F）---
ATTR_DIR_PTR = 0x10             # {i64 first_dir_block}  目录 → 子目录链头
ATTR_DIR_OBJECT = 0x11          # {i64 L}                目录 → 链接块（内容块表）【读侧已有】

# --- symlink 家族（0x20–0x2F）---
ATTR_SYMLINK_TINY = 0x20        # {path}（≤255 B）       目标就在属性里
ATTR_SYMLINK_PTR = 0x21         # {i64 delta}{u32 size} 目标放数据块里，delta 寻址
ATTR_SYMLINK_OBJECT = 0x22      # {i64 L}{u32 size}     目标放数据块里，L 寻址

# --- data 家族（0x30–0x3F）---
ATTR_DATA_TINY = 0x30           # {data}（≤255 B）       内联内容（0 jump）
ATTR_DATA_PTR = 0x31            # {i64 delta}{u32 size} 直接指向（1 jump）
ATTR_DATA_OBJECT = 0x32         # {i64 L}               条目 → 链接块（2 jump）
ATTR_CRC32 = 0x33               # {u32}                 内容校验和（可选，必须在末位）

# --- 名字 / 时间（0x40–0x4F）---
ATTR_NAME = 0x40                # 名字原始字节（条目分隔符，必须第一个）
ATTR_NAME_HASH = 0x41           # {u8}                  名字哈希（索引用，可选）
ATTR_TCREATE = 0x42             # {u32 unix}            创建时间
ATTR_TMODIFY = 0x43             # {u32 unix}            修改时间

# --- 链接家族（0x50–0x5F）---
ATTR_NLINK = 0x50               # {u32}                 链接块内的引用计数

ATTR_NAME_STR = {
    ATTR_PAD1: "PAD1",
    ATTR_PADN: "PADn",
    ATTR_DATA_TINY: "DATA_TINY",
    ATTR_DATA_PTR: "DATA_PTR",
    ATTR_CRC32: "CRC32",
    ATTR_DATA_OBJECT: "DATA_OBJECT",
    ATTR_NLINK: "NLINK",
    ATTR_SYMLINK_TINY: "SYMLINK_TINY",
    ATTR_SYMLINK_PTR: "SYMLINK_PTR",
    ATTR_SYMLINK_OBJECT: "SYMLINK_OBJECT",
    ATTR_NAME: "NAME",
    ATTR_NAME_HASH: "NAME_HASH",
    ATTR_DIR_PTR: "DIR_PTR",
    ATTR_DIR_OBJECT: "DIR_OBJECT",
    ATTR_TCREATE: "TCREATE",
    ATTR_TMODIFY: "TMODIFY",
}

# 属性分组（语义分类，解析器按组处理，避免到处写死类型号）
PAD_ATTRS = (ATTR_PADN, ATTR_PAD1)                        # 占位：解析时跳过
SYMLINK_ATTRS = (ATTR_SYMLINK_TINY, ATTR_SYMLINK_PTR, ATTR_SYMLINK_OBJECT)
CONTENT_TINY_ATTRS = (ATTR_DATA_TINY, ATTR_SYMLINK_TINY)  # 内容内联在属性里
CONTENT_RUN_ATTRS = (ATTR_DATA_PTR, ATTR_SYMLINK_PTR)     # 内容是 delta 寻址的段
CONTENT_RUN_LOGICAL_ATTRS = (ATTR_SYMLINK_OBJECT,)        # 内容是 L 寻址的段

# 名字 / 属性长度上限
NAME_MAX = 255                  # 名字长度（字节）
TINY_MAX = 255                  # 内联内容 / 软链接短目标上限

# ============================================================ 5. 目录与条目（2-dir.md）

DIR_FIRST_SEQ = 0               # 目录链首块的 seq
ENTRY_MIN_SIZE = ATTR_TLV_HDR + 1   # 最短条目：NAME + ≥1 字节名字

# ============================================================ 6. 位图块（1-alloc.md §3）

BM_OFF_REGION_DELTA = 64        # 8 B  区域起点（自相对 delta，基准 = 位图块自己）
BM_OFF_REGION_BYTES = 72        # 8 B  本区域覆盖的字节数
BM_OFF_BLOCK_BYTES = 80         # 4 B  位图块的 block_bytes（自适应 4 KiB…4 GiB）
BM_OFF_BIT_UNIT = 84            # 4 B  1 bit 代表多少字节
BM_OFF_LOGICAL_START = 88       # 8 B  本区域起点的逻辑坐标 L
BM_HDR_MIN = 96                 # 位图块的 header_bytes 至少这么大（[64,96) 是保留扩展位）

BIT_UNIT_MAX = 1 << 40          # bit_unit 上限（1 TiB；覆盖到 32 PiB 的卷）（2 的幂阶梯：4K/8K/…/1G，见 1-alloc.md §13.3）
#   —— 混合粒度下 bit_unit 可以比 chunk 粗；约束是"2 的幂 + 是 chunk 的整数倍"。
#   默认路径（不加 --mixed）仍然恒等于 chunk。
MAX_BITMAP_BLOCKS = 1024        # 位图链块数上限（自动选型，1-alloc.md §3.4）

# ============================================================ 7. anchor 块（5-anchor.md §2.1）
# **只有 head/tail anchor 用这个布局**（其它块还是 common.md §2 的 64 B 通用头）。
# 形式：每个字段 = 8 字节 ASCII 名（空格补齐）+ 它的值 ⇒ **每个字段 16 字节**，
# 字段起点都是 16 的倍数：
#   0  "easypart" + 版本字符串（如 "0.0.0.0"）   ← 魔数本身就是一个 tag
#   16 tag(8) + value(8)
#   32 tag(8) + value(8)   ……
# 解析规则：**按顺序读 tag；遇到不认识的 tag 就停止**（后面都算保留 ⇒ 将来只能追加）。

TAG_WIDTH = 8                   # tag 宽度（ASCII，空格补齐）
VALUE_WIDTH = 8                 # 值宽度（u8/u16/u32/u64 一律占 8 字节）
ANCHOR_MAGIC_TAG = b"easypart"  # 第一个 tag：魔数；**它的值就是版本字符串**
ANCHOR_VERSION_STR = b"0.0.0.0"  # 卷头版本字符串（8 字节 ASCII，改格式时动第一位）
ANCHOR_POOL_MAGIC_TAG = b"easypool"  # pool 段第一个 tag（有它 = 池成员）
ANCHOR_POOL_VERSION_STR = b"0.0.0.0"  # pool 段版本字符串
TAG_POOL_CRC = "poolcrc "    # pool 段 CRC（卷头 CRC 不含 pool 段）

# 有序 tag 表：`(tag, 值字节数)`。顺序 = 块内摆放顺序。**没有填充**：
#   * 普通字段：8 字节 tag + 值（u8/u16/u32/u64 一律 8 字节）
#   * **16 字节的值（uuid / 三个 guid）：`tag = None` ⇒ 裸值，不带 tag**（一个 uuid 一眼就是 uuid）
# ⇒ **每个字段恰好 16 字节**，字段起点都是 16 的倍数。
# 三段各自以 CRC 结尾：几何 / 身份段（geocrc）、状态段（stacrc）、pool 段（poolcrc）——
# 段级 CRC 仍用来**定位**坏在哪一段（header_crc 式的整体校验是 hdrcrc）。
# 段起点**固定**（一眼知道去哪儿找）；段内每个字段 16 字节，段末尾是保留区。
ANCHOR_OFF_HEADER = 0x000     # 头基本信息
ANCHOR_OFF_GEO = 0x040        # 几何 / 身份段
ANCHOR_OFF_STATE = 0x100      # 状态段（每次提交重写）
ANCHOR_OFF_POOL = 0x200       # pool 段【将来方向】
# **卷头**（头 + 几何 + 状态）到这儿；`hdrbytes` = 这个值，`hdrcrc` 覆盖 [0, 0x200)。
# **pool 段不在卷头里**（它从 0x200 开始、自带 poolcrc），所以卷头 CRC 不含 pool 段。
ANCHOR_VOL_HDR_END = 0x200
ANCHOR_POOL_END = 0x3D0       # pool 段实际用到这儿（含 poolcrc）
ANCHOR_HDR_END = ANCHOR_VOL_HDR_END   # 兼容旧名：= 卷头长度

# 每段的字段表：`(tag, 值宽)`，`tag = None` ⇒ **裸值（不带 tag）**。
# **所有 uuid 都放在各段最后**（在段 CRC 之前），这样 16 字节裸值不打断前面的 16 字节节奏。
ANCHOR_TAGS_VOL = ANCHOR_TAGS_HEADER = (
    ("easypart", 8),            # 魔数 tag；值是版本字符串（ANCHOR_VERSION_STR）
    ("blktype ", 8),            # u16 块类型（= 5）
    ("hdrbytes", 8),            # u32 头总长（= ANCHOR_HDR_END）
    ("hdrcrc  ", 8),            # u32 覆盖 [0, hdrbytes)（本字段按 0 计）—— **唯一校验权威**
)
ANCHOR_TAGS_GEO = (
    ("reglen  ", 8), ("peer    ", 8), ("dlolog  ", 8), ("chunk   ", 8),
    ("geover  ", 8), ("geomflag", 8),
    (None, 16),                 # 卷 uuid（裸值，放段末）
    # `policy` 挪到状态段，紧贴 `polstate`（同类紧贴；见 5-anchor.md §2.1 的摆放原则）
)
ANCHOR_TAGS_STATE = (
    # 家族顺序：提交计数 | 根（类型+入口）| 分配结构（类型+入口+块数+字节和）| 策略（id+状态）| 标志
    ("gen     ", 8), ("stateflg", 8),
    ("roottype", 8), ("rootioff", 8),
    ("allotype", 8), ("alloioff", 8), ("allocnum", 8), ("allosize", 8),
    ("policy  ", 8), ("polstate", 8),
)

# 分配结构的类型（anchor 的 `allotype` tag；与 ROOT_TYPE_* 对称）
ALLOC_TYPE_CHAIN = 1            # 扁平位图链（现状，**v0 只用这个**）
ALLOC_TYPE_OBJECT = 2           # 分配器**对象**（结构放链接块里；bitmap_OBJECT，将来）
ALLOC_TYPE_NAME = {ALLOC_TYPE_CHAIN: "chain（扁平位图链）",
                   ALLOC_TYPE_OBJECT: "object（分配器对象：结构在链接块里）"}
ANCHOR_TAGS_POOL = (
    ("easypool", 8),            # pool 魔数 tag；值是 pool 版本字符串 —— **有它 = 池成员**
    ("poolcrc ", 8),            # u32 **pool 段 CRC**：覆盖 [0x200, 0x3d0)（本字段按 0 计）
                                #    紧跟魔数 ⇒ 读方**先验 CRC 再信后面字段**（同卷头的 hdrcrc）
    ("memindex", 8), ("memcount", 8), ("vdevtype", 8), ("nparity ", 8),
    ("ashift  ", 8), ("stripe  ", 8), ("topover ", 8), ("memmapct", 8),
) + tuple(("memmap%02d" % k, 8) for k in range(16)) + (
    (None, 16), (None, 16), (None, 16),     # 池 / vdev / 成员 uuid（裸值，放段末）
)

# 两大段：卷头（ANCHOR_TAGS_VOL，[0,0x200)）+ pool 段（ANCHOR_TAGS_POOL，[0x200,…)）
ANCHOR_SECTIONS = (
    ("header", ANCHOR_OFF_HEADER, ANCHOR_TAGS_HEADER),
    ("geo", ANCHOR_OFF_GEO, ANCHOR_TAGS_GEO),
    ("state", ANCHOR_OFF_STATE, ANCHOR_TAGS_STATE),
    ("pool", ANCHOR_OFF_POOL, ANCHOR_TAGS_POOL),
)


# ============================================================ 8. 分配策略（1-alloc.md §5）
# 编号必须与 `POLICY_NAME` 表一致（这是**真实存在的 8 种**，不是猜的）

POLICY_FIRST_FIT_LEFT = 0
POLICY_FIRST_FIT_RIGHT = 1
POLICY_LAST_FIT = 2
POLICY_MIDDLE_OUT = 3
POLICY_BEST_FIT = 4
POLICY_WORST_FIT = 5
POLICY_RANDOM = 6
POLICY_EDGE_RESERVE = 7

POLICY_DEFAULT = POLICY_MIDDLE_OUT      # mkfs / create 的默认策略

POLICY_NAME = {
    0: "first-fit-left",
    1: "first-fit-right",
    2: "last-fit",
    3: "middle-out",
    4: "best-fit",
    5: "worst-fit",
    6: "random",
    7: "edge-reserve",
}

# ============================================================ 9. 设备层（easyfs_device.py）

SECTOR = 512                    # 逻辑扇区大小（MBR / GPT / VHD 都用它）
VHD_FOOTER_MAGIC = b"conectix"  # VHD 页脚魔数
VHD_FOOTER_SIZE = 512           # 固定页脚大小
VHD_COPY_OFFSET = 512           # 固定 VHD 里的页脚副本位置（0 扇区之后）
VHD_DYN_HEADER_OFF = 512 + 1024  # 动态头的偏移（页脚副本 + 保留区）
VHD_CHS_HEADS = 16              # VHD CHS 几何：磁头数
VHD_CHS_SECTORS = 63            # VHD CHS 几何：每道扇区数
VHD_CHS_MAX_CYLS = 0xFFFF       # VHD CHS 几何：柱面上限

MBR_PART_OFF = 0x1BE            # MBR 分区表项起点
MBR_PART_ENTRY = 16             # 每个分区表项 16 字节
MBR_PART_COUNT = 4              # 4 个主分区项
MBR_SIG_OFF = 0x1FE             # MBR 结束签名 0x55AA
MBR_SIG = b"\x55\xAA"
GPT_HDR_MAGIC = b"EFI PART"     # GPT 头魔数

DEVICE_BLOCK = SECTOR           # 设备 I/O 的默认块粒度（流式读写按它切）
DEFAULT_CONTAINER_SIZE = 64 << 20   # 容器不存在时 mkfs 的默认大小（64 MiB）
