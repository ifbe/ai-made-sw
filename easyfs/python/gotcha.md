# python/gotcha —— 写代码时踩过的坑

> **只记写代码过程中遇到的东西** ✓：踩了什么、为什么、以后怎么避 ✓。
> **设计 / 语义**看 [`../doc/`](../doc/README.md) ✓；**代码现状与用法**看 [`README.md`](README.md) ✓。
> 写新代码**不需要**先读本文件 ✓；只在"这段为什么要这么写"时来查 ✓。

---

## 1. `stamp_header()` 的参数顺序（漏掉第三个就 TypeError）

* 现象：`TypeError: stamp_header() missing 1 required positional argument: 'header_bytes'`
* 签名：`stamp_header(buf, block_type, header_bytes, payload_len, seq=0, …)`
* 规矩：写块头一律 `stamp_header(buf, BT_xxx, 64, payload_len)` ✓。

## 2. `_window()` 返回 `(win, desc)`，不是设备

* 现象：`'tuple' object has no attribute 'close'`
* 原因：`_open_scoped` 把返回值直接当设备用了
* 规矩：拆开取 `win, desc = _window(...)` ✓。

## 3. 自己写"开容器"函数最容易漏 `--disk`

* 现象：`resize --disk` 抛 `TypeError: stat: path should be string, bytes, os.PathLike or integer, not NoneType`
* 原因：`open_container_device()` 只认 `--mem` / `--vdisk` / `--file`，`args.file` 是 `None`
* 规矩：新增"自己开设备"的函数时，**照 `open_device` 逐项核对载体类型**（含 `--disk`）✓。

## 4. `--offs` 的默认值是字符串 `"0"` ⇒ `if args.offs` 恒真

* 现象：`--part N` 与 `--offs/--size` 的"二选一"判断假阳性（明明没给也报错）
* 规矩：判"有没有给"用 `arg.offs not in (None, "0", 0)` ✓。

## 5. 互斥组 `required=True` 会让"打印帮助"也要求参数

* 现象：`optimize` 不带任何参数时 argparse 直接报
  `one of the arguments --file --vdisk --mem --disk is required`，帮助打不出来
* 规矩：只想打帮助的命令 ⇒ `add_device_args(op, required=False)` ✓，真正需要设备时再报错 ✓。

## 6. 替换 argparse 区块时容易连带删掉 `add_device_args()`

* 现象：命令的 `--file` / `--vdisk` / `--mem` / `--disk` 全部消失（`unrecognized arguments`）
* 规矩：改完 argparse 区块**立刻跑一次 `--help`**，确认四个载体参数还在 ✓。

## 7. argparse 的 `dest` 由选项串推导，非 ASCII 名字很别扭

* 现象：`--alloc-合并` ⇒ `args.alloc_合并`
* 规矩：选项名带非 ASCII 时显式写 `dest=` ✓（现在动作名都用英文 ✓）。

## 8. `--force` 会跟别的工具撞名

* 现象：argparse 冲突 ⇒ `tool-sftpcli` 直接起不来
* 原因：`--force` 在两个工具里语义不同（覆盖远端文件 vs 越过磁盘保护）
* 规矩：安全参数放在"**会写盘的命令自己**"那里，并用 `dest="disk_force"` ✓。

## 9. 只读句柄上不许写（`mark_clean` / `rebuild_bitmap`）

* 现象：`optimize --dry-run` 报 `只读设备` 并 exit 1
* 原因：卷 dirty 时无条件 `rebuild_bitmap(apply=True)`；收尾又无条件 `mark_clean()`
* 规矩：`--dry-run` 走 `read_only=True` ⇒ **所有写路径都要先过 `dry_run` 判断** ✓。

## 10. `BLOCK_MAGIC` 表必须放在 `BT_*` 常量之后

* 现象：`NameError: name 'BT_ALLOC' is not defined`（模块导入即失败 ⇒ 整个工具入口挂掉）
* 规矩：配置表若引用常量，就放在常量定义**之后**；改完立刻 `py_compile` ✓。

## 11. "是不是我们的块"别只比一个魔数

* 现状：每类块一个魔数（`easyallc` / `easydir ` / `easylink` / `easypart` / `easybad `）
* 规矩：`magic_ok`（等于该类型应有的魔数）+ `prefix_ok`（`easy` 前缀）**两个都要看** ✓
  —— 否则报错时分不清"不是我们的块"和"是我们的块但类型不认识" ✓。

## 12. `.dmg` 的类型要从**文件尾**判

* 现象：UDIF 的 `koly` 在文件末尾 ⇒ `open_container` 从头读会把 `.dmg` 误判成 raw
* 规矩：容器类型先看**尾部签名**，再看头部魔数 ✓。

## 13. 没有真盘 / 没有 root 时，测试用"骗一下"

* 用法：`easyfs_device.is_block_device = lambda p: True`（`test/run_all.py` 的 1i 就这么做 ✓）
* 注意：`/dev/loop0` 常是**已挂载**的 snap 设备 ✗ 不能写 ⇒ 只能做 sysfs 类只读测试 ✓。

## 14. `[y/N]` 确认必须用真 pty 测

* 现象：非 tty 时 `confirm_dangerous_disk` 直接拒绝（这是设计 ✓）
* 规矩：测"喂 n / 喂 y"用 `pty.openpty()` ✓；并且断言"**喂 n ⇒ 盘一个字节没写**" ✓。

## 15. 别在 bytes 字面量里写中文

* 现象：`SyntaxError: bytes can only contain ASCII literal characters`
* 规矩：用 `"已取消".encode("utf-8")` ✓。

## 16. 两个测试套件并行跑会互相清 `test/.work`

* 现象：随机报 `文件不存在: test/.work/xxx`（看起来像真 bug ✗）
* 原因：两个 `run_all.py` 同时跑，启动时都会清工作目录
* 规矩：**串行跑**；看到"文件不存在"先怀疑并行 ✓。

## 17. `re.sub` 的替换串里 `\*` 在 Py3.6 不报错

* 现象：`\*\*` 被原样写进文件（Markdown 里显示成星号而不是粗体）
* 规矩：替换串里别带反斜杠转义；要字面的 `*` 就直接写 `*` ✓。

## 18. 改入口 / 配置后必须 `py_compile` + 跑一次 `--help`

* 现象：`tool.py` 的 `ABOUT` 字典插入错位 ⇒ `IndentationError` ⇒ **所有命令全挂**
* 规矩：`python3 -m py_compile python/*.py` + 跑一次 `tool.py help` ✓。
