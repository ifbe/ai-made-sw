#!/usr/bin/env python3
"""img2json.py — 图片转结构化标签 JSON（AI 自动打标签，v2 schema 外部化）

用法:
    python3 img2json.py <图片/文件夹>                       # 用内置 schema
    python3 img2json.py <...> --schema <schema.json>        # 用指定 schema
    python3 img2json.py <...> --update                      # --update 模式
    python3 img2json.py <...> --force                       # 强制覆盖
    python3 img2json.py <...> --quiet                       # 静默

新设计（v2）：
  - schema 外置：找不到 --schema 文件则用内置 BUILTIN_SCHEMA
  - prompt 4 段：角色 / schema 模板 / 回复模板 / [--update 时的上次 tags]
  - AI 回复可含 "schema" 段（仅在内存表里 += 更新，不写 sidecar）
  - sidecar JSON = {tags, meta, ai} 三段平级（meta 保留旧字段；ai 是 reasoning/raw）
  - 跑完 / Ctrl+C 写入 <schema>-aimerge.json（原 schema.json 不动）

依赖:
    pip install requests
"""

import sys
import os
import re
import json
import base64
import atexit
import signal
from pathlib import Path
from datetime import datetime
import requests

# ====== 配置 ======
HOST = 'macmini.local'
PORT = 12345
API_KEY = '52755227'
MODEL = 'Qwen3.6-35B-A3B-4bit'
URL = f'http://{HOST}:{PORT}/v1/chat/completions'
TIMEOUT = 300
MAX_TOKENS = 32768

IMAGE_EXT = {'.png', '.jpg', '.jpeg', '.webp', '.gif', '.bmp', '.tiff'}
MIME = {
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webp': 'image/webp',
    '.gif': 'image/gif',
    '.bmp': 'image/bmp',
    '.tiff': 'image/tiff',
}

# ====== 内置 schema 模板（找不到 --schema 时用） ======
BUILTIN_SCHEMA = {
    "scene": [
        "海边", "城市", "乡村", "山景", "雪地", "森林"
    ],
    "time": [
        "日出", "上午", "正午", "下午", "黄昏", "日落"
    ],
    "weather": [
        "晴朗", "多云", "阴天", "雨天", "雪天"
    ],
    "tone": [
        "暖色调", "冷色调", "黑白", "鲜艳", "柔和", "复古"
    ],
    "composition": [
        "特写", "中景", "远景", "全景", "俯拍", "仰拍"
    ],
    "action": [
        "站立", "坐", "躺", "跑", "跳", "走",
        "拥抱", "牵手", "微笑", "大笑", "专注", "回眸"
    ],
    "mood": [
        "开心", "严肃", "搞怪", "温馨", "浪漫", "孤独",
        "震撼", "宁静", "活力"
    ],
    "subjects": [],  # array 自由填词，最多 5
}

# ====== Key 类型分类（供 prompt 区分 enum / array，避免 AI 混淆）======
# 这些 key 在 tags 输出里是字符串数组，不是从值列表里选一个
ARRAY_KEYS = {"subjects"}
ARRAY_MAX = {"subjects": 5}

# ====== Prompt 4 段 ======

# 第 1 段：角色
PROMPT_ROLE = """分析图片，输出JSON
"""

# 第 2 段：图片分类（schema 模板）
PROMPT_CLASS = """当前schema：
{enum_keys}
{array_keys}
"""

# 第 3 段：回复模板说明 + 规则
PROMPT_RESPONSE = """规则：
1.schema段：默认省略这个段，如果提供的schema模板所有词都不合适，就找合适的中文单词拓展它
2.tags段：除了subjects自由项，其他项都必须在schema里选值
3.tags.subjects：最多5个，自由填词，不进schema段

输出示例
{
  "schema": {
    "<subject>": ["<新值1>", "<新值2>"]
  },
  "tags": {
    "scene": "...",
    "time": "...",
    "weather": "...",
    "tone": "...",
    "composition": "...",
    "action": "...",
    "mood": "...",
    "subjects": ["...", "..."]
  }
}
"""

# 第 4 段：上次分类结果（仅 --update 且 sidecar 存在时使用）
PROMPT_LAST = """以下是上次该文件的分类结果供你参考：
{prev_tags_json}
"""


# ====== 全局状态：内存 schema 表 + 退出钩子 ======
_MEMORY_SCHEMA = None
_SCHEMA_PATH = None          # --schema 指定的绝对路径
_SCHEMA_BASENAME = None      # basename（用于 aimerge 文件名）
_INITIAL_SCHEMA_HASH = None  # 用于判断有没有变化


def load_schema(path):
    """读 schema.json；找不到或解析失败 → 用 BUILTIN_SCHEMA"""
    if path:
        p = Path(path)
        if p.exists():
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return {k: list(v) if isinstance(v, list) else v
                            for k, v in data.items()}, str(p.resolve())
                print(f'⚠️  {path} 不是合法 JSON 对象，回退内置')
            except Exception as e:
                print(f'⚠️  读取 {path} 失败: {e}，回退内置')
        else:
            print(f'⚠️  找不到 {path}，回退内置 BUILTIN_SCHEMA')
    return {k: list(v) if isinstance(v, list) else v
            for k, v in BUILTIN_SCHEMA.items()}, None


def merge_into_memory(memory_schema, ai_schema_segment):
    """只 +=，每次扩展打印日志；非法结构跳过"""
    if not ai_schema_segment:
        return
    for subject, values in ai_schema_segment.items():
        if not isinstance(subject, str) or not isinstance(values, list):
            print(f"  ⚠️  跳过非法 schema 项：{subject}={values!r}（必须 {{str: [str, ...]}}）")
            continue
        new_values = [v for v in values if isinstance(v, str)]
        if subject in memory_schema:
            existing = memory_schema[subject]
            if not isinstance(existing, list):
                print(f"  ⚠️  {subject} 不是 enum 列表，跳过")
                continue
            added = [v for v in new_values if v not in existing]
            existing.extend(added)
            if added:
                print(f"  ✓ schema {subject}+={added}")
        else:
            memory_schema[subject] = list(new_values)
            print(f"  ✓ schema + 新维度 {subject}={new_values}")


def _render_enum_keys(memory_schema):
    """渲染 PROMPT_CLASS 里的 {enum_keys} 占位符"""
    lines = []
    for k, v in memory_schema.items():
        if k in ARRAY_KEYS:
            continue
        lines.append(f"  {k}（单值，从下面选一个）：{', '.join(v)}")
    return "\n".join(lines) if lines else "  （无）"


def _render_array_keys(memory_schema):
    """渲染 PROMPT_CLASS 里的 {array_keys} 占位符"""
    lines = []
    for k, v in memory_schema.items():
        if k not in ARRAY_KEYS:
            continue
        max_n = ARRAY_MAX.get(k, "?")
        example = v if v else "任意字符串"
        lines.append(f"  {k}（数组，最多 {max_n} 个，自由填词，例：{example}）")
    return "\n".join(lines) if lines else "  （无）"


def render_prompt(memory_schema, prev_tags=None):
    parts = []
    # 第 1 段
    parts.append(PROMPT_ROLE)
    # 第 2 段：用当前 schema 填 PROMPT_CLASS 占位符
    parts.append(PROMPT_CLASS.format(
        enum_keys=_render_enum_keys(memory_schema),
        array_keys=_render_array_keys(memory_schema),
    ))
    # 第 3 段
    parts.append(PROMPT_RESPONSE)
    # 第 4 段（仅 --update 且有 prev_tags）
    if prev_tags is not None:
        prev_clean = {"tags": prev_tags}
        parts.append(PROMPT_LAST.format(
            prev_tags_json=json.dumps(prev_clean, ensure_ascii=False, indent=2)
        ))
    return "\n\n".join(parts)


def call_ai_api(image_path, memory_schema, prev_tags=None, debug=True):
    """调用 AI 接口（流式），thinking/content 实时打印到 stdout

    返回 (raw_content, reasoning_content, tags, schema_ext)
    """
    mime = MIME.get(Path(image_path).suffix.lower(), 'image/png')
    with open(image_path, 'rb') as f:
        b64 = base64.b64encode(f.read()).decode()

    system_prompt = render_prompt(memory_schema, prev_tags)

    payload = {
        'model': MODEL,
        'messages': [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': [
                {'type': 'text', 'text': '输出 JSON：'},
                {'type': 'image_url', 'image_url': {'url': f'data:{mime};base64,{b64}'}},
            ]}
        ],
        'max_tokens': MAX_TOKENS,
        'reasoning_effort': 'low',  # 压低思考开销（批量跑用）
        'stream': True,  # 流式输出
    }
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json',
    }

    response = requests.post(URL, json=payload, headers=headers, timeout=TIMEOUT, stream=True)
    response.raise_for_status()
    response.encoding = 'utf-8'

    reasoning_content = ''
    raw_content = ''
    state = 'idle'  # 'idle' | 'reasoning' | 'content'

    if debug:
        print(f'\n\033[90m📡 流式请求：{image_path.name}\033[0m')

    for line in response.iter_lines(decode_unicode=True):
        if not line or not line.startswith('data:'):
            continue
        data_str = line[5:].strip()
        if data_str == '[DONE]':
            break
        try:
            chunk = json.loads(data_str)
        except json.JSONDecodeError:
            continue
        if not chunk.get('choices'):
            continue
        delta = chunk['choices'][0].get('delta', {})
        r_delta = delta.get('reasoning_content') or ''
        c_delta = delta.get('content') or ''

        if r_delta:
            if state != 'reasoning':
                if debug:
                    print('\n\033[90m── reasoning_content ──\033[0m')
                    sys.stdout.flush()
                state = 'reasoning'
            reasoning_content += r_delta
            if debug:
                sys.stdout.write(r_delta.replace('\\n', '\n'))
                sys.stdout.flush()

        if c_delta:
            if state == 'reasoning':
                if debug:
                    print('\n\033[90m──────────────────────\033[0m')
                state = 'content'
                if debug:
                    print('\033[92m── content ──\033[0m')
            elif state != 'content':
                state = 'content'
                if debug:
                    print('\n\033[92m── content ──\033[0m')
            raw_content += c_delta
            if debug:
                sys.stdout.write(c_delta.replace('\\n', '\n'))
                sys.stdout.flush()

    if debug:
        print('\n\033[0m')
        # 流完后尝试解析 content，格式化打印一次
        if raw_content.strip():
            try:
                parsed = json.loads(raw_content)
                print('\033[93m── 解析结果 ──\033[0m')
                print(json.dumps(parsed, ensure_ascii=False, indent=2))
            except Exception:
                pass
            print()

    # 解析 AI 回复
    ai_reply = None
    try:
        ai_reply = json.loads(raw_content)
    except json.JSONDecodeError:
        match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_content, re.DOTALL)
        if match:
            try:
                ai_reply = json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        if ai_reply is None:
            start = raw_content.find('{')
            end = raw_content.rfind('}')
            if start != -1 and end != -1 and end > start:
                try:
                    ai_reply = json.loads(raw_content[start:end + 1])
                except json.JSONDecodeError:
                    pass

    if isinstance(ai_reply, dict):
        tags = ai_reply.get('tags')
        schema_ext = ai_reply.get('schema')
    else:
        tags = None
        schema_ext = None

    return raw_content, reasoning_content, tags, schema_ext


def write_aimerge():
    """atexit 钩子：写 <schema>-aimerge.json（仅当 --schema 指定过）"""
    global _MEMORY_SCHEMA, _SCHEMA_PATH
    if _MEMORY_SCHEMA is None or _SCHEMA_PATH is None:
        return
    out_path = Path(_SCHEMA_PATH).with_name(Path(_SCHEMA_PATH).stem + '-aimerge.json')
    try:
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(_MEMORY_SCHEMA, f, ensure_ascii=False, indent=2)
        # 判断有无变化
        initial = {k: list(v) if isinstance(v, list) else v
                   for k, v in BUILTIN_SCHEMA.items()}
        # 重新读 _SCHEMA_PATH 原始内容做 diff
        try:
            with open(_SCHEMA_PATH, 'r', encoding='utf-8') as f:
                original = json.load(f)
        except Exception:
            original = initial
        if _MEMORY_SCHEMA == original:
            print(f'\n📝 内存 schema 与 {_SCHEMA_PATH.name} 相同，未写入 {out_path.name}')
        else:
            print(f'\n📝 AI 提议 schema 扩展已写入 {out_path}')
            print(f'   原 schema 不变，确认采纳请: mv {out_path.name} {_SCHEMA_PATH.name}')
    except Exception as e:
        print(f'\n⚠️  写 {out_path} 失败: {e}', file=sys.stderr)


def setup_signal_handler():
    """Ctrl+C 也走 write_aimerge"""
    def handler(sig, frame):
        write_aimerge()
        print('\n⚠️  中断')
        sys.exit(0)
    signal.signal(signal.SIGINT, handler)


def load_previous_tags(json_path):
    """--update 时读旧 sidecar，只取 tags（兼容新旧两种格式）"""
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # 新格式 {tags: {...}, meta: {...}, ai: {...}}
        # 旧格式 {tags: {...}, source_file: ..., ...}
        return data.get('tags', {}) or {}
    except Exception as e:
        print(f'⚠️  读取旧 JSON 失败: {e}')
        return None


def process_image(image_path, memory_schema, force=False, quiet=False, debug=True, update=False):
    image_path = Path(image_path)
    json_path = image_path.with_suffix(image_path.suffix + '.json')

    if update and not json_path.exists():
        if not quiet:
            print(f'❌ 更新模式需要JSON文件存在: {json_path.name}')
        return False
    if not update and json_path.exists() and not force:
        if not quiet:
            print(f'⏭️  跳过: {json_path.name}（使用 --force 覆盖，或 --update 更新）')
        return False

    if not quiet:
        mode_str = '🔄 更新' if update else '📝 新建'
        print(f'[{mode_str}] {image_path.name} ...', end=' ', flush=True)

    try:
        prev_tags = None
        existing_meta = None
        if update:
            try:
                with open(json_path, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
                prev_tags = existing_data.get('tags', {}) or {}
                existing_meta = existing_data.get('meta', {})
            except Exception:
                existing_meta = {}

        raw_content, reasoning_content, tags, schema_ext = call_ai_api(
            image_path, memory_schema, prev_tags=prev_tags, debug=debug
        )

        if schema_ext:
            merge_into_memory(memory_schema, schema_ext)

        meta = {
            'source_file': image_path.name,
            'generated_at': datetime.now().isoformat(),
            'file_size_bytes': image_path.stat().st_size,
        }
        if existing_meta:
            if 'created_at' in existing_meta:
                meta['created_at'] = existing_meta['created_at']
        meta['updated_at'] = meta['generated_at']

        result = {
            'tags': tags if isinstance(tags, dict) else {},
            'meta': meta,
            'ai': {
                'reasoning_content': reasoning_content,
                'raw_content': raw_content,
            }
        }

        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        if not quiet:
            if tags:
                print('✅ 完成')
            else:
                print('⚠️  完成（无 JSON）')
        return True

    except Exception as e:
        if not quiet:
            print(f'❌ {e}')
        return False


def process_folder(folder_path, memory_schema, force=False, quiet=False, debug=True, update=False):
    folder = Path(folder_path)
    images = sorted([f for f in folder.iterdir() if f.suffix.lower() in IMAGE_EXT])

    if not images:
        print(f'⚠️  {folder} 中没有图片')
        return

    mode_str = '更新' if update else '新建'
    print(f'📁 找到 {len(images)} 张图片，{mode_str}模式\n')

    success = 0
    for i, img in enumerate(images, 1):
        print(f'[{i:2d}/{len(images)}] ', end='')
        if process_image(img, memory_schema, force=force, quiet=quiet, debug=debug, update=update):
            success += 1

    print(f'\n📊 成功: {success}/{len(images)}')


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)

    # 解析 flag
    force = '--force' in args or '-f' in args
    quiet = '--quiet' in args or '-q' in args
    update = '--update' in args or '-u' in args
    debug = not quiet

    schema_arg = None
    if '--schema' in args:
        idx = args.index('--schema')
        if idx + 1 < len(args):
            schema_arg = args[idx + 1]
            args = args[:idx] + args[idx + 2:]
        else:
            print('❌ --schema 需要文件名参数')
            sys.exit(1)

    target = args[0] if args else None

    try:
        import requests
    except ImportError:
        print('❌ pip install requests')
        sys.exit(1)

    if not target or not os.path.exists(target):
        print(f'❌ 不存在: {target}')
        sys.exit(1)

    # 加载 schema
    global _MEMORY_SCHEMA, _SCHEMA_PATH, _SCHEMA_BASENAME
    _MEMORY_SCHEMA, _SCHEMA_PATH = load_schema(schema_arg)
    if _SCHEMA_PATH:
        _SCHEMA_BASENAME = Path(_SCHEMA_PATH).stem
        setup_signal_handler()
        atexit.register(write_aimerge)

    try:
        if os.path.isdir(target):
            process_folder(target, _MEMORY_SCHEMA, force=force, quiet=quiet, debug=debug, update=update)
        else:
            process_image(Path(target), _MEMORY_SCHEMA, force=force, quiet=quiet, debug=debug, update=update)
    except KeyboardInterrupt:
        # signal handler 兜底
        print('\n⚠️  中断')


if __name__ == '__main__':
    main()