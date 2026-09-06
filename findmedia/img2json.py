#!/usr/bin/env python3
"""
img2json.py — 图片转结构化标签JSON（AI自动打标签）

用法:
    python3 img2json.py <图片文件>                    # 生成 图片名.json
    python3 img2json.py <文件夹>                      # 遍历文件夹内所有图片生成JSON
    python3 img2json.py <图片文件> --update           # 读取已有JSON，让AI检查并更新标签
    python3 img2json.py <图片文件> --force            # 强制覆盖已有JSON
    python3 img2json.py <图片文件> --quiet            # 静默模式（不打印调试信息）

依赖:
    pip install requests
"""

import sys
import json
import base64
import os
import re
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

# 支持的图片格式
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

# ====== 提示词 ======

# 新建/覆盖时的提示词
SYSTEM_PROMPT_NEW = """你是一个图片标签分析专家。请根据图片内容，严格按照以下JSON格式输出标签。

{
  "scene": "",      // 场景：海滩/城市/乡村/山景/雪地/森林/水域/室内/街道/天空/沙漠/草原/建筑/夜景/花园/其他
  "time": "",       // 时间：日出/上午/正午/下午/黄昏/日落/夜晚/黄金时刻/蓝色时刻/其他
  "weather": "",    // 天气：晴朗/多云/阴天/雨天/雪天/雾天/暴风雨/其他
  "tone": "",       // 色调：暖色调/冷色调/黑白/鲜艳/柔和/复古/其他
  "composition": "",// 构图：特写/中景/远景/俯拍/仰拍/平拍/侧面/正面/其他
  "subjects": [],   // 主体数组，最多5个
  "action": "",     // 动作：站立/坐/躺/跑/跳/走/拥抱/牵手/微笑/大笑/专注/回眸/其他
  "mood": "",       // 情绪：开心/严肃/搞怪/温馨/浪漫/孤独/震撼/宁静/活力/忧郁/其他
  "objects": []     // 显著物体数组，最多3个
}

规则：
1. 从枚举值中选择，无法匹配时用"其他"
2. 无法判断的字段留空字符串
3. 只输出JSON，不要其他文字"""

# 更新时的提示词
SYSTEM_PROMPT_UPDATE = """你是一个图片标签分析专家。请根据图片内容，检查并更新已有的标签JSON。

你将会收到：
1. 一张图片
2. 之前生成的标签JSON（可能不准确或不完整）

任务：
1. 重新仔细观察图片
2. 检查已有标签是否准确、完整
3. 如有必要，更新标签值
4. 输出更新后的完整JSON

JSON格式：
{
  "scene": "",      // 场景：海滩/城市/乡村/山景/雪地/森林/水域/室内/街道/天空/沙漠/草原/建筑/夜景/花园/其他
  "time": "",       // 时间：日出/上午/正午/下午/黄昏/日落/夜晚/黄金时刻/蓝色时刻/其他
  "weather": "",    // 天气：晴朗/多云/阴天/雨天/雪天/雾天/暴风雨/其他
  "tone": "",       // 色调：暖色调/冷色调/黑白/鲜艳/柔和/复古/其他
  "composition": "",// 构图：特写/中景/远景/俯拍/仰拍/平拍/侧面/正面/其他
  "subjects": [],   // 主体数组，最多5个
  "action": "",     // 动作：站立/坐/躺/跑/跳/走/拥抱/牵手/微笑/大笑/专注/回眸/其他
  "mood": "",       // 情绪：开心/严肃/搞怪/温馨/浪漫/孤独/震撼/宁静/活力/忧郁/其他
  "objects": []     // 显著物体数组，最多3个
}

规则：
1. 从枚举值中选择，无法匹配时用"其他"
2. 无法判断的字段留空字符串
3. 只输出JSON，不要其他文字
4. 如果已有标签准确，保持原样；如果不准确，修正它"""


# ====== 工具函数 ======

def format_text_with_newlines(text):
    """将文本中的 \n 转换为实际换行，并保留缩进"""
    if not text:
        return text
    # 将 \n 转换为实际换行
    return text.replace('\\n', '\n')


def load_existing_json(json_path):
    """读取已有的JSON文件，返回内容字典"""
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f'⚠️  读取JSON失败: {e}')
        return None


# ====== 核心函数 ======

def call_ai_api(image_path, debug=True, update_mode=False, existing_tags=None):
    """
    调用AI接口，返回原始内容和提取的JSON
    
    Args:
        image_path: 图片路径
        debug: 是否打印调试信息
        update_mode: 是否为更新模式
        existing_tags: 已有的标签（更新模式时使用）
    
    Returns:
        tuple: (raw_content, reasoning_content, tags_dict)
    """
    mime = MIME.get(Path(image_path).suffix.lower(), 'image/png')
    
    with open(image_path, 'rb') as f:
        b64 = base64.b64encode(f.read()).decode()

    # 选择提示词
    system_prompt = SYSTEM_PROMPT_UPDATE if update_mode else SYSTEM_PROMPT_NEW
    
    # 构建用户消息
    user_text = '输出JSON：'
    if update_mode and existing_tags:
        user_text = f'这是已有的标签，请检查并更新：\n{json.dumps(existing_tags, ensure_ascii=False, indent=2)}\n\n请重新分析图片，输出更新后的JSON：'

    payload = {
        'model': MODEL,
        'messages': [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': [
                {'type': 'text', 'text': user_text},
                {'type': 'image_url', 'image_url': {'url': f'data:{mime};base64,{b64}'}},
            ]}
        ],
        'max_tokens': MAX_TOKENS,
        'temperature': 0.0,
    }

    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json',
    }

    response = requests.post(URL, json=payload, headers=headers, timeout=TIMEOUT)
    response.raise_for_status()

    data = response.json()
    
    if not data.get('choices') or len(data['choices']) == 0:
        raise ValueError('API返回为空，没有choices字段')
    
    choice = data['choices'][0]
    message = choice.get('message', {})
    
    raw_content = message.get('content', '').strip()
    reasoning_content = message.get('reasoning_content', '').strip()

    # ====== 调试打印 ======
    if debug:
        if reasoning_content:
            # 将 \n 转换为实际换行显示
            formatted_reasoning = format_text_with_newlines(reasoning_content)
            print('\n\033[90m' + '─' * 60)
            print('📝 [reasoning_content]：')
            print(formatted_reasoning)
            print('─' * 60 + '\033[0m')
        
        if raw_content:
            print('\033[92m📝 [content]：\033[0m')
            try:
                parsed = json.loads(raw_content)
                print(json.dumps(parsed, ensure_ascii=False, indent=2))
            except:
                print(raw_content)
            print()

    # ====== 提取JSON ======
    tags = None
    search_content = raw_content
    
    try:
        tags = json.loads(raw_content)
        return raw_content, reasoning_content, tags
    except json.JSONDecodeError:
        pass

    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', search_content, re.DOTALL)
    if match:
        try:
            tags = json.loads(match.group(1))
            return raw_content, reasoning_content, tags
        except json.JSONDecodeError:
            pass

    start = search_content.find('{')
    end = search_content.rfind('}')
    if start != -1 and end != -1 and end > start:
        try:
            tags = json.loads(search_content[start:end+1])
            return raw_content, reasoning_content, tags
        except json.JSONDecodeError:
            pass

    return raw_content, reasoning_content, None


def process_image(image_path, force=False, quiet=False, debug=True, update=False):
    """处理单张图片"""
    image_path = Path(image_path)
    json_path = image_path.with_suffix(image_path.suffix + '.json')
    
    # 更新模式：必须存在JSON文件
    if update and not json_path.exists():
        if not quiet:
            print(f'❌ 更新模式需要JSON文件存在: {json_path.name}')
        return False
    
    # 检查是否已存在（非更新、非强制模式）
    if not update and json_path.exists() and not force:
        if not quiet:
            print(f'⏭️  跳过: {json_path.name}（使用 --force 覆盖，或 --update 更新）')
        return False

    if not quiet:
        mode_str = '🔄 更新' if update else '📝 新建'
        print(f'[{mode_str}] {image_path.name} ...', end=' ', flush=True)

    try:
        # 更新模式：读取已有JSON
        existing_data = None
        existing_tags = None
        if update:
            existing_data = load_existing_json(json_path)
            if existing_data:
                existing_tags = existing_data.get('tags', {})
        
        # 调用AI
        raw_content, reasoning_content, tags = call_ai_api(
            image_path, 
            debug=debug, 
            update_mode=update,
            existing_tags=existing_tags
        )
        
        # 构建结果
        result = {
            'source_file': image_path.name,
            'generated_at': datetime.now().isoformat(),
            'file_size_bytes': image_path.stat().st_size,
            'reasoning_content': reasoning_content,
            'raw_content': raw_content,
            'tags': tags if tags else {}
        }
        
        # 如果是更新模式，保留一些旧字段（如创建时间）
        if update and existing_data:
            if 'created_at' in existing_data:
                result['created_at'] = existing_data['created_at']
            if 'updated_at' not in result:
                result['updated_at'] = result['generated_at']

        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        if not quiet:
            if tags:
                print('✅ 完成')
            else:
                print('⚠️  完成（无JSON）')
        return True

    except Exception as e:
        if not quiet:
            print(f'❌ {e}')
        return False


def process_folder(folder_path, force=False, quiet=False, debug=True, update=False):
    """遍历文件夹"""
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
        if process_image(img, force=force, quiet=quiet, debug=debug, update=update):
            success += 1

    print(f'\n📊 成功: {success}/{len(images)}')


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)

    target = args[0]
    force = '--force' in args or '-f' in args
    quiet = '--quiet' in args or '-q' in args
    update = '--update' in args or '-u' in args
    debug = not quiet

    try:
        import requests
    except ImportError:
        print('❌ pip install requests')
        sys.exit(1)

    if not os.path.exists(target):
        print(f'❌ 不存在: {target}')
        sys.exit(1)

    try:
        if os.path.isdir(target):
            process_folder(target, force=force, quiet=quiet, debug=debug, update=update)
        else:
            process_image(target, force=force, quiet=quiet, debug=debug, update=update)
    except KeyboardInterrupt:
        print('\n⚠️  中断')


if __name__ == '__main__':
    main()
