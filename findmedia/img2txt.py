#!/usr/bin/env python3
"""
img2txt.py — 图片转文字（omlx / Qwen3.6-35B-A3B-4bit）

用法:
    python3 img2txt.py <图片文件> [提示词]

说明: 通过 curl 调用 macmini 的 omlx OpenAI 兼容接口
      /v1/chat/completions（更可靠地连到局域网主机）。
"""
import sys, subprocess, json, base64, os

HOST = 'macmini.local'
PORT = 12345
API_KEY = '52755227'
MODEL = 'Qwen3.6-35B-A3B-4bit'
URL = f'http://{HOST}:{PORT}/v1/chat/completions'
MIME = {'.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.webp': 'image/webp', '.gif': 'image/gif'}

# 未传提示词时的默认提示（多行）
DEFAULT_PROMPT = """请仔细描述这张图片：
1. 图片的总体内容/场景是什么？
2. 主要对象有哪些？
3. 它们的颜色、位置、数量分别如何？
4. 如果图中有文字，请读出来。"""


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    prompt = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PROMPT
    mime = MIME.get(os.path.splitext(path)[1].lower(), 'image/png')
    b64 = base64.b64encode(open(path, 'rb').read()).decode()

    body = json.dumps({
        'model': MODEL,
        'messages': [{'role': 'user', 'content': [
            {'type': 'text', 'text': prompt},
            {'type': 'image_url', 'image_url': {'url': f'data:{mime};base64,{b64}'}},
        ]}],
        'max_tokens': 512,
    })

    proc = subprocess.run(
        ['curl', '-s', '-m', '90', URL,
         '-H', f'Authorization: Bearer {API_KEY}',
         '-H', 'Content-Type: application/json',
         '-d', body],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        print(f'ERR: {proc.stderr.strip()}', file=sys.stderr)
        sys.exit(1)
    try:
        data = json.loads(proc.stdout)
        print(data['choices'][0]['message']['content'].strip())
    except Exception as e:
        print(f'ERR: 解析失败 {e} :: {proc.stdout[:300]}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
