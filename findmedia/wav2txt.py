#!/usr/bin/env python3
"""
wav2txt.py — 语音文件转文字（omlx / Qwen3-ASR-0.6B-4bit）

用法:
    python3 wav2txt.py <音频文件.wav>

说明: 通过 curl 调用 macmini 的 omlx OpenAI 兼容接口
      /v1/audio/transcriptions（更可靠地连到局域网主机）。
"""
import sys, subprocess, json

HOST = 'macmini.local'
PORT = 12345
API_KEY = '52755227'
MODEL = 'Qwen3-ASR-0.6B-4bit'
URL = f'http://{HOST}:{PORT}/v1/audio/transcriptions'


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]

    proc = subprocess.run(
        ['curl', '-s', '-m', '60', URL,
         '-H', f'Authorization: Bearer {API_KEY}',
         '-F', f'file=@{path}',
         '-F', f'model={MODEL}',
         '-F', 'stream=true'],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        print(f'ERR: {proc.stderr.strip()}', file=sys.stderr)
        sys.exit(1)

    text = ''
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith('data:'):
            continue
        payload = line[5:].strip()
        if not payload or payload == '[DONE]':
            continue
        try:
            obj = json.loads(payload)
        except Exception:
            continue
        if isinstance(obj, dict):
            if isinstance(obj.get('text'), str):
                text = obj['text']
            elif isinstance(obj.get('delta'), str):
                text += obj['delta']
    # 非 SSE（json）兜底；无法解析则视为空结果
    if not text:
        try:
            obj = json.loads(proc.stdout)
            text = obj.get('text', '') if isinstance(obj, dict) else ''
        except Exception:
            text = ''
    print(text.strip())


if __name__ == '__main__':
    main()
