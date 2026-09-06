#!/usr/bin/env python3
"""
findmedia.py — 单文件媒体索引 + Web 检索

用法:
  python3 findmedia.py                       # 打印 help
  python3 findmedia.py --dir=PATH            # 索引 + 起服务（默认 127.0.0.1:8765）
  python3 findmedia.py --dir=PATH --host=0.0.0.0 --port=9000

约定:
  所有媒体类型的 sidecar 均为 <name>.<ext>.json
  - 图片: img2json.py 现有产物（双扩展名）
  - 音频 / 视频: 后续脚本产出（格式同图片，含 tags 字段）

只读现有 JSON，不调用 AI / ffmpeg / 任何 subprocess。
"""
from __future__ import annotations
import sys
import json
import sqlite3
import argparse
import urllib.parse
import mimetypes
from pathlib import Path
from datetime import datetime, timedelta
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# ====== 路径 ======
ROOT = Path(__file__).parent.resolve()
WEB_DIR = ROOT / 'web'
DB_PATH = ROOT / 'index.db'

# 由 main() 设置；供 POST /api/reindex 使用
INDEX_ROOT: Path | None = None

# ====== 媒体类型 ======
IMAGE_EXT = {'.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp', '.tiff', '.heic'}
AUDIO_EXT = {'.wav', '.mp3', '.m4a', '.flac', '.ogg', '.aac', '.opus'}
VIDEO_EXT = {'.mp4', '.mov', '.mkv', '.webm', '.avi', '.m4v', '.flv', '.wmv'}
MEDIA_EXT = IMAGE_EXT | AUDIO_EXT | VIDEO_EXT

# JSON sidecar 命名约定：
#   <媒体文件名>.<媒体扩展名>.json
#   例：image.jpg → image.jpg.json
#       clip.mp4 → clip.mp4.json
#       song.mp3 → song.mp3.json
# 排除通用 .json（如 messages.json / manifest.json 等非媒体 sidecar）


def classify(path: Path) -> str | None:
    ext = path.suffix.lower()
    if ext in IMAGE_EXT:
        return 'image'
    if ext in AUDIO_EXT:
        return 'audio'
    if ext in VIDEO_EXT:
        return 'video'
    return None


def _sidecar_for(media_path: Path) -> Path | None:
    """按 <name>.<media_ext>.json 约定求 sidecar 路径；非媒体扩展名返回 None

    示例：
      /x/a.jpg     → /x/a.jpg.json
      /x/clip.mp4  → /x/clip.mp4.json
      /x/foo.exe   → None（不是媒体文件）
      /x/messages.json → None（本身就是 .json，不是媒体 sidecar）
    """
    if media_path.suffix.lower() not in MEDIA_EXT:
        return None
    return media_path.with_suffix(media_path.suffix + '.json')


# ====== 数据库 ======
SCHEMA = '''
CREATE TABLE IF NOT EXISTS media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,
    size INTEGER,
    mtime INTEGER,
    has_json INTEGER DEFAULT 0,
    indexed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_media_type ON media(type);

CREATE TABLE IF NOT EXISTS tags (
    media_id INTEGER REFERENCES media(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT
);
CREATE INDEX IF NOT EXISTS idx_tags_key ON tags(key);
CREATE INDEX IF NOT EXISTS idx_tags_value ON tags(value);
CREATE INDEX IF NOT EXISTS idx_tags_media ON tags(media_id);
'''


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def index_folder(root: Path, db_path: Path) -> dict:
    """扫描 root 下的媒体文件，按 sidecar 约定读取 JSON，写入 db"""
    conn = init_db(db_path)
    c = conn.cursor()
    stats = {'total': 0, 'indexed': 0, 'with_json': 0, 'skipped': 0, 'removed': 0}

    # 清理 root 下已经丢失的文件（避免脏数据）
    root_prefix = str(root)
    stale = c.execute(
        'SELECT id, path FROM media WHERE path LIKE ?', (root_prefix + '%',)).fetchall()
    for row in stale:
        mid = row['id']
        path_str = row['path']
        if not Path(path_str).exists():
            c.execute('DELETE FROM media WHERE id=?', (mid,))
            stats['removed'] += 1
    if stats['removed']:
        conn.commit()

    for path in sorted(root.rglob('*')):
        if not path.is_file():
            continue
        mtype = classify(path)
        if not mtype:
            continue
        stats['total'] += 1

        cur_mtime = int(path.stat().st_mtime)
        cur_size = path.stat().st_size
        json_sidecar = _sidecar_for(path)
        json_mtime = int(json_sidecar.stat().st_mtime) if (json_sidecar and json_sidecar.exists()) else 0
        # 以 media 和 sidecar 中较大的 mtime 为有效版本号
        # —— 这样光改 .json 也能触发重索引
        effective_mtime = max(cur_mtime, json_mtime)

        existing = c.execute('SELECT id, mtime FROM media WHERE path=?',
                             (str(path),)).fetchone()

        # mtime 未变 → 跳过
        if existing and existing['mtime'] == effective_mtime:
            stats['skipped'] += 1
            continue

        # upsert media
        now = int(datetime.now().timestamp())
        if existing:
            mid = existing['id']
            c.execute('UPDATE media SET type=?, size=?, mtime=?, indexed_at=? WHERE id=?',
                      (mtype, cur_size, effective_mtime, now, mid))
        else:
            c.execute('INSERT INTO media (path, type, size, mtime, indexed_at) '
                      'VALUES (?, ?, ?, ?, ?)',
                      (str(path), mtype, cur_size, effective_mtime, now))
            mid = c.lastrowid
        stats['indexed'] += 1

        # JSON sidecar（按 <name>.<media_ext>.json 约定；非媒体扩展名一律 None）
        json_sidecar = _sidecar_for(path)
        has_json = 0
        if json_sidecar and json_sidecar.exists():
            try:
                with open(json_sidecar, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if not isinstance(data, dict):
                    raise ValueError('JSON 顶层不是对象')
                tags = data.get('tags', {}) or {}
                if not isinstance(tags, dict):
                    raise ValueError('tags 字段不是对象')
                c.execute('DELETE FROM tags WHERE media_id=?', (mid,))
                rows = []
                for k, v in tags.items():
                    if isinstance(v, list):
                        for item in v:
                            if item is not None and str(item).strip():
                                rows.append((mid, str(k), str(item)))
                    elif v is not None and str(v).strip():
                        rows.append((mid, str(k), str(v)))
                if rows:
                    c.executemany(
                        'INSERT INTO tags (media_id, key, value) VALUES (?, ?, ?)', rows)
                has_json = 1
                stats['with_json'] += 1
            except Exception as e:
                print(f'  ⚠️  {json_sidecar.name}: {e}', file=sys.stderr)

        c.execute('UPDATE media SET has_json=? WHERE id=?', (has_json, mid))

    conn.commit()
    conn.close()
    return stats


def print_subjects_summary(db_path: Path):
    """打印扫到的 subject (key) + object (value) 汇总

    数据源：sidecar.json 的 tags 段（写入 DB tags 表）
    排序：key 按出现文件数降序；同 key 内 value 按文件数降序
    """
    if not db_path.exists():
        return
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        # 每个 (key, value) 的文件数
        rows = conn.execute('''
            SELECT key, value, COUNT(DISTINCT media_id) AS cnt
            FROM tags
            GROUP BY key, value
            ORDER BY key, cnt DESC, value ASC
        ''').fetchall()

        if not rows:
            print('\n📋 subject/object 汇总：（无 tag 数据）')
            return

        # 按 key 分组
        by_key: dict = {}
        for r in rows:
            by_key.setdefault(r['key'], []).append((r['value'], r['cnt']))

        # 每个 key 占多少个文件（独立 media_id 数）
        key_files: dict = {}
        for k in by_key:
            fc = conn.execute(
                'SELECT COUNT(DISTINCT media_id) FROM tags WHERE key=?', (k,)
            ).fetchone()[0]
            key_files[k] = fc

        # 按 key 文件数降序排
        ordered = sorted(by_key.keys(), key=lambda k: -key_files[k])

        print(f'\n📋 发现 {len(by_key)} 个 key（subject 列表，来自 sidecar.json 的 tags 段）：')
        for k in ordered:
            values = by_key[k]
            fc = key_files[k]
            vc = len(values)
            print(f'   {k:<14} {fc:>4} 文件 · {vc:>3} 值')
            for val, cnt in values:
                print(f'      {val} × {cnt}')
    finally:
        conn.close()


# ====== HTTP ======
class Handler(BaseHTTPRequestHandler):
    server_version = 'findmedia/1.0'

    def log_message(self, fmt, *args):
        sys.stderr.write(
            f'[{datetime.now().isoformat(timespec="seconds")}] '
            f'{self.address_string()} {fmt % args}\n')

    # ---------- 工具 ----------
    def _skip_body(self) -> bool:
        return self.command == 'HEAD'

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        if not self._skip_body():
            self.wfile.write(body)

    def _file(self, path: Path, content_type: str | None = None):
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
            return
        ct = content_type or mimetypes.guess_type(str(path))[0] or 'application/octet-stream'
        self.send_response(200)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        if not self._skip_body():
            self.wfile.write(data)

    def _db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        return conn

    # ---------- 路由 ----------
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == '/api/reindex':
            return self._api_reindex()
        self.send_response(404)
        self.end_headers()

    def do_HEAD(self):
        # HEAD 与 GET 共用逻辑，仅不写 body
        self.do_GET()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        if path in ('/', '/index.html'):
            return self._file(WEB_DIR / 'index.html', 'text/html; charset=utf-8')

        if path.startswith('/static/'):
            rel = path[len('/static/'):]
            if '..' in rel or rel.startswith('/'):
                self.send_response(400)
                self.end_headers()
                return
            return self._file(WEB_DIR / rel)

        if path == '/api/stats':
            return self._api_stats()
        if path == '/api/keys':
            return self._api_keys()
        if path == '/api/search':
            return self._api_search(qs)
        if path == '/api/timeline':
            return self._api_timeline()
        if path == '/api/fs':
            return self._api_fs(qs)

        if path.startswith('/api/media/'):
            try:
                mid = int(path[len('/api/media/'):].split('/')[0])
            except ValueError:
                return self._json({'error': 'bad id'}, 400)
            return self._api_media_detail(mid)

        if path.startswith('/raw/'):
            try:
                mid = int(path[len('/raw/'):].split('/')[0])
            except ValueError:
                return self._json({'error': 'bad id'}, 400)
            return self._raw(mid)

        self.send_response(404)
        self.end_headers()

    # ---------- API ----------
    def _api_timeline(self):
        """按时间分桶返回媒体分布，供底部时间线渲染
        自适应桶：>200天→月，>50天→周，否则日
        """
        if not DB_PATH.exists():
            return self._json({'error': f'db not found: {DB_PATH}'}, 503)
        conn = self._db()
        try:
            rows = conn.execute(
                'SELECT id, mtime, type FROM media ORDER BY mtime').fetchall()
            if not rows:
                return self._json({
                    'min_ts': 0, 'max_ts': 0, 'bucket': 'day', 'points': []
                })

            min_ts = min(r['mtime'] for r in rows)
            max_ts = max(r['mtime'] for r in rows)

            # 决定桶大小
            unique_days = len({
                (datetime.fromtimestamp(r['mtime']).year,
                 datetime.fromtimestamp(r['mtime']).month,
                 datetime.fromtimestamp(r['mtime']).day)
                for r in rows
            })
            if unique_days > 200:
                bucket = 'month'
            elif unique_days > 50:
                bucket = 'week'
            else:
                bucket = 'day'

            def bucket_key(mtime: int) -> int:
                dt = datetime.fromtimestamp(mtime)
                if bucket == 'day':
                    return int(datetime(dt.year, dt.month, dt.day).timestamp())
                if bucket == 'week':
                    monday = dt - timedelta(days=dt.weekday())
                    monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)
                    return int(monday.timestamp())
                # month
                return int(datetime(dt.year, dt.month, 1).timestamp())

            groups: dict = {}
            for r in rows:
                groups.setdefault(bucket_key(r['mtime']), []).append(r)

            points = []
            for ts in sorted(groups.keys()):
                items = groups[ts]
                rep = items[0]  # 取该桶首个作为代表
                dt = datetime.fromtimestamp(ts)
                if bucket == 'day':
                    date_str = dt.strftime('%Y-%m-%d')
                elif bucket == 'week':
                    date_str = 'Week ' + dt.strftime('%Y-%m-%d')
                else:
                    date_str = dt.strftime('%Y-%m')
                points.append({
                    'ts': ts,
                    'date': date_str,
                    'media_id': rep['id'],
                    'count': len(items),
                    'type': rep['type'],
                })

            return self._json({
                'min_ts': min_ts,
                'max_ts': max_ts,
                'bucket': bucket,
                'points': points,
            })
        finally:
            conn.close()

    def _api_fs(self, qs):
        """列出指定路径下的条目（文件树）
        qs: path=相对 INDEX_ROOT 的子路径（默认空=根）
        """
        if INDEX_ROOT is None:
            return self._json({'error': 'no root'}, 400)

        root_resolved = INDEX_ROOT.resolve()
        rel = qs.get('path', [''])[0].lstrip('/')
        abs_path = (INDEX_ROOT / rel).resolve() if rel else root_resolved

        # 防越权
        try:
            abs_path.relative_to(root_resolved)
        except ValueError:
            return self._json({'error': 'path escapes root'}, 403)
        if not abs_path.exists():
            return self._json({'error': 'not found'}, 404)
        if not abs_path.is_dir():
            return self._json({'error': 'not a directory'}, 400)

        # 一次性查 root 下所有 media，构建 path → 行 的字典
        conn = self._db()
        try:
            rows = conn.execute(
                "SELECT id, type, has_json, path FROM media WHERE path LIKE ?",
                (str(root_resolved) + '%',)).fetchall()
            by_path = {r['path']: r for r in rows}
        finally:
            conn.close()
        path_set = set(by_path.keys())

        # 列目录
        try:
            children = list(abs_path.iterdir())
        except PermissionError as e:
            return self._json({'error': f'permission denied: {e}'}, 403)

        def sort_key(e):
            try:
                is_dir = e.is_dir()
            except OSError:
                is_dir = False
            return (not is_dir, e.name.lower())

        entries = []
        for entry in sorted(children, key=sort_key):
            try:
                st = entry.stat()
            except OSError:
                continue
            item = {'name': entry.name, 'type': 'dir' if entry.is_dir() else 'file'}
            entry_str = str(entry)
            if entry.is_file():
                info = by_path.get(entry_str)
                if info:
                    item['media_id'] = info['id']
                    item['media_type'] = info['type']
                    item['has_json'] = bool(info['has_json'])
                item['size'] = st.st_size
                item['mtime'] = int(st.st_mtime)
            else:
                prefix = entry_str + '/'
                has_media = any(p == entry_str or p.startswith(prefix) for p in path_set)
                item['has_media'] = has_media
            entries.append(item)

        return self._json({
            'root': str(root_resolved),
            'path': rel,
            'entries': entries,
        })

    def _api_reindex(self):
        """重新扫描启动时指定的文件夹（供前端按钮调用）"""
        if INDEX_ROOT is None:
            return self._json({'error': 'no index root configured'}, 400)
        try:
            stats = index_folder(INDEX_ROOT, DB_PATH)
            print_subjects_summary(DB_PATH)
            return self._json({'ok': True, 'stats': stats, 'root': str(INDEX_ROOT)})
        except Exception as e:
            return self._json({'ok': False, 'error': str(e)}, 500)

    def _api_stats(self):
        if not DB_PATH.exists():
            return self._json({'error': f'db not found: {DB_PATH}'}, 503)
        conn = self._db()
        try:
            row = conn.execute('''
                SELECT
                    COUNT(*) AS total,
                    COALESCE(SUM(type='image'), 0) AS images,
                    COALESCE(SUM(type='audio'), 0) AS audio,
                    COALESCE(SUM(type='video'), 0) AS video,
                    COALESCE(SUM(has_json), 0) AS with_json
                FROM media
            ''').fetchone()
            d = dict(row)
            d['db'] = str(DB_PATH)
            return self._json(d)
        finally:
            conn.close()

    def _api_keys(self):
        """返回所有 tag key 及其取值集合（供前端构建下拉）"""
        conn = self._db()
        try:
            keys: dict[str, set[str]] = {}
            for row in conn.execute('SELECT key, value FROM tags ORDER BY key, value'):
                keys.setdefault(row['key'], set()).add(row['value'])
            return self._json({k: sorted(v) for k, v in keys.items()})
        finally:
            conn.close()

    def _api_search(self, qs):
        q = (qs.get('q', [''])[0] or '').strip()
        mtype = qs.get('type', [''])[0]
        tag_filters = qs.get('tag', [])  # 多个 ?tag=key:value
        path_present = 'path' in qs
        path = qs.get('path', [''])[0].strip().strip('/')
        tmin_s = qs.get('tmin', [''])[0]
        tmax_s = qs.get('tmax', [''])[0]
        has_json_filter = qs.get('has_json', [''])[0] == '1'
        limit = max(1, min(500, int(qs.get('limit', ['200'])[0])))

        conn = self._db()
        try:
            where: list[str] = []
            params: list = []

            if mtype in ('image', 'audio', 'video'):
                where.append('m.type = ?')
                params.append(mtype)

            if has_json_filter:
                where.append('m.has_json = 1')

            for tf in tag_filters:
                if ':' in tf:
                    k, v = tf.split(':', 1)
                    where.append('EXISTS (SELECT 1 FROM tags t '
                                 'WHERE t.media_id=m.id AND t.key=? AND t.value=?)')
                    params.extend([k, v])

            if q:
                like = f'%{q}%'
                ids: set[int] = set()
                for r in conn.execute(
                        'SELECT id FROM media WHERE path LIKE ?', (like,)):
                    ids.add(r['id'])
                for r in conn.execute(
                        'SELECT DISTINCT media_id AS id FROM tags WHERE value LIKE ?', (like,)):
                    ids.add(r['id'])
                if not ids:
                    return self._json({'hits': [], 'total': 0, 'q': q})
                where.append(f'm.id IN ({",".join("?" * len(ids))})')
                params.extend(list(ids))

            # 路径筛选：本层媒体（不递归子文件夹）
            if path_present:
                # 有 path 参数就应用路径筛选；空 path 表示"根目录本层"
                abs_path = INDEX_ROOT.resolve() if not path else (INDEX_ROOT / path).resolve()
                try:
                    abs_path.relative_to(INDEX_ROOT.resolve())
                except ValueError:
                    return self._json({'hits': [], 'total': 0, 'q': q, 'path': path, 'error': 'path escapes root'})
                abs_str = str(abs_path)
                where.append("m.path LIKE ?")
                params.append(abs_str + '/%')
                where.append("m.path NOT LIKE ?")
                params.append(abs_str + '/%/%')

            # 时间范围筛选（用于时间轴选区）
            if tmin_s:
                try:
                    where.append('m.mtime >= ?')
                    params.append(int(tmin_s))
                except ValueError:
                    pass
            if tmax_s:
                try:
                    where.append('m.mtime <= ?')
                    params.append(int(tmax_s))
                except ValueError:
                    pass

            where_sql = ('WHERE ' + ' AND '.join(where)) if where else ''
            sql = (f'SELECT m.id, m.path, m.type, m.size, m.mtime, m.has_json '
                   f'FROM media m {where_sql} ORDER BY m.mtime DESC LIMIT ?')
            params.append(limit)
            rows = conn.execute(sql, params).fetchall()

            hits = []
            for r in rows:
                d = dict(r)
                d['filename'] = Path(d['path']).name
                tag_rows = conn.execute(
                    'SELECT key, value FROM tags WHERE media_id=?', (d['id'],)).fetchall()
                d['tags'] = [dict(t) for t in tag_rows]
                hits.append(d)

            return self._json({'hits': hits, 'total': len(hits), 'q': q, 'path': path})
        finally:
            conn.close()

    def _api_media_detail(self, mid: int):
        conn = self._db()
        try:
            row = conn.execute('SELECT * FROM media WHERE id=?', (mid,)).fetchone()
            if not row:
                return self._json({'error': 'not found'}, 404)
            d = dict(row)
            d['filename'] = Path(d['path']).name
            tag_rows = conn.execute(
                'SELECT key, value FROM tags WHERE media_id=?', (mid,)).fetchall()
            d['tags'] = [dict(t) for t in tag_rows]
            return self._json(d)
        finally:
            conn.close()

    def _raw(self, mid: int):
        """流式发送原始文件，支持 HTTP Range"""
        conn = self._db()
        try:
            row = conn.execute('SELECT path FROM media WHERE id=?', (mid,)).fetchone()
        finally:
            conn.close()
        if not row:
            self.send_response(404)
            self.end_headers()
            return
        path = Path(row['path'])
        if not path.exists():
            self.send_response(404)
            self.end_headers()
            return
        # Content-Disposition: inline + 双格式 filename（兼容中文）
        # filename 是 ASCII 兑底，filename* 是 UTF-8 编码的现代版本
        fname = path.name
        ascii_safe = fname.encode('ascii', 'replace').decode('ascii')
        disposition = f'inline; filename="{ascii_safe}"; filename*=UTF-8\'\'{urllib.parse.quote(fname)}'

        size = path.stat().st_size
        ct = mimetypes.guess_type(str(path))[0] or 'application/octet-stream'
        range_header = self.headers.get('Range')

        try:
            if range_header:
                units, _, rng = range_header.partition('=')
                if units != 'bytes':
                    raise ValueError('only bytes')
                s, _, e = rng.partition('-')
                start = int(s) if s else 0
                end = int(e) if e else size - 1
                if start >= size or end >= size or start > end:
                    self.send_response(416)
                    self.send_header('Content-Range', f'bytes */{size}')
                    self.end_headers()
                    return
                length = end - start + 1
                self.send_response(206)
                self.send_header('Content-Type', ct)
                self.send_header('Content-Length', str(length))
                self.send_header('Content-Range', f'bytes {start}-{end}/{size}')
                self.send_header('Accept-Ranges', 'bytes')
                self.send_header('Content-Disposition', disposition)
                self.end_headers()
                if self._skip_body():
                    return
                with open(path, 'rb') as f:
                    f.seek(start)
                    remaining = length
                    while remaining > 0:
                        chunk = f.read(min(64 * 1024, remaining))
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
            else:
                self.send_response(200)
                self.send_header('Content-Type', ct)
                self.send_header('Content-Length', str(size))
                self.send_header('Accept-Ranges', 'bytes')
                self.send_header('Content-Disposition', disposition)
                self.end_headers()
                if self._skip_body():
                    return
                with open(path, 'rb') as f:
                    while True:
                        chunk = f.read(64 * 1024)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass


# ====== CLI ======
def main():
    parser = argparse.ArgumentParser(
        prog='findmedia',
        description='findmedia — 索引一个文件夹里的媒体文件（图/音/视），按 sidecar JSON 打标签，启动 Web 检索'
    )
    parser.add_argument('--dir', help='要索引的文件夹路径')
    parser.add_argument('--host', default='127.0.0.1', help='HTTP 监听地址（默认 127.0.0.1）')
    parser.add_argument('--port', type=int, default=8765, help='HTTP 端口（默认 8765）')

    # 无参数 → 只打印 help
    if len(sys.argv) == 1:
        parser.print_help()
        return

    args = parser.parse_args()

    if not args.dir:
        parser.error('--dir is required')

    folder = Path(args.dir).expanduser().resolve()
    if not folder.exists() or not folder.is_dir():
        print(f'❌ 文件夹不存在: {args.dir}')
        sys.exit(1)

    # 供 POST /api/reindex 使用
    global INDEX_ROOT
    INDEX_ROOT = folder

    print(f'📁 索引: {folder}')
    stats = index_folder(folder, DB_PATH)
    print(f'   总 {stats["total"]} · 新索引 {stats["indexed"]} · '
          f'带 JSON {stats["with_json"]} · 跳过未变 {stats["skipped"]} · '
          f'清理 {stats["removed"]}')
    print_subjects_summary(DB_PATH)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f'🌐 http://{args.host}:{args.port}')
    print(f'   DB:  {DB_PATH}')
    print('   Ctrl-C 退出')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n👋 bye')
        server.server_close()


if __name__ == '__main__':
    main()
