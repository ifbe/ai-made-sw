// ========== 工具函数 ==========

/** 界面设置（服务器地址 / 用户名）在 localStorage 里的键 */
const UI_PREFS_KEY = 'locate.ui';

/**
 * 写一条日志。
 *
 * 和 Android 的 AppLog 一样：既打到浏览器控制台，也进左下角日志矩形的缓冲。
 * 界面只显示应用自己写的消息，不镜像 console。
 */
function debugLog(...args) {
    AppLog.i(args.map(describe).join(' '));
}

function debugWarn(...args) {
    AppLog.w(args.map(describe).join(' '));
}

function debugError(...args) {
    AppLog.e(args.map(describe).join(' '));
}

function describe(value) {
    if (value instanceof Error) return value.message || String(value);
    if (value === null || value === undefined) return String(value);
    if (typeof value === 'object') {
        try {
            return JSON.stringify(value);
        } catch (e) {
            return String(value);
        }
    }
    return String(value);
}

// ========== 服务器地址 ==========

/** 补全成 http(s)://host 形式，去掉结尾的斜杠；空则用本页同源地址 */
function normalizeServerUrl(raw) {
    let url = (raw || '').trim();
    if (url === '') return SAME_ORIGIN;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) {
        url = (window.location.protocol === 'https:' ? 'https://' : 'http://') + url;
    }
    return url.replace(/\/+$/, '');
}

/** HTTP 接口地址 */
function apiUrl(path) {
    return normalizeServerUrl(AppState.serverUrl) + path;
}

/** WebSocket 地址（和原来的保持一致：只取 host） */
function wsUrl() {
    const url = new URL(normalizeServerUrl(AppState.serverUrl));
    return (url.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + url.host;
}

/** 等待 WebSocket 连上，超时就报错（原来的写法没有超时，服务器不通会一直转圈） */
function waitForSocket(timeoutMs = 8000) {
    return new Promise((resolve, reject) => {
        const started = Date.now();
        const timer = setInterval(() => {
            if (AppState.socket && AppState.socket.readyState === WebSocket.OPEN) {
                clearInterval(timer);
                resolve();
            } else if (Date.now() - started > timeoutMs) {
                clearInterval(timer);
                reject(new Error('连接服务器超时'));
            }
        }, 100);
    });
}

// ========== 界面设置读写 ==========

function loadPrefs() {
    const saved = readPrefs();
    AppState.serverUrl = normalizeServerUrl(saved.serverUrl || SAME_ORIGIN);
    DOM.serverUrl.value = AppState.serverUrl;
    DOM.username.value = saved.username || '';
}

function savePrefs() {
    try {
        localStorage.setItem(UI_PREFS_KEY, JSON.stringify({
            serverUrl: AppState.serverUrl,
            username: DOM.username.value.trim()
        }));
    } catch (e) {
        // 隐私模式下写不进去，忽略
    }
}

function readPrefs() {
    try {
        const raw = localStorage.getItem(UI_PREFS_KEY);
        return raw ? JSON.parse(raw) : {};
    } catch (e) {
        return {};
    }
}

// ========== 加密 ==========

function sha256(message) {
    return CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);
}

function hmacSha256(key, message) {
    return CryptoJS.HmacSHA256(message, key).toString(CryptoJS.enc.Hex);
}

// WGS-84 转 GCJ-02
function wgs84_to_gcj02(wgsLat, wgsLng) {
    const a = 6378245.0;
    const ee = 0.00669342162296594323;

    function transformLat(x, y) {
        let ret = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y + 0.1 * x * y + 0.2 * Math.sqrt(Math.abs(x));
        ret += (20.0 * Math.sin(6.0 * x * Math.PI) + 20.0 * Math.sin(2.0 * x * Math.PI)) * 2.0 / 3.0;
        ret += (20.0 * Math.sin(y * Math.PI) + 40.0 * Math.sin(y / 3.0 * Math.PI)) * 2.0 / 3.0;
        ret += (160.0 * Math.sin(y / 12.0 * Math.PI) + 320 * Math.sin(y * Math.PI / 30.0)) * 2.0 / 3.0;
        return ret;
    }

    function transformLng(x, y) {
        let ret = 300.0 + x + 2.0 * y + 0.1 * x * x + 0.1 * x * y + 0.1 * Math.sqrt(Math.abs(x));
        ret += (20.0 * Math.sin(6.0 * x * Math.PI) + 20.0 * Math.sin(2.0 * x * Math.PI)) * 2.0 / 3.0;
        ret += (20.0 * Math.sin(x * Math.PI) + 40.0 * Math.sin(x / 3.0 * Math.PI)) * 2.0 / 3.0;
        ret += (150.0 * Math.sin(x / 12.0 * Math.PI) + 300.0 * Math.sin(x / 30.0 * Math.PI)) * 2.0 / 3.0;
        return ret;
    }

    let dLat = transformLat(wgsLng - 105.0, wgsLat - 35.0);
    let dLng = transformLng(wgsLng - 105.0, wgsLat - 35.0);
    let radLat = wgsLat / 180.0 * Math.PI;
    let magic = Math.sin(radLat);
    magic = 1 - ee * magic * magic;
    let sqrtMagic = Math.sqrt(magic);
    dLat = (dLat * 180.0) / ((a * (1 - ee)) / (magic * sqrtMagic) * Math.PI);
    dLng = (dLng * 180.0) / (a / sqrtMagic * Math.cos(radLat) * Math.PI);

    return {
        lat: wgsLat + dLat,
        lng: wgsLng + dLng
    };
}
