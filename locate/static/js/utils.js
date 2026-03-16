// ========== 工具函数 ==========
function debugLog(...args) {
    const timestamp = new Date().toLocaleTimeString();
    const message = `[${timestamp}] ${args.join(' ')}`;
    console.log(message);

    if (AppState.debugEnabled) {
        const line = document.createElement('div');
        line.textContent = message;
        DOM.debugPanel.appendChild(line);
        DOM.debugPanel.scrollTop = DOM.debugPanel.scrollHeight;

        while (DOM.debugPanel.children.length > 100) {
            DOM.debugPanel.removeChild(DOM.debugPanel.firstChild);
        }
    }
}

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
