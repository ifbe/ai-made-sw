// ========== 主入口和事件绑定 ==========

/** 准备页最短展示时间（对应 Android 的 MIN_SPLASH_MS / iOS 的 minDisplaySeconds） */
const MIN_SPLASH_MS = 600;

// ===== 登录矩形 =====
DOM.loginBtn.addEventListener('click', handleLogin);

[DOM.serverUrl, DOM.username, DOM.password].forEach((input) => {
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleLogin();
    });
    input.addEventListener('input', () => showLoginError(''));
});

// ===== 退出登录（左上角本地面板标题行最右边） =====
DOM.logoutBtn.addEventListener('click', handleLogout);

// ===== 左上角"我的位置"按钮 =====
DOM.btnMyLocation.addEventListener('click', () => {
    const pos = getCurrentPosition();
    if (pos && AppState.map) {
        AppState.map.setView([pos.lat, pos.lng], AppState.map.getZoom());
        debugLog('飞图到我的位置：' + pos.lat.toFixed(6) + ', ' + pos.lng.toFixed(6));
    } else {
        debugWarn('无法获取当前位置');
    }
});

// ===== 左上角"设目标"按钮（切换模式）=====
DOM.btnSetTarget.addEventListener('click', () => {
    if (!AppState.currentUser) {
        debugWarn('请先登录');
        return;
    }
    if (!AppState.socket || AppState.socket.readyState !== WebSocket.OPEN || !AppState.sessionToken) {
        debugWarn('无法设置目标：连接未就绪');
        return;
    }

    if (AppState.targetLat !== null && AppState.targetLng !== null) {
        // 已有目标 → 取消
        clearTarget();
    } else {
        // 无目标 → 把地图中心设成目标
        const center = AppState.map.getCenter();
        onMapClick(center.lat, center.lng);
    }
});

// 页面可见性检测：回到前台时补一次重连
document.addEventListener('visibilitychange', () => {
    if (!document.hidden && AppState.currentUser && AppState.savedPassword && AppState.autoReconnectEnabled) {
        reconnect();
    }
});

// 窗口大小变化时修复地图，并重排日志矩形
window.addEventListener('resize', () => {
    if (AppState.map) {
        setTimeout(() => AppState.map.invalidateSize(), 100);
    }
    LogPanel.render();
});

// 页面关闭前清理
window.addEventListener('beforeunload', () => {
    if (AppState.watchId !== null) {
        navigator.geolocation.clearWatch(AppState.watchId);
    }
    if (AppState.socket) {
        AppState.socket.close();
    }
});

// ========== 准备页 ==========

/**
 * 只做启动准备：读一遍本地保存的服务器地址/用户名，保证最短展示时间，
 * 满足条件后直接进地图页（登录表单在地图页顶部的登录矩形里）。
 */
function startPrepare() {
    let prepDone = false;
    let minTimeElapsed = false;
    let finished = false;

    AppLog.i('正在准备…');

    function goIfReady() {
        if (finished || !prepDone || !minTimeElapsed) return;
        finished = true;
        enterMap();
    }

    try {
        loadPrefs();
    } catch (e) {
        AppLog.w('本地设置读取失败：' + describe(e));
    }
    prepDone = true;
    AppLog.i('启动准备完成');
    goIfReady();

    setTimeout(() => {
        minTimeElapsed = true;
        goIfReady();
    }, MIN_SPLASH_MS);
}

/** 准备完成：收起准备页，地图页开始工作 */
function enterMap() {
    DOM.splashPage.style.display = 'none';
    DOM.mapPage.style.display = 'block';
    AppLog.i('准备完成，进入地图');

    applyAuthUi();   // 未登录 → 显示登录矩形
    initMap();
    startGPSWatch();
    initSocket();
    LogPanel.render();
    debugLog('应用初始化完成');
}

// 日志矩形（左下角，和 Android 一样始终可见）
LogPanel.init();

// 启动
startPrepare();
