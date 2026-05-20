// ========== 主入口和事件绑定 ==========

// 调试面板切换
DOM.debugToggle.addEventListener('click', () => {
    DOM.debugPanel.classList.toggle('show');
    DOM.debugToggle.textContent = DOM.debugPanel.classList.contains('show') ? '🔧 隐藏日志' : '🔧 调试日志';
});

// 登录/登出事件
DOM.loginBtn.addEventListener('click', handleLogin);
// DOM.logoutBtn.addEventListener('click', handleLogout);

// 回车登录
DOM.password.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleLogin();
});
DOM.username.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleLogin();
});

// ===== 左上角"我的位置"按钮 =====
DOM.btnMyLocation.addEventListener('click', () => {
    const pos = getCurrentPosition();
    if (pos && AppState.map) {
        AppState.map.setView([pos.lat, pos.lng], AppState.map.getZoom());
        debugLog('飞图到我的位置:', pos.lat, pos.lng);
    } else {
        debugLog('无法获取当前位置');
    }
});

// ===== 左上角"设目标"按钮（切换模式）=====
DOM.btnSetTarget.addEventListener('click', () => {
    if (!AppState.currentUser) {
        alert('请先登录');
        return;
    }
    if (!AppState.socket || AppState.socket.readyState !== WebSocket.OPEN || !AppState.sessionToken) {
        debugLog('无法设置目标: 连接未就绪');
        return;
    }

    if (AppState.targetLat !== null && AppState.targetLng !== null) {
        // 已有目标 → 取消
        AppState.targetLat = null;
        AppState.targetLng = null;
        clearSelfTarget();
        debugLog('取消目标');
        AppState.socket.send(JSON.stringify({
            type: 'update_target',
            token: AppState.sessionToken,
            username: AppState.currentUser,
            target_lat: null,
            target_lng: null
        }));
    } else {
        // 无目标 → 设目标
        const center = AppState.map.getCenter();
        AppState.targetLat = center.lat;
        AppState.targetLng = center.lng;
        debugLog('设置目标:', AppState.targetLat, AppState.targetLng);
        updateSelfTarget();
        AppState.socket.send(JSON.stringify({
            type: 'update_target',
            token: AppState.sessionToken,
            username: AppState.currentUser,
            target_lat: AppState.targetLat,
            target_lng: AppState.targetLng
        }));
    }
});

// ===== 重连按钮 =====
DOM.autoReconnectBtn.addEventListener('click', () => {
    debugLog('开启自动重连');
    AppState.autoReconnectEnabled = true;
    if (AppState.currentUser && AppState.savedPassword) {
        reconnect();
    }
});

DOM.manualReconnectBtn.addEventListener('click', () => {
    debugLog('手动触发重连');
    if (AppState.currentUser && AppState.savedPassword) {
        reconnect();
    } else if (AppState.currentUser) {
        handleLogout();
        alert('密码已丢失，请重新登录');
    }
});

// 页面可见性检测
document.addEventListener('visibilitychange', () => {
    if (!document.hidden && AppState.currentUser && AppState.savedPassword && AppState.autoReconnectEnabled) {
        reconnect();
    }
});

// 窗口大小变化时修复地图
window.addEventListener('resize', () => {
    if (AppState.map) {
        setTimeout(() => AppState.map.invalidateSize(), 100);
    }
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

// ========== 初始化 ==========
function startApp() {
    debugLog('应用启动...');
    startGPSWatch();
    initSocket();
    debugLog('应用初始化完成');
}

// 确保登录页面显示
DOM.loginPage.style.display = 'flex';
DOM.mapPage.style.display = 'none';

// 启动应用
startApp();