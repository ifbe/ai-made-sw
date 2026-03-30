// ========== 主入口和事件绑定 ==========

// 调试面板切换
DOM.debugToggle.addEventListener('click', () => {
    DOM.debugPanel.classList.toggle('show');
    DOM.debugToggle.textContent = DOM.debugPanel.classList.contains('show') ? '🔧 隐藏日志' : '🔧 调试日志';
});

// 登录/登出事件
DOM.loginBtn.addEventListener('click', handleLogin);
DOM.logoutBtn.addEventListener('click', handleLogout);

// 回车登录
DOM.password.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleLogin();
});
DOM.username.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleLogin();
});

// ===== 目标按钮事件 =====
DOM.targetBtn.addEventListener('click', () => {
    if (!AppState.currentUser) {
        alert('请先登录');
        return;
    }
    
    AppState.targetMode = !AppState.targetMode;
    
    if (AppState.targetMode) {
        // 进入目标设置模式
        DOM.targetBtn.textContent = '✅ 已设置目标 (点击取消)';
        DOM.targetBtn.classList.add('set');
        
        // 获取十字星位置（地图中心）
        const center = AppState.map.getCenter();
        AppState.targetLat = center.lat;
        AppState.targetLng = center.lng;
        
        debugLog('设置目标:', AppState.targetLat, AppState.targetLng);
        
        // 显示自己的目标线
        updateSelfTarget();
        
        // 发送目标更新
        sendTargetUpdate();
        
    } else {
        // 取消目标
        DOM.targetBtn.textContent = '🎯 点我设置目标';
        DOM.targetBtn.classList.remove('set');
        
        // 清除目标
        AppState.targetLat = null;
        AppState.targetLng = null;
        
        // 清除自己的目标线
        clearSelfTarget();
        
        // 发送目标更新（清除）
        sendTargetUpdate();
        
        debugLog('取消目标');
    }
});

// ===== 专门发送目标更新的函数 =====
function sendTargetUpdate() {
    if (!AppState.currentUser || !AppState.socket || AppState.socket.readyState !== WebSocket.OPEN || !AppState.sessionToken) {
        debugLog('无法发送目标: 连接未就绪');
        return;
    }

    const msg = {
        type: 'update_target',  // 新的消息类型
        token: AppState.sessionToken,
        username: AppState.currentUser,
        target_lat: AppState.targetLat,
        target_lng: AppState.targetLng
    };
    
    AppState.socket.send(JSON.stringify(msg));
    debugLog('发送目标更新:', AppState.targetLat, AppState.targetLng);
}

// 重连按钮
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
