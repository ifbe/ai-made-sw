// ========== 认证功能 ==========
async function handleLogin() {
    const username = DOM.username.value.trim();
    const password = DOM.password.value.trim();

    debugLog('登录尝试 - 用户名:', username);

    if (username === '') {
        DOM.loginError.innerText = '请输入用户名';
        return;
    }
    if (password === '') {
        DOM.loginError.innerText = '请输入密码';
        return;
    }

    DOM.loginBtn.disabled = true;
    DOM.loginBtn.innerHTML = '<span class="loading"></span> 登录中...';
    DOM.loginError.innerText = '';

    try {
        const challengeResponse = await fetch('/api/challenge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        const challengeData = await challengeResponse.json();

        if (!challengeData.success) {
            throw new Error(challengeData.message || '获取挑战码失败');
        }

        const { challenge, salt } = challengeData;

        AppState.currentUser = username;
        AppState.savedPassword = password;

        const passwordHash = sha256(password + salt);
        const response = hmacSha256(passwordHash, challenge);

        if (!AppState.socket || AppState.socket.readyState !== WebSocket.OPEN) {
            initSocket();
            await new Promise(resolve => {
                const checkInterval = setInterval(() => {
                    if (AppState.socket && AppState.socket.readyState === WebSocket.OPEN) {
                        clearInterval(checkInterval);
                        resolve();
                    }
                }, 100);
            });
        }

        AppState.socket.send(JSON.stringify({
            type: 'login',
            username: username,
            response: response,
            lat: AppState.localLat,
            lng: AppState.localLng,
            heading: AppState.localHeading
        }));

    } catch (error) {
        debugLog('登录错误:', error);
        DOM.loginError.innerText = error.message || '登录失败';
        DOM.loginBtn.disabled = false;
        DOM.loginBtn.innerHTML = '登录';
    }
}

function handleLogout() {
    debugLog('用户登出');

    if (AppState.socket && AppState.socket.readyState === WebSocket.OPEN && AppState.sessionToken) {
        AppState.socket.send(JSON.stringify({
            type: 'logout',
            token: AppState.sessionToken,
            username: AppState.currentUser
        }));
    }

    if (AppState.map) {
        AppState.userMarkers.forEach((marker) => AppState.map.removeLayer(marker));
        AppState.userMarkers.clear();
        if (AppState.selfLocalMarker) AppState.map.removeLayer(AppState.selfLocalMarker);
        if (AppState.selfServerMarker) AppState.map.removeLayer(AppState.selfServerMarker);
    }

    if (AppState.reconnectTimer) {
        clearTimeout(AppState.reconnectTimer);
        AppState.reconnectTimer = null;
    }

    AppState.currentUser = null;
    AppState.sessionToken = null;
    AppState.savedPassword = null;
    AppState.lastPosition = null;

    DOM.mapPage.style.display = 'none';
    DOM.loginPage.style.display = 'flex';
    DOM.username.value = '';
    DOM.password.value = '';
    DOM.loginError.innerText = '';
    DOM.onlineCount.innerText = '0';
    DOM.loginBtn.disabled = false;
    DOM.loginBtn.innerHTML = '登录';
    
    DOM.autoReconnectBtn.classList.remove('show');
    DOM.manualReconnectBtn.classList.remove('show');
}
