// ========== 认证功能 ==========

/** 未登录 / 登录中：显示登录矩形；登录成功后：显示两个角面板 */
function applyAuthUi() {
    const loggedIn = !!AppState.currentUser;
    DOM.loginCard.style.display = loggedIn ? 'none' : 'block';
    DOM.localSettingsPanel.style.display = loggedIn ? 'block' : 'none';
    DOM.userListPanel.style.display = loggedIn ? 'block' : 'none';
}

function showLoginError(message) {
    DOM.loginError.textContent = message || '';
    DOM.loginError.classList.toggle('show', !!message);
}

function setLoginBusy(busy) {
    DOM.loginBtn.disabled = busy;
    DOM.loginBtn.innerHTML = busy ? '<span class="loading"></span>登录中…' : '登录';
    DOM.serverUrl.disabled = busy;
    DOM.username.disabled = busy;
    DOM.password.disabled = busy;
}

async function handleLogin() {
    const serverUrl = normalizeServerUrl(DOM.serverUrl.value);
    const username = DOM.username.value.trim();
    const password = DOM.password.value.trim();

    if (username === '') {
        showLoginError('请输入用户名');
        return;
    }
    if (password === '') {
        showLoginError('请输入密码');
        return;
    }

    DOM.serverUrl.value = serverUrl;
    const serverChanged = AppState.serverUrl !== serverUrl;
    AppState.serverUrl = serverUrl;
    AppState.currentUser = username;
    AppState.savedPassword = password;
    AppState.loggingIn = true;
    savePrefs();

    setLoginBusy(true);
    showLoginError('');
    debugLog('正在登录：' + username + ' @ ' + serverUrl);

    try {
        const challengeResponse = await fetch(apiUrl('/api/challenge'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        const challengeData = await challengeResponse.json();

        if (!challengeData.success) {
            throw new Error(challengeData.message || '获取挑战码失败');
        }

        const { challenge, salt } = challengeData;
        const passwordHash = sha256(password + salt);
        const response = hmacSha256(passwordHash, challenge);

        // 换了服务器地址就重连到新的地址
        if (serverChanged || !AppState.socket || AppState.socket.readyState !== WebSocket.OPEN) {
            initSocket();
        }
        await waitForSocket();

        AppState.socket.send(JSON.stringify({
            type: 'login',
            username: username,
            response: response,
            lat: AppState.localLat,
            lng: AppState.localLng,
            heading: AppState.localHeading
        }));

    } catch (error) {
        AppState.currentUser = null;
        AppState.savedPassword = null;
        AppState.loggingIn = false;
        debugError('登录失败：' + describe(error));
        showLoginError(error.message || '登录失败');
        setLoginBusy(false);
    }
}

function handleLogout() {
    if (!AppState.currentUser) return;
    debugLog('退出登录');

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
        if (AppState.selfLocalMarker) {
            AppState.map.removeLayer(AppState.selfLocalMarker);
            AppState.selfLocalMarker = null;
        }
        AppState.otherTargets.forEach((target) => {
            if (target.line) AppState.map.removeLayer(target.line);
            if (target.marker) AppState.map.removeLayer(target.marker);
        });
        AppState.otherTargets.clear();
        clearSelfTarget();
    }

    if (AppState.reconnectTimer) {
        clearTimeout(AppState.reconnectTimer);
        AppState.reconnectTimer = null;
    }

    AppState.currentUser = null;
    AppState.sessionToken = null;
    AppState.savedPassword = null;
    AppState.lastPosition = null;
    AppState.loggingIn = false;
    AppState.targetLat = null;
    AppState.targetLng = null;
    AppState.otherUsersData.clear();

    // 回到"未登录"：清空队友、目标，收起两个角面板，只留登录矩形
    DOM.password.value = '';
    DOM.userListContent.innerHTML = '';
    DOM.userListTitle.textContent = '同服人数: 0';
    updateTargetButton(false);
    showLoginError('');
    setLoginBusy(false);
    applyAuthUi();
}
