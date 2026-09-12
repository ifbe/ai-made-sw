// ========== WebSocket功能 ==========

// 重新认证
async function reconnect() {
    if (AppState.isReconnecting || !AppState.currentUser || !AppState.savedPassword) return;

    AppState.isReconnecting = true;
    debugLog('开始重新认证…');

    try {
        const challengeResponse = await fetch(apiUrl('/api/challenge'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: AppState.currentUser })
        });

        const challengeData = await challengeResponse.json();

        if (!challengeData.success) {
            throw new Error(challengeData.message || '获取挑战码失败');
        }

        const { challenge, salt } = challengeData;

        const passwordHash = sha256(AppState.savedPassword + salt);
        const response = hmacSha256(passwordHash, challenge);

        if (!AppState.socket || AppState.socket.readyState !== WebSocket.OPEN) {
            initSocket();
        }
        await waitForSocket();

        const loginMsg = {
            type: 'login',
            username: AppState.currentUser,
            response: response,
            lat: AppState.localLat,
            lng: AppState.localLng,
            heading: AppState.localHeading
        };

        // 如果有目标，一并发送
        if (AppState.targetLat && AppState.targetLng) {
            loginMsg.target_lat = AppState.targetLat;
            loginMsg.target_lng = AppState.targetLng;
        }

        AppState.socket.send(JSON.stringify(loginMsg));
        debugLog('重新认证成功');

    } catch (error) {
        debugError('重新认证失败：' + describe(error));
        AppState.savedPassword = null;
        handleLogout();
        showLoginError('重新认证失败，请重新登录');
    } finally {
        AppState.isReconnecting = false;
    }
}

// 初始化WebSocket
function initSocket() {
    if (AppState.socket) {
        // 主动关闭：别让 onclose 再触发一次自动重连
        AppState.socket.onclose = null;
        AppState.socket.close();
        AppState.socket = null;
    }

    const url = wsUrl();
    AppState.socketUrl = url;

    debugLog('连接 WebSocket：' + url);
    const socket = new WebSocket(url);
    AppState.socket = socket;

    socket.onopen = () => {
        if (AppState.socket !== socket) return;
        debugLog('WebSocket连接成功');
    };

    socket.onclose = (event) => {
        if (AppState.socket !== socket) return;
        debugWarn('WebSocket连接断开：' + event.code + ' ' + (event.reason || ''));

        if (AppState.currentUser && AppState.savedPassword && AppState.autoReconnectEnabled) {
            debugLog('自动重连已开启，3秒后尝试…');
            if (AppState.reconnectTimer) clearTimeout(AppState.reconnectTimer);
            AppState.reconnectTimer = setTimeout(() => {
                reconnect();
            }, 3000);
        }
    };

    socket.onerror = () => {
        debugError('WebSocket 连接出错：' + url);
    };

    socket.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            debugLog('收到消息: ' + data.type);

            switch (data.type) {
                case 'login_success':
                    AppLog.i('登录成功：' + (data.nickname || AppState.currentUser || ''));
                    AppState.sessionToken = data.token;
                    AppState.loggingIn = false;
                    setLoginBusy(false);
                    applyAuthUi();

                    if (!AppState.mapInitialized) {
                        initMap();
                    } else {
                        setTimeout(() => AppState.map.invalidateSize(), 100);
                    }

                    // 清空所有标记
                    AppState.userMarkers.forEach((marker) => AppState.map.removeLayer(marker));
                    AppState.userMarkers.clear();
                    if (AppState.selfLocalMarker) AppState.map.removeLayer(AppState.selfLocalMarker);

                    // 清空所有目标线
                    AppState.otherTargets.forEach((target) => {
                        if (target.line) AppState.map.removeLayer(target.line);
                        if (target.marker) AppState.map.removeLayer(target.marker);
                    });
                    AppState.otherTargets.clear();
                    clearSelfTarget();

                    updateSelfLocalMarker();

                    // 如果有目标，显示目标线
                    if (AppState.targetLat && AppState.targetLng) {
                        updateSelfTarget();
                        updateTargetButton(true);
                    }

                    socket.send(JSON.stringify({
                        type: 'get_users',
                        token: AppState.sessionToken,
                        username: AppState.currentUser
                    }));

                    // 发送当前位置
                    if (typeof sendPositionToServer === 'function') {
                        sendPositionToServer();
                    }
                    break;

                case 'user_list':
                    debugLog('收到用户列表：' + data.users.length + ' 人');

                    // 存储所有用户（包括自己），用于右上角面板
                    AppState.otherUsersData.clear();
                    data.users.forEach(u => {
                        AppState.otherUsersData.set(u.username, u);
                    });
                    refreshOtherMarkers(data.users);
                    updateUserListPanel(data.users); // 传入全部用户，右上角面板自己过滤
                    break;

                case 'update_position': {
                    debugLog('位置更新：' + data.username);

                    // 更新 otherUsersData（所有人一视同仁，包括自己）
                    // username 也要写进去：只从位置更新认识的人，右上角面板要用它
                    const existingData = AppState.otherUsersData.get(data.username) || {};
                    const mergedData = {
                        ...existingData,
                        username: data.username,
                        lat: data.lat,
                        lng: data.lng,
                        heading: data.heading
                    };
                    AppState.otherUsersData.set(data.username, mergedData);

                    // 蓝色 ↑ 标记：没有就建、有就更新（服务器回显的自己那份也一样）
                    // 位置广播里没有 nickname，所以昵称沿用 user_list 里的，别退回用户名
                    upsertUserMarker(
                        data.username,
                        mergedData.nickname || data.username,
                        data.lat,
                        data.lng,
                        data.heading
                    );

                    // 目标虚线跟着人走
                    refreshUserTargetLine(data.username, mergedData);

                    // 如果是自己，同时更新服务器坐标和自己的目标（向后兼容）
                    if (data.username === AppState.currentUser) {
                        AppState.serverLat = data.lat;
                        AppState.serverLng = data.lng;
                        AppState.serverHeading = data.heading;
                        if (data.target_lat !== undefined && data.target_lng !== undefined) {
                            AppState.targetLat = data.target_lat;
                            AppState.targetLng = data.target_lng;
                            if (AppState.targetLat && AppState.targetLng) {
                                updateSelfTarget();
                                updateTargetButton(true);
                            } else {
                                clearSelfTarget();
                                updateTargetButton(false);
                            }
                        }
                    }

                    // 刷新右上角面板
                    updateUserListPanel([...AppState.otherUsersData.values()]);
                    break;
                }

                case 'update_target': {
                    debugLog('目标更新：' + data.username + ' ' + data.target_lat + ', ' + data.target_lng);

                    // 更新数据（所有人一视同仁）
                    const tgtUserData = AppState.otherUsersData.get(data.username) || {};
                    AppState.otherUsersData.set(data.username, {
                        ...tgtUserData,
                        target_lat: data.target_lat,
                        target_lng: data.target_lng
                    });

                    // 如果是自己
                    if (data.username === AppState.currentUser) {
                        if (data.target_lat && data.target_lng) {
                            AppState.targetLat = data.target_lat;
                            AppState.targetLng = data.target_lng;
                            updateSelfTarget();
                            updateTargetButton(true);
                        } else {
                            AppState.targetLat = null;
                            AppState.targetLng = null;
                            clearSelfTarget();
                            updateTargetButton(false);
                        }
                    } else {
                        // 其他用户：更新目标线
                        // 这里不用管他的标记建没建起来：坐标还没到就先记着，
                        // 等他位置上报时 update_position 会再补画一次
                        refreshUserTargetLine(data.username);
                    }

                    // 刷新右上角面板
                    updateUserListPanel([...AppState.otherUsersData.values()]);
                    break;
                }

                case 'user_joined': {
                    debugLog('用户加入：' + data.username);

                    const joined = {
                        ...(AppState.otherUsersData.get(data.username) || {}),
                        username: data.username,
                        nickname: data.nickname,
                        lat: data.lat,
                        lng: data.lng,
                        heading: data.heading,
                        target_lat: data.target_lat,
                        target_lng: data.target_lng
                    };
                    AppState.otherUsersData.set(data.username, joined);
                    upsertUserMarker(data.username, data.nickname || data.username, data.lat, data.lng, data.heading);
                    refreshUserTargetLine(data.username, joined);

                    if (AppState.sessionToken && AppState.currentUser && AppState.socket.readyState === WebSocket.OPEN) {
                        socket.send(JSON.stringify({
                            type: 'get_users',
                            token: AppState.sessionToken,
                            username: AppState.currentUser
                        }));
                    }
                    break;
                }

                case 'user_left':
                    debugLog('用户离开：' + data.username);
                    // 清除离开用户的目标线
                    clearOtherTarget(data.username);

                    if (AppState.sessionToken && AppState.currentUser && AppState.socket.readyState === WebSocket.OPEN) {
                        socket.send(JSON.stringify({
                            type: 'get_users',
                            token: AppState.sessionToken,
                            username: AppState.currentUser
                        }));
                    }
                    break;

                case 'force_logout':
                    debugWarn('被强制登出：' + (data.message || ''));
                    handleLogout();
                    showLoginError(data.message || '您的账号已在其他地方登录');
                    break;

                case 'error':
                    debugError('服务器错误：' + (data.message || ''));
                    if (AppState.loggingIn || !AppState.currentUser) {
                        // 登录过程中的错误放回登录矩形里
                        AppState.loggingIn = false;
                        AppState.currentUser = null;
                        AppState.savedPassword = null;
                        showLoginError(data.message || '登录失败');
                        setLoginBusy(false);
                    } else {
                        alert('错误: ' + data.message);
                    }
                    break;

                case 'logout_success':
                    debugLog('登出成功');
                    break;
            }
        } catch (error) {
            debugError('处理消息错误：' + describe(error));
        }
    };
}
