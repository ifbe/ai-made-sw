// ========== WebSocket功能 ==========

// 重新认证
async function reconnect() {
    if (AppState.isReconnecting || !AppState.currentUser || !AppState.savedPassword) return;

    AppState.isReconnecting = true;
    debugLog('开始重新认证...');

    try {
        const challengeResponse = await fetch('/api/challenge', {
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
            await new Promise(resolve => {
                const checkInterval = setInterval(() => {
                    if (AppState.socket && AppState.socket.readyState === WebSocket.OPEN) {
                        clearInterval(checkInterval);
                        resolve();
                    }
                }, 100);
            });
        }

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
        debugLog('重新认证错误:', error);
        AppState.savedPassword = null;
        handleLogout();
        alert('重新认证失败，请手动登录');
    } finally {
        AppState.isReconnecting = false;
    }
}

// 初始化WebSocket
function initSocket() {
    if (AppState.socket) {
        AppState.socket.close();
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}`;

    debugLog('连接 WebSocket:', wsUrl);
    AppState.socket = new WebSocket(wsUrl);

    AppState.socket.onopen = () => {
        debugLog('WebSocket连接成功');
        DOM.connectionStatus.innerText = '✅ 已连接';
        DOM.connectionStatus.className = 'connection-status connected';
        DOM.autoReconnectBtn.classList.remove('show');
        DOM.manualReconnectBtn.classList.remove('show');
    };

    AppState.socket.onclose = (event) => {
        debugLog('WebSocket连接断开:', event.code, event.reason);
        DOM.connectionStatus.innerText = '❌ 连接断开';
        DOM.connectionStatus.className = 'connection-status disconnected';

        if (AppState.currentUser) {
            DOM.autoReconnectBtn.classList.add('show');
            DOM.manualReconnectBtn.classList.add('show');
            
            if (AppState.autoReconnectEnabled) {
                debugLog('自动重连已开启，3秒后尝试...');
                if (AppState.reconnectTimer) clearTimeout(AppState.reconnectTimer);
                AppState.reconnectTimer = setTimeout(() => {
                    reconnect();
                }, 3000);
            }
        }
    };

    AppState.socket.onerror = (error) => {
        debugLog('WebSocket错误:', error);
    };

    AppState.socket.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            debugLog('收到消息:', data.type);

            switch (data.type) {
                case 'login_success':
                    debugLog('登录成功:', data);
                    AppState.sessionToken = data.token;
                    DOM.currentUserDisplay.innerText = `👋 ${data.nickname}`;

                    DOM.loginPage.style.display = 'none';
                    DOM.mapPage.style.display = 'block';

                    if (!AppState.mapInitialized) {
                        initMap();
                    } else {
                        setTimeout(() => AppState.map.invalidateSize(), 100);
                    }

                    // 清空所有标记
                    AppState.userMarkers.forEach((marker) => AppState.map.removeLayer(marker));
                    AppState.userMarkers.clear();
                    if (AppState.selfLocalMarker) AppState.map.removeLayer(AppState.selfLocalMarker);
                    if (AppState.selfServerMarker) AppState.map.removeLayer(AppState.selfServerMarker);
                    
                    // 清空所有目标线
                    AppState.otherTargets.forEach((target) => {
                        if (target.line) AppState.map.removeLayer(target.line);
                        if (target.marker) AppState.map.removeLayer(target.marker);
                    });
                    AppState.otherTargets.clear();
                    clearSelfTarget();

                    updateSelfMarkers();
                    
                    // 如果有目标，显示目标线
                    if (AppState.targetLat && AppState.targetLng) {
                        updateSelfTarget();
                    }

                    AppState.socket.send(JSON.stringify({
                        type: 'get_users',
                        token: AppState.sessionToken,
                        username: AppState.currentUser
                    }));

                    // 发送当前位置
                    if (typeof sendPositionToServer === 'function') {
                        sendPositionToServer();
                    }

                    DOM.loginBtn.disabled = false;
                    DOM.loginBtn.innerHTML = '登录';
                    break;

                case 'user_list':
                    debugLog('收到用户列表:', data.users.length, '人');
                    const selfInList = data.users.find(u => u.username === AppState.currentUser);
                    if (selfInList) {
                        AppState.serverLat = selfInList.lat;
                        AppState.serverLng = selfInList.lng;
                        AppState.serverHeading = selfInList.heading || 0;
                        updateSelfMarkers();
                    }
                    refreshOtherMarkers(data.users);
                    break;

                case 'update_position':
                    debugLog('位置更新:', data.username);
                    if (data.username === AppState.currentUser) {
                        // 更新自己的服务器位置
                        AppState.serverLat = data.lat;
                        AppState.serverLng = data.lng;
                        AppState.serverHeading = data.heading;
                        updateSelfMarkers();
                        
                        // 如果位置更新里带了目标（向后兼容）
                        if (data.target_lat !== undefined && data.target_lng !== undefined) {
                            AppState.targetLat = data.target_lat;
                            AppState.targetLng = data.target_lng;
                            if (AppState.targetLat && AppState.targetLng) {
                                updateSelfTarget();
                            } else {
                                clearSelfTarget();
                            }
                        }
                    } else {
                        // 更新其他用户的标记
                        const marker = AppState.userMarkers.get(data.username);
                        if (marker) {
                            const icon = createHeadingIcon(data.heading, data.nickname || data.username, 'other');
                            marker.setLatLng([data.lat, data.lng]);
                            marker.setIcon(icon);
                        }
                    }
                    break;

                // ===== 新增：处理目标更新消息 =====
                case 'update_target':
                    debugLog('目标更新:', data.username, data.target_lat, data.target_lng);
                    
                    if (data.username === AppState.currentUser) {
                        // 自己的目标更新
                        if (data.target_lat && data.target_lng) {
                            AppState.targetLat = data.target_lat;
                            AppState.targetLng = data.target_lng;
                            updateSelfTarget();
                            debugLog('自己的目标已更新');
                        } else {
                            AppState.targetLat = null;
                            AppState.targetLng = null;
                            clearSelfTarget();
                            debugLog('自己的目标已清除');
                        }
                    } else {
                        // 其他用户的目标更新
                        const userMarker = AppState.userMarkers.get(data.username);
                        if (userMarker) {
                            if (data.target_lat && data.target_lng) {
                                // 获取该用户的当前位置
                                const userPos = userMarker.getLatLng();
                                updateOtherTarget(data.username, userPos.lat, userPos.lng, data.target_lat, data.target_lng);
                                debugLog(`更新用户 ${data.username} 的目标`);
                            } else {
                                clearOtherTarget(data.username);
                                debugLog(`清除用户 ${data.username} 的目标`);
                            }
                        }
                    }
                    break;

                case 'user_joined':
                    debugLog('用户加入:', data.username);
                    if (data.target_lat && data.target_lng) {
                        updateOtherTarget(data.username,
                            data.lat, data.lng,
                            data.target_lat, data.target_lng);
                    }
                    if (AppState.sessionToken && AppState.currentUser && AppState.socket.readyState === WebSocket.OPEN) {
                        AppState.socket.send(JSON.stringify({
                            type: 'get_users',
                            token: AppState.sessionToken,
                            username: AppState.currentUser
                        }));
                    }
                    break;

                case 'user_left':
                    debugLog('用户离开:', data.username);
                    // 清除离开用户的目标线
                    clearOtherTarget(data.username);
                    
                    if (AppState.sessionToken && AppState.currentUser && AppState.socket.readyState === WebSocket.OPEN) {
                        AppState.socket.send(JSON.stringify({
                            type: 'get_users',
                            token: AppState.sessionToken,
                            username: AppState.currentUser
                        }));
                    }
                    break;

                case 'force_logout':
                    debugLog('被强制登出:', data.message);
                    alert(data.message || '您的账号已在其他地方登录');
                    handleLogout();
                    break;

                case 'error':
                    debugLog('服务器错误:', data.message);
                    if (data.message.includes('认证') || data.message.includes('登录')) {
                        DOM.loginError.innerText = data.message;
                        DOM.loginBtn.disabled = false;
                        DOM.loginBtn.innerHTML = '登录';
                    } else {
                        alert('错误: ' + data.message);
                    }
                    break;

                case 'logout_success':
                    debugLog('登出成功');
                    break;
            }
        } catch (error) {
            debugLog('处理消息错误:', error);
        }
    };
}
