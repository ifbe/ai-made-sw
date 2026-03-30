// ========== 地图功能 ==========

// 创建带朝向的图标
function createHeadingIcon(headingDeg, userName, type = 'other') {
    let arrowColor, bgColor;

    switch(type) {
        case 'self_local':
            arrowColor = '#ffdf7e';
            bgColor = '#d4a500';
            break;
        case 'self_server':
            arrowColor = '#ff7e7e';
            bgColor = '#d45a5a';
            break;
        default:
            arrowColor = '#7ec8ff';
            bgColor = '#1e6eb5';
            break;
    }

    const container = document.createElement('div');
    container.className = 'custom-marker';
    container.style.setProperty('--bg-color', bgColor);
    container.style.setProperty('--arrow-color', arrowColor);

    const label = document.createElement('div');
    label.className = 'marker-label';
    label.textContent = userName + (type === 'self_local' ? ' (我)' : type === 'self_server' ? ' (云)' : '');
    container.appendChild(label);

    const arrow = document.createElement('div');
    arrow.className = 'marker-arrow';
    arrow.style.transform = `rotate(${headingDeg}deg)`;
    arrow.innerHTML = '↑';
    container.appendChild(arrow);

    return L.divIcon({
        html: container.outerHTML,
        className: 'leaflet-div-icon',
        iconSize: [60, 60],
        iconAnchor: [30, 50]
    });
}

// 更新自己的两个标记
function updateSelfMarkers() {
    if (!AppState.map || !AppState.currentUser) return;

    if (AppState.selfLocalMarker) AppState.map.removeLayer(AppState.selfLocalMarker);
    const localIcon = createHeadingIcon(AppState.localHeading, AppState.currentUser, 'self_local');
    AppState.selfLocalMarker = L.marker([AppState.localLat, AppState.localLng], { icon: localIcon }).addTo(AppState.map);

    if (AppState.selfServerMarker) AppState.map.removeLayer(AppState.selfServerMarker);
    const serverIcon = createHeadingIcon(AppState.serverHeading, AppState.currentUser, 'self_server');
    AppState.selfServerMarker = L.marker([AppState.serverLat, AppState.serverLng], { icon: serverIcon }).addTo(AppState.map);
}

// ========== 目标线功能 ==========

// 创建目标线（队友用）
function createOtherTargetLine(fromLat, fromLng, toLat, toLng) {
    return L.polyline([[fromLat, fromLng], [toLat, toLng]], {
        color: '#ffa500',
        weight: 2,
        opacity: 0.6,
        dashArray: '6, 6',
        className: 'target-line-other'
    }).addTo(AppState.map);
}

// 创建自己的目标线
function createSelfTargetLine(fromLat, fromLng, toLat, toLng) {
    return L.polyline([[fromLat, fromLng], [toLat, toLng]], {
        color: '#ffa500',
        weight: 3,
        opacity: 0.9,
        dashArray: '8, 8',
        className: 'target-line-self'
    }).addTo(AppState.map);
}

// 创建目标点标记（队友用）
function createOtherTargetMarker(lat, lng, username) {
    const icon = L.divIcon({
        html: `<div class="target-label-other">🎯 ${username}</div>`,
        className: 'target-label-container',
        iconSize: [60, 20],
        iconAnchor: [30, 10]
    });
    
    return L.marker([lat, lng], { icon: icon }).addTo(AppState.map);
}

// 创建自己的目标点标记
function createSelfTargetMarker(lat, lng) {
    const icon = L.divIcon({
        html: `<div class="target-label-self">🎯 我的目标</div>`,
        className: 'target-label-container',
        iconSize: [70, 24],
        iconAnchor: [35, 12]
    });
    
    return L.marker([lat, lng], { icon: icon }).addTo(AppState.map);
}

// 更新其他用户的目标线
function updateOtherTarget(username, userLat, userLng, targetLat, targetLng) {
    if (!AppState.map || !targetLat || !targetLng) return;
    
    // 移除旧的线和标记
    if (AppState.otherTargets.has(username)) {
        const old = AppState.otherTargets.get(username);
        if (old.line) AppState.map.removeLayer(old.line);
        if (old.marker) AppState.map.removeLayer(old.marker);
    }
    
    // 创建新的线和标记
    const line = createOtherTargetLine(userLat, userLng, targetLat, targetLng);
    const marker = createOtherTargetMarker(targetLat, targetLng, username);
    
    AppState.otherTargets.set(username, { line, marker });
}

// 清除其他用户的目标线
function clearOtherTarget(username) {
    if (AppState.otherTargets.has(username)) {
        const target = AppState.otherTargets.get(username);
        if (target.line) AppState.map.removeLayer(target.line);
        if (target.marker) AppState.map.removeLayer(target.marker);
        AppState.otherTargets.delete(username);
    }
}

// 更新自己的目标线
function updateSelfTarget() {
    if (!AppState.map || !AppState.currentUser || !AppState.targetLat || !AppState.targetLng) return;
    
    // 移除旧的线和标记
    if (AppState.selfTargetLine) AppState.map.removeLayer(AppState.selfTargetLine);
    if (AppState.selfTargetMarker) AppState.map.removeLayer(AppState.selfTargetMarker);
    
    // 创建新的线和标记
    AppState.selfTargetLine = createSelfTargetLine(
        AppState.localLat, AppState.localLng,
        AppState.targetLat, AppState.targetLng
    );
    AppState.selfTargetMarker = createSelfTargetMarker(AppState.targetLat, AppState.targetLng);
}

// 清除自己的目标线
function clearSelfTarget() {
    if (AppState.selfTargetLine) {
        AppState.map.removeLayer(AppState.selfTargetLine);
        AppState.selfTargetLine = null;
    }
    if (AppState.selfTargetMarker) {
        AppState.map.removeLayer(AppState.selfTargetMarker);
        AppState.selfTargetMarker = null;
    }
}

// 发送目标到服务器
function sendTargetToServer() {
    if (!AppState.currentUser || !AppState.socket || AppState.socket.readyState !== WebSocket.OPEN || !AppState.sessionToken) return;

    AppState.socket.send(JSON.stringify({
        type: 'update_position',
        token: AppState.sessionToken,
        username: AppState.currentUser,
        target_lat: AppState.targetLat,
        target_lng: AppState.targetLng
    }));
    debugLog('发送目标到服务器:', AppState.targetLat, AppState.targetLng);
}

// 刷新其他用户标记（包含目标线）
function refreshOtherMarkers(users) {
    if (!AppState.map || !users) return;

    DOM.onlineCount.innerText = users.length;

    const otherUsers = users.filter(u => u.username !== AppState.currentUser);
    const otherUsernames = new Set(otherUsers.map(u => u.username));

    // 更新其他用户的标记
    const existingIds = new Set(AppState.userMarkers.keys());
    const newIds = otherUsernames;

    // 移除不存在的用户及其目标线
    existingIds.forEach(id => {
        if (!newIds.has(id)) {
            const marker = AppState.userMarkers.get(id);
            if (marker) AppState.map.removeLayer(marker);
            AppState.userMarkers.delete(id);
            clearOtherTarget(id);  // 清除该用户的目标线
        }
    });

    // 添加或更新其他用户
    otherUsers.forEach(user => {
        let marker = AppState.userMarkers.get(user.username);
        const icon = createHeadingIcon(user.heading || 0, user.nickname || user.username, 'other');

        if (marker) {
            marker.setLatLng([user.lat, user.lng]);
            marker.setIcon(icon);
        } else {
            marker = L.marker([user.lat, user.lng], { icon: icon }).addTo(AppState.map);
            AppState.userMarkers.set(user.username, marker);
        }
        
        // 处理该用户的目标线
        if (user.target_lat && user.target_lng) {
            updateOtherTarget(user.username, user.lat, user.lng, user.target_lat, user.target_lng);
        } else {
            clearOtherTarget(user.username);
        }
    });
}

// 初始化地图
function initMap() {
    AppState.map = L.map('map', {
        center: [AppState.localLat, AppState.localLng],
        zoom: 17
    });
    
    L.tileLayer('https://webrd01.is.autonavi.com/appmaptile?lang=zh_cn&size=1&scale=1&style=8&x={x}&y={y}&z={z}', {
        attribution: '© 高德地图'
    }).addTo(AppState.map);
    
    setTimeout(() => AppState.map.invalidateSize(), 300);
    AppState.mapInitialized = true;
}
