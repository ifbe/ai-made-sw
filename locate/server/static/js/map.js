// ========== 地图功能 ==========

// 创建带朝向的图标
function createHeadingIcon(headingDeg, userName, type = 'other') {
    let arrowColor, bgColor, arrowHtml, arrowClass;

    switch(type) {
        case 'self_local':
            arrowColor = '#FFD700';
            bgColor = '#d4a500';
            arrowClass = 'arrow-self';
            arrowHtml = '&#9651;'; // △ 空心三角
            break;
        default:
            arrowColor = '#7ec8ff';
            bgColor = '#1e6eb5';
            arrowClass = 'arrow-up';
            arrowHtml = '&#8593;'; // ↑ 向上箭头
            break;
    }

    const container = document.createElement('div');
    container.className = 'custom-marker';
    container.style.setProperty('--bg-color', bgColor);
    container.style.setProperty('--arrow-color', arrowColor);

    const label = document.createElement('div');
    label.className = 'marker-label';
    label.textContent = userName;
    container.appendChild(label);

    const arrow = document.createElement('div');
    arrow.className = 'marker-arrow ' + arrowClass;
    arrow.style.transform = `rotate(${headingDeg}deg)`;
    arrow.innerHTML = arrowHtml;
    container.appendChild(arrow);

    return L.divIcon({
        html: container.outerHTML,
        className: 'leaflet-div-icon',
        iconSize: [60, 60],
        iconAnchor: [30, 50]
    });
}

// 更新本地GPS标记（只有一个 △，无特殊我的箭头）
function updateSelfLocalMarker() {
    if (!AppState.map || !AppState.currentUser) return;

    if (AppState.selfLocalMarker) AppState.map.removeLayer(AppState.selfLocalMarker);
    const localIcon = createHeadingIcon(AppState.localHeading, AppState.currentUser, 'self_local');
    AppState.selfLocalMarker = L.marker([AppState.localLat, AppState.localLng], { icon: localIcon }).addTo(AppState.map);
}

// 刷新其他用户标记（所有人包括服务器发的自己都用 ↑）
function refreshOtherMarkers(users) {
    if (!AppState.map || !users) return;

    const myUsername = AppState.currentUser;
    const otherUsers = users.filter(u => u.username !== myUsername);
    const otherUsernames = new Set(otherUsers.map(u => u.username));

    // 移除不存在的用户及其目标线
    const existingIds = new Set(AppState.userMarkers.keys());
    existingIds.forEach(id => {
        if (!otherUsernames.has(id)) {
            const marker = AppState.userMarkers.get(id);
            if (marker) AppState.map.removeLayer(marker);
            AppState.userMarkers.delete(id);
            clearOtherTarget(id);
        }
    });

    // 添加或更新其他用户（服务器发的所有人包括服务器发的我自己都用 ↑）
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

        if (user.target_lat && user.target_lng) {
            updateOtherTarget(user.username, user.lat, user.lng, user.target_lat, user.target_lng);
        } else {
            clearOtherTarget(user.username);
        }
    });
}

// ========== 右上角用户列表面板 ==========
function updateUserListPanel(users) {
    // iOS 风格：不过滤自己，所有人（包括自己）都显示在右上角面板
    const allUsers = users; // 直接用传入的全部用户，不额外过滤

    DOM.userListTitle.textContent = '同服人数: ' + allUsers.length;

    if (allUsers.length === 0) {
        DOM.userListContent.innerHTML = '';
        return;
    }

    DOM.userListContent.innerHTML = allUsers.map(user => {
        const hasTarget = user.target_lat && user.target_lng;
        return `
            <div class="user-list-row" data-username="${user.username}">
                <span class="user-name" data-action="fly">${user.nickname || user.username}</span>
                <span class="target-btn-small" data-action="fly-target" ${hasTarget ? '' : 'style="opacity:0.3"'}>🎯 目标</span>
            </div>
        `;
    }).join('');

    // 绑定点击事件
    DOM.userListContent.querySelectorAll('.user-list-row').forEach(row => {
        row.addEventListener('click', (e) => {
            const username = row.dataset.username;
            const action = e.target.dataset.action;
            const userData = AppState.otherUsersData.get(username);

            if (action === 'fly' && userData) {
                const lat = userData.lat;
                const lng = userData.lng;
                if (lat != null && lng != null) {
                    AppState.map.setView([lat, lng], AppState.map.getZoom());
                    debugLog('飞图到用户 ' + username + ':', lat, lng);
                }
            } else if (action === 'fly-target' && userData) {
                if (userData.target_lat && userData.target_lng) {
                    AppState.map.setView([userData.target_lat, userData.target_lng], AppState.map.getZoom());
                    debugLog('飞图到用户 ' + username + ' 的目标:', userData.target_lat, userData.target_lng);
                }
            }
        });
    });
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

// 更新其他用户的目标线
function updateOtherTarget(username, userLat, userLng, targetLat, targetLng) {
    if (!AppState.map || !targetLat || !targetLng) return;

    if (AppState.otherTargets.has(username)) {
        const old = AppState.otherTargets.get(username);
        if (old.line) AppState.map.removeLayer(old.line);
        if (old.marker) AppState.map.removeLayer(old.marker);
    }

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

    if (AppState.selfTargetLine) AppState.map.removeLayer(AppState.selfTargetLine);
    if (AppState.selfTargetMarker) AppState.map.removeLayer(AppState.selfTargetMarker);

    AppState.selfTargetLine = L.polyline([
        [AppState.localLat, AppState.localLng],
        [AppState.targetLat, AppState.targetLng]
    ], {
        color: '#ffa500',
        weight: 3,
        opacity: 0.9,
        dashArray: '8, 8',
        className: 'target-line-self'
    }).addTo(AppState.map);

    const icon = L.divIcon({
        html: `<div class="target-label-self">🎯 我的目标</div>`,
        className: 'target-label-container',
        iconSize: [70, 24],
        iconAnchor: [35, 12]
    });
    AppState.selfTargetMarker = L.marker([AppState.targetLat, AppState.targetLng], { icon: icon }).addTo(AppState.map);
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

// ========== 十字星坐标更新 ==========
function updateCrosshairInfo() {
    if (!AppState.map) return;
    const center = AppState.map.getCenter();
    const zoom = AppState.map.getZoom();

    document.getElementById('infoLng').textContent = '经度: ' + center.lng.toFixed(6);
    document.getElementById('infoLat').textContent = '纬度: ' + center.lat.toFixed(6);

    // 海拔从 GPS 数据获取
    const alt = AppState.currentAltitude;
    document.getElementById('infoAlt').textContent = alt != null ? '海拔: ' + alt.toFixed(1) + ' m' : '海拔: -- m';
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

    // 地图移动时更新十字星坐标
    AppState.map.on('moveend', updateCrosshairInfo);
    AppState.map.on('zoomend', updateCrosshairInfo);

    setTimeout(() => AppState.map.invalidateSize(), 300);
    AppState.mapInitialized = true;
    updateCrosshairInfo();
}