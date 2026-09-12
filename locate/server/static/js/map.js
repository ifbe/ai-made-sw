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
    // 还没定位到就当没位置，别把标记画到几内亚湾
    if (AppState.localLat === 0 && AppState.localLng === 0) return;

    if (AppState.selfLocalMarker) AppState.map.removeLayer(AppState.selfLocalMarker);
    const localIcon = createHeadingIcon(AppState.localHeading, AppState.currentUser, 'self_local');
    AppState.selfLocalMarker = L.marker([AppState.localLat, AppState.localLng], { icon: localIcon }).addTo(AppState.map);
}

// 刷新队友标记：服务器发回来的"自己"那一份也画成蓝色↑（本地还有个金色△，两条路各画各的）
function refreshOtherMarkers(users) {
    if (!AppState.map || !users) return;

    // 不过滤自己：安卓/iOS 上服务器回显的自己也是一支蓝色↑
    const allNames = new Set(users.map(u => u.username));

    // 移除列表里已经没有的人及其目标线
    const existingIds = new Set(AppState.userMarkers.keys());
    existingIds.forEach(id => {
        if (!allNames.has(id)) {
            const marker = AppState.userMarkers.get(id);
            if (marker) AppState.map.removeLayer(marker);
            AppState.userMarkers.delete(id);
            clearOtherTarget(id);
        }
    });

    // 添加或更新队友（服务器发的所有人，包括服务器发的我自己，都用 ↑）
    users.forEach(user => {
        // 还没上报过坐标的人不画，否则所有标记都会堆在地图左上角
        if (user.lat === 0 && user.lng === 0) {
            const stale = AppState.userMarkers.get(user.username);
            if (stale) {
                AppState.map.removeLayer(stale);
                AppState.userMarkers.delete(user.username);
            }
            clearOtherTarget(user.username);
            return;
        }

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
const USER_COLORS = [
    '#0099ff', '#9900ff', '#00cc99', '#ff6699',
    '#66ccff', '#ff9933', '#cc6600', '#999999'
];

/** 按用户名取一个固定的颜色（和 iOS 一样，每个人一个色点） */
function colorForUsername(username) {
    let hash = 0;
    for (let i = 0; i < username.length; i++) {
        hash = (hash * 31 + username.charCodeAt(i)) | 0;
    }
    return USER_COLORS[Math.abs(hash) % USER_COLORS.length];
}

/**
 * 点这一行该飞到哪：
 * - 自己那一行用本地 GPS：服务器上那份可能还是登录时占位的 (0,0)，或者被同账号的另一个客户端覆盖过
 * - 还是 (0,0) 的人（从没上报过位置）不给飞，免得飞到几内亚湾
 */
function flyTargetFor(user) {
    const isSelf = user.username === AppState.currentUser;
    if (isSelf) {
        const local = getCurrentPosition();
        return local ? { lat: local.lat, lng: local.lng } : null;
    }
    if (user.lat === 0 && user.lng === 0) return null;
    if (user.lat == null || user.lng == null) return null;
    return { lat: user.lat, lng: user.lng };
}

function updateUserListPanel(users) {
    // 不过滤自己，所有人（包括自己）都显示在右上角面板
    const allUsers = users || [];

    DOM.userListTitle.textContent = '同服人数: ' + allUsers.length;

    if (allUsers.length === 0) {
        DOM.userListContent.innerHTML = '';
        return;
    }

    DOM.userListContent.innerHTML = allUsers.map(user => {
        const hasTarget = !!(user.target_lat && user.target_lng);
        const name = user.nickname || user.username;
        return `
            <div class="user-list-row" data-username="${escapeAttr(user.username)}">
                <span class="user-dot" style="background:${colorForUsername(user.username)}"></span>
                <span class="user-name" data-action="fly">${escapeAttr(name)}</span>
                <span class="target-btn-small ${hasTarget ? 'active' : ''}" data-action="fly-target">⊕</span>
            </div>
        `;
    }).join('');

    // 绑定点击事件
    DOM.userListContent.querySelectorAll('.user-list-row').forEach(row => {
        row.addEventListener('click', (e) => {
            const username = row.dataset.username;
            const action = e.target.dataset ? e.target.dataset.action : null;
            const userData = AppState.otherUsersData.get(username);
            if (!userData) return;

            if (action === 'fly') {
                const coord = flyTargetFor(userData);
                if (coord) {
                    AppState.map.setView([coord.lat, coord.lng], AppState.map.getZoom());
                    debugLog('飞图到用户 ' + username + '：' + coord.lat + ', ' + coord.lng);
                }
            } else if (action === 'fly-target') {
                if (userData.target_lat && userData.target_lng &&
                    !(userData.target_lat === 0 && userData.target_lng === 0)) {
                    AppState.map.setView([userData.target_lat, userData.target_lng], AppState.map.getZoom());
                    debugLog('飞图到用户 ' + username + ' 的目标：' + userData.target_lat + ', ' + userData.target_lng);
                }
            }
        });
    });
}

function escapeAttr(text) {
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
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

// 发送目标到服务器（服务器只认 update_target；位置消息里的 target 字段会被忽略）
function sendTargetToServer() {
    if (!AppState.currentUser || !AppState.socket || AppState.socket.readyState !== WebSocket.OPEN || !AppState.sessionToken) return;

    AppState.socket.send(JSON.stringify({
        type: 'update_target',
        token: AppState.sessionToken,
        username: AppState.currentUser,
        target_lat: AppState.targetLat,
        target_lng: AppState.targetLng
    }));
    debugLog('发送目标到服务器：' + AppState.targetLat + ', ' + AppState.targetLng);
}

/** 设目标（对应 Android 的 MapViewModel.onMapClick） */
function onMapClick(lat, lng) {
    AppState.targetLat = lat;
    AppState.targetLng = lng;
    updateSelfTarget();
    updateTargetButton(true);
    sendTargetToServer();
}

/** 取消目标 */
function clearTarget() {
    AppState.targetLat = null;
    AppState.targetLng = null;
    clearSelfTarget();
    updateTargetButton(false);
    sendTargetToServer();
}

/** 本地面板第二行的文字和颜色：有目标时是橙色的「取消目标」 */
function updateTargetButton(hasTarget) {
    DOM.btnSetTargetText.textContent = hasTarget ? '取消目标' : '设目标';
    DOM.btnSetTarget.classList.toggle('target-active', !!hasTarget);
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