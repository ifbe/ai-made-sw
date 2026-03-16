// ========== GPS功能 ==========

// 发送位置到服务器（只发送位置和朝向，不包含目标）
function sendPositionToServer() {
    if (!AppState.currentUser || !AppState.socket || AppState.socket.readyState !== WebSocket.OPEN || !AppState.sessionToken) return;

    const msg = {
        type: 'update_position',
        token: AppState.sessionToken,
        username: AppState.currentUser,
        lat: AppState.localLat,
        lng: AppState.localLng,
        heading: AppState.localHeading
    };
    
    AppState.socket.send(JSON.stringify(msg));
}

// 开始GPS监听
function startGPSWatch() {
    if (!navigator.geolocation) {
        debugLog('浏览器不支持GPS定位');
        return;
    }

    if (AppState.watchId !== null) {
        navigator.geolocation.clearWatch(AppState.watchId);
    }

    debugLog('开始GPS定位...');

    AppState.watchId = navigator.geolocation.watchPosition(
        (position) => {
            const wgsLat = position.coords.latitude;
            const wgsLng = position.coords.longitude;

            const gcj02 = wgs84_to_gcj02(wgsLat, wgsLng);
            AppState.localLat = gcj02.lat;
            AppState.localLng = gcj02.lng;

            if (position.coords.heading !== null) {
                AppState.localHeading = position.coords.heading;
            }

            if (!AppState.lastPosition ||
                Math.abs(AppState.localLat - AppState.lastPosition.lat) > 0.00001 ||
                Math.abs(AppState.localLng - AppState.lastPosition.lng) > 0.00001) {

                debugLog('GPS更新:', AppState.localLat.toFixed(6), AppState.localLng.toFixed(6), AppState.localHeading + '°');

                updateSelfMarkers();
                
                // 如果有目标，更新自己的目标线（但不发送）
                if (AppState.targetLat && AppState.targetLng) {
                    updateSelfTarget();
                }

                if (AppState.currentUser) {
                    sendPositionToServer();
                }

                AppState.lastPosition = { lat: AppState.localLat, lng: AppState.localLng };
            }
        },
        (error) => {
            debugLog('GPS定位错误:', error.code, error.message);
        },
        {
            enableHighAccuracy: true,
            timeout: 10000,
            maximumAge: 0
        }
    );
}
