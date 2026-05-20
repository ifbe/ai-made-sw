// ========== 全局变量和配置 ==========
const AppState = {
    // 用户状态
    currentUser: null,
    sessionToken: null,
    savedPassword: null,
    
    // 地图相关
    map: null,
    userMarkers: new Map(),
    mapInitialized: false,
    
    // GPS相关
    watchId: null,
    lastPosition: null,
    
    // WebSocket相关
    socket: null,
    reconnectTimer: null,
    isReconnecting: false,
    autoReconnectEnabled: true,
    
    // 调试
    debugEnabled: true,
    
    // 位置数据
    localLat: 32.0455,      // 南京默认
    localLng: 118.7908,
    localHeading: 0,
    currentAltitude: null,
    serverLat: 32.0455,
    serverLng: 118.7908,
    serverHeading: 0,
    
    // 标记对象
    selfLocalMarker: null,
    
    // ===== 目标相关 =====
    targetMode: false,           // 是否处于设置目标模式
    targetLat: null,             // 当前设置的目标纬度
    targetLng: null,             // 当前设置的目标经度
    
    // 存储其他用户的目标线 (username -> {line, marker})
    otherTargets: new Map(),

    // 存储其他用户的数据 (username -> userObj) 用于右上角面板
    otherUsersData: new Map(),
    
    // 自己的目标线对象
    selfTargetLine: null,
    selfTargetMarker: null
};

// DOM 元素引用
const DOM = {
    loginPage: document.getElementById('loginPage'),
    mapPage: document.getElementById('mapPage'),
    username: document.getElementById('username'),
    password: document.getElementById('password'),
    loginBtn: document.getElementById('loginBtn'),
    logoutBtn: document.getElementById('logoutBtn'),
    loginError: document.getElementById('loginError'),
    connectionStatus: document.getElementById('connectionStatus'),
    debugPanel: document.getElementById('debugPanel'),
    debugToggle: document.getElementById('debugToggle'),
    autoReconnectBtn: document.getElementById('autoReconnectBtn'),
    manualReconnectBtn: document.getElementById('manualReconnectBtn'),
    // 左上面板
    btnMyLocation: document.getElementById('btnMyLocation'),
    btnSetTarget: document.getElementById('btnSetTarget'),
    // 右上角面板
    userListPanel: document.getElementById('userListPanel'),
    userListTitle: document.getElementById('userListTitle'),
    userListContent: document.getElementById('userListContent'),
    // 十字星坐标
    crosshairInfo: document.getElementById('crosshairInfo')
};
