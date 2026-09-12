// ========== 全局变量和配置 ==========

/** 同源地址（默认服务器地址；登录矩形第一行可以改） */
const SAME_ORIGIN = window.location.origin;

const AppState = {
    // 用户状态
    currentUser: null,
    sessionToken: null,
    savedPassword: null,
    loggingIn: false,       // 正在登录（用来把服务器的错误放回登录矩形里，而不是弹窗）

    // 服务器地址（登录矩形的第一行）：默认就是本页所在的服务器
    serverUrl: SAME_ORIGIN,

    // 地图相关
    map: null,
    userMarkers: new Map(),
    mapInitialized: false,

    // GPS相关
    watchId: null,
    lastPosition: null,

    // WebSocket相关
    socket: null,
    socketUrl: null,
    reconnectTimer: null,
    isReconnecting: false,
    autoReconnectEnabled: true,

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
    // 准备页 / 地图页
    splashPage: document.getElementById('splashPage'),
    mapPage: document.getElementById('mapPage'),

    // 登录矩形（未登录时悬浮在地图上方）
    loginCard: document.getElementById('loginCard'),
    serverUrl: document.getElementById('serverUrl'),
    username: document.getElementById('username'),
    password: document.getElementById('password'),
    loginBtn: document.getElementById('loginBtn'),
    loginError: document.getElementById('loginError'),

    // 左上角本地面板（标题行右侧是退出登录）
    localSettingsPanel: document.getElementById('localSettingsPanel'),
    logoutBtn: document.getElementById('logoutBtn'),
    btnMyLocation: document.getElementById('btnMyLocation'),
    btnSetTarget: document.getElementById('btnSetTarget'),
    btnSetTargetText: document.getElementById('btnSetTargetText'),

    // 右上角同服人数面板
    userListPanel: document.getElementById('userListPanel'),
    userListTitle: document.getElementById('userListTitle'),
    userListContent: document.getElementById('userListContent'),

    // 左下角日志矩形
    logPanel: document.getElementById('logPanel'),
    logRows: document.getElementById('logRows'),
    logLines: document.getElementById('logLines'),
    logScrollbar: document.getElementById('logScrollbar'),
    logThumb: document.getElementById('logThumb'),
    logGrip: document.getElementById('logGrip'),
    logStrip: document.getElementById('logStrip'),
    logStripText: document.getElementById('logStripText'),
    logTriangle: document.getElementById('logTriangle'),

    // 十字星坐标
    crosshairInfo: document.getElementById('crosshairInfo')
};
