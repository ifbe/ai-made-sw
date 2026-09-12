package com.example.locate.ui.map

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.locate.data.local.SecurePrefs
import com.example.locate.data.remote.ApiClient
import com.example.locate.data.repository.AuthRepository
import com.example.locate.domain.model.User
import com.example.locate.service.LocationTrackerService
import com.example.locate.util.AppLog
import com.example.locate.util.Constants
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class MapActivity : ComponentActivity() {

    private lateinit var viewModel: MapViewModel
    private lateinit var securePrefs: SecurePrefs

    private var locationService: LocationTrackerService? = null
    private var serviceBound = false
    private var serviceStarted = false
    private var permissionRequestLaunched = false
    private var missingPermissionLogged = false

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val localBinder = binder as LocationTrackerService.LocalBinder
            locationService = localBinder.getService()
            serviceBound = true
            locationService?.setApiClient(viewModel.apiClient)
            viewModel.onServiceConnected(locationService!!)
            // 把地图传给 LocationTrackerService，让它能在第一次 GPS 到达时飞图
            viewModel.getMapView()?.let { locationService?.setMapView(it) }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            locationService = null
            serviceBound = false
        }
    }

    private val locationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val fineLocationGranted = permissions[Manifest.permission.ACCESS_FINE_LOCATION] == true
        if (fineLocationGranted) {
            AppLog.i("已获得定位权限")
            startLocationService()
        } else {
            AppLog.w("位置权限被拒绝，地图无法定位")
            Toast.makeText(this, "位置权限被拒绝，功能将受限", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        securePrefs = SecurePrefs(this)
        viewModel = MapViewModel(
            AuthRepository(securePrefs.serverUrl, securePrefs),
            securePrefs
        )

        setContent {
            MaterialTheme {
                MapScreen(viewModel = viewModel)
            }
        }

        checkAndRequestPermissions()
    }

    override fun onResume() {
        super.onResume()
        // 用户可能在系统设置里补授了权限，回到前台再试一次
        if (!serviceStarted) checkAndRequestPermissions()
    }

    private fun requiredPermissions(): Array<String> {
        val permissions = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        return permissions.toTypedArray()
    }

    private fun checkAndRequestPermissions() {
        val hasLocation = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.ACCESS_FINE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED

        if (hasLocation) {
            startLocationService()
            return
        }

        if (permissionRequestLaunched) return

        // 启动页已经问过一次，就别在进地图时立刻再弹一次
        val askedBefore = getSharedPreferences(Constants.UI_PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(Constants.KEY_PERMISSIONS_REQUESTED, false)
        if (askedBefore) {
            if (!missingPermissionLogged) {
                missingPermissionLogged = true
                AppLog.w("缺少定位权限，请在系统设置中授予")
            }
            return
        }

        permissionRequestLaunched = true
        locationPermissionLauncher.launch(requiredPermissions())
    }

    private fun startLocationService() {
        if (serviceStarted) return
        serviceStarted = true
        val serviceIntent = Intent(this, LocationTrackerService::class.java)
        startForegroundService(serviceIntent)
        bindService(serviceIntent, serviceConnection, Context.BIND_AUTO_CREATE)
    }

    override fun onStop() {
        super.onStop()
        if (serviceBound) {
            unbindService(serviceConnection)
            serviceBound = false
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        viewModel.onDestroy()
    }
}

/** 登录态：未登录 / 自动登录中 / 已登录 */
enum class AuthState { LOGGED_OUT, AUTO_LOGGING_IN, LOGGED_IN }

class MapViewModel(
    private var authRepository: AuthRepository,
    private val securePrefs: SecurePrefs
) : ViewModel() {

    val apiClient: ApiClient get() = authRepository.getApiClient()

    private var locationService: LocationTrackerService? = null
    private var mapViewInterface: MapView? = null
    private var loginUsername: String? = null
    private var lastConnectionLog: String? = null

    private val _otherUsers = MutableStateFlow<List<User>>(emptyList())
    val otherUsers: StateFlow<List<User>> = _otherUsers

    private val _uiState = MutableStateFlow(
        MapUiState(
            serverUrl = securePrefs.serverUrl,
            username = securePrefs.username ?: ""
        )
    )
    val uiState: StateFlow<MapUiState> = _uiState

    init {
        attachApiListener()
        autoLoginIfPossible()
    }

    // ─── 网络回调 ─────────────────────────────────────────────────────

    private fun attachApiListener() {
        apiClient.listener = object : ApiClient.ApiListener {

            override fun onLoginSuccess(token: String, nickname: String) {
                // 正常路径下登录结果由 AuthRepository.login() 返回，这里只是兜底
                onLoggedIn(nickname)
            }

            override fun onLoginFailed(error: String) {
                onLoginError("登录失败: $error")
            }

            override fun onUserList(users: List<User>) {
                // user_list 只用于 UI 显示，不过滤坐标（坐标为0不影响列表展示），
                // 也不过滤自己，让自己的服务器位置（蓝色）一起显示
                _otherUsers.value = users
                mapViewInterface?.showOtherUsers(users)
                mapViewInterface?.updateUserList(users)
                logConnection(1, users.size + 1)  // +1=自己
            }

            override fun onUserJoined(user: User) {
                _otherUsers.value = _otherUsers.value + user
                mapViewInterface?.showOtherUser(user)
                mapViewInterface?.updateUserList(_otherUsers.value)
                logConnection(1, _otherUsers.value.size + 1)
            }

            override fun onUserLeft(username: String) {
                _otherUsers.value = _otherUsers.value.filter { it.username != username }
                mapViewInterface?.removeOtherUser(username)
                mapViewInterface?.updateUserList(_otherUsers.value)
                logConnection(1, _otherUsers.value.size + 1)
            }

            override fun onTargetUpdate(username: String, targetLat: Double?, targetLng: Double?) {
                _otherUsers.value = _otherUsers.value.map { user ->
                    if (user.username == username) {
                        user.copy(targetLat = targetLat, targetLng = targetLng)
                    } else user
                }
                mapViewInterface?.showOtherUsers(_otherUsers.value)
                mapViewInterface?.updateUserList(_otherUsers.value)
            }

            override fun onPositionUpdate(username: String, lat: Double, lng: Double, heading: Float) {
                _otherUsers.value = _otherUsers.value.map { user ->
                    if (user.username == username) {
                        user.copy(lat = lat, lng = lng, heading = heading)
                    } else user
                }
                if (username == loginUsername) {
                    // 自己的金色本地 GPS 标记
                    mapViewInterface?.showUser(lat, lng, heading)
                }
                // 自己和他人都按服务器坐标画蓝色标记
                mapViewInterface?.showOtherUsers(_otherUsers.value)
                mapViewInterface?.updateUserList(_otherUsers.value)
            }

            override fun onError(message: String) {
                AppLog.e(message)
                val state = _uiState.value
                if (state.authState == AuthState.LOGGED_OUT) {
                    _uiState.value = state.copy(error = message)
                }
            }

            override fun onConnected() {
                logConnection(1, _otherUsers.value.size + 1)
            }

            override fun onDisconnected() {
                logConnection(2)
            }
        }
    }

    /** 连接状态只在变化时写一行日志（否则每次位置更新都会刷屏） */
    private fun logConnection(status: Int, onlineCount: Int = 0) {
        val key = "$status:$onlineCount"
        if (key == lastConnectionLog) return
        lastConnectionLog = key
        when (status) {
            0 -> AppLog.i("服务器连接中…")
            1 -> AppLog.i("服务器已连接（在线 $onlineCount 人）")
            else -> AppLog.w("服务器已断开")
        }
    }

    // ─── 登录 / 退出 ──────────────────────────────────────────────────

    private fun autoLoginIfPossible() {
        val username = securePrefs.username
        val password = securePrefs.password
        if (username.isNullOrEmpty() || password.isNullOrEmpty()) {
            AppLog.i("未登录：请填写服务器地址、用户名和密码")
            _uiState.value = _uiState.value.copy(
                authState = AuthState.LOGGED_OUT,
                username = username ?: ""
            )
            return
        }

        _uiState.value = _uiState.value.copy(
            authState = AuthState.AUTO_LOGGING_IN,
            username = username,
            loading = false,
            error = null
        )
        AppLog.i("使用已保存凭证自动登录：$username")

        viewModelScope.launch {
            when (val result = authRepository.login(username, password)) {
                is AuthRepository.LoginState.Success -> onLoggedIn(result.nickname)
                is AuthRepository.LoginState.Error -> onLoginError(result.message)
            }
        }
    }

    fun onServerUrlChange(serverUrl: String) {
        if (serverUrl == _uiState.value.serverUrl) return

        // 换服务器等于换连接，先把旧的断干净（正常只在未登录时可改）
        if (_uiState.value.authState == AuthState.LOGGED_IN) {
            AppLog.w("服务器地址已变更，需要重新登录")
            apiClient.listener = null
            authRepository.logout()
            resetSession()
        }
        apiClient.listener = null
        apiClient.disconnect()

        securePrefs.serverUrl = serverUrl
        _uiState.value = _uiState.value.copy(serverUrl = serverUrl)

        authRepository = AuthRepository(serverUrl, securePrefs)
        attachApiListener()
        locationService?.setApiClient(apiClient)
        AppLog.i("服务器地址已切换：$serverUrl")
    }

    fun onUsernameChange(username: String) {
        _uiState.value = _uiState.value.copy(username = username)
    }

    fun onPasswordChange(password: String) {
        _uiState.value = _uiState.value.copy(password = password)
    }

    fun onLogin() {
        val state = _uiState.value
        if (state.username.isBlank() || state.password.isBlank()) {
            _uiState.value = state.copy(error = "请输入用户名和密码")
            return
        }

        _uiState.value = state.copy(loading = true, error = null)
        AppLog.i("正在登录：${state.username} @ ${state.serverUrl}")

        // AuthRepository.login() 结束后会把 listener 还原成"发起登录时的那个"，
        // 所以每次登录前重新挂一次，避免退出登录后回调丢失
        attachApiListener()

        viewModelScope.launch {
            when (val result = authRepository.login(state.username, state.password)) {
                is AuthRepository.LoginState.Success -> onLoggedIn(result.nickname)
                is AuthRepository.LoginState.Error -> onLoginError(result.message)
            }
        }
    }

    private fun onLoggedIn(nickname: String) {
        if (_uiState.value.authState == AuthState.LOGGED_IN) return

        loginUsername = securePrefs.username ?: _uiState.value.username
        lastConnectionLog = null
        _uiState.value = _uiState.value.copy(
            authState = AuthState.LOGGED_IN,
            loading = false,
            error = null,
            password = "",   // 密码不留在内存状态里
            nickname = nickname
        )
        applyCornerPanels()
        AppLog.i("登录成功：${nickname.ifBlank { loginUsername ?: "" }}")
        // 服务可能还握着旧的 ApiClient（换过地址的话），这里对齐一次
        locationService?.setApiClient(apiClient)
    }

    private fun onLoginError(message: String) {
        _uiState.value = _uiState.value.copy(
            authState = AuthState.LOGGED_OUT,
            loading = false,
            error = message
        )
        applyCornerPanels()
        AppLog.e("登录失败：$message")
    }

    fun logout() {
        if (_uiState.value.authState != AuthState.LOGGED_IN) return
        AppLog.i("退出登录")
        apiClient.listener = null
        authRepository.logout()   // 清凭证 + 断开 WebSocket
        resetSession()
    }

    /** 退出登录后把界面恢复到"未登录"：清空队友、目标，收起两个角面板 */
    private fun resetSession() {
        _otherUsers.value.forEach { mapViewInterface?.removeOtherUser(it.username) }
        _otherUsers.value = emptyList()
        mapViewInterface?.updateUserList(emptyList())
        mapViewInterface?.clearTarget()
        mapViewInterface?.updateTargetButton(false)

        loginUsername = null
        lastConnectionLog = null
        _uiState.value = _uiState.value.copy(
            authState = AuthState.LOGGED_OUT,
            loading = false,
            error = null,
            password = "",
            nickname = "",
            username = securePrefs.username ?: "",
            targetLat = null,
            targetLng = null
        )
        applyCornerPanels()
    }

    private fun applyCornerPanels() {
        mapViewInterface?.setCornerPanelsVisible(_uiState.value.authState == AuthState.LOGGED_IN)
    }

    // ─── 地图 ─────────────────────────────────────────────────────────

    fun onServiceConnected(service: LocationTrackerService) {
        this.locationService = service
    }

    fun onMapReady() {
        // 地图就绪后，立即刷新当前位置并移动到我的位置
        locationService?.let { svc ->
            val pos = svc.getCurrentGcj02Position()
            if (pos != null) {
                mapViewInterface?.showUser(pos.lat, pos.lng, svc.getCurrentHeading())
                mapViewInterface?.moveTo(pos.lat, pos.lng, 17.0)
            }
        }
    }

    fun setMapView(mapView: MapView) {
        this.mapViewInterface = mapView

        // Activity 重建 / 旋转会重新走这里，把当前状态重放一遍
        mapView.showOtherUsers(_otherUsers.value)
        mapView.updateUserList(_otherUsers.value)
        mapView.updateTargetButton(_uiState.value.targetLat != null)
        _uiState.value.targetLat?.let { lat ->
            _uiState.value.targetLng?.let { lng -> mapView.showTarget(lat, lng) }
        }
        applyCornerPanels()

        // 本地设置面板：我的位置 / 我的目标 / 退出登录
        mapView.setOnLocalSettingsClickListener { type, lat, lng ->
            when (type) {
                "location" -> {
                    locationService?.let { svc ->
                        val pos = svc.getCurrentGcj02Position()
                        if (pos != null) mapViewInterface?.moveTo(pos.lat, pos.lng, 17.0)
                    }
                }
                "target" -> {
                    if (_uiState.value.targetLat != null) {
                        clearTarget()
                    } else {
                        onMapClick(lat, lng)
                    }
                }
                "logout" -> logout()
            }
        }

        // 队友列表面板点击
        mapView.setOnUserListClickListener { action, user ->
            when (action) {
                "user" -> mapViewInterface?.moveTo(user.lat, user.lng, 17.0)
                "target" -> {
                    if (user.targetLat != null && user.targetLng != null) {
                        mapViewInterface?.moveTo(user.targetLat, user.targetLng, 17.0)
                    }
                }
            }
        }
    }

    fun getMapView(): MapView? = mapViewInterface

    fun onMapClick(lat: Double, lng: Double) {
        _uiState.value = _uiState.value.copy(
            targetLat = lat,
            targetLng = lng
        )
        mapViewInterface?.showTarget(lat, lng)
        mapViewInterface?.updateTargetButton(true)
        apiClient.sendTarget(lat, lng)   // 未登录时 ApiClient 内部会直接返回
    }

    fun clearTarget() {
        _uiState.value = _uiState.value.copy(
            targetLat = null,
            targetLng = null
        )
        mapViewInterface?.clearTarget()
        mapViewInterface?.updateTargetButton(false)
        apiClient.sendTarget(null, null)
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }

    fun onDestroy() {
        apiClient.listener = null
        apiClient.disconnect()
    }
}

data class MapUiState(
    val authState: AuthState = AuthState.LOGGED_OUT,
    val serverUrl: String = Constants.DEFAULT_SERVER_URL,
    val username: String = "",
    val password: String = "",
    val loading: Boolean = false,
    val nickname: String = "",
    val error: String? = null,
    val targetLat: Double? = null,
    val targetLng: Double? = null
)

@Composable
fun MapScreen(viewModel: MapViewModel) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current

    // 已登录时用 Toast 提示服务端错误；未登录时错误显示在登录矩形里
    LaunchedEffect(uiState.error, uiState.authState) {
        val error = uiState.error
        if (error != null && uiState.authState == AuthState.LOGGED_IN) {
            Toast.makeText(context, error, Toast.LENGTH_SHORT).show()
            viewModel.clearError()
        }
    }

    // 原来这里有一层 Scaffold（只为挂 FAB），去掉后它携带的系统栏 insets 要补回来，
    // 否则地图和内部叠加面板会顶到状态栏/导航栏下面
    Box(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.systemBars)
    ) {
        AndroidView(
            factory = { ctx ->
                MapViewImpl(ctx).apply {
                    setOnMapClickListener { _, _ ->
                        // 地图层只显示，不响应点击
                    }
                    setOnFirstMapReadyListener { viewModel.onMapReady() }
                    viewModel.setMapView(this)
                }
            },
            modifier = Modifier.fillMaxSize()
        )

        // 未登录 / 登录中：顶部悬浮的登录矩形
        if (uiState.authState != AuthState.LOGGED_IN) {
            LoginCard(
                uiState = uiState,
                onServerUrlChange = viewModel::onServerUrlChange,
                onUsernameChange = viewModel::onUsernameChange,
                onPasswordChange = viewModel::onPasswordChange,
                onLogin = viewModel::onLogin,
                modifier = Modifier
                    .align(Alignment.TopCenter)
                    .padding(start = 16.dp, end = 16.dp, top = 12.dp)
            )
        }
    }
}

@Composable
private fun LoginCard(
    uiState: MapUiState,
    onServerUrlChange: (String) -> Unit,
    onUsernameChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onLogin: () -> Unit,
    modifier: Modifier = Modifier
) {
    val focusManager = LocalFocusManager.current
    val busy = uiState.loading || uiState.authState == AuthState.AUTO_LOGGING_IN
    val shape = RoundedCornerShape(10.dp)

    Column(
        modifier = modifier
            .widthIn(max = 300.dp)
            .background(Color(0xF5FFFFFF), shape)
            .border(1.dp, Color(0x33000000), shape)
            .padding(horizontal = 12.dp, vertical = 10.dp)
    ) {
        CompactField(
            value = uiState.serverUrl,
            onValueChange = onServerUrlChange,
            label = "服务器地址",
            enabled = !busy,
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Uri,
                imeAction = ImeAction.Next
            ),
            keyboardActions = KeyboardActions(onNext = { focusManager.moveFocus(FocusDirection.Down) }),
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(5.dp))

        CompactField(
            value = uiState.username,
            onValueChange = onUsernameChange,
            label = "用户名",
            enabled = !busy,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
            keyboardActions = KeyboardActions(onNext = { focusManager.moveFocus(FocusDirection.Down) }),
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(5.dp))

        CompactField(
            value = uiState.password,
            onValueChange = onPasswordChange,
            label = "密码",
            enabled = !busy,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                imeAction = ImeAction.Done
            ),
            keyboardActions = KeyboardActions(onDone = {
                focusManager.clearFocus()
                onLogin()
            }),
            modifier = Modifier.fillMaxWidth()
        )

        uiState.error?.let { error ->
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = error,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall
            )
        }

        Spacer(modifier = Modifier.height(7.dp))

        // 登录中/自动登录中的转圈放在按钮里，省掉一行标题
        Button(
            onClick = onLogin,
            enabled = !busy && uiState.username.isNotBlank() && uiState.password.isNotBlank(),
            modifier = Modifier
                .fillMaxWidth()
                .height(38.dp),
            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 0.dp)
        ) {
            if (busy) {
                CircularProgressIndicator(
                    modifier = Modifier.size(14.dp),
                    color = MaterialTheme.colorScheme.onPrimary,
                    strokeWidth = 2.dp
                )
                Spacer(modifier = Modifier.width(6.dp))
            }
            Text("登录", style = MaterialTheme.typography.bodyMedium)
        }
    }
}

/**
 * 紧凑输入框：标签和输入框在同一行，一行一个字段。
 *
 * M3 的 OutlinedTextField 有 56dp 最小高度，硬压高度会把文字上下裁掉；
 * 这里用 BasicTextField 直接拼一个 30dp 的框，所以上下留白很小、文字完整。
 */
@Composable
private fun CompactField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    enabled: Boolean,
    modifier: Modifier = Modifier,
    keyboardOptions: KeyboardOptions = KeyboardOptions.Default,
    keyboardActions: KeyboardActions = KeyboardActions.Default,
    visualTransformation: VisualTransformation = VisualTransformation.None
) {
    val shape = RoundedCornerShape(6.dp)
    val focusRequester = remember { FocusRequester() }

    Row(modifier = modifier, verticalAlignment = Alignment.CenterVertically) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp, lineHeight = 12.sp),
            color = Color(0xFF888888),
            maxLines = 1,
            modifier = Modifier.width(56.dp)
        )
        Box(
            modifier = Modifier
                .weight(1f)
                .height(30.dp)
                .background(if (enabled) Color(0x0F000000) else Color(0x08000000), shape)
                .border(1.dp, Color(0x22000000), shape)
                // 点框内任意位置都能落到输入框上（文字只占中间 20dp）
                .clickable(interactionSource = null, indication = null) {
                    focusRequester.requestFocus()
                }
                .padding(horizontal = 8.dp),
            contentAlignment = Alignment.CenterStart
        ) {
            BasicTextField(
                value = value,
                onValueChange = onValueChange,
                enabled = enabled,
                singleLine = true,
                textStyle = MaterialTheme.typography.bodyMedium.copy(color = Color(0xFF1A1A1A)),
                visualTransformation = visualTransformation,
                keyboardOptions = keyboardOptions,
                keyboardActions = keyboardActions,
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                modifier = Modifier
                    .fillMaxWidth()
                    .focusRequester(focusRequester)
            )
        }
    }
}
