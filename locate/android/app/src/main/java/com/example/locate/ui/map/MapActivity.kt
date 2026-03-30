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
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import com.example.locate.data.local.SecurePrefs
import com.example.locate.data.remote.ApiClient
import com.example.locate.data.repository.AuthRepository
import com.example.locate.domain.model.ServerMessage
import com.example.locate.domain.model.User
import com.example.locate.service.LocationTrackerService
import com.example.locate.ui.login.LoginActivity
import com.example.locate.ui.map.MapViewImpl
import com.example.locate.util.Constants
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.MainScope

class MapActivity : ComponentActivity() {

    private lateinit var viewModel: MapViewModel
    private var locationService: LocationTrackerService? = null
    private var serviceBound = false

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val localBinder = binder as LocationTrackerService.LocalBinder
            locationService = localBinder.getService()
            serviceBound = true
            locationService?.setApiClient(viewModel.apiClient)
            viewModel.onServiceConnected(locationService!!)
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
            startLocationService()
        } else {
            Toast.makeText(this, "位置权限被拒绝，功能将受限", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val securePrefs = SecurePrefs(this)
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

    private fun checkAndRequestPermissions() {
        val permissions = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        val hasLocation = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (hasLocation) {
            startLocationService()
        } else {
            locationPermissionLauncher.launch(permissions.toTypedArray())
        }
    }

    private fun startLocationService() {
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

class MapViewModel(
    private val authRepository: AuthRepository,
    private val securePrefs: SecurePrefs
) : ViewModel() {

    val apiClient: ApiClient get() = authRepository.getApiClient()
    private var locationService: LocationTrackerService? = null

    private val _uiState = MutableStateFlow(MapUiState())
    val uiState: StateFlow<MapUiState> = _uiState

    private val _otherUsers = MutableStateFlow<List<User>>(emptyList())
    private var _loginUsername: String? = null
    val otherUsers: StateFlow<List<User>> = _otherUsers

    private var mapViewInterface: MapView? = null

    init {
        setupApiClient()
        attemptAutoLogin()
    }

    private fun setupApiClient() {
        apiClient.listener = object : ApiClient.ApiListener {
            override fun onLoginSuccess(token: String, nickname: String) {
                _loginUsername = securePrefs.username
                _uiState.value = _uiState.value.copy(
                    loggedIn = true,
                    nickname = nickname
                )
            }

            override fun onLoginFailed(error: String) {
                _uiState.value = _uiState.value.copy(error = "登录失败: $error")
            }

            override fun onUserList(users: List<User>) {
                _otherUsers.value = users
                mapViewInterface?.showOtherUsers(users)
            }

            override fun onUserJoined(username: String) {
                // 服务器会推送新的 user_list
            }

            override fun onUserLeft(username: String) {
                _otherUsers.value = _otherUsers.value.filter { it.username != username }
                mapViewInterface?.removeOtherUser(username)
            }

            override fun onTargetUpdate(username: String, targetLat: Double?, targetLng: Double?) {
                _otherUsers.value = _otherUsers.value.map { user ->
                    if (user.username == username) {
                        user.copy(targetLat = targetLat, targetLng = targetLng)
                    } else user
                }
                // 重新显示
                mapViewInterface?.showOtherUsers(_otherUsers.value)
            }

            override fun onPositionUpdate(username: String, lat: Double, lng: Double, heading: Float) {
                android.util.Log.d("MapDebug", "onPositionUpdate: username=$username lat=$lat lng=$lng currentUser=$_loginUsername")
                val currentUser = _loginUsername
                if (username == currentUser) {
                    // 自己的位置
                    mapViewInterface?.showUser(lat, lng, heading)
                } else {
                    // 其他用户的位置
                    _otherUsers.value = _otherUsers.value.map { user ->
                        if (user.username == username) {
                            user.copy(lat = lat, lng = lng, heading = heading)
                        } else user
                    }
                    mapViewInterface?.showOtherUsers(_otherUsers.value)
                }
            }

            override fun onError(message: String) {
                _uiState.value = _uiState.value.copy(error = message)
            }

            override fun onConnected() {}
            override fun onDisconnected() {}
        }
    }

    private fun attemptAutoLogin() {
        val username = securePrefs.username ?: return
        val password = securePrefs.password ?: return

        _uiState.value = _uiState.value.copy(autoLoggingIn = true)

        // 自动登录需要重新走 challenge-response 流程
        kotlinx.coroutines.MainScope().launch {
            when (val result = authRepository.login(username, password)) {
                is AuthRepository.LoginState.Success -> {
                    _uiState.value = _uiState.value.copy(autoLoggingIn = false)
                    _loginUsername = username
                }
                is AuthRepository.LoginState.Error -> {
                    _uiState.value = _uiState.value.copy(
                        autoLoggingIn = false,
                        error = result.message
                    )
                }
            }
        }
    }

    fun onServiceConnected(service: LocationTrackerService) {
        this.locationService = service
    }

    fun onMapReady() {
        // 地图就绪后，立即刷新当前位置并移动到我的位置
        locationService?.let { svc ->
            val pos = svc.getCurrentPosition()
            if (pos != null) {
                android.util.Log.d("MapDebug", "onMapReady: got position $pos")
                mapViewInterface?.showUser(pos.lat, pos.lng, svc.getCurrentHeading())
                mapViewInterface?.moveTo(pos.lat, pos.lng, 17.0)
            } else {
                android.util.Log.d("MapDebug", "onMapReady: no cached position, will use WebSocket updates")
            }
        }
    }

    fun setMapView(mapView: MapView) {
        this.mapViewInterface = mapView
        // 恢复已有用户
        mapView.showOtherUsers(_otherUsers.value)
        // 恢复目标点
        _uiState.value.targetLat?.let { lat ->
            _uiState.value.targetLng?.let { lng ->
                mapView.showTarget(lat, lng)
            }
        }
    }

    fun onMapClick(lat: Double, lng: Double) {
        _uiState.value = _uiState.value.copy(
            targetLat = lat,
            targetLng = lng
        )
        mapViewInterface?.showTarget(lat, lng)
        apiClient.sendTarget(lat, lng)
    }

    fun clearTarget() {
        _uiState.value = _uiState.value.copy(
            targetLat = null,
            targetLng = null
        )
        mapViewInterface?.clearTarget()
        apiClient.sendTarget(null, null)
    }

    fun logout() {
        authRepository.logout()
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
    val loggedIn: Boolean = false,
    val autoLoggingIn: Boolean = false,
    val nickname: String = "",
    val error: String? = null,
    val targetLat: Double? = null,
    val targetLng: Double? = null
)

@Composable
fun MapScreen(viewModel: MapViewModel) {
    val uiState by viewModel.uiState.collectAsState()
    val otherUsers by viewModel.otherUsers.collectAsState()
    val context = LocalContext.current

    var mapViewImpl by remember { mutableStateOf<MapViewImpl?>(null) }

    LaunchedEffect(uiState.error) {
        uiState.error?.let {
            Toast.makeText(context, it, Toast.LENGTH_SHORT).show()
            viewModel.clearError()
        }
    }

    Scaffold(
        floatingActionButton = {
            Column {
                FloatingActionButton(
                    onClick = {
                        // 由 LocationTrackerService 驱动位置更新
                    },
                    modifier = Modifier.padding(bottom = 8.dp)
                ) {
                    Icon(Icons.Default.LocationOn, contentDescription = "我的位置")
                }

                if (uiState.targetLat != null) {
                    FloatingActionButton(
                        onClick = { viewModel.clearTarget() }
                    ) {
                        Icon(Icons.Default.Clear, contentDescription = "清除目标")
                    }
                }
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            AndroidView(
                factory = { ctx ->
                    val impl = MapViewImpl(ctx)
                    mapViewImpl = impl

                    impl.setOnMapClickListener { lat, lng ->
                        viewModel.onMapClick(lat, lng)
                    }

                    impl.setOnFirstMapReadyListener {
                        android.util.Log.d("MapDebug", "onFirstMapReady called!")
                        viewModel.onMapReady()
                    }

                    viewModel.setMapView(impl)
                    impl.getView()
                },
                modifier = Modifier.fillMaxSize()
            )

            // 自动登录中提示
            if (uiState.autoLoggingIn) {
                CircularProgressIndicator(
                    modifier = Modifier
                        .align(androidx.compose.ui.Alignment.Center)
                        .size(48.dp)
                )
            }
        }
    }
}
