package com.example.locate.ui.login

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.locate.data.local.SecurePrefs
import com.example.locate.data.repository.AuthRepository
import com.example.locate.ui.map.MapActivity
import com.example.locate.util.Constants
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class LoginActivity : ComponentActivity() {

    private lateinit var viewModel: LoginViewModel

    private val locationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val fineLocationGranted = permissions[Manifest.permission.ACCESS_FINE_LOCATION] == true
        if (fineLocationGranted) {
            viewModel.onPermissionsGranted()
        } else {
            Toast.makeText(this, "需要位置权限才能使用", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val securePrefs = SecurePrefs(this)
        viewModel = LoginViewModel(
            AuthRepository(Constants.DEFAULT_SERVER_URL, securePrefs),
            securePrefs
        )

        // 检查已保存凭证
        viewModel.checkSavedCredentials()

        setContent {
            MaterialTheme {
                LoginScreen(
                    viewModel = viewModel,
                    onLoginSuccess = {
                        requestLocationPermissions()
                    },
                    onNavigateToMap = {
                        startActivity(Intent(this, MapActivity::class.java))
                        finish()
                    }
                )
            }
        }
    }

    private fun requestLocationPermissions() {
        val permissions = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        locationPermissionLauncher.launch(permissions.toTypedArray())
    }
}

class LoginViewModel(
    private var authRepository: AuthRepository,
    private val securePrefs: SecurePrefs
) : ViewModel() {

    private val _uiState = MutableStateFlow(LoginUiState(
        serverUrl = securePrefs.serverUrl
    ))
    val uiState: StateFlow<LoginUiState> = _uiState

    private val _loginSuccess = MutableStateFlow(false)
    val loginSuccess: StateFlow<Boolean> = _loginSuccess

    fun checkSavedCredentials() {
        if (authRepository.hasSavedCredentials()) {
            _uiState.value = _uiState.value.copy(
                username = securePrefs.username ?: "",
                autoLogin = true
            )
            // 自动登录（后续完善）
        }
    }

    fun onServerUrlChange(serverUrl: String) {
        if (serverUrl == _uiState.value.serverUrl) return
        _uiState.value = _uiState.value.copy(serverUrl = serverUrl)
        securePrefs.serverUrl = serverUrl
        authRepository = AuthRepository(serverUrl, securePrefs)
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

        viewModelScope.launch {
            when (val result = authRepository.login(state.username, state.password)) {
                is AuthRepository.LoginState.Success -> {
                    _loginSuccess.value = true
                }
                is AuthRepository.LoginState.Error -> {
                    _uiState.value = _uiState.value.copy(
                        loading = false,
                        error = result.message
                    )
                }
            }
        }
    }

    fun onPermissionsGranted() {
        _loginSuccess.value = true
    }

    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }
}

data class LoginUiState(
    val serverUrl: String = Constants.DEFAULT_SERVER_URL,
    val username: String = "",
    val password: String = "",
    val loading: Boolean = false,
    val error: String? = null,
    val autoLogin: Boolean = false
)

@Composable
fun LoginScreen(
    viewModel: LoginViewModel,
    onLoginSuccess: () -> Unit,
    onNavigateToMap: () -> Unit
) {
    val uiState by viewModel.uiState.collectAsState()
    val loginSuccess by viewModel.loginSuccess.collectAsState()
    val focusManager = LocalFocusManager.current
    val context = LocalContext.current

    LaunchedEffect(loginSuccess) {
        if (loginSuccess) {
            onNavigateToMap()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "旅迹定位",
            style = MaterialTheme.typography.headlineLarge
        )

        Spacer(modifier = Modifier.height(48.dp))

        OutlinedTextField(
            value = uiState.serverUrl,
            onValueChange = viewModel::onServerUrlChange,
            label = { Text("服务器地址") },
            singleLine = true,
            enabled = !uiState.loading,
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Uri,
                imeAction = ImeAction.Next
            ),
            keyboardActions = KeyboardActions(onNext = { focusManager.moveFocus(FocusDirection.Down) }),
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedTextField(
            value = uiState.username,
            onValueChange = viewModel::onUsernameChange,
            label = { Text("用户名") },
            singleLine = true,
            enabled = !uiState.loading,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
            keyboardActions = KeyboardActions(onNext = { focusManager.moveFocus(FocusDirection.Down) }),
            modifier = Modifier.fillMaxWidth()
        )

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedTextField(
            value = uiState.password,
            onValueChange = viewModel::onPasswordChange,
            label = { Text("密码") },
            singleLine = true,
            enabled = !uiState.loading,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                imeAction = ImeAction.Done
            ),
            keyboardActions = KeyboardActions(onDone = {
                focusManager.clearFocus()
                viewModel.onLogin()
            }),
            modifier = Modifier.fillMaxWidth()
        )

        uiState.error?.let { error ->
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = error,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        Button(
            onClick = { viewModel.onLogin() },
            enabled = !uiState.loading && uiState.username.isNotBlank() && uiState.password.isNotBlank(),
            modifier = Modifier.fillMaxWidth()
        ) {
            if (uiState.loading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = MaterialTheme.colorScheme.onPrimary,
                    strokeWidth = 2.dp
                )
                Spacer(modifier = Modifier.width(8.dp))
            }
            Text("登录")
        }
    }
}
