package com.example.p2pnet

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import com.example.p2pnet.data.local.LocalPrefs
import com.example.p2pnet.data.repository.P2pRepository
import com.example.p2pnet.service.P2pService
import com.example.p2pnet.ui.MainScreen
import com.example.p2pnet.ui.login.LoginViewModel
import com.example.p2pnet.ui.theme.P2pnetTheme

class MainActivity : ComponentActivity() {

    private var p2pService: P2pService? = null
    private var serviceBound = false
    private lateinit var viewModel: LoginViewModel
    private val localPrefs by lazy { LocalPrefs(this) }
    private val repository by lazy { P2pRepository(localPrefs) }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val b = binder as P2pService.LocalBinder
            p2pService = b.getService()
            serviceBound = true
            repository.useClient(p2pService!!.wsClient)
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            serviceBound = false
            p2pService = null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        viewModel = LoginViewModel(repository)

        viewModel.onStartService = { startP2pService() }
        viewModel.onStopService = { stopP2pService() }

        // Bind to existing service if running
        bindService(
            Intent(this, P2pService::class.java),
            serviceConnection,
            Context.BIND_AUTO_CREATE
        )

        setContent {
            P2pnetTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainScreen(viewModel = viewModel)
                }
            }
        }
    }

    fun startP2pService() {
        val intent = Intent(this, P2pService::class.java)
        startForegroundService(intent)
        // Rebind to get the new service instance
        if (!serviceBound) {
            bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
        }
    }

    fun stopP2pService() {
        if (serviceBound) {
            unbindService(serviceConnection)
            serviceBound = false
        }
        stopService(Intent(this, P2pService::class.java))
        repository.useClient(null)
    }

    override fun onDestroy() {
        if (serviceBound) {
            unbindService(serviceConnection)
            serviceBound = false
        }
        super.onDestroy()
    }
}
