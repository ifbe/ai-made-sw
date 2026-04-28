package com.example.waterinbox.socket

import android.util.Log
import kotlinx.coroutines.*
import java.io.PrintWriter
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.LinkedBlockingQueue

object SocketManager {
    private const val TAG = "SocketManager"
    private const val QUEUE_CAPACITY = 100

    // Connection params
    var protocol = "TCP"  // "TCP" or "UDP"
    var ip = "192.168.5.129"
    var port = 9999
    var contentType = "quaternion"  // "quaternion" or "measure"

    // Connection state
    var isConnected = false
        private set

    private var tcpSocket: Socket? = null
    private var udpSocket: DatagramSocket? = null
    private var tcpWriter: PrintWriter? = null

    // Non-blocking send queue (sensor thread → IO thread)
    private val sendQueue = LinkedBlockingQueue<String>(QUEUE_CAPACITY)

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var senderJob: Job? = null

    /**
     * Attempt to connect using current protocol/ip/port.
     * Calls callback with true on success, false on failure.
     */
    fun connect(callback: (Boolean) -> Unit) {
        scope.launch {
            try {
                disconnectSync()
                when (protocol) {
                    "TCP" -> {
                        tcpSocket = Socket(ip, port)
                        tcpSocket?.let { sock ->
                            tcpWriter = PrintWriter(sock.getOutputStream(), true)
                            isConnected = true
                            startSender()
                            Log.i(TAG, "TCP connected to $ip:$port")
                            callback(true)
                        } ?: run {
                            isConnected = false
                            callback(false)
                        }
                    }
                    "UDP" -> {
                        udpSocket = DatagramSocket()
                        isConnected = true
                        startSender()
                        Log.i(TAG, "UDP connected to $ip:$port")
                        callback(true)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Connection failed: ${e.message}")
                isConnected = false
                callback(false)
            }
        }
    }

    private fun startSender() {
        senderJob?.cancel()
        senderJob = scope.launch {
            while (isActive && isConnected) {
                val data = sendQueue.poll()
                if (data != null) {
                    try {
                        when (protocol) {
                            "TCP" -> tcpWriter?.println(data)
                            "UDP" -> {
                                val addr = InetAddress.getByName(ip)
                                val buf = (data + "\n").toByteArray()
                                val packet = DatagramPacket(buf, buf.size, addr, port)
                                udpSocket?.send(packet)
                            }
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Send error: ${e.message}")
                        isConnected = false
                        break
                    }
                } else {
                    delay(5) // queue empty, small back-off
                }
            }
        }
    }

    /**
     * Disconnect and clean up resources.
     */
    fun disconnect() {
        scope.launch {
            disconnectSync()
        }
    }

    private fun disconnectSync() {
        senderJob?.cancel()
        senderJob = null
        try {
            tcpWriter?.close()
            tcpSocket?.close()
            tcpSocket = null
            tcpWriter = null
            udpSocket?.close()
            udpSocket = null
        } catch (e: Exception) {
            Log.e(TAG, "Disconnect error: ${e.message}")
        }
        isConnected = false
        sendQueue.clear()
    }

    /**
     * Called from SensorManager.emit() with current sensor data.
     * Non-blocking: formats data and enqueues it for sending.
     * Drops oldest items when queue is full (100 items max).
     */
    fun onSensorData(
        qx: Float, qy: Float, qz: Float, qw: Float,
        gx: Float, gy: Float, gz: Float,
        ax: Float, ay: Float, az: Float,
        mx: Float, my: Float, mz: Float,
        ms: Long
    ) {
        val data = when (contentType) {
            "quaternion" -> String.format("%.4f, %.4f, %.4f, %.4f", qx, qy, qz, qw)
            "measure"    -> String.format(
                "%.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f",
                gx, gy, gz,
                ax, ay, az,
                mx, my, mz,
                ms / 1_000_000_000.0,
            )
            else         -> return
        }
        // poll oldest if full (LinkedBlockingQueue drops null on offer but we want drop-oldest)
        if (sendQueue.remainingCapacity() == 0) {
            sendQueue.poll() // discard oldest
        }
        sendQueue.offer(data)
    }

    fun destroy() {
        disconnect()
        scope.cancel()
    }
}
