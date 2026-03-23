package com.example.pusher.camera

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.SurfaceTexture
import android.hardware.camera2.*
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import android.view.Surface
import android.view.TextureView
import android.view.ViewGroup
import android.widget.FrameLayout
import androidx.core.content.ContextCompat

class CameraHelper(private val context: Context) {

    private val cameraManager = context.getSystemService(Context.CAMERA_SERVICE) as android.hardware.camera2.CameraManager
    private var cameraId: String? = null
    private var cameraDevice: CameraDevice? = null
    private var captureSession: CameraCaptureSession? = null
    private var backgroundHandler: Handler? = null
    private var backgroundThread: HandlerThread? = null
    private var textureView: TextureView? = null
    private var encoderSurface: Surface? = null
    private var onPreviewReadyCallback: ((Int, Int) -> Unit)? = null

    var previewWidth = 0
        private set
    var previewHeight = 0
        private set

    fun setOnPreviewReady(callback: (Int, Int) -> Unit) {
        onPreviewReadyCallback = callback
    }

    fun getPreviewSize(callback: (Int, Int) -> Unit) {
        getBestPreviewSize(callback)
    }

    fun startPreview(
        textureView: TextureView,
        encoderSurface: Surface? = null,
        callback: (Boolean) -> Unit
    ) {
        this.textureView = textureView
        this.encoderSurface = encoderSurface

        Log.d("CameraHelper", "startPreview called, encoderSurface=$encoderSurface")

        textureView.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(surface: SurfaceTexture, width: Int, height: Int) {
                Log.d("CameraHelper", "SurfaceTexture available: ${width}x${height}")

                getBestPreviewSize { pw, ph ->
                    previewWidth = pw
                    previewHeight = ph
                    surface.setDefaultBufferSize(pw, ph)
                    Log.d("CameraHelper", "Set buffer size: ${pw}x${ph}")
                    openCamera(callback)
                }
            }

            override fun onSurfaceTextureSizeChanged(surface: SurfaceTexture, width: Int, height: Int) {
                Log.d("CameraHelper", "SurfaceTexture size changed: ${width}x${height}")
                adjustTextureViewSize(width, height)
            }

            override fun onSurfaceTextureDestroyed(surface: SurfaceTexture): Boolean {
                Log.d("CameraHelper", "SurfaceTexture destroyed")
                return true
            }

            override fun onSurfaceTextureUpdated(surface: SurfaceTexture) {
                // 不需要处理
            }
        }

        // 如果已经可用，直接获取预览尺寸并打开相机
        if (textureView.isAvailable) {
            Log.d("CameraHelper", "TextureView already available")
            getBestPreviewSize { pw, ph ->
                previewWidth = pw
                previewHeight = ph
                textureView.surfaceTexture?.setDefaultBufferSize(pw, ph)
                Log.d("CameraHelper", "Set buffer size: ${pw}x${ph}")
                openCamera(callback)
            }
        } else {
            Log.d("CameraHelper", "Waiting for TextureView to be available")
        }
    }

    private fun getBestPreviewSize(callback: (Int, Int) -> Unit) {
        try {
            val cameraIdList = cameraManager.cameraIdList
            val cameraId = cameraIdList.firstOrNull { id ->
                val characteristics = cameraManager.getCameraCharacteristics(id)
                characteristics.get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK
            } ?: cameraIdList.firstOrNull()

            if (cameraId == null) {
                Log.e("CameraHelper", "No camera found")
                callback(1920, 1080)
                return
            }

            val characteristics = cameraManager.getCameraCharacteristics(cameraId)
            val configs = characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
            val previewSizes = configs?.getOutputSizes(SurfaceTexture::class.java)

            if (previewSizes != null && previewSizes.isNotEmpty()) {
                // 只选择 16:9 比例的尺寸
                val targetRatio = 16f / 9f
                val targetWidth = 1920
                val targetHeight = 1080

                // 选择最接近 1920x1080 的尺寸，且不超过它
                val bestSize = previewSizes.filter { size ->
                    val ratio = size.width.toFloat() / size.height
                    Math.abs(ratio - targetRatio) < 0.05
                }.minByOrNull { size ->
                    Math.abs(size.width - targetWidth) + Math.abs(size.height - targetHeight)
                } ?: previewSizes.firstOrNull { size ->
                    val ratio = size.width.toFloat() / size.height
                    Math.abs(ratio - targetRatio) < 0.05
                }

                if (bestSize != null) {
                    Log.d("CameraHelper", "Selected preview size: ${bestSize.width} x ${bestSize.height}")
                    callback(bestSize.width, bestSize.height)
                } else {
                    Log.e("CameraHelper", "No suitable size found, using default")
                    callback(1920, 1080)
                }
            } else {
                Log.e("CameraHelper", "No preview sizes available")
                callback(1920, 1080)
            }
        } catch (e: Exception) {
            Log.e("CameraHelper", "Error getting preview size", e)
            callback(1920, 1080)
        }
    }

    private fun startBackgroundThread() {
        backgroundThread = HandlerThread("CameraBackground").apply { start() }
        backgroundHandler = Handler(backgroundThread!!.looper)
    }

    private fun stopBackgroundThread() {
        backgroundThread?.quitSafely()
        try {
            backgroundThread?.join()
        } catch (e: InterruptedException) {
            e.printStackTrace()
        }
        backgroundThread = null
        backgroundHandler = null
    }

    private fun openCamera(callback: (Boolean) -> Unit) {
        startBackgroundThread()

        try {
            val cameraIdList = cameraManager.cameraIdList
            cameraId = cameraIdList.firstOrNull { id ->
                val characteristics = cameraManager.getCameraCharacteristics(id)
                characteristics.get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK
            } ?: cameraIdList.firstOrNull()

            if (cameraId == null) {
                Log.e("CameraHelper", "No camera found")
                callback(false)
                return
            }

            if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                Log.e("CameraHelper", "Camera permission not granted")
                callback(false)
                return
            }

            cameraManager.openCamera(cameraId!!, object : CameraDevice.StateCallback() {
                override fun onOpened(camera: CameraDevice) {
                    Log.d("CameraHelper", "Camera opened")
                    cameraDevice = camera
                    createCaptureSession(callback)
                }

                override fun onDisconnected(camera: CameraDevice) {
                    Log.e("CameraHelper", "Camera disconnected")
                    camera.close()
                    callback(false)
                }

                override fun onError(camera: CameraDevice, error: Int) {
                    Log.e("CameraHelper", "Camera error: $error")
                    callback(false)
                }
            }, backgroundHandler)

        } catch (e: Exception) {
            Log.e("CameraHelper", "Error opening camera", e)
            callback(false)
        }
    }

    private fun adjustTextureViewSize(viewWidth: Int, viewHeight: Int) {
        val textureView = this.textureView ?: return

        android.os.Handler(android.os.Looper.getMainLooper()).post {
            // 相机比例 16:9
            val srcRatio = 16f / 9f  // 1.777
            val dstRatio = viewWidth.toFloat() / viewHeight  // 510/405 = 1.259

            var newWidth = viewWidth
            var newHeight = viewHeight

            if (srcRatio > dstRatio) {
                // 以宽度为准，高度按比例缩小
                newHeight = (viewWidth / srcRatio).toInt()
            } else {
                // 以高度为准，宽度按比例缩小
                newWidth = (viewHeight * srcRatio).toInt()
            }

            // 设置 TextureView 尺寸
            val layoutParams = textureView.layoutParams
            layoutParams.width = newWidth
            layoutParams.height = newHeight
            textureView.layoutParams = layoutParams

            // 让父容器居中（不需要 translation）
            textureView.translationX = 0f
            textureView.translationY = 0f

            Log.d("CameraHelper", "TextureView: ${newWidth}x${newHeight}")
        }
    }

    @Suppress("DEPRECATION")
    private fun createCaptureSession(callback: (Boolean) -> Unit) {
        val surfaceTexture = textureView?.surfaceTexture ?: run {
            Log.e("CameraHelper", "SurfaceTexture is null")
            callback(false)
            return
        }

        val previewSurface = Surface(surfaceTexture)
        val encoderSurf = encoderSurface

        if (!previewSurface.isValid) {
            Log.e("CameraHelper", "Preview surface is invalid")
            callback(false)
            return
        }

        val surfaces = mutableListOf<Surface>()
        surfaces.add(previewSurface)
        if (encoderSurf != null && encoderSurf.isValid) {
            surfaces.add(encoderSurf)
        }

        val captureRequestBuilder = cameraDevice!!.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
            addTarget(previewSurface)
            if (encoderSurf != null && encoderSurf.isValid) {
                addTarget(encoderSurf)
            }

            set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
            set(CaptureRequest.CONTROL_AE_MODE, CaptureRequest.CONTROL_AE_MODE_ON_AUTO_FLASH)
        }

        cameraDevice!!.createCaptureSession(surfaces, object : CameraCaptureSession.StateCallback() {
            override fun onConfigured(session: CameraCaptureSession) {
                captureSession = session
                session.setRepeatingRequest(captureRequestBuilder.build(), null, backgroundHandler)

                textureView?.post {
                    adjustTextureViewSize(textureView!!.width, textureView!!.height)
                }

                callback(true)
            }

            override fun onConfigureFailed(session: CameraCaptureSession) {
                Log.e("CameraHelper", "Capture session configuration failed")
                callback(false)
            }
        }, backgroundHandler)
    }

    fun stopPreview() {
        try {
            captureSession?.close()
            captureSession = null
            cameraDevice?.close()
            cameraDevice = null
        } catch (e: Exception) {
            e.printStackTrace()
        }
        stopBackgroundThread()
        encoderSurface = null
        textureView = null
    }
}