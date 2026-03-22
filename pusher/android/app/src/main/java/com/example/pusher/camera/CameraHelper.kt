package com.example.pusher.camera

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.camera2.*
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import android.view.Surface
import android.view.SurfaceHolder
import android.view.SurfaceView
import androidx.core.content.ContextCompat

class CameraHelper(private val context: Context) {

    private val cameraManager = context.getSystemService(Context.CAMERA_SERVICE) as android.hardware.camera2.CameraManager
    private var cameraId: String? = null
    private var cameraDevice: CameraDevice? = null
    private var captureSession: CameraCaptureSession? = null
    private var backgroundHandler: Handler? = null
    private var backgroundThread: HandlerThread? = null
    private var previewSurfaceView: SurfaceView? = null
    private var previewSurfaceHolder: SurfaceHolder? = null
    private var encoderSurface: Surface? = null

    var previewWidth = 0
        private set
    var previewHeight = 0
        private set

    fun getPreviewSize(callback: (Int, Int) -> Unit) {
        getBestPreviewSize(callback)
    }

    fun startPreview(
        surfaceView: SurfaceView,
        encoderSurface: Surface? = null,
        callback: (Boolean) -> Unit
    ) {
        this.encoderSurface = encoderSurface
        this.previewSurfaceView = surfaceView
        this.previewSurfaceHolder = surfaceView.holder
        surfaceView.holder.setFormat(android.graphics.PixelFormat.RGBA_8888)

        Log.d("CameraHelper", "startPreview called, encoderSurface=$encoderSurface")

        // 添加 SurfaceHolder.Callback2 来检测渲染
        previewSurfaceHolder?.addCallback(object : SurfaceHolder.Callback2 {
            override fun surfaceRedrawNeeded(holder: SurfaceHolder) {
                Log.d("CameraHelper", "*** SURFACE REDRAW NEEDED - PREVIEW IS RENDERING ***")
            }

            override fun surfaceCreated(holder: SurfaceHolder) {
                Log.d("CameraHelper", "Surface created")
            }

            override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {
                Log.d("CameraHelper", "Surface changed: ${width}x${height}")
            }

            override fun surfaceDestroyed(holder: SurfaceHolder) {
                Log.d("CameraHelper", "Surface destroyed")
                stopPreview()
            }
        })

        // 先获取相机预览尺寸
        getBestPreviewSize { width, height ->
            if (width > 0 && height > 0) {
                previewWidth = width
                previewHeight = height
                Log.d("CameraHelper", "Preview size: ${width}x${height}")
                surfaceView.holder.setFixedSize(width, height)
                Log.d("CameraHelper", "Set SurfaceView fixed size to ${width}x${height}")
            }

            // 检查 Surface 是否已经创建
            if (surfaceView.holder.surface.isValid) {
                Log.d("CameraHelper", "Surface already valid, opening camera directly")
                openCamera(callback)
            } else {
                // 不需要再添加回调，已经添加过了
                Log.d("CameraHelper", "Waiting for surface creation")
            }
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
                Log.e("CameraHelper", "No camera found for preview size")
                callback(0, 0)
                return
            }

            val characteristics = cameraManager.getCameraCharacteristics(cameraId)
            val configs = characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
            val previewSizes = configs?.getOutputSizes(SurfaceHolder::class.java)

            if (previewSizes != null && previewSizes.isNotEmpty()) {
                Log.d("CameraHelper", "Supported preview sizes:")
                previewSizes.forEach { size ->
                    Log.d("CameraHelper", "  ${size.width} x ${size.height}")
                }

                val targetWidth = 1920
                val targetHeight = 1080
                val bestSize = previewSizes.minByOrNull { size ->
                    Math.abs(size.width - targetWidth) + Math.abs(size.height - targetHeight)
                } ?: previewSizes.first()

                Log.d("CameraHelper", "Best preview size: ${bestSize.width} x ${bestSize.height}")
                callback(bestSize.width, bestSize.height)
            } else {
                Log.w("CameraHelper", "No preview sizes available")
                callback(0, 0)
            }
        } catch (e: Exception) {
            Log.e("CameraHelper", "Error getting preview size", e)
            callback(0, 0)
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

    @Suppress("DEPRECATION")
    private fun createCaptureSession(callback: (Boolean) -> Unit) {
        val holder = previewSurfaceHolder ?: run {
            Log.e("CameraHelper", "previewSurfaceHolder is null")
            callback(false)
            return
        }

        val previewSurface = holder.surface
        if (!previewSurface.isValid) {
            Log.e("CameraHelper", "Preview surface is invalid")
            callback(false)
            return
        }

        Log.d("CameraHelper", "Preview surface is valid")

        val surfaces = mutableListOf<Surface>()
        surfaces.add(previewSurface)

        val encoderSurf = encoderSurface
        if (encoderSurf != null && encoderSurf.isValid) {
            Log.d("CameraHelper", "Adding encoder surface")
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

                // ✅ 只调用一次 setRepeatingRequest
                session.setRepeatingRequest(
                    captureRequestBuilder.build(),
                    object : CameraCaptureSession.CaptureCallback() {
                        override fun onCaptureStarted(
                            session: CameraCaptureSession,
                            request: CaptureRequest,
                            timestamp: Long,
                            frameNumber: Long
                        ) {
                            Log.d("CameraHelper", "Frame captured, frameNumber=$frameNumber")
                        }
                    },
                    backgroundHandler
                )

                Log.d("CameraHelper", "Capture session configured successfully")
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
        previewSurfaceView = null
        previewSurfaceHolder = null
    }
}