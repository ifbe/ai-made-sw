package com.example.pusher.camera

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.SurfaceTexture
import android.hardware.camera2.*
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import android.view.Gravity
import android.view.Surface
import android.view.TextureView
import android.view.View
import android.widget.FrameLayout
import androidx.core.content.ContextCompat
import com.example.pusher.utils.AppLog

class CameraHelper(
    private val context: Context,
    // 后置 / 前置
    private val lensFacing: Int = CameraCharacteristics.LENS_FACING_BACK,
    // 期望分辨率（会选最接近的可用尺寸）
    private val preferredWidth: Int = 1920,
    private val preferredHeight: Int = 1080,
    // 当前选择的视频编码器类型（用于校验编码器是否支持候选尺寸）
    private val videoMime: String = android.media.MediaFormat.MIMETYPE_VIDEO_AVC
) {

    private val cameraManager = context.getSystemService(Context.CAMERA_SERVICE) as android.hardware.camera2.CameraManager
    private var cameraId: String? = null
    private var cameraDevice: CameraDevice? = null
    private var captureSession: CameraCaptureSession? = null
    private var textureView: TextureView? = null
    private var surfaceTextureRef: SurfaceTexture? = null
    private var encoderSurface: Surface? = null

    /** 非 GL 路径下由我们创建的预览 Surface（相机直接写 TextureView 的 SurfaceTexture） */
    private var previewSurface: Surface? = null

    /**
     * 预览显示链路的 GL 直通渲染器：
     * 相机 → 它自己的 SurfaceTexture → GL(忽略变换矩阵) → TextureView 的 Surface。
     * 见 PreviewGlRenderer 的注释。
     */
    private var glRenderer: PreviewGlRenderer? = null

    // 是否已经 stop：camera2 的回调是异步的，stop 之后可能还有 onOpened/onConfigured 到达
    @Volatile
    private var released = false

    // 是否正在配置相机会话。配置期间禁止改 View 尺寸：
    // TextureView.onSizeChanged() 会把 SurfaceTexture 缓冲区尺寸改成 View 像素尺寸，
    // 而相机服务是异步读取该尺寸来配置预览流的 —— 一旦被改，画面会被 HAL 缩放变形并烤进帧数据。
    @Volatile
    private var sessionConfiguring = false

    // 实测到的"相机提示旋转"（-1=还没测到；0/90/270=元数据实测值）。
    // 预览的摆放完全按它来，不猜公式。
    @Volatile
    private var measuredHintRotation = -1

    // 实测到的"提示里是否带水平镜像"（前置相机通常带）
    @Volatile
    private var measuredMirrored = false

    @Volatile
    private var previewFrameCount = 0

    private var lastMatrixSignature: String? = null

    // 设备是否支持"明确要求不旋转不裁剪"
    private var rotateAndCropNoneSupported = false

    var previewWidth = 0
        private set
    var previewHeight = 0
        private set

    // 编码/推流尺寸：预览要按“与推流完全一致”来显示（所见即所推）
    private var encodeWidth = 0
    private var encodeHeight = 0

    /** 只查询将要使用的预览/编码尺寸（不会打开相机） */
    fun getPreviewSize(callback: (Int, Int) -> Unit) {
        getBestPreviewSize(callback)
    }

    /** 容器尺寸变化后重新计算预览画面尺寸（不重建会话） */
    fun refreshPreviewLayout() {
        applyPreviewLayout()
    }

    /**
     * 显示方向变化（横竖屏切换）。
     *
     * 预览走 GL 直通、完全无视相机的变换提示，所以"方向"本身不再需要跟着屏幕走；
     * 这里只需重新量一遍黑框尺寸（横屏时卡片变矮变宽，画面要重新等比摆放）。
     */
    fun onDisplayRotationChanged() {
        if (released) return
        // 只重新摆放，不重建会话。
        //
        // 早期版本在这里重建会话，是为了让相机按新屏幕方向重新下发 buffer transform 提示；
        // 现在预览摆放完全按**实测到的元数据**走，而那个提示描述的正是"显示侧会怎么转"，
        // 无论它是否随方向变化、是否过期，补偿都依然正确 —— 所以重建是多余的，
        // 而且每转一次屏就重启一次相机会话，推流会卡一下。去掉它，转屏时画面不中断。
        applyPreviewLayout()
        glRenderer?.onViewSizeChanged()
    }

    fun startPreview(
        textureView: TextureView,
        encoderSurface: Surface? = null,
        callback: (Boolean) -> Unit
    ) {
        released = false
        this.textureView = textureView
        this.encoderSurface = encoderSurface

        Log.d(TAG, "startPreview called, encoderSurface=$encoderSurface, facing=$lensFacing, " +
                "preferred=${preferredWidth}x$preferredHeight")

        textureView.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(surface: SurfaceTexture, width: Int, height: Int) {
                Log.d(TAG, "SurfaceTexture available: ${width}x${height}")
                surfaceTextureRef = surface
                if (released) return
                if (USE_GL_PREVIEW) {
                    // GL 路径：这个 SurfaceTexture 只是我们的显示目标，相机不直接写它
                    glRenderer?.attachView(surface)
                } else if (previewWidth > 0 && previewHeight > 0) {
                    // 直连路径：相机马上要按这个 Surface 配置预览流，先断言成推流尺寸
                    surface.setDefaultBufferSize(previewWidth, previewHeight)
                }

                // 相机还没开：初始打开由 startPreview 负责，这里不管
                if (cameraDevice == null) return

                // 相机已经在跑（折叠展开 / 从后台回来）：把预览流挂回会话
                rebuildSession(includePreview = true)
            }

            override fun onSurfaceTextureSizeChanged(surface: SurfaceTexture, width: Int, height: Int) {
                Log.d(TAG, "SurfaceTexture size changed: ${width}x$height")
                if (released) return
                // 黑框尺寸可能跟着卡片变了：重算摆放 + 让 GL 输出 Surface 跟上新分辨率
                applyPreviewLayout()
                glRenderer?.onViewSizeChanged()
            }

            override fun onSurfaceTextureDestroyed(surface: SurfaceTexture): Boolean {
                Log.d(TAG, "SurfaceTexture destroyed")
                surfaceTextureRef = null
                glRenderer?.detachView()
                // 预览不可见（折叠 / 锁屏 / 回 home）时 TextureView 的 Surface 会被销毁，
                // 但推流要继续：摘掉预览流，只用编码 Surface 重建会话继续出帧。
                if (!released && cameraDevice != null && encoderSurface?.isValid == true) {
                    rebuildSession(includePreview = false)
                }
                return true
            }

            override fun onSurfaceTextureUpdated(surface: SurfaceTexture) {
                // 相机给预览这一路的元数据（buffer transform）：
                //  1) 打进「app 特殊日志」；
                //  2) 作为**实测值**决定预览怎么摆（不猜传感器/屏幕方向的公式）。
                // 注意：第 1~2 帧读到的还是初始单位阵（HWUI 的 updateTexImage 还没跑），
                // 必须等几帧再采，否则会读到假数据。
                previewFrameCount++
                val n = previewFrameCount
                if (n < MATRIX_SETTLE_FRAMES) return
                val m = readTransformMatrix(surface) ?: return
                val signature = String.format(
                    java.util.Locale.US, "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f",
                    m[0], m[1], m[4], m[5], m[12], m[13]
                )
                if (signature == lastMatrixSignature) return
                lastMatrixSignature = signature
                AppLog.log(String.format(
                    java.util.Locale.US,
                    "预览元数据(第%d帧): [%.2f,%.2f,%.2f,%.2f] 平移=[%.2f,%.2f]",
                    n, m[0], m[1], m[4], m[5], m[12], m[13]
                ))
                val hint = rotationFromMatrix(m)
                val mirrored = mirroredFromMatrix(m)
                if (hint != measuredHintRotation || mirrored != measuredMirrored) {
                    measuredHintRotation = hint
                    measuredMirrored = mirrored
                    AppLog.log("预览元数据 → 实测相机提示旋转=${hint}° 镜像=${mirrored}，" +
                            "按它重排预览（屏幕旋转=${displayRotationDegrees()}°）")
                    applyPreviewLayout()
                }
            }
        }

        // 关键：不再等 SurfaceTexture 可用才开相机。
        // 新 UI 下视频模块默认是折叠(GONE)的，TextureView 没有 Surface；
        // 若在这里等，就会永远不开相机 → 视频流没有画面。
        // 相机该开就开（会话里先只挂编码 Surface），预览可见时再通过
        // onSurfaceTextureAvailable → rebuildSession 把预览流加回去。
        surfaceTextureRef = textureView.surfaceTexture
        getBestPreviewSize { pw, ph ->
            if (released) return@getBestPreviewSize
            previewWidth = pw
            previewHeight = ph
            Log.d(TAG, "Set buffer size: ${pw}x$ph")
            applyPreviewLayout()
            if (USE_GL_PREVIEW) {
                // GL 直通：相机的帧先写进 GL 自己的 SurfaceTexture，建好之后再开会话
                val renderer = glRenderer ?: PreviewGlRenderer().also { glRenderer = it }
                renderer.start()
                renderer.setBufferSize(pw, ph, cameraHandler()) {
                    if (released) return@setBufferSize
                    openCamera(callback)
                }
            } else {
                // 直连：相机直接写 TextureView 的 SurfaceTexture。
                // 必须把它的缓冲区尺寸断言成推流尺寸，否则相机会按 View 像素尺寸配置预览流，
                // 画面被 HAL 缩放变形后烤进帧数据。
                surfaceTextureRef?.setDefaultBufferSize(pw, ph)
                openCamera(callback)
            }
        }
    }

    /** 预览目标当前是否真的可用（折叠状态下 TextureView 没有 Surface） */
    private fun isPreviewAvailable(): Boolean {
        val view = textureView ?: return false
        if (!view.isAvailable) return false
        return (surfaceTextureRef ?: view.surfaceTexture) != null
    }

    /**
     * 选择最接近期望分辨率的 16:9 尺寸。
     */
    /** 尺寸选择结果 */
    private data class SizeChoice(
        val bufferW: Int,           // 相机缓冲尺寸（传感器方向，用于预览）
        val bufferH: Int,
        val encodeW: Int,           // 编码/推流尺寸
        val encodeH: Int,
        val swapped: Boolean,       // 屏幕方向是否与传感器差 90/270
        val encodeMatchesDisplay: Boolean,  // 是否成功采用“屏幕方向同尺寸”（竖屏流）
        val portraitCandidateSupported: Boolean,
        val stSizes: List<android.util.Size>,
        val codecSizes: List<android.util.Size>
    )

    /** 编码器（MediaCodec）自身是否支持该尺寸 */
    private fun isEncoderSizeSupported(w: Int, h: Int): Boolean {
        return try {
            val list = android.media.MediaCodecList(android.media.MediaCodecList.REGULAR_CODECS)
            list.codecInfos.any { info ->
                if (!info.isEncoder) return@any false
                if (info.supportedTypes.none { it.equals(videoMime, ignoreCase = true) }) return@any false
                val caps = info.getCapabilitiesForType(videoMime)
                caps.videoCapabilities?.isSizeSupported(w, h) ?: false
            }
        } catch (t: Throwable) {
            Log.w(TAG, "isEncoderSizeSupported failed", t)
            false
        }
    }

    private fun sameSize(a: android.util.Size, b: android.util.Size) =
        a.width == b.width && a.height == b.height

    /**
     * 选定两个尺寸：
     *  - bufferSize：相机缓冲尺寸（传感器方向），预览几何用它；
     *  - encodeSize：编码/推流尺寸。默认优先采用“屏幕方向上的同尺寸”
     *    （竖屏时即 1080x1920，这样接收端拿到的是竖屏视频），
     *    若相机/编码器不支持该尺寸，则回退到 bufferSize（保持原行为）。
     */
    private fun pickSizes(): SizeChoice? {
        val cameraId = pickCameraId() ?: return null
        val characteristics = cameraManager.getCameraCharacteristics(cameraId)
        val configs = characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP) ?: return null
        val stSizes = configs.getOutputSizes(SurfaceTexture::class.java)?.toList().orEmpty()
        if (stSizes.isEmpty()) return null
        val codecSizes = try {
            configs.getOutputSizes(android.media.MediaCodec::class.java)?.toList().orEmpty()
        } catch (t: Throwable) {
            Log.w(TAG, "getOutputSizes(MediaCodec) failed", t)
            emptyList()
        }

        // 1) 相机缓冲尺寸：优先与期望分辨率同比例、且两类输出都支持、最接近期望分辨率
        val targetRatio = preferredWidth.toFloat() / preferredHeight
        val sameRatio = stSizes.filter { Math.abs(it.width.toFloat() / it.height - targetRatio) < 0.05 }
        var candidates = if (sameRatio.isNotEmpty()) sameRatio else stSizes
        if (codecSizes.isNotEmpty()) {
            val both = candidates.filter { c -> codecSizes.any { sameSize(it, c) } }
            if (both.isNotEmpty()) candidates = both
        }
        rotateAndCropNoneSupported = try {
            characteristics.get(CameraCharacteristics.SCALER_AVAILABLE_ROTATE_AND_CROP_MODES)
                ?.contains(CaptureRequest.SCALER_ROTATE_AND_CROP_NONE) == true
        } catch (t: Throwable) {
            Log.w(TAG, "read SCALER_AVAILABLE_ROTATE_AND_CROP_MODES failed", t)
            false
        }

        val buffer = candidates.minByOrNull {
            Math.abs(it.width - preferredWidth) + Math.abs(it.height - preferredHeight)
        } ?: android.util.Size(preferredWidth, preferredHeight)

        // 2) 屏幕方向是否需要交换（与预览几何同一套公式）
        val sensor = characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 90
        val displayRotation = when (textureView?.display?.rotation ?: Surface.ROTATION_0) {
            Surface.ROTATION_90 -> 90
            Surface.ROTATION_180 -> 180
            Surface.ROTATION_270 -> 270
            else -> 0
        }
        val relative = ((sensor - displayRotation) % 360 + 360) % 360
        val swapped = (relative == 90 || relative == 270)

        // 3) 编码尺寸候选：屏幕方向上的同尺寸
        val displaySize = if (swapped) android.util.Size(buffer.height, buffer.width) else buffer
        val cameraSupportsDisplaySize = codecSizes.any { sameSize(it, displaySize) }
        val encoderSupportsDisplaySize = cameraSupportsDisplaySize &&
                isEncoderSizeSupported(displaySize.width, displaySize.height)
        val useDisplaySize = ENCODE_MATCH_DISPLAY && cameraSupportsDisplaySize &&
                encoderSupportsDisplaySize && !sameSize(displaySize, buffer)
        Log.d(TAG, "display size ${displaySize.width}x${displaySize.height}: " +
                "cameraSupports=$cameraSupportsDisplaySize encoderSupports=$encoderSupportsDisplaySize")

        encodeWidth = if (useDisplaySize) displaySize.width else buffer.width
        encodeHeight = if (useDisplaySize) displaySize.height else buffer.height
        return SizeChoice(
            bufferW = buffer.width,
            bufferH = buffer.height,
            encodeW = if (useDisplaySize) displaySize.width else buffer.width,
            encodeH = if (useDisplaySize) displaySize.height else buffer.height,
            swapped = swapped,
            encodeMatchesDisplay = useDisplaySize,
            portraitCandidateSupported = cameraSupportsDisplaySize,
            stSizes = stSizes,
            codecSizes = codecSizes
        )
    }

    private fun logSizeChoice(c: SizeChoice, forWhat: String) {
        val st = c.stSizes.joinToString(",") { "${it.width}x${it.height}" }
        val codec = if (c.codecSizes.isEmpty()) "(不可用)" else c.codecSizes.joinToString(",") { "${it.width}x${it.height}" }
        Log.d(TAG, "[$forWhat] buffer=${c.bufferW}x${c.bufferH} display=${if (c.swapped) "${c.bufferH}x${c.bufferW}" else "${c.bufferW}x${c.bufferH}"} encode=${c.encodeW}x${c.encodeH} portraitSupported=${c.portraitCandidateSupported}")
        AppLog.log("[$forWhat] 相机缓冲=${c.bufferW}x${c.bufferH}, 屏幕方向同尺寸=${if (c.swapped) "${c.bufferH}x${c.bufferW}" else "${c.bufferW}x${c.bufferH}"}, " +
                "编码尺寸=${c.encodeW}x${c.encodeH}, 采用屏幕方向尺寸=${c.encodeMatchesDisplay}, " +
                "该尺寸受支持=${c.portraitCandidateSupported}")
        AppLog.log("[$forWhat] 设备支持尺寸 SurfaceTexture=[$st]")
        AppLog.log("[$forWhat] 设备支持尺寸 MediaCodec=[$codec]")
    }

    /** 对外：返回“编码/推流尺寸”（MainActivity 用它配置编码器与流头） */
    private fun getBestPreviewSize(callback: (Int, Int) -> Unit) {
        try {
            val choice = pickSizes()
            if (choice == null) {
                Log.e(TAG, "No camera/size info, use preferred ${preferredWidth}x$preferredHeight")
                callback(preferredWidth, preferredHeight)
                return
            }
            logSizeChoice(choice, "编码尺寸")
            callback(choice.encodeW, choice.encodeH)
        } catch (e: Exception) {
            Log.e(TAG, "Error getting preview size", e)
            callback(preferredWidth, preferredHeight)
        }
    }

    /**
     * 按 lensFacing 挑相机；找不到就退回第一个。
     */
    private fun pickCameraId(): String? {
        val list = cameraManager.cameraIdList
        return list.firstOrNull { id ->
            cameraManager.getCameraCharacteristics(id).get(CameraCharacteristics.LENS_FACING) == lensFacing
        } ?: list.firstOrNull()
    }

    private fun openCamera(callback: (Boolean) -> Unit) {
        val handler = cameraHandler()

        try {
            val id = pickCameraId()
            cameraId = id
            if (id == null) {
                Log.e(TAG, "No camera found")
                callback(false)
                return
            }

            if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                Log.e(TAG, "Camera permission not granted")
                callback(false)
                return
            }

            AppLog.log("打开相机: id=$id facing=$lensFacing, 期望=${preferredWidth}x$preferredHeight")
            cameraManager.openCamera(id, object : CameraDevice.StateCallback() {
                override fun onOpened(camera: CameraDevice) {
                    Log.d(TAG, "Camera opened")
                    if (released) {
                        // stop 之后才回来：直接把相机还回去，避免泄漏 CAMERA 资源
                        camera.close()
                        return
                    }
                    cameraDevice = camera
                    // 预览可见才挂预览目标；折叠状态下只挂编码 Surface
                    createSession(camera, includePreview = isPreviewAvailable(), callback = callback)
                }

                override fun onDisconnected(camera: CameraDevice) {
                    Log.e(TAG, "Camera disconnected")
                    camera.close()
                    if (cameraDevice === camera) cameraDevice = null
                    if (!released) callback(false)
                }

                override fun onError(camera: CameraDevice, error: Int) {
                    Log.e(TAG, "Camera error: $error")
                    AppLog.log("相机错误: code=$error")
                    camera.close()
                    if (cameraDevice === camera) cameraDevice = null
                    if (!released) callback(false)
                }
            }, handler)

        } catch (e: Exception) {
            Log.e(TAG, "Error opening camera", e)
            callback(false)
        }
    }

    /**
     * 重建会话（后台/前台切换时增删预览目标）。旧会话先关闭再建新的。
     */
    private fun rebuildSession(includePreview: Boolean) {
        if (released) return
        val device = cameraDevice ?: return
        cameraHandler().post {
            if (released || cameraDevice == null) return@post
            Log.d(TAG, "rebuildSession(includePreview=$includePreview)")
            try {
                captureSession?.close()
            } catch (t: Throwable) {
                Log.w(TAG, "close old session failed", t)
            }
            captureSession = null
            createSession(device, includePreview, callback = null)
        }
    }

    /**
     * 预览画面的摆放（所见即所推）。
     *
     * 画面内容就是编码器拿到的同一份原始缓冲（不裁剪、不拉伸），
     * 摆放只做两件事：把显示侧多加的旋转抵消掉、把黑框按推流比例摆好。
     * 把**黑框**(preview_frame)按推流画面的比例算好尺寸并居中 ——
     * 黑框 = 收流端的画面窗口，画面正好铺满它，没有黑边也没有裁剪。
     *
     * TextureView 自己 match_parent 铺满黑框即可，不需要任何旋转/缩放/尺寸计算，
     * 因此横竖屏、自动旋转开关都不会改变"屏上 == 收流端"这个关系。
     */
    private fun applyPreviewLayout() {
        val view = textureView ?: return
        if (sessionConfiguring) {
            // 直连路径下 View 尺寸会影响相机的预览流配置，配置期间先不动布局
            Log.d(TAG, "applyPreviewLayout deferred: session configuring")
            return
        }
        if (previewWidth <= 0 || previewHeight <= 0) {
            Log.d(TAG, "applyPreviewLayout skipped: preview size unknown")
            return
        }
        val frameView = view.parent as? View ?: return          // 黑框
        val slot = frameView.parent as? View                     // 黑框可用的区域
        val availW = (slot?.width ?: 0).takeIf { it > 0 } ?: frameView.width
        val availH = (slot?.height ?: 0).takeIf { it > 0 } ?: frameView.height
        if (availW <= 0 || availH <= 0) {
            Log.d(TAG, "applyPreviewLayout skipped: area=${availW}x$availH")
            return
        }

        // 黑框 = 推流画面比例（等比收进可用区域）
        val rawRatio = previewWidth.toFloat() / previewHeight
        val targetW: Int
        val targetH: Int
        if (rawRatio > availW.toFloat() / availH) {
            targetW = availW
            targetH = (availW / rawRatio).toInt()
        } else {
            targetH = availH
            targetW = (availH * rawRatio).toInt()
        }
        if (targetW <= 0 || targetH <= 0) return

        // 画面**上屏后的呈现比例**：相机提示转了 90/270 时，显示管线会把宽高转过来。
        // PREVIEW_USE_MEASURED_HINT=false 时完全不用元数据（画面原样塞进黑框，只打日志）
        val hint = if (PREVIEW_USE_MEASURED_HINT) measuredHintRotation else -1
        val swap = (hint == 90 || hint == 270)
        val boxW = if (swap) targetH else targetW
        val boxH = if (swap) targetW else targetH
        // 是否需要水平镜像：前置相机预览比收流端多一次镜像（相机/显示侧带来的），要抵消掉。
        // 两条来源取或：实测矩阵判定 + 镜头朝向前置兜底（有的设备直接把镜像烤进像素里）。
        val mirrored = (PREVIEW_USE_MEASURED_HINT && measuredMirrored) ||
                (PREVIEW_MIRROR_FRONT && readLensFacing() == CameraCharacteristics.LENS_FACING_FRONT)

        // 逆着抵消相机提示的旋转：屏上就回到"编码器拿到的原始画面"，和收流端一致。
        // 带镜像时旋转与镜像共轭，方向要反过来（否则正好差 180°）。
        val rotation = if (hint > 0) {
            if (mirrored && MIRROR_FLIPS_ROTATION) hint % 360 else (360 - hint) % 360
        } else {
            0
        }

        val applyLayout = Runnable {
            if (released) return@Runnable
            var changed = false

            val flp = frameView.layoutParams
            if (flp != null && (flp.width != targetW || flp.height != targetH)) {
                flp.width = targetW
                flp.height = targetH
                if (flp is FrameLayout.LayoutParams) flp.gravity = Gravity.CENTER
                frameView.layoutParams = flp
                changed = true
            }

            val target = textureView
            val lp = target?.layoutParams
            if (lp != null && (lp.width != boxW || lp.height != boxH)) {
                lp.width = boxW
                lp.height = boxH
                if (lp is FrameLayout.LayoutParams) lp.gravity = Gravity.CENTER
                target.layoutParams = lp
                changed = true
            }

            if (target != null) {
                if (target.rotation != rotation.toFloat()) {
                    target.rotation = rotation.toFloat()
                    changed = true
                }
                val wantScaleX = if (mirrored) -1f else 1f
                if (target.scaleX != wantScaleX) {
                    target.scaleX = wantScaleX
                    changed = true
                }
                target.translationX = 0f
                target.translationY = 0f
            }

            if (changed) {
                Log.d(TAG, "预览摆放: 黑框=${targetW}x$targetH 盒=${boxW}x$boxH 旋转=${rotation}° " +
                        "镜像=$mirrored (实测提示=${hint}°, 推流画面=${previewWidth}x$previewHeight)")
                AppLog.log("预览摆放: 黑框=${targetW}x$targetH 画面盒=${boxW}x$boxH " +
                        "抵消旋转=${rotation}° 镜像=$mirrored " +
                        "(实测相机提示=${hint}° 屏幕旋转=${displayRotationDegrees()}°)")
            }
        }
        if (android.os.Looper.myLooper() == android.os.Looper.getMainLooper()) {
            applyLayout.run()
        } else {
            view.post(applyLayout)
        }
    }

    @Suppress("DEPRECATION")
    private fun createSession(device: CameraDevice, includePreview: Boolean, callback: ((Boolean) -> Unit)?) {
        val handler = cameraHandler()
        previewFrameCount = 0
        lastMatrixSignature = null

        // 预览流（可选）
        val newPreviewSurface: Surface? = if (includePreview) {
            if (USE_GL_PREVIEW) {
                // GL 直通：相机写进 GL 渲染器自己的 SurfaceTexture（这个 Surface 归渲染器所有，不能 release）
                val ps = glRenderer?.surface
                if (ps == null) {
                    Log.w(TAG, "请求了预览流，但 GL 预览 Surface 还没就绪")
                    null
                } else if (ps.isValid) {
                    AppLog.log("配置会话: 预览流=${previewWidth}x$previewHeight (GL 直通·原始画面)")
                    ps
                } else {
                    Log.w(TAG, "GL 预览 Surface 无效")
                    null
                }
            } else {
                // 直连：相机直接写 TextureView 的 SurfaceTexture，画面原样进矩形
                val st = surfaceTextureRef ?: textureView?.surfaceTexture
                if (st == null) {
                    Log.w(TAG, "请求了预览流，但 TextureView 的 SurfaceTexture 不可用")
                    null
                } else {
                    if (previewWidth > 0 && previewHeight > 0) {
                        st.setDefaultBufferSize(previewWidth, previewHeight)
                        AppLog.log("配置会话: 预览流=${previewWidth}x$previewHeight " +
                                "(直连 TextureView，尺寸已断言)")
                    }
                    val ps = Surface(st)
                    if (ps.isValid) ps else {
                        ps.release()
                        Log.w(TAG, "预览 Surface 无效")
                        null
                    }
                }
            }
        } else {
            null
        }

        if (!USE_GL_PREVIEW) {
            releasePreviewSurface()
            previewSurface = newPreviewSurface
        }

        val encoderSurf = encoderSurface
        val surfaces = mutableListOf<Surface>()
        if (newPreviewSurface != null) surfaces.add(newPreviewSurface)
        if (encoderSurf != null && encoderSurf.isValid) surfaces.add(encoderSurf)

        if (surfaces.isEmpty()) {
            Log.e(TAG, "No valid output surface for capture session")
            callback?.invoke(false)
            return
        }

        val captureRequestBuilder = try {
            device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                surfaces.forEach { addTarget(it) }
                set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                // 推流场景不要自动闪光（暗光下旧代码会触发闪光灯）
                set(CaptureRequest.CONTROL_AE_MODE, CaptureRequest.CONTROL_AE_MODE_ON)
                // 预览要和编码器拿到的一模一样 → 明确要求"不旋转、不裁剪"。
                // 有的设备默认 AUTO，可能把旋转/裁剪烤进预览帧里（编码器那路不受影响），
                // 那样预览就会又转又裁，和收流端对不上。
                if (rotateAndCropNoneSupported) {
                    set(CaptureRequest.SCALER_ROTATE_AND_CROP, CaptureRequest.SCALER_ROTATE_AND_CROP_NONE)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "createCaptureRequest failed", e)
            callback?.invoke(false)
            return
        }

        sessionConfiguring = true
        try {
            device.createCaptureSession(surfaces, object : CameraCaptureSession.StateCallback() {
                override fun onConfigured(session: CameraCaptureSession) {
                    sessionConfiguring = false
                    if (released) {
                        session.close()
                        return
                    }
                    captureSession = session
                    try {
                        session.setRepeatingRequest(captureRequestBuilder.build(), null, handler)
                    } catch (e: Exception) {
                        Log.e(TAG, "setRepeatingRequest failed", e)
                        callback?.invoke(false)
                        return
                    }

                    if (includePreview) {
                        // 会话就绪后再校一次比例（此时容器通常已经完成布局）
                        applyPreviewLayout()
                    }
                    Log.d(TAG, "session configured (preview=$includePreview, targets=${surfaces.size})")
                    AppLog.log("相机会话就绪: 预览流=$includePreview 输出数=${surfaces.size} " +
                            "画面尺寸=${previewWidth}x$previewHeight (原始画面·GL 直通)")
                    callback?.invoke(true)
                }

                override fun onConfigureFailed(session: CameraCaptureSession) {
                    sessionConfiguring = false
                    Log.e(TAG, "Capture session configuration failed (preview=$includePreview)")
                    AppLog.log("相机会话配置失败(预览流=$includePreview)")
                    if (includePreview) {
                        // 预览流不被接受时先摘掉它重试，保证推流不中断
                        AppLog.log("回退：摘掉预览流，只用编码 Surface 重建会话")
                        createSession(device, includePreview = false, callback = callback)
                        return
                    }
                    callback?.invoke(false)
                }
            }, handler)
        } catch (e: Exception) {
            sessionConfiguring = false
            Log.e(TAG, "createCaptureSession failed", e)
            callback?.invoke(false)
        }
    }

    private fun releasePreviewSurface() {
        try {
            previewSurface?.release()
        } catch (t: Throwable) {
            Log.w(TAG, "previewSurface.release failed", t)
        }
        previewSurface = null
    }

    private fun readLensFacing(): Int {
        return try {
            val id = cameraId ?: pickCameraId()
            if (id != null) {
                cameraManager.getCameraCharacteristics(id)
                    .get(CameraCharacteristics.LENS_FACING) ?: lensFacing
            } else {
                lensFacing
            }
        } catch (t: Throwable) {
            Log.w(TAG, "read LENS_FACING failed", t)
            lensFacing
        }
    }

    private fun readTransformMatrix(st: SurfaceTexture): FloatArray? {
        return try {
            val m = FloatArray(16)
            st.getTransformMatrix(m)
            m
        } catch (t: Throwable) {
            Log.w(TAG, "getTransformMatrix failed", t)
            null
        }
    }

    /**
     * 从相机给的变换矩阵读出"它把画面转了多少度"。
     *
     * 2x2 里主对角线占优（|m0|、|m5| 大）= 没转（180° 与 0° 无法区分，按不转处理）；
     * 副对角线占优（|m1|、|m4| 大）= 转了 90° 或 270°。
     * 90/270 的符号约定见 [HINT_90_IS_CLOCKWISE]。
     */
    private fun rotationFromMatrix(m: FloatArray): Int {
        val diag = Math.abs(m[0]) + Math.abs(m[5])
        val anti = Math.abs(m[1]) + Math.abs(m[4])
        if (anti <= diag) return 0
        val positive = if (HINT_90_IS_CLOCKWISE) m[1] > 0f else m[1] < 0f
        return if (positive) 90 else 270
    }

    /**
     * 提示矩阵里是否额外带了水平镜像。
     *
     * 纯旋转（含 gralloc 固有的那次 v 翻转）的 2x2 行列式是**负**的；
     * 再叠加一次镜像会让行列式变**正**。所以 det > 0 判为"带镜像"。
     *
     * 【本机实测】后置 [0,-1,-1,0] → det=-1（不镜像）；前置 [0,-1,1,0] → det=+1（镜像），
     * 且前置三种姿态实测与收流端一致。
     */
    private fun mirroredFromMatrix(m: FloatArray): Boolean {
        return (m[0] * m[5] - m[1] * m[4]) > 0f
    }

    private fun displayRotationDegrees(): Int = when (textureView?.display?.rotation ?: Surface.ROTATION_0) {
        Surface.ROTATION_90 -> 90
        Surface.ROTATION_180 -> 180
        Surface.ROTATION_270 -> 270
        else -> 0
    }

    fun stopPreview() {
        released = true
        sessionConfiguring = false
        try {
            captureSession?.close()
        } catch (t: Throwable) {
            Log.w(TAG, "captureSession.close failed", t)
        }
        captureSession = null

        try {
            cameraDevice?.close()
        } catch (t: Throwable) {
            Log.w(TAG, "cameraDevice.close failed", t)
        }
        cameraDevice = null

        releasePreviewSurface()
        encoderSurface = null
        textureView = null
        surfaceTextureRef = null

        // GL 预览链路整体释放（当前未启用；启用时才会创建）
        glRenderer?.release()
        glRenderer = null
    }

    private companion object {
        private const val TAG = "CameraHelper"

        /**
         * 预览是否走 GL 直通（[PreviewGlRenderer]）。
         *
         * 【当前 false】GL 直通在本机实测是黑屏，先关掉不调用（代码整体保留，方便后面继续调）。
         * 关掉时预览链路是"直连"：
         *   相机 → TextureView 的 SurfaceTexture → 屏幕
         * 画面原样塞进按**推流比例**算好的矩形里（1920x1080 的框），
         * 相机的 buffer transform 元数据完全不参与计算，只打进「app 特殊日志」。
         */
        private const val USE_GL_PREVIEW = false

        /**
         * 预览摆放是否采用**实测到的元数据**：
         *  true  = 用元数据决定"画面盒比例 + 抵消旋转"，让屏上尽可能等于收流端 —— 默认
         *  false = 完全不用元数据，画面原样塞进推流比例的矩形（元数据只打日志）
         */
        private const val PREVIEW_USE_MEASURED_HINT = true

        /** 前几帧读到的矩阵还是初始单位阵（HWUI 尚未 updateTexImage），跳过这么多帧再采信 */
        private const val MATRIX_SETTLE_FRAMES = 3

        /**
         * 兜底：镜头朝前时是否抵消水平镜像。
         *
         * 本机前置的镜像**写在元数据里**（det=+1，见 [mirroredFromMatrix]），靠矩阵判定就够了；
         * 这个开关是给"不写元数据、直接把镜像烤进像素"的设备兜底的。
         */
        private const val PREVIEW_MIRROR_FRONT = true

        /**
         * 带镜像时，补偿旋转的方向是否要反过来（镜像与旋转共轭，差 180°）。
         *
         * 【已实测确认 true】前置相机竖屏/左横/右横三种姿态均与收流端一致。
         * 若换设备后前置画面方向差 180°（上下颠倒、镜像方向是对的），把它改成 false。
         */
        private const val MIRROR_FLIPS_ROTATION = true

        /**
         * 元数据里副对角线 **m[1] < 0** 时，是否代表"顺时针 90°"。
         *
         * 【本机实测标定值，前后置均已三种姿态验证通过】
         *   后置：[0,-1,-1,0] 平移=[1,1]  det=-1 → 提示顺时针 90° → 抵消转 270°，不镜像
         *   前置：[0,-1, 1,0] 平移=[0,1]  det=+1 → 提示顺时针 90° → 抵消转  90°，且镜像
         * 物理上显示管线要把传感器的横向原始画面**顺时针转 90°** 才能摆正，
         * 即 m[1] < 0 对应顺时针 90°。
         * （一开始取反了，画面正好差 180°，已按实测改正。）
         *
         * 另外两种副对角线形态（m[1] > 0）按同一约定的镜像对称处理为 270°，
         * 对应屏幕/传感器方向相反的设备。
         */
        private const val HINT_90_IS_CLOCKWISE = false

        /**
         * 编码尺寸是否优先采用“屏幕方向上的同尺寸”：
         * 竖屏时把编码尺寸设成竖屏尺寸（如 1080x1920）。
         * 前提是相机+编码器支持该尺寸，否则自动回退到相机缓冲尺寸（横向）。
         *
         * 【当前默认 false】这是一项实验特性：改请求尺寸会让相机按竖屏比例裁剪，
         * 而 camera2 不旋转内容，画面方向取决于厂商 HAL。等实测确认后再单独打开验证。
         *
         * 注意：camera2 不负责旋转内容，只按请求比例裁剪+缩放，
         * 因此"帧变成竖的"和"内容也正过来"是两件事，取决于厂商 HAL，请用 ffplay 实测确认。
         */
        private const val ENCODE_MATCH_DISPLAY = false

        // 相机后台线程做成进程内共享：camera2 的回调是异步的，
        // 如果 stopPreview 把线程 quit 掉，晚到的 onOpened 会被丢弃，
        // 结果是相机被打开却永远没人 close（相机泄漏，下一次打开失败）。
        // 共享线程常驻，配合 released 标志即可安全地把晚到的相机还回去。
        private var sharedThread: HandlerThread? = null
        private var sharedHandler: Handler? = null

        @Synchronized
        private fun cameraHandler(): Handler {
            val alive = sharedThread?.isAlive == true
            if (!alive) {
                val thread = HandlerThread("CameraBackground").apply { start() }
                sharedThread = thread
                sharedHandler = Handler(thread.looper)
            }
            return sharedHandler ?: Handler(android.os.Looper.getMainLooper())
        }
    }
}
