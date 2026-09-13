package com.example.pusher.camera

import android.graphics.SurfaceTexture
import android.opengl.EGL14
import android.opengl.EGLConfig
import android.opengl.EGLContext
import android.opengl.EGLDisplay
import android.opengl.EGLSurface
import android.opengl.GLES11Ext
import android.opengl.GLES20
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import android.view.Surface
import com.example.pusher.utils.AppLog
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.FloatBuffer
import java.util.Locale

/**
 * 预览"所见即所推"的 GL 直通渲染器。
 *
 * 【为什么需要它】
 * 相机写预览帧时会附带一个 buffer transform 提示（旋转/镜像/裁剪），TextureView 内部的
 * HWUI 会**自动按提示把画面转正**，而且没有公开 API 能关掉 —— 于是"屏上看到的"永远比
 * "编码器拿到的"多一次旋转，两边对不上。
 *
 * 【做法】绕开 TextureView 的取景逻辑，自己接管预览显示链路：
 *
 *   相机 ──► 本类的 SurfaceTexture ──GL(彻底无视变换矩阵，只做标准 v 翻转)──► TextureView 的 Surface
 *
 * 屏上显示的就是编码器拿到的同一份原始缓冲：不旋转、不裁剪、不拉伸、不做镜像，
 * 和收流端逐像素同向；屏幕方向、自动旋转开关都不影响它。
 *
 * 所有 GL/EGL 操作都在自己的渲染线程上执行，对外接口线程安全。
 */
internal class PreviewGlRenderer {

    private var thread: HandlerThread? = null
    private var handler: Handler? = null

    private var eglDisplay: EGLDisplay = EGL14.EGL_NO_DISPLAY
    private var eglContext: EGLContext = EGL14.EGL_NO_CONTEXT
    private var eglConfig: EGLConfig? = null
    private var pbufferSurface: EGLSurface = EGL14.EGL_NO_SURFACE

    /** 相机（生产者）往这里写帧 */
    private var cameraSt: SurfaceTexture? = null
    private var cameraSurface: Surface? = null
    private var cameraTexId = 0
    private var matrixLogged = false

    /** 我们自己（生产者）往 TextureView 的 SurfaceTexture 写帧 */
    private var windowSurface: EGLSurface = EGL14.EGL_NO_SURFACE
    private var viewSurface: Surface? = null
    private var viewWidth = 0
    private var viewHeight = 0

    private var program = 0
    private var aPosition = 0
    private var aTexCoord = 0
    private var uScale = 0
    private var bufferWidth = 0
    private var bufferHeight = 0

    private val quad: FloatBuffer = ByteBuffer
        .allocateDirect(QUAD.size * FLOAT_SIZE)
        .order(ByteOrder.nativeOrder())
        .asFloatBuffer()
        .apply {
            put(QUAD)
            position(0)
        }

    @Volatile
    private var released = false

    @Volatile
    private var drawScheduled = false

    /** 显示目标：TextureView 的 SurfaceTexture（我们作为生产者往里画） */
    @Volatile
    private var displaySt: SurfaceTexture? = null

    /** 相机可写的预览 Surface（还没准备好时为 null） */
    @Volatile
    var surface: Surface? = null
        private set

    val isReady: Boolean get() = surface != null

    // ------------------------------------------------------------------ 生命周期

    fun start() {
        if (handler != null) return
        released = false
        val t = HandlerThread("PreviewGl")
        t.start()
        thread = t
        handler = Handler(t.looper)
    }

    /**
     * 设定相机缓冲尺寸并（重新）创建相机的 SurfaceTexture。
     *
     * @param callbackHandler 回调线程，一般给相机会话用的那个 Handler
     * @param onSurface 相机可写的 Surface；失败时给 null（相机仍应以"只推流"方式打开）
     */
    fun setBufferSize(
        width: Int,
        height: Int,
        callbackHandler: Handler?,
        onSurface: (Surface?) -> Unit
    ) {
        bufferWidth = width
        bufferHeight = height
        val h = handler
        if (h == null) {
            Log.e(TAG, "setBufferSize 前必须先 start()")
            postTo(callbackHandler, onSurface, null)
            return
        }
        h.post {
            if (released) return@post
            releaseCameraTexture()
            if (width <= 0 || height <= 0) {
                postTo(callbackHandler, onSurface, null)
                return@post
            }
            if (!ensureEgl()) {
                postTo(callbackHandler, onSurface, null)
                return@post
            }
            val st = try {
                SurfaceTexture(cameraTexId).apply { setDefaultBufferSize(width, height) }
            } catch (t: Throwable) {
                Log.e(TAG, "创建相机 SurfaceTexture 失败", t)
                null
            }
            if (st == null) {
                postTo(callbackHandler, onSurface, null)
                return@post
            }
            st.setOnFrameAvailableListener({ onFrameAvailable() }, h)
            cameraSt = st
            val s = Surface(st)
            if (!s.isValid) {
                Log.e(TAG, "相机预览 Surface 无效")
                s.release()
                st.release()
                cameraSt = null
                postTo(callbackHandler, onSurface, null)
                return@post
            }
            cameraSurface = s
            surface = s
            matrixLogged = false
            Log.d(TAG, "相机预览 Surface 就绪: ${width}x$height")
            AppLog.log("预览链路: GL 直通就绪，相机缓冲=${width}x$height（原始画面，无视变换矩阵）")
            postTo(callbackHandler, onSurface, s)
        }
    }

    /** 预览可见：把 TextureView 的 SurfaceTexture 挂成 GL 的输出目标 */
    fun attachView(surfaceTexture: SurfaceTexture) {
        displaySt = surfaceTexture
        handler?.post {
            if (released) return@post
            destroyWindowSurface()
            if (!ensureEgl()) return@post
            createWindowSurface(surfaceTexture)
        }
    }

    /** 预览不可见：断开输出目标（相机 SurfaceTexture 保留，不进会话就不产帧） */
    fun detachView() {
        displaySt = null
        handler?.post { if (!released) destroyWindowSurface() }
    }

    /** TextureView 尺寸变了（黑框重新算过尺寸），重建输出 Surface 以匹配分辨率 */
    fun onViewSizeChanged() {
        handler?.post {
            if (released) return@post
            val st = displaySt ?: return@post
            destroyWindowSurface()
            createWindowSurface(st)
        }
    }

    fun release() {
        released = true
        val h = handler
        if (h == null) {
            surface = null
            return
        }
        h.post { teardown() }
        thread?.quitSafely()
        thread = null
        handler = null
        surface = null
    }

    // ------------------------------------------------------------------ 渲染

    private fun onFrameAvailable() {
        if (released || drawScheduled) return
        drawScheduled = true
        handler?.post {
            drawScheduled = false
            drawFrame()
        }
    }

    private fun drawFrame() {
        if (released) return
        val st = cameraSt ?: return
        if (eglDisplay == EGL14.EGL_NO_DISPLAY || eglContext == EGL14.EGL_NO_CONTEXT) return

        // updateTexImage 必须在 EGL context current 的线程上调用
        val visible = windowSurface != EGL14.EGL_NO_SURFACE
        val target = if (visible) windowSurface else pbufferSurface
        if (!EGL14.eglMakeCurrent(eglDisplay, target, target, eglContext)) {
            Log.w(TAG, "eglMakeCurrent 失败: 0x${Integer.toHexString(EGL14.eglGetError())}")
            return
        }
        try {
            st.updateTexImage()
        } catch (t: Throwable) {
            Log.w(TAG, "updateTexImage 失败", t)
            return
        }
        if (!matrixLogged) {
            matrixLogged = true
            logTransformMatrix(st)
        }
        // 预览不可见：帧已经被取走（避免相机这块缓冲被占满），不画
        if (!visible) return

        GLES20.glViewport(0, 0, viewWidth, viewHeight)
        GLES20.glClearColor(0f, 0f, 0f, 1f)
        GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT)

        GLES20.glUseProgram(program)
        // 等比收进窗口（正常情况下黑框比例 == 画面比例，缩放系数正好是 1，不会出现黑边；
        // 万一布局还没算好，也只是短暂留黑边，绝不拉伸）
        if (bufferWidth > 0 && bufferHeight > 0 && viewWidth > 0 && viewHeight > 0) {
            val bufRatio = bufferWidth.toFloat() / bufferHeight
            val viewRatio = viewWidth.toFloat() / viewHeight
            var sx = 1f
            var sy = 1f
            if (bufRatio > viewRatio) sy = viewRatio / bufRatio else sx = bufRatio / viewRatio
            GLES20.glUniform2f(uScale, sx, sy)
        }
        GLES20.glActiveTexture(GLES20.GL_TEXTURE0)
        GLES20.glBindTexture(GLES11Ext.GL_TEXTURE_EXTERNAL_OES, cameraTexId)

        quad.position(0)
        GLES20.glVertexAttribPointer(aPosition, 2, GLES20.GL_FLOAT, false, STRIDE, quad)
        GLES20.glEnableVertexAttribArray(aPosition)
        quad.position(2)
        GLES20.glVertexAttribPointer(aTexCoord, 2, GLES20.GL_FLOAT, false, STRIDE, quad)
        GLES20.glEnableVertexAttribArray(aTexCoord)

        GLES20.glDrawArrays(GLES20.GL_TRIANGLE_STRIP, 0, 4)

        if (!EGL14.eglSwapBuffers(eglDisplay, windowSurface)) {
            Log.w(TAG, "eglSwapBuffers 失败: 0x${Integer.toHexString(EGL14.eglGetError())}")
        }
    }

    // ------------------------------------------------------------------ EGL / GL 初始化

    private fun ensureEgl(): Boolean {
        if (eglDisplay != EGL14.EGL_NO_DISPLAY && eglContext != EGL14.EGL_NO_CONTEXT) return true

        eglDisplay = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY)
        if (eglDisplay == EGL14.EGL_NO_DISPLAY) {
            Log.e(TAG, "eglGetDisplay 失败")
            return false
        }
        val version = IntArray(2)
        if (!EGL14.eglInitialize(eglDisplay, version, 0, version, 1)) {
            Log.e(TAG, "eglInitialize 失败")
            eglDisplay = EGL14.EGL_NO_DISPLAY
            return false
        }

        val configAttrs = intArrayOf(
            EGL14.EGL_RED_SIZE, 8,
            EGL14.EGL_GREEN_SIZE, 8,
            EGL14.EGL_BLUE_SIZE, 8,
            EGL14.EGL_ALPHA_SIZE, 8,
            EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
            EGL14.EGL_SURFACE_TYPE, EGL14.EGL_WINDOW_BIT or EGL14.EGL_PBUFFER_BIT,
            EGL14.EGL_NONE
        )
        val configs = arrayOfNulls<EGLConfig>(1)
        val numConfigs = IntArray(1)
        if (!EGL14.eglChooseConfig(eglDisplay, configAttrs, 0, configs, 0, 1, numConfigs, 0) ||
            numConfigs[0] <= 0 || configs[0] == null
        ) {
            Log.e(TAG, "eglChooseConfig 失败")
            return false
        }
        eglConfig = configs[0]

        val contextAttrs = intArrayOf(EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE)
        eglContext = EGL14.eglCreateContext(eglDisplay, eglConfig, EGL14.EGL_NO_CONTEXT, contextAttrs, 0)
        if (eglContext == EGL14.EGL_NO_CONTEXT) {
            Log.e(TAG, "eglCreateContext 失败")
            return false
        }

        // 先挂一个 1x1 的 pbuffer，保证创建纹理/SurfaceTexture 时有 current context
        val pbufferAttrs = intArrayOf(
            EGL14.EGL_WIDTH, 1,
            EGL14.EGL_HEIGHT, 1,
            EGL14.EGL_NONE
        )
        pbufferSurface = EGL14.eglCreatePbufferSurface(eglDisplay, eglConfig, pbufferAttrs, 0)
        if (pbufferSurface == EGL14.EGL_NO_SURFACE ||
            !EGL14.eglMakeCurrent(eglDisplay, pbufferSurface, pbufferSurface, eglContext)
        ) {
            Log.e(TAG, "创建 pbuffer / makeCurrent 失败")
            return false
        }

        if (!createProgram()) return false
        createCameraTexture()
        return true
    }

    private fun createWindowSurface(st: SurfaceTexture) {
        if (eglDisplay == EGL14.EGL_NO_DISPLAY || eglConfig == null) return
        val s = Surface(st)
        if (!s.isValid) {
            s.release()
            Log.w(TAG, "TextureView 的 Surface 无效")
            return
        }
        val attrs = intArrayOf(EGL14.EGL_NONE)
        val ws = EGL14.eglCreateWindowSurface(eglDisplay, eglConfig, s, attrs, 0)
        if (ws == null || ws == EGL14.EGL_NO_SURFACE) {
            Log.w(TAG, "eglCreateWindowSurface 失败: 0x${Integer.toHexString(EGL14.eglGetError())}")
            s.release()
            return
        }
        viewSurface = s
        windowSurface = ws
        if (!EGL14.eglMakeCurrent(eglDisplay, ws, ws, eglContext)) {
            Log.w(TAG, "窗口 Surface makeCurrent 失败")
        }
        val w = IntArray(1)
        val h = IntArray(1)
        EGL14.eglQuerySurface(eglDisplay, ws, EGL14.EGL_WIDTH, w, 0)
        EGL14.eglQuerySurface(eglDisplay, ws, EGL14.EGL_HEIGHT, h, 0)
        viewWidth = w[0]
        viewHeight = h[0]
        Log.d(TAG, "预览输出就绪: ${viewWidth}x$viewHeight")
    }

    private fun destroyWindowSurface() {
        if (eglDisplay != EGL14.EGL_NO_DISPLAY && eglContext != EGL14.EGL_NO_CONTEXT) {
            EGL14.eglMakeCurrent(
                eglDisplay, pbufferSurface, pbufferSurface, eglContext
            )
            if (windowSurface != EGL14.EGL_NO_SURFACE) {
                EGL14.eglDestroySurface(eglDisplay, windowSurface)
            }
        }
        windowSurface = EGL14.EGL_NO_SURFACE
        viewSurface?.release()
        viewSurface = null
        viewWidth = 0
        viewHeight = 0
    }

    private fun createCameraTexture() {
        val ids = IntArray(1)
        GLES20.glGenTextures(1, ids, 0)
        cameraTexId = ids[0]
        GLES20.glBindTexture(GLES11Ext.GL_TEXTURE_EXTERNAL_OES, cameraTexId)
        GLES20.glTexParameterf(GLES11Ext.GL_TEXTURE_EXTERNAL_OES, GLES20.GL_TEXTURE_MIN_FILTER, GLES20.GL_LINEAR.toFloat())
        GLES20.glTexParameterf(GLES11Ext.GL_TEXTURE_EXTERNAL_OES, GLES20.GL_TEXTURE_MAG_FILTER, GLES20.GL_LINEAR.toFloat())
        GLES20.glTexParameteri(GLES11Ext.GL_TEXTURE_EXTERNAL_OES, GLES20.GL_TEXTURE_WRAP_S, GLES20.GL_CLAMP_TO_EDGE)
        GLES20.glTexParameteri(GLES11Ext.GL_TEXTURE_EXTERNAL_OES, GLES20.GL_TEXTURE_WRAP_T, GLES20.GL_CLAMP_TO_EDGE)
        GLES20.glBindTexture(GLES11Ext.GL_TEXTURE_EXTERNAL_OES, 0)
    }

    private fun createProgram(): Boolean {
        val vs = compileShader(GLES20.GL_VERTEX_SHADER, VERTEX_SHADER)
        val fs = compileShader(GLES20.GL_FRAGMENT_SHADER, FRAGMENT_SHADER)
        if (vs == 0 || fs == 0) return false
        val p = GLES20.glCreateProgram()
        GLES20.glAttachShader(p, vs)
        GLES20.glAttachShader(p, fs)
        GLES20.glLinkProgram(p)
        val linked = IntArray(1)
        GLES20.glGetProgramiv(p, GLES20.GL_LINK_STATUS, linked, 0)
        if (linked[0] != GLES20.GL_TRUE) {
            Log.e(TAG, "链接 shader 失败: ${GLES20.glGetProgramInfoLog(p)}")
            GLES20.glDeleteProgram(p)
            return false
        }
        GLES20.glDeleteShader(vs)
        GLES20.glDeleteShader(fs)
        program = p
        aPosition = GLES20.glGetAttribLocation(p, "aPosition")
        aTexCoord = GLES20.glGetAttribLocation(p, "aTexCoord")
        uScale = GLES20.glGetUniformLocation(p, "uScale")
        return true
    }

    private fun compileShader(type: Int, src: String): Int {
        val id = GLES20.glCreateShader(type)
        GLES20.glShaderSource(id, src)
        GLES20.glCompileShader(id)
        val ok = IntArray(1)
        GLES20.glGetShaderiv(id, GLES20.GL_COMPILE_STATUS, ok, 0)
        if (ok[0] != GLES20.GL_TRUE) {
            Log.e(TAG, "编译 shader 失败: ${GLES20.glGetShaderInfoLog(id)}")
            GLES20.glDeleteShader(id)
            return 0
        }
        return id
    }

    private fun releaseCameraTexture() {
        cameraSt?.let { st ->
            try {
                st.setOnFrameAvailableListener(null)
            } catch (_: Throwable) {
            }
            try {
                st.release()
            } catch (t: Throwable) {
                Log.w(TAG, "SurfaceTexture.release 失败", t)
            }
        }
        cameraSt = null
        cameraSurface?.release()
        cameraSurface = null
        surface = null
    }

    private fun teardown() {
        released = true
        destroyWindowSurface()
        releaseCameraTexture()
        if (cameraTexId != 0) {
            GLES20.glDeleteTextures(1, intArrayOf(cameraTexId), 0)
            cameraTexId = 0
        }
        if (program != 0) {
            GLES20.glDeleteProgram(program)
            program = 0
        }
        if (eglDisplay != EGL14.EGL_NO_DISPLAY) {
            EGL14.eglMakeCurrent(
                eglDisplay, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT
            )
            if (pbufferSurface != EGL14.EGL_NO_SURFACE) {
                EGL14.eglDestroySurface(eglDisplay, pbufferSurface)
            }
            pbufferSurface = EGL14.EGL_NO_SURFACE
            if (eglContext != EGL14.EGL_NO_CONTEXT) {
                EGL14.eglDestroyContext(eglDisplay, eglContext)
            }
            EGL14.eglTerminate(eglDisplay)
        }
        eglContext = EGL14.EGL_NO_CONTEXT
        eglDisplay = EGL14.EGL_NO_DISPLAY
    }

    /** 只打日志：相机给预览这一路的 transform 提示长什么样（我们并不使用它） */
    private fun logTransformMatrix(st: SurfaceTexture) {
        try {
            val m = FloatArray(16)
            st.getTransformMatrix(m)
            AppLog.log(
                String.format(
                    Locale.US,
                    "相机变换提示(已忽略): [%.2f,%.2f,%.2f,%.2f] 平移=[%.2f,%.2f]",
                    m[0], m[1], m[4], m[5], m[12], m[13]
                )
            )
        } catch (t: Throwable) {
            Log.w(TAG, "getTransformMatrix 失败", t)
        }
    }

    private fun postTo(handler: Handler?, cb: (Surface?) -> Unit, value: Surface?) {
        if (handler == null) cb(value) else handler.post { cb(value) }
    }

    private companion object {
        private const val TAG = "PreviewGl"
        private const val FLOAT_SIZE = 4
        private const val STRIDE = 4 * FLOAT_SIZE

        /**
         * 顶点：x, y (NDC) + u, v。
         *
         * v 用的是**标准翻转**（屏幕上方取缓冲第一行）：这是 gralloc 行序与 GL 原点之间
         * 的固定约定，也是"完全不看变换矩阵"时唯一必须保留的一项 —— 保留它画面才是正的，
         * 但相机附加的旋转/镜像/裁剪提示一律不采用，所以屏上 = 编码器拿到的原始画面。
         */
        private val QUAD = floatArrayOf(
            -1f, -1f, 0f, 1f,
            1f, -1f, 1f, 1f,
            -1f, 1f, 0f, 0f,
            1f, 1f, 1f, 0f
        )

        private val VERTEX_SHADER = """
            attribute vec4 aPosition;
            attribute vec2 aTexCoord;
            uniform vec2 uScale;
            varying vec2 vTexCoord;
            void main() {
                gl_Position = vec4(aPosition.xy * uScale, 0.0, 1.0);
                vTexCoord = aTexCoord;
            }
        """.trimIndent()

        private val FRAGMENT_SHADER = """
            #extension GL_OES_EGL_image_external : require
            precision mediump float;
            varying vec2 vTexCoord;
            uniform samplerExternalOES sTexture;
            void main() {
                gl_FragColor = texture2D(sTexture, vTexCoord);
            }
        """.trimIndent()
    }
}
