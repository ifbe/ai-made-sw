package com.example.waterinbox.renderer

import android.content.Context
import android.opengl.GLES30
import android.opengl.GLSurfaceView
import android.util.DisplayMetrics
import android.util.Log
import javax.microedition.khronos.egl.EGLConfig
import javax.microedition.khronos.opengles.GL10
import kotlin.math.min

/**
 * BoxSpace — OpenGL renderer for the water-in-box simulation.
 *
 * Architecture mirrors iOS Metal renderer: the main class holds state and dispatches
 * to element objects. Each element owns its GL programs, uniforms, and draw calls.
 *
 * File layout:
 *   BoxSpace.kt         — Renderer entry, GL state, draw dispatch
 *   BoxSpaceDebug.kt    — Debug element: axes, arrows (program + uniforms owned here)
 *   BoxSpaceWater.kt    — Water element: surface, body, boat (program + uniforms owned here)
 */
class BoxSpace(context: Context) : GLSurfaceView.Renderer {

    // ── Screen / Box Dimensions ────────────────────────────────────
    val boxW: Float
    val boxH: Float
    val boxD: Float
    val hw: Float
    val hh: Float

    // ── Sensor State (written by SensorManager, read by draw frame) ──
    @JvmField @Volatile var qX = 0f
    @JvmField @Volatile var qY = 0f
    @JvmField @Volatile var qZ = 0f
    @JvmField @Volatile var qW = 1f

    @JvmField @Volatile var gX = 0f
    @JvmField @Volatile var gY = 0f
    @JvmField @Volatile var gZ = -1f

    // ── Cached World Axes (recomputed each frame) ──────────────────
    @JvmField @Volatile var wxX = 1f; @JvmField @Volatile var wxY = 0f; @JvmField @Volatile var wxZ = 0f
    @JvmField @Volatile var wyX = 0f; @JvmField @Volatile var wyY = 1f; @JvmField @Volatile var wyZ = 0f
    @JvmField @Volatile var wzX = 0f; @JvmField @Volatile var wzY = 0f; @JvmField @Volatile var wzZ = 1f

    // ── Draw Toggles ────────────────────────────────────────────────
    @JvmField @Volatile var drawWorldAxes = false
    @JvmField @Volatile var drawGravityArrow = false
    @JvmField @Volatile var drawMagnetArrow = false
    @JvmField @Volatile var drawBoat = false
    @JvmField @Volatile var drawWaterSurface = false
    @JvmField @Volatile var drawWaterBody = false
    @JvmField @Volatile var drawHuman = false
    @JvmField @Volatile var drawFixation = false

    // ── Arrow Dimensions (used by BoxSpaceDebug) ───────────────────
    val shaftLen get() = boxD * 0.5f
    val coneLen get() = shaftLen * 0.5f
    val shaftR get() = boxD * 0.05f
    val coneR get() = boxD * 0.1f

    // ── Shared GL Resources ─────────────────────────────────────────
    var vaoScreen: Int = 0
        private set
    var vboScreen: Int = 0
        private set

    // ── Element State (owned by element classes) ───────────────────
    val water = BoxSpaceWater(this)
    val debug = BoxSpaceDebug(this)
    val other = BoxSpaceOther(this)
    val human = BoxSpaceHuman(this)

    // ── BoxMath (used by BoxSpaceWater) ─────────────────────────────
    val boxMath: com.example.waterinbox.math.BoxMath

    init {
        val metrics: DisplayMetrics = context.resources.displayMetrics
        boxW = metrics.widthPixels.toFloat()
        boxH = metrics.heightPixels.toFloat()
        boxD = minOf(boxW, boxH) / 2f
        hw = boxW / 2f
        hh = boxH / 2f
        boxMath = com.example.waterinbox.math.BoxMath(hw, hh, boxD)

        // Randomly enable one of the three render groups on startup
        when ((Math.random() * 3).toInt()) {
            0 -> { drawWorldAxes = true; drawGravityArrow = true; drawMagnetArrow = true }
            1 -> { drawBoat = true; drawWaterSurface = true; drawWaterBody = true }
            2 -> { drawHuman = true; drawFixation = true }
        }
    }

    // ── External API ────────────────────────────────────────────────

    fun setGravity(gx: Float, gy: Float, gz: Float) {
        gX = gx; gY = gy; gZ = gz
    }

    /** @deprecated use setGravity */
    fun setQuaternion(x: Float, y: Float, z: Float, w: Float) {
        qX = x; qY = y; qZ = z; qW = w
    }

    /** @deprecated gravity now comes from SensorManager.emit() */
    fun setAccelerometer(x: Float, y: Float, z: Float) { /* no-op */ }

    fun getBoatVertices(): FloatArray = water.boatVertices

    // ── GLSurfaceView.Renderer ───────────────────────────────────────

    override fun onSurfaceCreated(gl: GL10?, config: EGLConfig?) {
        GLES30.glClearColor(0.03f, 0.03f, 0.07f, 1f)
        GLES30.glEnable(GLES30.GL_DEPTH_TEST)
        GLES30.glEnable(GLES30.GL_BLEND)
        GLES30.glBlendFunc(GLES30.GL_SRC_ALPHA, GLES30.GL_ONE_MINUS_SRC_ALPHA)
        GLES30.glDepthFunc(GLES30.GL_LESS)

        setupScreenQuad()
        water.setup()
        debug.setup()
        other.setup()
        human.setup()

        Log.i("BoxSpace", "ok")
    }

    override fun onSurfaceChanged(gl: GL10?, width: Int, height: Int) {
        GLES30.glViewport(0, 0, width, height)
    }

    override fun onDrawFrame(gl: GL10?) {
        GLES30.glClear(GLES30.GL_COLOR_BUFFER_BIT or GLES30.GL_DEPTH_BUFFER_BIT)

        val mvp = computeMVP()
        val gLen3 = kotlin.math.sqrt(gX * gX + gY * gY + gZ * gZ)

        updateWorldAxes()

        debug.draw(mvp, gLen3)
        water.draw(mvp, gLen3)
        other.draw(mvp, gLen3)
        human.draw(mvp, gLen3)
    }

    // ── World Axes Update ───────────────────────────────────────────

    private fun updateWorldAxes() {
        val qx = qX; val qy = qY; val qz = qZ; val qw = qW
        wxX =  1f - 2f * (qy * qy + qz * qz); wxY =  2f * (qx * qy - qz * qw); wxZ =  2f * (qx * qz + qy * qw)
        wyX =  2f * (qx * qy + qz * qw); wyY =  1f - 2f * (qx * qx + qz * qz); wyZ =  2f * (qy * qz - qx * qw)
        wzX =  2f * (qx * qz - qy * qw); wzY =  2f * (qy * qz + qx * qw); wzZ =  1f - 2f * (qx * qx + qy * qy)
    }

    // ── Screen Quad ────────────────────────────────────────────────

    private fun setupScreenQuad() {
        val screenVaoArr = IntArray(1)
        val screenVboArr = IntArray(1)
        GLES30.glGenVertexArrays(1, screenVaoArr, 0)
        GLES30.glGenBuffers(1, screenVboArr, 0)
        vaoScreen = screenVaoArr[0]
        vboScreen = screenVboArr[0]
        val screenZ = boxD / 2f - 0.01f
        val sqVerts = floatArrayOf(
            -hw, -hh, screenZ,
             hw, -hh, screenZ,
            -hw,  hh, screenZ,
             hw,  hh, screenZ
        )
        val sqBuf = java.nio.ByteBuffer.allocateDirect(sqVerts.size * 4)
            .order(java.nio.ByteOrder.nativeOrder()).asFloatBuffer()
            .put(sqVerts).position(0)
        GLES30.glBindVertexArray(vaoScreen)
        GLES30.glBindBuffer(GLES30.GL_ARRAY_BUFFER, vboScreen)
        GLES30.glBufferData(GLES30.GL_ARRAY_BUFFER, sqVerts.size * 4, sqBuf, GLES30.GL_STATIC_DRAW)
        GLES30.glEnableVertexAttribArray(0)
        GLES30.glVertexAttribPointer(0, 3, GLES30.GL_FLOAT, false, 0, 0)
        GLES30.glBindVertexArray(0)
    }

    // ── MVP ────────────────────────────────────────────────────────

    private fun computeMVP(): FloatArray {
        val V = floatArrayOf(
            1f, 0f, 0f, 0f,
            0f, 1f, 0f, 0f,
            0f, 0f, -1f, 0f,
            0f, 0f, 0f, 1f
        )
        val P = floatArrayOf(
            2f / boxW, 0f, 0f, 0f,
            0f, 2f / boxH, 0f, 0f,
            0f, 0f, 2f / boxD, 0f,
            0f, 0f, 0f, 1f
        )
        return floatArrayOf(
            P[0] * V[0], P[4] * V[0] + P[5] * V[4], P[8] * V[0] + P[9] * V[4] + P[10] * V[8], P[12] * V[0] + P[13] * V[4] + P[14] * V[8] + P[15] * V[12],
            P[0] * V[1], P[4] * V[1] + P[5] * V[5], P[8] * V[1] + P[9] * V[5] + P[10] * V[9], P[12] * V[1] + P[13] * V[5] + P[14] * V[9] + P[15] * V[13],
            P[0] * V[2], P[4] * V[2] + P[5] * V[6], P[8] * V[2] + P[9] * V[6] + P[10] * V[10], P[12] * V[2] + P[13] * V[6] + P[14] * V[10] + P[15] * V[14],
            P[0] * V[3], P[4] * V[3] + P[5] * V[7], P[8] * V[3] + P[9] * V[7] + P[10] * V[11], P[12] * V[3] + P[13] * V[7] + P[14] * V[11] + P[15] * V[15]
        )
    }

    // ── Shader Compilation (used by element classes) ───────────────

    open fun createProgram(vert: String, frag: String, tag: String): Int {
        val v = GLES30.glCreateShader(GLES30.GL_VERTEX_SHADER)
        GLES30.glShaderSource(v, vert); GLES30.glCompileShader(v)
        val vLog = GLES30.glGetShaderInfoLog(v)
        if (vLog.isNotEmpty()) Log.e(tag, "Vert: $vLog")
        val f = GLES30.glCreateShader(GLES30.GL_FRAGMENT_SHADER)
        GLES30.glShaderSource(f, frag); GLES30.glCompileShader(f)
        val fLog = GLES30.glGetShaderInfoLog(f)
        if (fLog.isNotEmpty()) Log.e(tag, "Frag: $fLog")
        val p = GLES30.glCreateProgram()
        GLES30.glAttachShader(p, v); GLES30.glAttachShader(p, f)
        GLES30.glLinkProgram(p)
        val pLog = GLES30.glGetProgramInfoLog(p)
        if (pLog.isNotEmpty()) Log.e(tag, "Link: $pLog")
        return p
    }
}