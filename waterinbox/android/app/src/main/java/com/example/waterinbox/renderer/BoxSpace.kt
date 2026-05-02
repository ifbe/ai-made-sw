package com.example.waterinbox.renderer

import android.content.Context
import android.opengl.GLES30
import android.opengl.GLSurfaceView
import android.util.DisplayMetrics
import android.util.Log
import com.example.waterinbox.math.BoxMath
import javax.microedition.khronos.egl.EGLConfig
import javax.microedition.khronos.opengles.GL10
import kotlin.math.cos
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Water surface (blue) + gravity arrow (red).
 * Box dimensions from phone physical screen size.
 */
class BoxSpace(context: Context) : GLSurfaceView.Renderer {

    // Screen pixel dimensions
    private val metrics: DisplayMetrics = context.resources.displayMetrics
    private val boxW: Float = metrics.widthPixels.toFloat()
    private val boxH: Float = metrics.heightPixels.toFloat()
    private val boxD: Float = minOf(boxW, boxH) / 2f
    // Box half-extents (matches BoxMath: x ∈ [-hw,+hw], y ∈ [-hh,+hh], z ∈ [-d,+d])
    private val hw: Float = boxW / 2f
    private val hh: Float = boxH / 2f

    private val boxMath = BoxMath(hw, hh, boxD)

    // NDC: x ∈ [-hw,+hw] → [-1,+1], y ∈ [-hh,+hh] → [-1,+1]
    // Camera at z=+D looking toward -z (back of phone)
    // z=+D/2 (screen, closest) → NDC -1 (near), z=-D/2 (back) → NDC +1 (far)


    // World gravity in box space, from quaternion
    @Volatile private var gX = 0f; @Volatile private var gY = 0f; @Volatile private var gZ = -1f
    // Quaternion [x,y,z,w] — stored for axis arrow debug
    @Volatile private var qX = 0f; @Volatile private var qY = 0f; @Volatile private var qZ = 0f; @Volatile private var qW = 1f
    // World axes in body space (computed once in onDrawFrame, reused by drawArrow/drawBoat)
    @Volatile private var wxX = 1f; @Volatile private var wxY = 0f; @Volatile private var wxZ = 0f
    @Volatile private var wyX = 0f; @Volatile private var wyY = 1f; @Volatile private var wyZ = 0f
    @Volatile private var wzX = 0f; @Volatile private var wzY = 0f; @Volatile private var wzZ = 1f
    // Boat corner positions (updated each frame in drawBoat)
    @Volatile private var bFRx = 0f; @Volatile private var bFRy = 0f; @Volatile private var bFRz = 0f
    @Volatile private var bFLx = 0f; @Volatile private var bFLy = 0f; @Volatile private var bFLz = 0f
    @Volatile private var bBLx = 0f; @Volatile private var bBLy = 0f; @Volatile private var bBLz = 0f
    @Volatile private var bBRx = 0f; @Volatile private var bBRy = 0f; @Volatile private var bBRz = 0f
    @Volatile private var tFRx = 0f; @Volatile private var tFRy = 0f; @Volatile private var tFRz = 0f
    @Volatile private var tFLx = 0f; @Volatile private var tFLy = 0f; @Volatile private var tFLz = 0f
    @Volatile private var tBLx = 0f; @Volatile private var tBLy = 0f; @Volatile private var tBLz = 0f
    @Volatile private var tBRx = 0f; @Volatile private var tBRy = 0f; @Volatile private var tBRz = 0f
    // Draw toggles — controlled by UI panel
    @Volatile var drawWorldAxes = true
    @Volatile var drawGravityArrow = true
    @Volatile var drawMagnetArrow = true
    @Volatile var drawBoat = true
    @Volatile var drawWaterSurface = true
    @Volatile var drawWaterBody = true

    /** Returns the 8 boat corner positions [x,y,z]×8 as a FloatArray. Call after onDrawFrame. */
    fun getBoatVertices(): FloatArray = floatArrayOf(
        bFRx, bFRy, bFRz, bFLx, bFLy, bFLz, bBLx, bBLy, bBLz, bBRx, bBRy, bBRz,
        tFRx, tFRy, tFRz, tFLx, tFLy, tFLz, tBLx, tBLy, tBLz, tBRx, tBRy, tBRz
    )

    private var vaoWater = 0; private var vboWater = 0
    private var vaoScreen = 0; private var vboScreen = 0
    private var programWater = 0; private var programWaterSurface = 0; private var programArrow = 0
    private var uMVP_Water = 0; private var uMVP_WS = 0; private var uAlpha_WS = 0; private var uMVP_Arrow = 0
    private var uNormal_Water = 0; private var uScreenZ_Water = 0; private var uAlpha_Water = 0

    // Arrow dimensions in pixels
    private val shaftLen get() = boxD * 0.5f
    private val coneLen get() = shaftLen * 0.5f
    private val shaftR get() = boxD * 0.05f
    private val coneR get() = boxD * 0.1f

    /**
     * Deprecated: gravity is now computed in SensorManager.emit() and passed directly here.
     * Kept for reference:
     *   World gravity (0, 0, -1) rotated into body frame using C++ formula:
     *   gX = 2*(qy*qw + qz*qx), gY = 2*(qz*qy - qx*qw), gZ = -(qw² + qz² - qx² - qy²)
     */
    fun setQuaternion(x: Float, y: Float, z: Float, w: Float) {
        qX = x; qY = y; qZ = z; qW = w
        /*
        gX =  2f * (y * w + z * x)
        gY =  2f * (z * y - x * w)
        gZ = -(w * w + z * z - x * x - y * y)
        */
    }

    /** @deprecated use SensorManager.emit() gravity directly */
    fun setAccelerometer(x: Float, y: Float, z: Float) {
        /* no-op: gravity now comes from SensorManager.emit() */
    }

    /**
     * Set gravity direction in local box space, pre-computed from quaternion in SensorManager.emit().
     * This is the single entry point for water-surface and arrow rendering.
     */
    fun setGravity(gx: Float, gy: Float, gz: Float) {
        gX = gx
        gY = gy
        gZ = gz
    }

    override fun onSurfaceCreated(gl: GL10?, config: EGLConfig?) {
        GLES30.glClearColor(0.03f, 0.03f, 0.07f, 1f)
        GLES30.glEnable(GLES30.GL_DEPTH_TEST)
        GLES30.glEnable(GLES30.GL_BLEND)
        GLES30.glBlendFunc(GLES30.GL_SRC_ALPHA, GLES30.GL_ONE_MINUS_SRC_ALPHA)
        GLES30.glDepthFunc(GLES30.GL_LESS)

        programWater = createProgram(WATER_VERT, WATER_FRAG, "Water")
        programWaterSurface = createProgram(WATER_SURFACE_VERT, WATER_SURFACE_FRAG, "WaterSurface")
        programArrow = createProgram(ARROW_VERT, ARROW_FRAG, "Arrow")
        uMVP_Water = GLES30.glGetUniformLocation(programWater, "uMVP")
        uNormal_Water = GLES30.glGetUniformLocation(programWater, "uNormal")
        uAlpha_Water = GLES30.glGetUniformLocation(programWater, "uAlpha")
        uMVP_WS = GLES30.glGetUniformLocation(programWaterSurface, "uMVP")
        uAlpha_WS = GLES30.glGetUniformLocation(programWaterSurface, "uAlpha")
        uMVP_Arrow = GLES30.glGetUniformLocation(programArrow, "uMVP")

        // Screen quad VAO/VBO (reused every frame)
        val screenVaoArr = IntArray(1); val screenVboArr = IntArray(1)
        GLES30.glGenVertexArrays(1, screenVaoArr, 0)
        GLES30.glGenBuffers(1, screenVboArr, 0)
        vaoScreen = screenVaoArr[0]; vboScreen = screenVboArr[0]
        // Quad: x∈[-hw,hw], y∈[-hh,hh], z=screenZ
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

        Log.i("WaterRenderer", "ok")
    }

    override fun onSurfaceChanged(gl: GL10?, width: Int, height: Int) {
        GLES30.glViewport(0, 0, width, height)
    }

    override fun onDrawFrame(gl: GL10?) {
        GLES30.glClear(GLES30.GL_COLOR_BUFFER_BIT or GLES30.GL_DEPTH_BUFFER_BIT)

        // Compute MVP: World=I, View(z-neg), Proj(ortho to [0,1] NDC Z)
        val mvp = computeMVP(qX, qY, qZ, qW)
        val gLen3 = sqrt(gX * gX + gY * gY + gZ * gZ)

        // ── 1. Compute world axes from quaternion (reused by arrow + boat) ──
        val qx = qX; val qy = qY; val qz = qZ; val qw = qW
        wxX =  1f - 2f*(qy*qy + qz*qz); wxY =  2f * (qx*qy - qz*qw); wxZ =  2f * (qx*qz + qy*qw)
        wyX =  2f * (qx*qy + qz*qw); wyY =  1f - 2f*(qx*qx + qz*qz); wyZ =  2f * (qy*qz - qx*qw)
        wzX =  2f * (qx*qz - qy*qw); wzY =  2f * (qy*qz + qx*qw); wzZ =  1f - 2f*(qx*qx + qy*qy)

        // ── 2. Gravity arrow ──
        val aX = com.example.waterinbox.math.FusionConfig.accelX
        val aY = com.example.waterinbox.math.FusionConfig.accelY
        val aZ = com.example.waterinbox.math.FusionConfig.accelZ
        val gLen1 = sqrt(aX * aX + aY * aY + aZ * aZ)
        if (drawGravityArrow && gLen1 >= 0.001f) {
            drawArrow(aX / gLen1, aY / gLen1, aZ / gLen1, mvp)
        }

        // ── Magnet arrow (from FusionConfig mag) ──
        val mX = com.example.waterinbox.math.FusionConfig.magX
        val mY = com.example.waterinbox.math.FusionConfig.magY
        val mZ = com.example.waterinbox.math.FusionConfig.magZ
        val mLen = sqrt(mX * mX + mY * mY + mZ * mZ)
        if (drawMagnetArrow && mLen >= 0.001f) {
            drawArrow(mX / mLen, mY / mLen, mZ / mLen, mvp, shaftLen * 0.6f)
        }

        // ── 3. Boat ──
        val gLen2 = sqrt(gX * gX + gY * gY + gZ * gZ)
        if (drawBoat && gLen2 >= 0.001f) {
            drawBoat(mvp)
        }

        // ── World axis debug rays ──
        if (drawWorldAxes) {
            val axisLen = 1000f  // box-space length to stretch across screen
            drawDebugLine(0f, 0f, 0f, wxX * axisLen, wxY * axisLen, wxZ * axisLen, 1f, 0.05f, 0.05f, mvp)  // red: world X
            drawDebugLine(0f, 0f, 0f, wyX * axisLen, wyY * axisLen, wyZ * axisLen, 0.05f, 1f, 0.05f, mvp)  // green: world Y
            drawDebugLine(0f, 0f, 0f, wzX * axisLen, wzY * axisLen, wzZ * axisLen, 0.05f, 0.05f, 1f, mvp)  // blue: world Z
        }

        // ── 2. Water surface polygon (opaque) ──
        if (drawWaterSurface && gLen3 >= 0.001f) {
            val result = boxMath.solveWaterPlane(floatArrayOf(gX, gY, gZ))
            if (result.isWaterVisible && result.polygon.size >= 3) {
                drawWaterSurface(result.polygon, mvp)
            }
        }

        // ── 3. Water body (transparent, depth write OFF) ──
        if (drawWaterBody && gLen3 >= 0.001f) {
            val nx = gX / gLen3; val ny = gY / gLen3; val nz = gZ / gLen3
            GLES30.glEnable(GLES30.GL_BLEND)
            GLES30.glBlendFunc(GLES30.GL_SRC_ALPHA, GLES30.GL_ONE_MINUS_SRC_ALPHA)
            GLES30.glDepthMask(false)
            GLES30.glUseProgram(programWater)
            GLES30.glUniformMatrix4fv(uMVP_Water, 1, false, mvp, 0)
            GLES30.glUniform3f(uNormal_Water, nx, ny, nz)
            GLES30.glUniform1f(uAlpha_Water, 0.95f)
            GLES30.glBindVertexArray(vaoScreen)
            GLES30.glDrawArrays(GLES30.GL_TRIANGLE_STRIP, 0, 4)
            GLES30.glBindVertexArray(0)
            GLES30.glDepthMask(true)
            GLES30.glDisable(GLES30.GL_BLEND)
        }
    }

    // World=I, View(z=-), Proj(ortho: box dims → [-1,1] NDC)
    private fun computeMVP(qx: Float, qy: Float, qz: Float, qW: Float): FloatArray {
        // View: x,y unchanged; z_view = -z_box (eye at box top, looking down)
        val V = floatArrayOf(
            1f, 0f, 0f, 0f,
            0f, 1f, 0f, 0f,
            0f, 0f, -1f, 0f,
            0f, 0f, 0f, 1f
        )
        // Ortho projection: box dims → [-1,1], Z depth/2 → [-1,1]
        val P = floatArrayOf(
            2f/boxW, 0f, 0f, 0f,
            0f, 2f/boxH, 0f, 0f,
            0f, 0f, 2f/boxD, 0f,
            0f, 0f, 0f, 1f
        )
        // MVP = P * V (column-major, clip = P*V*v_world)
        return floatArrayOf(
            P[0]*V[0],             P[4]*V[0]+P[5]*V[4], P[8]*V[0]+P[9]*V[4]+P[10]*V[8],  P[12]*V[0]+P[13]*V[4]+P[14]*V[8]+P[15]*V[12],
            P[0]*V[1],             P[4]*V[1]+P[5]*V[5], P[8]*V[1]+P[9]*V[5]+P[10]*V[9],  P[12]*V[1]+P[13]*V[5]+P[14]*V[9]+P[15]*V[13],
            P[0]*V[2],             P[4]*V[2]+P[5]*V[6], P[8]*V[2]+P[9]*V[6]+P[10]*V[10], P[12]*V[2]+P[13]*V[6]+P[14]*V[10]+P[15]*V[14],
            P[0]*V[3],             P[4]*V[3]+P[5]*V[7], P[8]*V[3]+P[9]*V[7]+P[10]*V[11], P[12]*V[3]+P[13]*V[7]+P[14]*V[11]+P[15]*V[15]
        )
    }

    private fun drawWaterWalls(polygon3D: List<FloatArray>, gnx: Float, gny: Float, gnz: Float, mvp: FloatArray) {
        val lightR = 0.5f; val lightG = 0.7f; val lightB = 1.0f  // light blue for wall water
        val hd = boxD / 2f

        // 6 faces of the box
        val faces = listOf(
            listOf(floatArrayOf(-hw, -hh,  hd), floatArrayOf( hw, -hh,  hd), floatArrayOf( hw,  hh,  hd), floatArrayOf(-hw,  hh,  hd)), // front z=+D/2
            listOf(floatArrayOf(-hw, -hh, -hd), floatArrayOf( hw, -hh, -hd), floatArrayOf( hw,  hh, -hd), floatArrayOf(-hw,  hh, -hd)), // back z=-D/2
            listOf(floatArrayOf( hw, -hh, -hd), floatArrayOf( hw,  hh, -hd), floatArrayOf( hw,  hh,  hd), floatArrayOf( hw, -hh,  hd)), // right x=+W/2
            listOf(floatArrayOf(-hw, -hh, -hd), floatArrayOf(-hw,  hh, -hd), floatArrayOf(-hw,  hh,  hd), floatArrayOf(-hw, -hh,  hd)), // left x=-W/2
            listOf(floatArrayOf(-hw,  hh, -hd), floatArrayOf( hw,  hh, -hd), floatArrayOf( hw,  hh,  hd), floatArrayOf(-hw,  hh,  hd)), // top y=+H/2
            listOf(floatArrayOf(-hw, -hh, -hd), floatArrayOf( hw, -hh, -hd), floatArrayOf( hw, -hh,  hd), floatArrayOf(-hw, -hh,  hd))  // bottom y=-H/2
        )

        val allVerts = mutableListOf<Float>()

        for (face in faces) {
            val subPoly = computeSubmergedPolygon(face, polygon3D, gnx, gny, gnz)
            if (subPoly.size < 3) continue

            val cx = subPoly.sumOf { it[0].toDouble() }.toFloat() / subPoly.size
            val cy = subPoly.sumOf { it[1].toDouble() }.toFloat() / subPoly.size
            val cz = subPoly.sumOf { it[2].toDouble() }.toFloat() / subPoly.size
            allVerts.addAll(listOf(cx, cy, cz, lightR, lightG, lightB))
            for (p in subPoly) allVerts.addAll(listOf(p[0], p[1], p[2], lightR, lightG, lightB))
        }

        if (allVerts.isEmpty()) return

        val buf = java.nio.ByteBuffer.allocateDirect(allVerts.size * 4)
            .order(java.nio.ByteOrder.nativeOrder())
            .asFloatBuffer()
        buf.put(allVerts.toFloatArray()).position(0)

        val vaoArr = IntArray(1); val vboArr = IntArray(1)
        GLES30.glGenVertexArrays(1, vaoArr, 0)
        GLES30.glGenBuffers(1, vboArr, 0)
        GLES30.glBindVertexArray(vaoArr[0])
        GLES30.glBindBuffer(GLES30.GL_ARRAY_BUFFER, vboArr[0])
        GLES30.glBufferData(GLES30.GL_ARRAY_BUFFER, allVerts.size * 4, buf, GLES30.GL_DYNAMIC_DRAW)
        GLES30.glEnableVertexAttribArray(0)
        GLES30.glVertexAttribPointer(0, 3, GLES30.GL_FLOAT, false, 24, 0)
        GLES30.glEnableVertexAttribArray(1)
        GLES30.glVertexAttribPointer(1, 3, GLES30.GL_FLOAT, false, 24, 12)

        GLES30.glUseProgram(programArrow)
        GLES30.glUniformMatrix4fv(uMVP_Arrow, 1, false, mvp, 0)
        GLES30.glDrawArrays(GLES30.GL_TRIANGLE_FAN, 0, allVerts.size / 6)
        GLES30.glBindVertexArray(0)
        GLES30.glDeleteBuffers(1, vboArr, 0)
        GLES30.glDeleteVertexArrays(1, vaoArr, 0)
    }
    private fun computeSubmergedPolygon(
        face: List<FloatArray>,
        waterPoly: List<FloatArray>,
        gnx: Float, gny: Float, gnz: Float
    ): List<FloatArray> {
        // Water plane: normal = gravity (gnx,gny,gnz), point on plane = any vertex of waterPoly
        val wx = waterPoly[0][0]; val wy = waterPoly[0][1]; val wz = waterPoly[0][2]
        val intersections = mutableListOf<FloatArray>()
        val submergedCorners = mutableListOf<FloatArray>()
        for (i in 0 until face.size) {
            val c0 = face[i]; val c1 = face[(i + 1) % face.size]
            val d0 = gnx*(c0[0]-wx) + gny*(c0[1]-wy) + gnz*(c0[2]-wz)
            val d1 = gnx*(c1[0]-wx) + gny*(c1[1]-wy) + gnz*(c1[2]-wz)
            if (d0 <= 0f) submergedCorners.add(c0)
            if (d0 * d1 < 0f) {
                val t = d0 / (d0 - d1)
                intersections.add(floatArrayOf(
                    c0[0] + t * (c1[0] - c0[0]),
                    c0[1] + t * (c1[1] - c0[1]),
                    c0[2] + t * (c1[2] - c0[2])
                ))
            }
        }
        val allPts = (submergedCorners + intersections).toMutableList()
        if (allPts.size < 3) return emptyList()
        val cx = allPts.sumOf { it[0].toDouble() } / allPts.size
        val cy = allPts.sumOf { it[1].toDouble() } / allPts.size
        val cz = allPts.sumOf { it[2].toDouble() } / allPts.size
        allPts.sortBy { p: FloatArray -> java.lang.Math.atan2((p[1] - cy).toDouble(), (p[0] - cx).toDouble()) }
        return allPts
    }

    private fun drawWaterSurface(polygon3D: List<FloatArray>, mvp: FloatArray) {
        val darkR = 0.12f; val darkG = 0.35f; val darkB = 0.90f  // dark blue for surface
        if (polygon3D.size < 3) return

        // Water plane normal = gravity direction
        val gLen = sqrt(gX * gX + gY * gY + gZ * gZ)
        val nx = gX / gLen; val ny = gY / gLen; val nz = gZ / gLen

        
        // Basis vectors on the plane: u ⟂ v, both ⟂ n
        // ref = (0,1,0) unless n is nearly vertical
        val refX = if (kotlin.math.abs(ny) < 0.9f) 0f else 1f
        val refY = if (kotlin.math.abs(ny) < 0.9f) 1f else 0f
        val refZ = 0f
        // u = normalize(ref × n)
        val ux = refY * nz - refZ * ny
        val uy = refZ * nx - refX * nz
        val uz = refX * ny - refY * nx
        val uLen = sqrt(ux * ux + uy * uy + uz * uz)
        val uNormX = ux / uLen; val uNormY = uy / uLen; val uNormZ = uz / uLen
        // v = n × u
        val vx = ny * uNormZ - nz * uNormY
        val vy = nz * uNormX - nx * uNormZ
        val vz = nx * uNormY - ny * uNormX

        // Project each polygon vertex onto the plane → 2D coords (s, t)
        val pts2D = polygon3D.map { p ->
            val s = p[0] * uNormX + p[1] * uNormY + p[2] * uNormZ
            val t = p[0] * vx + p[1] * vy + p[2] * vz
            floatArrayOf(p[0], p[1], p[2], s, t)
        }

        // Centroid of polygon in 2D
        val cS = pts2D.sumOf { it[3].toDouble() } / pts2D.size
        val cT = pts2D.sumOf { it[4].toDouble() } / pts2D.size

        // Sort by angle around centroid, clockwise (negative atan2)
        val sorted = pts2D.sortedBy { java.lang.Math.atan2(it[4] - cT, it[3] - cS) }

        // Explicit triangles: (o,0,1), (o,1,2), (o,2,3), (o,3,0)
        val cx3D = polygon3D.sumOf { it[0].toDouble() } / polygon3D.size
        val cy3D = polygon3D.sumOf { it[1].toDouble() } / polygon3D.size
        val cz3D = polygon3D.sumOf { it[2].toDouble() } / polygon3D.size
        val verts = mutableListOf<Float>()
        val n = sorted.size
        for (i in 0 until n) {
            val p = sorted[i]
            val next = sorted[(i + 1) % n]
            // (o, v_i, v_{i+1})
            verts.addAll(listOf(cx3D.toFloat(), cy3D.toFloat(), cz3D.toFloat(), darkR, darkG, darkB))
            verts.addAll(listOf(p[0], p[1], p[2], darkR, darkG, darkB))
            verts.addAll(listOf(next[0], next[1], next[2], darkR, darkG, darkB))
        }

        val buf = java.nio.ByteBuffer.allocateDirect(verts.size * 4)
            .order(java.nio.ByteOrder.nativeOrder())
            .asFloatBuffer()
        buf.put(verts.toFloatArray()).position(0)

        val vaoArr = IntArray(1); val vboArr = IntArray(1)
        GLES30.glGenVertexArrays(1, vaoArr, 0)
        GLES30.glGenBuffers(1, vboArr, 0)
        GLES30.glBindVertexArray(vaoArr[0])
        GLES30.glBindBuffer(GLES30.GL_ARRAY_BUFFER, vboArr[0])
        GLES30.glBufferData(GLES30.GL_ARRAY_BUFFER, verts.size * 4, buf, GLES30.GL_DYNAMIC_DRAW)
        GLES30.glEnableVertexAttribArray(0)
        GLES30.glVertexAttribPointer(0, 3, GLES30.GL_FLOAT, false, 24, 0)
        GLES30.glEnableVertexAttribArray(1)
        GLES30.glVertexAttribPointer(1, 3, GLES30.GL_FLOAT, false, 24, 12)

        GLES30.glEnable(GLES30.GL_POLYGON_OFFSET_FILL)
        GLES30.glPolygonOffset(4.0f, 4.0f)
        GLES30.glUseProgram(programWaterSurface)
        GLES30.glUniformMatrix4fv(uMVP_WS, 1, false, mvp, 0)
        GLES30.glUniform1f(uAlpha_WS, 0.99f)
        GLES30.glDrawArrays(GLES30.GL_TRIANGLES, 0, verts.size / 6)
        GLES30.glDisable(GLES30.GL_POLYGON_OFFSET_FILL)
        GLES30.glBindVertexArray(0)
        GLES30.glDeleteBuffers(1, vboArr, 0)
        GLES30.glDeleteVertexArrays(1, vaoArr, 0)
    }

    // Arrow: from box center toward gravity direction
    // Shaft from center to tip, cone at the tip (pointing in gravity direction)
    private fun drawArrow(gx: Float, gy: Float, gz: Float, mvp: FloatArray, customLength: Float = -1f) {
        val arrowLen = if (customLength > 0f) customLength else shaftLen
        val sides = 12
        val cr = 0.9f; val cg = 0.15f; val cb = 0.15f  // red cone
        val greenR = 0.15f; val greenG = 0.9f; val greenB = 0.15f  // green shaft

        // Box center = tail
        val tailX = 0f; val tailY = 0f; val tailZ = 0f
        val tipX = tailX + gx * shaftLen; val tipY = tailY + gy * shaftLen; val tipZ = tailZ + gz * shaftLen

        // Perpendicular basis for cross-section (same as before)
        val px: Float; val py: Float; val pz: Float
        if (gy * gy < 0.81f) {
            val t = sqrt((gx*gx + gy*gy).toDouble()).toFloat()
            px = -gy/t; py = gx/t; pz = 0f
        } else {
            val t = sqrt((gy*gy + gz*gz).toDouble()).toFloat()
            px = 0f; py = -gz/t; pz = gy/t
        }
        val qx = gy*pz - gz*py
        val qy = gz*px - gx*pz
        val qz = gx*py - gy*px

        val verts = mutableListOf<Float>()

        // Cone base (toward tail) and cone tip (toward gravity)
        val coneBaseX = tipX - gx * coneLen; val coneBaseY = tipY - gy * coneLen; val coneBaseZ = tipZ - gz * coneLen

        // === TAIL CAP: disc at box center (closes shaft back end) ===
        verts.addAll(listOf(tailX, tailY, tailZ, greenR, greenG, greenB))
        for (i in sides downTo 0) {
            val a = (2 * Math.PI * i / sides).toFloat()
            val rx = cos(a) * shaftR; val ry = sin(a) * shaftR
            val wx = rx * px + ry * qx; val wy = rx * py + ry * qy; val wz = rx * pz + ry * qz
            verts.addAll(listOf(tailX + wx, tailY + wy, tailZ + wz, greenR, greenG, greenB))
        }
        val tailCapCount = sides + 2

        // === SHAFT: triangle strip from tail to cone base ===
        for (i in 0..sides) {
            val a = (2 * Math.PI * i / sides).toFloat()
            val rx = cos(a) * shaftR; val ry = sin(a) * shaftR
            val wx = rx * px + ry * qx; val wy = rx * py + ry * qy; val wz = rx * pz + ry * qz
            verts.addAll(listOf(tailX + wx, tailY + wy, tailZ + wz, greenR, greenG, greenB))
            verts.addAll(listOf(coneBaseX + wx, coneBaseY + wy, coneBaseZ + wz, greenR, greenG, greenB))
        }
        val shaftCount = (sides + 1) * 2

        // === CONE BASE CAP: disc at cone base (closes shaft front end) ===
        verts.addAll(listOf(coneBaseX, coneBaseY, coneBaseZ, greenR, greenG, greenB))
        for (i in 0..sides) {
            val a = (2 * Math.PI * i / sides).toFloat()
            val rx = cos(a) * shaftR; val ry = sin(a) * shaftR
            val wx = rx * px + ry * qx; val wy = rx * py + ry * qy; val wz = rx * pz + ry * qz
            verts.addAll(listOf(coneBaseX + wx, coneBaseY + wy, coneBaseZ + wz, greenR, greenG, greenB))
        }
        val coneBaseCapCount = sides + 2

        // === CONE: triangle fan at tip (cone tip toward gravity, base at cone base) ===
        // Cone tip at arrow tip
        verts.addAll(listOf(tipX, tipY, tipZ, cr, cg, cb))
        // Cone base ring
        for (i in 0..sides) {
            val a = (2 * Math.PI * i / sides).toFloat()
            val rx = cos(a) * coneR; val ry = sin(a) * coneR
            val wx = rx * px + ry * qx
            val wy = rx * py + ry * qy
            val wz = rx * pz + ry * qz
            verts.addAll(listOf(coneBaseX + wx, coneBaseY + wy, coneBaseZ + wz, 0.75f, 0.5f, 0.2f))
        }
        val coneCount = 1 + sides + 1

        val buf = java.nio.ByteBuffer.allocateDirect(verts.size * 4)
            .order(java.nio.ByteOrder.nativeOrder())
            .asFloatBuffer()
        buf.put(verts.toFloatArray()).position(0)

        val vaoArr = IntArray(1)
        val vboArr = IntArray(1)
        GLES30.glGenVertexArrays(1, vaoArr, 0)
        GLES30.glGenBuffers(1, vboArr, 0)
        GLES30.glBindVertexArray(vaoArr[0])
        GLES30.glBindBuffer(GLES30.GL_ARRAY_BUFFER, vboArr[0])
        GLES30.glBufferData(GLES30.GL_ARRAY_BUFFER, verts.size * 4, buf, GLES30.GL_DYNAMIC_DRAW)
        GLES30.glEnableVertexAttribArray(0)
        GLES30.glVertexAttribPointer(0, 3, GLES30.GL_FLOAT, false, 24, 0)
        GLES30.glEnableVertexAttribArray(1)
        GLES30.glVertexAttribPointer(1, 3, GLES30.GL_FLOAT, false, 24, 12)

        GLES30.glUseProgram(programArrow)
        GLES30.glUniformMatrix4fv(uMVP_Arrow, 1, false, mvp, 0)
        // Tail cap: triangle fan
        GLES30.glDrawArrays(GLES30.GL_TRIANGLE_FAN, 0, tailCapCount)
        // Shaft: triangle strip
        GLES30.glDrawArrays(GLES30.GL_TRIANGLE_STRIP, tailCapCount, shaftCount)
        // Cone base cap: triangle fan
        GLES30.glDrawArrays(GLES30.GL_TRIANGLE_FAN, tailCapCount + shaftCount, coneBaseCapCount)
        // Cone: triangle fan (tip at 0, base ring starts at 1)
        GLES30.glDrawArrays(GLES30.GL_TRIANGLE_FAN, tailCapCount + shaftCount + coneBaseCapCount, coneCount)

        GLES30.glBindVertexArray(0)
        GLES30.glDeleteBuffers(1, vboArr, 0)
        GLES30.glDeleteVertexArrays(1, vaoArr, 0)
    }

    /** Flat rectangular raft — same quaternion basis computed once in onDrawFrame. */
    private fun drawBoat(mvp: FloatArray) {
        val fx = wyX; val fy = wyY; val fz = wyZ  // forward = world Y in body space
        val rx = wxX; val ry = wxY; val rz = wxZ  // right = world X in body space
        val ux = wzX; val uy = wzY; val uz = wzZ  // up = world Z in body space

        val halfLen = boxD * 0.12f
        val halfWid = boxD * 0.08f
        val raftH = boxD / 12f  // 高度改为原来的 1/4

        // bottom 4 corners (at water surface)
        val bFRxv =  rx*halfWid + fx*halfLen; val bFRyv =  ry*halfWid + fy*halfLen; val bFRzv =  rz*halfWid + fz*halfLen
        val bFLxv = -rx*halfWid + fx*halfLen; val bFLyv = -ry*halfWid + fy*halfLen; val bFLzv = -rz*halfWid + fz*halfLen
        val bBLxv = -rx*halfWid - fx*halfLen; val bBLyv = -ry*halfWid - fy*halfLen; val bBLzv = -rz*halfWid - fz*halfLen
        val bBRxv =  rx*halfWid - fx*halfLen; val bBRyv =  ry*halfWid - fy*halfLen; val bBRzv =  rz*halfWid - fz*halfLen

        // top 4 corners = bottom + up * raftH
        val tFRxv = bFRxv + ux*raftH; val tFRyv = bFRyv + uy*raftH; val tFRzv = bFRzv + uz*raftH
        val tFLxv = bFLxv + ux*raftH; val tFLyv = bFLyv + uy*raftH; val tFLzv = bFLzv + uz*raftH
        val tBLxv = bBLxv + ux*raftH; val tBLyv = bBLyv + uy*raftH; val tBLzv = bBLzv + uz*raftH
        val tBRxv = bBRxv + ux*raftH; val tBRyv = bBRyv + uy*raftH; val tBRzv = bBRzv + uz*raftH

        // Store to class fields for getBoatVertices()
        bFRx = bFRxv; bFRy = bFRyv; bFRz = bFRzv
        bFLx = bFLxv; bFLy = bFLyv; bFLz = bFLzv
        bBLx = bBLxv; bBLy = bBLyv; bBLz = bBLzv
        bBRx = bBRxv; bBRy = bBRyv; bBRz = bBRzv
        tFRx = tFRxv; tFRy = tFRyv; tFRz = tFRzv
        tFLx = tFLxv; tFLy = tFLyv; tFLz = tFLzv
        tBLx = tBLxv; tBLy = tBLyv; tBLz = tBLzv
        tBRx = tBRxv; tBRy = tBRyv; tBRz = tBRzv
        bFRx = bFRxv; bFRy = bFRyv; bFRz = bFRzv
        bFLx = bFLxv; bFLy = bFLyv; bFLz = bFLzv
        bBLx = bBLxv; bBLy = bBLyv; bBLz = bBLzv
        bBRx = bBRxv; bBRy = bBRyv; bBRz = bBRzv
        tFRx = tFRxv; tFRy = tFRyv; tFRz = tFRzv
        tFLx = tFLxv; tFLy = tFLyv; tFLz = tFLzv
        tBLx = tBLxv; tBLy = tBLyv; tBLz = tBLzv
        tBRx = tBRxv; tBRy = tBRyv; tBRz = tBRzv

        val rR = 0.75f; val rG = 0.50f; val rB = 0.25f  // sides
        val botR = 1f; val botG = 0f; val botB = 1f       // bottom = 0xff00ff magenta

        // Bottom face (magenta)
        val bottomVerts = floatArrayOf(
            bBRx,bBRy,bBRz, botR,botG,botB,  bFRx,bFRy,bFRz, botR,botG,botB,  bFLx,bFLy,bFLz, botR,botG,botB,
            bBRx,bBRy,bBRz, botR,botG,botB,  bFLx,bFLy,bFLz, botR,botG,botB,  bBLx,bBLy,bBLz, botR,botG,botB
        )
        // 4 side faces (brown)
        val sideVerts = floatArrayOf(
            bFRx,bFRy,bFRz, rR,rG,rB,  tFLx,tFLy,tFLz, rR,rG,rB,  tFRx,tFRy,tFRz, rR,rG,rB,
            bFRx,bFRy,bFRz, rR,rG,rB,  bFLx,bFLy,bFLz, rR,rG,rB,  tFLx,tFLy,tFLz, rR,rG,rB,
            bBRx,bBRy,bBRz, rR,rG,rB,  tFRx,tFRy,tFRz, rR,rG,rB,  tBRx,tBRy,tBRz, rR,rG,rB,
            bBRx,bBRy,bBRz, rR,rG,rB,  bFRx,bFRy,bFRz, rR,rG,rB,  tFRx,tFRy,tFRz, rR,rG,rB,
            bBLx,bBLy,bBLz, rR,rG,rB,  tBRx,tBRy,tBRz, rR,rG,rB,  tBLx,tBLy,tBLz, rR,rG,rB,
            bBLx,bBLy,bBLz, rR,rG,rB,  bBRx,bBRy,bBRz, rR,rG,rB,  tBRx,tBRy,tBRz, rR,rG,rB,
            bFLx,bFLy,bFLz, rR,rG,rB,  tBLx,tBLy,tBLz, rR,rG,rB,  tFLx,tFLy,tFLz, rR,rG,rB,
            bFLx,bFLy,bFLz, rR,rG,rB,  bBLx,bBLy,bBLz, rR,rG,rB,  tBLx,tBLy,tBLz, rR,rG,rB
        )

        fun drawVerts(verts: FloatArray) {
            val buf = java.nio.ByteBuffer.allocateDirect(verts.size * 4)
                .order(java.nio.ByteOrder.nativeOrder()).asFloatBuffer()
            buf.put(verts).position(0)
            val vaoArr = IntArray(1); val vboArr = IntArray(1)
            GLES30.glGenVertexArrays(1, vaoArr, 0)
            GLES30.glGenBuffers(1, vboArr, 0)
            GLES30.glBindVertexArray(vaoArr[0])
            GLES30.glBindBuffer(GLES30.GL_ARRAY_BUFFER, vboArr[0])
            GLES30.glBufferData(GLES30.GL_ARRAY_BUFFER, verts.size * 4, buf, GLES30.GL_DYNAMIC_DRAW)
            GLES30.glEnableVertexAttribArray(0)
            GLES30.glVertexAttribPointer(0, 3, GLES30.GL_FLOAT, false, 24, 0)
            GLES30.glEnableVertexAttribArray(1)
            GLES30.glVertexAttribPointer(1, 3, GLES30.GL_FLOAT, false, 24, 12)
            GLES30.glUseProgram(programArrow)
            GLES30.glUniformMatrix4fv(uMVP_Arrow, 1, false, mvp, 0)
            GLES30.glDrawArrays(GLES30.GL_TRIANGLES, 0, verts.size / 6)
            GLES30.glBindVertexArray(0)
            GLES30.glDeleteBuffers(1, vboArr, 0)
            GLES30.glDeleteVertexArrays(1, vaoArr, 0)
        }

        drawVerts(bottomVerts)
        drawVerts(sideVerts)

        // debug: draw 8 vertex points as tiny lines
        val dp = 5f
        drawDebugLine(bFRx,bFRy,bFRz-dp, bFRx,bFRy,bFRz+dp, 1f,1f,0f, mvp)
        drawDebugLine(bFLx,bFLy,bFLz-dp, bFLx,bFLy,bFLz+dp, 1f,0.8f,0f, mvp)
        drawDebugLine(bBLx,bBLy,bBLz-dp, bBLx,bBLy,bBLz+dp, 1f,0.6f,0f, mvp)
        drawDebugLine(bBRx,bBRy,bBRz-dp, bBRx,bBRy,bBRz+dp, 1f,0.4f,0f, mvp)
        drawDebugLine(tFRx,tFRy,tFRz-dp, tFRx,tFRy,tFRz+dp, 0f,1f,1f, mvp)
        drawDebugLine(tFLx,tFLy,tFLz-dp, tFLx,tFLy,tFLz+dp, 0f,0.8f,1f, mvp)
        drawDebugLine(tBLx,tBLy,tBLz-dp, tBLx,tBLy,tBLz+dp, 0f,0.6f,1f, mvp)
        drawDebugLine(tBRx,tBRy,tBRz-dp, tBRx,tBRy,tBRz+dp, 0f,0.4f,1f, mvp)
    }
    /** Draw a simple 4px line from origin in direction (gx,gy,gz). */
    private fun drawDebugLine(tailX: Float, tailY: Float, tailZ: Float, tipX: Float, tipY: Float, tipZ: Float, r: Float, g: Float, b: Float, mvp: FloatArray) {
        val verts = floatArrayOf(
            tailX, tailY, tailZ, r, g, b,
            tipX, tipY, tipZ, r, g, b
        )

        val buf = java.nio.ByteBuffer.allocateDirect(verts.size * 4)
            .order(java.nio.ByteOrder.nativeOrder())
            .asFloatBuffer()
        buf.put(verts).position(0)

        val vaoArr = IntArray(1); val vboArr = IntArray(1)
        GLES30.glGenVertexArrays(1, vaoArr, 0)
        GLES30.glGenBuffers(1, vboArr, 0)
        GLES30.glBindVertexArray(vaoArr[0])
        GLES30.glBindBuffer(GLES30.GL_ARRAY_BUFFER, vboArr[0])
        GLES30.glBufferData(GLES30.GL_ARRAY_BUFFER, verts.size * 4, buf, GLES30.GL_DYNAMIC_DRAW)
        GLES30.glEnableVertexAttribArray(0)
        GLES30.glVertexAttribPointer(0, 3, GLES30.GL_FLOAT, false, 24, 0)
        GLES30.glEnableVertexAttribArray(1)
        GLES30.glVertexAttribPointer(1, 3, GLES30.GL_FLOAT, false, 24, 12)

        GLES30.glLineWidth(4f)
        GLES30.glUseProgram(programArrow)
        GLES30.glUniformMatrix4fv(uMVP_Arrow, 1, false, mvp, 0)
        GLES30.glDrawArrays(GLES30.GL_LINES, 0, 2)

        GLES30.glBindVertexArray(0)
        GLES30.glDeleteBuffers(1, vboArr, 0)
        GLES30.glDeleteVertexArrays(1, vaoArr, 0)
    }

    private fun createProgram(vert: String, frag: String, tag: String): Int {
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

    companion object {
        val WATER_VERT = """
            #version 300 es
            uniform mat4 uMVP;
            in vec3 aPosition;
            out vec3 vLocalPos;
            void main() {
                gl_Position = uMVP * vec4(aPosition, 1.0);
                vLocalPos = aPosition;
            }
        """.trimIndent()
        val WATER_FRAG = """
            #version 300 es
            precision highp float;
            uniform vec3 uNormal;    // water plane normal (normalized)
            uniform float uScreenZ;  // screen face z = depth/2 - offset
            uniform float uAlpha;
            in vec3 vLocalPos;
            out vec4 fragColor;
            void main() {
                // n·P = signed distance from water plane (n is normalized)
                // n·P < 0 → above water (discard), n·P > 0 → underwater (keep)
                vec3 n = normalize(uNormal);
                vec3 p = vLocalPos;
                float np = dot(n, p);
                if (np <= 0.0) discard;
                // np > 0: depth into water, use as-is (already in box-space units)
                float depth = np;
                float factor = pow(0.98, depth / 10.0);
                float maxDepth = 30.0;
                float t = clamp(depth / maxDepth, 0.0, 1.0);
                float r = mix(0.5, 0.12, t) * factor;
                float g = mix(0.7, 0.35, t) * factor;
                float b = mix(1.0, 0.90, t) * factor;
                fragColor = vec4(r, g, b, uAlpha);
            }
        """.trimIndent()
        val WATER_SURFACE_VERT = """
            #version 300 es
            uniform mat4 uMVP;
            in vec3 aPosition;
            void main() { gl_Position = uMVP * vec4(aPosition, 1.0); }
        """.trimIndent()
        val WATER_SURFACE_FRAG = """
            #version 300 es
            precision highp float;
            uniform float uAlpha;
            out vec4 fragColor;
            void main() { fragColor = vec4(0.5, 0.7, 1.0, uAlpha); }
        """.trimIndent()
        val ARROW_VERT = """
            #version 300 es
            uniform mat4 uMVP;
            in vec3 aPosition;
            in vec3 aColor;
            out vec3 vColor;
            void main() { gl_Position = uMVP * vec4(aPosition, 1.0); vColor = aColor; }
        """.trimIndent()
        val ARROW_FRAG = """
            #version 300 es
            precision highp float;
            in vec3 vColor;
            out vec4 fragColor;
            void main() { fragColor = vec4(vColor, 1.0); }
        """.trimIndent()
    }
}
