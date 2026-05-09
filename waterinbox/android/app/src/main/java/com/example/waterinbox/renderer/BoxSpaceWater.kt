package com.example.waterinbox.renderer

import android.opengl.GLES30
import com.example.waterinbox.math.FusionConfig
import kotlin.math.abs
import kotlin.math.atan2
import kotlin.math.sqrt

/**
 * BoxSpaceWater — water surface polygon, water body, and boat.
 * Owns its GL programs, uniforms, and draw calls.
 */
class BoxSpaceWater(private val boxSpace: BoxSpace) {

    // ── Boat Vertices (exposed to UISpace via BoxSpace.getBoatVertices()) ──
    var boatVertices: FloatArray = FloatArray(24)
        private set

    // ── GL Resources ─────────────────────────────────────────────────
    private var programWater = 0
    private var programWaterSurface = 0
    private var uMVP_Water = 0
    private var uNormal_Water = 0
    private var uAlpha_Water = 0
    private var uMVP_WS = 0
    private var uAlpha_WS = 0

    // ── Shader Strings ───────────────────────────────────────────────

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
            uniform vec3 uNormal;
            uniform float uScreenZ;
            uniform float uAlpha;
            in vec3 vLocalPos;
            out vec4 fragColor;
            void main() {
                vec3 n = normalize(uNormal);
                vec3 p = vLocalPos;
                float np = dot(n, p);
                if (np <= 0.0) discard;
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
    }

    // ── Setup ───────────────────────────────────────────────────────

    fun setup() {
        programWater = boxSpace.createProgram(WATER_VERT, WATER_FRAG, "Water")
        programWaterSurface = boxSpace.createProgram(WATER_SURFACE_VERT, WATER_SURFACE_FRAG, "WaterSurface")
        uMVP_Water = GLES30.glGetUniformLocation(programWater, "uMVP")
        uNormal_Water = GLES30.glGetUniformLocation(programWater, "uNormal")
        uAlpha_Water = GLES30.glGetUniformLocation(programWater, "uAlpha")
        uMVP_WS = GLES30.glGetUniformLocation(programWaterSurface, "uMVP")
        uAlpha_WS = GLES30.glGetUniformLocation(programWaterSurface, "uAlpha")
    }

    // ── Draw ────────────────────────────────────────────────────────

    fun draw(mvp: FloatArray, gLen3: Float) {
        val gLen = gLen3
        val gX = boxSpace.gX
        val gY = boxSpace.gY
        val gZ = boxSpace.gZ

        // ── Boat ────────────────────────────────────────────────────
        if (boxSpace.drawBoat && gLen >= 0.001f) {
            drawBoat(mvp)
        }

        // ── Water surface polygon ───────────────────────────────────
        if (boxSpace.drawWaterSurface && gLen >= 0.001f) {
            val result = boxSpace.boxMath.solveWaterPlane(floatArrayOf(gX, gY, gZ))
            if (result.isWaterVisible && result.polygon.size >= 3) {
                drawWaterSurface(result.polygon, mvp, gX, gY, gZ, gLen)
            }
        }

        // ── Water body ─────────────────────────────────────────────
        if (boxSpace.drawWaterBody && gLen >= 0.001f) {
            val nx = gX / gLen; val ny = gY / gLen; val nz = gZ / gLen
            GLES30.glEnable(GLES30.GL_BLEND)
            GLES30.glBlendFunc(GLES30.GL_SRC_ALPHA, GLES30.GL_ONE_MINUS_SRC_ALPHA)
            GLES30.glDepthMask(false)
            GLES30.glUseProgram(programWater)
            GLES30.glUniformMatrix4fv(uMVP_Water, 1, false, mvp, 0)
            GLES30.glUniform3f(uNormal_Water, nx, ny, nz)
            GLES30.glUniform1f(uAlpha_Water, 0.95f)
            GLES30.glBindVertexArray(boxSpace.vaoScreen)
            GLES30.glDrawArrays(GLES30.GL_TRIANGLE_STRIP, 0, 4)
            GLES30.glBindVertexArray(0)
            GLES30.glDepthMask(true)
            GLES30.glDisable(GLES30.GL_BLEND)
        }
    }

    // ── Water Surface ───────────────────────────────────────────────

    private fun drawWaterSurface(polygon3D: List<FloatArray>, mvp: FloatArray, gX: Float, gY: Float, gZ: Float, gLen: Float) {
        val darkR = 0.12f; val darkG = 0.35f; val darkB = 0.90f
        if (polygon3D.size < 3) return

        val nx = gX / gLen; val ny = gY / gLen; val nz = gZ / gLen

        val refX = if (abs(ny) < 0.9f) 0f else 1f
        val refY = if (abs(ny) < 0.9f) 1f else 0f
        val refZ = 0f

        var ux = refY * nz - refZ * ny
        var uy = refZ * nx - refX * nz
        var uz = refX * ny - refY * nx
        val uLen = sqrt(ux * ux + uy * uy + uz * uz)
        val uNormX = ux / uLen; val uNormY = uy / uLen; val uNormZ = uz / uLen

        val vx = ny * uNormZ - nz * uNormY
        val vy = nz * uNormX - nx * uNormZ
        val vz = nx * uNormY - ny * uNormX

        val pts2D = polygon3D.map { p ->
            val s = p[0] * uNormX + p[1] * uNormY + p[2] * uNormZ
            val t = p[0] * vx + p[1] * vy + p[2] * vz
            floatArrayOf(p[0], p[1], p[2], s, t)
        }

        val cS = pts2D.sumOf { it[3].toDouble() } / pts2D.size
        val cT = pts2D.sumOf { it[4].toDouble() } / pts2D.size
        val sorted = pts2D.sortedBy { atan2(it[4] - cT, it[3] - cS) }

        val cx3D = polygon3D.sumOf { it[0].toDouble() } / polygon3D.size
        val cy3D = polygon3D.sumOf { it[1].toDouble() } / polygon3D.size
        val cz3D = polygon3D.sumOf { it[2].toDouble() } / polygon3D.size

        val verts = mutableListOf<Float>()
        val n = sorted.size
        for (i in 0 until n) {
            val p = sorted[i]
            val next = sorted[(i + 1) % n]
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

    // ── Boat ────────────────────────────────────────────────────────

    private fun drawBoat(mvp: FloatArray) {
        val fx = boxSpace.wyX; val fy = boxSpace.wyY; val fz = boxSpace.wyZ
        val rx = boxSpace.wxX; val ry = boxSpace.wxY; val rz = boxSpace.wxZ
        val ux = boxSpace.wzX; val uy = boxSpace.wzY; val uz = boxSpace.wzZ

        val halfLen = boxSpace.boxD * 0.12f
        val halfWid = boxSpace.boxD * 0.08f
        val raftH = boxSpace.boxD / 12f

        val bFRx =  rx * halfWid + fx * halfLen; val bFRy =  ry * halfWid + fy * halfLen; val bFRz =  rz * halfWid + fz * halfLen
        val bFLx = -rx * halfWid + fx * halfLen; val bFLy = -ry * halfWid + fy * halfLen; val bFLz = -rz * halfWid + fz * halfLen
        val bBLx = -rx * halfWid - fx * halfLen; val bBLy = -ry * halfWid - fy * halfLen; val bBLz = -rz * halfWid - fz * halfLen
        val bBRx =  rx * halfWid - fx * halfLen; val bBRy =  ry * halfWid - fy * halfLen; val bBRz =  rz * halfWid - fz * halfLen

        val tFRx = bFRx + ux * raftH; val tFRy = bFRy + uy * raftH; val tFRz = bFRz + uz * raftH
        val tFLx = bFLx + ux * raftH; val tFLy = bFLy + uy * raftH; val tFLz = bFLz + uz * raftH
        val tBLx = bBLx + ux * raftH; val tBLy = bBLy + uy * raftH; val tBLz = bBLz + uz * raftH
        val tBRx = bBRx + ux * raftH; val tBRy = bBRy + uy * raftH; val tBRz = bBRz + uz * raftH

        boatVertices = floatArrayOf(
            bFRx, bFRy, bFRz, bFLx, bFLy, bFLz, bBLx, bBLy, bBLz, bBRx, bBRy, bBRz,
            tFRx, tFRy, tFRz, tFLx, tFLy, tFLz, tBLx, tBLy, tBLz, tBRx, tBRy, tBRz
        )

        val rR = 0.75f; val rG = 0.50f; val rB = 0.25f
        val botR = 1f; val botG = 0f; val botB = 1f

        val bottomVerts = floatArrayOf(
            bBRx, bBRy, bBRz, botR, botG, botB,  bFRx, bFRy, bFRz, botR, botG, botB,  bFLx, bFLy, bFLz, botR, botG, botB,
            bBRx, bBRy, bBRz, botR, botG, botB,  bFLx, bFLy, bFLz, botR, botG, botB,  bBLx, bBLy, bBLz, botR, botG, botB
        )
        val sideVerts = floatArrayOf(
            bFRx, bFRy, bFRz, rR, rG, rB,  bFLx, bFLy, bFLz, rR, rG, rB,  tFLx, tFLy, tFLz, rR, rG, rB,
            bFRx, bFRy, bFRz, rR, rG, rB,  tFLx, tFLy, tFLz, rR, rG, rB,  tFRx, tFRy, tFRz, rR, rG, rB,
            bBRx, bBRy, bBRz, rR, rG, rB,  bBLx, bBLy, bBLz, rR, rG, rB,  tBLx, tBLy, tBLz, rR, rG, rB,
            bBRx, bBRy, bBRz, rR, rG, rB,  tBLx, tBLy, tBLz, rR, rG, rB,  tBRx, tBRy, tBRz, rR, rG, rB,
            bFLx, bFLy, bFLz, rR, rG, rB,  bBLx, bBLy, bBLz, rR, rG, rB,  tBLx, tBLy, tBLz, rR, rG, rB,
            bFLx, bFLy, bFLz, rR, rG, rB,  tBLx, tBLy, tFLz, rR, rG, rB,  tFLx, tFLy, tFLz, rR, rG, rB,
            bBRx, bBRy, bBRz, rR, rG, rB,  bFRx, bFRy, bFRz, rR, rG, rB,  tFRx, tFRy, tFRz, rR, rG, rB,
            bBRx, bBRy, bBRz, rR, rG, rB,  tFRx, tFRy, tFRz, rR, rG, rB,  tBRx, tBRy, tBRz, rR, rG, rB
        )

        // Use BoxSpaceDebug's drawArrow for boat debug lines
        val debug = boxSpace.debug

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
            GLES30.glUseProgram(debug.programArrow)
            GLES30.glUniformMatrix4fv(debug.uMVP_Arrow, 1, false, mvp, 0)
            GLES30.glDrawArrays(GLES30.GL_TRIANGLES, 0, verts.size / 6)
            GLES30.glBindVertexArray(0)
            GLES30.glDeleteBuffers(1, vboArr, 0)
            GLES30.glDeleteVertexArrays(1, vaoArr, 0)
        }

        drawVerts(bottomVerts)
        drawVerts(sideVerts)

        // debug: 8 vertex markers via BoxSpaceDebug
        val dp = 5f
        debug.drawDebugLine(bFRx, bFRy, bFRz - dp, bFRx, bFRy, bFRz + dp, 1f, 1f, 0f, mvp)
        debug.drawDebugLine(bFLx, bFLy, bFLz - dp, bFLx, bFLy, bFLz + dp, 1f, 0.8f, 0f, mvp)
        debug.drawDebugLine(bBLx, bBLy, bBLz - dp, bBLx, bBLy, bBLz + dp, 1f, 0.6f, 0f, mvp)
        debug.drawDebugLine(bBRx, bBRy, bBRz - dp, bBRx, bBRy, bBRz + dp, 1f, 0.4f, 0f, mvp)
        debug.drawDebugLine(tFRx, tFRy, tFRz - dp, tFRx, tFRy, tFRz + dp, 0f, 1f, 1f, mvp)
        debug.drawDebugLine(tFLx, tFLy, tFLz - dp, tFLx, tFLy, tFLz + dp, 0f, 0.8f, 1f, mvp)
        debug.drawDebugLine(tBLx, tBLy, tBLz - dp, tBLx, tBLy, tBLz + dp, 0f, 0.6f, 1f, mvp)
        debug.drawDebugLine(tBRx, tBRy, tBRz - dp, tBRx, tBRy, tBRz + dp, 0f, 0.4f, 1f, mvp)
    }
}