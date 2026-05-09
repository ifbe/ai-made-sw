package com.example.waterinbox.renderer

import android.opengl.GLES30
import com.example.waterinbox.math.FusionConfig
import kotlin.math.cos
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * BoxSpaceDebug — world axes, gravity arrow, magnet arrow.
 * Owns its GL program, uniforms, and draw calls.
 */
class BoxSpaceDebug(private val boxSpace: BoxSpace) {

    // ── GL Resources ────────────────────────────────────────────────
    internal var programArrow = 0
        private set
    internal var uMVP_Arrow = 0
        private set

    // ── Shader Strings ──────────────────────────────────────────────

    companion object {
        val ARROW_VERT = """
            #version 300 es
            uniform mat4 uMVP;
            in vec3 aPosition;
            in vec3 aColor;
            out vec3 vColor;
            void main() {
                gl_Position = uMVP * vec4(aPosition, 1.0);
                vColor = aColor;
            }
        """.trimIndent()

        val ARROW_FRAG = """
            #version 300 es
            precision highp float;
            in vec3 vColor;
            out vec4 fragColor;
            void main() { fragColor = vec4(vColor, 1.0); }
        """.trimIndent()
    }

    // ── Setup ───────────────────────────────────────────────────────

    fun setup() {
        programArrow = boxSpace.createProgram(ARROW_VERT, ARROW_FRAG, "Arrow")
        uMVP_Arrow = GLES30.glGetUniformLocation(programArrow, "uMVP")
    }

    // ── Draw ────────────────────────────────────────────────────────

    fun draw(mvp: FloatArray, gLen3: Float) {
        // World axes
        if (boxSpace.drawWorldAxes) {
            val axisLen = 1000f
            drawDebugLine(0f, 0f, 0f, boxSpace.wxX * axisLen, boxSpace.wxY * axisLen, boxSpace.wxZ * axisLen, 1f, 0.05f, 0.05f, mvp)
            drawDebugLine(0f, 0f, 0f, boxSpace.wyX * axisLen, boxSpace.wyY * axisLen, boxSpace.wyZ * axisLen, 0.05f, 1f, 0.05f, mvp)
            drawDebugLine(0f, 0f, 0f, boxSpace.wzX * axisLen, boxSpace.wzY * axisLen, boxSpace.wzZ * axisLen, 0.05f, 0.05f, 1f, mvp)
        }

        // Gravity arrow — length = |accel| * 10
        if (boxSpace.drawGravityArrow && gLen3 >= 0.001f) {
            val aX = FusionConfig.accelX
            val aY = FusionConfig.accelY
            val aZ = FusionConfig.accelZ
            val gLen1 = sqrt(aX * aX + aY * aY + aZ * aZ)
            if (gLen1 >= 0.001f) {
                drawArrow(aX / gLen1, aY / gLen1, aZ / gLen1, mvp,
                    shaftLen = gLen1 * 20f)
            }
        }

        // Magnet arrow — length = |mag| (raw µT value, e.g. ~450)
        if (boxSpace.drawMagnetArrow) {
            val mX = FusionConfig.magX
            val mY = FusionConfig.magY
            val mZ = FusionConfig.magZ
            val mLen = sqrt(mX * mX + mY * mY + mZ * mZ)
            if (mLen >= 0.001f) {
                drawArrow(mX / mLen, mY / mLen, mZ / mLen, mvp,
                    shaftLen = mLen)
            }
        }
    }

    // ── Debug Line ──────────────────────────────────────────────────

    fun drawDebugLine(
        tailX: Float, tailY: Float, tailZ: Float,
        tipX: Float, tipY: Float, tipZ: Float,
        r: Float, g: Float, b: Float,
        mvp: FloatArray
    ) {
        val verts = floatArrayOf(
            tailX, tailY, tailZ, r, g, b,
            tipX, tipY, tipZ, r, g, b
        )

        val buf = java.nio.ByteBuffer.allocateDirect(verts.size * 4)
            .order(java.nio.ByteOrder.nativeOrder())
            .asFloatBuffer()
        buf.put(verts).position(0)

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

        GLES30.glLineWidth(4f)
        GLES30.glUseProgram(programArrow)
        GLES30.glUniformMatrix4fv(uMVP_Arrow, 1, false, mvp, 0)
        GLES30.glDrawArrays(GLES30.GL_LINES, 0, 2)

        GLES30.glBindVertexArray(0)
        GLES30.glDeleteBuffers(1, vboArr, 0)
        GLES30.glDeleteVertexArrays(1, vaoArr, 0)
    }

    // ── Arrow ───────────────────────────────────────────────────────

    private fun drawArrow(
        gx: Float, gy: Float, gz: Float,
        mvp: FloatArray,
        shaftR: Float = boxSpace.shaftR,
        shaftLen: Float = boxSpace.shaftLen,
        shaftColorR: Float = 0.15f, shaftColorG: Float = 0.9f, shaftColorB: Float = 0.15f,
        coneColorR: Float = 0.9f, coneColorG: Float = 0.15f, coneColorB: Float = 0.15f
    ) {
        // Cone length scales with shaftLen: cone=1/4, shaft=3/4. shaftR stays fixed.
        val coneLen = shaftLen * 0.25f
        val coneR = shaftR * 2f
        val sides = 12

        val px: Float; val py: Float; val pz: Float
        if (gy * gy < 0.81f) {
            val t = sqrt(gx * gx + gy * gy)
            px = -gy / t; py = gx / t; pz = 0f
        } else {
            val t = sqrt(gy * gy + gz * gz)
            px = 0f; py = -gz / t; pz = gy / t
        }
        val qx = gy * pz - gz * py
        val qy = gz * px - gx * pz
        val qz = gx * py - gy * px

        val tipX = gx * shaftLen; val tipY = gy * shaftLen; val tipZ = gz * shaftLen
        val coneBaseX = tipX - gx * coneLen
        val coneBaseY = tipY - gy * coneLen
        val coneBaseZ = tipZ - gz * coneLen

        val verts = mutableListOf<Float>()

        // TAIL CAP
        verts.addAll(listOf(0f, 0f, 0f, shaftColorR, shaftColorG, shaftColorB))
        for (i in sides downTo 0) {
            val a = (2 * Math.PI * i / sides).toFloat()
            val rx = cos(a) * shaftR; val ry = sin(a) * shaftR
            val wx = rx * px + ry * qx; val wy = rx * py + ry * qy; val wz = rx * pz + ry * qz
            verts.addAll(listOf(wx, wy, wz, shaftColorR, shaftColorG, shaftColorB))
        }
        val tailCapCount = sides + 2

        // SHAFT
        for (i in 0..sides) {
            val a = (2 * Math.PI * i / sides).toFloat()
            val rx = cos(a) * shaftR; val ry = sin(a) * shaftR
            val wx = rx * px + ry * qx; val wy = rx * py + ry * qy; val wz = rx * pz + ry * qz
            verts.addAll(listOf(wx, wy, wz, shaftColorR, shaftColorG, shaftColorB))
            verts.addAll(listOf(coneBaseX + wx, coneBaseY + wy, coneBaseZ + wz, shaftColorR, shaftColorG, shaftColorB))
        }
        val shaftCount = (sides + 1) * 2

        // CONE BASE CAP
        verts.addAll(listOf(coneBaseX, coneBaseY, coneBaseZ, shaftColorR, shaftColorG, shaftColorB))
        for (i in 0..sides) {
            val a = (2 * Math.PI * i / sides).toFloat()
            val rx = cos(a) * shaftR; val ry = sin(a) * shaftR
            val wx = rx * px + ry * qx; val wy = rx * py + ry * qy; val wz = rx * pz + ry * qz
            verts.addAll(listOf(coneBaseX + wx, coneBaseY + wy, coneBaseZ + wz, shaftColorR, shaftColorG, shaftColorB))
        }
        val coneBaseCapCount = sides + 2

        // CONE
        verts.addAll(listOf(tipX, tipY, tipZ, coneColorR, coneColorG, coneColorB))
        for (i in 0..sides) {
            val a = (2 * Math.PI * i / sides).toFloat()
            val rx = cos(a) * coneR; val ry = sin(a) * coneR
            val wx = rx * px + ry * qx; val wy = rx * py + ry * qy; val wz = rx * pz + ry * qz
            verts.addAll(listOf(coneBaseX + wx, coneBaseY + wy, coneBaseZ + wz, coneColorR, coneColorG, coneColorB))
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
        GLES30.glDrawArrays(GLES30.GL_TRIANGLE_FAN, 0, tailCapCount)
        GLES30.glDrawArrays(GLES30.GL_TRIANGLE_STRIP, tailCapCount, shaftCount)
        GLES30.glDrawArrays(GLES30.GL_TRIANGLE_FAN, tailCapCount + shaftCount, coneBaseCapCount)
        GLES30.glDrawArrays(GLES30.GL_TRIANGLE_FAN, tailCapCount + shaftCount + coneBaseCapCount, coneCount)

        GLES30.glBindVertexArray(0)
        GLES30.glDeleteBuffers(1, vboArr, 0)
        GLES30.glDeleteVertexArrays(1, vaoArr, 0)
    }
}