package com.example.waterinbox.renderer

import android.opengl.GLES30

/**
 * BoxSpaceHuman — spring-mass human figure inside the box.
 *
 * ── Model ────────────────────────────────────────────────────────
 *
 * The human is a spring-mass tree rooted at the hip (waist ring).
 * Each limb segment is a spring with rest length and stiffness.
 *
 *   Joint hierarchy (index):
 *   ┌─ abdomen (0) ─ root, fixed at box center (x=0, y=0, z=0) ← FIXATION GRIPS HERE
 *   │
 *   ├─ chest (1) ─ left/right shoulder midpoint
 *   │   ├─ left_shoulder (2)
 *   │   │  └─ left_elbow (3)
 *   │   │     └─ lefthand (4)
 *   │   └─ right_shoulder (5)
 *   │         └─ right_elbow (6)
 *   │            └─ righthand (7)
 *   │
 *   └─ pelvis (8) ─ left/right hip midpoint
 *       ├─ left_hip (9)
 *       │  └─ left_knee (10)
 *       │     └─ leftfoot (11)
 *       └─ right_hip (12)
 *          └─ right_knee (13)
 *             └─ rightfoot (14)
 *   (total: 15 joints, 0–14)
 *
 * ── Physics ──────────────────────────────────────────────────────
 *
 * Each frame (fixed timestep dt ≈ 16ms):
 *
 *   1. Accumulate forces on each mass point:
 *        F_gravity   = m * g_local          (g_local = box-space gravity)
 *        F_spring    = -k * (|Δx| - rest) * dir
 *        F_damping   = -c * velocity
 *
 *   2. Integrate (Verlet):
 *        velocity += F / m * dt
 *        position += velocity * dt
 *
 *   3. Apply joint constraints (angle limits, max stretch):
 *        clamp each spring length to [rest * 0.5, rest * 1.5]
 *
 *   4. Clamp hip to box floor (never leaves z = 0 plane).
 *
 * ── Rendering ─────────────────────────────────────────────────────
 *
 * Draw each joint as a sphere (GL_TRIANGLE_FAN circle billboard or actual sphere).
 * Draw each limb as a line or narrow quad cylinder.
 * Color: skin(240,200,170), joint(180,100,80), torso slightly darker.
 *
 * ── Integration ───────────────────────────────────────────────────
 *
 *   1. Add toggle: @JvmField @Volatile var drawHuman = false
 *   2. Instantiate: val human = BoxSpaceHuman(this)
 *   3. Call human.setup() / human.draw(mvp, gLen3) in BoxSpace
 *   4. Bind draw toggle to UISpace RenderToggle
 *
 * ── Parameters (placeholders) ────────────────────────────────────
 *
 *   k_spring  = 800   // stiffness (N/m)
 *   c_damp    = 15    // damping coefficient
 *   dt        = 0.016 // ~60 fps timestep
 *   hip_rest  = boxD * 0.1   // torso length
 *   arm_rest  = boxD * 0.12  // upper arm
 *   forearm_rest = boxD * 0.10
 *   leg_rest  = boxD * 0.14
 *   shin_rest = boxD * 0.12
 *   neck_rest = boxD * 0.05
 *   head_rest = boxD * 0.08
 *
 * ── TODO ──────────────────────────────────────────────────────────
 *
 *   - Spring-mass physics (Verlet integration)
 *   - Angle constraints at joints
 *   - Cylinder/box limb rendering
 *   - Sphere joint rendering
 *   - Human-facing direction (faces gravity arrow direction?)
 *   - Initialize human state at app start (arms down, standing)
 *   - Add draw toggle to BoxSpace and UISpace
 */
class BoxSpaceHuman(private val boxSpace: BoxSpace) {

    // ── State ──────────────────────────────────────────────────────

    // Mass positions [x, y, z] × 15 joints (see diagram above)
    private var positions: FloatArray = FloatArray(15 * 3)
    private var velocities: FloatArray = FloatArray(15 * 3)

    // ── Parameters ─────────────────────────────────────────────────

    // Spring stiffness and damping
    private val kSpring = 800f
    private val cDamp = 15f

    // Rest lengths for each spring segment
    private val spineUpperRest get() = boxSpace.boxD * 0.10f  // abdomen → shoulder
    private val spineLowerRest get() = boxSpace.boxD * 0.10f  // abdomen → hip
    private val armRest get() = boxSpace.boxD * 0.12f
    private val forearmRest get() = boxSpace.boxD * 0.10f
    private val thighRest get() = boxSpace.boxD * 0.14f
    private val shinRest get() = boxSpace.boxD * 0.12f

    // ── GL Resources ────────────────────────────────────────────────

    private var programLimb = 0
    private var uMVP_Limb = 0

    // ── Setup ─────────────────────────────────────────────────────

    fun setup() {
        programLimb = boxSpace.createProgram(LIMB_VERT, LIMB_FRAG, "Human")
        uMVP_Limb = GLES30.glGetUniformLocation(programLimb, "uMVP")
        initPose()
    }

    // ── Initialize Pose ────────────────────────────────────────────

    private fun initPose() {
        // Hardcoded T-pose positions, all z=0 (XY plane only)
        // x *= 2, y *= 3
        // abdomen(0) at origin
        positions[0] = 0f; positions[1] = 0f; positions[2] = 0f
        // spine up
        positions[3] = 0f; positions[4] = boxSpace.boxD * 0.12f * 3f; positions[5] = 0f  // chest(1)
        // left arm (T-pose: arm horizontal)
        positions[6] = -boxSpace.boxD * 0.12f * 2f; positions[7] = boxSpace.boxD * 0.15f * 3f; positions[8] = 0f  // left_shoulder(2)
        positions[9] = -boxSpace.boxD * 0.22f * 2f; positions[10] = boxSpace.boxD * 0.15f * 3f; positions[11] = 0f  // left_elbow(3)
        positions[12] = -boxSpace.boxD * 0.32f * 2f; positions[13] = boxSpace.boxD * 0.15f * 3f; positions[14] = 0f  // lefthand(4)
        // right arm
        positions[15] = boxSpace.boxD * 0.12f * 2f; positions[16] = boxSpace.boxD * 0.15f * 3f; positions[17] = 0f  // right_shoulder(5)
        positions[18] = boxSpace.boxD * 0.22f * 2f; positions[19] = boxSpace.boxD * 0.15f * 3f; positions[20] = 0f  // right_elbow(6)
        positions[21] = boxSpace.boxD * 0.32f * 2f; positions[22] = boxSpace.boxD * 0.15f * 3f; positions[23] = 0f  // righthand(7)
        // pelvis
        positions[24] = 0f; positions[25] = -boxSpace.boxD * 0.12f * 3f; positions[26] = 0f  // pelvis(8)
        // left leg
        positions[27] = -boxSpace.boxD * 0.06f * 2f; positions[28] = -boxSpace.boxD * 0.15f * 3f; positions[29] = 0f  // left_hip(9)
        positions[30] = -boxSpace.boxD * 0.09f * 2f; positions[31] = -boxSpace.boxD * 0.28f * 3f; positions[32] = 0f  // left_knee(10)
        positions[33] = -boxSpace.boxD * 0.06f * 2f; positions[34] = -boxSpace.boxD * 0.44f * 3f; positions[35] = 0f  // leftfoot(11)
        // right leg
        positions[36] = boxSpace.boxD * 0.06f * 2f; positions[37] = -boxSpace.boxD * 0.15f * 3f; positions[38] = 0f  // right_hip(12)
        positions[39] = boxSpace.boxD * 0.09f * 2f; positions[40] = -boxSpace.boxD * 0.28f * 3f; positions[41] = 0f  // right_knee(13)
        positions[42] = boxSpace.boxD * 0.06f * 2f; positions[43] = -boxSpace.boxD * 0.44f * 3f; positions[44] = 0f  // rightfoot(14)
    }

    // ── Physics Step ───────────────────────────────────────────────

    /**
     * Advance the human simulation by one timestep.
     * Called every frame in draw().
     *
     * Algorithm: Verlet integration per spring-mass point
     *
     * Pseudocode:
     *   for each non-fixed joint i:
     *     F = gravity_force + spring_forces + damping_force
     *     vel[i] += F / mass * dt
     *     pos[i] += vel[i] * dt
     *   apply joint angle constraints
     *   clamp hip to floor plane
     */
    private fun step(dt: Float) {
        // TODO: implement Verlet spring-mass physics
        // val gX = boxSpace.gX; val gY = boxSpace.gY; val gZ = boxSpace.gZ
        // for each joint:
        //   gravity: Fg = m * {gX, gY, gZ}
        //   spring: for each parent-child pair, Fs = -k * (dist - rest) * direction
        //   damping: Fd = -c * velocity
        //   integrate: vel += (Fg + Fs + Fd) / m * dt; pos += vel * dt
        // clamp hip to (0, 0, 0)
        // apply angle constraints per joint
    }

    // ── Draw ────────────────────────────────────────────────────────

    /** Called by BoxSpace.onDrawFrame — dispatches to sub-elements. */
    fun draw(mvp: FloatArray, gLen3: Float) {
        drawHumanElement(mvp, gLen3)
    }

    private fun drawHumanElement(mvp: FloatArray, gLen3: Float) {
        if (boxSpace.drawFixation) {
            drawFixation(mvp)
        }
        if (boxSpace.drawHuman) {
            // step(0.016f)  // TODO: uncomment when physics implemented
            drawLimbSegments(mvp)
            drawJointSpheres(mvp)
        }
    }

    // ── Rendering Helpers ──────────────────────────────────────────

    private fun drawFixation(mvp: FloatArray) {
        // Claw / open cage fixation: 10 vertices, 4 side faces, no top/bottom.
        // tx=boxD/4, ty=boxD/8, tz=boxD/4
        // o=back-bottom, a=left-mid, b=right-mid, c=left-top-front, d=right-top-front
        val tx = boxSpace.boxD / 4f
        val ty = boxSpace.boxD / 8f
        val tz = boxSpace.boxD / 4f

        // 10 hardcoded vertices [x, y, z]
        // Lower row (y=-ty):  o(0), a(1), b(2), c(3), d(4)
        // Upper row (y=+ty): o*(5), a*(6), b*(7), c*(8), d*(9)
        val P = floatArrayOf(
              0f,   -1.1f*ty,   -tz,    // 0: o
             -tx,   -     ty,    0f,    // 1: a
              tx,   -     ty,    0f,    // 2: b
             -tx/2, -0.9f*ty,  tz/2,    // 3: c
              tx/2, -0.9f*ty,  tz/2,    // 4: d
              0f,    1.1f*ty,   -tz,    // 5: o*
             -tx,         ty,    0f,    // 6: a*
              tx,         ty,    0f,    // 7: b*
             -tx/2,  0.9f*ty,  tz/2,    // 8: c*
              tx/2,  0.9f*ty,  tz/2     // 9: d*
        )

        // Point colors: o=BLACK, c/d=WHITE, a/b=GRAY
        // o=grayish black, a/b=grayish white, c=0.9white-red, d=0.9white-blue
        val ptColor = arrayOf(
            floatArrayOf(0.25f, 0.25f, 0.25f, 1f),  // 0: o  grayish black
            floatArrayOf(0.79f, 0.61f, 0.61f, 1f),  // 1: a  grayish white
            floatArrayOf(0.61f, 0.61f, 0.79f, 1f),  // 2: b  grayish white
            floatArrayOf(0.99f, 0.81f, 0.81f, 1f),  // 3: c  0.9white slightly red (R+0.01, B-0.02)
            floatArrayOf(0.81f, 0.81f, 0.99f, 1f),  // 4: d  0.9white slightly blue (R-0.02, B+0.01)
            floatArrayOf(0.25f, 0.25f, 0.25f, 1f),  // 5: o* grayish black
            floatArrayOf(0.79f, 0.61f, 0.61f, 1f),  // 6: a* grayish white
            floatArrayOf(0.61f, 0.61f, 0.79f, 1f),  // 7: b* grayish white
            floatArrayOf(0.99f, 0.81f, 0.81f, 1f),  // 8: c* 0.9white slightly red
            floatArrayOf(0.81f, 0.81f, 0.99f, 1f)   // 9: d* 0.9white slightly blue
        )

        // 4 faces, each made of 2 triangles, defined by vertex indices
        val faces = listOf(
            intArrayOf(3, 1, 6, 8),  // face 1: c→a→a*→c* (left wall, red tint)
            intArrayOf(1, 0, 5, 6),  // face 2: a→o→o*→a* (front-bottom, red tint)
            intArrayOf(0, 2, 7, 5),  // face 3: o→b→b*→o* (right wall, blue tint)
            intArrayOf(2, 4, 9, 7)   // face 4: b→d→d*→b* (back-right wall, blue tint)
        )

        val verts = mutableListOf<Float>()

        for (face in faces) {
            val i0=face[0]; val i1=face[1]; val i2=face[2]; val i3=face[3]
            val pairs = listOf(intArrayOf(i0,i1,i2), intArrayOf(i0,i2,i3))
            for (pair in pairs) {
                val ia=pair[0]; val ib=pair[1]; val ic=pair[2]
                val ax=P[ia*3]; val ay=P[ia*3+1]; val az=P[ia*3+2]
                val bx=P[ib*3]; val by=P[ib*3+1]; val bz=P[ib*3+2]
                val cx=P[ic*3]; val cy=P[ic*3+1]; val cz=P[ic*3+2]
                val ex=bx-ax; val ey=by-ay; val ez=bz-az
                val fx=cx-ax; val fy=cy-ay; val fz=cz-az
                val nx=ey*fz-ez*fy; val ny=ez*fx-ex*fz; val nz=ex*fy-ey*fx
                val len=kotlin.math.sqrt(nx*nx+ny*ny+nz*nz).toFloat()
                val nnx=nx/len; val nny=ny/len; val nnz=nz/len
                for (idx in pair) {
                    val c=ptColor[idx]
                    verts.addAll(listOf(P[idx*3], P[idx*3+1], P[idx*3+2],
                                        nnx, nny, nnz,
                                        c[0], c[1], c[2], c[3]))
                }
            }
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
        val stride = 40
        GLES30.glEnableVertexAttribArray(0)
        GLES30.glVertexAttribPointer(0, 3, GLES30.GL_FLOAT, false, stride, 0)
        GLES30.glEnableVertexAttribArray(1)
        GLES30.glVertexAttribPointer(1, 3, GLES30.GL_FLOAT, false, stride, 12)
        GLES30.glEnableVertexAttribArray(2)
        GLES30.glVertexAttribPointer(2, 4, GLES30.GL_FLOAT, false, stride, 24)

        GLES30.glUseProgram(programLimb)
        GLES30.glUniformMatrix4fv(uMVP_Limb, 1, false, mvp, 0)
        GLES30.glDrawArrays(GLES30.GL_TRIANGLES, 0, 24)  // 4 faces × 2 tri × 3 verts
        GLES30.glBindVertexArray(0)
        GLES30.glDeleteBuffers(1, vboArr, 0)
        GLES30.glDeleteVertexArrays(1, vaoArr, 0)
    }

    private fun drawLimbSegments(mvp: FloatArray) {
        val pairs = listOf(
            intArrayOf(0, 1),   // abdomen → chest
            intArrayOf(0, 8),   // abdomen → pelvis
            intArrayOf(1, 2),   // chest → left_shoulder
            intArrayOf(1, 5),   // chest → right_shoulder
            intArrayOf(2, 3),   // left_shoulder → left_elbow
            intArrayOf(3, 4),   // left_elbow → lefthand
            intArrayOf(5, 6),   // right_shoulder → right_elbow
            intArrayOf(6, 7),   // right_elbow → righthand
            intArrayOf(8, 9),   // pelvis → left_hip
            intArrayOf(8, 12),  // pelvis → right_hip
            intArrayOf(9, 10),  // left_hip → left_knee
            intArrayOf(10, 11), // left_knee → leftfoot
            intArrayOf(12, 13), // right_hip → right_knee
            intArrayOf(13, 14)  // right_knee → rightfoot
        )
        val verts = mutableListOf<Float>()
        for (p in pairs) {
            // 2 verts per pair, each vert: pos(3) + normal(3) + color(4) = 10 floats
            for (idx in p) {
                verts.addAll(listOf(
                    positions[idx*3], positions[idx*3+1], positions[idx*3+2],
                    0f, 0f, 1f,  // fake normal
                    0.9f, 0.8f, 0.6f, 1f  // color: light tan
                ))
            }
        }
        val buf = java.nio.ByteBuffer.allocateDirect(verts.size * 4)
            .order(java.nio.ByteOrder.nativeOrder()).asFloatBuffer()
            .put(verts.toFloatArray()).position(0)
        val vao = IntArray(1); val vbo = IntArray(1)
        GLES30.glGenVertexArrays(1, vao, 0)
        GLES30.glGenBuffers(1, vbo, 0)
        GLES30.glBindVertexArray(vao[0])
        GLES30.glBindBuffer(GLES30.GL_ARRAY_BUFFER, vbo[0])
        GLES30.glBufferData(GLES30.GL_ARRAY_BUFFER, verts.size * 4, buf, GLES30.GL_DYNAMIC_DRAW)
        val stride = 40
        GLES30.glEnableVertexAttribArray(0)
        GLES30.glVertexAttribPointer(0, 3, GLES30.GL_FLOAT, false, stride, 0)
        GLES30.glEnableVertexAttribArray(1)
        GLES30.glVertexAttribPointer(1, 3, GLES30.GL_FLOAT, false, stride, 12)
        GLES30.glEnableVertexAttribArray(2)
        GLES30.glVertexAttribPointer(2, 4, GLES30.GL_FLOAT, false, stride, 24)
        GLES30.glUseProgram(programLimb)
        GLES30.glUniformMatrix4fv(uMVP_Limb, 1, false, mvp, 0)
        GLES30.glDrawArrays(GLES30.GL_LINES, 0, pairs.size * 2)
        GLES30.glBindVertexArray(0)
        GLES30.glDeleteBuffers(1, vbo, 0)
        GLES30.glDeleteVertexArrays(1, vao, 0)
    }

    private fun drawJointSpheres(mvp: FloatArray) {
        // TODO: placeholder
    }

    // ── Shaders (placeholders) ─────────────────────────────────────

    companion object {
        val LIMB_VERT = """
#version 300 es
uniform mat4 uMVP;
layout(location = 0) in vec3 aPosition;
layout(location = 1) in vec3 aNormal;
layout(location = 2) in vec3 aColor;
out vec3 vColor;
void main() {
    gl_Position = uMVP * vec4(aPosition, 1.0);
    vColor = aColor;
}
        """.trimIndent()

        val LIMB_FRAG = """
#version 300 es
precision highp float;
in vec3 vColor;
out vec4 fragColor;
void main() { fragColor = vec4(vColor, 1.0); }
        """.trimIndent()
    }
}