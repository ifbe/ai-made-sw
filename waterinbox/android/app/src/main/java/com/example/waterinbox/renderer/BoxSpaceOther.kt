package com.example.waterinbox.renderer

/**
 * BoxSpaceOther — placeholder for future scene elements.
 *
 * Pattern for adding a new element:
 *
 *   1. Add draw toggle in BoxSpace:
 *        @JvmField @Volatile var drawXxx = false
 *
 *   2. Create element class (like this one) with setup() / draw().
 *
 *   3. Instantiate in BoxSpace.init:
 *        val other = BoxSpaceOther(this)
 *
 *   4. Call other.draw() in BoxSpace.onDrawFrame.
 *
 *   5. Expose state to UISpace via BoxSpace public properties.
 *
 * Examples:
 *   - Balloon spheres floating in the box
 *   - Particle bubbles in the water
 *   - Box wireframe edges
 *   - Compass rose overlay
 *   - Miniature person figure
 */
class BoxSpaceOther(private val boxSpace: BoxSpace) {

    // ── Setup ───────────────────────────────────────────────────────

    fun setup() {
        // TODO: compile any GL programs needed for this element
    }

    // ── Draw ────────────────────────────────────────────────────────

    fun draw(mvp: FloatArray, gLen3: Float) {
        // Placeholder draw body — replace with actual geometry
        // if (boxSpace.drawXxx) { ... }
    }
}