import Foundation
import Metal
import simd

// MARK: - Other Element
//
// drawOtherElement() — future optional scene elements.
// Pipeline setup: setupOtherPipelines().
//
// Adding a new element? Follow this pattern:
//
//   1. Add flag in RenderState (sensor/SensorManager.swift):
//        @Published var drawXxx: Bool = false
//
//   2. Add toggle in UISpace.swift → RenderTogglesPanel:
//        RenderToggle(label: "Xxx", isEnabled: $renderState.drawXxx)
//
//   3. Implement drawXxx(encoder: mvp:) in this file:
//        func drawXxx(encoder: MTLRenderCommandEncoder, mvp: inout simd_float4x4) {
//            guard RenderState.shared.drawXxx else { return }
//            // ... geometry and draw calls ...
//        }
//
//   4. Call drawXxx from drawOtherElement() below.

extension MetalViewController {

    // MARK: - Pipeline Setup

    func setupOtherPipelines() {
        // No pipelines yet — add as you implement new elements
    }

    // MARK: - Element Draw

    func drawOtherElement(encoder: MTLRenderCommandEncoder, mvp: inout simd_float4x4, gLen3: Float) {
        // ── Examples ────────────────────────────────────────────────
        // drawBalloons(encoder: encoder, mvp: &mvp)
        // drawMarbles(encoder: encoder, mvp: &mvp)
        // drawPersonInBox(encoder: encoder, mvp: &mvp)
        // ────────────────────────────────────────────────────────────
    }

    // MARK: - Placeholder Stubs

    // func drawBalloons(encoder: MTLRenderCommandEncoder, mvp: inout simd_float4x4) {
    //     guard RenderState.shared.drawBalloons else { return }
    //     // TODO: balloon sphere + string geometry
    // }

    // func drawMarbles(encoder: MTLRenderCommandEncoder, mvp: inout simd_float4x4) {
    //     guard RenderState.shared.drawMarbles else { return }
    //     // TODO: marble sphere geometry
    // }

    // func drawPersonInBox(encoder: MTLRenderCommandEncoder, mvp: inout simd_float4x4) {
    //     guard RenderState.shared.drawPersonInBox else { return }
    //     // TODO: box outline + simple silhouette geometry
    // }
}
