import Foundation
import Metal
import simd

// MARK: - Shared Uniforms

struct LineUniforms {
    var mvpMatrix: simd_float4x4
    var color: simd_float4
}

// MARK: - Debug Element
//
// drawDebugElement() — coordinate axes, gravity arrow, magnet arrow.
// Pipeline setup: setupDebugPipelines().

extension MetalViewController {

    // MARK: - Pipeline Setup

    func setupDebugPipelines() {
        let library = makeDebugLibrary()
        let vd = makeArrowVertexDescriptor()

        pipelineStateLine = makePipelineState(
            library: library,
            vertexFunction: "lineVertex",
            fragmentFunction: "lineFragment"
        )

        pipelineStateArrow = makePipelineState(
            library: library,
            vertexFunction: "arrowVertex",
            fragmentFunction: "arrowFragment",
            vertexDescriptor: vd
        )
    }

    // MARK: - Element Draw

    func drawDebugElement(encoder: MTLRenderCommandEncoder, mvp: inout simd_float4x4, gLen3: Float) {
        // World axes
        if RenderState.shared.drawWorldAxes {
            let axisLen: Float = 1000
            drawDebugLine(encoder: encoder, x1: 0, y1: 0, z1: 0, x2: wxX*axisLen, y2: wxY*axisLen, z2: wxZ*axisLen, r: 1, g: 0.05, b: 0.05, mvp: &mvp)
            drawDebugLine(encoder: encoder, x1: 0, y1: 0, z1: 0, x2: wyX*axisLen, y2: wyY*axisLen, z2: wyZ*axisLen, r: 0.05, g: 1, b: 0.05, mvp: &mvp)
            drawDebugLine(encoder: encoder, x1: 0, y1: 0, z1: 0, x2: wzX*axisLen, y2: wzY*axisLen, z2: wzZ*axisLen, r: 0.05, g: 0.05, b: 1, mvp: &mvp)
        }

        // Gravity arrow — shaftLen = gLen1 * 200 (gLen1 in m/s², ~9.8 when stationary)
        if RenderState.shared.drawGravityArrow && gLen3 >= 0.001 {
            let aX = FusionConfig.accelX
            let aY = FusionConfig.accelY
            let aZ = FusionConfig.accelZ
            let gLen1 = sqrt(aX * aX + aY * aY + aZ * aZ)
            if gLen1 >= 0.001 {
                let shaftLen = gLen1 * 200.0
                drawArrow(encoder: encoder, dx: aX/gLen1, dy: aY/gLen1, dz: aZ/gLen1, mvp: &mvp, shaftLen: shaftLen, shaftColorR: 0.15, shaftColorG: 0.9, shaftColorB: 0.15, coneColorR: 0.9, coneColorG: 0.15, coneColorB: 0.15)
            }
        }

        // Magnet arrow — shaftLen = |mag| raw µT value (~45-65)
        if RenderState.shared.drawMagnetArrow {
            let mX = FusionConfig.magX
            let mY = FusionConfig.magY
            let mZ = FusionConfig.magZ
            let mLen = sqrt(mX * mX + mY * mY + mZ * mZ)
            if mLen >= 0.001 {
                drawArrow(encoder: encoder, dx: mX/mLen, dy: mY/mLen, dz: mZ/mLen, mvp: &mvp, shaftLen: mLen, shaftColorR: 0.15, shaftColorG: 0.15, shaftColorB: 0.9, coneColorR: 0.9, coneColorG: 0.15, coneColorB: 0.15)
            }
        }
    }

    // MARK: - Debug Draw Calls

    func drawDebugLine(encoder: MTLRenderCommandEncoder, x1: Float, y1: Float, z1: Float, x2: Float, y2: Float, z2: Float, r: Float, g: Float, b: Float, mvp: inout simd_float4x4) {
        let verts: [Float] = [x1, y1, z1, 1, x2, y2, z2, 1]

        var vertexBuffer = device.makeBuffer(
            bytes: verts,
            length: verts.count * MemoryLayout<Float>.size,
            options: .storageModeShared
        )

        var uniforms = LineUniforms(mvpMatrix: mvp, color: simd_float4(r, g, b, 1.0))

        encoder.setRenderPipelineState(pipelineStateLine)
        encoder.setVertexBuffer(vertexBuffer, offset: 0, index: 0)
        encoder.setVertexBytes(&uniforms, length: MemoryLayout<LineUniforms>.stride, index: 1)
        encoder.setFragmentBytes(&uniforms, length: MemoryLayout<LineUniforms>.stride, index: 1)
        encoder.drawPrimitives(type: .line, vertexStart: 0, vertexCount: 2)
    }

    // Matches Android drawArrow logic exactly:
    // coneLen = shaftLen * 0.25, coneR = shaftR * 2
    func drawArrow(encoder: MTLRenderCommandEncoder, dx: Float, dy: Float, dz: Float, mvp: inout simd_float4x4, shaftLen: Float, shaftColorR: Float, shaftColorG: Float, shaftColorB: Float, coneColorR: Float, coneColorG: Float, coneColorB: Float) {
        let sides = 12
        let shaftR = boxD * 0.05
        let coneLen = shaftLen * 0.25
        let coneR = shaftR * 2.0

        // 计算局部坐标系的两个轴 p、q
        var px: Float; var py: Float; var pz: Float
        if (dy * dy < 0.81) {
            let t = sqrt(dx * dx + dy * dy)
            px = -dy / t; py = dx / t; pz = 0
        } else {
            let t = sqrt(dy * dy + dz * dz)
            px = 0; py = -dz / t; pz = dy / t
        }
        let qx = dy * pz - dz * py
        let qy = dz * px - dx * pz
        let qz = dx * py - dy * px

        var verts: [Float] = []

        let tipX = dx * shaftLen; let tipY = dy * shaftLen; let tipZ = dz * shaftLen
        let coneBaseX = tipX - dx * coneLen
        let coneBaseY = tipY - dy * coneLen
        let coneBaseZ = tipZ - dz * coneLen

        // ── 1. 尾部圆盘 (Tail cap) ──
        verts.append(0); verts.append(0); verts.append(0)
        verts.append(shaftColorR); verts.append(shaftColorG); verts.append(shaftColorB)
        for i in stride(from: sides, through: 0, by: -1) {
            let a = (2 * Float.pi * Float(i) / Float(sides))
            let rx = cos(a) * shaftR; let ry = sin(a) * shaftR
            let wx = rx * px + ry * qx; let wy = rx * py + ry * qy; let wz = rx * pz + ry * qz
            verts.append(wx); verts.append(wy); verts.append(wz)
            verts.append(shaftColorR); verts.append(shaftColorG); verts.append(shaftColorB)
        }
        let tailCapVerts = sides + 2   // 中心 + (sides+1) 个圆周点

        // ── 2. 杆身 (Shaft) Triangle strip ──
        for i in 0...sides {
            let a = (2 * Float.pi * Float(i) / Float(sides))
            let rx = cos(a) * shaftR; let ry = sin(a) * shaftR
            let wx = rx * px + ry * qx; let wy = rx * py + ry * qy; let wz = rx * pz + ry * qz
            verts.append(wx); verts.append(wy); verts.append(wz)
            verts.append(shaftColorR); verts.append(shaftColorG); verts.append(shaftColorB)
            verts.append(coneBaseX + wx); verts.append(coneBaseY + wy); verts.append(coneBaseZ + wz)
            verts.append(shaftColorR); verts.append(shaftColorG); verts.append(shaftColorB)
        }
        let shaftVertStart = tailCapVerts
        let shaftVertCount = (sides + 1) * 2

        // ── 3. 圆锥底面盖 (Cone base cap) ──
        verts.append(coneBaseX); verts.append(coneBaseY); verts.append(coneBaseZ)
        verts.append(coneColorR); verts.append(coneColorG); verts.append(coneColorB)
        for i in 0...sides {
            let a = (2 * Float.pi * Float(i) / Float(sides))
            let rx = cos(a) * coneR; let ry = sin(a) * coneR
            let wx = rx * px + ry * qx; let wy = rx * py + ry * qy; let wz = rx * pz + ry * qz
            verts.append(coneBaseX + wx); verts.append(coneBaseY + wy); verts.append(coneBaseZ + wz)
            verts.append(coneColorR); verts.append(coneColorG); verts.append(shaftColorB)
        }
        let coneBaseCapVertStart = tailCapVerts + shaftVertCount
        let coneBaseCapVertCount = sides + 2

        // ── 4. 圆锥体 (Cone) ──
        verts.append(tipX); verts.append(tipY); verts.append(tipZ)
        verts.append(coneColorR); verts.append(coneColorG); verts.append(coneColorB)
        for i in 0...sides {
            let a = (2 * Float.pi * Float(i) / Float(sides))
            let rx = cos(a) * coneR; let ry = sin(a) * coneR
            let wx = rx * px + ry * qx; let wy = rx * py + ry * qy; let wz = rx * pz + ry * qz
            verts.append(coneBaseX + wx); verts.append(coneBaseY + wy); verts.append(coneBaseZ + wz)
            verts.append(coneColorR); verts.append(coneColorG); verts.append(coneColorB)
        }
        let coneVertStart = coneBaseCapVertStart + coneBaseCapVertCount
        let coneVertCount = sides + 2

        // 创建顶点缓冲并绘制
        let vertexBuffer = device.makeBuffer(bytes: verts, length: verts.count * MemoryLayout<Float>.size, options: .storageModeShared)!

        encoder.setRenderPipelineState(pipelineStateArrow)
        encoder.setVertexBuffer(vertexBuffer, offset: 0, index: 0)
        encoder.setVertexBytes(&mvp, length: MemoryLayout<simd_float4x4>.stride, index: 1)

        encoder.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: tailCapVerts)
        encoder.drawPrimitives(type: .triangleStrip, vertexStart: shaftVertStart, vertexCount: shaftVertCount)
        encoder.drawPrimitives(type: .triangle, vertexStart: coneBaseCapVertStart, vertexCount: coneBaseCapVertCount)
        encoder.drawPrimitives(type: .triangle, vertexStart: coneVertStart, vertexCount: coneVertCount)
    }

    // MARK: - Shared Vertex Descriptor

    func makeArrowVertexDescriptor() -> MTLVertexDescriptor {
        let vd = MTLVertexDescriptor()
        vd.attributes[0].format = .float3
        vd.attributes[0].offset = 0
        vd.attributes[0].bufferIndex = 0
        vd.attributes[1].format = .float3
        vd.attributes[1].offset = MemoryLayout<Float>.size * 3
        vd.attributes[1].bufferIndex = 0
        vd.layouts[0].stride = MemoryLayout<Float>.size * 6
        vd.layouts[0].stepFunction = .perVertex
        return vd
    }

    // MARK: - Shaders

    func makeDebugLibrary() -> MTLLibrary {
        let src = """
        #include <metal_stdlib>
        using namespace metal;

        struct LineUniforms {
            float4x4 mvp;
            float4 color;
        };

        vertex float4 lineVertex(
            uint vertexID [[vertex_id]],
            constant float4* vertices [[buffer(0)]],
            constant LineUniforms& uniforms [[buffer(1)]]
        ) {
            return uniforms.mvp * float4(vertices[vertexID].xyz, 1.0);
        }

        fragment float4 lineFragment(constant LineUniforms& uniforms [[buffer(1)]]) {
            return uniforms.color;
        }

        struct ArrowVertexIn {
            float3 position [[attribute(0)]];
            float3 color [[attribute(1)]];
        };

        struct ArrowVertexOut {
            float4 position [[position]];
            float3 color;
        };

        vertex ArrowVertexOut arrowVertex(
            ArrowVertexIn in [[stage_in]],
            constant float4x4& mvp [[buffer(1)]]
        ) {
            ArrowVertexOut out;
            out.position = mvp * float4(in.position, 1.0);
            out.color = in.color;
            return out;
        }

        fragment float4 arrowFragment(ArrowVertexOut in [[stage_in]]) {
            return float4(in.color, 1.0);
        }

        """

        do {
            return try device.makeLibrary(source: src, options: nil)
        } catch {
            fatalError("Failed to create debug shader library: \(error)")
        }
    }
}
