import Foundation
import Metal
import simd

// MARK: - Human Element
//
// drawOtherElement() — human figure, fixation device.
// Pipeline setup: setupHumanPipelines().
//
// Joint hierarchy (15 joints):
//   abdomen(0) — root, fixed at box center
//   chest(1) — spine upper
//   left_shoulder(2) → left_elbow(3) → lefthand(4)
//   right_shoulder(5) → right_elbow(6) → righthand(7)
//   pelvis(8) — spine lower
//   left_hip(9) → left_knee(10) → leftfoot(11)
//   right_hip(12) → right_knee(13) → rightfoot(14)

extension MetalViewController {

    // MARK: - Pipeline Setup

    func setupHumanPipelines() {
        let library = makeHumanLibrary()
        let vd = makeHumanVertexDescriptor()
        pipelineStateHuman = makePipelineState(
            library: library,
            vertexFunction: "humanVertex",
            fragmentFunction: "humanFragment",
            vertexDescriptor: vd
        )
    }
    func makeHumanVertexDescriptor() -> MTLVertexDescriptor {
        let vd = MTLVertexDescriptor()
        // position
        vd.attributes[0].format = .float3
        vd.attributes[0].offset = 0
        vd.attributes[0].bufferIndex = 0
        // normal
        vd.attributes[1].format = .float3
        vd.attributes[1].offset = MemoryLayout<Float>.size * 3
        vd.attributes[1].bufferIndex = 0
        // color
        vd.attributes[2].format = .float3
        vd.attributes[2].offset = MemoryLayout<Float>.size * 6
        vd.attributes[2].bufferIndex = 0
        // layout
        vd.layouts[0].stride = MemoryLayout<Float>.size * 9
        vd.layouts[0].stepFunction = .perVertex
        return vd
    }

    // MARK: - Element Draw

    func drawHumanElement(encoder: MTLRenderCommandEncoder, mvp: inout simd_float4x4, gLen3: Float) {
        guard RenderState.shared.drawHuman || RenderState.shared.drawFixation else { return }

        encoder.setRenderPipelineState(pipelineStateHuman)
        encoder.setVertexBytes(&mvp, length: MemoryLayout<simd_float4x4>.stride, index: 1)

        if RenderState.shared.drawFixation {
            drawFixation(encoder: encoder, mvp: &mvp)
        }

        if RenderState.shared.drawHuman {
            drawLimbSegments(encoder: encoder, mvp: &mvp)
        }
    }

    // MARK: - Human Draw Calls

    private func drawFixation(encoder: MTLRenderCommandEncoder, mvp: inout simd_float4x4) {
        // Claw / open cage fixation: 10 vertices, 4 side faces, no top/bottom.
        // tx=boxD/4, ty=boxD/8, tz=boxD/4
        // o=back-bottom, a=left-mid, b=right-mid, c=left-top-front, d=right-top-front
        let tx = boxD / 4.0
        let ty = boxD / 8.0
        let tz = boxD / 4.0

        // 10 hardcoded vertices [x, y, z]
        // Lower row (y=-ty):  o(0), a(1), b(2), c(3), d(4)
        // Upper row (y=+ty): o*(5), a*(6), b*(7), c*(8), d*(9)
        let P: [Float] = [
              0,   -1.1*ty,   -tz,    // 0: o
            -tx,      -(ty),    0,    // 1: a
             tx,      -(ty),    0,    // 2: b
            -tx/2, -0.9*ty,  tz/2,    // 3: c
             tx/2, -0.9*ty,  tz/2,    // 4: d
              0,    1.1*ty,   -tz,    // 5: o*
            -tx,        ty,    0,    // 6: a*
             tx,        ty,    0,    // 7: b*
            -tx/2,  0.9*ty,  tz/2,    // 8: c*
             tx/2,  0.9*ty,  tz/2     // 9: d*
        ]

        // Point colors: o=BLACK, c/d=WHITE, a/b=GRAY
        // o=grayish black, a/b=grayish white, c=0.9white-red, d=0.9white-blue
        let ptColor: [[Float]] = [
            [0.25, 0.25, 0.25],  // 0: o  grayish black
            [0.79, 0.61, 0.61],  // 1: a  grayish white
            [0.61, 0.61, 0.79],  // 2: b  grayish white
            [0.99, 0.81, 0.81],  // 3: c  0.9white slightly red
            [0.81, 0.81, 0.99],  // 4: d  0.9white slightly blue
            [0.25, 0.25, 0.25],  // 5: o* grayish black
            [0.79, 0.61, 0.61],  // 6: a* grayish white
            [0.61, 0.61, 0.79],  // 7: b* grayish white
            [0.99, 0.81, 0.81],  // 8: c* 0.9white slightly red
            [0.81, 0.81, 0.99]   // 9: d* 0.9white slightly blue
        ]

        // 4 faces, each made of 2 triangles, defined by vertex indices
        let faces: [[Int]] = [
            [3, 1, 6, 8],  // face 1: c→a→a*→c* (left wall, red tint)
            [1, 0, 5, 6],  // face 2: a→o→o*→a* (front-bottom, red tint)
            [0, 2, 7, 5],  // face 3: o→b→b*→o* (right wall, blue tint)
            [2, 4, 9, 7]   // face 4: b→d→d*→b* (back-right wall, blue tint)
        ]

        var verts: [Float] = []

        for face in faces {
            let i0 = face[0]; let i1 = face[1]; let i2 = face[2]; let i3 = face[3]
            let pairs: [[Int]] = [[i0,i1,i2], [i0,i2,i3]]
            for pair in pairs {
                let ia = pair[0]; let ib = pair[1]; let ic = pair[2]
                let ax = P[ia*3]; let ay = P[ia*3+1]; let az = P[ia*3+2]
                let bx = P[ib*3]; let by = P[ib*3+1]; let bz = P[ib*3+2]
                let cx = P[ic*3]; let cy = P[ic*3+1]; let cz = P[ic*3+2]
                let ex = bx-ax; let ey = by-ay; let ez = bz-az
                let fx = cx-ax; let fy = cy-ay; let fz = cz-az
                let nx = ey*fz-ez*fy; let ny = ez*fx-ex*fz; let nz = ex*fy-ey*fx
                let len = sqrt(nx*nx+ny*ny+nz*nz)
                let nnx = nx/len; let nny = ny/len; let nnz = nz/len
                for idx in pair {
                    let c = ptColor[idx]
                    verts.append(P[idx*3]); verts.append(P[idx*3+1]); verts.append(P[idx*3+2])
                    verts.append(nnx); verts.append(nny); verts.append(nnz)
                    verts.append(c[0]); verts.append(c[1]); verts.append(c[2])
                }
            }
        }

        guard let vertexBuffer = device.makeBuffer(bytes: verts, length: verts.count * MemoryLayout<Float>.size, options: .storageModeShared) else { return }

        encoder.setVertexBuffer(vertexBuffer, offset: 0, index: 0)
        encoder.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: 24)  // 4 faces × 2 tri × 3 verts
    }

    private func drawLimbSegments(encoder: MTLRenderCommandEncoder, mvp: inout simd_float4x4) {
        // 15 joints in T-pose, all z=0
        let positions: [Float] = [
            // 0: abdomen(0) at origin
            0, 0, 0,
            // 1: chest(1)
            0, boxD * 0.36, 0,
            // 2: left_shoulder(2)
            -boxD * 0.24, boxD * 0.45, 0,
            // 3: left_elbow(3)
            -boxD * 0.44, boxD * 0.45, 0,
            // 4: lefthand(4)
            -boxD * 0.64, boxD * 0.45, 0,
            // 5: right_shoulder(5)
            boxD * 0.24, boxD * 0.45, 0,
            // 6: right_elbow(6)
            boxD * 0.44, boxD * 0.45, 0,
            // 7: righthand(7)
            boxD * 0.64, boxD * 0.45, 0,
            // 8: pelvis(8)
            0, -boxD * 0.36, 0,
            // 9: left_hip(9)
            -boxD * 0.12, -boxD * 0.45, 0,
            // 10: left_knee(10)
            -boxD * 0.18, -boxD * 0.84, 0,
            // 11: leftfoot(11)
            -boxD * 0.12, -boxD * 1.32, 0,
            // 12: right_hip(12)
            boxD * 0.12, -boxD * 0.45, 0,
            // 13: right_knee(13)
            boxD * 0.18, -boxD * 0.84, 0,
            // 14: rightfoot(14)
            boxD * 0.12, -boxD * 1.32, 0
        ]

        let pairs: [[Int]] = [
            [0, 1],    // abdomen → chest
            [0, 8],    // abdomen → pelvis
            [1, 2],    // chest → left_shoulder
            [1, 5],    // chest → right_shoulder
            [2, 3],    // left_shoulder → left_elbow
            [3, 4],    // left_elbow → lefthand
            [5, 6],    // right_shoulder → right_elbow
            [6, 7],    // right_elbow → righthand
            [8, 9],    // pelvis → left_hip
            [8, 12],   // pelvis → right_hip
            [9, 10],   // left_hip → left_knee
            [10, 11],  // left_knee → leftfoot
            [12, 13],  // right_hip → right_knee
            [13, 14]   // right_knee → rightfoot
        ]

        var verts: [Float] = []
        for pair in pairs {
            for idx in pair {
                let i = idx * 3
                // position(3) + normal(3) + color(3) = 9 floats per vertex
                verts.append(positions[i]); verts.append(positions[i+1]); verts.append(positions[i+2])
                verts.append(0); verts.append(0); verts.append(1)  // normal
                verts.append(0.9); verts.append(0.8); verts.append(0.6)  // color: light tan
            }
        }

        guard let vertexBuffer = device.makeBuffer(bytes: verts, length: verts.count * MemoryLayout<Float>.size, options: .storageModeShared) else { return }

        encoder.setVertexBuffer(vertexBuffer, offset: 0, index: 0)
        encoder.drawPrimitives(type: .line, vertexStart: 0, vertexCount: pairs.count * 2)
    }

    // MARK: - Shaders

    func makeHumanLibrary() -> MTLLibrary {
        let src = """
        #include <metal_stdlib>
        using namespace metal;

        struct VertexIn {
            float3 position [[attribute(0)]];
            float3 normal [[attribute(1)]];
            float3 color [[attribute(2)]];
        };

        struct VertexOut {
            float4 position [[position]];
            float3 color;
        };

        vertex VertexOut humanVertex(
            VertexIn in [[stage_in]],
            constant float4x4& mvp [[buffer(1)]]
        ) {
            VertexOut out;
            out.position = mvp * float4(in.position, 1.0);
            out.color = in.color;
            return out;
        }

        fragment float4 humanFragment(VertexOut in [[stage_in]]) {
            return float4(in.color, 1.0);
        }
        """

        do {
            return try device.makeLibrary(source: src, options: nil)
        } catch {
            fatalError("Failed to create human shader library: \(error)")
        }
    }
}
