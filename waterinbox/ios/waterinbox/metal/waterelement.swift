import Foundation
import Metal
import simd

// MARK: - Water Uniforms

struct WaterUniforms {
    var mvpMatrix: simd_float4x4
    var normal: simd_float3
    var alpha: Float
}

// MARK: - Water Element

extension MetalViewController {

    // MARK: - Pipeline Setup

    func setupWaterPipelines() {
        let library = makeWaterLibrary()
        let vd = makeBoatVertexDescriptor()

        pipelineStateBoat = makePipelineState(
            library: library,
            vertexFunction: "boatVertex",
            fragmentFunction: "boatFragment",
            vertexDescriptor: vd
        )

        pipelineStateWaterSurface = makePipelineState(
            library: library,
            vertexFunction: "waterSurfaceVertex",
            fragmentFunction: "waterSurfaceFragment"
        )

        pipelineStateWaterBody = makePipelineState(
            library: library,
            vertexFunction: "waterBodyVertex",
            fragmentFunction: "waterBodyFragment",
            enableBlending: true
        )
    }

    func makeBoatVertexDescriptor() -> MTLVertexDescriptor {
        let vd = MTLVertexDescriptor()
        vd.attributes[0].format = .float4
        vd.attributes[0].offset = 0
        vd.attributes[0].bufferIndex = 0
        vd.attributes[1].format = .float4
        vd.attributes[1].offset = MemoryLayout<Float>.size * 4
        vd.attributes[1].bufferIndex = 0
        vd.layouts[0].stride = MemoryLayout<Float>.size * 8
        vd.layouts[0].stepFunction = .perVertex
        return vd
    }

    func drawWaterElement(encoder: MTLRenderCommandEncoder, mvp: inout simd_float4x4, gLen3: Float) {
        // Boat
        if RenderState.shared.drawBoat && gLen3 >= 0.001 {
            drawBoat(encoder: encoder, mvp: &mvp)
        }

        // Water surface polygon
        if RenderState.shared.drawWaterSurface && gLen3 >= 0.001 {
            let result = sensorManager.data.waterPoly
            if result.count >= 3 {
                drawWaterSurface(encoder: encoder, polygon: result, mvp: &mvp)
            }
        }

        // Water body (semi-transparent underwater volume)
        if RenderState.shared.drawWaterBody && gLen3 >= 0.001 {
            let nx = gX / gLen3
            let ny = gY / gLen3
            let nz = gZ / gLen3

            var uniforms = WaterUniforms(
                mvpMatrix: mvp,
                normal: simd_float3(nx, ny, nz),
                alpha: 0.95
            )

            encoder.setRenderPipelineState(pipelineStateWaterBody)
            encoder.setVertexBuffer(screenQuadVertexBuffer, offset: 0, index: 0)
            encoder.setVertexBytes(&uniforms, length: MemoryLayout<WaterUniforms>.stride, index: 1)
            encoder.setFragmentBytes(&uniforms, length: MemoryLayout<WaterUniforms>.stride, index: 1)
            encoder.drawPrimitives(type: .triangleStrip, vertexStart: 0, vertexCount: 4)
        }
    }

    // MARK: - Water Draw Calls

    func getBoatVertices() -> [Float] {
        return boatVertices
    }

    func drawBoat(encoder: MTLRenderCommandEncoder, mvp: inout simd_float4x4) {
        let fx = wyX; let fy = wyY; let fz = wyZ
        let rx = wxX; let ry = wxY; let rz = wxZ
        let ux = wzX; let uy = wzY; let uz = wzZ

        let halfLen = boxD * 0.12
        let halfWid = boxD * 0.08
        let raftH = boxD / 12.0

        // bottom 4 corners
        let bFRx =  rx*halfWid + fx*halfLen; let bFRy =  ry*halfWid + fy*halfLen; let bFRz =  rz*halfWid + fz*halfLen
        let bFLx = -rx*halfWid + fx*halfLen; let bFLy = -ry*halfWid + fy*halfLen; let bFLz = -rz*halfWid + fz*halfLen
        let bBLx = -rx*halfWid - fx*halfLen; let bBLy = -ry*halfWid - fy*halfLen; let bBLz = -rz*halfWid - fz*halfLen
        let bBRx =  rx*halfWid - fx*halfLen; let bBRy =  ry*halfWid - fy*halfLen; let bBRz =  rz*halfWid - fz*halfLen

        // top 4 corners
        let tFRx = bFRx + ux*raftH; let tFRy = bFRy + uy*raftH; let tFRz = bFRz + uz*raftH
        let tFLx = bFLx + ux*raftH; let tFLy = bFLy + uy*raftH; let tFLz = bFLz + uz*raftH
        let tBLx = bBLx + ux*raftH; let tBLy = bBLy + uy*raftH; let tBLz = bBLz + uz*raftH
        let tBRx = bBRx + ux*raftH; let tBRy = bBRy + uy*raftH; let tBRz = bBRz + uz*raftH

        boatVertices = [
            bFRx, bFRy, bFRz,  bFLx, bFLy, bFLz,  bBLx, bBLy, bBLz,  bBRx, bBRy, bBRz,
            tFRx, tFRy, tFRz,  tFLx, tFLy, tFLz,  tBLx, tBLy, tBLz,  tBRx, tBRy, tBRz
        ]
        SensorManager.shared.latestBoatVertices = boatVertices

        let rR: Float = 0.75, rG: Float = 0.50, rB: Float = 0.25   // sides (brown)
        let botR: Float = 1.0, botG: Float = 0.0, botB: Float = 1.0 // bottom (magenta)

        let bottomVerts: [Float] = [
            bBRx,bBRy,bBRz,1, botR,botG,botB,1,  bFRx,bFRy,bFRz,1, botR,botG,botB,1,  bFLx,bFLy,bFLz,1, botR,botG,botB,1,
            bBRx,bBRy,bBRz,1, botR,botG,botB,1,  bFLx,bFLy,bFLz,1, botR,botG,botB,1,  bBLx,bBLy,bBLz,1, botR,botG,botB,1
        ]

        let sideVerts: [Float] = [
            bFRx,bFRy,bFRz,1, rR,rG,rB,1,  bFLx,bFLy,bFLz,1, rR,rG,rB,1,  tFLx,tFLy,tFLz,1, rR,rG,rB,1,
            bFRx,bFRy,bFRz,1, rR,rG,rB,1,  tFLx,tFLy,tFLz,1, rR,rG,rB,1,  tFRx,tFRy,tFRz,1, rR,rG,rB,1,
            bBRx,bBRy,bBRz,1, rR,rG,rB,1,  bBLx,bBLy,bBLz,1, rR,rG,rB,1,  tBLx,tBLy,tBLz,1, rR,rG,rB,1,
            bBRx,bBRy,bBRz,1, rR,rG,rB,1,  tBLx,tBLy,tBLz,1, rR,rG,rB,1,  tBRx,tBRy,tBRz,1, rR,rG,rB,1,
            bFLx,bFLy,bFLz,1, rR,rG,rB,1,  bBLx,bBLy,bBLz,1, rR,rG,rB,1,  tBLx,tBLy,tBLz,1, rR,rG,rB,1,
            bFLx,bFLy,bFLz,1, rR,rG,rB,1,  tBLx,tBLy,tFLz,1, rR,rG,rB,1,  tFLx,tFLy,tFLz,1, rR,rG,rB,1,
            bBRx,bBRy,bBRz,1, rR,rG,rB,1,  bFRx,bFRy,bFRz,1, rR,rG,rB,1,  tFRx,tFRy,tFRz,1, rR,rG,rB,1,
            bBRx,bBRy,bBRz,1, rR,rG,rB,1,  tFRx,tFRy,tFRz,1, rR,rG,rB,1,  tBRx,tBRy,tBRz,1, rR,rG,rB,1
        ]

        encoder.setRenderPipelineState(pipelineStateBoat)

        var buf = device.makeBuffer(bytes: bottomVerts, length: bottomVerts.count * MemoryLayout<Float>.stride, options: .storageModeShared)!
        encoder.setVertexBuffer(buf, offset: 0, index: 0)
        encoder.setVertexBytes(&mvp, length: MemoryLayout<simd_float4x4>.size, index: 1)
        encoder.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: 6)

        buf = device.makeBuffer(bytes: sideVerts, length: sideVerts.count * MemoryLayout<Float>.stride, options: .storageModeShared)!
        encoder.setVertexBuffer(buf, offset: 0, index: 0)
        encoder.setVertexBytes(&mvp, length: MemoryLayout<simd_float4x4>.size, index: 1)
        encoder.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: 24)
    }

    func drawWaterSurface(encoder: MTLRenderCommandEncoder, polygon: [[Float]], mvp: inout simd_float4x4) {
        guard polygon.count >= 3 else { return }
        let gLen = sqrt(gX * gX + gY * gY + gZ * gZ)
        guard gLen >= 1e-5 else { return }
        let nx = gX / gLen; let ny = gY / gLen; let nz = gZ / gLen

        let refX: Float = abs(ny) < 0.9 ? 0 : 1
        let refY: Float = abs(ny) < 0.9 ? 1 : 0
        let refZ: Float = 0

        var ux = refY * nz - refZ * ny
        var uy = refZ * nx - refX * nz
        var uz = refX * ny - refY * nx
        let uLen = sqrt(ux * ux + uy * uy + uz * uz)
        ux /= uLen; uy /= uLen; uz /= uLen

        let vx = ny * uz - nz * uy
        let vy = nz * ux - nx * uz
        let vz = nx * uy - ny * ux

        struct ProjPoint { let x, y, z: Float; let s, t: Float }
        var points: [ProjPoint] = []
        for p in polygon {
            let px = p.count > 0 ? p[0] : 0
            let py = p.count > 1 ? p[1] : 0
            let pz = p.count > 2 ? p[2] : 0
            points.append(ProjPoint(x: px, y: py, z: pz, s: px*ux + py*uy + pz*uz, t: px*vx + py*vy + pz*vz))
        }

        let cs = points.reduce(0.0) { $0 + $1.s } / Float(points.count)
        let ct = points.reduce(0.0) { $0 + $1.t } / Float(points.count)
        let sorted = points.sorted { atan2($0.t - ct, $0.s - cs) < atan2($1.t - ct, $1.s - cs) }

        let cx = points.reduce(0.0) { $0 + $1.x } / Float(points.count)
        let cy = points.reduce(0.0) { $0 + $1.y } / Float(points.count)
        let cz = points.reduce(0.0) { $0 + $1.z } / Float(points.count)

        var vertices: [Float] = []
        let n = sorted.count
        for i in 0..<n {
            let p = sorted[i]; let next = sorted[(i + 1) % n]
            vertices.append(contentsOf: [cx, cy, cz, 1.0])
            vertices.append(contentsOf: [p.x, p.y, p.z, 1.0])
            vertices.append(contentsOf: [next.x, next.y, next.z, 1.0])
        }

        guard let vertexBuffer = device.makeBuffer(bytes: vertices, length: vertices.count * MemoryLayout<Float>.size, options: .storageModeShared) else { return }

        var uniforms = WaterUniforms(mvpMatrix: mvp, normal: simd_float3(0, 0, 1), alpha: 0.99)
        encoder.setRenderPipelineState(pipelineStateWaterSurface)
        encoder.setVertexBuffer(vertexBuffer, offset: 0, index: 0)
        encoder.setVertexBytes(&uniforms, length: MemoryLayout<WaterUniforms>.stride, index: 1)
        encoder.setFragmentBytes(&uniforms, length: MemoryLayout<WaterUniforms>.stride, index: 1)
        encoder.setDepthBias(4.0, slopeScale: 4.0, clamp: 0.0)
        encoder.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: n * 3)
        encoder.setDepthBias(0.0, slopeScale: 0.0, clamp: 0.0)
    }

    // MARK: - Shaders

    func makeWaterLibrary() -> MTLLibrary {
        let src = """
        #include <metal_stdlib>
        using namespace metal;

        struct WaterUniforms {
            float4x4 mvp;
            float3 normal;
            float alpha;
        };

        struct boatVertexIn {
            float4 position [[attribute(0)]];
            float4 color [[attribute(1)]];
        };

        struct boatVertexOut {
            float4 position [[position]];
            float3 color;
        };

        vertex boatVertexOut boatVertex(boatVertexIn in [[stage_in]], constant float4x4& mvp [[buffer(1)]]) {
            boatVertexOut out;
            out.position = mvp * float4(in.position.xyz, 1.0);
            out.color = float3(in.color);
            return out;
        }

        fragment float4 boatFragment(boatVertexOut in [[stage_in]]) {
            return float4(in.color, 1.0);
        }

        struct VertexOut {
            float4 position [[position]];
            float3 localPos;
        };

        vertex VertexOut waterSurfaceVertex(uint vertexID [[vertex_id]], constant float4* vertices [[buffer(0)]], constant WaterUniforms& uniforms [[buffer(1)]]) {
            VertexOut out;
            out.position = uniforms.mvp * float4(vertices[vertexID].xyz, 1.0);
            out.localPos = vertices[vertexID].xyz;
            return out;
        }

        fragment float4 waterSurfaceFragment(VertexOut in [[stage_in]], constant WaterUniforms& uniforms [[buffer(1)]]) {
            return float4(0.5, 0.7, 1.0, uniforms.alpha);
        }

        vertex VertexOut waterBodyVertex(uint vertexID [[vertex_id]], constant float4* vertices [[buffer(0)]], constant WaterUniforms& uniforms [[buffer(1)]]) {
            VertexOut out;
            out.position = uniforms.mvp * float4(vertices[vertexID].xyz, 1.0);
            out.localPos = vertices[vertexID].xyz;
            return out;
        }

        fragment float4 waterBodyFragment(VertexOut in [[stage_in]], constant WaterUniforms& uniforms [[buffer(1)]]) {
            float3 n = normalize(uniforms.normal);
            float3 p = in.localPos;
            float np = dot(n, p);
            if (np <= 0.0) discard_fragment();
            float depth = np;
            float factor = pow(0.98, depth / 10.0);
            float maxDepth = 30.0;
            float t = clamp(depth / maxDepth, 0.0, 1.0);
            float r = mix(0.5, 0.12, t) * factor;
            float g = mix(0.7, 0.35, t) * factor;
            float b = mix(1.0, 0.90, t) * factor;
            return float4(r, g, b, uniforms.alpha);
        }
        """

        do {
            return try device.makeLibrary(source: src, options: nil)
        } catch {
            fatalError("Failed to create water shader library: \(error)")
        }
    }
}
