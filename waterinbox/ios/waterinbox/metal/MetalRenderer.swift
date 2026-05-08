import SwiftUI
import MetalKit
import simd

struct WaterUniforms {
    var mvpMatrix: simd_float4x4
    var normal: simd_float3
    var alpha: Float
}

struct LineUniforms {
    var mvpMatrix: simd_float4x4
    var color: simd_float4
}

class MetalViewController: NSObject, MTKViewDelegate {
    var device: MTLDevice!
    var commandQueue: MTLCommandQueue!
    var depthStencilState: MTLDepthStencilState!

    var pipelineStateLine: MTLRenderPipelineState!
    var pipelineStateArrow: MTLRenderPipelineState!
    var pipelineStateBoat: MTLRenderPipelineState!
    var pipelineStateWaterSurface: MTLRenderPipelineState!
    var pipelineStateWaterBody: MTLRenderPipelineState!

    var sensorManager: SensorManager

    var hw: Float = 0
    var hh: Float = 0
    var boxD: Float = 0

    var qX: Float = 0
    var qY: Float = 0
    var qZ: Float = 0
    var qW: Float = 1

    var gX: Float = 0
    var gY: Float = 0
    var gZ: Float = -1

    var drawWorldAxes: Bool = true
    var drawGravityArrow: Bool = true
    var drawMagnetArrow: Bool = true
    var drawBoat: Bool = true
    var drawWaterSurface: Bool = true
    var drawWaterBody: Bool = true

    var boxMath: BoxMath!

    // Boat vertex storage (8 corners × 3 floats = 24)
    private(set) var boatVertices: [Float] = Array(repeating: 0, count: 24)

    // Cached world axes (kept for drawBoat which derives local boat axes from them)
    var wxX: Float = 1, wxY: Float = 0, wxZ: Float = 0
    var wyX: Float = 0, wyY: Float = 1, wyZ: Float = 0
    var wzX: Float = 0, wzY: Float = 0, wzZ: Float = 1

    var screenQuadVertexBuffer: MTLBuffer!

    init(sensorManager: SensorManager, mtkView: MTKView) {
        self.sensorManager = sensorManager
        super.init()
        setupMetal(mtkView: mtkView)
    }

    func setupMetal(mtkView: MTKView) {
        guard let device = MTLCreateSystemDefaultDevice() else {
            fatalError("Metal is not supported on this device")
        }
        self.device = device
        mtkView.device = device
        mtkView.delegate = self
        mtkView.colorPixelFormat = .bgra8Unorm
        mtkView.depthStencilPixelFormat = .depth32Float

        commandQueue = device.makeCommandQueue()!

        // Screen dimensions - use points * scale for actual pixels
        let screenScale = UIScreen.main.scale
        let screenBounds = UIScreen.main.bounds
        hw = Float(screenBounds.width * screenScale)
        hh = Float(screenBounds.height * screenScale)
        boxD = min(hw, hh) / 2

        boxMath = BoxMath(hw: hw, hh: hh, d: boxD)

        setupPipelines()
        setupScreenQuad()

        // 创建深度模板状态：开启深度测试，允许写入
        let depthDescriptor = MTLDepthStencilDescriptor()
        depthDescriptor.depthCompareFunction = .less       // 或 .lessEqual
        depthDescriptor.isDepthWriteEnabled = true
        self.depthStencilState = device.makeDepthStencilState(descriptor: depthDescriptor)
    }

    func makeArrowBoatVertexDescriptor() -> MTLVertexDescriptor {
        let vd = MTLVertexDescriptor()

        // attribute 0：position (float3)
        vd.attributes[0].format = .float4
        vd.attributes[0].offset = 0
        vd.attributes[0].bufferIndex = 0

        // attribute 1：color (float3)
        vd.attributes[1].format = .float4
        vd.attributes[1].offset = MemoryLayout<Float>.size * 4   // 3 个 float 之后
        vd.attributes[1].bufferIndex = 0

        // buffer 0 的步长 = 6 个 float（position.xyz + color.xyz）
        vd.layouts[0].stride = MemoryLayout<Float>.size * 8
        vd.layouts[0].stepFunction = .perVertex

        return vd
    }
    func setupPipelines() {
        let waterLibrary = makeWaterLibrary()
        let arrowBoatVD = makeArrowBoatVertexDescriptor()

        // Line pipeline (position-only, 3 floats/vertex, color as uniform)
        pipelineStateLine = createPipelineState(
            library: waterLibrary,
            vertexFunction: "lineVertex",
            fragmentFunction: "lineFragment"
        )

        pipelineStateArrow = createPipelineState(
            library: waterLibrary,
            vertexFunction: "arrowVertex",
            fragmentFunction: "arrowFragment",
            vertexDescriptor: arrowBoatVD
        )

        pipelineStateBoat = createPipelineState(
            library: waterLibrary,
            vertexFunction: "boatVertex",
            fragmentFunction: "boatFragment",
            vertexDescriptor: arrowBoatVD    // ✅ 传入描述符
        )

        pipelineStateWaterSurface = createPipelineState(
            library: waterLibrary,
            vertexFunction: "waterSurfaceVertex",
            fragmentFunction: "waterSurfaceFragment"
        )

        pipelineStateWaterBody = createPipelineState(
            library: waterLibrary,
            vertexFunction: "waterBodyVertex",
            fragmentFunction: "waterBodyFragment",
            enableBlending: true
        )
    }

    func makeWaterLibrary() -> MTLLibrary {
        let shaderSource = """
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

        fragment float4 lineFragment(float4 in [[stage_in]], constant LineUniforms& uniforms [[buffer(1)]]) {
            return uniforms.color;
        }

        struct ArrowVertexIn {
            float4 position [[attribute(0)]];
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
            out.position = mvp * float4(in.position.xyz, 1.0);
            out.color = in.color;
            return out;
        }

        fragment float4 arrowFragment(ArrowVertexOut in [[stage_in]]) {
            return float4(in.color, 1.0);
        }

        struct BoatVertexIn {
            float4 position [[attribute(0)]];
            float4 color [[attribute(1)]];
        };

        struct BoatVertexOut {
            float4 position [[position]];
            float3 color;
        };

        vertex BoatVertexOut boatVertex(BoatVertexIn in [[stage_in]], constant float4x4& mvp [[buffer(1)]]) {
            BoatVertexOut out;
            out.position = mvp * float4(in.position.xyz, 1.0);
            out.color = float3(in.color);
            return out;
        }

        fragment float4 boatFragment(BoatVertexOut in [[stage_in]]) {
            return float4(in.color, 1.0);
        }

        struct WaterUniforms {
            float4x4 mvp;
            float3 normal;
            float alpha;
        };

        struct VertexOut {
            float4 position [[position]];
            float3 localPos;
        };

        vertex VertexOut waterSurfaceVertex(
            uint vertexID [[vertex_id]],
            constant float4* vertices [[buffer(0)]],
            constant WaterUniforms& uniforms [[buffer(1)]]
        ) {
            VertexOut out;
            out.position = uniforms.mvp * float4(vertices[vertexID].xyz, 1.0);
            out.localPos = vertices[vertexID].xyz;
            return out;
        }

        fragment float4 waterSurfaceFragment(
            VertexOut in [[stage_in]],
            constant WaterUniforms& uniforms [[buffer(1)]]
        ) {
            return float4(0.5, 0.7, 1.0, uniforms.alpha);
        }

        vertex VertexOut waterBodyVertex(
            uint vertexID [[vertex_id]],
            constant float4* vertices [[buffer(0)]],
            constant WaterUniforms& uniforms [[buffer(1)]]
        ) {
            VertexOut out;
            out.position = uniforms.mvp * float4(vertices[vertexID].xyz, 1.0);
            out.localPos = vertices[vertexID].xyz;
            return out;
        }

        fragment float4 waterBodyFragment(
            VertexOut in [[stage_in]],
            constant WaterUniforms& uniforms [[buffer(1)]]
        ) {
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
            return try device.makeLibrary(source: shaderSource, options: nil)
        } catch {
            fatalError("Failed to create shader library: \(error)")
        }
    }

    func createPipelineState(
        library: MTLLibrary,
        vertexFunction: String,
        fragmentFunction: String,
        vertexDescriptor: MTLVertexDescriptor? = nil,
        enableBlending: Bool = false
    ) -> MTLRenderPipelineState {
        let descriptor = MTLRenderPipelineDescriptor()
        descriptor.vertexFunction = library.makeFunction(name: vertexFunction)
        descriptor.fragmentFunction = library.makeFunction(name: fragmentFunction)
        descriptor.colorAttachments[0].pixelFormat = .bgra8Unorm
        descriptor.depthAttachmentPixelFormat = .depth32Float


        if enableBlending {
            descriptor.colorAttachments[0].isBlendingEnabled = true
            descriptor.colorAttachments[0].sourceRGBBlendFactor = .sourceAlpha
            descriptor.colorAttachments[0].destinationRGBBlendFactor = .oneMinusSourceAlpha
            descriptor.colorAttachments[0].sourceAlphaBlendFactor = .one
            descriptor.colorAttachments[0].destinationAlphaBlendFactor = .oneMinusSourceAlpha
        }

        // 设置顶点描述符（如果有）
        if let vd = vertexDescriptor {
            descriptor.vertexDescriptor = vd
        }

        do {
            return try device.makeRenderPipelineState(descriptor: descriptor)
        } catch {
            fatalError("Failed to create pipeline state: \(error)")
        }
    }

    func setupScreenQuad() {
        let screenZ = boxD / 2 - 0.01
        let vertices: [Float] = [
            -hw, -hh, screenZ, 1,
             hw, -hh, screenZ, 1,
            -hw,  hh, screenZ, 1,
             hw,  hh, screenZ, 1
        ]

        screenQuadVertexBuffer = device.makeBuffer(
            bytes: vertices,
            length: vertices.count * MemoryLayout<Float>.size,
            options: .storageModeShared
        )
    }

    func computeMVP() -> simd_float4x4 {
        var V = matrix_identity_float4x4
        V[2][2] = -1

        var P = matrix_identity_float4x4
        P[0][0] = 2.0 / hw
        P[1][1] = 2.0 / hh
        P[2][2] = 1.0 / boxD / 2
        P[3][2] = 0.5

        return P * V
    }

    func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {
    }

    func draw(in view: MTKView) {
        let data = sensorManager.data
        gX = data.gravity[0]
        gY = data.gravity[1]
        gZ = data.gravity[2]

        qX = data.quatFixed[0]
        qY = data.quatFixed[1]
        qZ = data.quatFixed[2]
        qW = data.quatFixed[3]

        guard let drawable = view.currentDrawable,
              let renderPassDescriptor = view.currentRenderPassDescriptor else {
            return
        }

        var commandBuffer = commandQueue.makeCommandBuffer()!

        renderPassDescriptor.colorAttachments[0].loadAction = .clear
        renderPassDescriptor.colorAttachments[0].clearColor = MTLClearColor(red: 0.03, green: 0.03, blue: 0.07, alpha: 1.0)

        var mvp = computeMVP()
        let gLen3 = sqrt(gX * gX + gY * gY + gZ * gZ)

        let encoder = commandBuffer.makeRenderCommandEncoder(descriptor: renderPassDescriptor)!
        encoder.setDepthStencilState(self.depthStencilState)

        // Sync render state from RenderState (written by UISpace toggles)
        drawWorldAxes = RenderState.shared.drawWorldAxes
        drawGravityArrow = RenderState.shared.drawGravityArrow
        drawMagnetArrow = RenderState.shared.drawMagnetArrow
        drawBoat = RenderState.shared.drawBoat
        drawWaterSurface = RenderState.shared.drawWaterSurface
        drawWaterBody = RenderState.shared.drawWaterBody

        let worldAxisX = sensorManager.data.worldAxisX
        let worldAxisY = sensorManager.data.worldAxisY
        let worldAxisZ = sensorManager.data.worldAxisZ
        wxX = worldAxisX[0]; wxY = worldAxisX[1]; wxZ = worldAxisX[2]
        wyX = worldAxisY[0]; wyY = worldAxisY[1]; wyZ = worldAxisY[2]
        wzX = worldAxisZ[0]; wzY = worldAxisZ[1]; wzZ = worldAxisZ[2]

        if drawWorldAxes {
            let axisLen: Float = 1000
            drawDebugLine(encoder: encoder, x1: 0, y1: 0, z1: 0, x2: wxX*axisLen, y2: wxY*axisLen, z2: wxZ*axisLen, r: 1, g: 0.05, b: 0.05, mvp: &mvp)
            drawDebugLine(encoder: encoder, x1: 0, y1: 0, z1: 0, x2: wyX*axisLen, y2: wyY*axisLen, z2: wyZ*axisLen, r: 0.05, g: 1, b: 0.05, mvp: &mvp)
            drawDebugLine(encoder: encoder, x1: 0, y1: 0, z1: 0, x2: wzX*axisLen, y2: wzY*axisLen, z2: wzZ*axisLen, r: 0.05, g: 0.05, b: 1, mvp: &mvp)
        }

        if drawGravityArrow && gLen3 >= 0.001 {
            let aX = FusionConfig.accelX
            let aY = FusionConfig.accelY
            let aZ = FusionConfig.accelZ
            let gLen1 = sqrt(aX * aX + aY * aY + aZ * aZ)
            if gLen1 >= 0.001 {
                drawArrow(encoder: encoder, dx: aX/gLen1, dy: aY/gLen1, dz: aZ/gLen1, mvp: &mvp, length: boxD * 0.5)
            }
        }

        if drawMagnetArrow {
            let mX = FusionConfig.magX
            let mY = FusionConfig.magY
            let mZ = FusionConfig.magZ
            let mLen = sqrt(mX * mX + mY * mY + mZ * mZ)
            if mLen >= 0.001 {
                drawArrow(encoder: encoder, dx: mX/mLen, dy: mY/mLen, dz: mZ/mLen, mvp: &mvp, length: boxD * 0.3)
            }
        }

        if drawBoat && gLen3 >= 0.001 {
            drawBoat(encoder: encoder, mvp: &mvp)
            
            // Sync latest boat vertices to SensorManager for UI display
            let bv = getBoatVertices()
            SensorManager.shared.latestBoatVertices = bv

        }

        if drawWaterSurface && gLen3 >= 0.001 {
            //let result = boxMath.solveWaterPlane(gravity: [gX, gY, gZ])
            let result = sensorManager.data.waterPoly
            if result.count >= 3 {
                drawWaterSurface(encoder: encoder, polygon: result, mvp: &mvp)
            }
        }

        if drawWaterBody && gLen3 >= 0.001 {
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

        encoder.endEncoding()
        commandBuffer.present(drawable)
        commandBuffer.commit()
    }

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

    func drawArrow(encoder: MTLRenderCommandEncoder, dx: Float, dy: Float, dz: Float, mvp: inout simd_float4x4, length: Float) {
        let arrowVerts: [Float] = [
            0, 0, 0, 1,
            dx * length, dy * length, dz * length, 1
        ]

        var vertexBuffer = device.makeBuffer(
            bytes: arrowVerts,
            length: arrowVerts.count * MemoryLayout<Float>.size,
            options: .storageModeShared
        )

        encoder.setRenderPipelineState(pipelineStateArrow)
        encoder.setVertexBuffer(vertexBuffer, offset: 0, index: 0)
        encoder.setVertexBytes(&mvp, length: MemoryLayout<simd_float4x4>.stride, index: 1)
        encoder.drawPrimitives(type: .line, vertexStart: 0, vertexCount: 2)
    }

    func getBoatVertices() -> [Float] {
        return boatVertices
    }
    func drawBoat(encoder: MTLRenderCommandEncoder, mvp: inout simd_float4x4) {
        let fx = wyX; let fy = wyY; let fz = wyZ  // forward = world Y in body space
        let rx = wxX; let ry = wxY; let rz = wxZ  // right = world X in body space
        let ux = wzX; let uy = wzY; let uz = wzZ  // up = world Z in body space

        let halfLen = boxD * 0.12
        let halfWid = boxD * 0.08
        let raftH = boxD / 12.0

        // bottom 4 corners (at water surface)
        let bFRx =  rx*halfWid + fx*halfLen; let bFRy =  ry*halfWid + fy*halfLen; let bFRz =  rz*halfWid + fz*halfLen
        let bFLx = -rx*halfWid + fx*halfLen; let bFLy = -ry*halfWid + fy*halfLen; let bFLz = -rz*halfWid + fz*halfLen
        let bBLx = -rx*halfWid - fx*halfLen; let bBLy = -ry*halfWid - fy*halfLen; let bBLz = -rz*halfWid - fz*halfLen
        let bBRx =  rx*halfWid - fx*halfLen; let bBRy =  ry*halfWid - fy*halfLen; let bBRz =  rz*halfWid - fz*halfLen

        // top 4 corners = bottom + up * raftH
        let tFRx = bFRx + ux*raftH; let tFRy = bFRy + uy*raftH; let tFRz = bFRz + uz*raftH
        let tFLx = bFLx + ux*raftH; let tFLy = bFLy + uy*raftH; let tFLz = bFLz + uz*raftH
        let tBLx = bBLx + ux*raftH; let tBLy = bBLy + uy*raftH; let tBLz = bBLz + uz*raftH
        let tBRx = bBRx + ux*raftH; let tBRy = bBRy + uy*raftH; let tBRz = bBRz + uz*raftH

        // Store 8 corners [x,y,z]×8
        boatVertices = [
            bFRx, bFRy, bFRz,  bFLx, bFLy, bFLz,  bBLx, bBLy, bBLz,  bBRx, bBRy, bBRz,
            tFRx, tFRy, tFRz,  tFLx, tFLy, tFLz,  tBLx, tBLy, tBLz,  tBRx, tBRy, tBRz
        ]

        // Sync to SensorManager for UI display
        SensorManager.shared.latestBoatVertices = boatVertices

        let rR: Float = 0.75, rG: Float = 0.50, rB: Float = 0.25  // sides (brown)
        let botR: Float = 1.0, botG: Float = 0.0, botB: Float = 1.0  // bottom (magenta)

        // Bottom face (2 triangles, magenta)
        let bottomVerts: [Float] = [
            bBRx,bBRy,bBRz,1, botR,botG,botB,1,  bFRx,bFRy,bFRz,1, botR,botG,botB,1,  bFLx,bFLy,bFLz,1, botR,botG,botB,1,
            bBRx,bBRy,bBRz,1, botR,botG,botB,1,  bFLx,bFLy,bFLz,1, botR,botG,botB,1,  bBLx,bBLy,bBLz,1, botR,botG,botB,1
        ]

        // 4 side faces (brown) - each face = 2 triangles
        let sideVerts: [Float] = [
            // front (bFR, bFL, tFL, tFR)
            bFRx,bFRy,bFRz,1, rR,rG,rB,1,  bFLx,bFLy,bFLz,1, rR,rG,rB,1,  tFLx,tFLy,tFLz,1, rR,rG,rB,1,
            bFRx,bFRy,bFRz,1, rR,rG,rB,1,  tFLx,tFLy,tFLz,1, rR,rG,rB,1,  tFRx,tFRy,tFRz,1, rR,rG,rB,1,
            // back (bBR, bBL, tBL, tBR)
            bBRx,bBRy,bBRz,1, rR,rG,rB,1,  bBLx,bBLy,bBLz,1, rR,rG,rB,1,  tBLx,tBLy,tBLz,1, rR,rG,rB,1,
            bBRx,bBRy,bBRz,1, rR,rG,rB,1,  tBLx,tBLy,tBLz,1, rR,rG,rB,1,  tBRx,tBRy,tBRz,1, rR,rG,rB,1,
            // left (bFL, bBL, tBL, tFL)
            bFLx,bFLy,bFLz,1, rR,rG,rB,1,  bBLx,bBLy,bBLz,1, rR,rG,rB,1,  tBLx,tBLy,tBLz,1, rR,rG,rB,1,
            bFLx,bFLy,bFLz,1, rR,rG,rB,1,  tBLx,tBLy,tBLz,1, rR,rG,rB,1,  tFLx,tFLy,tFLz,1, rR,rG,rB,1,
            // right (bBR, bFR, tFR, tBR)
            bBRx,bBRy,bBRz,1, rR,rG,rB,1,  bFRx,bFRy,bFRz,1, rR,rG,rB,1,  tFRx,tFRy,tFRz,1, rR,rG,rB,1,
            bBRx,bBRy,bBRz,1, rR,rG,rB,1,  tFRx,tFRy,tFRz,1, rR,rG,rB,1,  tBRx,tBRy,tBRz,1, rR,rG,rB,1
        ]

        encoder.setRenderPipelineState(pipelineStateBoat)

        // Bottom
        var buf = device.makeBuffer(bytes: bottomVerts, length: bottomVerts.count * MemoryLayout<Float>.stride, options: .storageModeShared)!
        encoder.setVertexBuffer(buf, offset: 0, index: 0)
        encoder.setVertexBytes(&mvp, length: MemoryLayout<simd_float4x4>.size, index: 1)
        encoder.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: 6)

        // Sides
        buf = device.makeBuffer(bytes: sideVerts, length: sideVerts.count * MemoryLayout<Float>.stride, options: .storageModeShared)!
        encoder.setVertexBuffer(buf, offset: 0, index: 0)
        encoder.setVertexBytes(&mvp, length: MemoryLayout<simd_float4x4>.size, index: 1)
        encoder.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: 24)
    }

    func drawWaterSurface(encoder: MTLRenderCommandEncoder, polygon: [[Float]], mvp: inout simd_float4x4) {
        guard polygon.count >= 3 else { return }

        // 1. 水面法线：取重力方向
        let gLen = sqrt(gX * gX + gY * gY + gZ * gZ)
        guard gLen >= 1e-5 else { return }
        let nx = gX / gLen
        let ny = gY / gLen
        let nz = gZ / gLen

        // 2. 构建水面平面上的两个基向量 u、v
        let refX: Float = abs(ny) < 0.9 ? 0 : 1
        let refY: Float = abs(ny) < 0.9 ? 1 : 0
        let refZ: Float = 0

        // u = normalize(ref × n)
        var ux = refY * nz - refZ * ny
        var uy = refZ * nx - refX * nz
        var uz = refX * ny - refY * nx
        let uLen = sqrt(ux * ux + uy * uy + uz * uz)
        ux /= uLen; uy /= uLen; uz /= uLen

        // v = n × u
        let vx = ny * uz - nz * uy
        let vy = nz * ux - nx * uz
        let vz = nx * uy - ny * ux

        // 3. 将多边形顶点投影到 (u,v) 平面上得到 2D 坐标 (s, t)
        struct ProjPoint {
            let x, y, z: Float
            let s, t: Float       // 2D 坐标
        }
        var points: [ProjPoint] = []
        for p in polygon {
            let px = p.count > 0 ? p[0] : 0
            let py = p.count > 1 ? p[1] : 0
            let pz = p.count > 2 ? p[2] : 0
            let s = px * ux + py * uy + pz * uz
            let t = px * vx + py * vy + pz * vz
            points.append(ProjPoint(x: px, y: py, z: pz, s: s, t: t))
        }

        // 4. 计算 2D 中心
        let cs = points.reduce(0.0) { $0 + $1.s } / Float(points.count)
        let ct = points.reduce(0.0) { $0 + $1.t } / Float(points.count)

        // 5. 按角度逆时针排序（Android 用负 atan2 实现顺时针，实际相同）
        let sorted = points.sorted {
            atan2($0.t - ct, $0.s - cs) < atan2($1.t - ct, $1.s - cs)
        }

        // 6. 计算 3D 中心点
        let cx = points.reduce(0.0) { $0 + $1.x } / Float(points.count)
        let cy = points.reduce(0.0) { $0 + $1.y } / Float(points.count)
        let cz = points.reduce(0.0) { $0 + $1.z } / Float(points.count)

        // 7. 生成扇形三角形顶点（位置 float4，w=1）
        var vertices: [Float] = []
        let n = sorted.count
        for i in 0..<n {
            let p = sorted[i]
            let next = sorted[(i + 1) % n]

            // 三角形：中心、当前点、下一点
            vertices.append(contentsOf: [cx, cy, cz, 1.0])
            vertices.append(contentsOf: [p.x, p.y, p.z, 1.0])
            vertices.append(contentsOf: [next.x, next.y, next.z, 1.0])
        }

        // 8. 上传顶点
        guard let vertexBuffer = device.makeBuffer(
            bytes: vertices,
            length: vertices.count * MemoryLayout<Float>.size,
            options: .storageModeShared
        ) else { return }

        var uniforms = WaterUniforms(mvpMatrix: mvp, normal: simd_float3(0, 0, 1), alpha: 0.99)

        encoder.setRenderPipelineState(pipelineStateWaterSurface)
        encoder.setVertexBuffer(vertexBuffer, offset: 0, index: 0)
        encoder.setVertexBytes(&uniforms, length: MemoryLayout<WaterUniforms>.stride, index: 1)
        encoder.setFragmentBytes(&uniforms, length: MemoryLayout<WaterUniforms>.stride, index: 1)

        // 9. 开启深度偏移（对应 Android 的 GL_POLYGON_OFFSET_FILL）
        encoder.setDepthBias(4.0, slopeScale: 4.0, clamp: 0.0)

        // 绘制 n 个三角形（3 * n 个顶点）
        encoder.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: n * 3)

        // 清除深度偏移（可选，因为下一帧 encoder 是新的，但良好的习惯）
        encoder.setDepthBias(0.0, slopeScale: 0.0, clamp: 0.0)
    }

}

struct MetalView: UIViewRepresentable {
    let sensorManager: SensorManager

    func makeUIView(context: Context) -> MTKView {
        let mtkView = MTKView()
        mtkView.preferredFramesPerSecond = 60
        mtkView.enableSetNeedsDisplay = false
        mtkView.isPaused = false

        let metalViewController = MetalViewController(sensorManager: sensorManager, mtkView: mtkView)
        context.coordinator.metalViewController = metalViewController

        return mtkView
    }

    func updateUIView(_ uiView: MTKView, context: Context) {
    }

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    class Coordinator {
        var metalViewController: MetalViewController?
    }

    static func dismantleCoordinator(coordinator: Coordinator) {
        // no-op
    }
}
