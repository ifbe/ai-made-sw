import SwiftUI
import MetalKit
import simd

// MARK: - Shared Uniforms

// LineUniforms moved to debugelement.swift

// MARK: - Pipeline Creator Protocol
/*
protocol PipelineCreator: AnyObject {
    func setupPipelines(in controller: MetalViewController)
}
*/
// MARK: - MetalViewController

class MetalViewController: NSObject, MTKViewDelegate {

    // ── Metal Objects ────────────────────────────────────────────────
    var device: MTLDevice!
    var commandQueue: MTLCommandQueue!
    var depthStencilState: MTLDepthStencilState!

    var pipelineStateLine: MTLRenderPipelineState!
    var pipelineStateArrow: MTLRenderPipelineState!
    var pipelineStateBoat: MTLRenderPipelineState!
    var pipelineStateWaterSurface: MTLRenderPipelineState!
    var pipelineStateWaterBody: MTLRenderPipelineState!
    var pipelineStateHuman: MTLRenderPipelineState!
/*
    // ── Pipeline Creators (set by extension files) ───────────────
    var debugPipelineCreator: PipelineCreator?
    var waterPipelineCreator: PipelineCreator?
    var otherPipelineCreator: PipelineCreator?
*/
    // ── Dependencies ─────────────────────────────────────────────────
    var sensorManager: SensorManager

    // ── Screen / Box Dimensions ─────────────────────────────────────
    var hw: Float = 0
    var hh: Float = 0
    var boxD: Float = 0

    // ── Sensor State ────────────────────────────────────────────────
    var qX: Float = 0
    var qY: Float = 0
    var qZ: Float = 0
    var qW: Float = 1

    var gX: Float = 0
    var gY: Float = 0
    var gZ: Float = -1

    // ── Cached World Axes ──────────────────────────────────────────
    var wxX: Float = 1, wxY: Float = 0, wxZ: Float = 0
    var wyX: Float = 0, wyY: Float = 1, wyZ: Float = 0
    var wzX: Float = 0, wzY: Float = 0, wzZ: Float = 1

    // ── Shared State ───────────────────────────────────────────────
    var boxMath: BoxMath!
    var screenQuadVertexBuffer: MTLBuffer!
    internal(set) var boatVertices: [Float] = Array(repeating: 0, count: 24)

    // ─────────────────────────────────────────────────────────────────
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

        let screenScale = UIScreen.main.scale
        let screenBounds = UIScreen.main.bounds
        hw = Float(screenBounds.width * screenScale)
        hh = Float(screenBounds.height * screenScale)
        boxD = min(hw, hh) / 2

        boxMath = BoxMath(hw: hw, hh: hh, d: boxD)

        setupPipelines()
        setupScreenQuad()

        let depthDescriptor = MTLDepthStencilDescriptor()
        depthDescriptor.depthCompareFunction = .less
        depthDescriptor.isDepthWriteEnabled = true
        self.depthStencilState = device.makeDepthStencilState(descriptor: depthDescriptor)
    }

    func setupPipelines() {
        /*
        debugPipelineCreator?.setupPipelines(in: self)
        waterPipelineCreator?.setupPipelines(in: self)
        otherPipelineCreator?.setupPipelines(in: self)
        */
        setupDebugPipelines()
        setupWaterPipelines()
        setupOtherPipelines()
        setupHumanPipelines()
    }

    func makePipelineState(
        library: MTLLibrary,
        vertexFunction: String,
        fragmentFunction: String,
        vertexDescriptor: MTLVertexDescriptor? = nil,
        enableBlending: Bool = false
    ) -> MTLRenderPipelineState {
        print("🔧 Creating pipeline: \(vertexFunction) / \(fragmentFunction)")
        
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

    // MARK: - draw(in:)

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

        let worldAxisX = sensorManager.data.worldAxisX
        let worldAxisY = sensorManager.data.worldAxisY
        let worldAxisZ = sensorManager.data.worldAxisZ
        wxX = worldAxisX[0]; wxY = worldAxisX[1]; wxZ = worldAxisX[2]
        wyX = worldAxisY[0]; wyY = worldAxisY[1]; wyZ = worldAxisY[2]
        wzX = worldAxisZ[0]; wzY = worldAxisZ[1]; wzZ = worldAxisZ[2]

        drawDebugElement(encoder: encoder, mvp: &mvp, gLen3: gLen3)
        drawWaterElement(encoder: encoder, mvp: &mvp, gLen3: gLen3)
        drawHumanElement(encoder: encoder, mvp: &mvp, gLen3: gLen3)
        drawOtherElement(encoder: encoder, mvp: &mvp, gLen3: gLen3)

        encoder.endEncoding()
        commandBuffer.present(drawable)
        commandBuffer.commit()
    }

    // MARK: - Element Dispatch Methods
    // (implemented in extension files: debugelement.swift, waterelement.swift, otherelement.swift)
}

// MARK: - MetalView

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
    }
}
