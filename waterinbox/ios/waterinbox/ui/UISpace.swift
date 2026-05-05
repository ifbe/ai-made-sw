import SwiftUI

struct UISpace: View {
    @ObservedObject var sensorManager: SensorManager
    @ObservedObject var socketManager: SocketManager

    @State private var leftExpanded = false
    @State private var topRightExpanded = false
    @State private var bottomLeftExpanded = false
    @State private var bottomRightExpanded = false

    private let monoFont = Font.system(size: 10, design: .monospaced)
    private let smallMonoFont = Font.system(size: 9, design: .monospaced)
    private let tinyMonoFont = Font.system(size: 8, design: .monospaced)
    private let labelColor = Color(hex: "90CAF9")

    var body: some View {
        GeometryReader { geometry in
            ZStack {
                // TOP-LEFT: toggle button
                Button(action: { leftExpanded.toggle() }) {
                    Circle()
                        .fill(leftExpanded ? Color.green.opacity(0.85) : Color.black.opacity(0.6))
                        .frame(width: 28, height: 28)
                        .overlay(
                            Text("▼")
                                .foregroundColor(.white)
                                .font(.system(size: 10))
                        )
                }
                .position(x: 26, y: 64)
                .buttonStyle(PlainButtonStyle())

                // TOP-LEFT: sensor data panel
                if leftExpanded {
                    SensorDataPanel(data: sensorManager.data)
                        .position(x: 100, y: 200)
                }

                // TOP-RIGHT: toggle button
                Button(action: { topRightExpanded.toggle() }) {
                    Circle()
                        .fill(topRightExpanded ? Color.blue.opacity(0.85) : Color.black.opacity(0.6))
                        .frame(width: 28, height: 28)
                        .overlay(
                            Text("▼")
                                .foregroundColor(.white)
                                .font(.system(size: 10))
                        )
                }
                .position(x: geometry.size.width - 26, y: 64)
                .buttonStyle(PlainButtonStyle())

                // TOP-RIGHT: render toggles panel
                if topRightExpanded {
                    RenderTogglesPanel(metalViewController: nil)
                        .position(x: geometry.size.width - 64, y: 200)
                }

                // BOTTOM-LEFT: toggle + buttons row
                HStack(spacing: 8) {
                    Button(action: { bottomLeftExpanded.toggle() }) {
                        Circle()
                            .fill(bottomLeftExpanded ? Color.green.opacity(0.85) : Color.black.opacity(0.6))
                            .frame(width: 28, height: 28)
                            .overlay(
                                Text("▲")
                                    .foregroundColor(.white)
                                    .font(.system(size: 10))
                            )
                    }
                    .buttonStyle(PlainButtonStyle())

                    Button(action: {
                        let next = {
                            switch FusionConfig.algorithm {
                            case "ios": return "mahony3"
                            case "mahony3": return "mahony6"
                            case "mahony6": return "madgwick"
                            case "madgwick": return "ekf"
                            default: return "ios"
                            }
                        }()
                        FusionConfig.algorithm = next
                        FusionState.reset()
                    }) {
                        Text(algoButtonText)
                            .font(monoFont)
                            .foregroundColor(.white)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color.black.opacity(0.7))
                            .cornerRadius(6)
                    }
                    .buttonStyle(PlainButtonStyle())

                    Button(action: {
                        let next = FusionConfig.yawAlgorithm == "none" ? "mag" : "none"
                        FusionConfig.yawAlgorithm = next
                    }) {
                        Text("YAW:\(FusionConfig.yawAlgorithm)")
                            .font(monoFont)
                            .foregroundColor(FusionConfig.yawAlgorithm == "none" ? .gray : Color(hex: "44FF88"))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color.black.opacity(0.7))
                            .cornerRadius(6)
                    }
                    .buttonStyle(PlainButtonStyle())
                }
                .position(x: 70, y: geometry.size.height - 36)

                // BOTTOM-LEFT: algo params panel
                if bottomLeftExpanded {
                    AlgoParamsPanel(data: sensorManager.data)
                        .position(x: 80, y: geometry.size.height - 140)
                }

                // BOTTOM-RIGHT: connect button + toggle row
                HStack(spacing: 8) {
                    Button(action: {
                        if socketManager.isConnected {
                            socketManager.disconnect()
                        } else {
                            socketManager.connect()
                        }
                    }) {
                        Circle()
                            .fill(socketManager.isConnected ? Color.green.opacity(0.85) : Color.black.opacity(0.6))
                            .frame(width: 50, height: 28)
                            .overlay(
                                Text(socketManager.isConnected ? "已连接" : "连接")
                                    .foregroundColor(.white)
                                    .font(.system(size: 9, design: .monospaced))
                            )
                    }
                    .buttonStyle(PlainButtonStyle())

                    Button(action: { bottomRightExpanded.toggle() }) {
                        Circle()
                            .fill(bottomRightExpanded ? Color.green.opacity(0.85) : Color.black.opacity(0.6))
                            .frame(width: 28, height: 28)
                            .overlay(
                                Text("▲")
                                    .foregroundColor(.white)
                                    .font(.system(size: 10))
                            )
                    }
                    .buttonStyle(PlainButtonStyle())
                }
                .position(x: geometry.size.width - 68, y: geometry.size.height - 36)

                // BOTTOM-RIGHT: socket panel
                if bottomRightExpanded {
                    SocketPanel(socketManager: socketManager)
                        .position(x: geometry.size.width - 80, y: geometry.size.height - 140)
                }
            }
        }
    }

    private var algoButtonText: String {
        switch FusionConfig.algorithm {
        case "ios": return "iOS"
        case "mahony3": return "MH3"
        case "mahony6": return "MH6"
        case "madgwick": return "MDW"
        case "ekf": return "EKF"
        default: return "??"
        }
    }
}

struct SensorDataPanel: View {
    let data: SensorData

    private let tinyMonoFont = Font.system(size: 8, design: .monospaced)
    private let labelColor = Color(hex: "90CAF9")

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            LabeledRow(label: "dt   ", values: [data.dt], fmt: "%.6f")
            DividerRow()
            LabeledRow(label: "Gyro ", values: data.gyro)
            LabeledRow(label: "Accel", values: data.accel)
            LabeledRow(label: "Mag  ", values: data.magnet)
            DividerRow()
            LabeledRow(label: "GyroC", values: data.gyroCorr)
            LabeledRow(label: "AccelC", values: data.accelCorr)
            LabeledRow(label: "MagC ", values: data.magnetCorr)
            DividerRow()
            LabeledRow(label: "qFused", values: data.quatFused)
            LabeledRow(label: "qFixed", values: data.quatFixed)
            DividerRow()
            LabeledRow(label: "Euler", values: data.euler)
            LabeledRow(label: "AxisA", values: data.axisAngle)
            DividerRow()
            LabeledRow(label: "WrdX ", values: data.worldAxisX, fmt: "%.4f", color: Color(hex: "FF4444"))
            LabeledRow(label: "WrdY ", values: data.worldAxisY, fmt: "%.4f", color: Color(hex: "44FF44"))
            LabeledRow(label: "WrdZ ", values: data.worldAxisZ, fmt: "%.4f", color: Color(hex: "4444FF"))
            DividerRow()
            LabeledRow(label: "Grav ", values: data.gravity)
            DividerRow()
            ForEach(0..<min(data.waterPoly.count, 8), id: \.self) { i in
                LabeledRow(label: "P\(i)   ", values: data.waterPoly[i], fmt: "%.2f", color: Color(hex: "80FF80"))
            }
            DividerRow()
            // Boat vertices from MetalRenderer (updated every frame)
            let bv = data.boatVertices
            if bv.count >= 24 {
                LabeledRow(label: "bFL  ", values: Array(bv[3...5]), fmt: "%.2f", color: Color(hex: "FF8800"))
                LabeledRow(label: "bFR  ", values: Array(bv[0...2]), fmt: "%.2f", color: Color(hex: "FF6600"))
                LabeledRow(label: "bBL  ", values: Array(bv[6...8]), fmt: "%.2f", color: Color(hex: "FFAA00"))
                LabeledRow(label: "bBR  ", values: Array(bv[9...11]), fmt: "%.2f", color: Color(hex: "FFCC00"))
                LabeledRow(label: "tFL  ", values: Array(bv[15...17]), fmt: "%.2f", color: Color(hex: "00CCFF"))
                LabeledRow(label: "tFR  ", values: Array(bv[12...14]), fmt: "%.2f", color: Color(hex: "00FFFF"))
                LabeledRow(label: "tBL  ", values: Array(bv[18...20]), fmt: "%.2f", color: Color(hex: "0099FF"))
                LabeledRow(label: "tBR  ", values: Array(bv[21...23]), fmt: "%.2f", color: Color(hex: "0066FF"))
            }
        }
        .padding(8)
        .background(Color.black.opacity(0.7))
        .cornerRadius(8)
    }
}

struct RenderTogglesPanel: View {
    @ObservedObject var renderState = RenderState.shared
    var metalViewController: MetalViewController?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            RenderToggle(label: "坐标轴", isEnabled: $renderState.drawWorldAxes, onSync: { metalViewController?.drawWorldAxes = renderState.drawWorldAxes })
            RenderToggle(label: "重力箭头", isEnabled: $renderState.drawGravityArrow, onSync: { metalViewController?.drawGravityArrow = renderState.drawGravityArrow })
            RenderToggle(label: "磁力箭头", isEnabled: $renderState.drawMagnetArrow, onSync: { metalViewController?.drawMagnetArrow = renderState.drawMagnetArrow })
            RenderToggle(label: "小船", isEnabled: $renderState.drawBoat, onSync: { metalViewController?.drawBoat = renderState.drawBoat })
            RenderToggle(label: "水面", isEnabled: $renderState.drawWaterSurface, onSync: { metalViewController?.drawWaterSurface = renderState.drawWaterSurface })
            RenderToggle(label: "水体", isEnabled: $renderState.drawWaterBody, onSync: { metalViewController?.drawWaterBody = renderState.drawWaterBody })
        }
        .padding(10)
        .frame(width: 110)
        .background(Color.black.opacity(0.7))
        .cornerRadius(8)
    }
}

struct AlgoParamsPanel: View {
    let data: SensorData

    private let smallMonoFont = Font.system(size: 9, design: .monospaced)

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            let algoColor = algoColorForAlgorithm(FusionConfig.algorithm)
            let algoP = data.algoParams

            switch FusionConfig.algorithm {
            case "madgwick":
                HStack {
                    Text("beta ").font(smallMonoFont).foregroundColor(algoColor)
                    Text(String(format: "%.3f", algoP[0])).font(smallMonoFont).foregroundColor(.white)
                }
            case "mahony6":
                HStack {
                    Text("Kp  ").font(smallMonoFont).foregroundColor(algoColor)
                    Text(String(format: "%.2f", algoP[0])).font(smallMonoFont).foregroundColor(.white)
                }
                HStack {
                    Text("Ki  ").font(smallMonoFont).foregroundColor(algoColor)
                    Text(String(format: "%.4f", algoP[1])).font(smallMonoFont).foregroundColor(.white)
                }
            case "ekf":
                Text("TODO: EKF params").font(smallMonoFont).foregroundColor(.white)
            default:
                EmptyView()
            }
        }
        .padding(8)
        .background(Color.black.opacity(0.7))
        .cornerRadius(8)
    }

    private func algoColorForAlgorithm(_ algo: String) -> Color {
        switch algo {
        case "madgwick": return Color(hex: "4488FF")
        case "mahony3": return Color(hex: "FF8844")
        case "ekf": return Color(hex: "FF44FF")
        default: return Color(hex: "44FF88")
        }
    }
}

struct SocketPanel: View {
    @ObservedObject var socketManager: SocketManager
    @State private var ipText: String = ""
    @State private var portText: String = ""

    private let smallMonoFont = Font.system(size: 9, design: .monospaced)
    private let labelColor = Color(hex: "90CAF9")

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            // IP
            HStack(spacing: 4) {
                Text("IP:").font(smallMonoFont).foregroundColor(labelColor)
                TextField("", text: $ipText)
                    .font(smallMonoFont)
                    .foregroundColor(.white)
                    .frame(width: 80)
                    .textFieldStyle(PlainTextFieldStyle())
                    .onChange(of: ipText) { _, newVal in
                        socketManager.ip = newVal
                    }
            }

            // Port
            HStack(spacing: 4) {
                Text("Port:").font(smallMonoFont).foregroundColor(labelColor)
                TextField("", text: $portText)
                    .font(smallMonoFont)
                    .foregroundColor(.white)
                    .frame(width: 50)
                    .keyboardType(.numberPad)
                    .textFieldStyle(PlainTextFieldStyle())
                    .onChange(of: portText) { _, newVal in
                        if let p = Int(newVal) {
                            socketManager.port = p
                        }
                    }
            }

            // Protocol
            HStack(spacing: 4) {
                Text("协议:").font(smallMonoFont).foregroundColor(labelColor)
                Button(action: { socketManager.protocol_ = "TCP" }) {
                    Text(socketManager.protocol_ == "TCP" ? "[TCP]" : "TCP")
                        .font(smallMonoFont)
                        .foregroundColor(socketManager.protocol_ == "TCP" ? Color(hex: "44FF44") : .gray)
                }
                .buttonStyle(PlainButtonStyle())
                Button(action: { socketManager.protocol_ = "UDP" }) {
                    Text(socketManager.protocol_ == "UDP" ? "[UDP]" : "UDP")
                        .font(smallMonoFont)
                        .foregroundColor(socketManager.protocol_ == "UDP" ? Color(hex: "44FF44") : .gray)
                }
                .buttonStyle(PlainButtonStyle())
            }

            // Content
            HStack(spacing: 4) {
                Text("内容:").font(smallMonoFont).foregroundColor(labelColor)
                Button(action: { socketManager.contentType = "quaternion" }) {
                    Text(socketManager.contentType == "quaternion" ? "[quat]" : "quat")
                        .font(smallMonoFont)
                        .foregroundColor(socketManager.contentType == "quaternion" ? Color(hex: "44FF44") : .gray)
                }
                .buttonStyle(PlainButtonStyle())
                Button(action: { socketManager.contentType = "measure" }) {
                    Text(socketManager.contentType == "measure" ? "[meas]" : "meas")
                        .font(smallMonoFont)
                        .foregroundColor(socketManager.contentType == "measure" ? Color(hex: "44FF44") : .gray)
                }
                .buttonStyle(PlainButtonStyle())
            }
        }
        .padding(8)
        .frame(width: 120)
        .background(Color.black.opacity(0.7))
        .cornerRadius(8)
        .onAppear {
            ipText = socketManager.ip
            portText = "\(socketManager.port)"
        }
    }
}

struct LabeledRow: View {
    let label: String
    let values: [Float]
    var fmt: String = "%.4f"
    var color: Color = .white

    private let tinyMonoFont = Font.system(size: 8, design: .monospaced)

    var body: some View {
        HStack {
            Text(label).font(tinyMonoFont).foregroundColor(Color(hex: "90CAF9"))
            Text(values.map { String(format: fmt, $0) }.joined(separator: " ")).font(tinyMonoFont).foregroundColor(color)
        }
    }
}

struct DividerRow: View {
    private let tinyMonoFont = Font.system(size: 8, design: .monospaced)

    var body: some View {
        Text("────────────────────")
            .font(tinyMonoFont)
            .foregroundColor(.gray)
    }
}

struct RenderToggle: View {
    let label: String
    @Binding var isEnabled: Bool
    var onSync: (() -> Void)?

    private let smallMonoFont = Font.system(size: 11, design: .monospaced)

    var body: some View {
        Button(action: {
            isEnabled.toggle()
            onSync?()
        }) {
            HStack(spacing: 8) {
                Text(isEnabled ? "■" : "□")
                    .font(smallMonoFont)
                    .foregroundColor(isEnabled ? Color(hex: "44FF44") : .gray)
                    .frame(width: 16)
                Text(label).font(smallMonoFont).foregroundColor(.white)
                Spacer()
            }
            .padding(.vertical, 6)
            .padding(.horizontal, 8)
            .background(Color.black.opacity(0.3))
            .cornerRadius(6)
        }
        .buttonStyle(PlainButtonStyle())
    }
}

extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let r, g, b: UInt64
        switch hex.count {
        case 6:
            (r, g, b) = ((int >> 16) & 0xFF, (int >> 8) & 0xFF, int & 0xFF)
        default:
            (r, g, b) = (1, 1, 1)
        }
        self.init(
            .sRGB,
            red: Double(r) / 255,
            green: Double(g) / 255,
            blue: Double(b) / 255,
            opacity: 1
        )
    }
}
