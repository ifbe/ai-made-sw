import Foundation
import Network
import Combine

class SocketManager: ObservableObject {
    static let shared = SocketManager()

    @Published var protocol_ = "TCP"
    @Published var ip = "192.168.5.129"
    @Published var port = 9999
    @Published var contentType = "quaternion"
    @Published var isConnected = false

    private var connection: NWConnection?

    private init() {}

    func connect() {
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(ip),
            port: NWEndpoint.Port(integerLiteral: UInt16(port))
        )

        switch protocol_ {
        case "TCP":
            connection = NWConnection(to: endpoint, using: .tcp)
        case "UDP":
            connection = NWConnection(to: endpoint, using: .udp)
        default:
            return
        }

        connection?.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                DispatchQueue.main.async {
                    self?.isConnected = true
                }
            case .failed, .cancelled:
                DispatchQueue.main.async {
                    self?.isConnected = false
                }
            default:
                break
            }
        }

        connection?.start(queue: .global(qos: .userInitiated))
        isConnected = true
    }

    func disconnect() {
        connection?.cancel()
        connection = nil
        isConnected = false
    }

    func onSensorData(
        qx: Float, qy: Float, qz: Float, qw: Float,
        gx: Float, gy: Float, gz: Float,
        ax: Float, ay: Float, az: Float,
        mx: Float, my: Float, mz: Float,
        ms: Double
    ) {
        let data: String
        switch contentType {
        case "quaternion":
            data = String(format: "%.4f, %.4f, %.4f, %.4f", qx, qy, qz, qw)
        case "measure":
            data = String(format: "%.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f",
                          gx, gy, gz, ax, ay, az, mx, my, mz, ms)
        default:
            return
        }

        guard let dataToSend = (data + "\n").data(using: .utf8) else { return }
        connection?.send(content: dataToSend, completion: .contentProcessed { error in
            if let error = error {
                print("Send error: \(error)")
            }
        })
    }
}
