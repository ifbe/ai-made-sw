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
    private let queue = DispatchQueue(label: "SocketManager.sendQueue", qos: .userInitiated)

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
    }

    func disconnect() {
        connection?.cancel()
        connection = nil
        DispatchQueue.main.async {
            self.isConnected = false
        }
    }

    /// Called from sensor thread. Drops if not connected.
    /// quat format: qx,qy,qz,qw (fixed quaternion, 4 decimal places)
    /// measure format: gx,gy,gz,ax,ay,az,mx,my,mz,timestamp_seconds (10 fields, 4 decimal places)
    func onSensorData(
        qx: Float, qy: Float, qz: Float, qw: Float,
        gx: Float, gy: Float, gz: Float,
        ax: Float, ay: Float, az: Float,
        mx: Float, my: Float, mz: Float,
        timestamp: Double
    ) {
        guard isConnected else { return }

        let data: String
        switch contentType {
        case "quaternion":
            data = String(format: "%.4f, %.4f, %.4f, %.4f", qx, qy, qz, qw)
        case "measure":
            data = String(format: "%.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f, %.4f",
                          gx, gy, gz, ax, ay, az, mx, my, mz, timestamp)
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
