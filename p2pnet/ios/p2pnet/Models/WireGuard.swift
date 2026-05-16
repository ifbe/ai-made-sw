import Foundation

struct WgConfig {
    var myIp: String = "10.0.0.2/24"
    var myPort: Int = 51820
    var myPrivateKey: String = ""
    var peerEndpoint: String = ""
    var peerPublicKey: String = ""
    var peerPresharedKey: String = ""
    var allowedIPs: String = "0.0.0.0/0"
    var dns: String = "8.8.8.8"
    var mtu: Int = 1420
}

struct WgInterface: Equatable {
    var myIp: String = "10.0.0.2/24"
    var myPort: Int = 51820
    var privateKey: String = ""
    var peers: [WgPeer] = []
}

struct WgPeer: Equatable, Identifiable {
    let id: String
    var endpoint: String = ""
    var publicKey: String = ""
    var presharedKey: String = ""
    var allowedIPs: String = "0.0.0.0/0"
    var status: TunnelStatus = .disconnected

    init(id: String = UUID().uuidString, endpoint: String = "", publicKey: String = "", presharedKey: String = "", allowedIPs: String = "0.0.0.0/0", status: TunnelStatus = .disconnected) {
        self.id = id
        self.endpoint = endpoint
        self.publicKey = publicKey
        self.presharedKey = presharedKey
        self.allowedIPs = allowedIPs
        self.status = status
    }
}

enum TunnelStatus: String {
    case disconnected = "DISCONNECTED"
    case connecting = "CONNECTING"
    case connected = "CONNECTED"
    case failed = "FAILED"
}