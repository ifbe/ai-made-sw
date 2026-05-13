import Foundation

/// 参与者配置（尚未连接，只保存配置）
struct ParticipantConfig: Identifiable, Equatable {
    let id: String
    let type: ParticipantType
    let name: String
    let params: [String: String]

    init(
        id: String = UUID().uuidString,
        type: ParticipantType,
        name: String,
        params: [String: String] = [:]
    ) {
        self.id = id
        self.type = type
        self.name = name
        self.params = params
    }

    static func == (lhs: ParticipantConfig, rhs: ParticipantConfig) -> Bool {
        lhs.id == rhs.id
    }
}

/// 序列化用（params 字典转字符串）
extension ParticipantConfig {
    var paramsString: String {
        params.map { "\($0.key):\($0.value)" }.joined(separator: " ")
    }
}
