import Foundation

/// 服务器 WebSocket 消息解析
/// 和 Android ServerMessage.kt 完全一致的解析逻辑
enum ServerMessage {
    case loginSuccess(token: String, nickname: String)
    case userList(users: [User])
    case userJoined(username: String, lat: Double, lng: Double, heading: Float, nickname: String?, targetLat: Double?, targetLng: Double?)
    case userLeft(username: String)
    case targetUpdate(username: String, targetLat: Double?, targetLng: Double?)
    case positionUpdate(username: String, lat: Double, lng: Double, heading: Float)
    case error(message: String)

    static func parse(_ jsonString: String) -> ServerMessage? {
        guard let data = jsonString.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = obj["type"] as? String else {
            return nil
        }

        switch type {
        case "login_success":
            let token = obj["token"] as? String ?? ""
            let nickname = obj["nickname"] as? String ?? ""
            return .loginSuccess(token: token, nickname: nickname)

        case "user_list":
            guard let usersArray = obj["users"] as? [[String: Any]] else {
                return .userList(users: [])
            }
            let users = usersArray.compactMap { parseUser($0) }
            return .userList(users: users)

        case "user_joined":
            return .userJoined(
                username: obj["username"] as? String ?? "",
                lat: obj["lat"] as? Double ?? 0,
                lng: obj["lng"] as? Double ?? 0,
                heading: Float(obj["heading"] as? Double ?? 0),
                nickname: obj["nickname"] as? String,
                targetLat: obj["target_lat"] as? Double,
                targetLng: obj["target_lng"] as? Double
            )

        case "user_left":
            return .userLeft(username: obj["username"] as? String ?? "")

        case "update_target":
            return .targetUpdate(
                username: obj["username"] as? String ?? "",
                targetLat: obj["target_lat"] as? Double,
                targetLng: obj["target_lng"] as? Double
            )

        case "update_position":
            return .positionUpdate(
                username: obj["username"] as? String ?? "",
                lat: obj["lat"] as? Double ?? 0,
                lng: obj["lng"] as? Double ?? 0,
                heading: Float(obj["heading"] as? Double ?? 0)
            )

        case "error":
            return .error(message: obj["message"] as? String ?? "未知错误")

        default:
            return nil
        }
    }

    private static func parseUser(_ dict: [String: Any]) -> User? {
        guard let username = dict["username"] as? String else { return nil }
        return User(
            username: username,
            lat: dict["lat"] as? Double ?? 0,
            lng: dict["lng"] as? Double ?? 0,
            heading: dict["heading"] as? Float ?? Float(dict["heading"] as? Double ?? 0),
            nickname: dict["nickname"] as? String,
            targetLat: dict["target_lat"] as? Double,
            targetLng: dict["target_lng"] as? Double
        )
    }
}