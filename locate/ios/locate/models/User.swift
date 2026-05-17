import Foundation

struct User: Identifiable, Codable, Equatable {
    var id: String { username }
    let username: String
    var lat: Double
    var lng: Double
    var heading: Float = 0
    var nickname: String?
    var targetLat: Double?
    var targetLng: Double?

    enum CodingKeys: String, CodingKey {
        case username, lat, lng, heading, nickname
        case targetLat = "target_lat"
        case targetLng = "target_lng"
    }
}

struct Position {
    let lat: Double
    let lng: Double
    let accuracy: Float
    let altitude: Double
    let speed: Float
    let bearing: Float
}