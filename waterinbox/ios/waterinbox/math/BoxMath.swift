import Foundation
import simd

class BoxMath {
    let hw: Float
    let hh: Float
    let d: Float

    init(hw: Float, hh: Float, d: Float) {
        self.hw = hw
        self.hh = hh
        self.d = d
    }

    struct Edge {
        let p1: [Float]
        let p2: [Float]
    }

    var edges: [Edge] {
        let hd = d / 2
        return [
            // Front face (z = +D/2)
            Edge(p1: [-hw, -hh,  hd], p2: [ hw, -hh,  hd]),
            Edge(p1: [ hw, -hh,  hd], p2: [ hw,  hh,  hd]),
            Edge(p1: [ hw,  hh,  hd], p2: [-hw,  hh,  hd]),
            Edge(p1: [-hw,  hh,  hd], p2: [-hw, -hh,  hd]),
            // Back face (z = -D/2)
            Edge(p1: [-hw, -hh, -hd], p2: [ hw, -hh, -hd]),
            Edge(p1: [ hw, -hh, -hd], p2: [ hw,  hh, -hd]),
            Edge(p1: [ hw,  hh, -hd], p2: [-hw,  hh, -hd]),
            Edge(p1: [-hw,  hh, -hd], p2: [-hw, -hh, -hd]),
            // Vertical edges
            Edge(p1: [-hw, -hh, -hd], p2: [-hw, -hh,  hd]),
            Edge(p1: [ hw, -hh, -hd], p2: [ hw, -hh,  hd]),
            Edge(p1: [ hw,  hh, -hd], p2: [ hw,  hh,  hd]),
            Edge(p1: [-hw,  hh, -hd], p2: [-hw,  hh,  hd]),
        ]
    }

    func intersectPlaneWithBox(nx: Float, ny: Float, nz: Float, c: Float) -> [[Float]] {
        var pts: [[Float]] = []
        for edge in edges {
            if let intersection = linePlaneIntersection(edge: edge, nx: nx, ny: ny, nz: nz, c: c) {
                pts.append(intersection)
            }
        }
        if pts.count < 3 { return [] }

        var cx: Double = 0
        var cy: Double = 0
        for pt in pts {
            cx += Double(pt[0])
            cy += Double(pt[1])
        }
        cx /= Double(pts.count)
        cy /= Double(pts.count)

        pts.sort { pt1, pt2 in
            let angle1 = atan2(Double(pt1[1]) - cy, Double(pt1[0]) - cx)
            let angle2 = atan2(Double(pt2[1]) - cy, Double(pt2[0]) - cx)
            return angle1 < angle2
        }
        return pts
    }

    func linePlaneIntersection(edge: Edge, nx: Float, ny: Float, nz: Float, c: Float) -> [Float]? {
        let p1 = edge.p1
        let p2 = edge.p2
        let d1 = nx * p1[0] + ny * p1[1] + nz * p1[2] - c
        let d2 = nx * p2[0] + ny * p2[1] + nz * p2[2] - c
        if d1 * d2 > 0 { return nil }
        if d1 == 0 && d2 == 0 { return nil }
        let t = d1 / (d1 - d2)
        if t < 0 || t > 1 { return nil }
        return [
            p1[0] + t * (p2[0] - p1[0]),
            p1[1] + t * (p2[1] - p1[1]),
            p1[2] + t * (p2[2] - p1[2])
        ]
    }

    func solveWaterPlane(gravity: [Float]) -> WaterPlaneResult {
        let gLen = sqrt(gravity[0] * gravity[0] + gravity[1] * gravity[1] + gravity[2] * gravity[2])
        if gLen < 1e-6 {
            return WaterPlaneResult(normal: [0, 0, 1], c: 0, volume: 0, polygon: [], isWaterVisible: false)
        }

        let nx = gravity[0] / gLen
        let ny = gravity[1] / gLen
        let nz = gravity[2] / gLen

        let c: Float = 0
        let polygon = intersectPlaneWithBox(nx: nx, ny: ny, nz: nz, c: c)

        return WaterPlaneResult(
            normal: [nx, ny, nz],
            c: c,
            volume: 0,
            polygon: polygon,
            isWaterVisible: polygon.count >= 3
        )
    }
}

struct WaterPlaneResult {
    let normal: [Float]
    let c: Float
    let volume: Float
    let polygon: [[Float]]
    let isWaterVisible: Bool
}