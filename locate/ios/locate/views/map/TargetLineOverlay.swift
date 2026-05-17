import MapKit

/// 橙色虚线渲染器
/// 对应 Android：TargetLineView
/// strokeColor=橙色(1.0,0.596,0.0), lineWidth=4, dash=[24,12]
final class TargetLineRenderer: MKOverlayRenderer {
    override func draw(_ mapRect: MKMapRect, zoomScale: MKZoomScale, in context: CGContext) {
        guard let polyline = overlay as? MKPolyline else { return }

        let lineWidth = 4.0 / zoomScale
        let dashPattern: [CGFloat] = [24.0 / zoomScale, 12.0 / zoomScale]

        context.setStrokeColor(UIColor(red: 1.0, green: 0.596, blue: 0.0, alpha: 0.8).cgColor)
        context.setLineWidth(lineWidth)
        context.setLineDash(phase: 0, lengths: dashPattern)

        let points = polyline.points()
        let startPoint = self.point(for: points[0])
        context.move(to: startPoint)
        for i in 1..<polyline.pointCount {
            context.addLine(to: self.point(for: points[i]))
        }
        context.strokePath()
    }
}

/// 创建目标连线 polyline
func makeTargetLine(from start: CLLocationCoordinate2D, to end: CLLocationCoordinate2D) -> MKPolyline {
    return MKPolyline(coordinates: [start, end], count: 2)
}