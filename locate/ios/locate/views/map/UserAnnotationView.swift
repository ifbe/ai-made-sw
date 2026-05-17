import MapKit
import UIKit

/// 用户标记视图（带箭头方向）
/// 对应 Android 的 MarkerView
class UserAnnotationView: MKAnnotationView {
    static let reuseIdentifier = "UserAnnotationView"

    private let arrowSize: CGFloat = 40
    private let arrowColorSelf = UIColor(red: 1.0, green: 0.8, blue: 0.0, alpha: 1.0)   // 金色（本地GPS）
    private let arrowColorOther = UIColor(red: 0.0, green: 0.6, blue: 1.0, alpha: 1.0) // 蓝色（服务器所有人）

    override var annotation: MKAnnotation? {
        didSet { setNeedsDisplay() }
    }

    override init(annotation: MKAnnotation?, reuseIdentifier: String?) {
        super.init(annotation: annotation, reuseIdentifier: reuseIdentifier)
        frame = CGRect(x: 0, y: 0, width: arrowSize, height: arrowSize)
        centerOffset = CGPoint(x: 0, y: -arrowSize / 2)
        backgroundColor = .clear
    }

    required init?(coder aDecoder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func draw(_ rect: CGRect) {
        guard let userAnnotation = annotation as? UserAnnotation else { return }
        let ctx = UIGraphicsGetCurrentContext()
        let cx = rect.midX
        let cy = rect.midY

        let headingRad = CGFloat(userAnnotation.heading) * .pi / 180.0
        ctx?.saveGState()
        ctx?.translateBy(x: cx, y: cy)
        ctx?.rotate(by: -headingRad)

        // 本地GPS：空心三角；服务器所有人：实心三角
        if userAnnotation.isSelf {
            // 本地 GPS：空心三角 emoji △，压扁变尖
            let font = UIFont.systemFont(ofSize: arrowSize * 0.95)
            let attrs: [NSAttributedString.Key: Any] = [
                .font: font,
                .foregroundColor: arrowColorSelf
            ]
            let text = "\u{25B3}"
            let textSize = (text as NSString).size(withAttributes: attrs)

            ctx?.scaleBy(x: 0.65, y: 1)

            let tx = -textSize.width / 2
            let ty = -textSize.height / 2
            (text as NSString).draw(at: CGPoint(x: tx, y: ty), withAttributes: attrs)
        } else {
            // 服务器所有人：↑ 箭头
            let font = UIFont.systemFont(ofSize: arrowSize * 0.85)
            let attrs: [NSAttributedString.Key: Any] = [
                .font: font,
                .foregroundColor: arrowColorOther
            ]
            let text = "\u{2191}"
            let textSize = (text as NSString).size(withAttributes: attrs)
            let tx = -textSize.width / 2
            let ty = -textSize.height / 2
            (text as NSString).draw(at: CGPoint(x: tx, y: ty), withAttributes: attrs)
        }

        ctx?.restoreGState()

        if !userAnnotation.isSelf {
            let name = userAnnotation.title ?? ""
            let attrs: [NSAttributedString.Key: Any] = [.font: UIFont.systemFont(ofSize: 10), .foregroundColor: UIColor.black]
            let size = (name as NSString).size(withAttributes: attrs)
            let nameRect = CGRect(x: cx - size.width / 2, y: cy + 2, width: size.width, height: size.height)
            (name as NSString).draw(in: nameRect, withAttributes: attrs)
        }
    }
}

/// 目标点标记视图（橙色方块 + "T"）
/// 对应 Android 的 TargetMarkerView
class TargetAnnotationView: MKAnnotationView {
    static let reuseIdentifier = "TargetAnnotationView"

    override init(annotation: MKAnnotation?, reuseIdentifier: String?) {
        super.init(annotation: annotation, reuseIdentifier: reuseIdentifier)
        frame = CGRect(x: 0, y: 0, width: 24, height: 24)
        centerOffset = CGPoint(x: 0, y: 0)
        backgroundColor = .clear
    }

    required init?(coder aDecoder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func draw(_ rect: CGRect) {
        let orange = UIColor(red: 1.0, green: 0.596, blue: 0.0, alpha: 1.0)
        let innerRect = rect.insetBy(dx: 2, dy: 2)

        // 橙色圆角矩形
        let path = UIBezierPath(roundedRect: innerRect, cornerRadius: 4)
        orange.setFill()
        path.fill()

        UIColor.white.setStroke()
        path.lineWidth = 1
        path.stroke()

        // "T" 文字
        let attrs: [NSAttributedString.Key: Any] = [
            .font: UIFont.systemFont(ofSize: 14, weight: .bold),
            .foregroundColor: UIColor.white
        ]
        let text = "T"
        let textSize = (text as NSString).size(withAttributes: attrs)
        let tx = rect.midX - textSize.width / 2
        let ty = rect.midY - textSize.height / 2 + 1
        (text as NSString).draw(at: CGPoint(x: tx, y: ty), withAttributes: attrs)
    }
}