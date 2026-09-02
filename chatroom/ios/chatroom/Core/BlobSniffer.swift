import Foundation
import ImageIO
import CoreGraphics

/// 通用 blob 嗅探工具：根据 magic bytes 识别 MIME 类型 + 取图片尺寸（仅 metadata，不分配像素）。
///
/// 设计目的：
///  - 与具体 transport（WS / TCP / UDP）解耦。任意来源的 Data 都能拿来 sniff。
///  - 单例（enum case less），无状态。
///
/// 限制：
///  - 不识别加密 / 压缩容器内部真实类型（例如 .tar.gz 只会识别成 gzip）。
///  - 仅识别工业标准魔数。自定义格式需自己扩展 if 分支。
///  - decodeImageSize 依赖 ImageIO；某些罕见容器拿不到尺寸，失败返回 nil。
enum BlobSniffer {

    /// 用 magic bytes 嗅探 blob 的常见 MIME 类型。
    /// 命中常见格式返回 type；不是任何已知格式返回 "application/octet-stream (unknown)"。
    /// 小于 4 字节的 blob 直接 unknown（无法判断）。
    static func detectType(_ data: Data) -> String {
        let count = data.count
        guard count >= 4 else {
            return "application/octet-stream (unknown, len<4)"
        }
        let b = [UInt8](data)
        let b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3]

        // image/jpeg: FF D8 FF
        if b0 == 0xFF && b1 == 0xD8 && b2 == 0xFF {
            return "image/jpeg"
        }
        // image/png: 89 50 4E 47 0D 0A 1A 0A
        if count >= 8 && b0 == 0x89 && b1 == 0x50 && b2 == 0x4E && b3 == 0x47
            && b[4] == 0x0D && b[5] == 0x0A && b[6] == 0x1A && b[7] == 0x0A {
            return "image/png"
        }
        // image/gif: GIF87a / GIF89a
        if count >= 6 && b0 == 0x47 && b1 == 0x49 && b2 == 0x46 && b3 == 0x38
            && (b[4] == 0x37 || b[4] == 0x39) && b[5] == 0x61 {
            return "image/gif"
        }
        // image/webp: RIFF....WEBP
        if count >= 12 && b0 == 0x52 && b1 == 0x49 && b2 == 0x46 && b3 == 0x46
            && b[8] == 0x57 && b[9] == 0x45 && b[10] == 0x42 && b[11] == 0x50 {
            return "image/webp"
        }
        // image/bmp: BM
        if b0 == 0x42 && b1 == 0x4D {
            return "image/bmp"
        }
        // image/tiff: II*\0 (LE) or MM\0* (BE)
        if (b0 == 0x49 && b1 == 0x49 && b2 == 0x2A && b3 == 0x00)
            || (b0 == 0x4D && b1 == 0x4D && b2 == 0x00 && b3 == 0x2A) {
            return "image/tiff"
        }
        // ISO BMFF, ftyp box at offset 4：heic/heif/avif 也走这个 branch
        if count >= 8 && b[4] == 0x66 && b[5] == 0x74 && b[6] == 0x79 && b[7] == 0x70 {
            let brand: String
            if count >= 12 {
                let brandBytes = Array(b[8..<12])
                brand = String(bytes: brandBytes, encoding: .ascii)?
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\0")) ?? "?"
            } else {
                brand = "?"
            }
            switch brand.lowercased() {
            case "heic", "heix", "heim", "heis", "hevc", "mif1", "msf1", "msf2":
                return "image/heic"
            case "avif", "avis":
                return "image/avif"
            default:
                return "video/mp4 (brand=\(brand))"
            }
        }
        // video/webm / video/x-matroska: EBML header
        if b0 == 0x1A && b1 == 0x45 && b2 == 0xDF && b3 == 0xA3 {
            return "video/webm"
        }
        // audio/mp3 (ID3v2 tag header)
        if b0 == 0x49 && b1 == 0x44 && b2 == 0x33 {
            return "audio/mp3 (ID3v2)"
        }
        // audio/mp3 (MPEG audio frame sync)
        if b0 == 0xFF && (b1 & 0xE0) == 0xE0 {
            return "audio/mp3 (frame)"
        }
        // audio/flac
        if b0 == 0x66 && b1 == 0x4C && b2 == 0x61 && b3 == 0x43 {
            return "audio/flac"
        }
        // audio/wav: RIFF....WAVE
        if count >= 12 && b0 == 0x52 && b1 == 0x49 && b2 == 0x46 && b3 == 0x46
            && b[8] == 0x57 && b[9] == 0x41 && b[10] == 0x56 && b[11] == 0x45 {
            return "audio/wav"
        }
        // audio/ogg
        if b0 == 0x4F && b1 == 0x67 && b2 == 0x67 && b3 == 0x53 {
            return "audio/ogg"
        }
        // application/pdf: %PDF
        if b0 == 0x25 && b1 == 0x50 && b2 == 0x44 && b3 == 0x46 {
            return "application/pdf"
        }
        // application/zip (PK\x03\x04 / PK\x05\x06 / PK\x07\x08): 涵盖 jar/apk/docx/xlsx/odt 等
        if b0 == 0x50 && b1 == 0x4B && (
            (b2 == 0x03 && b3 == 0x04) ||
            (b2 == 0x05 && b3 == 0x06) ||
            (b2 == 0x07 && b3 == 0x08)
        ) {
            return "application/zip"
        }
        // application/gzip
        if b0 == 0x1F && b1 == 0x8B {
            return "application/gzip"
        }
        // application/vnd.rar: Rar!\x1A\x07
        if count >= 7 && b0 == 0x52 && b1 == 0x61 && b2 == 0x72 && b3 == 0x21
            && b[4] == 0x1A && b[5] == 0x07 {
            return "application/vnd.rar"
        }
        // application/x-7z-compressed: 7z¼¯'\x1C
        if count >= 6 && b0 == 0x37 && b1 == 0x7A && b2 == 0xBC && b3 == 0xAF
            && b[4] == 0x27 && b[5] == 0x1C {
            return "application/x-7z-compressed"
        }
        // application/x-executable / application/x-sharedlib: ELF
        if b0 == 0x7F && b1 == 0x45 && b2 == 0x4C && b3 == 0x46 {
            return "application/elf"
        }
        // text/plain 启发式：全是可打印 ASCII + 空白
        let allPrintable = b.allSatisfy { c in
            let v = Int(c)
            return (0x20...0x7E).contains(v) || v == 0x09 || v == 0x0A || v == 0x0D
        }
        if allPrintable {
            return "text/plain (printable ASCII)"
        }

        return "application/octet-stream (unknown)"
    }

    /// 只读 image 的宽高（不分配像素），拿不到就返回 nil。
    /// 依赖 ImageIO 解析 ISO BMFF / PNG / JPEG / WebP 等多种容器 / 编码 的 header 部分。
    static func decodeImageSize(_ data: Data) -> (width: Int, height: Int)? {
        guard let src = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
        let opts = [kCGImageSourceShouldCache: false] as CFDictionary
        guard let props = CGImageSourceCopyPropertiesAtIndex(src, 0, opts) as? [CFString: Any] else { return nil }
        let w = props[kCGImagePropertyPixelWidth] as? Int ?? 0
        let h = props[kCGImagePropertyPixelHeight] as? Int ?? 0
        return w > 0 && h > 0 ? (w, h) : nil
    }
}