package com.example.chatroom.core

import android.graphics.BitmapFactory

/**
 * 通用 blob 嗅探工具：根据 magic bytes 识别 MIME 类型 + 取图片尺寸（仅 metadata，不分配像素）。
 *
 * 设计目的：
 *  - 与具体 transport（WS / TCP / UDP）解耦。任意来源的 ByteArray 都能拿来 sniff。
 *  - 单例（object），无状态。线程安全。
 *
 * 限制：
 *  - 不识别加密 / 压缩容器内部真实类型（例如 .tar.gz 只会识别成 gzip）。
 *  - 仅识别 RFC / 工业标准魔数。自定义格式需自己扩展 when 分支。
 *  - decodeImageSize 依赖 BitmapFactory；某些罕见容器（CMYK JPEG、HEIF 旧版本）可能拿不到尺寸，
 *    失败返回 null，调用方应降级到不显示 size。
 */
object BlobSniffer {

    /**
     * 用 magic bytes 嗅探 blob 的常见 MIME 类型。
     * 命中常见格式返回 type；不是任何已知格式返回 "application/octet-stream (unknown)"。
     * 小于 4 字节的 blob 直接 unknown（无法判断）。
     */
    fun detectType(data: ByteArray): String {
        if (data.size < 4) return "application/octet-stream (unknown, len<4)"

        val b = data
        val b0 = b[0]; val b1 = b[1]; val b2 = b[2]; val b3 = b[3]

        return when {
            // image/jpeg: FF D8 FF
            b0 == 0xFF.toByte() && b1 == 0xD8.toByte() && b2 == 0xFF.toByte() ->
                "image/jpeg"

            // image/png: 89 50 4E 47 0D 0A 1A 0A
            b.size >= 8 && b0 == 0x89.toByte() && b1 == 0x50.toByte() && b2 == 0x4E.toByte() && b3 == 0x47.toByte() &&
                b[4] == 0x0D.toByte() && b[5] == 0x0A.toByte() && b[6] == 0x1A.toByte() && b[7] == 0x0A.toByte() ->
                "image/png"

            // image/gif: GIF87a / GIF89a
            b.size >= 6 && b0 == 0x47.toByte() && b1 == 0x49.toByte() && b2 == 0x46.toByte() && b3 == 0x38.toByte() &&
                (b[4] == 0x37.toByte() || b[4] == 0x39.toByte()) && b[5] == 0x61.toByte() ->
                "image/gif"

            // image/webp: RIFF....WEBP
            b.size >= 12 && b0 == 0x52.toByte() && b1 == 0x49.toByte() && b2 == 0x46.toByte() && b3 == 0x46.toByte() &&
                b[8] == 0x57.toByte() && b[9] == 0x45.toByte() && b[10] == 0x42.toByte() && b[11] == 0x50.toByte() ->
                "image/webp"

            // image/bmp: BM
            b0 == 0x42.toByte() && b1 == 0x4D.toByte() ->
                "image/bmp"

            // image/tiff: II*\0 (LE) or MM\0* (BE)
            (b0 == 0x49.toByte() && b1 == 0x49.toByte() && b2 == 0x2A.toByte() && b3 == 0x00.toByte()) ||
                (b0 == 0x4D.toByte() && b1 == 0x4D.toByte() && b2 == 0x00.toByte() && b3 == 0x2A.toByte()) ->
                "image/tiff"

            // ISO BMFF, ftyp box at offset 4：heic/heif/avif 也走这个 branch
            b.size >= 8 && b[4] == 0x66.toByte() && b[5] == 0x74.toByte() && b[6] == 0x79.toByte() && b[7] == 0x70.toByte() -> {
                val brand = if (b.size >= 12) String(b.copyOfRange(8, 12), Charsets.US_ASCII).trimEnd('\u0000') else "?"
                when (brand.lowercase()) {
                    "heic", "heix", "heim", "heis", "hevc", "mif1", "msf1", "msf2" -> "image/heic"
                    "avif", "avis" -> "image/avif"
                    else -> "video/mp4 (brand=$brand)"
                }
            }

            // video/webm / video/x-matroska: EBML header
            b0 == 0x1A.toByte() && b1 == 0x45.toByte() && b2 == 0xDF.toByte() && b3 == 0xA3.toByte() ->
                "video/webm"

            // audio/mp3 (ID3v2 tag header)
            b0 == 0x49.toByte() && b1 == 0x44.toByte() && b2 == 0x33.toByte() ->
                "audio/mp3 (ID3v2)"

            // audio/mp3 (MPEG audio frame sync)
            b0 == 0xFF.toByte() && (b1.toInt() and 0xE0) == 0xE0 ->
                "audio/mp3 (frame)"

            // audio/flac
            b0 == 0x66.toByte() && b1 == 0x4C.toByte() && b2 == 0x61.toByte() && b3 == 0x43.toByte() ->
                "audio/flac"

            // audio/wav: RIFF....WAVE
            b.size >= 12 && b0 == 0x52.toByte() && b1 == 0x49.toByte() && b2 == 0x46.toByte() && b3 == 0x46.toByte() &&
                b[8] == 0x57.toByte() && b[9] == 0x41.toByte() && b[10] == 0x56.toByte() && b[11] == 0x45.toByte() ->
                "audio/wav"

            // audio/ogg
            b0 == 0x4F.toByte() && b1 == 0x67.toByte() && b2 == 0x67.toByte() && b3 == 0x53.toByte() ->
                "audio/ogg"

            // application/pdf: %PDF
            b0 == 0x25.toByte() && b1 == 0x50.toByte() && b2 == 0x44.toByte() && b3 == 0x46.toByte() ->
                "application/pdf"

            // application/zip (PK\x03\x04 / PK\x05\x06 / PK\x07\x08): 涵盖 jar/apk/docx/xlsx/odt 等
            b0 == 0x50.toByte() && b1 == 0x4B.toByte() && (
                (b2 == 0x03.toByte() && b3 == 0x04.toByte()) ||
                    (b2 == 0x05.toByte() && b3 == 0x06.toByte()) ||
                    (b2 == 0x07.toByte() && b3 == 0x08.toByte())
                ) ->
                "application/zip"

            // application/gzip
            b0 == 0x1F.toByte() && b1 == 0x8B.toByte() ->
                "application/gzip"

            // application/vnd.rar: Rar!\x1A\x07
            b.size >= 7 && b0 == 0x52.toByte() && b1 == 0x61.toByte() && b2 == 0x72.toByte() && b3 == 0x21.toByte() &&
                b[4] == 0x1A.toByte() && b[5] == 0x07.toByte() ->
                "application/vnd.rar"

            // application/x-7z-compressed: 7z¼¯'\x1C
            b.size >= 6 && b0 == 0x37.toByte() && b1 == 0x7A.toByte() && b2 == 0xBC.toByte() && b3 == 0xAF.toByte() &&
                b[4] == 0x27.toByte() && b[5] == 0x1C.toByte() ->
                "application/x-7z-compressed"

            // application/x-executable / application/x-sharedlib: ELF
            b0 == 0x7F.toByte() && b1 == 0x45.toByte() && b2 == 0x4C.toByte() && b3 == 0x46.toByte() ->
                "application/elf"

            // text/plain 启发式：全是可打印 ASCII + 空白
            b.all { c -> val v = c.toInt(); v in 0x20..0x7E || v == 0x09 || v == 0x0A || v == 0x0D } ->
                "text/plain (printable ASCII)"

            else -> "application/octet-stream (unknown)"
        }
    }

    /**
     * 只读 image 的宽高（不分配像素），拿不到就返回 null。
     * 依赖 BitmapFactory 解析 ISO BMFF / PNG / JPEG / WebP 等多种容器 / 编码 的 header 部分。
     */
    fun decodeImageSize(data: ByteArray): Pair<Int, Int>? {
        return try {
            val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeByteArray(data, 0, data.size, opts)
            if (opts.outWidth > 0 && opts.outHeight > 0) opts.outWidth to opts.outHeight else null
        } catch (e: Exception) {
            null
        }
    }
}