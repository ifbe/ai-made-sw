import AVFoundation
import Foundation

/// 全局单例音频播放器（短期工具，仅用于 chat 内的语音气泡点击播放）。
///
/// 用法：
///     AudioMessagePlayer.shared.play(wavData, cacheDir: context.cacheDir) { /* onComplete */ }
///
/// 行为：
/// - 同一时刻只播一条；新 play() 会先停掉当前的
/// - 把 wav 写到 cacheDir/voice_{uuid}.wav 临时文件，AVAudioPlayer 异步 prepare + play
/// - 播放完 / 出错自动 release + 删临时文件（用 AVAudioPlayerDelegate 回调驱动）
final class AudioMessagePlayer: NSObject {
    static let shared = AudioMessagePlayer()

    private var currentPlayer: AVAudioPlayer?
    private var currentURL: URL?
    private var currentOnComplete: (() -> Void)?

    private override init() {
        super.init()
    }

    /// 播放一段 WAV bytes。
    /// - Parameters:
    ///   - wavData: 完整 WAV（含 44 字节 header + PCM data）
    ///   - cacheDir: 用于写临时文件（建议传 FileManager.default.urls(for: .cachesDirectory) 的第一个）
    ///   - onComplete: 播放结束 / 失败时回调（主线程）
    func play(_ wavData: Data, cacheDir: URL, onComplete: (() -> Void)? = nil) {
        // 先停掉之前的（会 release + 删临时文件）
        stop()

        let url = cacheDir.appendingPathComponent("voice_\(UUID().uuidString).wav")
        do {
            try wavData.write(to: url, options: .atomic)
        } catch {
            onComplete?()
            return
        }

        // 配 session 为 playback（不抢 mic）
        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playback, mode: .default)
            try session.setActive(true)
        } catch {
            try? FileManager.default.removeItem(at: url)
            onComplete?()
            return
        }

        do {
            let player = try AVAudioPlayer(contentsOf: url)
            player.delegate = self
            player.prepareToPlay()
            player.play()
            currentPlayer = player
            currentURL = url
            currentOnComplete = onComplete
        } catch {
            try? FileManager.default.removeItem(at: url)
            onComplete?()
        }
    }

    /// 停掉当前播放（如有）；release player + 删临时文件
    func stop() {
        currentPlayer?.stop()
        cleanup()
    }

    private func cleanup() {
        currentPlayer?.delegate = nil
        currentPlayer = nil
        if let url = currentURL {
            try? FileManager.default.removeItem(at: url)
        }
        currentURL = nil
        currentOnComplete = nil
    }
}

extension AudioMessagePlayer: AVAudioPlayerDelegate {
    func audioPlayerDidFinishPlaying(_ player: AVAudioPlayer, successfully flag: Bool) {
        let cb = currentOnComplete
        cleanup()
        cb?()
    }

    func audioPlayerDecodeErrorDidOccur(_ player: AVAudioPlayer, error: Error?) {
        let cb = currentOnComplete
        cleanup()
        cb?()
    }
}