import AVFoundation
import Foundation

/// 一次录音的产物：完整 WAV bytes + 时长（毫秒）。
struct VoiceRecordingResult {
    let wavData: Data
    let durationMs: Double
}

/// 语音录制器（核心工具类，与 UI 解耦）。
///
/// 固定 PCM 16 kHz / mono / 16-bit（每秒 32000 bytes，与 Android VoiceRecorder 对齐）。
/// AVAudioRecorder 直接写到 cacheDir 临时 wav 文件；stop() 时读回 Data + 从字节数算时长。
///
/// 推荐生命周期：
///     initSession() → start() → ... → stop() / cancel() → release()
///
/// 单实例即可，多次 start/stop 在同一个 recorder 上复用。release() 后需重新 initSession。
final class VoiceRecorder {
    static let SAMPLE_RATE: Double = 16000
    /// WAV header 固定 44 字节（RIFF/fmt/data 三块的标准布局）
    static let WAV_HEADER_SIZE: Int = 44
    /// 16-bit mono 16kHz = 32000 bytes/s
    static let BYTES_PER_SECOND: Double = SAMPLE_RATE * 2

    private var audioRecorder: AVAudioRecorder?
    private var recordURL: URL?

    /// 检查录音权限并配置 AVAudioSession。
    /// iOS 17+ 走 `AVAudioApplication.requestRecordPermission`，低版本（项目 deployment target = 15.6）
    /// 走旧的 `AVAudioSession.requestRecordPermission` + continuation 桥接。
    /// - Returns: true = 已授权且 session 配置成功
    func initSession() async -> Bool {
        let granted: Bool
        if #available(iOS 17.0, *) {
            granted = await AVAudioApplication.requestRecordPermission()
        } else {
            granted = await withCheckedContinuation { cont in
                AVAudioSession.sharedInstance().requestRecordPermission { isGranted in
                    cont.resume(returning: isGranted)
                }
            }
        }
        guard granted else { return false }

        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playAndRecord, mode: .default,
                                    options: [.defaultToSpeaker, .allowBluetooth])
            try session.setActive(true, options: [])
        } catch {
            return false
        }
        return true
    }

    /// 启动录音（写到 cacheDir/voice_{uuid}.wav 临时文件）
    /// - Returns: true = 启动成功；false = session 激活失败 / 创建 recorder 失败
    func start() -> Bool {
        // 确保 session 已激活（initSession 失败时仍可能复用之前的激活状态）
        do {
            try AVAudioSession.sharedInstance().setActive(true, options: [])
        } catch {
            return false
        }

        let tempDir = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        let url = tempDir.appendingPathComponent("voice_\(UUID().uuidString).wav")

        let settings: [String: Any] = [
            AVFormatIDKey: kAudioFormatLinearPCM,
            AVSampleRateKey: Self.SAMPLE_RATE,
            AVNumberOfChannelsKey: 1,
            AVLinearPCMBitDepthKey: 16,
            AVLinearPCMIsBigEndianKey: false,
            AVLinearPCMIsFloatKey: false,
        ]

        do {
            let recorder = try AVAudioRecorder(url: url, settings: settings)
            recorder.prepareToRecord()
            guard recorder.record() else { return false }
            self.audioRecorder = recorder
            self.recordURL = url
            return true
        } catch {
            return false
        }
    }

    /// 取消录音，删除临时文件
    func cancel() {
        audioRecorder?.stop()
        audioRecorder = nil
        if let url = recordURL {
            try? FileManager.default.removeItem(at: url)
        }
        recordURL = nil
    }

    /// 停止录音，返回 WAV bytes + 时长（毫秒）。
    /// 时长从 PCM 字节数算（与 Android 对齐）：`durationMs = pcmBytes × 1000.0 / 32000.0`
    /// - Returns: nil = 未录音 / 录音文件读不出
    func stop() -> VoiceRecordingResult? {
        guard let recorder = audioRecorder, let url = recordURL else { return nil }
        recorder.stop()
        audioRecorder = nil

        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            try? FileManager.default.removeItem(at: url)
            recordURL = nil
            return nil
        }

        let pcmSize = max(data.count - Self.WAV_HEADER_SIZE, 0)
        let durationMs = Double(pcmSize) * 1000.0 / Self.BYTES_PER_SECOND

        try? FileManager.default.removeItem(at: url)
        recordURL = nil
        return VoiceRecordingResult(wavData: data, durationMs: durationMs)
    }

    /// 释放 AVAudioSession；自动 cancel 进行中的录音
    func release() {
        cancel()
        try? AVAudioSession.sharedInstance().setActive(false, options: [.notifyOthersOnDeactivation])
    }
}