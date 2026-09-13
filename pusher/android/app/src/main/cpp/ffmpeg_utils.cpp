#include <android/log.h>
#include <string>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <pthread.h>
extern "C"{
#include "libavformat/avformat.h"
#include "libavcodec/avcodec.h"
#include "libavutil/avutil.h"
#include "libavutil/time.h"
#include "libavutil/mem.h"
#include "libavcodec/bsf.h"
}

#define LOG_TAG "FFmpegUtils"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 逐包/逐帧的调试日志（含 sprintf 十六进制 dump）开销很大，默认关闭。
// 需要抓包分析时把它改成 1 重新编译即可，不影响其它逻辑。
#ifndef PUSHER_VERBOSE_LOG
#define PUSHER_VERBOSE_LOG 0
#endif
#if PUSHER_VERBOSE_LOG
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#else
#define LOGV(...) ((void)0)
#endif

// ffmpeg_utils.cpp 只调用以下函数，不直接写 JNI 代码
extern "C" {
    void java_on_send_callback(const uint8_t* buf, int buf_size, int64_t ts_ms);
    void java_on_mux_callback(const uint8_t* buf, int buf_size, int64_t ts_ms);
    void java_on_rtmp_error_callback(const char* error_msg);
}

// =============================================================================
// 生命周期保护：
// 写入（视频/音频线程）与关闭（会话线程）可能并发。旧代码里 write_mutex 只保护
// av_interleaved_write_frame，close_ffmpeg_pusher 却在无锁情况下 free format_ctx /
// hooked AVIO / 重置全局流指针，导致 use-after-free 和空指针解引用（偶现 SIGSEGV）。
// 这里用“写者计数 + closing 标志”保证：close 先禁止新写入，再等所有写入者退出，
// 之后才真正释放资源。
// =============================================================================
static pthread_mutex_t lifecycle_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t lifecycle_cond = PTHREAD_COND_INITIALIZER;
static int active_writers = 0;
static bool pusher_closing = false;

static bool writer_enter() {
    pthread_mutex_lock(&lifecycle_mutex);
    if (pusher_closing) {
        pthread_mutex_unlock(&lifecycle_mutex);
        return false;
    }
    active_writers++;
    pthread_mutex_unlock(&lifecycle_mutex);
    return true;
}

static void writer_exit() {
    pthread_mutex_lock(&lifecycle_mutex);
    active_writers--;
    if (active_writers <= 0) {
        active_writers = 0;
        pthread_cond_broadcast(&lifecycle_cond);
    }
    pthread_mutex_unlock(&lifecycle_mutex);
}

static void wait_writers_done() {
    pthread_mutex_lock(&lifecycle_mutex);
    while (active_writers > 0) {
        pthread_cond_wait(&lifecycle_cond, &lifecycle_mutex);
    }
    pthread_mutex_unlock(&lifecycle_mutex);
}

// RAII：保证任何 return 路径都会释放“写者”名额
namespace {
struct WriterGuard {
    bool ok;
    WriterGuard() : ok(writer_enter()) {}
    ~WriterGuard() { if (ok) writer_exit(); }
};
}

static int64_t g_stream_start_time = 0;  // 流开始的绝对时间（微秒）
// 自定义 hooked AVIO 上下文（独立追踪，避免 close 时 double-free）
static AVIOContext* hooked_avio_ctx = nullptr;
static AVIOContext* real_avio_ctx = nullptr;
AVFormatContext* format_ctx = nullptr;
AVStream* video_stream = nullptr;
AVStream* audio_stream = nullptr;
AVStream* subtitle_stream = nullptr;
int video_stream_index = -1;
int audio_stream_index = -1;
int subtitle_stream_index = -1;
int video_time_base_num = 1;
int video_time_base_den = 90000;
int audio_time_base_num = 1;
int audio_time_base_den = 44100;
int video_fps = 30;

// 0 = H.264(AVC)，1 = H.265(HEVC)；只影响 codec_id 与 CSD→extradata 的构造方式
static int g_video_codec = 0;

// VPS/SPS/PPS 收集缓冲区（HEVC 需要 VPS）
static uint8_t* vps_buffer = nullptr;
static int vps_size = 0;
static uint8_t* sps_buffer = nullptr;
static int sps_size = 0;
static uint8_t* pps_buffer = nullptr;
static int pps_size = 0;
static int extradata_sent = 0;

// 是否已经成功写入头部；只有写过头部才允许/需要写 trailer
static bool header_written = false;

// 最近一次失败的真实原因（回传给 Java，便于在“特殊日志”里看到）
static char g_last_error[256] = {0};

// ---- 本地录制：native 直接落盘 ----
// Java 侧把打开好的文件描述符（File 或 MediaStore 都行）detachFd 传进来，
// 这里在每个封包写出去的同时原样写一份到磁盘 —— 不跨 JNI 拷贝、不在 Java 排队，
// 预览那一路照旧只拿 16 字节（省事、零开销）。
static int record_fd = -1;
static long long record_bytes = 0;

// 字幕：Java 只设置文本；真正的样本在**视频关键帧**处写。
// 原因：fMP4 分片边界落在关键帧上，如果字幕样本写在两个关键帧之间，
// movenc 会把稀疏文本轨的簇截断，track_duration 记账变成负值 →
// get_cluster_duration() 里的 av_assert0(next_dts >= 0) 直接 abort（真机崩过）。
static char subtitle_text[512] = {0};
static bool subtitle_has_text = false;
static int64_t last_subtitle_pts_ms = -1;

void start_recording_fd(int fd) {
    if (record_fd >= 0 && record_fd != fd) {
        close(record_fd);
    }
    record_fd = fd;
    record_bytes = 0;
    LOGI("start_recording_fd: fd=%d", fd);
}

long long stop_recording_fd() {
    long long n = record_bytes;
    if (record_fd >= 0) {
        close(record_fd);
        record_fd = -1;
    }
    record_bytes = 0;
    LOGI("stop_recording_fd: bytes=%lld", n);
    return n;
}

/**
 * 当前这份 FFmpeg 库里编进去的"输出协议"清单（逗号分隔）。
 *
 * 用途：① 出错时告诉调用方"这个能力本库有没有"；② Java 侧启动时上报，
 * 便于发现"选了 srt/tcp 但库里没编"这类问题（需要重编 FFmpeg，不是 App 的 bug）。
 */
std::string supported_output_protocols() {
    std::string out;
    void* opaque = nullptr;
    const char* name = nullptr;
    while ((name = avio_enum_protocols(&opaque, 1)) != nullptr) {  // 1 = 输出方向
        if (!out.empty()) out += ",";
        out += name;
    }
    return out;
}

static void set_last_error(const char* msg) {
    if (msg == nullptr) {
        g_last_error[0] = '\0';
        return;
    }
    snprintf(g_last_error, sizeof(g_last_error), "%s", msg);
    LOGE("last error: %s", g_last_error);
}

const char* get_last_error() {
    return g_last_error;
}

// FFmpeg 写入锁：音视频写入必须串行化
static pthread_mutex_t write_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * 根据采样率和通道数构造 AAC AudioSpecificConfig (ASC)
 * 返回 2 字节的 ASC， caller 负责 free
 */
static uint8_t* build_aac_asc(int sample_rate, int channels, int* out_size) {
    // AAC-LC object type = 2
    // sampling_frequency_index: 44100=4, 48000=3, 16000=7, 8000=15
    // channel_configuration: 1=mono, 2=stereo
    static const int sample_rate_table[] = {
        96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050,
        16000, 12000, 11025, 8000, 7350, 0, 0, 0
    };
    int sri = 0xF; // default to 8000
    for (int i = 0; i < 16; i++) {
        if (sample_rate_table[i] == sample_rate) {
            sri = i;
            break;
        }
    }
    int ch = (channels >= 2) ? 2 : 1;

    // ASC 2字节格式 (AAC-LC):
    // byte0[7:5]=objecttype[4:2], byte0[4:0]=objecttype[1:0]|sri[3:2]
    // byte1[7:4]=sri[1:0], byte1[3:0]=channel_configuration
    uint8_t* asc = (uint8_t*)av_malloc(2);
    asc[0] = 0x02;                  // objecttype = AAC-LC (00010)
    asc[0] = (asc[0] << 3) | ((sri >> 1) & 0x07);
    asc[1] = ((sri & 0x01) << 7) | (ch << 3);
    *out_size = 2;
    LOGI("AAC ASC: sample_rate=%d sri=%d channels=%d -> ASC=%02x %02x",
         sample_rate, sri, ch, asc[0], asc[1]);
    return asc;
}

/**
 * 重置时间戳基准（只重置日志用的流起始时间）
 *
 * 注意：音视频 PTS 不再在 native 侧“各自从 0 开始”。
 * 旧实现里 adjust_video_pts / adjust_audio_pts 各减自己第一帧的时间戳，
 * 会把两条流的起始时间差抹掉（相机比音频晚启动 200ms，整条流就固定错 200ms）。
 * 现在由 Java 侧用同一个时钟（SystemClock.elapsedRealtime）把两条流的 PTS
 * 归一到会话基准上，native 直接使用即可。
 */
void reset_pts_base() {
    g_stream_start_time = 0;
}

/**
 * 重置 SPS/PPS 收集状态
 */
void reset_sps_pps_state() {
    if (vps_buffer) {
        free(vps_buffer);
        vps_buffer = nullptr;
        vps_size = 0;
    }
    if (sps_buffer) {
        free(sps_buffer);
        sps_buffer = nullptr;
        sps_size = 0;
    }
    if (pps_buffer) {
        free(pps_buffer);
        pps_buffer = nullptr;
        pps_size = 0;
    }
    extradata_sent = 0;
    LOGV("SPS/PPS state reset");
}

/**
 * 写一条字幕样本（tx3g 格式：uint16 大端长度 + UTF-8 文本）。
 *
 * @param text        UTF-8 文本（固定文字或 ASR 结果）
 * @param pts_ms      会话时间轴上的起点（ms）
 * @param duration_ms 这条字幕显示多久（ms）
 * @return 0 成功，<0 失败（没有字幕流时会返回 -1）
 */
/** Java 侧设置要显示的字幕文本（空 = 清除）。只存文本，不立刻写样本。 */
void set_subtitle_text(const char* text) {
    if (text == nullptr || text[0] == '\0') {
        subtitle_text[0] = '\0';
        subtitle_has_text = false;
        LOGI("subtitle text cleared");
        return;
    }
    snprintf(subtitle_text, sizeof(subtitle_text), "%s", text);
    subtitle_has_text = true;
    LOGI("subtitle text set: %s", subtitle_text);
}

int write_subtitle_frame(const char* text, int64_t pts_ms, int64_t duration_ms) {
    WriterGuard guard;
    if (!format_ctx || !subtitle_stream || subtitle_stream_index < 0 || text == nullptr) {
        return -1;
    }
    const int text_len = (int)strlen(text);
    if (text_len <= 0 || text_len > 60000) return -1;

    const int sample_size = 2 + text_len;
    uint8_t* buf = (uint8_t*)av_malloc(sample_size);
    if (!buf) return -1;
    buf[0] = (uint8_t)((text_len >> 8) & 0xFF);
    buf[1] = (uint8_t)(text_len & 0xFF);
    memcpy(buf + 2, text, text_len);

    AVPacket* pkt = av_packet_alloc();
    if (!pkt) {
        av_free(buf);
        return -1;
    }
    if (av_packet_from_data(pkt, buf, sample_size) < 0) {
        av_free(buf);
        av_packet_free(&pkt);
        return -1;
    }

    pkt->stream_index = subtitle_stream_index;
    pkt->pts = pkt->dts = av_rescale_q(pts_ms, {1, 1000}, subtitle_stream->time_base);
    pkt->duration = av_rescale_q(duration_ms, {1, 1000}, subtitle_stream->time_base);

    pthread_mutex_lock(&write_mutex);
    int ret = av_interleaved_write_frame(format_ctx, pkt);
    pthread_mutex_unlock(&write_mutex);
    av_packet_free(&pkt);
    if (ret < 0) {
        LOGV("write_subtitle_frame failed: %d", ret);
    }
    return ret;
}

/**
 * 自定义写入回调 - 捕获发送的数据包
 */
static int write_packet_callback(void* opaque, const uint8_t* buf, int buf_size) {
    LOGV("write_packet_callback called, size=%d", buf_size);

    if (PUSHER_VERBOSE_LOG && buf_size > 0) {
        char hex[64] = {0};
        int print_len = buf_size > 16 ? 16 : buf_size;
        for (int i = 0; i < print_len; i++) {
            sprintf(hex + i * 3, "%02x ", buf[i]);
        }
        LOGV("write_packet_callback data: %s", hex);
    }

    int64_t ts_us = av_gettime();
    if (g_stream_start_time == 0) g_stream_start_time = ts_us;
    int64_t ts_ms = (ts_us - g_stream_start_time) / 1000;
    int copy_len = buf_size > 16 ? 16 : buf_size;

    if (copy_len > 0) {
        java_on_send_callback(buf, buf_size, ts_ms);
    }

    // 本地录制：直接写 fd（调用方 write_mutex 已覆盖，不会与另一路音频/视频交错）
    if (record_fd >= 0 && buf_size > 0) {
        int off = 0;
        while (off < buf_size) {
            ssize_t n = write(record_fd, buf + off, (size_t)(buf_size - off));
            if (n > 0) {
                off += (int)n;
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            LOGE("record write failed: %s, recording stopped", strerror(errno));
            close(record_fd);
            record_fd = -1;
            break;
        }
        record_bytes += off;
    }

    AVIOContext* ctx = (AVIOContext*)opaque;
    if (ctx == nullptr) {
        // 只写本地文件（协议=关闭）：没有网络对端，假装写成功
        return buf_size;
    }
    return ctx->write_packet(ctx->opaque, buf, buf_size);
}

/**
 * 创建带有自定义回调的 AVIOContext
 *
 * 这个上下文是纯写入的（write_flag=1），读取回调不会被调用，
 * 所以不再注册 read 回调，也不再维护接收方向的 JNI 回调。
 */
static AVIOContext* create_hooked_avio_context(AVIOContext* real_ctx) {
    // real_ctx 允许为空："协议=关闭"时只写本地文件（fd 在 write_packet_callback 里写），
    // 没有网络对端。此时 hook 依然必须装上，否则封装字节无处可去、也录不到。
    LOGI("create_hooked_avio_context called (real=%p)", real_ctx);

    // 分配缓冲区
    size_t buffer_size = 4096;
    uint8_t* buffer = (uint8_t*)av_malloc(buffer_size);
    if (!buffer) {
        LOGE("create_hooked_avio_context: av_malloc failed");
        return nullptr;
    }

    // 创建新的 AVIOContext，使用自定义回调
    AVIOContext* hooked_ctx = avio_alloc_context(
            buffer,
            buffer_size,
            1,  // 可写
            real_ctx,
            nullptr,               // read_packet：写模式用不到
            write_packet_callback,
            nullptr                // seek 回调不需要
    );

    if (!hooked_ctx) {
        LOGE("avio_alloc_context failed, freeing buffer to avoid leak");
        av_free(buffer);
        return nullptr;
    }

    LOGI("create_hooked_avio_context done, hooked_ctx=%p", hooked_ctx);
    return hooked_ctx;
}

/**
 * 处理 CSD 数据，收集 SPS/PPS 并设置为 extradata
 */
/**
 * 去掉 RBSP 的 emulation prevention bytes（00 00 03 -> 00 00），只取前 dst_cap 字节。
 * HEVC/H.264 的 SPS 头字段按固定偏移读取，必须先去转义，否则插入了 0x03 会导致字段错位。
 */
static void unescape_rbsp(const uint8_t* src, int src_len, uint8_t* dst, int dst_cap, int* out_len) {
    int j = 0;
    for (int i = 0; i < src_len && j < dst_cap; i++) {
        if (i >= 2 && src[i] == 0x03 && src[i - 1] == 0x00 && src[i - 2] == 0x00) {
            continue;
        }
        dst[j++] = src[i];
    }
    *out_len = j;
}

/**
 * 构建 HEVCDecoderConfigurationRecord (hvcC)，字段定义见 ISO/IEC 14496-15 Annex E。
 * 只填必要字段：VPS/SPS/PPS 三个数组 + 从 SPS 头部取的 profile/tier/level。
 */
static uint8_t* build_hevc_extradata(int* out_size) {
    uint8_t sps_hdr[32];
    int sps_hdr_len = 0;
    int copy_len = sps_size > (int)sizeof(sps_hdr) ? (int)sizeof(sps_hdr) : sps_size;
    unescape_rbsp(sps_buffer, copy_len, sps_hdr, (int)sizeof(sps_hdr), &sps_hdr_len);
    if (sps_hdr_len < 13) {
        LOGE("HEVC SPS too short (%d bytes) to build hvcC", sps_hdr_len);
        return nullptr;
    }

    int total = 23 + (5 + vps_size) + (5 + sps_size) + (5 + pps_size);
    uint8_t* extradata = (uint8_t*)av_malloc(total + AV_INPUT_BUFFER_PADDING_SIZE);
    if (!extradata) {
        LOGE("av_malloc hvcC failed");
        return nullptr;
    }
    memset(extradata, 0, total + AV_INPUT_BUFFER_PADDING_SIZE);

    int o = 0;
    extradata[o++] = 0x01;          // configurationVersion
    extradata[o++] = sps_hdr[1];    // general_profile_space / tier_flag / profile_idc
    for (int i = 2; i <= 5; i++) extradata[o++] = sps_hdr[i];   // general_profile_compatibility_flags
    for (int i = 6; i <= 11; i++) extradata[o++] = sps_hdr[i];  // general_constraint_indicator_flags
    extradata[o++] = sps_hdr[12];   // general_level_idc
    extradata[o++] = 0xF0;          // min_spatial_segmentation_idc（高 4 位保留）
    extradata[o++] = 0x00;
    extradata[o++] = 0xFC;          // parallelismType
    extradata[o++] = 0xFC | 0x01;   // chromaFormat = 1 (4:2:0)
    extradata[o++] = 0xF8;          // bitDepthLumaMinus8 = 0
    extradata[o++] = 0xF8;          // bitDepthChromaMinus8 = 0
    extradata[o++] = 0x00;          // avgFrameRate
    extradata[o++] = 0x00;
    extradata[o++] = 0x03;          // lengthSizeMinusOne=3，时间层字段为 0
    extradata[o++] = 0x03;          // numOfArrays = 3

    const uint8_t* nals[3] = { vps_buffer, sps_buffer, pps_buffer };
    const int sizes[3] = { vps_size, sps_size, pps_size };
    const int types[3] = { 32, 33, 34 };  // VPS / SPS / PPS
    for (int a = 0; a < 3; a++) {
        extradata[o++] = (uint8_t)(0x80 | types[a]);  // array_completeness=1 + NAL_unit_type
        extradata[o++] = 0x00;                        // numNalus = 1 (big endian)
        extradata[o++] = 0x01;
        extradata[o++] = (sizes[a] >> 8) & 0xFF;      // nalUnitLength (big endian)
        extradata[o++] = sizes[a] & 0xFF;
        memcpy(extradata + o, nals[a], sizes[a]);
        o += sizes[a];
    }

    *out_size = o;
    return extradata;
}

/**
 * 处理 CSD 数据，收集 VPS/SPS/PPS 并设置成 extradata。
 * H.264 产出 AVCDecoderConfigurationRecord，H.265 产出 hvcC。
 */
static int process_csd_data(uint8_t* data, int size) {
    int pos = 0;
    while (pos < size) {
        int start_code_len = 0;
        if (pos + 3 < size && data[pos] == 0x00 && data[pos+1] == 0x00 && data[pos+2] == 0x01) {
            start_code_len = 3;
        } else if (pos + 4 < size && data[pos] == 0x00 && data[pos+1] == 0x00 && data[pos+2] == 0x00 && data[pos+3] == 0x01) {
            start_code_len = 4;
        } else {
            pos++;
            continue;
        }

        int nal_header = data[pos + start_code_len];
        // H.264: nal_type = b & 0x1F；HEVC: nal_type = (b >> 1) & 0x3F
        int nal_type = (g_video_codec == 1) ? ((nal_header >> 1) & 0x3F) : (nal_header & 0x1F);
        int start = pos + start_code_len;
        int end = start + 1;
        while (end < size - 3) {
            if (data[end] == 0x00 && data[end+1] == 0x00 &&
                ((data[end+2] == 0x01) || (data[end+2] == 0x00 && data[end+3] == 0x01))) {
                break;
            }
            end++;
        }
        int nal_size = end - start;
        if (nal_size <= 0) break;

        uint8_t** target = nullptr;
        int* target_size = nullptr;
        if (g_video_codec == 1) {
            if (nal_type == 32) { target = &vps_buffer; target_size = &vps_size; }
            else if (nal_type == 33) { target = &sps_buffer; target_size = &sps_size; }
            else if (nal_type == 34) { target = &pps_buffer; target_size = &pps_size; }
        } else {
            if (nal_type == 7) { target = &sps_buffer; target_size = &sps_size; }
            else if (nal_type == 8) { target = &pps_buffer; target_size = &pps_size; }
        }

        if (target != nullptr) {
            if (*target) free(*target);
            *target = (uint8_t*)malloc(nal_size);
            if (*target) {
                memcpy(*target, data + start, nal_size);
                *target_size = nal_size;
                LOGV("Collected NAL type %d, size=%d", nal_type, nal_size);
            }
        }

        pos = end;
    }

    if (extradata_sent || video_stream == nullptr || video_stream->codecpar == nullptr) {
        return 0;
    }

    uint8_t* extradata = nullptr;
    int extradata_len = 0;

    if (g_video_codec == 1) {
        if (vps_buffer && sps_buffer && pps_buffer && vps_size > 0 && sps_size > 13 && pps_size > 0) {
            extradata = build_hevc_extradata(&extradata_len);
        } else {
            LOGV("HEVC CSD incomplete (vps=%d sps=%d pps=%d)", vps_size, sps_size, pps_size);
        }
    } else if (sps_buffer && pps_buffer && sps_size >= 4 && pps_size >= 1) {
        // 构建 AVCDecoderConfigurationRecord
        extradata_len = 11 + sps_size + pps_size;
        extradata = (uint8_t*)av_malloc(extradata_len + AV_INPUT_BUFFER_PADDING_SIZE);
        if (extradata) {
            memset(extradata, 0, extradata_len + AV_INPUT_BUFFER_PADDING_SIZE);
            int offset = 0;
            extradata[offset++] = 0x01;
            extradata[offset++] = sps_buffer[1];   // profile
            extradata[offset++] = sps_buffer[2];   // compat
            extradata[offset++] = sps_buffer[3];   // level
            extradata[offset++] = 0xFC | 0x03;
            extradata[offset++] = 0xE0 | 0x01;
            extradata[offset++] = (sps_size >> 8) & 0xFF;
            extradata[offset++] = sps_size & 0xFF;
            memcpy(extradata + offset, sps_buffer, sps_size);
            offset += sps_size;
            extradata[offset++] = 0x01;
            extradata[offset++] = (pps_size >> 8) & 0xFF;
            extradata[offset++] = pps_size & 0xFF;
            memcpy(extradata + offset, pps_buffer, pps_size);
            offset += pps_size;
            extradata_len = offset;
        }
    }

    if (extradata != nullptr) {
        if (video_stream->codecpar->extradata) {
            av_free(video_stream->codecpar->extradata);
        }
        video_stream->codecpar->extradata = extradata;
        video_stream->codecpar->extradata_size = extradata_len;
        extradata_sent = 1;
        LOGI("Video extradata set (%s), size=%d",
             g_video_codec == 1 ? "hvcC" : "avcC", extradata_len);
        LOGI("extradata detail: vps=%d sps=%d pps=%d", vps_size, sps_size, pps_size);
    }

    // 收集缓冲用完就释放，避免下次会话混入旧数据
    if (vps_buffer) { free(vps_buffer); vps_buffer = nullptr; vps_size = 0; }
    if (sps_buffer) { free(sps_buffer); sps_buffer = nullptr; sps_size = 0; }
    if (pps_buffer) { free(pps_buffer); pps_buffer = nullptr; pps_size = 0; }

    return 0;
}

int write_video_frame(uint8_t* data, int size, int64_t pts_ms, int is_key_frame, int is_csd) {
    // 先占写入名额：close 会等所有写入者退出后才释放资源
    WriterGuard guard;
    if (!guard.ok) {
        LOGE("write_video_frame: pusher is closing, drop frame");
        return -1;
    }

    // 注意：这里必须同时检查 video_stream，close 过程中 format_ctx 与 video_stream
    // 的置空不是原子的，只检查 format_ctx 会踩到空指针。
    if (!format_ctx || !video_stream || video_stream_index < 0) {
        LOGE("Video stream not initialized");
        return -1;
    }

    if (PUSHER_VERBOSE_LOG && size > 0) {
        // 缓冲区必须容纳 32 组 "%02x " 再加结尾 '\0'：32*3+1 = 97 字节。
        // 旧代码用 char hex[96]，最后一组 sprintf 会越界写 1 字节（踩栈，偶现崩溃）。
        char hex[32 * 3 + 1] = {0};
        int print_len = size > 32 ? 32 : size;
        for (int i = 0; i < print_len; i++) {
            sprintf(hex + i * 3, "%02x ", data[i]);
        }
        LOGV("writeVideoFrame：timestamp=%lld size=%d pts=%lld key=%d data=%s",
             (long long)pts_ms, size, (long long)pts_ms * video_stream->time_base.den / 1000,
             is_key_frame, hex);
    }

    // CSD（SPS/PPS 或 VPS/SPS/PPS）：由 Java 显式标记，不再靠 pts==0 && size<100 猜
    // （旧启发式会把 pts 恰好为 0 的首帧误判成 CSD，也会在 CSD 超过 100 字节时漏判）
    // 第一个 CSD：用来构造 extradata（avcC / hvcC）
    if (is_csd && !extradata_sent) {
        LOGI("Processing CSD data, size=%d", size);
        process_csd_data(data, size);
        // 序列头也送去预览，便于确认这条回调是通的
        java_on_mux_callback(data, size, 0);
        return 0;
    }
    // 之后再次到达的 CSD【必须按普通帧写出，当作“带内重发参数集”】：
    // 我们的编码器 CSD 是在 avformat_write_header 之后才产生的，
    // FLV 序列头(avcC)这一份参数集在本场景下并不能可靠送达接收端，
    // 接收端实际依赖的就是这个带内 SPS/PPS 包（RTMP 完全合法）。
    // 丢过它一次，接收端就报 "non-existing PPS 0 referenced" / "no frame!"。
    if (is_csd) {
        LOGI("CSD (in-band repeat) -> write as normal packet, size=%d", size);
    }

    if (!extradata_sent) {
        LOGV("Waiting for extradata, skipping frame");
        return 0;
    }

    // PTS 由 Java 侧用统一时钟算好（相对会话起点，非负），这里只做保护性 clamp
    int64_t adjusted_pts_ms = pts_ms > 0 ? pts_ms : 0;

    AVPacket* pkt = av_packet_alloc();
    if (!pkt) {
        LOGE("Failed to allocate packet");
        return -1;
    }

    pkt->data = data;
    pkt->size = size;
    pkt->stream_index = video_stream_index;

    int64_t time_base_den = video_stream->time_base.den;
    int64_t pts = adjusted_pts_ms * time_base_den / 1000;

    pkt->pts = pts;
    pkt->dts = pts;
    pkt->duration = time_base_den / video_fps;

    if (is_key_frame) {
        pkt->flags |= AV_PKT_FLAG_KEY;
    }

    pthread_mutex_lock(&write_mutex);
    int ret = av_interleaved_write_frame(format_ctx, pkt);
    pthread_mutex_unlock(&write_mutex);

    // 每一帧都写一条字幕样本：文本轨变成"密集轨"，分片截断时
    // track_duration 每帧都在推进，不会再出现负时长（稀疏轨才会踩断言）。
    // 时长给一帧，连着写 = 常显。
    // 字幕轨停用时 subtitle_stream_index 为 -1，这里自然不会写
    if (ret >= 0 && subtitle_has_text && subtitle_stream_index >= 0) {
        int64_t dur = (video_fps > 0) ? (1000 / video_fps) : 33;
        if (dur < 1) dur = 1;
        if (write_subtitle_frame(subtitle_text, pts_ms, dur) >= 0) {
            last_subtitle_pts_ms = pts_ms;
        }
    }

    if (ret < 0) {
        char errbuf[256];
        av_strerror(ret, errbuf, sizeof(errbuf));
        LOGE("Error writing video frame: %d (%s)", ret, errbuf);
        set_last_error(errbuf);
        java_on_rtmp_error_callback(errbuf);
    } else {
        // 封装数据预览：把交给 muxer 的包（前若干字节）回调给 Java
        java_on_mux_callback(data, size, adjusted_pts_ms);
    }

    av_packet_free(&pkt);
    return ret;
}

/**
 * 写入音频帧
 */
int write_audio_frame(uint8_t* data, int size, int64_t pts_ms) {
    WriterGuard guard;
    if (!guard.ok) {
        LOGE("write_audio_frame: pusher is closing, drop frame");
        return -1;
    }

    if (!format_ctx || !audio_stream || audio_stream_index < 0) {
        LOGE("Audio stream not initialized");
        return -1;
    }

    // PTS 由 Java 侧用统一时钟算好（相对会话起点，非负）
    int64_t adjusted_pts_ms = pts_ms > 0 ? pts_ms : 0;

    AVPacket* pkt = av_packet_alloc();
    if (!pkt) {
        LOGE("Failed to allocate packet");
        return -1;
    }

    pkt->data = data;
    pkt->size = size;
    pkt->stream_index = audio_stream_index;

    int64_t time_base_den = audio_stream->time_base.den;
    int64_t pts = adjusted_pts_ms * time_base_den / 1000;

    LOGV("writeAudioFrame：timestamp=%lld size=%d pts=%lld",
         (long long)pts_ms, size, (long long)pts);

    pkt->pts = pts;
    pkt->dts = pts;

    pthread_mutex_lock(&write_mutex);
    int ret = av_interleaved_write_frame(format_ctx, pkt);
    pthread_mutex_unlock(&write_mutex);
    if (ret < 0) {
        char errbuf[256];
        av_strerror(ret, errbuf, sizeof(errbuf));
        LOGE("Error writing audio frame: %d (%s)", ret, errbuf);
        set_last_error(errbuf);
        java_on_rtmp_error_callback(errbuf);
    } else {
        java_on_mux_callback(data, size, adjusted_pts_ms);
    }

    av_packet_free(&pkt);
    return ret;
}

/**
 * 释放已分配的 FFmpeg 全局资源（幂等，可在 init 失败路径和 close 路径重复调用）。
 *
 * 旧代码在 init 的任何失败分支（找不到 muxer、打不开 URL、写 header 失败等）
 * 都直接 return -1，把 format_ctx / real_avio_ctx / 两个 stream 泄漏在全局变量里，
 * 下一次 init 直接覆盖指针，导致资源泄漏以及后续在“半初始化”上下文上做 trailer/free。
 */
static void release_ffmpeg_state(bool write_trailer) {
    if (format_ctx) {
        if (write_trailer && header_written) {
            int ret = av_write_trailer(format_ctx);
            if (ret < 0) {
                char errbuf[256];
                av_strerror(ret, errbuf, sizeof(errbuf));
                LOGE("av_write_trailer failed: %d (%s)", ret, errbuf);
            }
        }

        // 释放 video extradata（由 process_csd_data 分配），必须在 format_ctx 之前
        if (video_stream && video_stream->codecpar && video_stream->codecpar->extradata) {
            av_freep(&video_stream->codecpar->extradata);
            video_stream->codecpar->extradata_size = 0;
        }

        // 只 free 我们 av_malloc 出来的 hooked 上下文；real 上下文单独 avio_close
        if (hooked_avio_ctx) {
            if (hooked_avio_ctx->buffer) {
                av_free(hooked_avio_ctx->buffer);
            }
            av_free(hooked_avio_ctx);
            hooked_avio_ctx = nullptr;
        }

        // 解除 format_ctx 对 pb 的引用，避免 avformat_free_context 误用已释放的指针
        format_ctx->pb = nullptr;
        avformat_free_context(format_ctx);
        format_ctx = nullptr;
    }

    if (real_avio_ctx) {
        avio_close(real_avio_ctx);
        real_avio_ctx = nullptr;
    }

    video_stream = nullptr;
    audio_stream = nullptr;
    subtitle_stream = nullptr;
    video_stream_index = -1;
    audio_stream_index = -1;
    subtitle_stream_index = -1;
    header_written = false;
    last_subtitle_pts_ms = -1;

    reset_pts_base();
    reset_sps_pps_state();
}

/**
 * 初始化 FFmpeg 推流器
 */
int init_ffmpeg_pusher(const char* url, const char* format_name,
                       int video_width, int video_height,
                       int sample_rate, int channel_count,
                       int fps, int video_bitrate, int audio_bitrate,
                       int video_codec, int enable_subtitle) {

    LOGI("=== init_ffmpeg_pusher start ===");
    LOGI("url: %s", url ? url : "(null)");
    LOGI("format_name: %s", format_name ? format_name : "(null)");
    LOGI("video: %dx%d", video_width, video_height);
    LOGI("audio: %dHz %dch", sample_rate, channel_count);
    LOGI("fps: %d, video bitrate: %d, audio bitrate: %d, codec: %s",
         fps, video_bitrate, audio_bitrate, video_codec == 1 ? "H.265" : "H.264");

    // 用调用方传入的真实参数，避免流头里 advertise 错误的帧率/码率
    video_fps = (fps > 0) ? fps : 30;
    g_video_codec = (video_codec == 1) ? 1 : 0;
    set_last_error("");

    // 清掉可能残留的上一次会话（正常流程下 Java 侧会先 close，这里只做兜底）。
    // 注意：必须和正常关闭一样先禁止写入并等所有写者退出，否则会和正在写包的线程并发 free；
    // 残留会话也不再写 trailer（状态可能已经不一致，写 trailer 只会崩在 av_write_trailer 里）。
    if (format_ctx || real_avio_ctx || hooked_avio_ctx) {
        LOGE("init_ffmpeg_pusher: leftover state found, releasing before re-init");
        pthread_mutex_lock(&lifecycle_mutex);
        pusher_closing = true;
        pthread_mutex_unlock(&lifecycle_mutex);
        wait_writers_done();
        release_ffmpeg_state(false);
        pthread_mutex_lock(&lifecycle_mutex);
        pusher_closing = false;
        pthread_mutex_unlock(&lifecycle_mutex);
    }

    pthread_mutex_lock(&lifecycle_mutex);
    pusher_closing = false;
    pthread_mutex_unlock(&lifecycle_mutex);

    hooked_avio_ctx = nullptr;
    real_avio_ctx = nullptr;

    avformat_network_init();
    LOGI("avformat_network_init done");

    const AVOutputFormat* output_format = av_guess_format(format_name, nullptr, nullptr);
    if (!output_format) {
        LOGE("Cannot find output format: %s", format_name);
        snprintf(g_last_error, sizeof(g_last_error), "不支持的封装格式: %s", format_name ? format_name : "(null)");
        release_ffmpeg_state(false);
        return -1;
    }
    LOGI("Output format found: %s", output_format->name);

    int ret = avformat_alloc_output_context2(&format_ctx, output_format, format_name, url);
    if (ret < 0 || !format_ctx) {
        char errbuf[256];
        av_strerror(ret, errbuf, sizeof(errbuf));
        LOGE("Cannot allocate output context: %d (%s)", ret, errbuf);
        set_last_error(errbuf);
        release_ffmpeg_state(false);
        return -1;
    }
    LOGI("Output context allocated");

    // 添加视频流
    if (video_width > 0 && video_height > 0) {
        video_stream = avformat_new_stream(format_ctx, nullptr);
        if (!video_stream) {
            LOGE("Cannot create video stream");
            release_ffmpeg_state(false);
            return -1;
        }
        video_stream_index = video_stream->index;

        AVCodecParameters* codecpar = video_stream->codecpar;
        codecpar->codec_type = AVMEDIA_TYPE_VIDEO;
        codecpar->codec_id = (g_video_codec == 1) ? AV_CODEC_ID_HEVC : AV_CODEC_ID_H264;
        codecpar->width = video_width;
        codecpar->height = video_height;
        codecpar->format = AV_PIX_FMT_YUV420P;
        codecpar->bit_rate = (video_bitrate > 0) ? video_bitrate : 2500000;

        video_stream->time_base = {video_time_base_num, video_time_base_den};
        video_stream->avg_frame_rate = {video_fps, 1};

        LOGI("Video stream added: index=%d, %dx%d", video_stream_index, video_width, video_height);
    }

    // 添加音频流
    if (sample_rate > 0 && channel_count > 0) {
        audio_stream = avformat_new_stream(format_ctx, nullptr);
        if (!audio_stream) {
            LOGE("Cannot create audio stream");
            release_ffmpeg_state(false);
            return -1;
        }
        audio_stream_index = audio_stream->index;

        AVCodecParameters* codecpar = audio_stream->codecpar;
        codecpar->codec_type = AVMEDIA_TYPE_AUDIO;
        codecpar->codec_id = AV_CODEC_ID_AAC;
        codecpar->sample_rate = sample_rate;
        codecpar->ch_layout.nb_channels = channel_count;
        codecpar->format = 0;  // 压缩音频不设 sample format，让 FFmpeg自行推导
        codecpar->bit_rate = (audio_bitrate > 0) ? audio_bitrate : 128000;

        // 设置 AAC AudioSpecificConfig (ASC) 作为 extradata
        int asc_size = 0;
        uint8_t* asc = build_aac_asc(sample_rate, channel_count, &asc_size);
        if (asc && asc_size > 0) {
            codecpar->extradata = asc;
            codecpar->extradata_size = asc_size;
            LOGI("Audio extradata (ASC) set: %02x %02x", asc[0], asc[1]);
        }

        audio_stream->time_base = {audio_time_base_num, sample_rate};
        audio_time_base_den = sample_rate;

        LOGI("Audio stream added: index=%d, %dHz, %dch", audio_stream_index, sample_rate, channel_count);
    }

    // 添加独立字幕轨（tx3g / mov_text）：只有 mp4/mov(fMP4) 容器支持文本轨，
    // flv（RTMP）和 mpegts 都没有独立字幕轨，传进去只会让写头失败，所以这里直接跳过。
    const bool container_supports_subtitle =
            (output_format != nullptr && output_format->name != nullptr &&
             (strcmp(output_format->name, "mp4") == 0 || strcmp(output_format->name, "mov") == 0));
    // 【已停用】独立文本轨在 fMP4 下必崩：movenc 的 get_cluster_duration() 在分片边界上
    // 会把文本轨的簇时长算成负值，触发 av_assert0(next_dts >= 0) → abort。
    // 实测"每 2 秒一条"和"每帧一条"都会崩（23:35 / 23:36 / 23:43 / 23:53 四次），
    // 说明是 movenc 记账本身的问题，不是样本密度问题。
    // 想重新打开：置 true（需要先给 FFmpeg 打补丁或换方案），见聊天记录里的备选路线。
    const bool subtitle_track_enabled = false;
    if (enable_subtitle && !container_supports_subtitle) {
        LOGI("Subtitle: container doesn't support a text track, skipped");
    }
    if (enable_subtitle && subtitle_track_enabled && container_supports_subtitle) {
        subtitle_stream = avformat_new_stream(format_ctx, nullptr);
        if (subtitle_stream) {
            subtitle_stream_index = subtitle_stream->index;
            AVCodecParameters* codecpar = subtitle_stream->codecpar;
            codecpar->codec_type = AVMEDIA_TYPE_SUBTITLE;
            codecpar->codec_id = AV_CODEC_ID_MOV_TEXT;
            codecpar->codec_tag = MKTAG('t', 'x', '3', 'g');
            subtitle_stream->time_base = {1, 1000};
            LOGI("Subtitle stream added: index=%d (tx3g)", subtitle_stream_index);
        } else {
            LOGE("Cannot create subtitle stream, continue without subtitle");
        }
    } else if (enable_subtitle) {
        LOGI("Subtitle skipped: container '%s' does not support a text track",
             output_format && output_format->name ? output_format->name : "?");
    }

    // 打开输出 URL - 使用自定义 AVIOContext 捕获数据。
    // url 为空 = "只写本地文件"模式（协议选"关闭"）：不建网络连接，只走录制那条 fd。
    const bool has_url = (url != nullptr && url[0] != '\0');
    if (has_url && !(format_ctx->flags & AVFMT_NOFILE)) {
        LOGI("Opening URL: %s", url);

        // 设置 rw_timeout：网络不可达/对端不响应时不要让读写无限阻塞
        // （否则 stopPush / onPause / 退出应用都会长时间卡住）
        AVDictionary* io_opts = nullptr;
        av_dict_set(&io_opts, "rw_timeout", "5000000", 0);  // 5s

        ret = avio_open2(&real_avio_ctx, url, AVIO_FLAG_WRITE, nullptr, &io_opts);
        av_dict_free(&io_opts);
        if (ret < 0) {
            char errbuf[256];
            av_strerror(ret, errbuf, sizeof(errbuf));
            LOGE("Cannot open URL: %s, error: %d (%s)", url, ret, errbuf);
            // 这里通常就是“服务器没开/地址端口不对/网络不通”，把原因带上
            const std::string protos = supported_output_protocols();
            snprintf(g_last_error, sizeof(g_last_error), "打开地址失败(%s): %s（本库支持: %s）",
                     url ? url : "?", errbuf, protos.c_str());
            release_ffmpeg_state(false);
            return -1;
        }
        LOGI("URL opened successfully");

        // 创建自定义 AVIOContext 来捕获数据
        // 注意：如果 avio_alloc_context 失败，format_ctx->pb 会指向 real_avio_ctx
        // release_ffmpeg_state 通过 hooked_avio_ctx 区分两种情况，只 free 真正分配过的那个
        AVIOContext* hooked_pb = create_hooked_avio_context(real_avio_ctx);
        if (hooked_pb) {
            hooked_avio_ctx = hooked_pb;
            format_ctx->pb = hooked_pb;
            LOGI("Custom AVIOContext installed for data capture");
        } else {
            format_ctx->pb = real_avio_ctx;
            LOGE("Failed to create custom AVIOContext, using default");
        }
    }

    // 封装层参数。
    // 注意：tune/preset/profile 是 x264 编码器选项，容器层不做编码，传进来只会被忽略
    // （旧代码残留），已删除。
    // fMP4/MP4：输出是不可 seek 的（hooked AVIO 没有 seek 回调），必须用分片 MP4，
    // 否则 MP4 muxer 会以 "muxer does not support non seekable output" 直接失败。
    AVDictionary* opts = nullptr;
    bool is_mp4 = false;
    if (output_format->name != nullptr) {
        is_mp4 = (strcmp(output_format->name, "mp4") == 0) ||
                 (strcmp(output_format->name, "mov") == 0);
    }
    if (is_mp4) {
        av_dict_set(&opts, "movflags", "frag_keyframe+empty_moov+default_base_moof", 0);
        LOGI("fMP4 mode enabled (frag_keyframe+empty_moov) for non-seekable output");
    }

    LOGI("Writing header...");
    ret = avformat_write_header(format_ctx, &opts);
    av_dict_free(&opts);

    if (ret < 0) {
        char errbuf[256];
        av_strerror(ret, errbuf, sizeof(errbuf));
        LOGE("Cannot write header: %d (%s)", ret, errbuf);
        snprintf(g_last_error, sizeof(g_last_error), "写流头失败: %s", errbuf);
        release_ffmpeg_state(false);
        return -1;
    }

    header_written = true;
    reset_pts_base();

    LOGI("FFmpeg pusher initialized successfully");
    return 0;
}

/**
 * 关闭推流器并释放资源。
 *
 * 关键点一：必须先禁止新的写入，并等待所有正在写入的线程（视频/音频）退出，
 *           否则会与 write_video_frame / write_audio_frame 里的
 *           av_interleaved_write_frame 并发访问/释放同一个 AVFormatContext。
 * 关键点二：hooked_avio_ctx 与 real_avio_ctx 必须分别处理（hooked 自己 av_malloc，
 *           real 要走 avio_close），否则会 double-free。
 */
void close_ffmpeg_pusher() {
    LOGI("close_ffmpeg_pusher called, hooked=%p real=%p fmt=%p active_writers=%d",
         hooked_avio_ctx, real_avio_ctx, format_ctx, active_writers);

    // 1. 禁止新写入
    pthread_mutex_lock(&lifecycle_mutex);
    pusher_closing = true;
    pthread_mutex_unlock(&lifecycle_mutex);

    // 2. 等已在写入的线程退出（写者退出时不再引用 format_ctx）
    wait_writers_done();

    // 3. 释放
    release_ffmpeg_state(true);

    // 4. 允许下一次 init
    pthread_mutex_lock(&lifecycle_mutex);
    pusher_closing = false;
    pthread_mutex_unlock(&lifecycle_mutex);

    LOGI("FFmpeg pusher closed successfully");
}