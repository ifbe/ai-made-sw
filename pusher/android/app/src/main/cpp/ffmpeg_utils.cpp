#include <jni.h>
#include <android/log.h>
#include <string>
#include <cstring>
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

// 全局变量定义
extern JavaVM* g_jvm;
extern jobject g_listener;
jmethodID g_onSendData = nullptr;
jmethodID g_onRecvData = nullptr;
static int64_t g_stream_start_time = 0;  // 流开始的绝对时间（微秒）

static AVIOContext* real_avio_ctx = nullptr;
AVFormatContext* format_ctx = nullptr;
AVStream* video_stream = nullptr;
AVStream* audio_stream = nullptr;
int video_stream_index = -1;
int audio_stream_index = -1;
int video_time_base_num = 1;
int video_time_base_den = 90000;
int audio_time_base_num = 1;
int audio_time_base_den = 44100;
int video_fps = 30;
// SPS/PPS 收集缓冲区
static uint8_t* sps_buffer = nullptr;
static int sps_size = 0;
static uint8_t* pps_buffer = nullptr;
static int pps_size = 0;
static int extradata_sent = 0;

// 时间戳基准
static int64_t video_base_pts_ms = -1;
static int64_t audio_base_pts_ms = -1;

/**
 * 调整视频时间戳，从0开始
 */
static int64_t adjust_video_pts(int64_t pts_ms) {
    if (video_base_pts_ms == -1) {
        video_base_pts_ms = pts_ms;
        LOGI("Video base PTS set to %lld ms", (long long)video_base_pts_ms);
    }
    int64_t adjusted = pts_ms - video_base_pts_ms;
    return adjusted;
}

/**
 * 调整音频时间戳，从0开始
 */
static int64_t adjust_audio_pts(int64_t pts_ms) {
    if (audio_base_pts_ms == -1) {
        audio_base_pts_ms = pts_ms;
        LOGI("Audio base PTS set to %lld ms", (long long)audio_base_pts_ms);
    }
    int64_t adjusted = pts_ms - audio_base_pts_ms;
    return adjusted;
}

/**
 * 重置时间戳基准
 */
void reset_pts_base() {
    video_base_pts_ms = -1;
    audio_base_pts_ms = -1;
    g_stream_start_time = 0;
    LOGI("PTS base reset");
}

/**
 * 重置 SPS/PPS 收集状态
 */
void reset_sps_pps_state() {
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
    LOGI("SPS/PPS state reset");
}

/**
 * 自定义写入回调 - 捕获发送的数据包
 */
static int write_packet_callback(void* opaque, const uint8_t* buf, int buf_size) {
    LOGI("write_packet_callback called, size=%d", buf_size);

    if (buf_size > 0) {
        char hex[64] = {0};
        int print_len = buf_size > 16 ? 16 : buf_size;
        for (int i = 0; i < print_len; i++) {
            sprintf(hex + i * 3, "%02x ", buf[i]);
        }
        LOGI("write_packet_callback data: %s", hex);
    }

    int64_t ts_us = av_gettime();
    if (g_stream_start_time == 0) g_stream_start_time = ts_us;
    int64_t ts_ms = (ts_us - g_stream_start_time) / 1000;
    int copy_len = buf_size > 16 ? 16 : buf_size;

    if (copy_len > 0 && g_listener != nullptr) {
        JNIEnv* env = nullptr;
        if (g_jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            g_jvm->AttachCurrentThread(&env, nullptr);
        }

        if (env != nullptr) {
            jbyteArray data = env->NewByteArray(copy_len);
            env->SetByteArrayRegion(data, 0, copy_len, reinterpret_cast<const jbyte*>(buf));
            env->CallVoidMethod(g_listener, g_onSendData, data, ts_ms);
            env->DeleteLocalRef(data);
        }
    }

    AVIOContext* ctx = (AVIOContext*)opaque;
    return ctx->write_packet(ctx->opaque, buf, buf_size);
}

/**
 * 自定义读取回调 - 捕获接收的数据包
 */
static int read_packet_callback(void* opaque, uint8_t* buf, int buf_size) {
    AVIOContext* ctx = (AVIOContext*)opaque;
    int ret = ctx->read_packet(ctx->opaque, buf, buf_size);

    if (ret > 0 && g_listener != nullptr) {
        int64_t ts_us = av_gettime();
        if (g_stream_start_time == 0) g_stream_start_time = ts_us;
        int64_t ts_ms = (ts_us - g_stream_start_time) / 1000;

        int copy_len = ret > 16 ? 16 : ret;

        // 打印接收到的数据
        if (copy_len > 0) {
            char hex[64] = {0};
            for (int i = 0; i < copy_len; i++) {
                sprintf(hex + i * 3, "%02x ", buf[i]);
            }
            LOGI("read_packet_callback data: %s", hex);
        }

        JNIEnv* env = nullptr;
        if (g_jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
            g_jvm->AttachCurrentThread(&env, nullptr);
        }

        if (env != nullptr) {
            jbyteArray data = env->NewByteArray(copy_len);
            env->SetByteArrayRegion(data, 0, copy_len, reinterpret_cast<jbyte*>(buf));
            env->CallVoidMethod(g_listener, g_onRecvData, data, ts_ms);
            env->DeleteLocalRef(data);
        }
    }

    return ret;
}

/**
 * 创建带有自定义回调的 AVIOContext
 */
static AVIOContext* create_hooked_avio_context(AVIOContext* real_ctx) {
    if (real_ctx == nullptr) {
        return nullptr;
    }

    LOGI("create_hooked_avio_context called");

    // 分配缓冲区
    size_t buffer_size = 4096;
    uint8_t* buffer = (uint8_t*)av_malloc(buffer_size);

    // 创建新的 AVIOContext，使用自定义回调
    AVIOContext* hooked_ctx = avio_alloc_context(
            buffer,
            buffer_size,
            1,  // 可写
            real_ctx,
            read_packet_callback,
            write_packet_callback,
            nullptr  // seek 回调不需要
    );

    LOGI("create_hooked_avio_context done, hooked_ctx=%p", hooked_ctx);
    return hooked_ctx;
}

/**
 * 处理 CSD 数据，收集 SPS/PPS 并设置为 extradata
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

        int nal_type = data[pos + start_code_len] & 0x1F;
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

        if (nal_type == 7) {
            if (sps_buffer) free(sps_buffer);
            sps_buffer = (uint8_t*)malloc(nal_size);
            if (sps_buffer) {
                memcpy(sps_buffer, data + start, nal_size);
                sps_size = nal_size;
                LOGI("Collected SPS, size=%d", sps_size);
            }
        } else if (nal_type == 8) {
            if (pps_buffer) free(pps_buffer);
            pps_buffer = (uint8_t*)malloc(nal_size);
            if (pps_buffer) {
                memcpy(pps_buffer, data + start, nal_size);
                pps_size = nal_size;
                LOGI("Collected PPS, size=%d", pps_size);
            }
        }

        pos = end;
    }

    if (sps_buffer && pps_buffer && !extradata_sent) {
        // 构建 AVCDecoderConfigurationRecord
        uint8_t profile = sps_buffer[1];
        uint8_t compat = sps_buffer[2];
        uint8_t level = sps_buffer[3];

        int extradata_size = 7 + 2 + sps_size + 1 + 2 + pps_size;
        uint8_t* extradata = (uint8_t*)av_malloc(extradata_size + AV_INPUT_BUFFER_PADDING_SIZE);
        if (extradata) {
            int offset = 0;
            extradata[offset++] = 0x01;
            extradata[offset++] = profile;
            extradata[offset++] = compat;
            extradata[offset++] = level;
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

            if (video_stream->codecpar->extradata) {
                av_free(video_stream->codecpar->extradata);
            }
            video_stream->codecpar->extradata = extradata;
            video_stream->codecpar->extradata_size = offset;
            LOGI("AVCDecoderConfigurationRecord set, size=%d", offset);

            extradata_sent = 1;
        }

        free(sps_buffer);
        free(pps_buffer);
        sps_buffer = nullptr;
        pps_buffer = nullptr;
        sps_size = 0;
        pps_size = 0;

        return 0;
    }

    return 0;
}

int write_video_frame(uint8_t* data, int size, int64_t pts_ms, int is_key_frame) {
    if (!format_ctx || video_stream_index < 0) {
        LOGE("Video stream not initialized");
        return -1;
    }

    if (size > 0) {
        char hex[96] = {0};
        int print_len = size > 32 ? 32 : size;
        for (int i = 0; i < print_len; i++) {
            sprintf(hex + i * 3, "%02x ", data[i]);
        }
        LOGI("write_video_frame: size=%d, pts_ms=%lld (pts_ms*timebase=%lld), key=%d, data=%s",
             size, (long long)pts_ms, (long long)pts_ms * video_stream->time_base.den / 1000,
             is_key_frame, hex);
    }

    // 如果是 CSD 数据，处理 extradata
    if (pts_ms == 0 && size < 100 && !extradata_sent) {
        LOGI("Processing CSD data, size=%d", size);
        process_csd_data(data, size);
        return 0;
    }

    if (!extradata_sent) {
        LOGI("Waiting for extradata, skipping frame");
        return 0;
    }

    int64_t adjusted_pts_ms = adjust_video_pts(pts_ms);

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

    int ret = av_interleaved_write_frame(format_ctx, pkt);
    if (ret < 0) {
        char errbuf[256];
        av_strerror(ret, errbuf, sizeof(errbuf));
        LOGE("Error writing video frame: %d (%s)", ret, errbuf);
    }

    av_packet_free(&pkt);
    return ret;
}

/**
 * 写入音频帧
 */
int write_audio_frame(uint8_t* data, int size, int64_t pts_ms) {
    if (!format_ctx || audio_stream_index < 0) {
        LOGE("Audio stream not initialized");
        return -1;
    }

    int64_t adjusted_pts_ms = adjust_audio_pts(pts_ms);

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

    LOGI("write_audio_frame: size=%d, pts_ms=%lld, adjusted_pts_ms=%lld, pts_90k=%lld",
         size, (long long)pts_ms, (long long)adjusted_pts_ms, (long long)pts);

    pkt->pts = pts;
    pkt->dts = pts;

    int ret = av_interleaved_write_frame(format_ctx, pkt);
    if (ret < 0) {
        char errbuf[256];
        av_strerror(ret, errbuf, sizeof(errbuf));
        LOGE("Error writing audio frame: %d (%s)", ret, errbuf);
    }

    av_packet_free(&pkt);
    return ret;
}

/**
 * 初始化 FFmpeg 推流器
 */
int init_ffmpeg_pusher(const char* url, const char* format_name,
                       int video_width, int video_height,
                       int sample_rate, int channel_count) {

    LOGI("=== init_ffmpeg_pusher start ===");
    LOGI("url: %s", url);
    LOGI("format_name: %s", format_name);
    LOGI("video: %dx%d", video_width, video_height);
    LOGI("audio: %dHz %dch", sample_rate, channel_count);

    video_fps = 30;

    reset_sps_pps_state();

    avformat_network_init();
    LOGI("avformat_network_init done");

    const AVOutputFormat* output_format = av_guess_format(format_name, nullptr, nullptr);
    if (!output_format) {
        LOGE("Cannot find output format: %s", format_name);
        return -1;
    }
    LOGI("Output format found: %s", output_format->name);

    int ret = avformat_alloc_output_context2(&format_ctx, output_format, format_name, url);
    if (ret < 0 || !format_ctx) {
        char errbuf[256];
        av_strerror(ret, errbuf, sizeof(errbuf));
        LOGE("Cannot allocate output context: %d (%s)", ret, errbuf);
        return -1;
    }
    LOGI("Output context allocated");

    // 添加视频流
    if (video_width > 0 && video_height > 0) {
        video_stream = avformat_new_stream(format_ctx, nullptr);
        if (!video_stream) {
            LOGE("Cannot create video stream");
            return -1;
        }
        video_stream_index = video_stream->index;

        AVCodecParameters* codecpar = video_stream->codecpar;
        codecpar->codec_type = AVMEDIA_TYPE_VIDEO;
        codecpar->codec_id = AV_CODEC_ID_H264;
        codecpar->width = video_width;
        codecpar->height = video_height;
        codecpar->format = AV_PIX_FMT_YUV420P;
        codecpar->bit_rate = 2500000;

        video_stream->time_base = {video_time_base_num, video_time_base_den};
        video_stream->avg_frame_rate = {video_fps, 1};

        LOGI("Video stream added: index=%d, %dx%d", video_stream_index, video_width, video_height);
    }

    // 添加音频流
    if (sample_rate > 0 && channel_count > 0) {
        audio_stream = avformat_new_stream(format_ctx, nullptr);
        if (!audio_stream) {
            LOGE("Cannot create audio stream");
            return -1;
        }
        audio_stream_index = audio_stream->index;

        AVCodecParameters* codecpar = audio_stream->codecpar;
        codecpar->codec_type = AVMEDIA_TYPE_AUDIO;
        codecpar->codec_id = AV_CODEC_ID_AAC;
        codecpar->sample_rate = sample_rate;
        codecpar->ch_layout.nb_channels = channel_count;
        codecpar->format = AV_SAMPLE_FMT_FLTP;
        codecpar->bit_rate = 128000;

        audio_stream->time_base = {audio_time_base_num, sample_rate};
        audio_time_base_den = sample_rate;

        LOGI("Audio stream added: index=%d, %dHz, %dch", audio_stream_index, sample_rate, channel_count);
    }

    // 打开输出 URL - 使用自定义 AVIOContext 捕获数据
    if (!(format_ctx->flags & AVFMT_NOFILE)) {
        LOGI("Opening URL: %s", url);

        // 先打开原始 IO
        real_avio_ctx = nullptr;
        ret = avio_open2(&real_avio_ctx, url, AVIO_FLAG_WRITE, nullptr, nullptr);
        if (ret < 0) {
            char errbuf[256];
            av_strerror(ret, errbuf, sizeof(errbuf));
            LOGE("Cannot open URL: %s, error: %d (%s)", url, ret, errbuf);
            return -1;
        }
        LOGI("URL opened successfully");

        // 创建自定义 AVIOContext 来捕获数据
        AVIOContext* hooked_pb = create_hooked_avio_context(real_avio_ctx);
        if (hooked_pb) {
            format_ctx->pb = hooked_pb;
            LOGI("Custom AVIOContext installed for data capture");
        } else {
            format_ctx->pb = real_avio_ctx;
            LOGE("Failed to create custom AVIOContext, using default");
        }
    }

    // 设置编码器参数
    AVDictionary* opts = nullptr;
    av_dict_set(&opts, "tune", "zerolatency", 0);
    av_dict_set(&opts, "preset", "ultrafast", 0);
    av_dict_set(&opts, "profile", "baseline", 0);

    LOGI("Writing header...");
    ret = avformat_write_header(format_ctx, &opts);
    av_dict_free(&opts);

    if (ret < 0) {
        char errbuf[256];
        av_strerror(ret, errbuf, sizeof(errbuf));
        LOGE("Cannot write header: %d (%s)", ret, errbuf);
        return -1;
    }

    reset_pts_base();

    LOGI("FFmpeg pusher initialized successfully");
    return 0;
}

/**
 * 关闭推流器并释放资源
 */
void close_ffmpeg_pusher() {
    LOGI("close_ffmpeg_pusher called");

    if (format_ctx) {
        // 写入尾部
        int ret = av_write_trailer(format_ctx);
        if (ret < 0) {
            char errbuf[256];
            av_strerror(ret, errbuf, sizeof(errbuf));
            LOGE("av_write_trailer failed: %d (%s)", ret, errbuf);
        }

        // 关闭输出流
        if (format_ctx->pb) {
            LOGI("Closing AVIO context");

            // 获取自定义 AVIO 上下文
            AVIOContext* custom_ctx = format_ctx->pb;

            // 释放自定义上下文的缓冲区
            if (custom_ctx->buffer) {
                av_free(custom_ctx->buffer);
            }

            // 释放自定义上下文
            av_free(custom_ctx);
            format_ctx->pb = nullptr;
        }

        // 释放 video extradata（由 process_csd_data 分配）
        if (video_stream && video_stream->codecpar->extradata) {
            av_freep(&video_stream->codecpar->extradata);
            video_stream->codecpar->extradata_size = 0;
        }

        // 关闭真实的 AVIO 上下文
        if (real_avio_ctx) {
            LOGI("Closing real AVIO context");
            avio_close(real_avio_ctx);
            real_avio_ctx = nullptr;
        }

        // 释放上下文
        avformat_free_context(format_ctx);
        format_ctx = nullptr;
        LOGI("AVFormatContext freed");
    }

    // 重置流指针
    video_stream = nullptr;
    audio_stream = nullptr;
    video_stream_index = -1;
    audio_stream_index = -1;

    // 重置时间戳基准
    reset_pts_base();

    // 重置 SPS/PPS 状态
    reset_sps_pps_state();

    LOGI("FFmpeg pusher closed successfully");
}

/**
 * 设置 AVIO 数据回调
 */
void set_avio_callback(JNIEnv* env, jobject listener) {
    if (g_jvm == nullptr) {
        env->GetJavaVM(&g_jvm);
    }

    if (g_listener != nullptr) {
        env->DeleteGlobalRef(g_listener);
    }
    g_listener = env->NewGlobalRef(listener);

    jclass clazz = env->GetObjectClass(listener);
    g_onSendData = env->GetMethodID(clazz, "onSendData", "([BJ)V");
    g_onRecvData = env->GetMethodID(clazz, "onRecvData", "([BJ)V");

    LOGI("AVIO callback set");
}