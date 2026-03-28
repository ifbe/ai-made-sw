#include <jni.h>
#include <android/log.h>
#include <string>
#include <cstring>
extern "C" {
#include "libavformat/avformat.h"
#include "libavcodec/avcodec.h"
#include "libavutil/avutil.h"
#include "libavutil/time.h"
#include "libavutil/mem.h"  // 添加这个头文件
}
#define LOG_TAG "PusherJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 外部变量声明
extern AVFormatContext* format_ctx;
extern AVStream* video_stream;
extern AVStream* audio_stream;
extern int video_stream_index;
extern int audio_stream_index;

// 外部函数声明
extern int init_ffmpeg_pusher(const char* url, const char* format_name,
                              int video_width, int video_height,
                              int sample_rate, int channel_count);
extern int write_video_frame(uint8_t* data, int size, int64_t pts_ms, int is_key_frame);
extern int write_audio_frame(uint8_t* data, int size, int64_t pts_ms);
extern void close_ffmpeg_pusher();
//extern void set_avio_callback(JNIEnv* env, jobject listener);

// 全局 JVM 引用
JavaVM* g_jvm = nullptr;
jmethodID g_onSendData = nullptr;
jmethodID g_onRecvData = nullptr;
jmethodID g_onRtmpError = nullptr;
jobject g_listener = nullptr;


// JNI 函数实现
extern "C" {

/**
 * 初始化推流器
 */
JNIEXPORT jobject JNICALL
Java_com_example_pusher_push_JniWrapper_initPusher(
        JNIEnv* env,
        jobject thiz,
        jstring url,
        jstring protocol,
        jstring format,
        jint video_width,
        jint video_height,
        jint sample_rate,
        jint channel_count) {

    LOGI("=== initPusher START ===");

    // 转换 Java 字符串为 C 字符串
    const char* c_url = nullptr;
    const char* c_protocol = nullptr;
    const char* c_format = nullptr;

    if (url != nullptr) {
        c_url = env->GetStringUTFChars(url, nullptr);
        LOGI("URL: %s", c_url);
    } else {
        LOGE("URL is null");
        c_url = "";
    }

    if (protocol != nullptr) {
        c_protocol = env->GetStringUTFChars(protocol, nullptr);
        LOGI("Protocol: %s", c_protocol);
    } else {
        LOGI("Protocol is null");
        c_protocol = "";
    }

    if (format != nullptr) {
        c_format = env->GetStringUTFChars(format, nullptr);
        LOGI("Format: %s", c_format);
    } else {
        LOGI("Format is null");
        c_format = "";
    }

    LOGI("Video: %dx%d", video_width, video_height);
    LOGI("Audio: %dHz %dch", sample_rate, channel_count);

    // 初始化 FFmpeg 推流器
    LOGI("Calling init_ffmpeg_pusher...");
    int ret = init_ffmpeg_pusher(c_url, c_format, video_width, video_height, sample_rate, channel_count);
    LOGI("init_ffmpeg_pusher returned: %d", ret);

    // 释放字符串
    if (url != nullptr && c_url != nullptr) {
        env->ReleaseStringUTFChars(url, c_url);
    }
    if (protocol != nullptr && c_protocol != nullptr) {
        env->ReleaseStringUTFChars(protocol, c_protocol);
    }
    if (format != nullptr && c_format != nullptr) {
        env->ReleaseStringUTFChars(format, c_format);
    }

    // 创建 Pair 返回
    LOGI("Creating Pair object...");
    jclass pairClass = env->FindClass("kotlin/Pair");
    if (pairClass == nullptr) {
        LOGE("Cannot find kotlin/Pair class");
        return nullptr;
    }
    LOGI("Pair class found");

    jmethodID pairConstructor = env->GetMethodID(pairClass, "<init>", "(Ljava/lang/Object;Ljava/lang/Object;)V");
    if (pairConstructor == nullptr) {
        LOGE("Cannot find Pair constructor");
        return nullptr;
    }
    LOGI("Pair constructor found");

    // 创建 Boolean 对象
    jclass booleanClass = env->FindClass("java/lang/Boolean");
    if (booleanClass == nullptr) {
        LOGE("Cannot find Boolean class");
        return nullptr;
    }

    jmethodID booleanConstructor = env->GetMethodID(booleanClass, "<init>", "(Z)V");
    if (booleanConstructor == nullptr) {
        LOGE("Cannot find Boolean constructor");
        return nullptr;
    }

    jboolean success = (ret == 0) ? JNI_TRUE : JNI_FALSE;
    LOGI("success = %d", success);

    jobject successObj = env->NewObject(booleanClass, booleanConstructor, success);
    if (successObj == nullptr) {
        LOGE("Cannot create Boolean object");
        return nullptr;
    }

    // 创建错误信息字符串
    const char* errorMsgStr = "";
    if (ret != 0) {
        errorMsgStr = "FFmpeg initialization failed";
    }
    jstring errorMsg = env->NewStringUTF(errorMsgStr);
    if (errorMsg == nullptr) {
        LOGE("Cannot create error message string");
        return nullptr;
    }

    // 创建 Pair
    jobject pair = env->NewObject(pairClass, pairConstructor, successObj, errorMsg);
    if (pair == nullptr) {
        LOGE("Cannot create Pair object");
        return nullptr;
    }

    LOGI("=== initPusher SUCCESS, returning Pair ===");
    return pair;
}

/**
 * 设置 AVIO 回调
 */
JNIEXPORT void JNICALL
Java_com_example_pusher_push_JniWrapper_setAvioCallback(
        JNIEnv* env,
        jobject thiz,
        jobject listener) {

    LOGI("setAvioCallback called");

    if (listener == nullptr) {
        LOGE("listener is null");
        return;
    }

    // 保存 JavaVM 引用（如果还没有）
    if (g_jvm == nullptr) {
        env->GetJavaVM(&g_jvm);
        LOGI("JavaVM saved");
    }

    if (g_listener != nullptr) {
        env->DeleteGlobalRef(g_listener);
    }
    g_listener = env->NewGlobalRef(listener);

    jclass clazz = env->GetObjectClass(listener);
    g_onSendData = env->GetMethodID(clazz, "onSendData", "([BJ)V");
    g_onRecvData = env->GetMethodID(clazz, "onRecvData", "([BJ)V");
    g_onRtmpError = env->GetMethodID(clazz, "onRtmpError", "(Ljava/lang/String;)V");

    LOGI("setAvioCallback completed");
}

JNIEXPORT jboolean JNICALL
Java_com_example_pusher_push_JniWrapper_setVideoExtradata(
        JNIEnv* env,
        jobject thiz,
        jbyteArray data) {

    LOGI("setVideoExtradata called");

    jsize size = env->GetArrayLength(data);
    jbyte* bytes = env->GetByteArrayElements(data, nullptr);

    if (format_ctx != nullptr && video_stream != nullptr) {
        // 释放旧的 extradata
        if (video_stream->codecpar->extradata) {
            av_free(video_stream->codecpar->extradata);
            video_stream->codecpar->extradata = nullptr;
            video_stream->codecpar->extradata_size = 0;
        }

        // 分配新的 extradata
        video_stream->codecpar->extradata = (uint8_t*)av_malloc(size + AV_INPUT_BUFFER_PADDING_SIZE);
        if (video_stream->codecpar->extradata) {
            memcpy(video_stream->codecpar->extradata, bytes, size);
            video_stream->codecpar->extradata_size = size;
            LOGI("Video extradata set, size=%d", size);
            // 打印前16字节用于调试
            LOGI("Extradata preview: %02x %02x %02x %02x %02x %02x %02x %02x...",
                 bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF, bytes[3] & 0xFF,
                 bytes[4] & 0xFF, bytes[5] & 0xFF, bytes[6] & 0xFF, bytes[7] & 0xFF);
            env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
            return JNI_TRUE;
        }
    }

    env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
    return JNI_FALSE;
}

/**
 * 写入视频帧
 */
JNIEXPORT jboolean JNICALL
Java_com_example_pusher_push_JniWrapper_writeVideoFrame(
        JNIEnv* env,
        jobject thiz,
        jbyteArray data,
        jlong pts_ms,
        jboolean is_key_frame) {

    LOGI("writeVideoFrame called, pts=%ld, key=%d", pts_ms, is_key_frame);

    if (data == nullptr) {
        LOGE("writeVideoFrame: data is null");
        return JNI_FALSE;
    }

    // 获取字节数组数据
    jsize size = env->GetArrayLength(data);
    LOGI("Video frame size: %d", size);

    jbyte* bytes = env->GetByteArrayElements(data, nullptr);
    if (bytes == nullptr) {
        LOGE("writeVideoFrame: cannot get byte array elements");
        return JNI_FALSE;
    }

    // 写入视频帧
    int ret = write_video_frame(reinterpret_cast<uint8_t*>(bytes),
                                size,
                                static_cast<int64_t>(pts_ms),
                                is_key_frame ? 1 : 0);

    // 释放字节数组
    env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);

    if (ret == 0) {
        LOGI("writeVideoFrame SUCCESS");
        return JNI_TRUE;
    } else {
        LOGE("writeVideoFrame failed: %d", ret);
        return JNI_FALSE;
    }
}

/**
 * 写入音频帧
 */
JNIEXPORT jboolean JNICALL
Java_com_example_pusher_push_JniWrapper_writeAudioFrame(
        JNIEnv* env,
        jobject thiz,
        jbyteArray data,
        jlong pts_ms) {

    LOGI("writeAudioFrame called, pts=%ld", pts_ms);

    if (data == nullptr) {
        LOGE("writeAudioFrame: data is null");
        return JNI_FALSE;
    }

    // 获取字节数组数据
    jsize size = env->GetArrayLength(data);
    LOGI("Audio frame size: %d", size);

    jbyte* bytes = env->GetByteArrayElements(data, nullptr);
    if (bytes == nullptr) {
        LOGE("writeAudioFrame: cannot get byte array elements");
        return JNI_FALSE;
    }

    // 写入音频帧
    int ret = write_audio_frame(reinterpret_cast<uint8_t*>(bytes),
                                size,
                                static_cast<int64_t>(pts_ms));

    // 释放字节数组
    env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);

    if (ret == 0) {
        LOGI("writeAudioFrame SUCCESS");
        return JNI_TRUE;
    } else {
        LOGE("writeAudioFrame failed: %d", ret);
        return JNI_FALSE;
    }
}

/**
 * 关闭推流器
 */
JNIEXPORT void JNICALL
Java_com_example_pusher_push_JniWrapper_closePusher(
        JNIEnv* env,
        jobject thiz) {

    LOGI("closePusher called");

    // 关闭 FFmpeg 推流器
    close_ffmpeg_pusher();

    // 清理全局回调引用
    if (g_listener != nullptr) {
        env->DeleteGlobalRef(g_listener);
        g_listener = nullptr;
        LOGI("Global listener reference deleted");
    }

    LOGI("closePusher completed");
}

// =============================================================================
// 以下三个函数由 ffmpeg_utils.cpp 调用，实现 Java 回调的 JNI 细节
// ffmpeg_utils.cpp 只调用这些函数，不直接写 JNI 代码
// =============================================================================

/**
 * 回调 Java AvioDataListener.onSendData
 */
extern "C" void java_on_send_callback(const uint8_t* buf, int buf_size, int64_t ts_ms) {
    if (!g_jvm || !g_listener || !g_onSendData) return;
    JNIEnv* env = nullptr;
    int attached = 0;
    if (g_jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        if (g_jvm->AttachCurrentThread(&env, nullptr) != 0) return;
        attached = 1;
    }
    if (!env) return;

    int copy_len = buf_size > 16 ? 16 : buf_size;
    jbyteArray data = env->NewByteArray(copy_len);
    if (data) {
        env->SetByteArrayRegion(data, 0, copy_len, reinterpret_cast<const jbyte*>(buf));
        env->CallVoidMethod(g_listener, g_onSendData, data, ts_ms);
        env->DeleteLocalRef(data);
    }
    if (attached) g_jvm->DetachCurrentThread();
}

/**
 * 回调 Java AvioDataListener.onRecvData
 */
extern "C" void java_on_recv_callback(const uint8_t* buf, int buf_size, int64_t ts_ms) {
    if (!g_jvm || !g_listener || !g_onRecvData) return;
    JNIEnv* env = nullptr;
    int attached = 0;
    if (g_jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        if (g_jvm->AttachCurrentThread(&env, nullptr) != 0) return;
        attached = 1;
    }
    if (!env) return;

    int copy_len = buf_size > 16 ? 16 : buf_size;
    jbyteArray data = env->NewByteArray(copy_len);
    if (data) {
        env->SetByteArrayRegion(data, 0, copy_len, reinterpret_cast<const jbyte*>(buf));
        env->CallVoidMethod(g_listener, g_onRecvData, data, ts_ms);
        env->DeleteLocalRef(data);
    }
    if (attached) g_jvm->DetachCurrentThread();
}

/**
 * 回调 Java AvioDataListener.onRtmpError
 */
extern "C" void java_on_rtmp_error_callback(const char* error_msg) {
    if (!g_jvm || !g_listener || !g_onRtmpError) return;
    JNIEnv* env = nullptr;
    int attached = 0;
    if (g_jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        if (g_jvm->AttachCurrentThread(&env, nullptr) != 0) return;
        attached = 1;
    }
    if (!env) return;
    jstring jmsg = env->NewStringUTF(error_msg);
    if (jmsg) {
        env->CallVoidMethod(g_listener, g_onRtmpError, jmsg);
        env->DeleteLocalRef(jmsg);
    }
    if (attached) g_jvm->DetachCurrentThread();
}

} // extern "C"