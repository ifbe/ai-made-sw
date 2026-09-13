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
                              int sample_rate, int channel_count,
                              int fps, int video_bitrate, int audio_bitrate,
                              int video_codec, int enable_subtitle);
extern int write_subtitle_frame(const char* text, int64_t pts_ms, int64_t duration_ms);
extern void set_subtitle_text(const char* text);
extern int write_video_frame(uint8_t* data, int size, int64_t pts_ms, int is_key_frame, int is_csd);
extern int write_audio_frame(uint8_t* data, int size, int64_t pts_ms);
extern void close_ffmpeg_pusher();
extern const char* get_last_error();
extern std::string supported_output_protocols();
extern void start_recording_fd(int fd);
extern long long stop_recording_fd();
//extern void set_avio_callback(JNIEnv* env, jobject listener);

// 全局 JVM 引用
JavaVM* g_jvm = nullptr;
jmethodID g_onSendData = nullptr;
jmethodID g_onMuxData = nullptr;
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
        jint channel_count,
        jint fps,
        jint video_bitrate,
        jint audio_bitrate,
        jint video_codec,
        jboolean enable_subtitle) {

    LOGI("=== initPusher START ===");

    // 转换 Java 字符串为 C 字符串
    const char* c_url = nullptr;
    const char* c_protocol = nullptr;
    const char* c_format = nullptr;

    if (url != nullptr) {
        c_url = env->GetStringUTFChars(url, nullptr);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        if (c_url == nullptr) {
            LOGE("GetStringUTFChars(url) failed, abort init");
            return nullptr;
        }
        LOGI("URL: %s", c_url);
    } else {
        LOGE("URL is null");
        c_url = "";
    }

    if (protocol != nullptr) {
        c_protocol = env->GetStringUTFChars(protocol, nullptr);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        LOGI("Protocol: %s", c_protocol ? c_protocol : "(null)");
    } else {
        LOGI("Protocol is null");
        c_protocol = "";
    }

    if (format != nullptr) {
        c_format = env->GetStringUTFChars(format, nullptr);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        LOGI("Format: %s", c_format ? c_format : "(null)");
    } else {
        LOGI("Format is null");
        c_format = "";
    }

    LOGI("Video: %dx%d", video_width, video_height);
    LOGI("Audio: %dHz %dch", sample_rate, channel_count);
    LOGI("Fps: %d, video bitrate: %d, audio bitrate: %d, codec: %s",
         fps, video_bitrate, audio_bitrate, video_codec == 1 ? "H.265" : "H.264");

    // 初始化 FFmpeg 推流器
    LOGI("Calling init_ffmpeg_pusher...");
    int ret = init_ffmpeg_pusher(c_url, c_format, video_width, video_height,
                                 sample_rate, channel_count,
                                 fps, video_bitrate, audio_bitrate, video_codec,
                                 enable_subtitle ? 1 : 0);
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
        const char* detail = get_last_error();
        errorMsgStr = (detail != nullptr && detail[0] != '\0')
                ? detail
                : "FFmpeg initialization failed";
        LOGE("initPusher failed, reason: %s", errorMsgStr);
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
 * 查找监听器方法。
 *
 * 关键点：GetMethodID 找不到方法时会挂一个 NoSuchMethodError 到当前线程，
 * 如果不清掉，后面所有 JNI 调用都会受影响（表现为“某些回调莫名其妙不工作”）。
 * 典型场景：native 库和 Java 接口版本不一致（例如 .so 没重新编译）。
 */
static jmethodID find_listener_method(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    jmethodID id = env->GetMethodID(clazz, name, sig);
    if (env->ExceptionCheck()) {
        LOGE("listener method lookup threw: %s%s", name, sig);
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    if (id == nullptr) {
        LOGE("listener method NOT FOUND: %s%s —— native 与 Java 版本不一致？请重新编译 native 库",
             name, sig);
    }
    return id;
}

/**
 * 最近一次失败的真实原因（给 Java 侧展示/记录用）
 */
JNIEXPORT jstring JNICALL
Java_com_example_pusher_push_JniWrapper_getLastError(
        JNIEnv* env,
        jobject thiz) {
    const char* msg = get_last_error();
    return env->NewStringUTF((msg != nullptr) ? msg : "");
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
    g_onSendData = find_listener_method(env, clazz, "onSendData", "([BJI)V");
    g_onMuxData = find_listener_method(env, clazz, "onMuxData", "([BJ)V");
    g_onRtmpError = find_listener_method(env, clazz, "onRtmpError", "(Ljava/lang/String;)V");

    LOGI("setAvioCallback completed (send=%p mux=%p error=%p)",
         g_onSendData, g_onMuxData, g_onRtmpError);
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
        jboolean is_key_frame,
        jboolean is_csd) {

    if (data == nullptr) {
        LOGE("writeVideoFrame: data is null");
        return JNI_FALSE;
    }

    // 获取字节数组数据
    jsize size = env->GetArrayLength(data);

    jbyte* bytes = env->GetByteArrayElements(data, nullptr);
    if (bytes == nullptr) {
        LOGE("writeVideoFrame: cannot get byte array elements");
        return JNI_FALSE;
    }

    // 写入视频帧
    int ret = write_video_frame(reinterpret_cast<uint8_t*>(bytes),
                                size,
                                static_cast<int64_t>(pts_ms),
                                is_key_frame ? 1 : 0,
                                is_csd ? 1 : 0);

    // 释放字节数组
    env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);

    if (ret != 0) {
        LOGE("writeVideoFrame failed: %d", ret);
        return JNI_FALSE;
    }
    return JNI_TRUE;
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

    if (ret != 0) {
        LOGE("writeAudioFrame failed: %d", ret);
        return JNI_FALSE;
    }
    return JNI_TRUE;
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
    if (buf_size <= 0) return;
    JNIEnv* env = nullptr;
    int attached = 0;
    if (g_jvm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        if (g_jvm->AttachCurrentThread(&env, nullptr) != 0) return;
        attached = 1;
    }
    if (!env) return;

    // 预览只需要前 16 字节（PreviewLogView 也是按 16 字节显示/存储），
    // 本地录制已经改到 native 侧直接写 fd，不再依赖这份拷贝 —— 保持最小开销。
    int copy_len = buf_size > 16 ? 16 : buf_size;
    jbyteArray data = env->NewByteArray(copy_len);
    if (data) {
        env->SetByteArrayRegion(data, 0, copy_len, reinterpret_cast<const jbyte*>(buf));
        // 第三个参数是这次写入的**真实长度**（data 里只有前 16 字节，供预览/录制自检用）
        env->CallVoidMethod(g_listener, g_onSendData, data, ts_ms, (jint)buf_size);
        // Java 回调抛出的异常必须就地清除：否则异常会挂在本线程上，
        // 影响后续 JNI 调用，并且在 attach 线程 detach 时变成“未捕获异常”杀进程。
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        env->DeleteLocalRef(data);
    }
    if (attached) g_jvm->DetachCurrentThread();
}

/**
 * 回调 Java AvioDataListener.onMuxData
 * 用于“封装数据预览”：把交给 muxer 的包（前若干字节）回传给 Java。
 */
extern "C" void java_on_mux_callback(const uint8_t* buf, int buf_size, int64_t ts_ms) {
    if (!g_jvm || !g_listener || !g_onMuxData) return;
    if (buf_size <= 0) return;
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
        env->CallVoidMethod(g_listener, g_onMuxData, data, ts_ms);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
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
    jstring jmsg = env->NewStringUTF(error_msg ? error_msg : "");
    if (jmsg) {
        env->CallVoidMethod(g_listener, g_onRtmpError, jmsg);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        env->DeleteLocalRef(jmsg);
    }
    if (attached) g_jvm->DetachCurrentThread();
}

/**
 * 当前 FFmpeg 库支持的输出协议（逗号分隔）。
 * Java 侧启动时打一条日志：选了 srt/tcp 但这里没有，就说明需要重编 FFmpeg。
 */
JNIEXPORT jstring JNICALL
Java_com_example_pusher_push_JniWrapper_nativeGetOutputProtocols(JNIEnv* env, jclass clazz) {
    const std::string protos = supported_output_protocols();
    LOGI("supported output protocols: %s", protos.c_str());
    return env->NewStringUTF(protos.c_str());
}

/**
 * 开始本地录制：fd 由 Java 从 File/MediaStore 打开后 detachFd 传入（-1 = 关闭录制）
 */
JNIEXPORT void JNICALL
Java_com_example_pusher_push_JniWrapper_nativeStartRecord(JNIEnv* env, jclass clazz, jint fd) {
    start_recording_fd((int)fd);
}

/**
 * 停止本地录制并关闭 fd，返回写入的总字节数
 */
JNIEXPORT jlong JNICALL
Java_com_example_pusher_push_JniWrapper_nativeStopRecord(JNIEnv* env, jclass clazz) {
    return (jlong)stop_recording_fd();
}

/**
 * 设置要显示的字幕文本（只对 mp4/fMP4 有效）。
 * 真正的样本会在**视频关键帧**处写入，和分片边界对齐。
 */
JNIEXPORT void JNICALL
Java_com_example_pusher_push_JniWrapper_setSubtitleText(
        JNIEnv* env,
        jobject thiz,
        jstring text) {
    if (text == nullptr) {
        set_subtitle_text(nullptr);
        return;
    }
    const char* c_text = env->GetStringUTFChars(text, nullptr);
    if (c_text == nullptr) return;
    set_subtitle_text(c_text);
    env->ReleaseStringUTFChars(text, c_text);
}

/**
 * 写一条字幕样本（只对 mp4/fMP4 有效；没有字幕流时返回 false）
 */
JNIEXPORT jboolean JNICALL
Java_com_example_pusher_push_JniWrapper_writeSubtitleFrame(
        JNIEnv* env,
        jobject thiz,
        jstring text,
        jlong pts_ms,
        jlong duration_ms) {

    if (text == nullptr) return JNI_FALSE;
    const char* c_text = env->GetStringUTFChars(text, nullptr);
    if (c_text == nullptr) return JNI_FALSE;
    int ret = write_subtitle_frame(c_text, (int64_t)pts_ms, (int64_t)duration_ms);
    env->ReleaseStringUTFChars(text, c_text);
    return ret >= 0 ? JNI_TRUE : JNI_FALSE;
}

} // extern "C"