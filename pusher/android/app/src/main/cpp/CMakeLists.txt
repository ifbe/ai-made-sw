cmake_minimum_required(VERSION 3.22.1)
project("pusher")

set(FFMPEG_DIR ${CMAKE_SOURCE_DIR}/../ffmpeg)

# 引入头文件
include_directories(${FFMPEG_DIR}/include)

# 导入多个独立的 FFmpeg 库
add_library(avcodec SHARED IMPORTED)
set_target_properties(avcodec PROPERTIES
    IMPORTED_LOCATION ${FFMPEG_DIR}/lib/${ANDROID_ABI}/libavcodec.so
)

add_library(avformat SHARED IMPORTED)
set_target_properties(avformat PROPERTIES
    IMPORTED_LOCATION ${FFMPEG_DIR}/lib/${ANDROID_ABI}/libavformat.so
)

add_library(avutil SHARED IMPORTED)
set_target_properties(avutil PROPERTIES
    IMPORTED_LOCATION ${FFMPEG_DIR}/lib/${ANDROID_ABI}/libavutil.so
)

add_library(swresample SHARED IMPORTED)
set_target_properties(swresample PROPERTIES
    IMPORTED_LOCATION ${FFMPEG_DIR}/lib/${ANDROID_ABI}/libswresample.so
)

add_library(swscale SHARED IMPORTED)
set_target_properties(swscale PROPERTIES
    IMPORTED_LOCATION ${FFMPEG_DIR}/lib/${ANDROID_ABI}/libswscale.so
)

# 添加 JNI 库
add_library(pusher SHARED
    pusher_jni.cpp
    ffmpeg_utils.cpp
)

# 链接所有库
target_link_libraries(pusher
    avcodec
    avformat
    avutil
    swresample
    swscale
    log
    android
)
