LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := pty
LOCAL_SRC_FILES := ptmx.c serial.c
LOCAL_CFLAGS := -Wall
include $(BUILD_SHARED_LIBRARY)
