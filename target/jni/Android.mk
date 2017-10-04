LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := target
LOCAL_SRC_FILES := target.c

include $(BUILD_EXECUTABLE)