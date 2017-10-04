LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_MODULE    := inject
LOCAL_SRC_FILES :=  hook.c
LOCAL_LDLIBS := -llog
LOCAL_CFLAGS := -g

include $(BUILD_EXECUTABLE)