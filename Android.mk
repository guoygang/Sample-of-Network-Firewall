LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := inet_filter
LOCAL_CFLAGS	:= -pie -fPIE
LOCAL_LDFLAGS	:= -pie -fPIE
LOCAL_C_INCLUDES += include
LOCAL_SRC_FILES := $(wildcard *.c)
 

include $(BUILD_EXECUTABLE)
include $(call all-makefiles-under,$(LOCAL_PATH))
