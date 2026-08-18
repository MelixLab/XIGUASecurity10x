//=============================================================================
// trace.h - WPP 软件跟踪定义
//
// 定义 WPP 控制 GUID 和跟踪标志位
//=============================================================================

#pragma once

#define WPP_CONTROL_GUIDS                                                   \
    WPP_DEFINE_CONTROL_GUID(                                                \
        AVDriverTraceGuid,                                                  \
        (CA3E1E1B, 2B5E, 4F2B, A1C3, 0F5A7B8C9D0E),                       \
                                                                            \
        WPP_DEFINE_BIT(TRACE_FLAG_DEFAULT)                                  \
        WPP_DEFINE_BIT(TRACE_FLAG_IOCTL)                                    \
        WPP_DEFINE_BIT(TRACE_FLAG_AUTH)                                     \
        WPP_DEFINE_BIT(TRACE_FLAG_SESSION)                                  \
    )
