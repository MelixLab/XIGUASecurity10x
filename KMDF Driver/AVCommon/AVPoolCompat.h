//=============================================================================
// AVPoolCompat.h - ExAllocatePool2 兼容性封装
//
// ExAllocatePool2 在 Windows 10 2004 (build 19041) 才引入。
// 本头文件通过 MmGetSystemRoutineAddress 动态解析 ExAllocatePool2,
// 不可用时回退到 ExAllocatePoolWithTag + RtlZeroMemory。
//
// 用法:
//   1. 在 DriverEntry 中调用 AVPoolCompatInit()
//   2. 用 AV_ALLOC_PAGED / AV_ALLOC_NON_PAGED 替代 ExAllocatePool2
//   3. 释放仍用 ExFreePoolWithTag (或 ExFreePool)
//
// 本头文件仅用于 _KERNEL_MODE 编译
//=============================================================================

#pragma once

#ifdef _KERNEL_MODE

#include <ntddk.h>

//=============================================================================
// 类型定义
//=============================================================================

typedef PVOID (*PFN_ExAllocatePool2)(
    _In_ ULONG64 Flags,
    _In_ SIZE_T  NumberOfBytes,
    _In_ ULONG   Tag
);

//=============================================================================
// 全局状态 (每个驱动各自持有一份, 放在 .data 段)
//=============================================================================

static PFN_ExAllocatePool2 g_pfnExAllocatePool2 = NULL;

//
// POOL_FLAG 值 (与 WDK wdm.h 一致, 仅定义我们用到的)
//
#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED     0x0000000000000001ULL
#endif
#ifndef POOL_FLAG_PAGED
#define POOL_FLAG_PAGED         0x0000000000000002ULL
#endif

//=============================================================================
// 初始化 — 在 DriverEntry 中尽早调用
// 返回 TRUE 表示 ExAllocatePool2 可用, FALSE 表示使用回退路径
//=============================================================================

static __inline BOOLEAN AVPoolCompatInit(VOID)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"ExAllocatePool2");
    g_pfnExAllocatePool2 = (PFN_ExAllocatePool2)MmGetSystemRoutineAddress(&name);
    return (g_pfnExAllocatePool2 != NULL);
}

//=============================================================================
// 兼容分配函数
//
// ExAllocatePool2 默认零初始化, 回退路径也必须零初始化
// (ExAllocatePoolWithTag 不保证零初始化, 所以手动 RtlZeroMemory)
//=============================================================================

//
// 分配 PAGED 池内存 (零初始化)
//
static __inline PVOID AV_ALLOC_PAGED(_In_ SIZE_T NumberOfBytes, _In_ ULONG Tag)
{
    if (g_pfnExAllocatePool2 != NULL)
    {
        return g_pfnExAllocatePool2(POOL_FLAG_PAGED, NumberOfBytes, Tag);
    }
    //
    // 回退: ExAllocatePoolWithTag + 零初始化
    //
    PVOID p = ExAllocatePoolWithTag(PagedPool, NumberOfBytes, Tag);
    if (p != NULL)
    {
        RtlZeroMemory(p, NumberOfBytes);
    }
    return p;
}

//
// 分配 NON_PAGED 池内存 (零初始化)
//
static __inline PVOID AV_ALLOC_NON_PAGED(_In_ SIZE_T NumberOfBytes, _In_ ULONG Tag)
{
    if (g_pfnExAllocatePool2 != NULL)
    {
        return g_pfnExAllocatePool2(POOL_FLAG_NON_PAGED, NumberOfBytes, Tag);
    }
    //
    // 回退: ExAllocatePoolWithTag + 零初始化
    //
    PVOID p = ExAllocatePoolWithTag(NonPagedPool, NumberOfBytes, Tag);
    if (p != NULL)
    {
        RtlZeroMemory(p, NumberOfBytes);
    }
    return p;
}

#endif // _KERNEL_MODE
