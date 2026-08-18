//=============================================================================
// AVInjectTest.cpp - 远程线程注入测试工具 (独立临时测试解决方案)
//
// 功能: 向 notepad.exe 注入一段 x64 shellcode,
//       在 notepad 进程内调用 user32!MessageBoxW 弹出消息框。
// 用法: AVInjectTest.exe [PID]
//       不传 PID 时自动查找 notepad.exe, 未运行则自动启动一个。
//
// 注: 该工具用于测试 AVDriver 的远程线程注入防护。
//     注入起始地址位于 VirtualAllocEx 分配的内存中 (不在任何已加载模块内),
//     驱动弹窗会标记为"原始代码注入特征"。
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

//=============================================================================
// 查找指定进程名的 PID
//=============================================================================
static DWORD
FindProcessByName(
    _In_ const wchar_t* name
    )
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);

    DWORD pid = 0;
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, name) == 0)
            {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

//=============================================================================
// 启动系统目录下的 notepad.exe (避免 PATH 劫持)
//=============================================================================
static DWORD
StartNotepad(
    void
    )
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t notepadPath[MAX_PATH];

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!GetSystemDirectoryW(notepadPath, MAX_PATH))
    {
        return 0;
    }

    wcscat_s(notepadPath, L"\\notepad.exe");

    if (!CreateProcessW(notepadPath, NULL, NULL, NULL, FALSE, 0,
                        NULL, NULL, &si, &pi))
    {
        return 0;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return pi.dwProcessId;
}

//=============================================================================
// 构建 x64 shellcode:
//   MessageBoxW(NULL, "Injected!", "AVDriver Inject Test", MB_OK);
//   ExitThread(0);
//
// 布局 (RIP 相对寻址, 不依赖实际加载基址):
//   0x00 48 83 EC 28       sub rsp, 40      (对齐 16 字节 + 32 字节影子空间)
//   0x04 48 31 C9          xor rcx, rcx
//   0x07 48 8D 15 rel32    lea rdx, [rip+rel]   -> 文本
//   0x0E 4C 8D 05 rel32    lea r8,  [rip+rel]   -> 标题
//   0x15 45 31 C9          xor r9d, r9d
//   0x18 48 B8 imm64       mov rax, MessageBoxW
//   0x22 FF D0             call rax
//   0x24 48 31 C9          xor rcx, rcx
//   0x27 48 B8 imm64       mov rax, ExitThread
//   0x31 FF D0             call rax
//   0x33 代码结束
//   0x40 文本 (UTF-16LE, null 结尾)
//   0x60 标题 (UTF-16LE, null 结尾)
//
// 注: x64 调用约定要求 call 前 RSP 16 字节对齐且提供 32 字节影子空间,
//     线程入口处 RSP mod 16 == 8, 必须先 sub rsp, 40 才能安全调用。
//=============================================================================

#define SC_TEXT_OFFSET    0x40
#define SC_CAPTION_OFFSET 0x60
#define SC_TOTAL_SIZE     0x100

static BYTE*
BuildShellcode(
    _Out_ SIZE_T* pSize,
    _In_ FARPROC pfnMessageBoxW,
    _In_ FARPROC pfnExitThread
    )
{
    BYTE* buf = (BYTE*)malloc(SC_TOTAL_SIZE);
    if (buf == NULL)
    {
        return NULL;
    }

    ZeroMemory(buf, SC_TOTAL_SIZE);

    BYTE* p = buf;

    // sub rsp, 40
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x28;

    // xor rcx, rcx
    *p++ = 0x48; *p++ = 0x31; *p++ = 0xC9;

    // lea rdx, [rip + (SC_TEXT_OFFSET - 0x0E)]
    *p++ = 0x48; *p++ = 0x8D; *p++ = 0x15;
    DWORD relText = SC_TEXT_OFFSET - 0x0E;
    memcpy(p, &relText, sizeof(relText));
    p += sizeof(relText);

    // lea r8, [rip + (SC_CAPTION_OFFSET - 0x15)]
    *p++ = 0x4C; *p++ = 0x8D; *p++ = 0x05;
    DWORD relCap = SC_CAPTION_OFFSET - 0x15;
    memcpy(p, &relCap, sizeof(relCap));
    p += sizeof(relCap);

    // xor r9d, r9d
    *p++ = 0x45; *p++ = 0x31; *p++ = 0xC9;

    // mov rax, pfnMessageBoxW
    *p++ = 0x48; *p++ = 0xB8;
    memcpy(p, &pfnMessageBoxW, sizeof(pfnMessageBoxW));
    p += sizeof(pfnMessageBoxW);

    // call rax
    *p++ = 0xFF; *p++ = 0xD0;

    // xor rcx, rcx
    *p++ = 0x48; *p++ = 0x31; *p++ = 0xC9;

    // mov rax, pfnExitThread
    *p++ = 0x48; *p++ = 0xB8;
    memcpy(p, &pfnExitThread, sizeof(pfnExitThread));
    p += sizeof(pfnExitThread);

    // call rax
    *p++ = 0xFF; *p++ = 0xD0;

    // 文本与标题
    wcscpy_s((wchar_t*)(buf + SC_TEXT_OFFSET),
             (SC_TOTAL_SIZE - SC_TEXT_OFFSET) / sizeof(wchar_t),
             L"Injected!");
    wcscpy_s((wchar_t*)(buf + SC_CAPTION_OFFSET),
             (SC_TOTAL_SIZE - SC_CAPTION_OFFSET) / sizeof(wchar_t),
             L"AVDriver Inject Test");

    *pSize = SC_TOTAL_SIZE;
    return buf;
}

//=============================================================================
// 主函数
//=============================================================================
int
wmain(
    _In_ int argc,
    _In_reads_(argc) wchar_t* argv[]
    )
{
    DWORD pid = 0;
    HANDLE hProcess = NULL;
    FARPROC pfnMessageBoxW = NULL;
    FARPROC pfnExitThread = NULL;
    BYTE* shellcode = NULL;
    SIZE_T scSize = 0;
    LPVOID remoteMem = NULL;
    HANDLE hThread = NULL;
    DWORD threadId = 0;
    BOOL ok = FALSE;

    wprintf(L"[AVInjectTest] Remote thread injection test\n");

    //
    // 解析目标 PID (可选参数), 否则查找/启动 notepad
    //
    if (argc >= 2)
    {
        pid = wcstoul(argv[1], NULL, 10);
    }

    if (pid == 0)
    {
        pid = FindProcessByName(L"notepad.exe");
        if (pid == 0)
        {
            wprintf(L"[AVInjectTest] notepad.exe not running, starting it...\n");
            pid = StartNotepad();
            if (pid == 0)
            {
                wprintf(L"[AVInjectTest] Failed to start notepad.exe\n");
                return 1;
            }
            Sleep(800);   // 等待 notepad 完成初始化
        }
    }

    wprintf(L"[AVInjectTest] Target PID: %u\n", pid);

    //
    // 打开目标进程
    //
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
    {
        wprintf(L"[AVInjectTest] OpenProcess failed (error: %lu)\n", GetLastError());
        return 1;
    }

    //
    // 解析 MessageBoxW / ExitThread 地址
    // 用 LoadLibraryW 确保 user32 已加载进本进程
    // (系统 DLL 在本次启动中各进程加载基址一致, 目标进程内地址相同)
    //
    pfnMessageBoxW = GetProcAddress(LoadLibraryW(L"user32.dll"), "MessageBoxW");
    pfnExitThread = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ExitThread");
    if (pfnMessageBoxW == NULL || pfnExitThread == NULL)
    {
        wprintf(L"[AVInjectTest] Resolve MessageBoxW/ExitThread failed\n");
        CloseHandle(hProcess);
        return 1;
    }
    wprintf(L"[AVInjectTest] MessageBoxW = 0x%p, ExitThread = 0x%p\n",
            pfnMessageBoxW, pfnExitThread);

    //
    // 构建 shellcode
    //
    shellcode = BuildShellcode(&scSize, pfnMessageBoxW, pfnExitThread);
    if (shellcode == NULL)
    {
        wprintf(L"[AVInjectTest] BuildShellcode failed\n");
        CloseHandle(hProcess);
        return 1;
    }

    //
    // 在目标进程中分配可执行内存并写入 shellcode
    //
    remoteMem = VirtualAllocEx(hProcess, NULL, scSize,
                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteMem == NULL)
    {
        wprintf(L"[AVInjectTest] VirtualAllocEx failed (error: %lu)\n", GetLastError());
        goto cleanup;
    }
    wprintf(L"[AVInjectTest] Remote memory: 0x%p\n", remoteMem);

    if (!WriteProcessMemory(hProcess, remoteMem, shellcode, scSize, NULL))
    {
        wprintf(L"[AVInjectTest] WriteProcessMemory failed (error: %lu)\n", GetLastError());
        goto cleanup;
    }

    //
    // 创建远程线程 (触发注入防护)
    //
    wprintf(L"[AVInjectTest] Creating remote thread...\n");
    hThread = CreateRemoteThread(hProcess, NULL, 0,
                                 (LPTHREAD_START_ROUTINE)remoteMem,
                                 NULL, 0, &threadId);
    if (hThread == NULL)
    {
        wprintf(L"[AVInjectTest] CreateRemoteThread failed (error: %lu)\n", GetLastError());
        goto cleanup;
    }
    wprintf(L"[AVInjectTest] Remote thread created, TID=%u, waiting for completion...\n",
            threadId);

    //
    // 等待注入线程完成 (MessageBox 关闭后 shellcode 调 ExitThread)
    //
    WaitForSingleObject(hThread, INFINITE);

    DWORD threadExitCode = 0;
    GetExitCodeThread(hThread, &threadExitCode);
    wprintf(L"[AVInjectTest] Injection finished (thread exit code: 0x%lX)\n",
            threadExitCode);
    ok = TRUE;

cleanup:
    if (hThread != NULL)
    {
        CloseHandle(hThread);
    }
    if (remoteMem != NULL)
    {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    }
    if (shellcode != NULL)
    {
        free(shellcode);
    }
    if (hProcess != NULL)
    {
        CloseHandle(hProcess);
    }

    return ok ? 0 : 1;
}
