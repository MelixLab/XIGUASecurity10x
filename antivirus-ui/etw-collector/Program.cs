using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

var sessionName = args.Length > 0 ? args[0] : "XIGUASecurity_ETW";
var flags = KernelTraceEventParser.Keywords.Process
    | KernelTraceEventParser.Keywords.Thread
    | KernelTraceEventParser.Keywords.FileIO
    | KernelTraceEventParser.Keywords.NetworkTCPIP
    | KernelTraceEventParser.Keywords.Registry;

using var session = new TraceEventSession(sessionName)
{
    StopOnDispose = true
};

session.EnableKernelProvider(flags);

Console.Error.WriteLine($"[ETW] Kernel session '{sessionName}' started");
Console.Error.Flush();

using var source = new ETWTraceEventSource(sessionName, TraceEventSourceType.Session);

source.Kernel.ProcessStart += (data) =>
{
    var evt = new EtwEvent
    {
        Type = "process_start",
        PID = data.ProcessID,
        Name = data.ProcessName,
        Details = data.ImageFileName,
        Time = data.TimeStamp.ToUniversalTime().ToString("O"),
        ParentPID = data.ParentID,
        ThreadID = data.ThreadID
    };
    WriteJson(evt);
};

source.Kernel.ProcessStop += (data) =>
{
    var evt = new EtwEvent
    {
        Type = "process_stop",
        PID = data.ProcessID,
        Name = data.ProcessName,
        Details = data.ImageFileName,
        Time = data.TimeStamp.ToUniversalTime().ToString("O"),
        ThreadID = data.ThreadID
    };
    WriteJson(evt);
};

source.Kernel.ThreadStart += (data) =>
{
    var evt = new EtwEvent
    {
        Type = "thread",
        PID = data.ProcessID,
        Name = data.ProcessName,
        Details = $"Thread {data.ThreadID} start",
        Time = data.TimeStamp.ToUniversalTime().ToString("O"),
        ThreadID = data.ThreadID
    };
    WriteJson(evt);
};

source.Kernel.ImageLoad += (data) =>
{
    var evt = new EtwEvent
    {
        Type = "image",
        PID = data.ProcessID,
        Name = data.ProcessName,
        Details = data.FileName,
        Time = data.TimeStamp.ToUniversalTime().ToString("O"),
        ThreadID = data.ThreadID
    };
    WriteJson(evt);
};

source.Kernel.FileIOCreate += (data) =>
{
    var evt = new EtwEvent
    {
        Type = "file",
        PID = data.ProcessID,
        Name = data.ProcessName,
        Details = data.FileName,
        Time = data.TimeStamp.ToUniversalTime().ToString("O"),
        ThreadID = data.ThreadID
    };
    WriteJson(evt);
};

source.Kernel.FileIORead += (data) =>
{
    var evt = new EtwEvent
    {
        Type = "file",
        PID = data.ProcessID,
        Name = data.ProcessName,
        Details = data.FileName,
        Time = data.TimeStamp.ToUniversalTime().ToString("O"),
        ThreadID = data.ThreadID
    };
    WriteJson(evt);
};

source.Kernel.FileIOWrite += (data) =>
{
    var evt = new EtwEvent
    {
        Type = "file",
        PID = data.ProcessID,
        Name = data.ProcessName,
        Details = data.FileName,
        Time = data.TimeStamp.ToUniversalTime().ToString("O"),
        ThreadID = data.ThreadID
    };
    WriteJson(evt);
};

source.Kernel.TcpIpConnect += (data) =>
{
    var evt = new EtwEvent
    {
        Type = "network",
        PID = data.ProcessID,
        Name = data.ProcessName,
        Details = $"{data.saddr}:{data.sport} → {data.daddr}:{data.dport}",
        Time = data.TimeStamp.ToUniversalTime().ToString("O"),
        ThreadID = data.ThreadID
    };
    WriteJson(evt);
};

source.Kernel.TcpIpAccept += (data) =>
{
    var evt = new EtwEvent
    {
        Type = "network",
        PID = data.ProcessID,
        Name = data.ProcessName,
        Details = $"Accept {data.saddr}:{data.sport} ← {data.daddr}:{data.dport}",
        Time = data.TimeStamp.ToUniversalTime().ToString("O"),
        ThreadID = data.ThreadID
    };
    WriteJson(evt);
};

source.Kernel.TcpIpSend += (data) =>
{
    var evt = new EtwEvent
    {
        Type = "network",
        PID = data.ProcessID,
        Name = data.ProcessName,
        Details = $"{data.saddr}:{data.sport} → {data.daddr}:{data.dport} 发送 {data.size} 字节",
        Time = data.TimeStamp.ToUniversalTime().ToString("O"),
        ThreadID = data.ThreadID
    };
    WriteJson(evt);
};

source.Kernel.TcpIpRecv += (data) =>
{
    var evt = new EtwEvent
    {
        Type = "network",
        PID = data.ProcessID,
        Name = data.ProcessName,
        Details = $"{data.saddr}:{data.sport} ← {data.daddr}:{data.dport} 接收 {data.size} 字节",
        Time = data.TimeStamp.ToUniversalTime().ToString("O"),
        ThreadID = data.ThreadID
    };
    WriteJson(evt);
};

source.Kernel.RegistryCreate += (data) =>
{
    if (IsRegistryNoise(data.KeyName)) return;
    var evt = new EtwEvent
    {
        Type = "registry",
        PID = data.ProcessID,
        Name = data.ProcessName,
        Details = data.KeyName,
        Time = data.TimeStamp.ToUniversalTime().ToString("O"),
        ThreadID = data.ThreadID
    };
    WriteJson(evt);
};

source.Kernel.RegistrySetValue += (data) =>
{
    if (IsRegistryNoise(data.KeyName)) return;
    var evt = new EtwEvent
    {
        Type = "registry",
        PID = data.ProcessID,
        Name = data.ProcessName,
        Details = $"{data.KeyName}\\{data.ValueName}",
        Time = data.TimeStamp.ToUniversalTime().ToString("O"),
        ThreadID = data.ThreadID
    };
    WriteJson(evt);
};

source.Kernel.RegistryDelete += (data) =>
{
    if (IsRegistryNoise(data.KeyName)) return;
    var evt = new EtwEvent
    {
        Type = "registry",
        PID = data.ProcessID,
        Name = data.ProcessName,
        Details = data.KeyName,
        Time = data.TimeStamp.ToUniversalTime().ToString("O"),
        ThreadID = data.ThreadID
    };
    WriteJson(evt);
};

// Start heartbeat thread to keep stdout alive
var cts = new CancellationTokenSource();
var heartbeatTask = Task.Run(async () =>
{
    while (!cts.IsCancellationRequested)
    {
        await Task.Delay(5000, cts.Token);
        var hb = new EtwEvent { Type = "heartbeat", PID = 0, Name = "", Details = "", Time = "" };
        WriteJson(hb);
    }
});

try
{
    source.Process();
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[ETW] Source stopped: {ex.Message}");
}
finally
{
    cts.Cancel();
    try { await heartbeatTask; } catch { }
}

Console.Error.WriteLine("[ETW] Collector stopped");

static bool IsRegistryNoise(string keyName)
{
    var upper = keyName.ToUpperInvariant();
    // 证书/加密/CRL
    if (upper.Contains("CRYPT") || upper.Contains("CERT") || upper.Contains("CRL")
     || upper.Contains("CTL") || upper.Contains("CHAIN") || upper.Contains("TRUST"))
        return true;
    // COM 注册
    if (upper.Contains("\\COM3") || upper.Contains("\\CLSID\\") || upper.Contains("\\TYPELIB\\")
     || upper.Contains("\\INTERFACE\\") || upper.Contains("\\APPID\\") || upper.Contains("\\PROGID\\"))
        return true;
    // 证书存储
    if (upper.Contains("SOFTWARE\\MICROSOFT\\SYSTEMCERTIFICATES")
     || upper.Contains("SOFTWARE\\MICROSOFT\\CRYPTOGRAPHY")
     || upper.Contains("SOFTWARE\\POLICIES\\MICROSOFT\\SYSTEMCERTIFICATES")
     || upper.Contains("SOFTWARE\\MICROSOFT\\ENTERPRISECERTIFICATES"))
        return true;
    // 应用缓存/兼容性
    if (upper.Contains("APPMODEL\\") || upper.Contains("APPCACHE") || upper.Contains("APCOMPATFLAGS")
     || upper.Contains("COMPATIBILITY ASSISTANT"))
        return true;
    // MUI 语言缓存
    if (upper.Contains("\\MUI\\") || upper.Contains("\\MUICACHE\\"))
        return true;
    // 字体缓存
    if (upper.Contains("\\FONTS\\") || upper.Contains("\\FONTCACHE\\") || upper.Contains("\\FONTLINK\\"))
        return true;
    // NLS/语言/时区
    if (upper.Contains("\\NLS\\") || upper.Contains("\\LANGUAGE\\") || upper.Contains("\\CODEPAGE\\")
     || upper.Contains("TIMEZONE") || upper.Contains("\\TIME ZONE\\") || upper.Contains("\\TZ\\"))
        return true;
    // KnownDLLs
    if (upper.Contains("\\KNOWNDLLS\\") || upper.Contains("\\KNOWNDLLS32\\"))
        return true;
    // Session Manager
    if (upper.Contains("\\SESSION MANAGER\\"))
        return true;
    // WMI
    if (upper.Contains("\\WMI\\") || upper.Contains("WBEM"))
        return true;
    // IFEO (Image File Execution Options)
    if (upper.Contains("IMAGE FILE EXECUTION OPTIONS"))
        return true;
    // Windows 内核/驱动配置
    if (upper.Contains("\\CONTROLSET\\") || upper.Contains("CURRENTCONTROLSET\\CONTROL\\")
     || upper.Contains("\\CONTROL\\CLASS\\") || upper.Contains("\\CONTROL\\DEVICECLASSES\\"))
        return true;
    // Windows NT 内部
    if (upper.Contains("\\WINDOWS NT\\CURRENTVERSION\\APPCOMPATFLAGS")
     || upper.Contains("\\WINDOWS NT\\CURRENTVERSION\\APPCACHE")
     || upper.Contains("\\WINDOWS NT\\CURRENTVERSION\\FONTS")
     || upper.Contains("\\WINDOWS NT\\CURRENTVERSION\\MUICACHE")
     || upper.Contains("\\WINDOWS NT\\CURRENTVERSION\\TIME ZONE")
     || upper.Contains("\\WINDOWS NT\\CURRENTVERSION\\APPCOMPATFLAGS"))
        return true;
    // Control 子键
    if (upper.Contains("\\CONTROL\\NLS\\") || upper.Contains("\\CONTROL\\SESSION MANAGER\\")
     || upper.Contains("\\CONTROL\\TIMEZONEINFORMATION"))
        return true;
    // BCD 引导
    if (upper.Contains("LOCAL MACHINE\\BCD") || upper.Contains("BCD00000000"))
        return true;
    // Windows 更新/调度
    if (upper.Contains("SCHEDULECACHE") || upper.Contains("WINDOWSUPDATE"))
        return true;
    // 路径中明显是操作系统内核模块的操作
    if (upper.Contains("\\MICROSOFT\\WINDOWS\\") && (upper.Contains("\\CURRENTVERSION\\") || upper.Contains("\\CONTROL\\")))
        return true;
    return false;
}

static void WriteJson(EtwEvent evt)
{
    var json = JsonSerializer.Serialize(evt);
    Console.WriteLine(json);
    Console.Out.Flush();
}

record struct EtwEvent(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("pid")] int PID,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("details")] string Details,
    [property: JsonPropertyName("time")] string Time,
    [property: JsonPropertyName("ppid")] int ParentPID = 0,
    [property: JsonPropertyName("tid")] int ThreadID = 0
);
