# TestXgsDriver.ps1 - Direct P/Invoke test for XGS driver (IntPtr version)
# Uses IntPtr instead of SafeFileHandle to avoid marshaling issues

Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class XgsDriverTest
{
    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x80;

    // IOCTL_XGS_AUTH_INIT = 0x8002E400
    public const uint IOCTL_XGS_AUTH_INIT = 0x8002E400;
    // IOCTL_XGS_GET_STATUS = 0x8002E44C
    public const uint IOCTL_XGS_GET_STATUS = 0x8002E44C;
    // IOCTL_AV_GET_STATUS = 0x8002E048 (for comparison with AVDriver)
    public const uint IOCTL_AV_GET_STATUS = 0x8002E048;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        byte[] lpInBuffer,
        uint nInBufferSize,
        byte[] lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public static void RunTest()
    {
        Console.WriteLine("=== XGS Driver Direct P/Invoke Test (IntPtr) ===");
        Console.WriteLine("Device: \\\\.\\XGSRansomFilter");
        Console.WriteLine();

        // Step 1: CreateFile
        Console.Write("[1] CreateFileW ... ");
        IntPtr hDevice = CreateFile(
            "\\\\.\\XGSRansomFilter",
            GENERIC_READ | GENERIC_WRITE,
            0,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            IntPtr.Zero
        );

        if (hDevice == IntPtr.Zero || hDevice == new IntPtr(-1))
        {
            uint err = (uint)Marshal.GetLastWin32Error();
            Console.WriteLine("FAILED (error: {0})", err);
            return;
        }
        Console.WriteLine("OK (handle: 0x{0:X})", hDevice.ToInt64());

        // Step 2: DeviceIoControl IOCTL_XGS_AUTH_INIT
        Console.Write("[2] DeviceIoControl(IOCTL_XGS_AUTH_INIT, 0x8002E400) ... ");
        byte[] outBuffer = new byte[40];
        uint bytesReturned;
        bool success = DeviceIoControl(
            hDevice,
            IOCTL_XGS_AUTH_INIT,
            null,
            0,
            outBuffer,
            (uint)outBuffer.Length,
            out bytesReturned,
            IntPtr.Zero
        );

        if (!success)
        {
            uint err = (uint)Marshal.GetLastWin32Error();
            Console.WriteLine("FAILED (error: {0})", err);
        }
        else
        {
            Console.WriteLine("OK (bytesReturned: {0})", bytesReturned);
            if (bytesReturned >= 40)
            {
                ulong seqId = BitConverter.ToUInt64(outBuffer, 0);
                Console.WriteLine("  SequenceId: {0}", seqId);
                Console.WriteLine("  Challenge:  {0}",
                    BitConverter.ToString(outBuffer, 8, 32).Replace("-", ""));
            }
        }

        // Step 3: Try IOCTL_XGS_GET_STATUS (without auth, should get ACCESS_DENIED)
        Console.Write("[3] DeviceIoControl(IOCTL_XGS_GET_STATUS, 0x8002E44C) ... ");
        byte[] statusBuffer = new byte[32];
        success = DeviceIoControl(
            hDevice,
            IOCTL_XGS_GET_STATUS,
            null,
            0,
            statusBuffer,
            (uint)statusBuffer.Length,
            out bytesReturned,
            IntPtr.Zero
        );

        if (!success)
        {
            uint err = (uint)Marshal.GetLastWin32Error();
            // Expected: ACCESS_DENIED (error 5) since not authenticated
            Console.WriteLine("FAILED (error: {0})", err);
            Console.WriteLine("  (Expected if driver validates auth)");
        }
        else
        {
            Console.WriteLine("OK (unexpected - driver returned data without auth)");
            Console.WriteLine("  bytesReturned: {0}", bytesReturned);
        }

        // Step 4: Try IOCTL_AV_GET_STATUS (wrong driver's IOCTL)
        Console.Write("[4] DeviceIoControl(IOCTL_AV_GET_STATUS, 0x8002E048) ... ");
        byte[] avStatusBuffer = new byte[48];
        success = DeviceIoControl(
            hDevice,
            IOCTL_AV_GET_STATUS,
            null,
            0,
            avStatusBuffer,
            (uint)avStatusBuffer.Length,
            out bytesReturned,
            IntPtr.Zero
        );

        if (!success)
        {
            uint err = (uint)Marshal.GetLastWin32Error();
            Console.WriteLine("FAILED (error: {0})", err);
            Console.WriteLine("  (Expected: driver shouldn't recognize this IOCTL)");
        }
        else
        {
            Console.WriteLine("OK (unexpected)");
        }

        // Step 5: Try with zero-length output buffer (should get BUFFER_TOO_SMALL)
        Console.Write("[5] DeviceIoControl(IOCTL_XGS_AUTH_INIT, outLen=0) ... ");
        success = DeviceIoControl(
            hDevice,
            IOCTL_XGS_AUTH_INIT,
            null,
            0,
            null,
            0,
            out bytesReturned,
            IntPtr.Zero
        );

        if (!success)
        {
            uint err = (uint)Marshal.GetLastWin32Error();
            Console.WriteLine("FAILED (error: {0})", err);
            // Error 122 = ERROR_INSUFFICIENT_BUFFER, 87 = ERROR_INVALID_PARAMETER
        }
        else
        {
            Console.WriteLine("OK (unexpected)");
        }

        // Cleanup
        CloseHandle(hDevice);
        Console.WriteLine();
        Console.WriteLine("=== Test Complete ===");
    }
}
"@

[XgsDriverTest]::RunTest()

Write-Host ""
Write-Host "=== NOTES ===" -ForegroundColor Cyan
Write-Host "Error 6  = ERROR_INVALID_HANDLE"
Write-Host "Error 5  = ERROR_ACCESS_DENIED (expected when not authenticated)"
Write-Host "Error 1  = ERROR_INVALID_FUNCTION (expected for unknown IOCTL)"
Write-Host "Error 87 = ERROR_INVALID_PARAMETER"
Write-Host "Error 122 = ERROR_INSUFFICIENT_BUFFER"