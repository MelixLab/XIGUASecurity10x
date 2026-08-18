#include <windows.h>
#include <stdio.h>

void TestReadMBR() {
    HANDLE hDevice;
    BYTE mbr[512];
    DWORD bytesRead;
    
    printf("\n=== Testing READ operation ===\n");
    
    hDevice = CreateFileW(
        L"\\\\.\\PhysicalDrive0",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        printf("Failed to open PhysicalDrive0: %lu\n", error);
        if (error == 5) {
            printf("Error 5 = ERROR_ACCESS_DENIED\n");
            printf("This is NOT caused by the boot sector protection driver.\n");
            printf("Possible causes:\n");
            printf("- Antivirus software blocking direct disk access\n");
            printf("- Windows Defender or other security software\n");
            printf("- Disk is in use by another process\n");
        }
        return;
    }
    
    printf("Successfully opened PhysicalDrive0 for READ\n");
    
    ZeroMemory(mbr, sizeof(mbr));
    bytesRead = 0;
    
    if (ReadFile(hDevice, mbr, 512, &bytesRead, NULL)) {
        printf("Successfully read MBR (%lu bytes)\n", bytesRead);
        printf("MBR Signature: 0x%02X 0x%02X\n", mbr[510], mbr[511]);
        
        if (mbr[510] == 0x55 && mbr[511] == 0xAA) {
            printf("Valid MBR signature found!\n");
        } else {
            printf("Warning: Invalid MBR signature!\n");
        }
    } else {
        printf("Failed to read MBR: %lu\n", GetLastError());
    }
    
    CloseHandle(hDevice);
}

void TestWriteBootSector() {
    HANDLE hDevice;
    BYTE originalMbr[512];
    BYTE testBuffer[512];
    DWORD bytesRead, bytesWritten;
    LARGE_INTEGER offset;
    BOOL result;
    
    printf("\n=== Testing WRITE to Boot Sector (Sector 0) ===\n");
    printf("This test will:\n");
    printf("1. Backup the original MBR\n");
    printf("2. Attempt to write to boot sector (should be blocked by driver)\n");
    printf("3. Restore the original MBR if write succeeded\n\n");
    
    // Step 1: Open device and backup MBR
    printf("Step 1: Opening device and backing up MBR...\n");
    hDevice = CreateFileW(
        L"\\\\.\\PhysicalDrive0",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        printf("Failed to open PhysicalDrive0: %lu\n", error);
        if (error == 5) {
            printf("Access denied - another security software may be blocking.\n");
        }
        return;
    }
    
    // Read original MBR
    ZeroMemory(originalMbr, sizeof(originalMbr));
    if (!ReadFile(hDevice, originalMbr, 512, &bytesRead, NULL)) {
        printf("Failed to read original MBR: %lu\n", GetLastError());
        CloseHandle(hDevice);
        return;
    }
    printf("Original MBR backed up (signature: 0x%02X 0x%02X)\n", originalMbr[510], originalMbr[511]);
    
    // Step 2: Prepare test data (modify one byte to make it different)
    memcpy(testBuffer, originalMbr, 512);
    testBuffer[0] = 0xFF; // Change first byte to make it different
    
    // Step 3: Attempt to write to boot sector
    printf("\nStep 2: Attempting to write to boot sector (offset 0)...\n");
    printf("If driver is working, you should see a 'Boot Sector Protection' popup.\n\n");
    
    offset.QuadPart = 0;
    if (!SetFilePointerEx(hDevice, offset, NULL, FILE_BEGIN)) {
        printf("Failed to set file pointer: %lu\n", GetLastError());
        CloseHandle(hDevice);
        return;
    }
    
    bytesWritten = 0;
    result = WriteFile(hDevice, testBuffer, 512, &bytesWritten, NULL);
    
    if (result) {
        printf("WARNING: Write succeeded! Wrote %lu bytes.\n", bytesWritten);
        printf("The driver did NOT block the write!\n\n");
        
        // Step 4: IMMEDIATELY restore original MBR
        printf("Step 3: RESTORING original MBR...\n");
        offset.QuadPart = 0;
        SetFilePointerEx(hDevice, offset, NULL, FILE_BEGIN);
        
        if (WriteFile(hDevice, originalMbr, 512, &bytesWritten, NULL)) {
            printf("Original MBR restored successfully. System is safe.\n");
        } else {
            printf("FAILED to restore MBR! System may be damaged!\n");
        }
    } else {
        DWORD error = GetLastError();
        printf("Write FAILED: %lu\n", error);
        if (error == 5) {
            printf("SUCCESS! Driver blocked the write (Access Denied).\n");
            printf("Boot sector protection is WORKING!\n");
        } else {
            printf("Write failed for other reasons.\n");
        }
    }
    
    CloseHandle(hDevice);
}

void TestWriteSafeSector() {
    HANDLE hDevice;
    BYTE buffer[512];
    DWORD bytesWritten;
    LARGE_INTEGER offset;
    BOOL result;
    
    printf("\n=== Testing WRITE to Safe Sector (Sector 100) ===\n");
    printf("This writes to sector 100 (offset 51200), outside boot sector.\n");
    printf("This should be ALLOWED (not protected).\n\n");
    
    hDevice = CreateFileW(
        L"\\\\.\\PhysicalDrive0",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        printf("Failed to open PhysicalDrive0: %lu\n", error);
        return;
    }
    
    printf("Successfully opened PhysicalDrive0\n");
    
    ZeroMemory(buffer, sizeof(buffer));
    sprintf((char*)buffer, "Test write to sector 100 - safe area");
    
    offset.QuadPart = 51200;
    if (!SetFilePointerEx(hDevice, offset, NULL, FILE_BEGIN)) {
        printf("Failed to set file pointer: %lu\n", GetLastError());
        CloseHandle(hDevice);
        return;
    }
    
    printf("Attempting to write to sector 100 (offset 51200)...\n");
    
    bytesWritten = 0;
    result = WriteFile(hDevice, buffer, 512, &bytesWritten, NULL);
    
    if (result) {
        printf("Write succeeded! Wrote %lu bytes to sector 100.\n", bytesWritten);
        printf("This is expected - sector 100 is outside protected boot area.\n");
    } else {
        DWORD error = GetLastError();
        printf("Write FAILED: %lu\n", error);
        if (error == 5) {
            printf("Access denied - driver may be blocking all writes.\n");
        }
    }
    
    CloseHandle(hDevice);
}

int main() {
    int choice;
    
    printf("=====================================\n");
    printf("    Boot Sector Protection Test\n");
    printf("=====================================\n\n");
    printf("This program tests the boot sector protection driver.\n");
    printf("It requires administrator privileges.\n\n");
    
    printf("Select test:\n");
    printf("1. Test READ from boot sector (safe)\n");
    printf("2. Test WRITE to boot sector (SAFE - auto-restores MBR)\n");
    printf("3. Test WRITE to safe sector (should be allowed)\n");
    printf("0. Exit\n");
    printf("\nChoice: ");
    
    scanf("%d", &choice);
    getchar();
    
    switch (choice) {
        case 1:
            TestReadMBR();
            break;
        case 2:
            TestWriteBootSector();
            break;
        case 3:
            TestWriteSafeSector();
            break;
        case 0:
            printf("Exiting...\n");
            return 0;
        default:
            printf("Invalid choice!\n");
            return 1;
    }
    
    printf("\n=====================================\n");
    printf("Test completed. Press Enter to exit...");
    getchar();
    
    return 0;
}
