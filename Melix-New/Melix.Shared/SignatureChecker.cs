using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Melix.Shared;

public enum SignatureStatus
{
    Unknown,
    Valid,           // 有效签名（受信任的CA颁发）
    SelfSigned,      // 自签名（不可信）
    Expired,         // 已过期
    Revoked,         // 已吊销
    InvalidChain,    // 证书链无效
    Invalid,
    NotSigned
}

public class SignatureInfo
{
    public SignatureStatus Status { get; set; }
    public string? Subject { get; set; }
    public string? Issuer { get; set; }
    public DateTime? ValidFrom { get; set; }
    public DateTime? ValidTo { get; set; }
    public bool IsCatalogSigned { get; set; }
    public bool IsEmbeddedSigned { get; set; }
    public bool IsWHQL { get; set; }
    public bool IsTrustedCA { get; set; }  // 是否来自受信任的CA
    public string? ValidationMessage { get; set; }
}

public static class SignatureChecker
{
    // WinTrust API 常量
    private const int WTD_CHOICE_FILE = 1;
    private const int WTD_REVOKE_NONE = 0;
    private const int WTD_REVOKE_WHOLECHAIN = 1;  // 检查吊销状态
    private const int WTD_UI_NONE = 2;
    private const int WTD_STATEACTION_VERIFY = 1;
    private const int WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x00000080;  // 不检查吊销，避免网络问题
    private const uint WTD_SAFER_FLAG = 0x00000100;  // SAFER 信任提供程序
    
    // 受信任的根CA列表（主要商业CA）
    private static readonly HashSet<string> TrustedRootCAs = new(StringComparer.OrdinalIgnoreCase)
    {
        // Microsoft
        "Microsoft Root Certificate Authority",
        "Microsoft Code Signing PCA",
        "Microsoft Windows Production PCA",
        "Microsoft Windows Hardware Driver PCA",
        "Microsoft Corporation",
        
        // GlobalSign
        "GlobalSign Root CA",
        "GlobalSign",
        
        // DigiCert
        "DigiCert Inc",
        "DigiCert Assured ID Root CA",
        "DigiCert High Assurance EV Root CA",
        "DigiCert Trusted Root G4",
        
        // Sectigo (原Comodo)
        "Sectigo",
        "COMODO",
        "COMODO RSA Certification Authority",
        "Sectigo Public Code Signing Root R46",
        
        // GoDaddy
        "GoDaddy",
        "GoDaddy.com, Inc.",
        "GoDaddy Root Certificate Authority",
        
        // Entrust
        "Entrust",
        "Entrust.net",
        "Entrust Root Certification Authority",
        
        // Symantec / VeriSign
        "Symantec Corporation",
        "VeriSign",
        "VeriSign, Inc.",
        "VeriSign Universal Root Certification Authority",
        
        // Thawte
        "Thawte",
        "Thawte Consulting",
        
        // GeoTrust
        "GeoTrust",
        "GeoTrust Inc.",
        
        // RapidSSL
        "RapidSSL",
        
        // Let's Encrypt (代码签名较少见，但可信)
        "Let's Encrypt",
        
        // Amazon
        "Amazon Root CA",
        "Amazon",
        
        // Google
        "Google Trust Services",
        "Google Internet Authority",
        
        // Apple
        "Apple Root CA",
        "Apple Inc.",
        
        // Adobe
        "Adobe Root CA",
        
        // Intel
        "Intel External Basic Issuing CA",
        
        // 其他主要CA
        "SSL.com",
        "SSL.com Root Certification Authority",
        "Certum",
        "Certum CA",
        "Starfield Technologies",
        "Starfield Root Certificate Authority",
        "Network Solutions",
        "WellsSecure",
        "XRamp Global Certification Authority",
        "QuoVadis",
        "SwissSign",
        "Actalis",
        "Buypass",
        "D-TRUST",
        "T-Systems",
        "Deutsche Telekom",
        "Trustwave",
        "Cybertrust",
        "Baltimore",
        "AddTrust",
        "USERTrust",
        "ISRG Root X1",  // Let's Encrypt
        "IdenTrust",
        "IdenTrust Commercial Root CA",
    };
    
    // 知名发布者列表（来自受信任CA的签名）
    private static readonly HashSet<string> WellKnownPublishers = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Microsoft Corporation", "Microsoft Windows", "Windows (R)",
        "Intel", "Intel Corporation",
        "NVIDIA", "NVIDIA Corporation",
        "AMD", "Advanced Micro Devices", "AMD Inc.",
        "Oracle", "Oracle Corporation",
        "Google", "Google LLC", "Google Inc.",
        "Apple", "Apple Inc.",
        "Adobe", "Adobe Inc.", "Adobe Systems",
        "Broadcom", "Broadcom Corporation",
        "Realtek", "Realtek Semiconductor",
        "ASUS", "ASUSTeK Computer", "ASUSTeK",
        "Dell", "Dell Inc.", "Dell Technologies",
        "HP", "Hewlett-Packard", "Hewlett Packard",
        "Lenovo", "Lenovo Group",
        "IBM", "International Business Machines",
        "Cisco", "Cisco Systems",
        "VMware", "VMware Inc.",
        "Symantec", "Symantec Corporation",
        "McAfee", "McAfee LLC",
        "Kaspersky", "Kaspersky Lab",
        "Autodesk", "Autodesk Inc.",
        "Corel", "Corel Corporation",
        "Siemens", "Siemens AG",
        "SonicWALL", "SonicWALL Inc.",
        "Citrix", "Citrix Systems",
        "SAP", "SAP SE",
        "Mozilla", "Mozilla Corporation",
        "Opera", "Opera Software",
        "Avast", "Avast Software",
        "AVG", "AVG Technologies",
        "Bitdefender", "Bitdefender SRL",
        "ESET", "ESET LLC",
        "F-Secure", "F-Secure Corporation",
        "Trend Micro", "Trend Micro Inc.",
        "Qualcomm", "Qualcomm Inc.",
        "Texas Instruments", "TI",
        "Marvell", "Marvell Semiconductor",
        "Western Digital", "WD",
        "Seagate", "Seagate Technology",
        "Samsung", "Samsung Electronics",
        "LG", "LG Electronics",
        "Sony", "Sony Corporation",
        "Toshiba", "Toshiba Corporation",
        "Panasonic", "Panasonic Corporation",
        "Philips", "Philips Electronics",
        "Logitech", "Logitech Inc.",
        "Razer", "Razer Inc.",
        "Corsair", "Corsair Gaming",
        "ASRock", "ASRock Inc.",
        "MSI", "Micro-Star International",
        "Gigabyte", "Gigabyte Technology",
        "EVGA", "EVGA Corporation",
        "Creative", "Creative Technology",
        "Synaptics", "Synaptics Inc.",
        "Conexant", "Conexant Systems",
        "IDT", "Integrated Device Technology",
        "VIA", "VIA Technologies",
        "S3", "S3 Graphics",
        "Matrox", "Matrox Graphics",
        "3dfx", "3dfx Interactive",
        "ATI", "ATI Technologies",
        "Xerox", "Xerox Corporation",
        "Canon", "Canon Inc.",
        "Epson", "Seiko Epson",
        "Brother", "Brother Industries",
        "Lexmark", "Lexmark International",
        "Kyocera", "Kyocera Corporation",
        "Ricoh", "Ricoh Company",
        "Sharp", "Sharp Corporation",
        "Konica Minolta", "Konica Minolta Inc.",
        "Carbon Black", "Carbon Black, Inc.",
        "CrowdStrike", "CrowdStrike Inc.",
        "Palo Alto Networks",
        "Fortinet", "Fortinet Inc.",
        "Check Point", "Check Point Software",
        "FireEye", "FireEye Inc.",
        "Splunk", "Splunk Inc.",
        "Elastic", "Elastic NV",
        "MongoDB", "MongoDB Inc.",
        "Redis", "Redis Ltd",
        "HashiCorp", "HashiCorp Inc.",
        "JetBrains", "JetBrains s.r.o.",
        "Unity", "Unity Technologies",
        "Epic Games", "Epic Games Inc.",
        "Valve", "Valve Corporation",
        "Steam",
        "Discord", "Discord Inc.",
        "Slack", "Slack Technologies",
        "Zoom", "Zoom Video Communications",
        "TeamViewer", "TeamViewer Germany",
        "AnyDesk", "AnyDesk Software",
        "Parsec", "Parsec Cloud",
        "OBS Project",
        "VideoLAN", "VideoLAN Team",
        "FFmpeg",
        "Audacity",
        "GIMP", "GIMP Team",
        "Blender", "Blender Foundation",
        "Krita", "Krita Foundation",
        "Inkscape",
        "LibreOffice", "The Document Foundation",
        "OpenOffice", "Apache Software Foundation",
        "Mozilla Foundation",
        "Tor Project",
        "Signal", "Signal Messenger",
        "Telegram", "Telegram FZ-LLC",
        "WhatsApp", "WhatsApp Inc.",
        "Skype", "Skype Technologies",
    };

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("wintrust.dll", SetLastError = true)]
        public static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, IntPtr pgSubsystem, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        public static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        public static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", SetLastError = true)]
        public static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        public static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    public static SignatureInfo GetSignatureInfo(string filePath)
    {
        var info = new SignatureInfo { Status = SignatureStatus.Unknown };

        try
        {
            // 使用WinTrust API进行完整验证（包括证书链）
            var winTrustResult = CheckWinTrust(filePath);
            
            // 获取证书详细信息（支持嵌入式签名和目录签名）
            X509Certificate2? cert = null;
            try
            {
                cert = GetCertificateFromSignedFile(filePath);
                info.IsEmbeddedSigned = cert != null;
            }
            catch
            {
                info.IsEmbeddedSigned = false;
            }

            if (cert != null)
            {
                info.Subject = cert.Subject;
                info.Issuer = cert.Issuer;
                info.ValidFrom = cert.NotBefore;
                info.ValidTo = cert.NotAfter;
                
                // 检查是否是WHQL签名
                info.IsWHQL = cert.Issuer?.Contains("Microsoft Windows Hardware Compatibility", StringComparison.OrdinalIgnoreCase) == true
                           || cert.Subject?.Contains("WHQL", StringComparison.OrdinalIgnoreCase) == true;
                
                // 验证证书链和CA
                var chainValidation = ValidateCertificateChain(cert);
                info.IsTrustedCA = chainValidation.IsTrustedCA;
                
                // 检查有效期
                bool isExpired = DateTime.Now > cert.NotAfter || DateTime.Now < cert.NotBefore;
                
                // 判断是否自签名
                bool isSelfSigned = IsSelfSigned(cert);
                
                // 确定状态
                if (winTrustResult == 0)
                {
                    if (isExpired)
                    {
                        info.Status = SignatureStatus.Expired;
                        info.ValidationMessage = "Certificate has expired";
                    }
                    else if (isSelfSigned)
                    {
                        info.Status = SignatureStatus.SelfSigned;
                        info.ValidationMessage = "Self-signed certificate (not trusted)";
                    }
                    else if (!info.IsTrustedCA)
                    {
                        info.Status = SignatureStatus.InvalidChain;
                        info.ValidationMessage = "Certificate chain not trusted";
                    }
                    else
                    {
                        info.Status = SignatureStatus.Valid;
                        info.ValidationMessage = "Valid trusted signature";
                    }
                }
                else
                {
                    info.Status = SignatureStatus.Invalid;
                    info.ValidationMessage = $"WinTrust validation failed (error: 0x{winTrustResult:X8})";
                }
                
                cert.Dispose();
            }
            else if (winTrustResult == 0)
            {
                // WinTrust通过但无法获取证书信息
                info.Status = SignatureStatus.Valid;
                info.ValidationMessage = "Valid signature (catalog signed)";
            }
            else
            {
                // 尝试目录签名检测（Catalog Signing）
                bool isCatalogSigned = IsCatalogSignedFile(filePath);
                if (isCatalogSigned)
                {
                    info.Status = SignatureStatus.Valid;
                    info.IsCatalogSigned = true;
                    info.IsTrustedCA = true;
                    info.ValidationMessage = "Valid catalog signature";
                }
                else
                {
                    info.Status = SignatureStatus.NotSigned;
                    info.ValidationMessage = "File is not signed";
                }
            }
        }
        catch (Exception ex)
        {
            info.Status = SignatureStatus.NotSigned;
            info.ValidationMessage = $"Error: {ex.Message}";
        }

        return info;
    }

    private static bool IsCatalogSignedFile(string filePath)
    {
        IntPtr hFile = IntPtr.Zero;
        IntPtr hCatAdmin = IntPtr.Zero;
        IntPtr hCatInfo = IntPtr.Zero;
        GCHandle? guidHandle = null;
        
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            hFile = fs.SafeFileHandle.DangerousGetHandle();
            if (hFile == IntPtr.Zero || hFile == new IntPtr(-1)) return false;

            Guid subsystem = new Guid("{F750E6C3-38EE-11D1-85E5-00C04FC295EE}"); // DRIVER_ACTION_VERIFY
            guidHandle = GCHandle.Alloc(subsystem, GCHandleType.Pinned);
            IntPtr pSubsystem = guidHandle.Value.AddrOfPinnedObject();
            bool ctxAcquired = NativeMethods.CryptCATAdminAcquireContext(out hCatAdmin, pSubsystem, 0);
            if (!ctxAcquired) return false;

            uint hashSize = 0;
            NativeMethods.CryptCATAdminCalcHashFromFileHandle(hFile, ref hashSize, null, 0);
            if (hashSize == 0) return false;

            byte[] hash = new byte[hashSize];
            if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle(hFile, ref hashSize, hash, 0)) return false;

            hCatInfo = NativeMethods.CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, IntPtr.Zero);
            return hCatInfo != IntPtr.Zero;
        }
        catch { return false; }
        finally
        {
            if (hCatInfo != IntPtr.Zero) NativeMethods.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            if (hCatAdmin != IntPtr.Zero) NativeMethods.CryptCATAdminReleaseContext(hCatAdmin, 0);
            // hFile 由 FileStream 关闭，不要调用 CloseHandle
            guidHandle?.Free();
        }
    }

    private static X509Certificate2? GetCertificateFromSignedFile(string filePath)
    {
        try
        {
            // CreateFromSignedFile 支持嵌入式签名和目录签名
#pragma warning disable SYSLIB0057 // 类型或成员已过时
            var cert = X509Certificate2.CreateFromSignedFile(filePath);
            return cert as X509Certificate2 ?? X509CertificateLoader.LoadCertificate(cert.GetRawCertData()!);
#pragma warning restore SYSLIB0057
        }
        catch
        {
            return null;
        }
    }

    private static (bool IsTrustedCA, string ChainStatus) ValidateCertificateChain(X509Certificate2 cert)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;  // 离线检查
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            
            bool isValid = chain.Build(cert);
            
            // 检查根CA是否在受信任列表中
            bool isTrustedCA = false;
            if (chain.ChainElements.Count > 0)
            {
                var rootCert = chain.ChainElements[^1].Certificate;
                string rootSubject = rootCert.Subject;
                
                // 检查根CA是否在白名单中
                isTrustedCA = TrustedRootCAs.Any(ca => 
                    rootSubject.Contains(ca, StringComparison.OrdinalIgnoreCase));
            }
            
            // 收集链状态信息
            var status = new List<string>();
            foreach (var element in chain.ChainElements)
            {
                foreach (var chainStatus in element.ChainElementStatus)
                {
                    status.Add(chainStatus.Status.ToString());
                }
            }
            
            return (isTrustedCA, string.Join(", ", status));
        }
        catch (Exception ex)
        {
            return (false, $"Error: {ex.Message}");
        }
    }

    private static bool IsSelfSigned(X509Certificate2 cert)
    {
        // 检查是否是自签名证书
        if (string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase))
            return true;
        
        // 检查Issuer是否包含常见的自签名关键词
        string[] selfSignedKeywords = new[] { "CN=Test", "CN=Local", "CN=Dev", "CN=Root" };
        if (selfSignedKeywords.Any(kw => cert.Issuer.Contains(kw, StringComparison.OrdinalIgnoreCase)))
            return true;
        
        return false;
    }

    private static int CheckWinTrust(string filePath)
    {
        IntPtr? hFile = null;
        try
        {
            // 打开文件句柄，目录签名验证可能需要
            hFile = NativeMethods.CreateFileW(
                filePath,
                0x80000000, // GENERIC_READ
                0x00000001 | 0x00000002, // FILE_SHARE_READ | FILE_SHARE_WRITE
                IntPtr.Zero,
                3, // OPEN_EXISTING
                0x00000080, // FILE_ATTRIBUTE_NORMAL
                IntPtr.Zero);
            bool hasHandle = hFile.Value != new IntPtr(-1);

            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePath,
                hFile = hasHandle ? hFile.Value : IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            var trustData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,  // 不检查吊销，避免网络失败
                dwUnionChoice = WTD_CHOICE_FILE,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_SAFER_FLAG  // 使用 SAFER 信任提供程序
            };

            IntPtr pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);
            trustData.pFile = pFileInfo;

            IntPtr pTrustData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
            Marshal.StructureToPtr(trustData, pTrustData, false);

            Guid actionId = new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");
            int result = WinVerifyTrust(IntPtr.Zero, actionId, pTrustData);

            // 清理
            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(trustData, pTrustData, false);
            WinVerifyTrust(IntPtr.Zero, actionId, pTrustData);

            Marshal.FreeHGlobal(pFileInfo);
            Marshal.FreeHGlobal(pTrustData);

            if (hFile.HasValue && hFile.Value != new IntPtr(-1))
                NativeMethods.CloseHandle(hFile.Value);

            return result;
        }
        catch
        {
            if (hFile.HasValue && hFile.Value != new IntPtr(-1))
                NativeMethods.CloseHandle(hFile.Value);
            return -1;
        }
    }

    public static bool IsWellKnownPublisher(string? subject)
    {
        if (string.IsNullOrEmpty(subject))
            return false;

        return WellKnownPublishers.Any(p => subject.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsSystemFile(string filePath)
    {
        string[] systemPaths = new[]
        {
            @"C:\Windows\",
            @"C:\Program Files\",
            @"C:\Program Files (x86)\",
            @"C:\ProgramData\",
        };

        string normalizedPath = filePath.ToLowerInvariant();
        return systemPaths.Any(sp => normalizedPath.StartsWith(sp.ToLowerInvariant()));
    }
}
