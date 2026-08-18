namespace Melix.Shared;

public static class FeatureExtractor
{
    // 303维增强特征：
    // 256字节频率 + 熵 + 统计 + 增强PE结构（头、节区、导入、资源、字符串）
    private const int FeatureDim = 303;
    private const int ChunkSize = 1024 * 1024; // 1MB 分块
    private const int PeHeaderSize = 8192;       // PE头基础解析
    private const int ExtendedReadSize = 262144; // 256KB，用于导入/资源表解析
    private const int MinFileSize = 16;
    private const int StringMinLength = 4;

    public static int FeatureCount => FeatureDim;

    public static float[] Extract(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"File not found: {filePath}");

        var fileInfo = new FileInfo(filePath);
        long fileSize = fileInfo.Length;

        if (fileSize < MinFileSize)
            return CreateDefaultFeatures((int)fileSize);

        return ExtractFeaturesStreaming(filePath, fileSize);
    }

    private static float[] ExtractFeaturesStreaming(string filePath, long fileSize)
    {
        var features = new float[FeatureDim];

        var globalCounts = new long[256];
        var blockCounts = new long[8 * 256]; // 8块 x 256字节
        var halfCounts = new long[2 * 256];  // 2半 x 256字节

        byte[]? peHeader = null;

        long printable = 0, control = 0, high = 0, zeros = 0;
        long totalBytes = 0;
        long halfPoint = fileSize / 2;
        int numBlocks = 8;
        int blockSize = (int)Math.Max(1, fileSize / numBlocks);

        // 字符串统计
        long stringCount = 0;
        long totalStringLength = 0;
        long urlLikeCount = 0;
        long ipLikeCount = 0;
        int currentStringLength = 0;
        var currentString = new System.Text.StringBuilder(64);

        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 65536);
        byte[] buffer = new byte[ChunkSize];
        int bytesRead;
        long position = 0;

        while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
        {
            // 保留前8KB用于PE结构解析
            if (position == 0 && peHeader == null)
            {
                int peLen = Math.Min(bytesRead, PeHeaderSize);
                peHeader = new byte[peLen];
                Buffer.BlockCopy(buffer, 0, peHeader, 0, peLen);
            }

            for (int i = 0; i < bytesRead; i++)
            {
                byte b = buffer[i];
                long absPos = position + i;

                globalCounts[b]++;

                int blockIdx = Math.Min((int)(absPos / blockSize), numBlocks - 1);
                blockCounts[blockIdx * 256 + b]++;

                int halfIdx = absPos < halfPoint ? 0 : 1;
                halfCounts[halfIdx * 256 + b]++;

                if (b >= 32 && b <= 126) printable++;
                else if (b < 32 || b == 127) control++;
                if (b >= 0x80) high++;
                if (b == 0) zeros++;

                // 字符串提取：可打印ASCII
                if (b >= 32 && b <= 126)
                {
                    if (currentStringLength < 64)
                        currentString.Append((char)b);
                    currentStringLength++;
                }
                else
                {
                    if (currentStringLength >= StringMinLength)
                    {
                        stringCount++;
                        totalStringLength += currentStringLength;
                        string s = currentString.ToString();
                        if (LooksLikeUrl(s)) urlLikeCount++;
                        if (LooksLikeIp(s)) ipLikeCount++;
                    }
                    currentString.Clear();
                    currentStringLength = 0;
                }
            }

            totalBytes += bytesRead;
            position += bytesRead;
        }

        // 处理末尾字符串
        if (currentStringLength >= StringMinLength)
        {
            stringCount++;
            totalStringLength += currentStringLength;
            string s = currentString.ToString();
            if (LooksLikeUrl(s)) urlLikeCount++;
            if (LooksLikeIp(s)) ipLikeCount++;
        }

        double total = totalBytes;
        int idx = 0;

        // 1. 字节频率直方图 (256维)
        for (int i = 0; i < 256; i++)
            features[idx++] = (float)(globalCounts[i] / total);

        // 2. 全局熵 (1维)
        features[idx++] = CalculateEntropy(globalCounts, 0, total);

        // 3. 块熵统计 (4维)
        var blockEnts = new float[numBlocks];
        for (int b = 0; b < numBlocks; b++)
        {
            int blockLen = (b < numBlocks - 1) ? blockSize : (int)(fileSize - (long)b * blockSize);
            blockEnts[b] = CalculateEntropy(blockCounts, b * 256, blockLen);
        }
        features[idx++] = blockEnts.Average();
        features[idx++] = (float)Math.Sqrt(blockEnts.Select(e => (e - blockEnts.Average()) * (e - blockEnts.Average())).Average());
        features[idx++] = blockEnts.Max();
        features[idx++] = blockEnts.Min();

        // 4. 前后半熵 (2维)
        int halfLen = (int)halfPoint;
        int secondHalfLen = (int)(fileSize - halfPoint);
        features[idx++] = CalculateEntropy(halfCounts, 0, halfLen);
        features[idx++] = CalculateEntropy(halfCounts, 256, secondHalfLen);

        // 5. 基础统计 (6维)
        features[idx++] = (float)(printable / total);
        features[idx++] = (float)(control / total);
        features[idx++] = (float)(high / total);
        features[idx++] = (float)(zeros / total);

        int unique = 0;
        for (int i = 0; i < 256; i++) if (globalCounts[i] > 0) unique++;
        features[idx++] = unique / 256.0f;
        features[idx++] = (float)Math.Log10(fileSize + 1);

        // 6. 增强PE结构特征
        var peFeatures = peHeader != null ? ParseEnhancedPEFeatures(filePath, peHeader, fileSize) : new PEFeatures();
        
        // PE头特征 (12维)
        features[idx++] = peFeatures.IsPE ? 1.0f : 0.0f;
        features[idx++] = peFeatures.IsDLL ? 1.0f : 0.0f;
        features[idx++] = peFeatures.IsEXE ? 1.0f : 0.0f;
        features[idx++] = (float)peFeatures.Subsystem / 16.0f;
        features[idx++] = (float)Math.Log10(peFeatures.ImageBase + 1);
        features[idx++] = (float)Math.Log10(peFeatures.SizeOfImage + 1);
        features[idx++] = Math.Min(peFeatures.EntryPoint / (float)int.MaxValue, 1.0f);
        features[idx++] = Math.Min(peFeatures.NumberOfSections / 16.0f, 1.0f);
        features[idx++] = (float)Math.Log10(peFeatures.SizeOfHeaders + 1);
        features[idx++] = Math.Min(peFeatures.CheckSum / (float)uint.MaxValue, 1.0f);
        features[idx++] = (float)peFeatures.Characteristics / 65535.0f;
        features[idx++] = Math.Min(peFeatures.TimeDateStamp / 4_000_000_000.0f, 1.0f);

        // 节区特征 (12维)
        features[idx++] = Math.Min(peFeatures.NumExecutableSections / 8.0f, 1.0f);
        features[idx++] = Math.Min(peFeatures.NumWritableSections / 8.0f, 1.0f);
        features[idx++] = Math.Min(peFeatures.NumReadableSections / 8.0f, 1.0f);
        features[idx++] = Math.Min(peFeatures.NumCodeSections / 8.0f, 1.0f);
        features[idx++] = Math.Min(peFeatures.NumDataSections / 8.0f, 1.0f);
        features[idx++] = Math.Min(peFeatures.MaxSectionEntropy / 8.0f, 1.0f);
        features[idx++] = Math.Min(peFeatures.MinSectionEntropy / 8.0f, 1.0f);
        features[idx++] = Math.Min(peFeatures.MeanSectionEntropy / 8.0f, 1.0f);
        features[idx++] = (float)Math.Log10(peFeatures.MaxSectionSize + 1);
        features[idx++] = (float)Math.Log10(peFeatures.MinSectionSize + 1);
        features[idx++] = (float)Math.Log10(peFeatures.TotalRawSize + 1);
        features[idx++] = (float)Math.Log10(peFeatures.TotalVirtualSize + 1);

        // 导入特征 (3维)
        features[idx++] = peFeatures.HasImport ? 1.0f : 0.0f;
        features[idx++] = (float)Math.Log10(peFeatures.NumberOfImportedDlls + 1);
        features[idx++] = (float)Math.Log10(peFeatures.NumberOfImportedFunctions + 1);

        // 资源特征 (2维)
        features[idx++] = peFeatures.HasResource ? 1.0f : 0.0f;
        features[idx++] = (float)Math.Log10(peFeatures.ResourceSize + 1);

        // 字符串特征 (5维)
        features[idx++] = (float)Math.Log10(stringCount + 1);
        features[idx++] = stringCount > 0 ? Math.Min(totalStringLength / (float)stringCount / 64.0f, 1.0f) : 0f;
        features[idx++] = (float)Math.Log10(urlLikeCount + 1);
        features[idx++] = (float)Math.Log10(ipLikeCount + 1);
        features[idx++] = peFeatures.HasSuspiciousImports ? 1.0f : 0.0f;

        return features;
    }

    private static float[] CreateDefaultFeatures(int fileSize)
    {
        var features = new float[FeatureDim];
        features[256] = 0.0f;
        features[265] = (float)Math.Log10(fileSize + 1);
        return features;
    }

    private static float CalculateEntropy(long[] counts, int offset, double total)
    {
        if (total <= 0) return 0;
        double entropy = 0;
        for (int i = 0; i < 256; i++)
        {
            long c = counts[offset + i];
            if (c > 0)
            {
                double p = c / total;
                entropy -= p * Math.Log2(p);
            }
        }
        return (float)entropy;
    }

    private static bool LooksLikeUrl(string s)
    {
        return s.Contains("http://") || s.Contains("https://") || s.Contains("www.") || s.Contains(".com") || s.Contains(".net") || s.Contains(".org");
    }

    private static bool LooksLikeIp(string s)
    {
        if (s.Length < 7 || s.Length > 15) return false;
        int dotCount = 0;
        bool lastWasDigit = false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '.')
            {
                dotCount++;
                lastWasDigit = false;
            }
            else if (c >= '0' && c <= '9')
            {
                lastWasDigit = true;
            }
            else
            {
                return false;
            }
        }
        return dotCount == 3 && lastWasDigit;
    }

    public static bool IsPEFile(string filePath)
    {
        if (!File.Exists(filePath)) return false;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            byte[] header = new byte[64];
            if (fs.Read(header, 0, 64) < 64) return false;
            if (header[0] != 'M' || header[1] != 'Z') return false;

            int peOffset = BitConverter.ToInt32(header, 60);
            if (peOffset <= 0) return false;

            fs.Position = peOffset;
            byte[] peSig = new byte[4];
            if (fs.Read(peSig, 0, 4) < 4) return false;
            return peSig[0] == 'P' && peSig[1] == 'E';
        }
        catch { return false; }
    }

    #region Enhanced PE Parsing

    private struct PEFeatures
    {
        public bool IsPE;
        public bool IsDLL;
        public bool IsEXE;
        public int Subsystem;
        public ulong ImageBase;
        public uint SizeOfImage;
        public uint EntryPoint;
        public int NumberOfSections;
        public uint SizeOfOptionalHeader;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Characteristics;
        public uint TimeDateStamp;

        public int NumExecutableSections;
        public int NumWritableSections;
        public int NumReadableSections;
        public int NumCodeSections;
        public int NumDataSections;
        public float MaxSectionEntropy;
        public float MinSectionEntropy;
        public float MeanSectionEntropy;
        public long MaxSectionSize;
        public long MinSectionSize;
        public long TotalRawSize;
        public long TotalVirtualSize;

        public bool HasImport;
        public int NumberOfImportedDlls;
        public int NumberOfImportedFunctions;

        public bool HasResource;
        public long ResourceSize;

        public bool HasSuspiciousImports;
    }

    private struct SectionInfo
    {
        public string Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint RawSize;
        public uint RawAddress;
        public uint Characteristics;
    }

    private static PEFeatures ParseEnhancedPEFeatures(string filePath, byte[] peHeader, long fileSize)
    {
        var result = new PEFeatures();
        if (peHeader.Length < 64 || peHeader[0] != 'M' || peHeader[1] != 'Z')
            return result;

        int peOffset = BitConverter.ToInt32(peHeader, 60);
        if (peOffset < 0 || peOffset + 24 > peHeader.Length || peHeader[peOffset] != 'P' || peHeader[peOffset + 1] != 'E')
            return result;

        result.IsPE = true;

        // COFF Header
        int machine = BitConverter.ToUInt16(peHeader, peOffset + 4);
        result.NumberOfSections = BitConverter.ToUInt16(peHeader, peOffset + 6);
        result.TimeDateStamp = BitConverter.ToUInt32(peHeader, peOffset + 8);
        result.SizeOfOptionalHeader = BitConverter.ToUInt16(peHeader, peOffset + 20);
        result.Characteristics = BitConverter.ToUInt16(peHeader, peOffset + 22);
        result.IsDLL = (result.Characteristics & 0x2000) != 0;
        result.IsEXE = !result.IsDLL;

        int optionalHeaderOffset = peOffset + 24;
        if (optionalHeaderOffset + 2 > peHeader.Length)
            return result;

        ushort magic = BitConverter.ToUInt16(peHeader, optionalHeaderOffset);
        bool isPE32Plus = magic == 0x20B;

        // Read important optional header fields
        if (optionalHeaderOffset + 68 <= peHeader.Length)
        {
            result.EntryPoint = BitConverter.ToUInt32(peHeader, optionalHeaderOffset + 16);
            if (isPE32Plus)
            {
                result.ImageBase = BitConverter.ToUInt64(peHeader, optionalHeaderOffset + 24);
            }
            else
            {
                result.ImageBase = BitConverter.ToUInt32(peHeader, optionalHeaderOffset + 28);
            }
        }

        if (optionalHeaderOffset + (isPE32Plus ? 120 : 104) <= peHeader.Length)
        {
            int sizeOfImageOffset = optionalHeaderOffset + (isPE32Plus ? 56 : 56);
            result.SizeOfImage = BitConverter.ToUInt32(peHeader, sizeOfImageOffset);
            int sizeOfHeadersOffset = optionalHeaderOffset + (isPE32Plus ? 60 : 60);
            result.SizeOfHeaders = BitConverter.ToUInt32(peHeader, sizeOfHeadersOffset);
            int checkSumOffset = optionalHeaderOffset + (isPE32Plus ? 64 : 64);
            result.CheckSum = BitConverter.ToUInt32(peHeader, checkSumOffset);
            int subsystemOffset = optionalHeaderOffset + (isPE32Plus ? 68 : 68);
            result.Subsystem = BitConverter.ToUInt16(peHeader, subsystemOffset);
        }

        // Data directories
        int dataDirOffset = optionalHeaderOffset + (isPE32Plus ? 112 : 96);
        int dataDirCount = 16;
        var dataDirs = new (uint Rva, uint Size)[dataDirCount];
        for (int i = 0; i < dataDirCount && dataDirOffset + 8 * (i + 1) <= peHeader.Length; i++)
        {
            dataDirs[i] = (
                BitConverter.ToUInt32(peHeader, dataDirOffset + i * 8),
                BitConverter.ToUInt32(peHeader, dataDirOffset + i * 8 + 4)
            );
        }

        // Section table
        int sectionTableOffset = optionalHeaderOffset + (int)result.SizeOfOptionalHeader;
        var sections = new List<SectionInfo>();
        for (int i = 0; i < result.NumberOfSections && i < 64; i++)
        {
            int secOff = sectionTableOffset + i * 40;
            if (secOff + 40 > peHeader.Length) break;

            var sec = new SectionInfo
            {
                Name = GetSectionName(peHeader, secOff),
                VirtualSize = BitConverter.ToUInt32(peHeader, secOff + 8),
                VirtualAddress = BitConverter.ToUInt32(peHeader, secOff + 12),
                RawSize = BitConverter.ToUInt32(peHeader, secOff + 16),
                RawAddress = BitConverter.ToUInt32(peHeader, secOff + 20),
                Characteristics = BitConverter.ToUInt32(peHeader, secOff + 36)
            };
            sections.Add(sec);
        }

        // 加载扩展数据用于节区熵/导入/资源解析
        byte[]? extendedData = LoadExtendedData(filePath, sections, dataDirs, fileSize);

        // 节区特征
        ComputeSectionFeatures(ref result, sections, extendedData);

        // 导入特征
        if (dataDirs.Length > 1 && dataDirs[1].Rva > 0)
        {
            ComputeImportFeatures(ref result, sections, extendedData, dataDirs[1].Rva);
        }

        // 资源特征
        if (dataDirs.Length > 2)
        {
            result.HasResource = dataDirs[2].Rva != 0;
            result.ResourceSize = (long)dataDirs[2].Size;
        }

        return result;
    }

    private static byte[]? LoadExtendedData(string filePath, List<SectionInfo> sections, (uint Rva, uint Size)[] dataDirs, long fileSize)
    {
        try
        {
            // 确定需要读取的最大范围
            long maxRaw = 0;
            long maxSize = 0;

            // 节区
            foreach (var sec in sections)
            {
                if (sec.RawAddress > 0 && sec.RawSize > 0)
                {
                    long end = sec.RawAddress + sec.RawSize;
                    if (end > maxRaw + maxSize)
                    {
                        maxRaw = sec.RawAddress;
                        maxSize = sec.RawSize;
                    }
                }
            }

            // 导入表
            if (dataDirs.Length > 1 && dataDirs[1].Rva > 0)
            {
                var importRaw = RvaToRaw(dataDirs[1].Rva, sections);
                if (importRaw >= 0)
                {
                    long end = importRaw + Math.Max(dataDirs[1].Size, 4096);
                    if (end > maxRaw + maxSize)
                    {
                        maxRaw = importRaw;
                        maxSize = Math.Max(dataDirs[1].Size, 4096);
                    }
                }
            }

            // 资源表
            if (dataDirs.Length > 2 && dataDirs[2].Rva > 0)
            {
                var resourceRaw = RvaToRaw(dataDirs[2].Rva, sections);
                if (resourceRaw >= 0)
                {
                    long end = resourceRaw + Math.Max(dataDirs[2].Size, 4096);
                    if (end > maxRaw + maxSize)
                    {
                        maxRaw = resourceRaw;
                        maxSize = Math.Max(dataDirs[2].Size, 4096);
                    }
                }
            }

            if (maxRaw < 0 || maxSize <= 0) return null;

            long start = maxRaw;
            long endPos = Math.Min(start + maxSize, fileSize);
            int readSize = (int)Math.Min(endPos - start, ExtendedReadSize);
            if (readSize <= 0) return null;

            byte[] data = new byte[readSize];
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            fs.Position = start;
            int read = fs.Read(data, 0, readSize);
            if (read < readSize) return data.Take(read).ToArray();
            return data;
        }
        catch { return null; }
    }

    private static long RvaToRaw(uint rva, List<SectionInfo> sections)
    {
        foreach (var sec in sections)
        {
            if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + Math.Max(sec.VirtualSize, sec.RawSize))
            {
                if (sec.RawAddress == 0) return -1;
                long offset = rva - sec.VirtualAddress;
                return sec.RawAddress + offset;
            }
        }
        return -1;
    }

    private static void ComputeSectionFeatures(ref PEFeatures result, List<SectionInfo> sections, byte[]? extendedData)
    {
        if (sections.Count == 0) return;

        var entropies = new List<float>();
        long maxSize = 0;
        long minSize = long.MaxValue;
        long totalRaw = 0;
        long totalVirtual = 0;

        foreach (var sec in sections)
        {
            bool exec = (sec.Characteristics & 0x20000000) != 0;
            bool write = (sec.Characteristics & 0x80000000) != 0;
            bool read = (sec.Characteristics & 0x40000000) != 0;
            bool code = (sec.Characteristics & 0x00000020) != 0;
            bool initData = (sec.Characteristics & 0x00000040) != 0;
            bool uninitData = (sec.Characteristics & 0x00000080) != 0;

            if (exec) result.NumExecutableSections++;
            if (write) result.NumWritableSections++;
            if (read) result.NumReadableSections++;
            if (code) result.NumCodeSections++;
            if (initData || uninitData) result.NumDataSections++;

            long rawSize = sec.RawSize;
            long virtSize = sec.VirtualSize;
            totalRaw += rawSize;
            totalVirtual += virtSize;
            if (rawSize > maxSize) maxSize = rawSize;
            if (rawSize < minSize) minSize = rawSize;

            // 计算节区熵
            if (extendedData != null && sec.RawAddress > 0 && sec.RawSize > 0)
            {
                long start = sec.RawAddress;
                int len = (int)Math.Min(sec.RawSize, extendedData.Length - start);
                if (len > 0 && start < extendedData.Length)
                {
                    float ent = CalculateByteEntropy(extendedData, (int)start, len);
                    entropies.Add(ent);
                }
            }
        }

        result.MaxSectionSize = maxSize;
        result.MinSectionSize = minSize == long.MaxValue ? 0 : minSize;
        result.TotalRawSize = totalRaw;
        result.TotalVirtualSize = totalVirtual;

        if (entropies.Count > 0)
        {
            result.MaxSectionEntropy = entropies.Max();
            result.MinSectionEntropy = entropies.Min();
            result.MeanSectionEntropy = entropies.Average();
        }
    }

    private static void ComputeImportFeatures(ref PEFeatures result, List<SectionInfo> sections, byte[]? extendedData, uint importRva)
    {
        if (extendedData == null) return;

        long raw = RvaToRaw(importRva, sections);
        if (raw < 0 || raw >= extendedData.Length) return;

        int offset = (int)raw;
        const int ImportDescriptorSize = 20;
        var dllNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int functionCount = 0;
        bool hasSuspicious = false;

        int maxDescriptors = 1000;
        for (int i = 0; i < maxDescriptors; i++)
        {
            int descOff = offset + i * ImportDescriptorSize;
            if (descOff + ImportDescriptorSize > extendedData.Length) break;

            uint origFirstThunk = BitConverter.ToUInt32(extendedData, descOff);
            uint nameRva = BitConverter.ToUInt32(extendedData, descOff + 12);
            uint firstThunk = BitConverter.ToUInt32(extendedData, descOff + 16);

            if (origFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;

            // 读取 DLL 名
            if (nameRva > 0)
            {
                long nameRaw = RvaToRaw(nameRva, sections);
                if (nameRaw >= 0 && nameRaw < extendedData.Length)
                {
                    string dllName = ReadNullTerminatedString(extendedData, (int)nameRaw);
                    if (!string.IsNullOrEmpty(dllName))
                        dllNames.Add(dllName);
                }
            }

            // 读取导入函数
            uint thunkRva = origFirstThunk != 0 ? origFirstThunk : firstThunk;
            if (thunkRva > 0)
            {
                long thunkRaw = RvaToRaw(thunkRva, sections);
                if (thunkRaw >= 0 && thunkRaw < extendedData.Length)
                {
                    int thunkOff = (int)thunkRaw;
                    int maxImports = 2000;
                    for (int j = 0; j < maxImports; j++)
                    {
                        if (thunkOff + 4 > extendedData.Length) break;
                        uint thunk = BitConverter.ToUInt32(extendedData, thunkOff);
                        thunkOff += 4;
                        if (thunk == 0) break;

                        // 按序号导入（最高位为1）
                        if ((thunk & 0x80000000) != 0)
                        {
                            functionCount++;
                            continue;
                        }

                        // 按名称导入
                        long nameRaw = RvaToRaw(thunk, sections);
                        if (nameRaw >= 0 && nameRaw < extendedData.Length)
                        {
                            int hintLen = 2; // hint
                            int nameStart = (int)nameRaw + hintLen;
                            string funcName = ReadNullTerminatedString(extendedData, nameStart);
                            if (!string.IsNullOrEmpty(funcName))
                            {
                                functionCount++;
                                if (IsSuspiciousApi(funcName))
                                    hasSuspicious = true;
                            }
                        }
                    }
                }
            }
        }

        result.HasImport = dllNames.Count > 0 || functionCount > 0;
        result.NumberOfImportedDlls = dllNames.Count;
        result.NumberOfImportedFunctions = functionCount;
        result.HasSuspiciousImports = hasSuspicious;
    }

    private static bool IsSuspiciousApi(string name)
    {
        string lower = name.ToLowerInvariant();
        string[] suspicious = new[]
        {
            "create", "remote", "thread", "process", "alloc", "virtual", "write", "read",
            "inject", "load", "library", "getproc", "shell", "exec", "winexec", "createprocess",
            "regset", "regcreate", "internet", "wininet", "url", "socket", "connect", "send",
            "recv", "download", "urlmon", "crypt", "encrypt", "decrypt", "hash"
        };
        return suspicious.Any(s => lower.Contains(s));
    }

    private static string GetSectionName(byte[] data, int offset)
    {
        var sb = new System.Text.StringBuilder(8);
        for (int i = 0; i < 8 && offset + i < data.Length; i++)
        {
            byte b = data[offset + i];
            if (b == 0) break;
            sb.Append((char)b);
        }
        return sb.ToString();
    }

    private static string ReadNullTerminatedString(byte[] data, int offset)
    {
        var sb = new System.Text.StringBuilder(64);
        for (int i = 0; i < 128 && offset + i < data.Length; i++)
        {
            byte b = data[offset + i];
            if (b == 0) break;
            if (b >= 32 && b <= 126) sb.Append((char)b);
            else break;
        }
        return sb.ToString();
    }

    private static float CalculateByteEntropy(byte[] bytes, int offset, int length)
    {
        if (length <= 0) return 0;
        var counts = new long[256];
        int end = Math.Min(offset + length, bytes.Length);
        for (int i = offset; i < end; i++) counts[bytes[i]]++;
        return CalculateEntropy(counts, 0, end - offset);
    }

    #endregion
}
