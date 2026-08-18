using Melix.Shared;
using Microsoft.ML;
using Microsoft.ML.Data;

namespace Melix.Diagnose;

class Program
{
    private const string ModelPath = @"..\Melix-Core.zip";
    private const string BlackFolder = @"D:\Downloads\Black";
    private const string WhiteFolder = @"D:\Downloads\White";

    static void Main(string[] args)
    {
        if (args.Length > 0 && args[0].Equals("threshold", StringComparison.OrdinalIgnoreCase))
        {
            ThresholdAnalyzer.Run();
            return;
        }
        
        string targetFile = args.Length > 0 ? args[0] : @"D:\downloads\White\d3dcsx_42.dll";

        if (!File.Exists(targetFile))
        {
            Console.WriteLine($"文件不存在: {targetFile}");
            return;
        }

        if (!File.Exists(ModelPath))
        {
            Console.WriteLine($"模型不存在: {ModelPath}");
            return;
        }

        Console.WriteLine($"诊断文件: {targetFile}");
        Console.WriteLine();

        // 1. 加载模型
        var mlContext = new MLContext(seed: 42);
        var model = mlContext.Model.Load(ModelPath, out _);
        var predEngine = mlContext.Model.CreatePredictionEngine<ModelInput, ModelOutput>(model);

        // 2. 提取目标文件特征并预测
        var targetFeatures = FeatureExtractor.Extract(targetFile);
        var targetInput = new ModelInput { Features = targetFeatures };
        var targetPred = predEngine.Predict(targetInput);

        Console.WriteLine("=== 目标文件预测 ===");
        Console.WriteLine($"文件大小: {new FileInfo(targetFile).Length:N0} bytes");
        Console.WriteLine($"恶意概率: {targetPred.Probability:P4}");
        Console.WriteLine($"预测标签: {(targetPred.PredictedLabel ? "恶意" : "正常")}");
        Console.WriteLine($"原始分数: {targetPred.Score:F4}");
        Console.WriteLine();

        // 3. 特征分析：找出最异常的特征
        Console.WriteLine("=== 特征分布分析 ===");
        AnalyzeFeatures(targetFile, targetFeatures);

        // 4. 最近邻分析
        Console.WriteLine();
        Console.WriteLine("=== 最近邻分析（欧氏距离） ===");
        FindNearestNeighbors(targetFile, targetFeatures, 10);
    }

    static void AnalyzeFeatures(string targetFile, float[] features)
    {
        // 读取白样本和黑样本的平均特征
        var whiteFeatures = LoadSampleFeatures(WhiteFolder, 100);
        var blackFeatures = LoadSampleFeatures(BlackFolder, 100);

        if (whiteFeatures.Count == 0 || blackFeatures.Count == 0)
        {
            Console.WriteLine("样本不足，无法分析");
            return;
        }

        var whiteAvg = AverageFeatures(whiteFeatures);
        var blackAvg = AverageFeatures(blackFeatures);

        // 计算目标文件偏离白样本的程度
        var anomalies = new List<(int Index, string Name, float Target, float WhiteAvg, float BlackAvg, float WhiteDiff, float BlackDiff)>();

        string[] names = BuildFeatureNames();
        for (int i = 0; i < features.Length; i++)
        {
            float whiteDiff = Math.Abs(features[i] - whiteAvg[i]);
            float blackDiff = Math.Abs(features[i] - blackAvg[i]);
            anomalies.Add((i, names[i], features[i], whiteAvg[i], blackAvg[i], whiteDiff, blackDiff));
        }

        // 找出目标文件最像黑样本、最不像白样本的特征
        var topAnomalies = anomalies
            .OrderByDescending(a => a.BlackDiff - a.WhiteDiff) // 更像黑，更不像白
            .Take(15)
            .ToList();

        Console.WriteLine(string.Format("{0,-6} {1,-30} {2,-12} {3,-12} {4,-12} {5,-12}", "维度", "名称", "目标", "白均值", "黑均值", "像黑程度"));
        foreach (var a in topAnomalies)
        {
            string name = a.Name.Length > 30 ? a.Name.Substring(0, 30) : a.Name;
            Console.WriteLine($"{a.Index,-6} {name,-30} {a.Target,-12:F6} {a.WhiteAvg,-12:F6} {a.BlackAvg,-12:F6} {a.BlackDiff - a.WhiteDiff,-12:F6}");
        }
    }

    static void FindNearestNeighbors(string targetFile, float[] targetFeatures, int k)
    {
        var whiteFiles = Directory.Exists(WhiteFolder) ? Directory.GetFiles(WhiteFolder, "*.*", SearchOption.AllDirectories) : Array.Empty<string>();
        var blackFiles = Directory.Exists(BlackFolder) ? Directory.GetFiles(BlackFolder, "*.*", SearchOption.AllDirectories) : Array.Empty<string>();

        var random = new Random(42);
        var sampledWhite = whiteFiles.OrderBy(x => random.Next()).Take(200).ToList();
        var sampledBlack = blackFiles.OrderBy(x => random.Next()).Take(200).ToList();

        var neighbors = new List<(string File, string Label, float Distance)>();

        foreach (var f in sampledWhite)
        {
            try
            {
                var feats = FeatureExtractor.Extract(f);
                float dist = EuclideanDistance(targetFeatures, feats);
                neighbors.Add((f, "正常", dist));
            }
            catch { }
        }

        foreach (var f in sampledBlack)
        {
            try
            {
                var feats = FeatureExtractor.Extract(f);
                float dist = EuclideanDistance(targetFeatures, feats);
                neighbors.Add((f, "恶意", dist));
            }
            catch { }
        }

        var nearest = neighbors.OrderBy(n => n.Distance).Take(k).ToList();
        Console.WriteLine(string.Format("{0,-10} {1,-6} {2,-80}", "距离", "标签", "文件路径"));
        foreach (var n in nearest)
        {
            string path = n.File.Length > 80 ? "..." + n.File.Substring(n.File.Length - 77) : n.File;
            Console.WriteLine($"{n.Distance,-10:F6} {n.Label,-6} {path}");
        }
    }

    static List<float[]> LoadSampleFeatures(string folder, int count)
    {
        var result = new List<float[]>();
        if (!Directory.Exists(folder)) return result;

        var files = Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories);
        var random = new Random(42);
        var sampled = files.OrderBy(x => random.Next()).Take(count).ToList();

        foreach (var f in sampled)
        {
            try
            {
                result.Add(FeatureExtractor.Extract(f));
            }
            catch { }
        }
        return result;
    }

    static float[] AverageFeatures(List<float[]> features)
    {
        if (features.Count == 0) return Array.Empty<float>();
        int dim = features[0].Length;
        var avg = new float[dim];
        for (int i = 0; i < dim; i++)
        {
            double sum = 0;
            foreach (var f in features) sum += f[i];
            avg[i] = (float)(sum / features.Count);
        }
        return avg;
    }

    static float EuclideanDistance(float[] a, float[] b)
    {
        double sum = 0;
        for (int i = 0; i < a.Length; i++)
        {
            double diff = a[i] - b[i];
            sum += diff * diff;
        }
        return (float)Math.Sqrt(sum);
    }

    static string[] BuildFeatureNames()
    {
        var names = new List<string>();
        for (int i = 0; i < 256; i++) names.Add($"ByteFreq_{i:X2}");
        names.Add("GlobalEntropy");
        names.Add("BlockEntropyMean");
        names.Add("BlockEntropyStd");
        names.Add("BlockEntropyMax");
        names.Add("BlockEntropyMin");
        names.Add("FirstHalfEntropy");
        names.Add("SecondHalfEntropy");
        names.Add("PrintableRatio");
        names.Add("ControlRatio");
        names.Add("HighByteRatio");
        names.Add("ZeroRatio");
        names.Add("UniqueByteRatio");
        names.Add("FileSizeLog");
        names.Add("IsPE");
        names.Add("SectionCount");
        names.Add("HasImport");
        names.Add("AvgSectionEntropy");
        return names.ToArray();
    }
}

public class ModelInput
{
    [VectorType(273)]
    public float[] Features { get; set; } = Array.Empty<float>();
}

public class ModelOutput
{
    [ColumnName("PredictedLabel")]
    public bool PredictedLabel { get; set; }

    [ColumnName("Probability")]
    public float Probability { get; set; }

    [ColumnName("Score")]
    public float Score { get; set; }
}
