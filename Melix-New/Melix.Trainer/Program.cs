using System.Text;
using System.Collections.Concurrent;
using Melix.Shared;
using Microsoft.ML;
using Microsoft.ML.Data;

namespace Melix.Trainer;

class Program
{
    private const int ExpectedFeatureCount = 303;  // 256字节频率 + 熵 + 统计 + 增强PE结构（头、节区、导入、资源、字符串）
    
    // 颜色代码
    private const string Reset = "\x1b[0m";
    private const string Red = "\x1b[91m";
    private const string Green = "\x1b[92m";
    private const string Yellow = "\x1b[93m";
    private const string Cyan = "\x1b[96m";
    private const string Gray = "\x1b[90m";
    private const string White = "\x1b[97m";
    
    static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        PrintBanner();
        
        string blackFolder = @"D:\Downloads\Black";
        string whiteFolder = @"D:\Downloads\White";
        string modelPath = "Melix-Core.zip";
        string onnxPath = "DeepMode.onnx";
        
        Console.WriteLine();
        PrintColored("=== 训练参数 ===", White);
        PrintColored($"可疑样本库: {blackFolder}", White);
        PrintColored($"正常样本库: {whiteFolder}", White);
        PrintColored($"核心模型路径: {modelPath}", White);
        PrintColored($"导出模型路径: {onnxPath}", White);
        PrintColored($"特征维度: {ExpectedFeatureCount}", White);
        Console.WriteLine();
        
        var data = LoadData(blackFolder, whiteFolder);
        if (data.Count == 0)
        {
            PrintColored("错误: 没有加载到任何数据!", Red);
            return;
        }
        
        PrintColored($"数据载入完成，总共 {data.Count} 个文件", Green);
        Console.WriteLine();
        
        var model = TrainModel(data, modelPath, onnxPath);
        
        if (model != null)
        {
            PrintColored("=============================================", Green);
            PrintColored("  训练完成！", Green);
            PrintColored($"  核心模型已保存至: {modelPath}", Green);
            PrintColored($"  导出格式已保存至: {onnxPath}", Green);
            PrintColored("=============================================", Green);
        }
        
        Console.WriteLine();
        PrintColored("按任意键退出...", Gray);
        try
        {
            Console.ReadKey();
        }
        catch (InvalidOperationException)
        {
            // 非交互式终端忽略
        }
    }
    
    static void PrintBanner()
    {
        Console.WriteLine();
        PrintColored("  __  __          _   _            _____                   _                ", White);
        PrintColored(" |  \\/  |   ___  | | (_) __  __   | ____|  _ __     __ _  (_)  _ __     ___ ", White);
        PrintColored(" | |\\/| |  / _ \\ | | | | \\ \\/ /   |  _|   | '_ \\   / _` | | | | '_ \\   / _ \\ ", White);
        PrintColored(" | |  | | |  __/ | | | |  >  <    | |___  | | | | | (_| | | | | | | | |  __/ ", White);
        PrintColored(" |_|  |_|  \\___| |_| |_| /_/\\_\\   |_____| |_| |_|  \\__, | |_| |_| |_|  \\___| ", White);
        PrintColored("                                                    |___/                    ", White);
        PrintColored("================================================================", White);
        PrintColored("  Melix Engine - 轻量GBM模型训练系统", White);
        PrintColored("================================================================", White);
    }
    
    static void PrintColored(string text, string color)
    {
        Console.WriteLine($"{color}{text}{Reset}");
    }
    
    static void PrintProgressBar(int current, int total, string label)
    {
        int width = 40;
        float percent = (float)current / total;
        int filled = (int)(width * percent);
        int empty = width - filled;
        
        string bar = $"{White}{new string('█', filled)}{Gray}{new string('░', empty)}{Reset}";
        string percentStr = $"{Cyan}{percent * 100,5:F1}%{Reset}";
        string labelColored = $"{Yellow}{label}{Reset}";
        string countColored = $"{White}({current}/{total}){Reset}";
        
        Console.Write($"\r[{bar}] {percentStr} {labelColored} {countColored}");
    }
    
    static List<FileData> LoadData(string blackFolder, string whiteFolder)
    {
        var data = new List<FileData>();
        
        if (Directory.Exists(blackFolder))
        {
            PrintColored($"正在扫描可疑样本库: {blackFolder}", Yellow);
            var files = Directory.GetFiles(blackFolder, "*.*", SearchOption.AllDirectories);
            PrintColored($"发现 {files.Length} 个文件，开始并行载入...", Yellow);
            
            var blackData = LoadFiles(files, label: true);
            data.AddRange(blackData);
            PrintColored($"可疑样本库载入完成: {blackData.Count} 个", Green);
        }
        
        if (Directory.Exists(whiteFolder))
        {
            PrintColored($"\n正在扫描正常样本库: {whiteFolder}", Yellow);
            var files = Directory.GetFiles(whiteFolder, "*.*", SearchOption.AllDirectories);
            PrintColored($"发现 {files.Length} 个文件，开始并行载入...", Yellow);
            
            var whiteData = LoadFiles(files, label: false);
            data.AddRange(whiteData);
            PrintColored($"正常样本库载入完成: {whiteData.Count} 个", Green);
        }
        
        return data;
    }
    
    static List<FileData> LoadFiles(string[] files, bool label)
    {
        var result = new ConcurrentBag<FileData>();
        int processed = 0;
        int skippedNonPE = 0;
        var lockObj = new object();
        
        Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, file =>
        {
            int current = Interlocked.Increment(ref processed);
            
            if (current % 100 == 0 || current == files.Length)
            {
                lock (lockObj)
                {
                    PrintProgressBar(current, files.Length, label ? "可疑样本" : "正常样本");
                }
            }
            
            try
            {
                // 只加载PE文件，过滤非PE并直接删除
                if (!FeatureExtractor.IsPEFile(file))
                {
                    Interlocked.Increment(ref skippedNonPE);
                    try
                    {
                        File.Delete(file);
                    }
                    catch { }
                    return;
                }
                
                var features = FeatureExtractor.Extract(file);
                result.Add(new FileData 
                { 
                    FilePath = file, 
                    Features = features, 
                    Label = label 
                });
            }
            catch 
            { 
                // 忽略异常文件
            }
        });
        
        Console.WriteLine();
        if (skippedNonPE > 0)
        {
            PrintColored($"  已跳过非PE文件: {skippedNonPE} 个", Yellow);
        }
        return result.ToList();
    }
    
    static List<FileData> BalanceData(List<FileData> data)
    {
        var blackFiles = data.Where(d => d.Label).ToList();
        var whiteFiles = data.Where(d => !d.Label).ToList();
        
        int blackCount = blackFiles.Count;
        int whiteCount = whiteFiles.Count;
        
        PrintColored($"数据分布: 可疑 {blackCount} 个, 正常 {whiteCount} 个", Yellow);
        PrintColored("保留全部样本，不进行欠采样", Yellow);
        
        return data;
    }
    
    static ITransformer? TrainModel(List<FileData> data, string modelPath, string onnxPath)
    {
        PrintColored("\n开始训练核心模型...", Cyan);
        
        var balancedData = BalanceData(data);
        int newBlackCount = balancedData.Count(d => d.Label);
        int newWhiteCount = balancedData.Count(d => !d.Label);
        PrintColored($"平衡后: 可疑 {newBlackCount} 个, 正常 {newWhiteCount} 个", Yellow);
        
        var mlContext = new MLContext(seed: 42);
        
        var trainingData = balancedData.Select(d => new ModelInput
        {
            Features = d.Features,
            Label = d.Label
        }).ToList();
        
        var dataView = mlContext.Data.LoadFromEnumerable(trainingData);
        var split = mlContext.Data.TrainTestSplit(dataView, testFraction: 0.2);
        var trainSet = split.TrainSet;
        var testSet = split.TestSet;
        
        PrintColored("正在构建轻量梯度提升树...", Yellow);
        
        // 优化后的LightGBM参数：防止过拟合，速度更快
        var pipeline = mlContext.Transforms.Concatenate("Features", nameof(ModelInput.Features))
            .Append(mlContext.BinaryClassification.Trainers.LightGbm(
                labelColumnName: nameof(ModelInput.Label),
                featureColumnName: "Features",
                learningRate: 0.1,
                numberOfLeaves: 31,
                minimumExampleCountPerLeaf: 50,
                numberOfIterations: 300));
        
        var model = pipeline.Fit(trainSet);
        
        PrintColored("正在评估模型性能...", Yellow);
        var predictions = model.Transform(testSet);
        var metrics = mlContext.BinaryClassification.Evaluate(predictions, labelColumnName: nameof(ModelInput.Label));
        
        Console.WriteLine();
        PrintColored("=== 模型性能评估 ===", Cyan);
        PrintColored($"准确率: {metrics.Accuracy:P4}", Green);
        PrintColored($"AUC: {metrics.AreaUnderRocCurve:P4}", Green);
        PrintColored($"F1 分数: {metrics.F1Score:P4}", Green);
        PrintColored($"正例精度: {metrics.PositivePrecision:P4}", Green);
        PrintColored($"正例召回: {metrics.PositiveRecall:P4}", Green);
        Console.WriteLine();
        
        PrintColored($"正在保存核心模型至：{modelPath}", Yellow);
        mlContext.Model.Save(model, trainSet.Schema, modelPath);
        PrintColored("核心模型保存成功!", Green);
        
        PrintColored($"\n正在导出通用格式至：{onnxPath}", Yellow);
        try
        {
            using var stream = File.Create(onnxPath);
            mlContext.Model.ConvertToOnnx(model, dataView, stream);
            PrintColored("通用格式导出成功!", Green);
        }
        catch (Exception ex)
        {
            PrintColored($"通用格式导出失败：{ex.Message}", Red);
        }
        
        return model;
    }
}

public class FileData
{
    public string FilePath { get; set; } = "";
    public float[] Features { get; set; } = Array.Empty<float>();
    public bool Label { get; set; }
}

public class ModelInput
{
    [VectorType(303)]  // 256字节频率 + 熵 + 统计 + 增强PE结构（头、节区、导入、资源、字符串）
    public float[] Features { get; set; } = Array.Empty<float>();
    
    public bool Label { get; set; }
}
