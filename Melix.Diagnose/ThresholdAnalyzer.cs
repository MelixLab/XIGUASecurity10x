using Melix.Shared;
using Microsoft.ML;
using Microsoft.ML.Data;

namespace Melix.Diagnose;

class ThresholdAnalyzer
{
    private const string ModelPath = @"..\Melix-Core.zip";
    private const string BlackFolder = @"D:\Downloads\Black";
    private const string WhiteFolder = @"D:\Downloads\White";

    public static void Run()
    {
        if (!File.Exists(ModelPath))
        {
            Console.WriteLine($"模型不存在: {ModelPath}");
            return;
        }

        Console.WriteLine("正在加载模型...");
        var mlContext = new MLContext(seed: 42);
        var model = mlContext.Model.Load(ModelPath, out _);
        var predEngine = mlContext.Model.CreatePredictionEngine<ModelInput, ModelOutput>(model);

        Console.WriteLine("正在扫描黑样本...");
        var blackFiles = Directory.GetFiles(BlackFolder, "*.*", SearchOption.AllDirectories);
        Console.WriteLine($"黑样本总数: {blackFiles.Length}");

        Console.WriteLine("正在扫描白样本...");
        var whiteFiles = Directory.GetFiles(WhiteFolder, "*.*", SearchOption.AllDirectories);
        Console.WriteLine($"白样本总数: {whiteFiles.Length}");

        // 采样分析（太多文件会慢，采3000个足够）
        var random = new Random(42);
        var sampledBlack = blackFiles.OrderBy(x => random.Next()).Take(3000).ToList();
        var sampledWhite = whiteFiles.OrderBy(x => random.Next()).Take(3000).ToList();

        Console.WriteLine($"采样: 黑 {sampledBlack.Count} 个, 白 {sampledWhite.Count} 个");
        Console.WriteLine("正在预测...");

        var blackProbs = new List<float>();
        var whiteProbs = new List<float>();

        int processed = 0;
        foreach (var f in sampledBlack)
        {
            try
            {
                if (!FeatureExtractor.IsPEFile(f)) continue;
                var feats = FeatureExtractor.Extract(f);
                var pred = predEngine.Predict(new ModelInput { Features = feats });
                blackProbs.Add(pred.Probability);
            }
            catch { }

            processed++;
            if (processed % 100 == 0) Console.Write($"\r黑样本: {processed}/{sampledBlack.Count}");
        }
        Console.WriteLine();

        processed = 0;
        foreach (var f in sampledWhite)
        {
            try
            {
                if (!FeatureExtractor.IsPEFile(f)) continue;
                var feats = FeatureExtractor.Extract(f);
                var pred = predEngine.Predict(new ModelInput { Features = feats });
                whiteProbs.Add(pred.Probability);
            }
            catch { }

            processed++;
            if (processed % 100 == 0) Console.Write($"\r白样本: {processed}/{sampledWhite.Count}");
        }
        Console.WriteLine();

        Console.WriteLine($"\n有效预测: 黑 {blackProbs.Count} 个, 白 {whiteProbs.Count} 个");

        // 阈值分析
        Console.WriteLine("\n=== 阈值分析表 ===");
        Console.WriteLine(string.Format("{0,-8} {1,-10} {2,-10} {3,-10} {4,-10}", "阈值", "召回率", "误报率", "F1", "精确率"));

        float[] thresholds = { 0.10f, 0.20f, 0.30f, 0.40f, 0.50f, 0.60f, 0.70f, 0.80f, 0.90f, 0.95f, 0.96f, 0.97f, 0.98f, 0.985f, 0.99f, 0.995f };
        float bestThreshold = 0.5f;
        float bestRecall = 0;

        foreach (var threshold in thresholds)
        {
            int tp = blackProbs.Count(p => p >= threshold);
            int fn = blackProbs.Count - tp;
            int fp = whiteProbs.Count(p => p >= threshold);
            int tn = whiteProbs.Count - fp;

            float recall = blackProbs.Count > 0 ? (float)tp / blackProbs.Count : 0;
            float fpr = whiteProbs.Count > 0 ? (float)fp / whiteProbs.Count : 0;
            float precision = (tp + fp) > 0 ? (float)tp / (tp + fp) : 0;
            float f1 = (precision + recall) > 0 ? 2 * precision * recall / (precision + recall) : 0;

            Console.WriteLine($"{threshold,-8:F3} {recall * 100,-10:F2}% {fpr * 100,-10:F4}% {f1,-10:F4} {precision * 100,-10:F2}%");

            if (fpr <= 0.001f && recall > bestRecall) // 误报率 < 0.1%
            {
                bestRecall = recall;
                bestThreshold = threshold;
            }
        }

        Console.WriteLine($"\n=== 推荐阈值（误报率<0.1%）===");
        Console.WriteLine($"阈值: {bestThreshold:F3}");
        Console.WriteLine($"预期召回率: {bestRecall * 100:F2}%");

        //  also print the best F1 threshold
        float bestF1 = 0;
        float bestF1Threshold = 0.5f;
        foreach (var threshold in thresholds)
        {
            int tp = blackProbs.Count(p => p >= threshold);
            int fp = whiteProbs.Count(p => p >= threshold);
            float recall = blackProbs.Count > 0 ? (float)tp / blackProbs.Count : 0;
            float precision = (tp + fp) > 0 ? (float)tp / (tp + fp) : 0;
            float f1 = (precision + recall) > 0 ? 2 * precision * recall / (precision + recall) : 0;
            if (f1 > bestF1)
            {
                bestF1 = f1;
                bestF1Threshold = threshold;
            }
        }
        Console.WriteLine($"\n最佳 F1 阈值: {bestF1Threshold:F2} (F1={bestF1:F4})");
    }
}
