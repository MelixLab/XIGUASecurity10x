using System.Text;
using Melix.Shared;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;

namespace Melix.Engine;

class Program
{
    private static InferenceSession? _session;
    private const float THRESHOLD = 0.70f;
    
    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Usage: Melix <file_path>");
            return;
        }
        
        string filePath = args[0];
        
        if (!File.Exists(filePath))
        {
            Console.WriteLine($"Error: File not found - {filePath}");
            return;
        }
        
        try
        {
            InitializeModel();
            var (isVirus, probability, signatureInfo) = ScanFile(filePath);
            
            string result = isVirus ? "MALICIOUS" : "CLEAN";
            Console.WriteLine($"File: {filePath}");
            Console.WriteLine($"Result: {result}");
            Console.WriteLine($"Probability: {probability:P4}");
            
            // Show signature info
            if (signatureInfo != null && signatureInfo.Status != SignatureStatus.NotSigned)
            {
                string sigType = signatureInfo.IsWHQL ? "WHQL" : 
                                (signatureInfo.IsCatalogSigned ? "Catalog" : "Embedded");
                string trustStatus = signatureInfo.IsTrustedCA ? "Trusted" : "Untrusted";
                Console.WriteLine($"Signature: {sigType} [{trustStatus}] - {signatureInfo.Subject}");
                if (!string.IsNullOrEmpty(signatureInfo.ValidationMessage))
                {
                    Console.WriteLine($"Validation: {signatureInfo.ValidationMessage}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
    
    static void InitializeModel()
    {
        if (_session != null) return;
        
        string modelPath = Path.Combine(AppContext.BaseDirectory, "DeepMode.onnx");
        
        if (!File.Exists(modelPath))
        {
            throw new FileNotFoundException($"Model file not found: {modelPath}");
        }
        
        var sessionOptions = new SessionOptions
        {
            GraphOptimizationLevel = GraphOptimizationLevel.ORT_ENABLE_BASIC, // BASIC 跳过耗时的图优化, LightGBM 模型不需要
            IntraOpNumThreads = 1,
            InterOpNumThreads = 1
        };
        sessionOptions.AppendExecutionProvider_CPU();
        
        _session = new InferenceSession(modelPath, sessionOptions);
    }
    
    static (bool isVirus, float probability, SignatureInfo? sigInfo) ScanFile(string filePath)
    {
        if (_session == null)
        {
            throw new InvalidOperationException("Model not initialized");
        }
        
        // 1. Check signature first
        var sigInfo = SignatureChecker.GetSignatureInfo(filePath);
        
        // 2. Only trusted signatures from well-known publishers are considered safe
        // Self-signed, expired, or invalid chain signatures are NOT trusted
        if (sigInfo.Status == SignatureStatus.Valid && 
            sigInfo.IsTrustedCA &&
            SignatureChecker.IsWellKnownPublisher(sigInfo.Subject))
        {
            return (false, 0.0f, sigInfo);
        }
        
        // 3. System files with valid trusted signatures are considered safe
        if (SignatureChecker.IsSystemFile(filePath) && 
            sigInfo.Status == SignatureStatus.Valid &&
            sigInfo.IsTrustedCA)
        {
            return (false, 0.0f, sigInfo);
        }
        
        // 4. Extract features for ML detection
        var features = FeatureExtractor.Extract(filePath);
        
        // Create input tensor
        var inputTensor = new DenseTensor<float>(new[] { 1, features.Length });
        for (int i = 0; i < features.Length; i++)
        {
            inputTensor[0, i] = features[i];
        }
        
        // Create Label input (required by ML.NET exported ONNX)
        var labelTensor = new DenseTensor<bool>(new[] { 1, 1 });
        labelTensor[0, 0] = false;
        
        // Run inference
        var inputs = new List<NamedOnnxValue>
        {
            NamedOnnxValue.CreateFromTensor("Features", inputTensor),
            NamedOnnxValue.CreateFromTensor("Label", labelTensor)
        };
        
        using var results = _session.Run(inputs);
        
        // Get probability output
        float rawProb = 0.0f;
        var probOutput = results.FirstOrDefault(r => r.Name == "Probability.output");
        if (probOutput != null)
        {
            var probTensor = probOutput.AsTensor<float>();
            rawProb = probTensor[0];
        }
        else
        {
            // Try Score.output
            var scoreOutput = results.FirstOrDefault(r => r.Name == "Score.output");
            if (scoreOutput != null)
            {
                var scoreTensor = scoreOutput.AsTensor<float>();
                float score = scoreTensor[0];
                rawProb = 1.0f / (1.0f + (float)Math.Exp(-score));
            }
        }
        
        // 5. Only valid trusted signatures reduce score
        // Self-signed or invalid signatures do NOT reduce the score
        float adjustedProb = rawProb;
        if (sigInfo.Status == SignatureStatus.Valid && sigInfo.IsTrustedCA)
        {
            // Valid trusted signature reduces score by 70%
            adjustedProb = rawProb * 0.3f;
        }
        // Self-signed, expired, invalid chain signatures: no reduction (malware could use these)
        
        bool isVirus = adjustedProb >= THRESHOLD;
        return (isVirus, adjustedProb, sigInfo);
    }
}
