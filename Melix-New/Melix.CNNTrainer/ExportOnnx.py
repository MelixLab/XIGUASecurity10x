# Copyright (C) 2026 LinduCMint
# This file is part of Melix AntiVirus Engine, licensed under MINT License.

import torch
import torch.onnx
from Model import MelixCNN


def export_onnx(model_path: str, output_path: str = "melix.onnx"):
    """将训练好的 Melix 模型导出为 ONNX 格式"""
    
    # 加载模型
    device = torch.device('cpu')
    model = MelixCNN(input_dim=12288, hidden_dim=64, num_classes=2, dropout=0.0)
    
    checkpoint = torch.load(model_path, map_location=device)
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    model.to(device)
    
    # 创建 dummy input
    dummy_input = torch.randn(1, 12288, device=device)
    
    # 导出 ONNX
    torch.onnx.export(
        model,
        dummy_input,
        output_path,
        export_params=True,
        opset_version=17,
        do_constant_folding=True,
        input_names=['input'],
        output_names=['output'],
        dynamic_axes={
            'input': {0: 'batch_size'},
            'output': {0: 'batch_size'}
        }
    )
    
    print(f"ONNX model exported to: {output_path}")
    
    # 验证模型
    import onnx
    onnx_model = onnx.load(output_path)
    onnx.checker.check_model(onnx_model)
    print("ONNX model validation passed!")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ExportOnnx.py <model_path> [output_path]")
        print("Example: python ExportOnnx.py melix_best.pth melix.onnx")
        sys.exit(1)
    
    model_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "melix.onnx"
    export_onnx(model_path, output_path)
