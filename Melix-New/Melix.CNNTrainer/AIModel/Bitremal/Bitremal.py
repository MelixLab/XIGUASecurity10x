import torch
import torch.nn as nn
import numpy as np


class Bitremal(nn.Module):
    def __init__(self, num_classes: int = 2, input_dim: int = 512,
                 token_dim: int = 512, num_tokens: int = 8,
                 embed_dim: int = 512, depth: int = 4, heads: int = 8) -> None:
        super().__init__()
        self.input_dim: int = input_dim
        self.num_tokens: int = num_tokens
        self.tokenizer: nn.Conv1d = nn.Conv1d(1, token_dim, kernel_size=input_dim // num_tokens, stride=input_dim // num_tokens)
        self.feature_proj: nn.Linear = nn.Linear(token_dim, embed_dim)
        self.cls_token: nn.Parameter = nn.Parameter(torch.zeros(1, 1, embed_dim))
        self.pos_embed: nn.Parameter = nn.Parameter(torch.zeros(1, num_tokens + 1, embed_dim))
        nn.init.trunc_normal_(self.cls_token, std=0.02)
        nn.init.trunc_normal_(self.pos_embed, std=0.02)
        encoder_layer: nn.TransformerEncoderLayer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=heads,
            dim_feedforward=embed_dim * 4,
            dropout=0.0,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.transformer: nn.TransformerEncoder = nn.TransformerEncoder(encoder_layer, num_layers=depth, enable_nested_tensor=False)
        self.norm: nn.LayerNorm = nn.LayerNorm(embed_dim)
        self.head: nn.Linear = nn.Linear(embed_dim, num_classes)

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        x: torch.Tensor = features.unsqueeze(1)
        x = self.tokenizer(x)
        x = x.permute(0, 2, 1)
        x = self.feature_proj(x)
        B: int = x.shape[0]
        cls_tokens: torch.Tensor = self.cls_token.expand(B, -1, -1)
        x = torch.cat([cls_tokens, x], dim=1)
        x = x + self.pos_embed
        x = self.transformer(x)
        x = self.norm(x)
        x = x[:, 0]
        x = self.head(x)
        return x


if __name__ == "__main__":
    from thop import profile
    import time

    device: torch.device = torch.device("cpu")
    model: Bitremal = Bitremal(num_classes=2).to(device)
    features: torch.Tensor = torch.randn(1, 512).to(device)
    logits: torch.Tensor = model(features)
    print(features.shape)
    print(logits.shape)

    flops, params = profile(model, inputs=(features,), verbose=False)
    print(f"FLOPs: {flops / 1e9:.2f}G")
    print(f"Params: {params / 1e6:.2f}M")

    for device_name in ["cpu", "cuda"]:
        if device_name == "cuda" and not torch.cuda.is_available():
            print("CUDA not available, skip GPU benchmark")
            continue
        try:
            dev: torch.device = torch.device(device_name)
            model_bench: Bitremal = Bitremal(num_classes=2).to(dev).eval()
            features_bench: torch.Tensor = torch.randn(1, 512).to(dev)
            with torch.no_grad():
                for _ in range(5):
                    _ = model_bench(features_bench)
                if dev.type == "cuda":
                    torch.cuda.synchronize()
                runs: int = 10
                start: float = time.perf_counter()
                for _ in range(runs):
                    _ = model_bench(features_bench)
                    if dev.type == "cuda":
                        torch.cuda.synchronize()
                end: float = time.perf_counter()
                avg_ms: float = (end - start) / runs * 1000
                print(f"{device_name.upper()} FP32 avg: {avg_ms:.2f} ms")
        except Exception as e:
            print(f"{device_name.upper()} FP32 benchmark failed: {e}")
