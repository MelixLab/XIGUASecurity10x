import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Optional


class AssemblyListEmbedding(nn.Module):
    def __init__(self, vocab_size: int = 614, embed_dim: int = 192, seq_len: int = 1024) -> None:
        super().__init__()
        self.vocab_size: int = vocab_size
        self.embed_dim: int = embed_dim
        self.seq_len: int = seq_len
        self.embedding: nn.Embedding = nn.Embedding(vocab_size, embed_dim)
        self._initialize()

    def _initialize(self) -> None:
        nn.init.normal_(self.embedding.weight, mean=0.0, std=0.02)

    def forward(self, input_ids: torch.Tensor) -> torch.Tensor:
        if input_ids.shape[-1] != self.seq_len:
            raise ValueError(f"Input length must be {self.seq_len}, got {input_ids.shape[-1]}")
        embedded: torch.Tensor = self.embedding(input_ids)
        embedded = embedded.permute(0, 2, 1).contiguous()
        return embedded

    def export_bin(self, path: str) -> None:
        weight: np.ndarray = self.embedding.weight.detach().cpu().numpy().astype(np.float32)
        weight.tofile(path)

    @classmethod
    def from_bin(cls, path: str, vocab_size: int = 614, embed_dim: int = 192, seq_len: int = 1024) -> "AssemblyListEmbedding":
        weight: np.ndarray = np.fromfile(path, dtype=np.float32)
        if weight.size != vocab_size * embed_dim:
            raise ValueError(f"Weight size mismatch: expected {vocab_size * embed_dim}, got {weight.size}")
        weight = weight.reshape(vocab_size, embed_dim)
        instance: AssemblyListEmbedding = cls(vocab_size, embed_dim, seq_len)
        instance.embedding.weight.data.copy_(torch.from_numpy(weight))
        return instance


def ids_to_input_ids(ids: list[int], device: Optional[torch.device] = None) -> torch.Tensor:
    if len(ids) != 1024:
        raise ValueError(f"Input ID length must be 1024, got {len(ids)}")
    arr: np.ndarray = np.array(ids, dtype=np.int64)
    return torch.from_numpy(arr).unsqueeze(0).to(device)


class DConvCompress(nn.Module):
    def __init__(self, channels: int, kernel_size: int = 31, stride: int = 4) -> None:
        super().__init__()
        padding: int = kernel_size // 2
        self.dwconv: nn.Conv1d = nn.Conv1d(channels, channels, kernel_size=kernel_size, stride=stride, padding=padding, groups=channels)
        self.norm1: nn.BatchNorm1d = nn.BatchNorm1d(channels)
        self.act: nn.GELU = nn.GELU()
        self.pwconv: nn.Conv1d = nn.Conv1d(channels, channels, kernel_size=1)
        self.norm2: nn.BatchNorm1d = nn.BatchNorm1d(channels)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.dwconv(x)
        x = self.norm1(x)
        x = self.act(x)
        x = self.pwconv(x)
        x = self.norm2(x)
        x = self.act(x)
        return x


class AssemblyListBackbone(nn.Module):
    def __init__(self, embed_dim: int = 192, gru_hidden: int = 192, gru_layers: int = 2,
                 tf_embed_dim: int = 128, tf_depth: int = 2, tf_heads: int = 4) -> None:
        super().__init__()
        self.compress: DConvCompress = DConvCompress(embed_dim, kernel_size=31, stride=4)
        self.gru: nn.GRU = nn.GRU(embed_dim, gru_hidden, num_layers=gru_layers, batch_first=True, dropout=0.0)
        self.proj: nn.Linear = nn.Linear(gru_hidden, tf_embed_dim)
        self.num_tokens: int = 256
        self.cls_token: nn.Parameter = nn.Parameter(torch.zeros(1, 1, tf_embed_dim))
        self.pos_embed: nn.Parameter = nn.Parameter(torch.zeros(1, self.num_tokens + 1, tf_embed_dim))
        nn.init.trunc_normal_(self.cls_token, std=0.02)
        nn.init.trunc_normal_(self.pos_embed, std=0.02)
        encoder_layer: nn.TransformerEncoderLayer = nn.TransformerEncoderLayer(
            d_model=tf_embed_dim,
            nhead=tf_heads,
            dim_feedforward=tf_embed_dim * 4,
            dropout=0.0,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.transformer: nn.TransformerEncoder = nn.TransformerEncoder(encoder_layer, num_layers=tf_depth, enable_nested_tensor=False)
        self.norm: nn.LayerNorm = nn.LayerNorm(tf_embed_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.compress(x)
        x = x.permute(0, 2, 1)
        x, _ = self.gru(x)
        x = self.proj(x)
        B: int = x.shape[0]
        cls_tokens: torch.Tensor = self.cls_token.expand(B, -1, -1)
        x = torch.cat([cls_tokens, x], dim=1)
        x = x + self.pos_embed
        x = self.transformer(x)
        x = self.norm(x)
        x = x[:, 0]
        return x


class AssemblyListModel(nn.Module):
    def __init__(self, num_classes: int = 2, embed_dim: int = 192,
                 gru_hidden: int = 192, gru_layers: int = 2,
                 tf_embed_dim: int = 128, tf_depth: int = 2, tf_heads: int = 4) -> None:
        super().__init__()
        self.embedding: AssemblyListEmbedding = AssemblyListEmbedding(embed_dim=embed_dim)
        self.backbone: AssemblyListBackbone = AssemblyListBackbone(embed_dim, gru_hidden, gru_layers, tf_embed_dim, tf_depth, tf_heads)
        self.head: nn.Linear = nn.Linear(128, num_classes)

    def forward(self, input_ids: torch.Tensor) -> torch.Tensor:
        x: torch.Tensor = self.embedding(input_ids)
        x = self.backbone(x)
        x = self.head(x)
        return x

    def export_embedding(self, path: str) -> None:
        self.embedding.export_bin(path)


if __name__ == "__main__":
    from thop import profile
    import time
    import os

    device: torch.device = torch.device("cpu")
    model: AssemblyListModel = AssemblyListModel(num_classes=2).to(device)
    dummy_ids: list[int] = list(range(614)) * 1 + [0] * (1024 - 614)
    input_ids: torch.Tensor = ids_to_input_ids(dummy_ids, device=device)
    logits: torch.Tensor = model(input_ids)
    print(input_ids.shape)
    print(logits.shape)

    flops, params = profile(model, inputs=(input_ids,), verbose=False)
    print(f"FLOPs: {flops / 1e9:.2f}G")
    print(f"Params: {params / 1e6:.2f}M")

    for device_name in ["cpu", "cuda"]:
        if device_name == "cuda" and not torch.cuda.is_available():
            print("CUDA not available, skip GPU benchmark")
            continue
        try:
            dev: torch.device = torch.device(device_name)
            model_bench: AssemblyListModel = AssemblyListModel(num_classes=2).to(dev).eval()
            input_bench: torch.Tensor = ids_to_input_ids(dummy_ids, device=dev)
            with torch.no_grad():
                for _ in range(5):
                    _ = model_bench(input_bench)
                if dev.type == "cuda":
                    torch.cuda.synchronize()
                runs: int = 10
                start: float = time.perf_counter()
                for _ in range(runs):
                    _ = model_bench(input_bench)
                    if dev.type == "cuda":
                        torch.cuda.synchronize()
                end: float = time.perf_counter()
                avg_ms: float = (end - start) / runs * 1000
                print(f"{device_name.upper()} FP32 avg: {avg_ms:.2f} ms")
        except Exception as e:
            print(f"{device_name.upper()} FP32 benchmark failed: {e}")

    os.makedirs("./Embeddings/AssemblyList", exist_ok=True)
    embedding: AssemblyListEmbedding = AssemblyListEmbedding()
    embedding.export_bin("./Embeddings/AssemblyList/embedding_static.bin")
