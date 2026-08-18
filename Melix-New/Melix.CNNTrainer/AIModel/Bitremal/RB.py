import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Optional, Tuple


class RawBytesEmbedding(nn.Module):
    def __init__(self, vocab_size: int = 256, embed_dim: int = 8, seq_len: int = 16384) -> None:
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
        output: torch.Tensor = embedded.reshape(-1, self.embed_dim, 128, 128)
        return output

    def export_bin(self, path: str) -> None:
        weight: np.ndarray = self.embedding.weight.detach().cpu().numpy().astype(np.float32)
        weight.tofile(path)

    @classmethod
    def from_bin(cls, path: str, vocab_size: int = 256, embed_dim: int = 8, seq_len: int = 16384) -> "RawBytesEmbedding":
        weight: np.ndarray = np.fromfile(path, dtype=np.float32)
        if weight.size != vocab_size * embed_dim:
            raise ValueError(f"Weight size mismatch: expected {vocab_size * embed_dim}, got {weight.size}")
        weight = weight.reshape(vocab_size, embed_dim)
        instance: RawBytesEmbedding = cls(vocab_size, embed_dim, seq_len)
        instance.embedding.weight.data.copy_(torch.from_numpy(weight))
        return instance


def bytes_to_input_ids(data: bytes, device: Optional[torch.device] = None) -> torch.Tensor:
    if len(data) != 16384:
        raise ValueError(f"Input byte length must be 16384, got {len(data)}")
    arr: np.ndarray = np.frombuffer(data, dtype=np.uint8).astype(np.int64)
    return torch.from_numpy(arr).unsqueeze(0).to(device)


def embedded_flat_to_nchw(embedded_flat: torch.Tensor) -> torch.Tensor:
    if embedded_flat.shape[-1] != 131072:
        raise ValueError(f"Embedded flat length must be 131072, got {embedded_flat.shape[-1]}")
    B: int = embedded_flat.shape[0]
    return embedded_flat.reshape(B, 8, 128, 128)


class LayerNorm2d(nn.Module):
    def __init__(self, channels: int, eps: float = 1e-6) -> None:
        super().__init__()
        self.weight: nn.Parameter = nn.Parameter(torch.ones(channels))
        self.bias: nn.Parameter = nn.Parameter(torch.zeros(channels))
        self.eps: float = eps

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        u: torch.Tensor = x.mean(1, keepdim=True)
        s: torch.Tensor = (x - u).pow(2).mean(1, keepdim=True)
        x = (x - u) / torch.sqrt(s + self.eps)
        x = self.weight[:, None, None] * x + self.bias[:, None, None]
        return x


class ECA(nn.Module):
    def __init__(self, channels: int, gamma: int = 2, b: int = 1) -> None:
        super().__init__()
        kernel_size: int = int(abs((np.log2(channels) / gamma) + b / gamma))
        kernel_size = kernel_size if kernel_size % 2 else kernel_size + 1
        self.avg_pool: nn.AdaptiveAvgPool2d = nn.AdaptiveAvgPool2d(1)
        self.conv: nn.Conv1d = nn.Conv1d(1, 1, kernel_size=kernel_size, padding=(kernel_size - 1) // 2, bias=False)
        self.sigmoid: nn.Sigmoid = nn.Sigmoid()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        y: torch.Tensor = self.avg_pool(x)
        y = y.squeeze(-1).transpose(-1, -2)
        y = self.conv(y)
        y = self.sigmoid(y)
        y = y.transpose(-1, -2).unsqueeze(-1)
        return x * y.expand_as(x)


class GateConv(nn.Module):
    def __init__(self, in_channels: int, out_channels: int, kernel_size: int = 3, stride: int = 1, padding: int = 1, bias: bool = False) -> None:
        super().__init__()
        self.out_channels: int = out_channels
        self.conv: nn.Conv2d = nn.Conv2d(in_channels, out_channels * 2, kernel_size, stride=stride, padding=padding, bias=bias)
        self.bn: nn.BatchNorm2d = nn.BatchNorm2d(out_channels * 2)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.bn(self.conv(x))
        x1: torch.Tensor
        x2: torch.Tensor
        x1, x2 = torch.chunk(x, 2, dim=1)
        return x1 * torch.sigmoid(x2)


class ResidualGateConv(nn.Module):
    def __init__(self, in_channels: int, out_channels: int, stride: int = 1) -> None:
        super().__init__()
        self.gate_conv: GateConv = GateConv(in_channels, out_channels, stride=stride)
        if in_channels != out_channels or stride != 1:
            self.shortcut: nn.Module = nn.Conv2d(in_channels, out_channels, kernel_size=1, stride=stride, bias=False)
        else:
            self.shortcut = nn.Identity()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.gate_conv(x) + self.shortcut(x)


class DWConv(nn.Module):
    def __init__(self, channels: int, kernel_size: int, stride: int = 1, padding: int = 0, dilation: int = 1, bias: bool = False) -> None:
        super().__init__()
        self.conv: nn.Conv2d = nn.Conv2d(channels, channels, kernel_size, stride=stride, padding=padding, dilation=dilation, groups=channels, bias=bias)
        self.bn: nn.BatchNorm2d = nn.BatchNorm2d(channels)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.bn(self.conv(x))


class RepVGGBlock(nn.Module):
    def __init__(self, in_channels: int, out_channels: int, kernel_size: int = 3, stride: int = 1, padding: int = 1, groups: int = 1, deploy: bool = False) -> None:
        super().__init__()
        self.deploy: bool = deploy
        self.groups: int = groups
        self.in_channels: int = in_channels
        self.out_channels: int = out_channels

        if deploy:
            self.rbr_reparam: nn.Conv2d = nn.Conv2d(in_channels, out_channels, kernel_size, stride, padding, groups=groups, bias=True)
        else:
            self.rbr_dense: nn.Sequential = nn.Sequential(
                nn.Conv2d(in_channels, out_channels, kernel_size, stride, padding, groups=groups, bias=False),
                nn.BatchNorm2d(out_channels),
            )
            self.rbr_1x1: nn.Sequential = nn.Sequential(
                nn.Conv2d(in_channels, out_channels, 1, stride, 0, groups=groups, bias=False),
                nn.BatchNorm2d(out_channels),
            )
            self.rbr_identity: Optional[nn.BatchNorm2d] = nn.BatchNorm2d(out_channels) if out_channels == in_channels and stride == 1 and groups == 1 else None

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if self.deploy:
            return self.rbr_reparam(x)
        out: torch.Tensor = self.rbr_dense(x)
        out = out + self.rbr_1x1(x)
        if self.rbr_identity is not None:
            out = out + self.rbr_identity(x)
        return out

    def _pad_1x1_to_3x3_tensor(self, kernel1x1: torch.Tensor) -> torch.Tensor:
        return F.pad(kernel1x1, [1, 1, 1, 1])

    def _fuse_bn_tensor(self, branch: nn.Module) -> Tuple[torch.Tensor, torch.Tensor]:
        if isinstance(branch, nn.Sequential):
            kernel: torch.Tensor = branch[0].weight
            running_mean: torch.Tensor = branch[1].running_mean
            running_var: torch.Tensor = branch[1].running_var
            gamma: torch.Tensor = branch[1].weight
            beta: torch.Tensor = branch[1].bias
            eps: float = branch[1].eps
            std: torch.Tensor = (running_var + eps).sqrt()
            t: torch.Tensor = (gamma / std).reshape(-1, 1, 1, 1)
            return kernel * t, beta - running_mean * gamma / std
        if isinstance(branch, nn.BatchNorm2d):
            input_dim: int = self.in_channels // self.groups
            kernel_value: torch.Tensor = torch.zeros((self.out_channels, input_dim, 3, 3), dtype=branch.weight.dtype, device=branch.weight.device)
            for i in range(self.out_channels):
                kernel_value[i, i % input_dim, 1, 1] = 1.0
            running_mean = branch.running_mean
            running_var = branch.running_var
            gamma = branch.weight
            beta = branch.bias
            eps = branch.eps
            std = (running_var + eps).sqrt()
            t = (gamma / std).reshape(-1, 1, 1, 1)
            return kernel_value * t, beta - running_mean * gamma / std
        raise TypeError("Unsupported branch type")

    def _get_equivalent_kernel_bias(self) -> Tuple[torch.Tensor, torch.Tensor]:
        kernel3x3, bias3x3 = self._fuse_bn_tensor(self.rbr_dense)
        kernel1x1, bias1x1 = self._fuse_bn_tensor(self.rbr_1x1)
        kernel: torch.Tensor = kernel3x3 + self._pad_1x1_to_3x3_tensor(kernel1x1)
        bias: torch.Tensor = bias3x3 + bias1x1
        if self.rbr_identity is not None:
            kernelid, biasid = self._fuse_bn_tensor(self.rbr_identity)
            kernel = kernel + kernelid
            bias = bias + biasid
        return kernel, bias

    def switch_to_deploy(self) -> None:
        if self.deploy:
            return
        kernel, bias = self._get_equivalent_kernel_bias()
        self.rbr_reparam = nn.Conv2d(self.in_channels, self.out_channels, 3, self.rbr_dense[0].stride, 1, groups=self.groups, bias=True)
        self.rbr_reparam.weight.data = kernel
        self.rbr_reparam.bias.data = bias
        self.deploy = True
        delattr(self, "rbr_dense")
        delattr(self, "rbr_1x1")
        if hasattr(self, "rbr_identity"):
            delattr(self, "rbr_identity")


class ConvNeXtBlock(nn.Module):
    def __init__(self, channels: int, expansion: int = 4, drop_path: float = 0.0, layer_scale_init_value: float = 1e-6) -> None:
        super().__init__()
        self.dwconv: nn.Conv2d = nn.Conv2d(channels, channels, kernel_size=7, padding=3, groups=channels)
        self.norm: nn.LayerNorm = nn.LayerNorm(channels, eps=1e-6)
        hidden_dim: int = expansion * channels
        self.pwconv1: nn.Linear = nn.Linear(channels, hidden_dim)
        self.act: nn.GELU = nn.GELU()
        self.pwconv2: nn.Linear = nn.Linear(hidden_dim, channels)
        self.gamma: Optional[nn.Parameter] = nn.Parameter(layer_scale_init_value * torch.ones(channels)) if layer_scale_init_value > 0 else None
        self.drop_path: nn.Module = DropPath(drop_path) if drop_path > 0.0 else nn.Identity()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        input_x: torch.Tensor = x
        x = self.dwconv(x)
        x = x.permute(0, 2, 3, 1)
        x = self.norm(x)
        x = self.pwconv1(x)
        x = self.act(x)
        x = self.pwconv2(x)
        if self.gamma is not None:
            x = self.gamma * x
        x = x.permute(0, 3, 1, 2)
        x = input_x + self.drop_path(x)
        return x


class DropPath(nn.Module):
    def __init__(self, drop_prob: float = 0.0) -> None:
        super().__init__()
        self.drop_prob: float = drop_prob

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if self.drop_prob == 0.0 or not self.training:
            return x
        keep_prob: float = 1 - self.drop_prob
        shape: Tuple[int, ...] = (x.shape[0],) + (1,) * (x.ndim - 1)
        random_tensor: torch.Tensor = keep_prob + torch.rand(shape, dtype=x.dtype, device=x.device)
        random_tensor.floor_()
        output: torch.Tensor = x.div(keep_prob) * random_tensor
        return output


class GateStage(nn.Module):
    def __init__(self, in_channels: int, out_channels: int, stride: int = 1) -> None:
        super().__init__()
        self.norm: LayerNorm2d = LayerNorm2d(in_channels)
        self.act: nn.GELU = nn.GELU()
        self.gate: ResidualGateConv = ResidualGateConv(in_channels, out_channels, stride=stride)
        self.dw3: DWConv = DWConv(out_channels, kernel_size=3, stride=1, padding=1)
        self.dw5: DWConv = DWConv(out_channels, kernel_size=5, stride=1, padding=2)
        self.eca: ECA = ECA(out_channels)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.norm(x)
        x = self.act(x)
        x = self.gate(x)
        x = self.dw3(x)
        x = self.dw5(x)
        x = self.eca(x)
        return x


class ConvStage(nn.Module):
    def __init__(self, in_channels: int, out_channels: int, rep_kernel: int = 3, stride: int = 1, expansion: int = 4, drop_path: float = 0.0) -> None:
        super().__init__()
        self.norm: LayerNorm2d = LayerNorm2d(in_channels)
        self.act: nn.GELU = nn.GELU()
        self.repvgg: RepVGGBlock = RepVGGBlock(in_channels, out_channels, kernel_size=rep_kernel, stride=stride, padding=rep_kernel // 2)
        self.convnext1: ConvNeXtBlock = ConvNeXtBlock(out_channels, expansion=expansion, drop_path=drop_path)
        self.convnext2: ConvNeXtBlock = ConvNeXtBlock(out_channels, expansion=expansion, drop_path=drop_path)
        self.eca: ECA = ECA(out_channels)
        if stride != 1 or in_channels != out_channels:
            self.proj: nn.Module = nn.Conv2d(in_channels, out_channels, kernel_size=1, stride=stride, bias=False)
        else:
            self.proj = nn.Identity()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual: torch.Tensor = self.proj(x)
        x = self.norm(x)
        x = self.act(x)
        x = self.repvgg(x)
        x = self.convnext1(x)
        x = self.convnext2(x)
        x = self.eca(x)
        return x + residual


class TokenEmbedding(nn.Module):
    def __init__(self, in_channels: int, embed_dim: int) -> None:
        super().__init__()
        self.proj: nn.Conv2d = nn.Conv2d(in_channels, embed_dim, kernel_size=1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.proj(x)
        x = x.flatten(2).transpose(1, 2)
        return x


class TransformerEncoderBlock(nn.Module):
    def __init__(self, embed_dim: int, num_heads: int, mlp_ratio: float = 4.0, qkv_bias: bool = False, drop: float = 0.0, attn_drop: float = 0.0, drop_path: float = 0.0) -> None:
        super().__init__()
        self.norm1: nn.LayerNorm = nn.LayerNorm(embed_dim)
        self.attn: nn.MultiheadAttention = nn.MultiheadAttention(embed_dim, num_heads, dropout=attn_drop, batch_first=True)
        self.norm2: nn.LayerNorm = nn.LayerNorm(embed_dim)
        hidden_dim: int = int(embed_dim * mlp_ratio)
        self.mlp: nn.Module = nn.Sequential(
            nn.Linear(embed_dim, hidden_dim, bias=True),
            nn.GELU(),
            nn.Dropout(drop),
            nn.Linear(hidden_dim, embed_dim, bias=True),
            nn.Dropout(drop),
        )
        self.drop_path1: nn.Module = DropPath(drop_path) if drop_path > 0.0 else nn.Identity()
        self.drop_path2: nn.Module = DropPath(drop_path) if drop_path > 0.0 else nn.Identity()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x + self.drop_path1(self.attn(self.norm1(x), self.norm1(x), self.norm1(x), need_weights=False)[0])
        x = x + self.drop_path2(self.mlp(self.norm2(x)))
        return x


class RawBytesBackbone(nn.Module):
    def __init__(self, vit_embed_dim: int = 128, vit_depth: int = 2, vit_heads: int = 4, dropout: float = 0.0) -> None:
        super().__init__()
        self.stage1: GateStage = GateStage(8, 16, stride=1)
        self.stage2: GateStage = GateStage(16, 24, stride=2)
        self.stage3: nn.Sequential = nn.Sequential(
            ConvStage(24, 48, rep_kernel=3, stride=2),
            ConvStage(48, 48, rep_kernel=3, stride=1),
        )
        self.stage4: nn.Sequential = nn.Sequential(
            ConvStage(48, 96, rep_kernel=5, stride=2),
            ConvStage(96, 96, rep_kernel=5, stride=1),
        )

        self.token_embedding: TokenEmbedding = TokenEmbedding(96, vit_embed_dim)
        self.num_tokens: int = 16 * 16
        self.cls_token: nn.Parameter = nn.Parameter(torch.zeros(1, 1, vit_embed_dim))
        self.pos_embed: nn.Parameter = nn.Parameter(torch.zeros(1, self.num_tokens + 1, vit_embed_dim))
        nn.init.trunc_normal_(self.cls_token, std=0.02)
        nn.init.trunc_normal_(self.pos_embed, std=0.02)

        self.vit_blocks: nn.Sequential = nn.Sequential(
            *[
                TransformerEncoderBlock(
                    vit_embed_dim,
                    vit_heads,
                    drop=dropout,
                    attn_drop=dropout,
                    drop_path=0.1 * i / max(vit_depth - 1, 1),
                )
                for i in range(vit_depth)
            ]
        )

        self.norm: nn.LayerNorm = nn.LayerNorm(vit_embed_dim)
        self.proj: nn.Linear = nn.Linear(vit_embed_dim, 128)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.stage1(x)
        x = self.stage2(x)
        x = self.stage3(x)
        x = self.stage4(x)
        x = self.token_embedding(x)

        B: int = x.shape[0]
        cls_tokens: torch.Tensor = self.cls_token.expand(B, -1, -1)
        x = torch.cat([cls_tokens, x], dim=1)
        x = x + self.pos_embed

        x = self.vit_blocks(x)
        x = self.norm(x)
        x = x[:, 0]
        x = self.proj(x)
        return x


class RawBytesModel(nn.Module):
    def __init__(self, num_classes: int = 2, vit_embed_dim: int = 128, vit_depth: int = 2, vit_heads: int = 4, dropout: float = 0.0) -> None:
        super().__init__()
        self.embedding: RawBytesEmbedding = RawBytesEmbedding()
        self.backbone: RawBytesBackbone = RawBytesBackbone(vit_embed_dim, vit_depth, vit_heads, dropout)
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
    model: RawBytesModel = RawBytesModel(num_classes=2).to(device)
    dummy_bytes: bytes = bytes(range(256)) * 64
    input_ids: torch.Tensor = bytes_to_input_ids(dummy_bytes, device=device)
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
            model_bench: RawBytesModel = RawBytesModel(num_classes=2).to(dev).eval()
            input_bench: torch.Tensor = bytes_to_input_ids(dummy_bytes, device=dev)
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

    os.makedirs("./Embeddings/RawByte", exist_ok=True)
    embedding: RawBytesEmbedding = RawBytesEmbedding()
    embedding.export_bin("./Embeddings/RawByte/embedding_static.bin")

    dll_path: str = r"C:\Windows\System32\user32.dll"
    with open(dll_path, "rb") as f:
        dll_data: bytes = f.read(16384)
    if len(dll_data) < 16384:
        dll_data = dll_data + bytes(16384 - len(dll_data))
    dll_input: torch.Tensor = bytes_to_input_ids(dll_data, device=device)
    with torch.no_grad():
        dll_embedded: torch.Tensor = embedding(dll_input)
    dll_embedded_np: np.ndarray = dll_embedded.detach().cpu().numpy().astype(np.float32)
    dll_embedded_np.tofile("./Embeddings/RawByte/user32_dll_embedding_python.bin")

    embedding_table: np.ndarray = embedding.embedding.weight.detach().cpu().numpy().astype(np.float32)
    output_cs: np.ndarray = np.empty((8, 16384), dtype=np.float32)
    for c in range(8):
        for i in range(16384):
            token_id: int = dll_data[i]
            output_cs[c, i] = embedding_table[token_id, c]
    diff: float = float(np.abs(dll_embedded_np.reshape(8, 16384) - output_cs).max())
    print(f"max diff vs C# layout: {diff:.6f}")
