import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import torch
import torch.nn as nn
from Bitremal.RB import RawBytesEmbedding, RawBytesBackbone, bytes_to_input_ids
from Bitremal.AL import AssemblyListEmbedding, AssemblyListBackbone, ids_to_input_ids
from Bitremal.EM import EntropyMapEncoder
from Bitremal.IT import ImportTableEncoder
from Bitremal.Bitremal import Bitremal


class EndToEnd(nn.Module):
    def __init__(self, num_classes: int = 2) -> None:
        super().__init__()
        self.rb_embedding: RawBytesEmbedding = RawBytesEmbedding()
        self.al_embedding: AssemblyListEmbedding = AssemblyListEmbedding()
        self.rb_backbone: RawBytesBackbone = RawBytesBackbone()
        self.al_backbone: AssemblyListBackbone = AssemblyListBackbone()
        self.em_encoder: EntropyMapEncoder = EntropyMapEncoder(output_dim=128)
        self.it_encoder: ImportTableEncoder = ImportTableEncoder(output_dim=128)
        self.rb_head: nn.Linear = nn.Linear(128, num_classes)
        self.al_head: nn.Linear = nn.Linear(128, num_classes)
        self.bitremal: Bitremal = Bitremal(num_classes=num_classes)

    def forward(self, rb_input: torch.Tensor, al_input: torch.Tensor, em_input: torch.Tensor, it_input: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        rb_embedded: torch.Tensor = self.rb_embedding(rb_input)
        al_embedded: torch.Tensor = self.al_embedding(al_input)
        rb_feature: torch.Tensor = self.rb_backbone(rb_embedded)
        al_feature: torch.Tensor = self.al_backbone(al_embedded)
        em_feature: torch.Tensor = self.em_encoder(em_input)
        it_feature: torch.Tensor = self.it_encoder(it_input)
        rb_logits: torch.Tensor = self.rb_head(rb_feature)
        al_logits: torch.Tensor = self.al_head(al_feature)
        merged: torch.Tensor = torch.cat([rb_feature, al_feature, em_feature, it_feature], dim=-1)
        bitremal_logits: torch.Tensor = self.bitremal(merged)
        return rb_logits, al_logits, bitremal_logits

    def get_components(self) -> dict[str, nn.Module]:
        return {
            "rb_embedding": self.rb_embedding,
            "al_embedding": self.al_embedding,
            "rb_backbone": self.rb_backbone,
            "al_backbone": self.al_backbone,
            "em_encoder": self.em_encoder,
            "it_encoder": self.it_encoder,
            "rb_head": self.rb_head,
            "al_head": self.al_head,
            "bitremal": self.bitremal,
        }


if __name__ == "__main__":
    from thop import profile

    device: torch.device = torch.device("cpu")
    model: EndToEnd = EndToEnd(num_classes=2).to(device)

    rb_input: torch.Tensor = bytes_to_input_ids(bytes(range(256)) * 64, device=device)
    al_input: torch.Tensor = ids_to_input_ids(list(range(614)) + [0] * (1024 - 614), device=device)
    em_input: torch.Tensor = torch.randn(1, 64, 1).to(device)
    it_input: torch.Tensor = torch.randn(1, 417, 1).to(device)

    rb_logits: torch.Tensor
    al_logits: torch.Tensor
    bitremal_logits: torch.Tensor
    rb_logits, al_logits, bitremal_logits = model(rb_input, al_input, em_input, it_input)
    print(rb_logits.shape)
    print(al_logits.shape)
    print(bitremal_logits.shape)

    flops, params = profile(model, inputs=(rb_input, al_input, em_input, it_input), verbose=False)
    print(f"EndToEnd FLOPs: {flops / 1e9:.2f}G")
    print(f"EndToEnd Params: {params / 1e6:.2f}M")

    criterion: nn.CrossEntropyLoss = nn.CrossEntropyLoss()
    target: torch.Tensor = torch.tensor([1], dtype=torch.long).to(device)
    loss_rb: torch.Tensor = criterion(rb_logits, target)
    loss_al: torch.Tensor = criterion(al_logits, target)
    loss_bitremal: torch.Tensor = criterion(bitremal_logits, target)

    components: dict[str, nn.Module] = model.get_components()

    model.zero_grad()
    rb_backbone_param: nn.Parameter = next(model.rb_backbone.parameters())
    al_backbone_param: nn.Parameter = next(model.al_backbone.parameters())
    em_param: nn.Parameter = next(model.em_encoder.parameters())
    it_param: nn.Parameter = next(model.it_encoder.parameters())
    bitremal_param: nn.Parameter = next(model.bitremal.parameters())
    rb_head_param: nn.Parameter = next(model.rb_head.parameters())
    al_head_param: nn.Parameter = next(model.al_head.parameters())

    loss_bitremal.backward(retain_graph=True)
    grad_after_bitremal_rb: torch.Tensor = rb_backbone_param.grad.clone()
    grad_after_bitremal_al: torch.Tensor = al_backbone_param.grad.clone()

    loss_rb.backward(retain_graph=True)
    grad_after_rb_rb: torch.Tensor = rb_backbone_param.grad.clone()

    loss_al.backward()
    grad_after_al_al: torch.Tensor = al_backbone_param.grad.clone()

    print("backward ok")
    print(f"components count: {len(components)}")
    print(f"bitremal/em/it/rb_backbone/al_backbone got grad from bitremal loss:")
    print(f"  rb_backbone: {rb_backbone_param.grad is not None}")
    print(f"  al_backbone: {al_backbone_param.grad is not None}")
    print(f"  em_encoder: {em_param.grad is not None}")
    print(f"  it_encoder: {it_param.grad is not None}")
    print(f"  bitremal: {bitremal_param.grad is not None}")
    print(f"rb_head/al_head got grad from respective loss:")
    print(f"  rb_head: {rb_head_param.grad is not None}")
    print(f"  al_head: {al_head_param.grad is not None}")
    print(f"rb_backbone/al_backbone got extra grad from rb/al loss:")
    print(f"  rb_backbone grad changed: {not torch.equal(grad_after_bitremal_rb, grad_after_rb_rb)}")
    print(f"  al_backbone grad changed: {not torch.equal(grad_after_bitremal_al, grad_after_al_al)}")
    for name in components:
        print(name)
