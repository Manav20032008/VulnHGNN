from dataclasses import dataclass

@dataclass(frozen=True)
class ModelSchema:
    class_names: tuple[str, ...] = (
        "non-vulnerable", "CWE-476", "CWE-191", "CWE-190", "CWE-369"
    )
    node_feature_dim: int = 22
    edge_type_count: int = 3
    hidden_dim: int = 96
    heads: int = 4
    layers: int = 3
    dropout: float = 0.20

    @property
    def num_classes(self):
        return len(self.class_names)

SCHEMA = ModelSchema()
