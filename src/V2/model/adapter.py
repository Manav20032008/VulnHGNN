from pathlib import Path
import pickle
import torch
from torch_geometric.data import Data

class GraphTensorAdapter:
    OPCODES = (
        "add","sub","mul","sdiv","udiv","srem","urem","load","store",
        "alloca","call","icmp","br","gep","phi","ret","select","zext",
        "sext","trunc","other"
    )

    def __init__(self, feature_dim=22):
        self.feature_dim = feature_dim

    def _features(self, attrs):
        opcode = str(attrs.get("opcode","other")).lower()
        text = str(attrs.get("text",""))
        x = [0.0] * self.feature_dim
        x[self.OPCODES.index(opcode) if opcode in self.OPCODES else 20] = 1.0
        flags = [
            opcode in {"add","sub","mul"},
            opcode in {"sdiv","udiv","srem","urem"},
            opcode in {"load","store","gep"},
            opcode == "call", opcode == "icmp",
            "null" in text.lower(),
            "malloc" in text.lower() or "calloc" in text.lower(),
            "free" in text.lower(), "nsw" in text.lower(),
            "nuw" in text.lower(), bool(attrs.get("result"))
        ]
        for i, flag in enumerate(flags):
            x[21-len(flags)+1+i] = float(flag)
        return x

    def convert(self, graph):
        nodes = list(graph.nodes())
        ids = {n:i for i,n in enumerate(nodes)}
        features = [
            self._features(graph.nodes[n])
            if graph.nodes[n].get("node_type") == "instruction"
            else [0.0] * self.feature_dim
            for n in nodes
        ]
        edges, types = [], []
        type_map = {"sequential":0, "data_flow":1, "control_flow":2, "contains":2}
        for u,v,a in graph.edges(data=True):
            edges.append([ids[u],ids[v]])
            types.append(type_map.get(str(a.get("type","")),0))
        edge_index = (torch.tensor(edges,dtype=torch.long).t().contiguous()
                      if edges else torch.empty((2,0),dtype=torch.long))
        edge_type = (torch.tensor(types,dtype=torch.long)
                     if types else torch.empty((0,),dtype=torch.long))
        return Data(x=torch.tensor(features,dtype=torch.float32),
                    edge_index=edge_index, edge_type=edge_type,
                    num_nodes=len(nodes))

    @staticmethod
    def load_graphs(path):
        with open(path,"rb") as f:
            return pickle.load(f)
