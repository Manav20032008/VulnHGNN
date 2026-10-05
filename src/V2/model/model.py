import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv, global_mean_pool, global_max_pool
from .schema import SCHEMA, ModelSchema

class VulnHGNNV2(nn.Module):
    def __init__(self, schema: ModelSchema = SCHEMA):
        super().__init__()
        self.schema = schema
        h, heads = schema.hidden_dim, schema.heads
        self.input_proj = nn.Sequential(
            nn.Linear(schema.node_feature_dim,h),
            nn.LayerNorm(h), nn.GELU()
        )
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()
        for _ in range(schema.layers):
            self.convs.append(GATv2Conv(
                h, h//heads, heads=heads, concat=True,
                edge_dim=schema.edge_type_count,
                dropout=schema.dropout, add_self_loops=True
            ))
            self.norms.append(nn.LayerNorm(h))
        self.classifier = nn.Sequential(
            nn.Linear(2*h,h), nn.GELU(),
            nn.Dropout(schema.dropout),
            nn.Linear(h,schema.num_classes)
        )

    def forward(self,x,edge_index,edge_type=None,batch=None):
        if batch is None:
            batch = torch.zeros(x.size(0),dtype=torch.long,device=x.device)
        if edge_type is None:
            edge_type = torch.zeros(edge_index.size(1),dtype=torch.long,device=x.device)
        edge_attr = F.one_hot(
            edge_type.long().clamp(0,self.schema.edge_type_count-1),
            num_classes=self.schema.edge_type_count
        ).float()
        h = self.input_proj(x)
        for conv,norm in zip(self.convs,self.norms):
            residual = h
            h = F.gelu(conv(h,edge_index,edge_attr))
            h = norm(h + residual)
            h = F.dropout(h,p=self.schema.dropout,training=self.training)
        pooled = torch.cat([global_mean_pool(h,batch),global_max_pool(h,batch)],dim=-1)
        return self.classifier(pooled)

    def probabilities(self,*args,**kwargs):
        return torch.sigmoid(self.forward(*args,**kwargs))
