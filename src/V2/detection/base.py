from abc import ABC, abstractmethod

from .catalog import STAGE_LLVM_IR_GRAPH


class BaseDetector(ABC):
    cwe_id = "UNKNOWN"
    title = "Unknown"
    severity = "MEDIUM"
    compiler_stage = STAGE_LLVM_IR_GRAPH

    @abstractmethod
    def detect(self, graph, context=None):
        raise NotImplementedError
