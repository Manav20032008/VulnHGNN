from abc import ABC, abstractmethod

class BaseDetector(ABC):
    cwe_id = "UNKNOWN"
    title = "Unknown"
    severity = "MEDIUM"

    @abstractmethod
    def detect(self, graph, context=None):
        raise NotImplementedError
