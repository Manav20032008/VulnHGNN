from .cwe121 import CWE121Detector
from .cwe122 import CWE122Detector
from .cwe125 import CWE125Detector
from .cwe134 import CWE134Detector
from .cwe190 import CWE190Detector
from .cwe191 import CWE191Detector
from .cwe369 import CWE369Detector
from .cwe400 import CWE400Detector
from .cwe476 import CWE476Detector
from .cwe789 import CWE789Detector
from .cwe833 import CWE833Detector
from .cwe835 import CWE835Detector
from .memory_lifecycle import MemoryLifecycleDetector


def get_detectors():
    return [
        CWE190Detector(),
        CWE191Detector(),
        CWE369Detector(),
        CWE476Detector(),
        CWE121Detector(),
        CWE122Detector(),
        CWE125Detector(),
        CWE134Detector(),
        CWE789Detector(),
        CWE400Detector(),
        CWE835Detector(),
        CWE833Detector(),
        MemoryLifecycleDetector(),
    ]
