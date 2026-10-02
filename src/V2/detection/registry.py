from .cwe190 import CWE190Detector
from .cwe191 import CWE191Detector
from .cwe369 import CWE369Detector
from .cwe476 import CWE476Detector

def get_detectors():
    return [
        CWE190Detector(),
        CWE191Detector(),
        CWE369Detector(),
        CWE476Detector(),
    ]
