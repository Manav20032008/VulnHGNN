from __future__ import annotations

from pathlib import Path

C_SUFFIXES = frozenset({".c"})
CPP_SUFFIXES = frozenset({".cc", ".cpp", ".cxx"})
C_FAMILY_SUFFIXES = C_SUFFIXES | CPP_SUFFIXES
PYTHON_SUFFIXES = frozenset({".py"})
SUPPORTED_SUFFIXES = C_FAMILY_SUFFIXES | PYTHON_SUFFIXES

LANGUAGE_CHOICES: tuple[dict[str, str], ...] = (
    {"id": "c", "label": "C", "extension": ".c", "workspace": "editor_workspace.c"},
    {"id": "cpp", "label": "C++", "extension": ".cpp", "workspace": "editor_workspace.cpp"},
    {"id": "python", "label": "Python", "extension": ".py", "workspace": "editor_workspace.py"},
)


def suffix_for_language(language_id: str) -> str:
    lang = (language_id or "c").lower()
    for item in LANGUAGE_CHOICES:
        if item["id"] == lang:
            return item["extension"]
    return ".c"


def workspace_name_for_language(language_id: str) -> str:
    lang = (language_id or "c").lower()
    for item in LANGUAGE_CHOICES:
        if item["id"] == lang:
            return item["workspace"]
    return "editor_workspace.c"


def language_id_from_suffix(suffix: str) -> str:
    s = (suffix or "").lower()
    if s in PYTHON_SUFFIXES:
        return "python"
    if s in CPP_SUFFIXES:
        return "cpp"
    return "c"


def is_python_path(path: Path) -> bool:
    return path.suffix.lower() in PYTHON_SUFFIXES


def is_c_family_path(path: Path) -> bool:
    return path.suffix.lower() in C_FAMILY_SUFFIXES


def is_cpp_suffix(suffix: str) -> bool:
    return suffix.lower() in CPP_SUFFIXES


def compiler_for_source(source: Path) -> str:
    if is_cpp_suffix(source.suffix):
        return "clang++"
    return "clang"


def validate_supported_suffix(suffix: str) -> None:
    if suffix.lower() not in SUPPORTED_SUFFIXES:
        raise ValueError(
            "supported languages: C (.c), C++ (.cc, .cpp, .cxx), Python (.py)"
        )
