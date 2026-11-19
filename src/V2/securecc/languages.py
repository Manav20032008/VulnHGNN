from __future__ import annotations

from pathlib import Path

C_SUFFIXES = frozenset({".c"})
CPP_SUFFIXES = frozenset({".cc", ".cpp", ".cxx"})
JAVA_SUFFIXES = frozenset({".java"})
C_FAMILY_SUFFIXES = C_SUFFIXES | CPP_SUFFIXES
ENGINE_SUFFIXES = C_FAMILY_SUFFIXES | JAVA_SUFFIXES
SUPPORTED_SUFFIXES = ENGINE_SUFFIXES

LANGUAGE_CHOICES: tuple[dict[str, str], ...] = (
    {"id": "c", "label": "C", "extension": ".c", "workspace": "editor_workspace.c"},
    {"id": "cpp", "label": "C++", "extension": ".cpp", "workspace": "editor_workspace.cpp"},
    {"id": "java", "label": "Java", "extension": ".java", "workspace": "editor_workspace.java"},
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
    if s in JAVA_SUFFIXES:
        return "java"
    if s in CPP_SUFFIXES:
        return "cpp"
    return "c"


def is_java_path(path: Path) -> bool:
    return path.suffix.lower() in JAVA_SUFFIXES


def is_c_family_path(path: Path) -> bool:
    return path.suffix.lower() in C_FAMILY_SUFFIXES


def is_engine_path(path: Path) -> bool:
    return path.suffix.lower() in ENGINE_SUFFIXES


def is_cpp_suffix(suffix: str) -> bool:
    return suffix.lower() in CPP_SUFFIXES


def compiler_for_source(source: Path) -> str:
    if is_java_path(source):
        return "javac"
    if is_cpp_suffix(source.suffix):
        return "clang++"
    return "clang"


def validate_supported_suffix(suffix: str) -> None:
    if suffix.lower() not in SUPPORTED_SUFFIXES:
        raise ValueError(
            "supported languages: C (.c), C++ (.cc, .cpp, .cxx), Java (.java)"
        )