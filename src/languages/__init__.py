"""
Language support registry.

Python is handled by the original ``ast``-based pipeline. Java, C and C++ are
parsed with tree-sitter (``src/languages/treesitter_extract.py``) into the same
``ModuleFeatures`` / ``ContextGraph`` objects, so comment wording, complexity
labels and the GUI insight views are shared. IR, pattern analysis, security
analysis and the ML model remain Python-only.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class LanguageInfo:
    key: str                     # "python", "java", "c", "cpp"
    name: str                    # display name
    extensions: Tuple[str, ...]
    doc_style: str               # "google" | "javadoc" | "doxygen"


LANGUAGES: Dict[str, LanguageInfo] = {
    "python": LanguageInfo("python", "Python", (".py", ".pyw"), "google"),
    "java": LanguageInfo("java", "Java", (".java",), "javadoc"),
    "c": LanguageInfo("c", "C", (".c", ".h"), "doxygen"),
    "cpp": LanguageInfo("cpp", "C++", (".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".h++", ".ipp", ".tpp"), "doxygen"),
}

_BY_EXT = {ext: info.key for info in LANGUAGES.values() for ext in info.extensions}

# A .h file is C unless it clearly uses C++ syntax.
_CPP_HINTS = re.compile(
    r"^\s*(class|namespace|template\s*<|using\s+namespace|public:|private:|protected:)"
    r"|\bstd::|\bvirtual\b|\boperator\s*[^\w\s]|#include\s*<(iostream|string|vector|memory|map)>",
    re.MULTILINE,
)


def detect_language(filepath: Optional[str], source: Optional[str] = None) -> str:
    """Language key for a file path (falls back to Python for unknown extensions)."""
    ext = os.path.splitext(filepath or "")[1].lower()
    key = _BY_EXT.get(ext, "python")
    if ext == ".h" and source is not None and _CPP_HINTS.search(source):
        return "cpp"
    return key


def is_supported(filepath: str) -> bool:
    return os.path.splitext(filepath)[1].lower() in _BY_EXT


def language_name(key: str) -> str:
    return LANGUAGES[key].name if key in LANGUAGES else key


SUPPORTED_EXTENSIONS: Tuple[str, ...] = tuple(sorted(_BY_EXT))


def file_dialog_filter() -> str:
    """Qt file-dialog filter string covering every supported language."""
    parts = [f"{info.name} files ({' '.join('*' + e for e in info.extensions)})" for info in LANGUAGES.values()]
    every = " ".join("*" + e for e in SUPPORTED_EXTENSIONS)
    return ";;".join([f"Source files ({every})", *parts, "All files (*)"])
