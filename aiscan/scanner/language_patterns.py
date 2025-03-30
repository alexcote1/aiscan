"""
Language-specific patterns for code analysis.
"""

# Import patterns for different languages
IMPORT_PATTERNS = {
    "python": [
        r"^from\s+(\w+)\s+import\s+(\w+)",
        r"^import\s+(\w+)",
        r"^import\s+(\w+)\s+as\s+(\w+)"
    ],
    "go": [
        r"^import\s+(\"[\w/]+\")",
        r"^import\s+\(([\s\S]*?)\)",
        r"^import\s+(\w+)\s+(\"[\w/]+\")"
    ],
    "rust": [
        r"^use\s+(crate|super|self)::(\w+)",
        r"^use\s+(\w+)::(\w+)",
        r"^mod\s+(\w+)"
    ],
    "java": [
        r"^import\s+([\w.]+)",
        r"^import\s+static\s+([\w.]+)"
    ],
    "cpp": [
        r"^#include\s+[<\"]([\w/]+)[>\"]",
        r"^using\s+namespace\s+(\w+)"
    ]
}

# Function declaration patterns
FUNCTION_PATTERNS = {
    "python": [
        r"^def\s+(\w+)\s*\((.*?)\)",
        r"^async\s+def\s+(\w+)\s*\((.*?)\)"
    ],
    "go": [
        r"^func\s+(\w+)\s*\((.*?)\)\s*(\w+)?",
        r"^func\s*\((.*?)\)\s+(\w+)\s*\((.*?)\)\s*(\w+)?"
    ],
    "rust": [
        r"^fn\s+(\w+)\s*\((.*?)\)\s*->\s*(\w+)",
        r"^unsafe\s+fn\s+(\w+)\s*\((.*?)\)\s*->\s*(\w+)"
    ],
    "java": [
        r"^(public|private|protected)\s+(\w+)\s+(\w+)\s*\((.*?)\)",
        r"^(public|private|protected)\s+static\s+(\w+)\s+(\w+)\s*\((.*?)\)"
    ],
    "cpp": [
        r"^(\w+)\s+(\w+)\s*\((.*?)\)",
        r"^virtual\s+(\w+)\s+(\w+)\s*\((.*?)\)"
    ]
}

# Entry point patterns
ENTRY_POINT_PATTERNS = {
    "python": [
        r"^if\s+__name__\s*==\s*['\"]__main__['\"]",
        r"^def\s+main\s*\(\)"
    ],
    "go": [
        r"^func\s+main\s*\(\)"
    ],
    "rust": [
        r"^fn\s+main\s*\(\)"
    ],
    "java": [
        r"^public\s+static\s+void\s+main\s*\(String\[\]\s+args\)"
    ],
    "cpp": [
        r"^int\s+main\s*\(int\s+argc,\s*char\*\s+argv\[\]\)"
    ]
}

# Security-sensitive patterns
SECURITY_PATTERNS = {
    "python": [
        r"exec\s*\(.*?\)",
        r"eval\s*\(.*?\)",
        r"os\.system\s*\(.*?\)",
        r"subprocess\.call\s*\(.*?\)",
        r"open\s*\(.*?\)"
    ],
    "go": [
        r"exec\.Command\s*\(.*?\)",
        r"os\.Open\s*\(.*?\)",
        r"unsafe\.Pointer",
        r"syscall\.Syscall"
    ],
    "rust": [
        r"unsafe\s*\{",
        r"std::fs::File::open\s*\(.*?\)",
        r"std::process::Command\s*\(.*?\)"
    ],
    "java": [
        r"Runtime\.exec\s*\(.*?\)",
        r"ProcessBuilder\s*\(.*?\)",
        r"File\.create\s*\(.*?\)"
    ],
    "cpp": [
        r"system\s*\(.*?\)",
        r"exec\s*\(.*?\)",
        r"fopen\s*\(.*?\)",
        r"new\s+.*?\*"
    ]
}

# Language-specific file extensions
LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "go": {".go"},
    "rust": {".rs"},
    "java": {".java"},
    "cpp": {".cpp", ".hpp", ".cc", ".hh"},
    "c": {".c", ".h"},
    "csharp": {".cs"},
    "ruby": {".rb"},
    "php": {".php"},
    "javascript": {".js"},
    "typescript": {".ts"}
}

def get_language_from_extension(extension: str) -> str:
    """Get the language name from a file extension."""
    for lang, exts in LANGUAGE_EXTENSIONS.items():
        if extension in exts:
            return lang
    return "unknown" 