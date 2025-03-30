"""
Configuration settings for the code security scanner.
"""

from aiscan.scanner.prompts import (
    FUNCTION_ANALYSIS_PROMPT,
    FUNCTION_EXTRACTION_PROMPT,
    SECURITY_PROMPT,
    FUNCTION_MATCHING_PROMPT
)

# LM Studio API Configuration
LM_STUDIO_API_URL = "127.0.0.1:1234"

# Model parameters
MODEL_PARAMS = {

    #qwen2.5-coder-14b-instruct
    #gemma-3-27b-it
    "model": "qwen2.5-coder-14b-instruct",
    "draftModel": "qwen2.5-coder-0.5b-instruct"
}

# File extensions to scan
SUPPORTED_EXTENSIONS = {
    ".py",    # Python
    ".js",    # JavaScript
    ".ts",    # TypeScript
    ".java",  # Java
    ".cpp",   # C++
    ".c",     # C
    ".cs",    # C#
    ".go",    # Go
    ".rb",    # Ruby
    ".php",   # PHP
}

# Ignore patterns for files and directories
IGNORE_PATTERNS = {
    "node_modules",
    "venv",
    "__pycache__",
    ".git",
    "dist",
    "build",
    ".env",
    "*.pyc",
    "*.pyo",
    "*.pyd",
} 