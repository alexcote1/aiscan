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
LM_STUDIO_API_URL = "192.168.10.212:1234"

# Model parameters
MODEL_PARAMS = {


    #gemma-3-27b-it
     "model": "gemma-3-27b-it",
    #  "model": "qwen2.5-coder-32b-instruct",
    #  "draftModel": "qwen2.5-coder-3b-instruct"
    # "model": "deepseek-r1-distill-qwen-32b",
    # "draftModel": "deepseek-r1-distill-qwen-1.5b"
}

# Maximum number of parallel jobs for independent operations
MAX_PARALLEL_JOBS = 4

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