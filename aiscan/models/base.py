from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class FunctionAnalysis(BaseModel):
    function_summary: str
    potential_vulnerabilities: str
    logic_flaws: str
    data_flow: str

class FunctionCall(BaseModel):
    name: str
    line: int
    is_imported: bool

class FunctionCallAnalysis(BaseModel):
    custom_calls: List[FunctionCall]

class FunctionBoundary(BaseModel):
    name: str
    start_line: int
    end_line: int
    is_entry_point: bool = False  # Whether this function is likely a user entry point

class FunctionExtractionResult(BaseModel):
    functions: List[FunctionBoundary]

class CodeFunction(BaseModel):
    """Metadata about a function, without the actual code content."""
    name: str
    start_line: int
    end_line: int
    is_entry_point: bool = False  # Whether this function is likely a user entry point
    analysis: Optional[FunctionAnalysis] = None  # Detailed analysis of the function
    call_analysis: Optional[FunctionCallAnalysis] = None  # Analysis of function calls
    module_name: str = ""  # The module name (file name without extension)
    full_module_path: str = ""  # The full module path (e.g., package.subpackage.module)
    imports: List[str] = []  # List of imports used in the function
    imported_functions: Dict[str, str] = {}  # Map of imported function names to their source modules
    called_functions: List[str] = []  # List of function names this function calls

class FileFunction(BaseModel):
    """A function with its file location information and code content."""
    function: CodeFunction
    file_path: str  # The full file path where this function is defined
    code: str  # The actual code content of the function

class SecurityFinding(BaseModel):
    thinking: str
    title: str
    severity: str
    description: str
    impact: str
    fix: str
    confidence: str
    evidence: str
    function_name: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    called_functions: Optional[List[str]] = None  # Track which functions are called where the issue was found
    is_entry_point: Optional[bool] = None  # Whether the function is an entry point
    function_analysis: Optional[Dict[str, str]] = None  # Detailed analysis of the function
    imported_from: Optional[str] = None  # Information about the imported function

class SecurityAnalysis(BaseModel):
    findings: List[SecurityFinding] 