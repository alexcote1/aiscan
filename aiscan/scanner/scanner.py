import os
import sys
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.syntax import Syntax
import re

from ..models.base import (
    FunctionAnalysis,
    CodeFunction,
    SecurityFinding,
    SecurityAnalysis,
    FunctionExtractionResult,
    FunctionBoundary,
    FileFunction,
    FunctionCallAnalysis
)
from ..utils.display import display_results
from ..utils.llm_client import LLMClient
from ..visualization.call_graph import draw_call_graph
from ..config import (
    SUPPORTED_EXTENSIONS,
    IGNORE_PATTERNS
)
from .prompts import (
    FUNCTION_ANALYSIS_PROMPT,
    FUNCTION_EXTRACTION_PROMPT,
    SECURITY_PROMPT,
    FUNCTION_MATCHING_PROMPT,
    FUNCTION_CALL_ANALYSIS_PROMPT
)
from .language_patterns import IMPORT_PATTERNS

console = Console()

# Patterns for well-known library functions that should be excluded
WELL_KNOWN_LIBRARY_PATTERNS = [
    # Authentication/Password
    "bcrypt.",
    "pbkdf2_sha256.",
    "hashlib.",
    "passlib.",
    "argon2.",
    
    # Database
    "sqlite3.",
    "psycopg2.",
    "mysql.",
    "pymongo.",
    "redis.",
    
    # Web Frameworks
    "flask.",
    "django.",
    "fastapi.",
    "aiohttp.",
    
    # HTTP Clients
    "requests.",
    "urllib.",
    "httpx.",
    
    # File Operations
    "os.",
    "pathlib.",
    "shutil.",
    
    # Date/Time
    "datetime.",
    "time.",
    
    # JSON/Data
    "json.",
    "yaml.",
    
    # Logging
    "logging.",
    
    # Testing
    "pytest.",
    "unittest."
]

class CodeScanner:
    def __init__(self, verbose: bool = False):
        self.llm_client = LLMClient(verbose=verbose)
        self.supported_extensions = SUPPORTED_EXTENSIONS
        self.ignore_patterns = IGNORE_PATTERNS
        self.function_analyses = {}  # Cache for function analyses
        self.verbose = verbose
        self.all_functions = []  # List to store all functions across all files

    def check_lm_studio_connection(self) -> bool:
        """Check if LM Studio is running and accessible."""
        try:
            if self.llm_client.check_connection():
                return True
            console.print("[red]Error: Could not connect to LM Studio[/red]")
            console.print("\nPlease ensure that:")
            console.print("1. LM Studio is installed and running")
            console.print("2. A model is loaded in LM Studio")
            console.print("3. The API server is enabled in LM Studio\n")
            return False
        except Exception as e:
            console.print(f"[red]Error: Could not connect to LM Studio: {e}[/red]")
            return False

    def should_ignore(self, path: str) -> bool:
        """Check if the path should be ignored based on ignore patterns."""
        return any(pattern in path for pattern in self.ignore_patterns)

    def get_code_files(self, directory: str) -> List[Path]:
        """Recursively get all code files from the directory."""
        code_files = []
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = Path(root) / file
                    if (file_path.suffix in self.supported_extensions and 
                        not self.should_ignore(str(file_path))):
                        code_files.append(file_path)
        except Exception as e:
            console.print(f"[red]Error scanning directory: {e}[/red]")
            sys.exit(1)
        return code_files
    
    def add_line_numbers(self, code: str) -> str:
        """Add line numbers to the code for better context."""
        lines = code.split('\n')
        return '\n'.join(f"{i+1:4d} | {line}" for i, line in enumerate(lines))

    def match_functions_using_llm(self, source_func: str, target_funcs: List[str], context: str) -> str:
        """Use LLM to match a source function name with the most likely target function from a list."""
        try:
            # Extract module name and full path from context
            module_name = ""
            full_path = ""
            for line in context.split('\n'):
                if line.startswith('Module: '):
                    module_name = line[8:].strip()
                elif line.startswith('Full path: '):
                    full_path = line[10:].strip()
            
            # Extract imports from context
            imports = []
            in_imports = False
            for line in context.split('\n'):
                if line.strip() == 'Imports:':
                    in_imports = True
                elif in_imports and line.strip() == '```':
                    in_imports = False
                elif in_imports and line.strip():
                    imports.append(line.strip())
            
            prompt = FUNCTION_MATCHING_PROMPT.format(
                source_func=source_func,
                target_funcs=', '.join(target_funcs),
                module_name=module_name,
                full_module_path=full_path,
                imports='\n'.join(imports) if imports else "No imports"
            )

            result = self.llm_client.call_llm(prompt, context=f"Function matching for {source_func}")
            
            matched_func = result.strip() if isinstance(result, str) else result.content.strip()
            return matched_func if matched_func in target_funcs else "NO_MATCH"
        except Exception as e:
            console.print(f"\n[dim]Warning: LLM function matching failed: {str(e)}[/dim]")
            return "NO_MATCH"

    def analyze_function_calls(self, function: FileFunction) -> FunctionCallAnalysis:
        """Analyze function calls within a function using LLM."""
        try:
            prompt = FUNCTION_CALL_ANALYSIS_PROMPT.format(
                code=function.code,
                imports='\n'.join(function.function.imports) if function.function.imports else "No imports"
            )

            result = self.llm_client.call_llm(
                prompt, 
                response_format=FunctionCallAnalysis,
                context=f"Function call analysis for {function.function.name}"
            )
            
            # Filter out well-known library functions
            if result and result.custom_calls:
                result.custom_calls = [
                    call for call in result.custom_calls
                    if not any(pattern in call.name for pattern in WELL_KNOWN_LIBRARY_PATTERNS)
                ]
            return result
        except Exception as e:
            console.print(f"\n[dim]Warning: Function call analysis failed: {str(e)}[/dim]")
            return FunctionCallAnalysis(custom_calls=[])

    def get_language_from_extension(self, file_path: Path) -> str:
        """Determine the programming language from the file extension."""
        extension = file_path.suffix.lower()
        if extension == '.py':
            return 'python'
        elif extension == '.go':
            return 'go'
        elif extension == '.rs':
            return 'rust'
        elif extension == '.java':
            return 'java'
        elif extension in ['.cpp', '.hpp', '.cc', '.hh']:
            return 'cpp'
        return 'python'  # Default to Python if unknown

    def extract_imports(self, code_lines: List[str], language: str) -> tuple[List[str], Dict[str, str]]:
        """Extract imports based on the programming language."""
        import_lines = []
        imported_functions = {}
        
        if language == 'python':
            for line in code_lines:
                if line.strip().startswith('import '):
                    # Handle 'import module' style imports
                    module = line.strip().split('import ')[1].split(' as ')[0].strip()
                    import_lines.append(line.strip())
                elif line.strip().startswith('from '):
                    # Handle 'from module import function' style imports
                    parts = line.strip().split('import ')
                    module = parts[0].split('from ')[1].strip()
                    functions = [f.strip() for f in parts[1].split(',')]
                    for func in functions:
                        imported_functions[func] = module
                    import_lines.append(line.strip())
        
        elif language == 'go':
            in_import_block = False
            for line in code_lines:
                line = line.strip()
                if line.startswith('import '):
                    if line.startswith('import ('):
                        in_import_block = True
                        import_lines.append(line)
                    else:
                        # Handle single import
                        parts = line.split('import ')[1].split(' ')
                        if len(parts) == 2:
                            alias, path = parts
                            imported_functions[alias] = path.strip('"')
                        else:
                            path = parts[0].strip('"')
                            imported_functions[path.split('/')[-1]] = path
                        import_lines.append(line)
                elif in_import_block:
                    if line == ')':
                        in_import_block = False
                        import_lines.append(line)
                    elif line:
                        # Handle imports in block
                        parts = line.split(' ')
                        if len(parts) == 2:
                            alias, path = parts
                            imported_functions[alias] = path.strip('"')
                        else:
                            path = parts[0].strip('"')
                            imported_functions[path.split('/')[-1]] = path
                        import_lines.append(line)
        
        elif language == 'rust':
            for line in code_lines:
                line = line.strip()
                if line.startswith('use '):
                    # Handle 'use' statements
                    parts = line.split('use ')[1].split('::')
                    if len(parts) > 1:
                        module = parts[0]
                        functions = parts[1].split(',')
                        for func in functions:
                            imported_functions[func.strip()] = module
                    else:
                        # Handle 'use module' style
                        module = parts[0]
                        imported_functions[module] = module
                    import_lines.append(line)
                elif line.startswith('mod '):
                    # Handle module declarations
                    module = line.split('mod ')[1].strip()
                    imported_functions[module] = module
                    import_lines.append(line)
        
        return import_lines, imported_functions

    def extract_functions(self, file_path: Path, code: str) -> List[FileFunction]:
        """Extract individual functions from the code using LLM."""
        try:
            # Add line numbers to the code
            numbered_code = self.add_line_numbers(code)
            code_lines = code.split('\n')
            total_lines = len(code_lines)
            
            # Determine language and extract imports
            language = self.get_language_from_extension(file_path)
            import_lines, imported_functions = self.extract_imports(code_lines, language)
            
            # Get module information
            module_name = file_path.stem  # File name without extension
            try:
                # Try to get relative path from current workspace
                full_module_path = str(file_path.relative_to(Path.cwd())).replace(os.sep, '.')
            except ValueError:
                # If file is outside workspace, use absolute path
                full_module_path = str(file_path).replace(os.sep, '.')
            
            def validate_and_extract_functions(extraction_result: FunctionExtractionResult) -> List[FileFunction]:
                functions = []
                invalid_functions = []
                
                for boundary in extraction_result.functions:
                    # Validate line numbers
                    if boundary.start_line < 1 or boundary.end_line > total_lines:
                        invalid_functions.append({
                            "name": boundary.name,
                            "start_line": boundary.start_line,
                            "end_line": boundary.end_line,
                            "error": f"Invalid line numbers: start_line={boundary.start_line}, end_line={boundary.end_line} (file has {total_lines} lines)"
                        })
                        continue
                    
                    if boundary.start_line > boundary.end_line:
                        invalid_functions.append({
                            "name": boundary.name,
                            "start_line": boundary.start_line,
                            "end_line": boundary.end_line,
                            "error": f"Invalid line range: start_line ({boundary.start_line}) is greater than end_line ({boundary.end_line})"
                        })
                        continue
                    
                    # Extract the actual code for this function
                    function_code = '\n'.join(code_lines[boundary.start_line - 1:boundary.end_line])
                    
                    # Skip empty functions
                    if not function_code.strip():
                        invalid_functions.append({
                            "name": boundary.name,
                            "start_line": boundary.start_line,
                            "end_line": boundary.end_line,
                            "error": "Empty function body"
                        })
                        continue
                    
                    # Create the CodeFunction object (without code)
                    function = CodeFunction(
                        name=boundary.name,
                        start_line=boundary.start_line,
                        end_line=boundary.end_line,
                        is_entry_point=boundary.is_entry_point,
                        module_name=module_name,
                        full_module_path=full_module_path,
                        imports=import_lines,
                        imported_functions=imported_functions,
                        called_functions=[]  # Initialize empty list, will be populated by analyze_function_calls
                    )
                    
                    # Create the FileFunction wrapper with the code
                    file_function = FileFunction(
                        function=function,
                        file_path=str(file_path),
                        code=function_code
                    )
                    
                    # Analyze function calls
                    call_analysis = self.analyze_function_calls(file_function)
                    function.call_analysis = call_analysis
                    
                    # Extract called functions from call_analysis
                    if call_analysis and call_analysis.custom_calls:
                        function.called_functions = [call.name for call in call_analysis.custom_calls]
                    
                    functions.append(file_function)
                
                return functions, invalid_functions
            
            # Create a prompt that focuses on function boundaries
            prompt = FUNCTION_EXTRACTION_PROMPT.format(
                file_name=file_path.name,
                module_name=module_name,
                full_module_path=full_module_path,
                code=numbered_code
            )

            max_retries = 3
            for attempt in range(max_retries):
                try:
                    result = self.llm_client.call_llm(prompt, response_format=FunctionExtractionResult)
                    
                    # The result should already be a FunctionExtractionResult object
                    if not isinstance(result, FunctionExtractionResult):
                        raise ValueError(f"Expected FunctionExtractionResult, got {type(result)}")
                    
                    # If no functions were extracted, create a single "full file" function
                    if not result.functions:
                        lines = code.split('\n')
                        result.functions = [FunctionBoundary(
                            name=f"{file_path.name} (full file)",
                            start_line=1,
                            end_line=len(lines),
                            called_functions=[],
                            is_entry_point=False
                        )]
                    
                    # Validate and extract functions
                    functions, invalid_functions = validate_and_extract_functions(result)
                    
                    # If we have invalid functions and this isn't our last attempt, retry with error feedback
                    if invalid_functions and attempt < max_retries - 1:
                        error_feedback = "\n".join([
                            f"Function '{f['name']}' has invalid boundaries: {f['error']}"
                            for f in invalid_functions
                        ])
                        prompt += f"\n\nPrevious attempt had errors:\n{error_feedback}\n\nPlease fix these errors and try again."
                        continue
                    
                    return functions
                    
                except (json.JSONDecodeError, ValueError) as e:
                    if attempt < max_retries - 1:
                        console.print(f"\n[yellow]Warning: Could not parse function extraction result (attempt {attempt + 1}): {str(e)}[/yellow]")
                        continue
                    else:
                        console.print(f"\n[yellow]Warning: Could not parse function extraction result after {max_retries} attempts: {str(e)}[/yellow]")
                        # Return the whole file as a single function if parsing failed
                        lines = code.split('\n')
                        function = CodeFunction(
                            name=f"{file_path.name} (full file)",
                            start_line=1,
                            end_line=len(lines),
                            called_functions=[],
                            is_entry_point=False,
                            module_name=file_path.stem,
                            full_module_path=full_module_path,
                            imports=import_lines,
                            imported_functions=imported_functions
                        )
                        return [FileFunction(
                            function=function,
                            file_path=str(file_path),
                            code=code
                        )]
            
            # If we get here, all retries failed
            console.print(f"\n[red]Error: Failed to extract valid functions after {max_retries} attempts[/red]")
            lines = code.split('\n')
            function = CodeFunction(
                name=f"{file_path.name} (full file)",
                start_line=1,
                end_line=len(lines),
                called_functions=[],
                is_entry_point=False,
                module_name=file_path.stem,
                full_module_path=full_module_path,
                imports=import_lines,
                imported_functions=imported_functions
            )
            return [FileFunction(
                function=function,
                file_path=str(file_path),
                code=code
            )]
                
        except Exception as e:
            console.print(f"\n[red]Error extracting functions from {file_path}: {str(e)}[/red]")
            # Return the whole file as a single function if extraction failed
            lines = code.split('\n')
            try:
                # Try to get relative path from current workspace
                full_module_path = str(file_path.relative_to(Path.cwd())).replace(os.sep, '.')
            except ValueError:
                # If file is outside workspace, use absolute path
                full_module_path = str(file_path).replace(os.sep, '.')
            
            function = CodeFunction(
                name=f"{file_path.name} (full file)",
                start_line=1,
                end_line=len(lines),
                called_functions=[],
                is_entry_point=False,
                module_name=file_path.stem,
                full_module_path=full_module_path,
                imports=import_lines,
                imported_functions=imported_functions
            )
            return [FileFunction(
                function=function,
                file_path=str(file_path),
                code=code
            )]

    def build_call_tree(self, functions: List[FileFunction]) -> Dict[str, List[str]]:
        """Build a directed graph of function calls."""
        call_tree = {}
        for func in functions:
            # Extract function names from call_analysis
            called_functions = []
            if func.function.call_analysis and func.function.call_analysis.custom_calls:
                called_functions = [call.name for call in func.function.call_analysis.custom_calls]
            call_tree[func.function.name] = called_functions
        return call_tree

    def get_analysis_order(self, call_tree: Dict[str, List[str]]) -> List[str]:
        """Get the order to analyze functions (bottom-up)."""
        visited = set()
        order = []
        
        def visit(func_name: str):
            if func_name in visited:
                return
            visited.add(func_name)
            
            # Visit all called functions first
            for called_func in call_tree.get(func_name, []):
                visit(called_func)
            
            # Add this function after its dependencies
            order.append(func_name)
        
        # Start with entry points
        entry_points = [name for name, calls in call_tree.items() if not any(name in calls for calls in call_tree.values())]
        for entry in entry_points:
            visit(entry)
        
        return order

    def analyze_function(self, file_path: Path, function: FileFunction, rabbit_mode: bool = False) -> List[SecurityFinding]:
        """Analyze a single function using LM Studio."""
        try:
            # Add line numbers to the function code
            numbered_code = self.add_line_numbers(function.code)
            
            # If in rabbit mode, first get function analysis
            if rabbit_mode:
                # First ensure all child functions are analyzed
                for called_func_name in function.function.called_functions:
                    if called_func_name not in self.function_analyses:
                        # Find the called function in our function list
                        called_func = next((f for f in self.all_functions if f.function.name == called_func_name), None)
                        if called_func:
                            # Recursively analyze the child function
                            child_findings = self.analyze_function(Path(called_func.file_path), called_func, rabbit_mode)
                            # Store the findings but don't return them yet
                            if child_findings:
                                self.function_analyses[called_func_name] = {
                                    "findings": child_findings,
                                    "analysis": self.function_analyses.get(called_func_name, {})
                                }
                
                # Now proceed with the current function's analysis
                if function.function.name not in self.function_analyses:
                    max_retries = 3
                    for attempt in range(max_retries):
                        try:
                            # Build context from child function analyses
                            child_context = []
                            for called_func_name in function.function.called_functions:
                                if called_func_name in self.function_analyses:
                                    child_analysis = self.function_analyses[called_func_name]
                                    if isinstance(child_analysis, dict):
                                        child_context.append(f"""
Child Function: {called_func_name}
Summary: {child_analysis.get('analysis', {}).get('function_summary', 'Unknown')}
Potential Vulnerabilities: {child_analysis.get('analysis', {}).get('potential_vulnerabilities', 'Unknown')}
Logic Flaws: {child_analysis.get('analysis', {}).get('logic_flaws', 'Unknown')}
Data Flow: {child_analysis.get('analysis', {}).get('data_flow', 'Unknown')}
""")
                            
                            # Format the prompt with the code, imports, and child function context
                            analysis_prompt = FUNCTION_ANALYSIS_PROMPT.format(
                                code=numbered_code.replace('{', '{{').replace('}', '}}'),
                                imports='\n'.join(function.function.imports) if function.function.imports else "No imports",
                                child_functions_context='\n'.join(child_context) if child_context else "No child functions analyzed"
                            )
                            
                            analysis_result = self.llm_client.call_llm(
                                analysis_prompt, 
                                response_format=FunctionAnalysis,
                                context=f"Function analysis for {function.function.name}",
                                no_drafting=True
                            )
                            
                            self.function_analyses[function.function.name] = analysis_result
                            
                            # Now do call analysis
                            call_analysis = self.analyze_function_calls(function)
                            function.function.call_analysis = call_analysis
                            
                            # If we have call analysis, merge it with the function analysis based on line numbers
                            if call_analysis and call_analysis.custom_calls:
                                # Create a map of line numbers to function calls
                                call_map = {call.line: call for call in call_analysis.custom_calls}
                                
                                # Split the function summary into lines
                                summary_lines = analysis_result.function_summary.split('\n')
                                
                                # Insert call information after the relevant lines
                                new_summary_lines = []
                                for i, line in enumerate(summary_lines, 1):
                                    new_summary_lines.append(line)
                                    if i in call_map:
                                        call = call_map[i]
                                        new_summary_lines.append(f"  → Calls: {call.name} ({'imported' if call.is_imported else 'direct'})")
                                
                                # Update the function summary with the merged information
                                analysis_result.function_summary = '\n'.join(new_summary_lines)
                            
                            break
                        except Exception as e:
                            console.print(f"\n[dim]Attempt {attempt + 1}/{max_retries} failed for {function.function.name}: {str(e)}[/dim]")
                            if attempt == max_retries - 1:
                                console.print(f"[yellow]Warning: Function analysis failed for {function.function.name} after {max_retries} attempts[/yellow]")
                                self.function_analyses[function.function.name] = FunctionAnalysis(
                                    function_summary="Analysis failed",
                                    potential_vulnerabilities="Analysis failed",
                                    logic_flaws="Analysis failed",
                                    data_flow="Analysis failed"
                                )
                
                function.function.analysis = self.function_analyses.get(function.function.name)
            
            # Build called functions analysis context
            called_functions_analysis = []
            for called_func_name in function.function.called_functions:
                # First check if we have an analysis for this function
                if called_func_name in self.function_analyses:
                    called_analysis = self.function_analyses[called_func_name]
                    # Handle both dictionary and FunctionAnalysis object cases
                    if isinstance(called_analysis, dict):
                        called_functions_analysis.append(f"""
Function: {called_func_name}
Summary: {called_analysis.get('analysis', {}).get('function_summary', 'Unknown')}
Potential Vulnerabilities: {called_analysis.get('analysis', {}).get('potential_vulnerabilities', 'Unknown')}
Logic Flaws: {called_analysis.get('analysis', {}).get('logic_flaws', 'Unknown')}
Data Flow: {called_analysis.get('analysis', {}).get('data_flow', 'Unknown')}
""")
                    else:
                        called_functions_analysis.append(f"""
Function: {called_func_name}
Summary: {called_analysis.function_summary}
Potential Vulnerabilities: {called_analysis.potential_vulnerabilities}
Logic Flaws: {called_analysis.logic_flaws}
Data Flow: {called_analysis.data_flow}
""")
                else:
                    # If we don't have an analysis yet, add a placeholder
                    called_functions_analysis.append(f"""
Function: {called_func_name}
Summary: Function found in call tree but not analyzed
Potential Vulnerabilities: Unknown
Logic Flaws: Unknown
Data Flow: Unknown
""")
            
            # Then do security analysis
            prompt = SECURITY_PROMPT.format(
                code=numbered_code,
                called_functions_analysis="\n".join(called_functions_analysis) if called_functions_analysis else "No called functions analyzed yet.",
                imports='\n'.join(function.function.imports) if function.function.imports else "No imports"
            )
            result = self.llm_client.call_llm(
                prompt, 
                response_format=SecurityAnalysis,
                context=f"Security analysis for {function.function.name}",
                no_drafting=True
            )
            
            # Debug only if findings are present or in verbose mode
            if result and result.findings:
                # Filter out "No Security Vulnerability Found" findings
                actual_findings = [
                    finding for finding in result.findings 
                    if finding.title.lower() != "no security vulnerability found"
                ]
                if actual_findings:
                    console.print(f"\n[dim]Found {len(actual_findings)} issue(s) in function {function.function.name}[/dim]")
                
                # Add function metadata to each finding
                for finding in actual_findings:
                    finding.function_name = function.function.name
                    finding.start_line = function.function.start_line
                    finding.end_line = function.function.end_line
                    finding.called_functions = function.function.called_functions
                    finding.is_entry_point = function.function.is_entry_point
                    if rabbit_mode and function.function.analysis:
                        # Handle both dictionary and Pydantic model cases
                        if isinstance(function.function.analysis, dict):
                            finding.function_analysis = function.function.analysis
                        else:
                            finding.function_analysis = function.function.analysis.model_dump()
                    
                    # Add information about imported functions and handle ambiguous cases
                    if finding.function_name in function.function.imported_functions:
                        finding.imported_from = function.function.imported_functions[finding.function_name]
                    elif '.' in finding.function_name:
                        base_name = finding.function_name.split('.')[-1]
                        if base_name in function.function.imported_functions:
                            finding.imported_from = function.function.imported_functions[base_name]
                        else:
                            # Try to match the function using LLM for ambiguous cases
                            context = f"Module: {function.function.module_name}\nFull path: {function.function.full_module_path}\nImports: {', '.join(function.function.imports)}"
                            matched_func = self.match_functions_using_llm(
                                finding.function_name,
                                list(function.function.imported_functions.keys()),
                                context
                            )
                            if matched_func != "NO_MATCH":
                                finding.imported_from = function.function.imported_functions[matched_func]
                                finding.function_name = matched_func
                return actual_findings
            return []
        except Exception as e:
            # Only print error if it's not related to imported functions
            if not any(imported_func in str(e) for imported_func in function.function.imported_functions):
                console.print(f"\n[red]Error analyzing function {function.function.name} in {file_path}: {str(e)}[/red]")
            return []

    def scan_directory(self, directory: str, csv_output: bool = False, rabbit_mode: bool = False):
        """Scan a directory for security issues."""
        if not self.check_lm_studio_connection():
            sys.exit(1)

        console.print(Panel.fit(
            "[bold blue]Code Security Scanner[/bold blue]\n"
            f"Scanning directory: {directory}\n"
            f"Mode: {'Rabbit (Deep Analysis)' if rabbit_mode else 'Standard'}",
            title="Security Analysis"
        ))

        code_files = self.get_code_files(directory)
        if not code_files:
            console.print("[yellow]No supported code files found in the specified directory.[/yellow]")
            return

        # First phase: Extract all functions from all files
        console.print("\n[bold cyan]Phase 1: Extracting Functions[/bold cyan]")
        self.all_functions = []  # Reset the all_functions list
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            extraction_task = progress.add_task("Extracting functions...", total=len(code_files))
            
            for file_path in code_files:
                progress.update(extraction_task, description=f"Extracting functions from {file_path.name}...")
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        code = f.read()
                    functions = self.extract_functions(file_path, code)
                    self.all_functions.extend(functions)  # Update the class attribute
                    console.print(f"[dim]Found {len(functions)} functions in {file_path.name}[/dim]")
                except Exception as e:
                    console.print(f"[red]Error extracting functions from {file_path.name}: {str(e)}[/red]")
                progress.advance(extraction_task)

        # Second phase: Build call tree across all files
        console.print("\n[bold cyan]Phase 2: Building Call Tree[/bold cyan]")
        call_tree = self.build_call_tree(self.all_functions)
        analysis_order = self.get_analysis_order(call_tree)
        
        # Generate call graph if requested
        if hasattr(self, 'generate_call_graph') and self.generate_call_graph:
            draw_call_graph(call_tree, "project_call_graph.puml")

        # Third phase: Security Analysis
        console.print("\n[bold cyan]Phase 3: Security Analysis[/bold cyan]")
        results = []
        analysis_errors = []
        
        # Find orphaned functions in rabbit mode
        orphaned_functions = []
        if rabbit_mode:
            orphaned_functions = self.find_orphaned_functions(self.all_functions, call_tree)
            if orphaned_functions:
                console.print(f"\n[yellow]Found {len(orphaned_functions)} orphaned functions across all files[/yellow]")
                for func in orphaned_functions:
                    console.print(f"[dim]• {func.function.name} in {func.file_path} (lines {func.function.start_line}-{func.function.end_line})[/dim]")

        # First pass: Analyze all functions for function analysis in rabbit mode
        if rabbit_mode:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                analysis_task = progress.add_task("Analyzing function behaviors...", total=len(analysis_order))
                for func_name in analysis_order:
                    try:
                        file_func = next(f for f in self.all_functions if f.function.name == func_name)
                        progress.update(analysis_task, description=f"Analyzing function '{file_func.function.name}' in {file_func.file_path}...")
                        try:
                            # Only do function analysis, not security analysis
                            numbered_code = self.add_line_numbers(file_func.code)
                            analysis_prompt = FUNCTION_ANALYSIS_PROMPT.format(
                                code=numbered_code.replace('{', '{{').replace('}', '}}'),
                                imports='\n'.join(file_func.function.imports) if file_func.function.imports else "No imports"
                            )
                            analysis_result = self.llm_client.call_llm(analysis_prompt, response_format=FunctionAnalysis)
                            if hasattr(analysis_result, 'parsed'):
                                self.function_analyses[file_func.function.name] = analysis_result
                            elif hasattr(analysis_result, 'content'):
                                # Try to parse the content as JSON
                                try:
                                    content = analysis_result.content.strip()
                                    if content.startswith('```json'):
                                        content = content[7:]
                                    if content.endswith('```'):
                                        content = content[:-3]
                                    content = content.strip()
                                    analysis_dict = json.loads(content)
                                    self.function_analyses[file_func.function.name] = FunctionAnalysis(**analysis_dict)
                                except (json.JSONDecodeError, ValueError) as e:
                                    console.print(f"\n[dim]Warning: Could not parse function analysis result for {file_func.function.name}: {str(e)}[/dim]")
                                    self.function_analyses[file_func.function.name] = FunctionAnalysis(
                                        function_summary="Analysis failed",
                                        potential_vulnerabilities="Analysis failed",
                                        logic_flaws="Analysis failed",
                                        data_flow="Analysis failed"
                                    )
                        except Exception as e:
                            error_msg = f"Error analyzing function '{file_func.function.name}' in {file_func.file_path}: {str(e)}"
                            analysis_errors.append(error_msg)
                            console.print(f"[red]{error_msg}[/red]")
                    except StopIteration:
                        error_msg = f"Warning: Function '{func_name}' was found in call tree but not in extracted functions"
                        analysis_errors.append(error_msg)
                        console.print(f"[yellow]{error_msg}[/yellow]")
                    progress.advance(analysis_task)

        # Second pass: Security analysis on entry points and orphaned functions
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            security_task = progress.add_task("Performing security analysis...", total=len(analysis_order))
            
            for func_name in analysis_order:
                try:
                    file_func = next(f for f in self.all_functions if f.function.name == func_name)
                    # Skip security analysis if not an entry point or orphaned function in rabbit mode
                    if rabbit_mode and not file_func.function.is_entry_point and file_func not in orphaned_functions:
                        progress.advance(security_task)
                        continue
                        
                    progress.update(security_task, description=f"Analyzing function '{file_func.function.name}' in {file_func.file_path}...")
                    try:
                        function_findings = self.analyze_function(Path(file_func.file_path), file_func, rabbit_mode)
                        results.append({
                            "file": file_func.file_path,
                            "findings": [finding.model_dump() if hasattr(finding, 'model_dump') else finding.dict() for finding in function_findings]
                        })
                    except Exception as e:
                        error_msg = f"Error analyzing function '{file_func.function.name}' in {file_func.file_path}: {str(e)}"
                        analysis_errors.append(error_msg)
                        console.print(f"[red]{error_msg}[/red]")
                except StopIteration:
                    error_msg = f"Warning: Function '{func_name}' was found in call tree but not in extracted functions"
                    analysis_errors.append(error_msg)
                    console.print(f"[yellow]{error_msg}[/yellow]")
                progress.advance(security_task)

        # Add analysis errors and orphaned functions to results
        if analysis_errors:
            results.append({
                "file": "analysis_errors",
                "errors": analysis_errors
            })
            
        if rabbit_mode and orphaned_functions:
            results.append({
                "file": "orphaned_functions",
                "orphaned_functions": [
                    {
                        "name": func.function.name,
                        "file": func.file_path,
                        "start_line": func.function.start_line,
                        "end_line": func.function.end_line,
                        "code": func.code
                    }
                    for func in orphaned_functions
                ]
            })

        display_results(results, csv_output, rabbit_mode)

    def find_orphaned_functions(self, functions: List[FileFunction], call_tree: Dict[str, List[str]]) -> List[FileFunction]:
        """Find functions that aren't called by any entry point."""
        # Get all entry points
        entry_points = [func for func in functions if func.function.is_entry_point]
        if not entry_points:
            return functions  # If no entry points, all functions are orphaned
            
        # Create a set of all functions that are called by entry points
        called_functions = set()
        visited = set()  # Track visited functions to prevent infinite recursion
        
        for entry_point in entry_points:
            def collect_called(func_name: str):
                if func_name in visited:  # Skip if already visited
                    return
                visited.add(func_name)
                called_functions.add(func_name)
                for called in call_tree.get(func_name, []):
                    collect_called(called)
            
            collect_called(entry_point.function.name)
        
        # Return functions that aren't in the called_functions set
        return [func for func in functions if func.function.name not in called_functions]

    def analyze_code(self, file_path: Path, functions: List[FileFunction], progress=None, rabbit_mode: bool = False) -> Dict[str, Any]:
        """Analyze a code file using LM Studio by analyzing each function separately."""
        try:
            # Build call tree and get analysis order
            call_tree = self.build_call_tree(functions)
            analysis_order = self.get_analysis_order(call_tree)
            
            # Create a map of function names to functions
            function_map = {func.function.name: func for func in functions}
            
            all_findings = []
            analysis_errors = []
            
            # Find orphaned functions in rabbit mode
            orphaned_functions = []
            if rabbit_mode:
                orphaned_functions = self.find_orphaned_functions(functions, call_tree)
                if orphaned_functions:
                    console.print(f"\n[yellow]Found {len(orphaned_functions)} orphaned functions in {file_path.name}[/yellow]")
                    for func in orphaned_functions:
                        console.print(f"[dim]• {func.function.name} (lines {func.function.start_line}-{func.function.end_line})[/dim]")
            
            # First pass: Analyze all functions for function analysis in rabbit mode
            if rabbit_mode:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    analysis_task = progress.add_task("Analyzing function behaviors...", total=len(analysis_order))
                    for func_name in analysis_order:
                        try:
                            file_func = next(f for f in functions if f.function.name == func_name)
                            progress.update(analysis_task, description=f"Analyzing function '{file_func.function.name}' in {file_func.file_path}...")
                            try:
                                # Only do function analysis, not security analysis
                                numbered_code = self.add_line_numbers(file_func.code)
                                analysis_prompt = FUNCTION_ANALYSIS_PROMPT.format(
                                    code=numbered_code.replace('{', '{{').replace('}', '}}'),
                                    imports='\n'.join(file_func.function.imports) if file_func.function.imports else "No imports"
                                )
                                analysis_result = self.llm_client.call_llm(analysis_prompt, response_format=FunctionAnalysis)
                                if hasattr(analysis_result, 'parsed'):
                                    self.function_analyses[file_func.function.name] = analysis_result
                                elif hasattr(analysis_result, 'content'):
                                    # Try to parse the content as JSON
                                    try:
                                        content = analysis_result.content.strip()
                                        if content.startswith('```json'):
                                            content = content[7:]
                                        if content.endswith('```'):
                                            content = content[:-3]
                                        content = content.strip()
                                        analysis_dict = json.loads(content)
                                        self.function_analyses[file_func.function.name] = FunctionAnalysis(**analysis_dict)
                                    except (json.JSONDecodeError, ValueError) as e:
                                        console.print(f"\n[dim]Warning: Could not parse function analysis result for {file_func.function.name}: {str(e)}[/dim]")
                                        self.function_analyses[file_func.function.name] = FunctionAnalysis(
                                            function_summary="Analysis failed",
                                            potential_vulnerabilities="Analysis failed",
                                            logic_flaws="Analysis failed",
                                            data_flow="Analysis failed"
                                        )
                            except Exception as e:
                                error_msg = f"Error analyzing function '{file_func.function.name}' in {file_func.file_path}: {str(e)}"
                                analysis_errors.append(error_msg)
                                console.print(f"[red]{error_msg}[/red]")
                        except StopIteration:
                            error_msg = f"Warning: Function '{func_name}' was found in call tree but not in extracted functions"
                            analysis_errors.append(error_msg)
                            console.print(f"[yellow]{error_msg}[/yellow]")
                        progress.advance(analysis_task)
            
            # Second pass: Only do security analysis on entry points and orphaned functions in rabbit mode
            if progress:
                functions_task = progress.add_task(f"Analyzing functions in {file_path.name}...", total=len(analysis_order))
                
                for func_name in analysis_order:
                    function = function_map[func_name]
                    # Skip security analysis if not an entry point or orphaned function in rabbit mode
                    if rabbit_mode and not function.function.is_entry_point and function not in orphaned_functions:
                        progress.advance(functions_task)
                        continue
                        
                    progress.update(functions_task, description=f"Analyzing function '{function.function.name}'...")
                    try:
                        function_findings = self.analyze_function(file_path, function, rabbit_mode)
                        all_findings.extend(function_findings)
                    except Exception as e:
                        error_msg = f"Error analyzing function '{function.function.name}': {str(e)}"
                        analysis_errors.append(error_msg)
                        console.print(f"[red]{error_msg}[/red]")
                    progress.advance(functions_task)
            else:
                # Simple loop without progress bar
                for func_name in analysis_order:
                    function = function_map[func_name]
                    # Skip security analysis if not an entry point or orphaned function in rabbit mode
                    if rabbit_mode and not function.function.is_entry_point and function not in orphaned_functions:
                        continue
                        
                    console.print(f"[dim]Analyzing function '{function.function.name}'...[/dim]")
                    try:
                        function_findings = self.analyze_function(file_path, function, rabbit_mode)
                        all_findings.extend(function_findings)
                    except Exception as e:
                        error_msg = f"Error analyzing function '{function.function.name}': {str(e)}"
                        analysis_errors.append(error_msg)
                        console.print(f"[red]{error_msg}[/red]")
            
            result = {
                "file": str(file_path),
                "findings": [finding.model_dump() if hasattr(finding, 'model_dump') else finding.dict() for finding in all_findings]
            }
            
            if analysis_errors:
                result["analysis_errors"] = analysis_errors
                
            if rabbit_mode and orphaned_functions:
                result["orphaned_functions"] = [
                    {
                        "name": func.function.name,
                        "start_line": func.function.start_line,
                        "end_line": func.function.end_line,
                        "code": func.code
                    }
                    for func in orphaned_functions
                ]
                
            return result

        except Exception as e:
            error_msg = f"Error analyzing {file_path}: {str(e)}"
            console.print(f"\n[red]{error_msg}[/red]")
            return {
                "error": error_msg,
                "file": str(file_path)
            } 