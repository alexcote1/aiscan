#!/usr/bin/env python3
"""
Tests for the Code Security Scanner
"""

import json
import pytest
import os
from pathlib import Path
from unittest.mock import patch, MagicMock, call

from aiscan.models.base import (
    FunctionExtractionResult, 
    FunctionBoundary, 
    CodeFunction, 
    FileFunction,
    SecurityAnalysis,
    SecurityFinding,
    FunctionAnalysis,
    FunctionCallAnalysis,
    FunctionCall,
    FunctionMatch,
    FunctionMatchResponse
)

# ================================
# Individual Component Tests
# ================================

def test_check_lm_studio_connection_success(code_scanner):
    with patch('aiscan.utils.llm_client.LLMClient.check_connection', return_value=True):
        assert code_scanner.check_lm_studio_connection() is True

def test_check_lm_studio_connection_failure(code_scanner):
    with patch('aiscan.utils.llm_client.LLMClient.check_connection', return_value=False):
        assert code_scanner.check_lm_studio_connection() is False

def test_should_ignore(code_scanner):
    # Should ignore files matching ignore patterns
    assert code_scanner.should_ignore("path/to/node_modules/file.js") is True
    assert code_scanner.should_ignore("path/to/venv/file.py") is True
    
    # Should not ignore regular code files
    assert code_scanner.should_ignore("path/to/src/file.py") is False
    assert code_scanner.should_ignore("path/to/app.py") is False

def test_get_code_files(code_scanner, tmp_path):
    # Create test directory structure
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("def hello(): pass")
    (tmp_path / "src" / "utils.py").write_text("def helper(): pass")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text("function test() {}")
    
    # Test file collection
    files = code_scanner.get_code_files(str(tmp_path))
    
    # Should find Python files but ignore node_modules
    assert len(files) == 2
    file_paths = [str(f) for f in files]
    assert str(tmp_path / "src" / "app.py") in file_paths
    assert str(tmp_path / "src" / "utils.py") in file_paths
    assert str(tmp_path / "node_modules" / "lib.js") not in file_paths

def test_add_line_numbers(code_scanner):
    code = "def test():\n    return True"
    numbered = code_scanner.add_line_numbers(code)
    assert numbered == "   1 | def test():\n   2 |     return True"

def test_get_language_from_extension(code_scanner):
    assert code_scanner.get_language_from_extension(Path("test.py")) == "python"
    assert code_scanner.get_language_from_extension(Path("test.go")) == "go"
    assert code_scanner.get_language_from_extension(Path("test.rs")) == "rust"
    assert code_scanner.get_language_from_extension(Path("test.java")) == "java"
    assert code_scanner.get_language_from_extension(Path("test.cpp")) == "cpp"
    assert code_scanner.get_language_from_extension(Path("test.unknown")) == "python"  # Default

def test_extract_imports_python(code_scanner):
    code_lines = [
        "import os",
        "import sys as system",
        "from datetime import datetime",
        "from pathlib import Path, PurePath"
    ]
    imports, imported_functions = code_scanner.extract_imports(code_lines, "python")
    
    assert len(imports) == 4
    assert imports[0] == "import os"
    assert "datetime" in imported_functions
    assert imported_functions["datetime"] == "datetime"
    assert "Path" in imported_functions
    assert imported_functions["Path"] == "pathlib"

def test_match_functions_using_llm(code_scanner):
    # Create a mock response with the new schema
    mock_response = FunctionMatchResponse(
        matches=[
            FunctionMatch(
                target="target_func",
                confidence=95,
                criteria=["exact_name", "module_prefix"],
                context="Function name matches exactly"
            )
        ]
    )
    
    with patch('aiscan.utils.llm_client.LLMClient.call_llm', return_value=mock_response):
        result = code_scanner.match_functions_using_llm(
            "source_func", 
            ["target_func", "other_func"], 
            "Module: test\nFull path: test.py\nImports:\nimport os"
        )
        assert result == "target_func"

# ================================
# Function Extraction Tests
# ================================

def test_extract_functions(code_scanner):
    code = """
def function_one():
    print("Hello")
    return True

def function_two(param):
    # Call other function
    result = function_one()
    return result and param
"""
    
    # Mock the LLM response for function extraction
    extraction_result = FunctionExtractionResult(
        functions=[
            FunctionBoundary(
                name="function_one",
                start_line=2,
                end_line=4,
                is_entry_point=True,
                called_functions=[]
            ),
            FunctionBoundary(
                name="function_two",
                start_line=6,
                end_line=9,
                is_entry_point=False,
                called_functions=["function_one"]
            )
        ]
    )
    
    # Mock call analysis to return no calls for simplicity
    call_analysis = FunctionCallAnalysis(custom_calls=[])
    
    with patch('aiscan.utils.llm_client.LLMClient.call_llm', side_effect=[extraction_result, call_analysis, call_analysis]):
        file_path = Path("test.py")
        functions = code_scanner.extract_functions(file_path, code)
        
        assert len(functions) == 2
        assert functions[0].function.name == "function_one"
        assert functions[0].function.start_line == 2
        assert functions[0].function.end_line == 4
        assert functions[0].function.is_entry_point == True
        
        assert functions[1].function.name == "function_two"
        assert functions[1].function.start_line == 6
        assert functions[1].function.end_line == 9
        assert functions[1].function.is_entry_point == False

def test_extract_functions_error_handling(code_scanner):
    code = "def broken_function(): invalid syntax"
    
    # Mock LLM to raise exception for function extraction
    with patch('aiscan.utils.llm_client.LLMClient.call_llm', side_effect=Exception("Extraction error")):
        file_path = Path("test.py")
        functions = code_scanner.extract_functions(file_path, code)
        
        # Should return whole file as single function
        assert len(functions) == 1
        assert functions[0].function.name == "test.py (full file)"
        assert functions[0].function.start_line == 1
        assert functions[0].code == code

# ================================
# Function Call Analysis Tests
# ================================

def test_analyze_function_calls(code_scanner):
    function = FileFunction(
        function=CodeFunction(
            name="test_function",
            start_line=1,
            end_line=5,
            is_entry_point=True,
            module_name="test",
            full_module_path="test.py",
            imports=["import os", "from utils import helper"],
            imported_functions={"helper": "utils"},
            called_functions=[]
        ),
        file_path="test.py",
        code="def test_function():\n    result = helper()\n    return result"
    )
    
    # Mock the LLM response for call analysis
    call_analysis = FunctionCallAnalysis(
        custom_calls=[
            FunctionCall(
                name="helper",
                line=2,
                is_imported=True
            )
        ]
    )
    
    with patch('aiscan.utils.llm_client.LLMClient.call_llm', return_value=call_analysis):
        result = code_scanner.analyze_function_calls(function)
        
        assert len(result.custom_calls) == 1
        assert result.custom_calls[0].name == "helper"
        assert result.custom_calls[0].line == 2
        assert result.custom_calls[0].is_imported == True

# ================================
# Call Tree and Analysis Order Tests
# ================================

def test_build_call_tree(code_scanner):
    functions = [
        FileFunction(
            function=CodeFunction(
                name="main",
                start_line=1,
                end_line=5,
                is_entry_point=True,
                module_name="test",
                full_module_path="test.py",
                imports=[],
                imported_functions={},
                called_functions=["helper1", "helper2"],
                call_analysis=FunctionCallAnalysis(
                    custom_calls=[
                        FunctionCall(name="helper1", line=2, arguments="()", is_imported=False),
                        FunctionCall(name="helper2", line=3, arguments="()", is_imported=False)
                    ]
                )
            ),
            file_path="test.py",
            code=""
        ),
        FileFunction(
            function=CodeFunction(
                name="helper1",
                start_line=7,
                end_line=9,
                is_entry_point=False,
                module_name="test",
                full_module_path="test.py",
                imports=[],
                imported_functions={},
                called_functions=["helper3"],
                call_analysis=FunctionCallAnalysis(
                    custom_calls=[
                        FunctionCall(name="helper3", line=8, arguments="()", is_imported=False)
                    ]
                )
            ),
            file_path="test.py",
            code=""
        ),
        FileFunction(
            function=CodeFunction(
                name="helper2",
                start_line=11,
                end_line=13,
                is_entry_point=False,
                module_name="test",
                full_module_path="test.py",
                imports=[],
                imported_functions={},
                called_functions=[],
                call_analysis=FunctionCallAnalysis(custom_calls=[])
            ),
            file_path="test.py",
            code=""
        ),
        FileFunction(
            function=CodeFunction(
                name="helper3",
                start_line=15,
                end_line=17,
                is_entry_point=False,
                module_name="test",
                full_module_path="test.py",
                imports=[],
                imported_functions={},
                called_functions=[],
                call_analysis=FunctionCallAnalysis(custom_calls=[])
            ),
            file_path="test.py",
            code=""
        )
    ]
    
    call_tree = code_scanner.build_call_tree(functions)
    
    assert "main" in call_tree
    assert "helper1" in call_tree
    assert "helper2" in call_tree
    assert "helper3" in call_tree
    
    assert call_tree["main"] == ["helper1", "helper2"]
    assert call_tree["helper1"] == ["helper3"]
    assert call_tree["helper2"] == []
    assert call_tree["helper3"] == []

def test_get_analysis_order(code_scanner):
    call_tree = {
        "main": ["helper1", "helper2"],
        "helper1": ["helper3"],
        "helper2": [],
        "helper3": []
    }
    
    order = code_scanner.get_analysis_order(call_tree)
    
    # helper3 must come before helper1, helper1 and helper2 must come before main
    assert order.index("helper3") < order.index("helper1")
    assert order.index("helper1") < order.index("main")
    assert order.index("helper2") < order.index("main")

# ================================
# Function Analysis Tests
# ================================

@pytest.fixture
def mock_function():
    return FileFunction(
        function=CodeFunction(
            name="vulnerable_function",
            start_line=1,
            end_line=5,
            is_entry_point=True,
            module_name="test",
            full_module_path="test.py",
            imports=["import os", "import sqlite3"],
            imported_functions={},
            called_functions=[]
        ),
        file_path="test.py",
        code="def vulnerable_function(user_input):\n    query = f\"SELECT * FROM users WHERE id = {user_input}\"\n    return query"
    )

def test_analyze_function_only(code_scanner, mock_function):
    # Mock the LLM response for function analysis
    function_analysis = FunctionAnalysis(
        function_summary="This function constructs a SQL query using user input.",
        potential_vulnerabilities="SQL injection due to string interpolation.",
        logic_flaws="No input validation.",
        data_flow="User input flows directly into SQL query."
    )
    
    with patch('aiscan.utils.llm_client.LLMClient.call_llm', return_value=function_analysis):
        code_scanner.analyze_function_only(Path("test.py"), mock_function)
        
        # Verify the function analysis was stored correctly
        assert mock_function.function.name in code_scanner.function_analyses
        stored_analysis = code_scanner.function_analyses[mock_function.function.name]
        assert stored_analysis.function_summary == "This function constructs a SQL query using user input."
        assert "SQL injection" in stored_analysis.potential_vulnerabilities
        assert "No input validation" in stored_analysis.logic_flaws

def test_analyze_function(code_scanner, mock_function):
    # First, set up the function analysis in the cache
    code_scanner.function_analyses[mock_function.function.name] = FunctionAnalysis(
        function_summary="This function constructs a SQL query using user input.",
        potential_vulnerabilities="SQL injection due to string interpolation.",
        logic_flaws="No input validation.",
        data_flow="User input flows directly into SQL query."
    )
    
    # Mock the LLM response for security analysis
    security_analysis = SecurityAnalysis(
        findings=[
            SecurityFinding(
                title="SQL Injection Vulnerability",
                severity="High",
                description="Direct string interpolation in SQL query.",
                impact="An attacker could execute arbitrary SQL commands.",
                fix="Use parameterized queries.",
                line_number=2,
                code_snippet="query = f\"SELECT * FROM users WHERE id = {user_input}\""
            )
        ]
    )
    
    with patch('aiscan.utils.llm_client.LLMClient.call_llm', return_value=security_analysis):
        findings = code_scanner.analyze_function(Path("test.py"), mock_function)
        
        assert len(findings) == 1
        assert findings[0].title == "SQL Injection Vulnerability"
        assert findings[0].severity == "High"
        assert findings[0].function_name == "vulnerable_function"

# ================================
# End-to-End Analysis Tests
# ================================

def test_analyze_code_with_json_response(code_scanner, temp_test_file, expected_json_response):
    # Mock extract_functions to return a predefined list of functions
    mock_function = FileFunction(
        function=CodeFunction(
            name="process_user_input",
            start_line=2,
            end_line=5,
            is_entry_point=True,
            module_name="test_file",
            full_module_path="test_file.py",
            imports=[],
            imported_functions={},
            called_functions=[]
        ),
        file_path=str(temp_test_file),
        code="def process_user_input(user_input):\n    query = f\"SELECT * FROM users WHERE id = {user_input}\"\n    return query"
    )
    
    extraction_result = FunctionExtractionResult(
        functions=[
            FunctionBoundary(
                name="process_user_input",
                start_line=2,
                end_line=5,
                is_entry_point=True,
                called_functions=[]
            )
        ]
    )
    
    call_analysis = FunctionCallAnalysis(custom_calls=[])
    
    security_finding = SecurityFinding(
        title="SQL Injection Vulnerability",
        severity="High",
        description="Direct string interpolation in SQL query",
        impact="Potential SQL injection attack",
        fix="Use parameterized queries",
        line_number=3,
        code_snippet="query = f\"SELECT * FROM users WHERE id = {user_input}\""
    )
    
    security_analysis = SecurityAnalysis(findings=[security_finding])
    
    # Set up all the mocks
    with patch('aiscan.utils.llm_client.LLMClient.call_llm') as mock_llm:
        # Configure the mock to return different responses based on the calls
        mock_llm.side_effect = [
            extraction_result,  # For extract_functions
            call_analysis,      # For analyze_function_calls
            security_analysis   # For analyze_function security analysis
        ]
        
        # Analyze the code
        result = code_scanner.analyze_code(temp_test_file, [mock_function])
        
        # Verify the results
        assert "error" not in result
        assert result["file"] == str(temp_test_file)
        assert len(result["findings"]) == 1
        assert result["findings"][0]["title"] == "SQL Injection Vulnerability"
        assert result["findings"][0]["severity"] == "High"

def test_scan_directory_end_to_end(code_scanner, tmp_path):
    # Create test files
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    
    app_py = src_dir / "app.py"
    app_py.write_text("""
def main():
    user_input = get_user_input()
    result = process_input(user_input)
    return result

def get_user_input():
    return input("Enter ID: ")

def process_input(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query
""")
    
    # Mock all the necessary LLM responses
    extraction_result = FunctionExtractionResult(
        functions=[
            FunctionBoundary(
                name="main",
                start_line=2,
                end_line=5,
                is_entry_point=True,
                called_functions=["get_user_input", "process_input"]
            ),
            FunctionBoundary(
                name="get_user_input",
                start_line=7,
                end_line=8,
                is_entry_point=False,
                called_functions=[]
            ),
            FunctionBoundary(
                name="process_input",
                start_line=10,
                end_line=12,
                is_entry_point=False,
                called_functions=[]
            )
        ]
    )
    
    main_calls = FunctionCallAnalysis(
        custom_calls=[
            FunctionCall(name="get_user_input", line=3, arguments="()", is_imported=False),
            FunctionCall(name="process_input", line=4, arguments="(user_input)", is_imported=False)
        ]
    )
    
    get_input_calls = FunctionCallAnalysis(custom_calls=[])
    
    process_input_calls = FunctionCallAnalysis(custom_calls=[])
    
    function_analysis = FunctionAnalysis(
        function_summary="Test function",
        potential_vulnerabilities="None",
        logic_flaws="None",
        data_flow="User input is processed"
    )
    
    security_finding = SecurityFinding(
        title="SQL Injection Vulnerability",
        severity="High",
        description="Direct string interpolation in SQL query",
        impact="Potential SQL injection attack",
        fix="Use parameterized queries",
        line_number=11,
        code_snippet="query = f\"SELECT * FROM users WHERE id = {user_input}\""
    )
    
    security_analysis = SecurityAnalysis(findings=[security_finding])
    
    with patch('aiscan.utils.llm_client.LLMClient.check_connection', return_value=True), \
         patch('aiscan.utils.llm_client.LLMClient.call_llm') as mock_llm, \
         patch('aiscan.utils.display.display_results') as mock_display:
        
        # Configure mock to return different responses based on the call
        mock_llm.side_effect = [
            extraction_result,     # extract_functions
            main_calls,            # analyze_function_calls for main
            get_input_calls,       # analyze_function_calls for get_user_input
            process_input_calls,   # analyze_function_calls for process_input
            function_analysis,     # analyze_function_only for main
            function_analysis,     # analyze_function_only for get_user_input
            function_analysis,     # analyze_function_only for process_input
            security_analysis      # analyze_function for main (security analysis)
        ]
        
        # Run the scan
        code_scanner.scan_directory(str(tmp_path))
        
        # Verify display_results was called (the end of the scanning process)
        mock_display.assert_called_once()
        
        # Extract the results passed to display_results
        results = mock_display.call_args[0][0]
        
        # Verify we have findings
        assert len(results) > 0
        file_results = next((r for r in results if "file" in r and app_py.name in r["file"]), None)
        assert file_results is not None
        assert "findings" in file_results
        assert len(file_results["findings"]) > 0
        assert file_results["findings"][0]["title"] == "SQL Injection Vulnerability"

# ================================
# Original (slightly modified) Tests 
# ================================

def test_analyze_code_with_invalid_json(code_scanner, temp_test_file):
    with patch('aiscan.utils.llm_client.LLMClient.call_llm', side_effect=Exception("Failed to parse JSON")):
        # Mock extract_functions to return a simple function
        mock_function = FileFunction(
            function=CodeFunction(
                name="process_user_input",
                start_line=2,
                end_line=5,
                is_entry_point=True,
                module_name="test_file",
                full_module_path="test_file.py",
                imports=[],
                imported_functions={},
                called_functions=[]
            ),
            file_path=str(temp_test_file),
            code=""
        )
        
        # Analyze the code
        result = code_scanner.analyze_code(temp_test_file, [mock_function])
        
        # Verify error handling
        assert "error" in result
        assert result["file"] == str(temp_test_file)

def test_analyze_code_with_api_error(code_scanner, temp_test_file):
    with patch('aiscan.utils.llm_client.LLMClient.call_llm', side_effect=Exception("API request failed")):
        # Mock extract_functions to return a simple function
        mock_function = FileFunction(
            function=CodeFunction(
                name="process_user_input",
                start_line=2,
                end_line=5,
                is_entry_point=True,
                module_name="test_file",
                full_module_path="test_file.py",
                imports=[],
                imported_functions={},
                called_functions=[]
            ),
            file_path=str(temp_test_file),
            code=""
        )
        
        # Analyze the code
        result = code_scanner.analyze_code(temp_test_file, [mock_function])
        
        # Verify error handling
        assert "error" in result
        assert result["file"] == str(temp_test_file) 