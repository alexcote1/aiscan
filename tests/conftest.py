"""
Test configuration and shared fixtures
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from aiscan.scanner.scanner import CodeScanner  # Update import path

@pytest.fixture
def code_scanner():
    """Fixture to provide a CodeScanner instance for tests."""
    # Mock the LM Studio client initialization
    with patch('lmstudio.get_default_client') as mock_get_client, \
         patch('lmstudio.llm') as mock_llm:
        # Create a mock LLM model
        mock_model = MagicMock()
        mock_llm.return_value = mock_model
        
        # Initialize scanner with mocked components
        scanner = CodeScanner(verbose=False)
        
        # Initialize the all_functions list and function_analyses dict
        scanner.all_functions = []
        scanner.function_analyses = {}
        
        return scanner

@pytest.fixture
def sample_code():
    """Fixture to provide sample code for testing."""
    return """
def process_user_input(user_input):
    # This is a sample function with security issues
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query
"""

@pytest.fixture
def multi_function_code():
    """Fixture to provide sample code with multiple functions."""
    return """
def main():
    user_input = get_user_input()
    result = process_input(user_input)
    return result

def get_user_input():
    return input("Enter ID: ")

def process_input(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query
"""

@pytest.fixture
def expected_json_response():
    """Fixture to provide expected JSON response for testing."""
    return {
        "findings": [
            {
                "title": "SQL Injection Vulnerability",
                "severity": "High",
                "description": "Direct string interpolation in SQL query",
                "impact": "Potential SQL injection attack",
                "fix": "Use parameterized queries"
            }
        ]
    }

@pytest.fixture
def temp_test_file(tmp_path, sample_code):
    """Fixture to provide a temporary test file."""
    test_file = tmp_path / "test_file.py"
    test_file.write_text(sample_code)
    return test_file

@pytest.fixture
def temp_multi_function_file(tmp_path, multi_function_code):
    """Fixture to provide a temporary test file with multiple functions."""
    test_file = tmp_path / "test_multi_func.py"
    test_file.write_text(multi_function_code)
    return test_file

@pytest.fixture
def temp_test_directory(tmp_path, sample_code, multi_function_code):
    """Fixture to provide a temporary test directory with multiple files."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    
    # Create a file with a single vulnerable function
    (src_dir / "single_func.py").write_text(sample_code)
    
    # Create a file with multiple functions
    (src_dir / "multi_func.py").write_text(multi_function_code)
    
    # Create a file without vulnerabilities
    (src_dir / "safe.py").write_text("""
def safe_function(user_input):
    # This is a secure function
    import sqlite3
    cursor = sqlite3.Cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
    return cursor.fetchall()
""")
    
    return tmp_path 