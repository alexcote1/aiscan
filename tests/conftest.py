"""
Test configuration and shared fixtures
"""

import pytest
from pathlib import Path
from aiscan.scanner.code_scanner import CodeScanner

@pytest.fixture
def code_scanner():
    """Fixture to provide a CodeScanner instance for tests."""
    return CodeScanner()

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