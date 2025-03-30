#!/usr/bin/env python3
"""
Tests for the Code Security Scanner
"""

import unittest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from code_scanner import CodeScanner

class TestCodeScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = CodeScanner()
        self.sample_code = """
def process_user_input(user_input):
    # This is a sample function with security issues
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query
"""
        self.expected_json_response = {
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

    @patch('requests.post')
    def test_analyze_code_with_json_response(self, mock_post):
        # Mock the API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": json.dumps(self.expected_json_response)
                }
            }]
        }
        mock_post.return_value = mock_response

        # Create a temporary test file
        test_file = Path("test_file.py")
        test_file.write_text(self.sample_code)

        try:
            # Analyze the code
            result = self.scanner.analyze_code(test_file)

            # Verify the results
            self.assertNotIn("error", result)
            self.assertEqual(result["file"], str(test_file))
            self.assertEqual(len(result["findings"]), 1)
            self.assertEqual(result["findings"][0]["title"], "SQL Injection Vulnerability")
            self.assertEqual(result["findings"][0]["severity"], "High")

            # Verify the API call
            mock_post.assert_called_once()
            call_args = mock_post.call_args[1]["json"]
            self.assertIn("messages", call_args)
            self.assertIn("temperature", call_args)
            self.assertIn("max_tokens", call_args)

        finally:
            # Clean up
            test_file.unlink()

    @patch('requests.post')
    def test_analyze_code_with_invalid_json(self, mock_post):
        # Mock the API response with invalid JSON
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": "Invalid JSON response"
                }
            }]
        }
        mock_post.return_value = mock_response

        # Create a temporary test file
        test_file = Path("test_file.py")
        test_file.write_text(self.sample_code)

        try:
            # Analyze the code
            result = self.scanner.analyze_code(test_file)

            # Verify error handling
            self.assertIn("error", result)
            self.assertEqual(result["file"], str(test_file))
            self.assertEqual(result["error"], "Failed to parse JSON response from LM Studio")

        finally:
            # Clean up
            test_file.unlink()

    @patch('requests.post')
    def test_analyze_code_with_api_error(self, mock_post):
        # Mock the API response with an error
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        # Create a temporary test file
        test_file = Path("test_file.py")
        test_file.write_text(self.sample_code)

        try:
            # Analyze the code
            result = self.scanner.analyze_code(test_file)

            # Verify error handling
            self.assertIn("error", result)
            self.assertEqual(result["file"], str(test_file))
            self.assertEqual(result["error"], "API request failed with status code 500")

        finally:
            # Clean up
            test_file.unlink()

if __name__ == '__main__':
    unittest.main() 