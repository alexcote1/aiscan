#!/usr/bin/env python3
"""
Tests for the Code Security Scanner
"""

import json
import pytest
from unittest.mock import patch, MagicMock

def test_analyze_code_with_json_response(code_scanner, temp_test_file, expected_json_response):
    with patch('requests.post') as mock_post:
        # Mock the API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": json.dumps(expected_json_response)
                }
            }]
        }
        mock_post.return_value = mock_response

        # Analyze the code
        result = code_scanner.analyze_code(temp_test_file)

        # Verify the results
        assert "error" not in result
        assert result["file"] == str(temp_test_file)
        assert len(result["findings"]) == 1
        assert result["findings"][0]["title"] == "SQL Injection Vulnerability"
        assert result["findings"][0]["severity"] == "High"

        # Verify the API call
        mock_post.assert_called_once()
        call_args = mock_post.call_args[1]["json"]
        assert "messages" in call_args
        assert "temperature" in call_args
        assert "max_tokens" in call_args

def test_analyze_code_with_invalid_json(code_scanner, temp_test_file):
    with patch('requests.post') as mock_post:
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

        # Analyze the code
        result = code_scanner.analyze_code(temp_test_file)

        # Verify error handling
        assert "error" in result
        assert result["file"] == str(temp_test_file)
        assert result["error"] == "Failed to parse JSON response from LM Studio"

def test_analyze_code_with_api_error(code_scanner, temp_test_file):
    with patch('requests.post') as mock_post:
        # Mock the API response with an error
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        # Analyze the code
        result = code_scanner.analyze_code(temp_test_file)

        # Verify error handling
        assert "error" in result
        assert result["file"] == str(temp_test_file)
        assert result["error"] == "API request failed with status code 500" 