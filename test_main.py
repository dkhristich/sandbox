#!/usr/bin/env python3
"""
Tests for the GitHub Actions workflow runs exporter.
"""

import pytest
import sys
import os
import csv
import tempfile
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta, timezone
import requests

# Add the parent directory to the path so we can import main
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main


class TestExtractWorkflowDetails:
    """Tests for extract_workflow_details function."""
    
    def test_extract_workflow_details_basic(self):
        """Test extracting details from a basic workflow run."""
        runs = [
            {
                "name": "CI",
                "workflow_id": 123,
                "id": 456,
                "run_number": 1,
                "status": "completed",
                "conclusion": "success",
                "created_at": "2024-01-15T10:00:00Z",
                "updated_at": "2024-01-15T10:05:00Z",
                "run_started_at": "2024-01-15T10:01:00Z",
                "actor": {"login": "testuser"},
                "head_branch": "main",
                "head_sha": "abcdef1234567890",
                "head_commit": {"message": "Test commit"},
                "event": "push",
                "html_url": "https://github.com/owner/repo/actions/runs/456"
            }
        ]
        
        details = main.extract_workflow_details(runs)
        
        assert len(details) == 1
        assert details[0]["workflow_name"] == "CI"
        assert details[0]["workflow_id"] == 123
        assert details[0]["run_id"] == 456
        assert details[0]["run_number"] == 1
        assert details[0]["status"] == "completed"
        assert details[0]["conclusion"] == "success"
        assert details[0]["actor"] == "testuser"
        assert details[0]["branch"] == "main"
        assert details[0]["commit_sha"] == "abcdef12"
        assert details[0]["commit_message"] == "Test commit"
        assert details[0]["event"] == "push"
    
    def test_extract_workflow_details_missing_fields(self):
        """Test extracting details when some fields are missing."""
        runs = [
            {
                "name": "CI",
                "id": 456,
                "status": "in_progress",
                # Missing many fields
            }
        ]
        
        details = main.extract_workflow_details(runs)
        
        assert len(details) == 1
        assert details[0]["workflow_name"] == "CI"
        assert details[0]["workflow_id"] == "N/A"
        assert details[0]["conclusion"] == "N/A"
        assert details[0]["actor"] == "N/A"
        assert details[0]["branch"] == "N/A"
        assert details[0]["commit_sha"] == "N/A"
        assert details[0]["commit_message"] == "N/A"
    
    def test_extract_workflow_details_multiline_commit_message(self):
        """Test that multiline commit messages are truncated to first line."""
        runs = [
            {
                "name": "CI",
                "id": 456,
                "head_commit": {"message": "First line\nSecond line\nThird line"},
            }
        ]
        
        details = main.extract_workflow_details(runs)
        
        assert details[0]["commit_message"] == "First line"
    
    def test_extract_workflow_details_no_actor(self):
        """Test handling when actor is None."""
        runs = [
            {
                "name": "CI",
                "id": 456,
                "actor": None,
            }
        ]
        
        details = main.extract_workflow_details(runs)
        
        assert details[0]["actor"] == "N/A"
    
    def test_extract_workflow_details_empty_list(self):
        """Test extracting details from an empty list."""
        details = main.extract_workflow_details([])
        
        assert details == []


class TestSaveToCSV:
    """Tests for save_to_csv function."""
    
    def test_save_to_csv_basic(self):
        """Test saving details to CSV file."""
        details = [
            {
                "workflow_name": "CI",
                "workflow_id": 123,
                "run_id": 456,
                "run_number": 1,
                "status": "completed",
                "conclusion": "success",
                "created_at": "2024-01-15T10:00:00Z",
                "updated_at": "2024-01-15T10:05:00Z",
                "run_started_at": "2024-01-15T10:01:00Z",
                "actor": "testuser",
                "branch": "main",
                "commit_sha": "abcdef12",
                "commit_message": "Test commit",
                "event": "push",
                "workflow_url": "https://github.com/owner/repo/actions/runs/456"
            }
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            filename = f.name
        
        try:
            main.save_to_csv(details, filename)
            
            # Verify file was created and has correct content
            assert os.path.exists(filename)
            
            with open(filename, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                
                assert len(rows) == 1
                assert rows[0]["workflow_name"] == "CI"
                assert rows[0]["run_id"] == "456"
                assert rows[0]["status"] == "completed"
        finally:
            os.unlink(filename)
    
    def test_save_to_csv_empty_list(self, capsys):
        """Test saving empty list (should print message and not create file)."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            filename = f.name
        
        try:
            main.save_to_csv([], filename)
            
            captured = capsys.readouterr()
            assert "No workflow runs to save" in captured.out
            
            # File should not exist or be empty
            if os.path.exists(filename):
                assert os.path.getsize(filename) == 0
        finally:
            if os.path.exists(filename):
                os.unlink(filename)
    
    def test_save_to_csv_multiple_rows(self):
        """Test saving multiple workflow runs to CSV."""
        details = [
            {
                "workflow_name": "CI",
                "workflow_id": 123,
                "run_id": 456,
                "run_number": 1,
                "status": "completed",
                "conclusion": "success",
                "created_at": "2024-01-15T10:00:00Z",
                "updated_at": "2024-01-15T10:05:00Z",
                "run_started_at": "2024-01-15T10:01:00Z",
                "actor": "testuser",
                "branch": "main",
                "commit_sha": "abcdef12",
                "commit_message": "Test commit",
                "event": "push",
                "workflow_url": "https://github.com/owner/repo/actions/runs/456"
            },
            {
                "workflow_name": "Deploy",
                "workflow_id": 124,
                "run_id": 457,
                "run_number": 2,
                "status": "completed",
                "conclusion": "failure",
                "created_at": "2024-01-16T10:00:00Z",
                "updated_at": "2024-01-16T10:05:00Z",
                "run_started_at": "2024-01-16T10:01:00Z",
                "actor": "anotheruser",
                "branch": "develop",
                "commit_sha": "fedcba98",
                "commit_message": "Another commit",
                "event": "pull_request",
                "workflow_url": "https://github.com/owner/repo/actions/runs/457"
            }
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            filename = f.name
        
        try:
            main.save_to_csv(details, filename)
            
            with open(filename, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                
                assert len(rows) == 2
                assert rows[0]["workflow_name"] == "CI"
                assert rows[1]["workflow_name"] == "Deploy"
        finally:
            os.unlink(filename)


class TestGetWorkflowRuns:
    """Tests for get_workflow_runs function."""
    
    @patch('main.requests.get')
    def test_get_workflow_runs_single_page(self, mock_get):
        """Test fetching workflow runs from a single page."""
        # Mock response
        mock_response = Mock()
        mock_response.json.return_value = {
            "workflow_runs": [
                {
                    "name": "CI",
                    "id": 456,
                    "created_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat().replace("+00:00", "Z"),
                    "status": "completed",
                }
            ]
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        runs = main.get_workflow_runs("owner", "repo", "token", days=14)
        
        assert len(runs) == 1
        assert runs[0]["name"] == "CI"
        mock_get.assert_called_once()
    
    @patch('main.requests.get')
    def test_get_workflow_runs_pagination(self, mock_get):
        """Test fetching workflow runs across multiple pages."""
        now = datetime.now(timezone.utc)
        
        # First page response
        mock_response_page1 = Mock()
        mock_response_page1.json.return_value = {
            "workflow_runs": [
                {
                    "name": "CI",
                    "id": i,
                    "created_at": (now - timedelta(days=i)).isoformat().replace("+00:00", "Z"),
                    "status": "completed",
                }
                for i in range(1, 6)  # 5 runs
            ]
        }
        mock_response_page1.raise_for_status = Mock()
        
        # Second page response (empty)
        mock_response_page2 = Mock()
        mock_response_page2.json.return_value = {
            "workflow_runs": []
        }
        mock_response_page2.raise_for_status = Mock()
        
        mock_get.side_effect = [mock_response_page1, mock_response_page2]
        
        runs = main.get_workflow_runs("owner", "repo", "token", days=14, per_page=5)
        
        assert len(runs) == 5
        assert mock_get.call_count == 2
    
    @patch('main.requests.get')
    def test_get_workflow_runs_date_filtering(self, mock_get):
        """Test that runs outside the date range are filtered out."""
        now = datetime.now(timezone.utc)
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "workflow_runs": [
                {
                    "name": "CI",
                    "id": 1,
                    "created_at": (now - timedelta(days=5)).isoformat().replace("+00:00", "Z"),  # Within range
                    "status": "completed",
                },
                {
                    "name": "Deploy",
                    "id": 2,
                    "created_at": (now - timedelta(days=20)).isoformat().replace("+00:00", "Z"),  # Outside range
                    "status": "completed",
                }
            ]
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        runs = main.get_workflow_runs("owner", "repo", "token", days=14)
        
        # Only the run within the date range should be included
        assert len(runs) == 1
        assert runs[0]["id"] == 1
    
    @patch('main.requests.get')
    def test_get_workflow_runs_api_error(self, mock_get):
        """Test handling of API errors."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found")
        mock_response.text = "Not Found"
        mock_get.return_value = mock_response
        
        with pytest.raises(SystemExit):
            main.get_workflow_runs("owner", "repo", "token", days=14)
    
    @patch('main.requests.get')
    def test_get_workflow_runs_correct_url_and_headers(self, mock_get):
        """Test that the correct URL and headers are used."""
        mock_response = Mock()
        mock_response.json.return_value = {"workflow_runs": []}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        main.get_workflow_runs("testowner", "testrepo", "testtoken", days=7)
        
        # Verify URL
        assert "testowner" in mock_get.call_args[0][0]
        assert "testrepo" in mock_get.call_args[0][0]
        
        # Verify headers
        headers = mock_get.call_args[1]["headers"]
        assert headers["Authorization"] == "token testtoken"
        assert headers["Accept"] == "application/vnd.github.v3+json"


class TestMain:
    """Tests for main function."""
    
    @patch('main.get_workflow_runs')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_success(self, mock_save, mock_extract, mock_get_runs):
        """Test successful execution of main function."""
        mock_get_runs.return_value = [{"id": 1, "name": "CI"}]
        mock_extract.return_value = [{"workflow_name": "CI"}]
        
        test_args = [
            "--owner", "testowner",
            "--repo", "testrepo",
            "--token", "testtoken"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            main.main()
        
        mock_get_runs.assert_called_once_with("testowner", "testrepo", "testtoken", 14)
        mock_extract.assert_called_once()
        mock_save.assert_called_once()
    
    @patch('main.get_workflow_runs')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_custom_days_and_output(self, mock_save, mock_extract, mock_get_runs):
        """Test main with custom days and output filename."""
        mock_get_runs.return_value = []
        mock_extract.return_value = []
        
        test_args = [
            "--owner", "testowner",
            "--repo", "testrepo",
            "--token", "testtoken",
            "--days", "7",
            "--output", "custom.csv"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            main.main()
        
        mock_get_runs.assert_called_once_with("testowner", "testrepo", "testtoken", 7)
        mock_save.assert_called_once_with([], "custom.csv")
    
    def test_main_missing_owner(self, capsys):
        """Test main with missing owner argument."""
        test_args = [
            "--repo", "testrepo",
            "--token", "testtoken"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            with pytest.raises(SystemExit):
                main.main()
        
        captured = capsys.readouterr()
        assert "Repository owner is required" in captured.err
    
    def test_main_missing_repo(self, capsys):
        """Test main with missing repo argument."""
        test_args = [
            "--owner", "testowner",
            "--token", "testtoken"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            with pytest.raises(SystemExit):
                main.main()
        
        captured = capsys.readouterr()
        assert "Repository name is required" in captured.err
    
    def test_main_missing_token(self, capsys):
        """Test main with missing token argument."""
        test_args = [
            "--owner", "testowner",
            "--repo", "testrepo"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            with pytest.raises(SystemExit):
                main.main()
        
        captured = capsys.readouterr()
        assert "GitHub token is required" in captured.err
    
    @patch.dict(os.environ, {
        'GITHUB_OWNER': 'envowner',
        'GITHUB_REPO': 'envrepo',
        'GITHUB_TOKEN': 'envtoken'
    })
    @patch('main.get_workflow_runs')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_environment_variables(self, mock_save, mock_extract, mock_get_runs):
        """Test main using environment variables."""
        mock_get_runs.return_value = []
        mock_extract.return_value = []
        
        with patch.object(sys, 'argv', ['main.py']):
            main.main()
        
        mock_get_runs.assert_called_once_with("envowner", "envrepo", "envtoken", 14)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

