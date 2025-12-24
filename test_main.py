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
                "path": ".github/workflows/ci.yml",
                "status": "completed",
                "conclusion": "success",
                "run_started_at": "2024-01-15T10:01:00Z",
                "head_branch": "main",
                "head_sha": "abcdef1234567890",
                "event": "push",
                "html_url": "https://github.com/owner/repo/actions/runs/456"
            }
        ]
        
        details = main.extract_workflow_details(runs)
        
        assert len(details) == 1
        assert details[0]["workflow_name"] == "CI"
        assert details[0]["workflow_file"] == ".github/workflows/ci.yml"
        assert details[0]["workflow_url"] == "https://github.com/owner/repo/actions/runs/456"
        assert details[0]["status"] == "completed"
        assert details[0]["conclusion"] == "success"
        assert details[0]["run_started_at"] == "2024-01-15T10:01:00Z"
        assert details[0]["branch"] == "main"
        assert details[0]["commit_sha"] == "abcdef12"
        assert details[0]["event"] == "push"
    
    def test_extract_workflow_details_missing_fields(self):
        """Test extracting details when some fields are missing."""
        runs = [
            {
                "name": "CI",
                "status": "in_progress",
                # Missing many fields
            }
        ]
        
        details = main.extract_workflow_details(runs)
        
        assert len(details) == 1
        assert details[0]["workflow_name"] == "CI"
        assert details[0]["workflow_file"] == "N/A"
        assert details[0]["workflow_url"] == "N/A"
        assert details[0]["status"] == "in_progress"
        assert details[0]["conclusion"] == "N/A"
        assert details[0]["run_started_at"] == "N/A"
        assert details[0]["branch"] == "N/A"
        assert details[0]["commit_sha"] == "N/A"
        assert details[0]["event"] == "N/A"
    
    def test_extract_workflow_details_workflow_file(self):
        """Test extracting workflow file path."""
        runs = [
            {
                "name": "CI",
                "path": ".github/workflows/test.yml",
                "status": "completed",
            }
        ]
        
        details = main.extract_workflow_details(runs)
        
        assert details[0]["workflow_file"] == ".github/workflows/test.yml"
    
    def test_extract_workflow_details_missing_workflow_file(self):
        """Test handling when workflow file path is missing."""
        runs = [
            {
                "name": "CI",
                "status": "completed",
                # No path field
            }
        ]
        
        details = main.extract_workflow_details(runs)
        
        assert details[0]["workflow_file"] == "N/A"
    
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
                "workflow_file": ".github/workflows/ci.yml",
                "workflow_url": "https://github.com/owner/repo/actions/runs/456",
                "status": "completed",
                "conclusion": "success",
                "run_started_at": "2024-01-15T10:01:00Z",
                "branch": "main",
                "commit_sha": "abcdef12",
                "event": "push"
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
                assert rows[0]["workflow_file"] == ".github/workflows/ci.yml"
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
                "workflow_file": ".github/workflows/ci.yml",
                "workflow_url": "https://github.com/owner/repo/actions/runs/456",
                "status": "completed",
                "conclusion": "success",
                "run_started_at": "2024-01-15T10:01:00Z",
                "branch": "main",
                "commit_sha": "abcdef12",
                "event": "push"
            },
            {
                "workflow_name": "Deploy",
                "workflow_file": ".github/workflows/deploy.yml",
                "workflow_url": "https://github.com/owner/repo/actions/runs/457",
                "status": "completed",
                "conclusion": "failure",
                "run_started_at": "2024-01-16T10:01:00Z",
                "branch": "develop",
                "commit_sha": "fedcba98",
                "event": "pull_request"
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
        mock_response.status_code = 200
        mock_response.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4999",
            "X-RateLimit-Reset": str(int(datetime.now(timezone.utc).timestamp()) + 3600)
        }
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
        mock_response_page1.status_code = 200
        mock_response_page1.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4998",
            "X-RateLimit-Reset": str(int(datetime.now(timezone.utc).timestamp()) + 3600)
        }
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
        mock_response_page2.status_code = 200
        mock_response_page2.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4997",
            "X-RateLimit-Reset": str(int(datetime.now(timezone.utc).timestamp()) + 3600)
        }
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
        mock_response.status_code = 200
        mock_response.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4999",
            "X-RateLimit-Reset": str(int(datetime.now(timezone.utc).timestamp()) + 3600)
        }
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
        mock_response.status_code = 404
        mock_response.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4999",
            "X-RateLimit-Reset": str(int(datetime.now(timezone.utc).timestamp()) + 3600)
        }
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found", response=mock_response)
        mock_response.text = "Not Found"
        mock_get.return_value = mock_response
        
        with pytest.raises(SystemExit):
            main.get_workflow_runs("owner", "repo", "token", days=14)
    
    @patch('main.requests.get')
    def test_get_workflow_runs_correct_url_and_headers(self, mock_get):
        """Test that the correct URL and headers are used."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4999",
            "X-RateLimit-Reset": str(int(datetime.now(timezone.utc).timestamp()) + 3600)
        }
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
        
        # Verify SSL verification is enabled by default
        assert mock_get.call_args[1]["verify"] is True
    
    @patch('main.requests.get')
    def test_get_workflow_runs_verify_ssl_false(self, mock_get):
        """Test that verify_ssl=False is passed to requests."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4999",
            "X-RateLimit-Reset": str(int(datetime.now(timezone.utc).timestamp()) + 3600)
        }
        mock_response.json.return_value = {"workflow_runs": []}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        main.get_workflow_runs("testowner", "testrepo", "testtoken", days=7, verify_ssl=False)
        
        assert mock_get.call_args[1]["verify"] is False
    
    @patch('main.requests.get')
    def test_get_workflow_runs_verify_ssl_ca_bundle(self, mock_get):
        """Test that verify_ssl with CA bundle path is passed to requests."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4999",
            "X-RateLimit-Reset": str(int(datetime.now(timezone.utc).timestamp()) + 3600)
        }
        mock_response.json.return_value = {"workflow_runs": []}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        ca_bundle_path = "/path/to/ca-bundle.crt"
        main.get_workflow_runs("testowner", "testrepo", "testtoken", days=7, verify_ssl=ca_bundle_path)
        
        assert mock_get.call_args[1]["verify"] == ca_bundle_path
    
    @patch('main.requests.get')
    def test_get_workflow_runs_ssl_error(self, mock_get, capsys):
        """Test handling of SSL errors with helpful error message."""
        mock_get.side_effect = requests.exceptions.SSLError("certificate verify failed")
        
        with pytest.raises(SystemExit) as exc_info:
            main.get_workflow_runs("owner", "repo", "token", days=14)
        
        # The function should exit with code 1
        assert exc_info.value.code == 1
        
        # Check that helpful error message is printed
        captured = capsys.readouterr()
        assert "SSL Error" in captured.err
        assert "--no-ssl-verify" in captured.err or "--ca-bundle" in captured.err
    
    @patch('main.requests.get')
    @patch('main.time.sleep')
    def test_get_workflow_runs_rate_limit_handling(self, mock_sleep, mock_get):
        """Test that rate limit errors are handled with retry."""
        now = datetime.now(timezone.utc)
        reset_time = int((now + timedelta(seconds=5)).timestamp())
        
        # First call: rate limit error (403)
        mock_response_403 = Mock()
        mock_response_403.status_code = 403
        mock_response_403.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(reset_time)
        }
        
        # Second call: success after waiting
        mock_response_success = Mock()
        mock_response_success.status_code = 200
        mock_response_success.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4999",
            "X-RateLimit-Reset": str(reset_time)
        }
        mock_response_success.json.return_value = {"workflow_runs": []}
        mock_response_success.raise_for_status = Mock()
        
        mock_get.side_effect = [mock_response_403, mock_response_success]
        
        runs = main.get_workflow_runs("owner", "repo", "token", days=14)
        
        # Should have retried and succeeded
        assert len(runs) == 0
        # Should have called sleep to wait for rate limit reset
        assert mock_sleep.called


class TestRateLimitHandling:
    """Tests for rate limit handling functions."""
    
    def test_check_rate_limit_normal(self, capsys):
        """Test rate limit checking with normal remaining requests."""
        mock_response = Mock()
        mock_response.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4500",
            "X-RateLimit-Reset": str(int(datetime.now(timezone.utc).timestamp()) + 3600)
        }
        
        main.check_rate_limit(mock_response)
        
        captured = capsys.readouterr()
        # Should not print warning for normal usage
        assert "Rate limit warning" not in captured.err
    
    def test_check_rate_limit_low(self, capsys):
        """Test rate limit checking when remaining is low."""
        mock_response = Mock()
        mock_response.headers = {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "500",  # 10%
            "X-RateLimit-Reset": str(int(datetime.now(timezone.utc).timestamp()) + 3600)
        }
        
        main.check_rate_limit(mock_response)
        
        captured = capsys.readouterr()
        assert "Rate limit warning" in captured.err
    
    def test_handle_rate_limit_error_with_reset_time(self):
        """Test handling rate limit error with reset time."""
        reset_timestamp = int(datetime.now(timezone.utc).timestamp()) + 10
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.headers = {
            "X-RateLimit-Reset": str(reset_timestamp)
        }
        
        with patch('main.time.sleep') as mock_sleep:
            result = main.handle_rate_limit_error(mock_response)
        
        assert result is True
        # Should have slept
        assert mock_sleep.called
    
    def test_handle_rate_limit_error_no_reset_time(self):
        """Test handling rate limit error without reset time."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.headers = {}
        
        with patch('main.time.sleep') as mock_sleep:
            result = main.handle_rate_limit_error(mock_response)
        
        assert result is True
        # Should have slept for default 60 seconds
        mock_sleep.assert_called_with(60)
    
    def test_handle_rate_limit_error_not_403(self):
        """Test that non-403 errors return False."""
        mock_response = Mock()
        mock_response.status_code = 404
        
        result = main.handle_rate_limit_error(mock_response)
        
        assert result is False


class TestFilterLatestRunsPerWorkflow:
    """Tests for filter_latest_runs_per_workflow function."""
    
    def test_filter_latest_runs_single_workflow(self):
        """Test filtering when there are multiple runs of the same workflow."""
        now = datetime.now(timezone.utc)
        runs = [
            {
                "workflow_id": 123,
                "name": "CI",
                "id": 1,
                "created_at": (now - timedelta(days=5)).isoformat().replace("+00:00", "Z"),
            },
            {
                "workflow_id": 123,
                "name": "CI",
                "id": 2,
                "created_at": (now - timedelta(days=2)).isoformat().replace("+00:00", "Z"),
            },
            {
                "workflow_id": 123,
                "name": "CI",
                "id": 3,
                "created_at": (now - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            }
        ]
        
        filtered = main.filter_latest_runs_per_workflow(runs)
        
        assert len(filtered) == 1
        assert filtered[0]["id"] == 3  # Most recent run
    
    def test_filter_latest_runs_multiple_workflows(self):
        """Test filtering with multiple different workflows."""
        now = datetime.now(timezone.utc)
        runs = [
            {
                "workflow_id": 123,
                "name": "CI",
                "id": 1,
                "created_at": (now - timedelta(days=5)).isoformat().replace("+00:00", "Z"),
            },
            {
                "workflow_id": 123,
                "name": "CI",
                "id": 2,
                "created_at": (now - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            },
            {
                "workflow_id": 456,
                "name": "Deploy",
                "id": 3,
                "created_at": (now - timedelta(days=3)).isoformat().replace("+00:00", "Z"),
            },
            {
                "workflow_id": 456,
                "name": "Deploy",
                "id": 4,
                "created_at": (now - timedelta(days=2)).isoformat().replace("+00:00", "Z"),
            }
        ]
        
        filtered = main.filter_latest_runs_per_workflow(runs)
        
        assert len(filtered) == 2
        # Should have one run for each workflow_id
        workflow_ids = {run["workflow_id"] for run in filtered}
        assert workflow_ids == {123, 456}
        # Verify it's the latest run for each
        for run in filtered:
            if run["workflow_id"] == 123:
                assert run["id"] == 2
            elif run["workflow_id"] == 456:
                assert run["id"] == 4
    
    def test_filter_latest_runs_empty_list(self):
        """Test filtering an empty list."""
        filtered = main.filter_latest_runs_per_workflow([])
        assert filtered == []
    
    def test_filter_latest_runs_single_run(self):
        """Test filtering when there's only one run."""
        now = datetime.now(timezone.utc)
        runs = [
            {
                "workflow_id": 123,
                "name": "CI",
                "id": 1,
                "created_at": (now - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            }
        ]
        
        filtered = main.filter_latest_runs_per_workflow(runs)
        
        assert len(filtered) == 1
        assert filtered[0]["id"] == 1
    
    def test_filter_latest_runs_missing_workflow_id(self):
        """Test that runs without workflow_id are skipped."""
        now = datetime.now(timezone.utc)
        runs = [
            {
                "workflow_id": 123,
                "name": "CI",
                "id": 1,
                "created_at": (now - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            },
            {
                # Missing workflow_id
                "name": "CI",
                "id": 2,
                "created_at": (now - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            }
        ]
        
        filtered = main.filter_latest_runs_per_workflow(runs)
        
        # Should only include the run with workflow_id
        assert len(filtered) == 1
        assert filtered[0]["id"] == 1
    
    def test_filter_latest_runs_missing_created_at(self):
        """Test that runs without created_at are skipped."""
        runs = [
            {
                "workflow_id": 123,
                "name": "CI",
                "id": 1,
                "created_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            },
            {
                "workflow_id": 456,
                "name": "Deploy",
                "id": 2,
                # Missing created_at
            }
        ]
        
        filtered = main.filter_latest_runs_per_workflow(runs)
        
        # Should only include the run with created_at
        assert len(filtered) == 1
        assert filtered[0]["id"] == 1


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
        
        mock_get_runs.assert_called_once_with("testowner", "testrepo", "testtoken", 14, verify_ssl=True)
        mock_extract.assert_called_once()
        # Default output goes to ./output directory
        expected_path = os.path.join("./output", "testowner_testrepo_runs.csv")
        mock_save.assert_called_once_with([{"workflow_name": "CI"}], expected_path)
    
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
        
        mock_get_runs.assert_called_once_with("testowner", "testrepo", "testtoken", 7, verify_ssl=True)
        # Custom filename goes to default output directory
        expected_path = os.path.join("./output", "custom.csv")
        mock_save.assert_called_once_with([], expected_path)
    
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
        
        mock_get_runs.assert_called_once_with("envowner", "envrepo", "envtoken", 14, verify_ssl=True)
        # Default output goes to ./output directory
        expected_path = os.path.join("./output", "envowner_envrepo_runs.csv")
        mock_save.assert_called_once_with([], expected_path)
    
    @patch('main.get_workflow_runs')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_no_ssl_verify(self, mock_save, mock_extract, mock_get_runs):
        """Test main with --no-ssl-verify flag."""
        mock_get_runs.return_value = []
        mock_extract.return_value = []
        
        test_args = [
            "--owner", "testowner",
            "--repo", "testrepo",
            "--token", "testtoken",
            "--no-ssl-verify"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            main.main()
        
        mock_get_runs.assert_called_once_with("testowner", "testrepo", "testtoken", 14, verify_ssl=False)
    
    @patch('main.get_workflow_runs')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_ca_bundle(self, mock_save, mock_extract, mock_get_runs):
        """Test main with --ca-bundle flag."""
        mock_get_runs.return_value = []
        mock_extract.return_value = []
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.crt') as f:
            ca_bundle_path = f.name
            f.write("fake CA certificate")
        
        try:
            test_args = [
                "--owner", "testowner",
                "--repo", "testrepo",
                "--token", "testtoken",
                "--ca-bundle", ca_bundle_path
            ]
            
            with patch.object(sys, 'argv', ['main.py'] + test_args):
                main.main()
            
            mock_get_runs.assert_called_once_with("testowner", "testrepo", "testtoken", 14, verify_ssl=ca_bundle_path)
        finally:
            if os.path.exists(ca_bundle_path):
                os.unlink(ca_bundle_path)
    
    def test_main_both_ssl_options_error(self, capsys):
        """Test that using both --no-ssl-verify and --ca-bundle causes an error."""
        test_args = [
            "--owner", "testowner",
            "--repo", "testrepo",
            "--token", "testtoken",
            "--no-ssl-verify",
            "--ca-bundle", "/path/to/ca.crt"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            with pytest.raises(SystemExit):
                main.main()
        
        captured = capsys.readouterr()
        assert "Cannot use both --no-ssl-verify and --ca-bundle" in captured.err
    
    @patch('main.get_workflow_runs')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_custom_output_dir(self, mock_save, mock_extract, mock_get_runs):
        """Test main with custom output directory."""
        mock_get_runs.return_value = []
        mock_extract.return_value = []
        
        test_args = [
            "--owner", "testowner",
            "--repo", "testrepo",
            "--token", "testtoken",
            "--output-dir", "custom_output"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            main.main()
        
        expected_path = os.path.join("custom_output", "testowner_testrepo_runs.csv")
        mock_save.assert_called_once_with([], expected_path)
    
    @patch('main.get_workflow_runs')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_absolute_output_path(self, mock_save, mock_extract, mock_get_runs):
        """Test that absolute output path overrides output directory."""
        mock_get_runs.return_value = []
        mock_extract.return_value = []
        
        test_args = [
            "--owner", "testowner",
            "--repo", "testrepo",
            "--token", "testtoken",
            "--output", "/absolute/path/to/file.csv"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            main.main()
        
        # Absolute path should be used as-is, ignoring output-dir
        mock_save.assert_called_once_with([], "/absolute/path/to/file.csv")
    
    @patch('main.get_workflow_runs')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_relative_output_path(self, mock_save, mock_extract, mock_get_runs):
        """Test that relative output path with directory overrides output directory."""
        mock_get_runs.return_value = []
        mock_extract.return_value = []
        
        test_args = [
            "--owner", "testowner",
            "--repo", "testrepo",
            "--token", "testtoken",
            "--output", "subdir/file.csv"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            main.main()
        
        # Relative path with directory should be used as-is
        mock_save.assert_called_once_with([], "subdir/file.csv")
    
    def test_save_to_csv_creates_directory(self):
        """Test that save_to_csv creates the output directory if it doesn't exist."""
        details = [
            {
                "workflow_name": "CI",
                "workflow_file": ".github/workflows/ci.yml",
                "workflow_url": "https://github.com/owner/repo/actions/runs/456",
                "status": "completed",
                "conclusion": "success",
                "run_started_at": "2024-01-15T10:01:00Z",
                "branch": "main",
                "commit_sha": "abcdef12",
                "event": "push"
            }
        ]
        
        # Use a temporary directory that doesn't exist
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = os.path.join(tmpdir, "nonexistent", "subdir")
            output_file = os.path.join(output_dir, "test.csv")
            
            # Directory shouldn't exist yet
            assert not os.path.exists(output_dir)
            
            # Save should create the directory
            main.save_to_csv(details, output_file)
            
            # Directory should now exist
            assert os.path.exists(output_dir)
            assert os.path.exists(output_file)
            
            # Verify file content
            with open(output_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                assert len(rows) == 1
                assert rows[0]["workflow_name"] == "CI"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

