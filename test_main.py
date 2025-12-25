#!/usr/bin/env python3
"""
Tests for the GitHub Actions workflow runs exporter.
"""

import os
import sys
import csv
import tempfile
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from unittest.mock import Mock, patch

import pytest
import requests

# Add the parent directory to the path so we can import main
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main


# Test Constants
DEFAULT_DAYS = 14
TEST_OWNER = "testowner"
TEST_REPO = "testrepo"
TEST_TOKEN = "testtoken"
TEST_WORKFLOW_NAME = "CI"
TEST_WORKFLOW_ID = 123
TEST_RUN_ID = 456
RATE_LIMIT_LIMIT = 5000
RATE_LIMIT_REMAINING_NORMAL = 4999
RATE_LIMIT_REMAINING_LOW = 500  # 10%
DEFAULT_RESET_TIME_OFFSET = 3600  # 1 hour in seconds


def _format_datetime(dt: datetime) -> str:
    """
    Format datetime to ISO format with Z suffix (as GitHub API returns).
    
    Args:
        dt: Datetime object
    
    Returns:
        ISO formatted string with Z suffix
    """
    return dt.isoformat().replace("+00:00", "Z")


def _create_mock_rate_limit_headers(
    remaining: int = RATE_LIMIT_REMAINING_NORMAL,
    limit: int = RATE_LIMIT_LIMIT,
    reset_offset: int = DEFAULT_RESET_TIME_OFFSET
) -> Dict[str, str]:
    """
    Create mock rate limit headers for API responses.
    
    Args:
        remaining: Remaining API requests
        limit: Total API request limit
        reset_offset: Seconds from now until rate limit reset
    
    Returns:
        Dictionary with rate limit headers
    """
    reset_timestamp = int(datetime.now(timezone.utc).timestamp()) + reset_offset
    return {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": str(reset_timestamp)
    }


def _create_mock_workflow_run(
    run_id: int = TEST_RUN_ID,
    workflow_id: int = TEST_WORKFLOW_ID,
    name: str = TEST_WORKFLOW_NAME,
    created_at: Optional[datetime] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Create a mock workflow run dictionary.
    
    Args:
        run_id: Workflow run ID
        workflow_id: Workflow ID
        name: Workflow name
        created_at: Creation datetime (defaults to now)
        **kwargs: Additional fields to include
    
    Returns:
        Mock workflow run dictionary
    """
    if created_at is None:
        created_at = datetime.now(timezone.utc)
    
    run = {
        "id": run_id,
        "workflow_id": workflow_id,
        "name": name,
        "created_at": _format_datetime(created_at),
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
        "head_sha": "abcdef1234567890",
        "event": "push",
        "html_url": f"https://github.com/{TEST_OWNER}/{TEST_REPO}/actions/runs/{run_id}",
        "path": f".github/workflows/{name.lower()}.yml",
        "run_started_at": _format_datetime(created_at),
    }
    run.update(kwargs)
    return run


def _create_mock_api_response(
    workflow_runs: List[Dict[str, Any]],
    status_code: int = 200,
    remaining: int = RATE_LIMIT_REMAINING_NORMAL,
    has_next: bool = False
) -> Mock:
    """
    Create a mock API response object.
    
    Args:
        workflow_runs: List of workflow run dictionaries
        status_code: HTTP status code
        remaining: Remaining API requests
        has_next: Whether there's a next page
    
    Returns:
        Mock response object
    """
    mock_response = Mock()
    mock_response.status_code = status_code
    mock_response.headers = _create_mock_rate_limit_headers(remaining=remaining)
    mock_response.json.return_value = {"workflow_runs": workflow_runs}
    mock_response.raise_for_status = Mock()
    mock_response.links = {"next": {"url": "http://example.com/page2"}} if has_next else {}
    return mock_response


def _create_empty_day_responses(days: int, start_offset: int = 0) -> List[Mock]:
    """
    Create mock responses for empty days.
    
    Args:
        days: Number of days to create responses for
        start_offset: Starting offset for rate limit remaining
    
    Returns:
        List of mock response objects
    """
    responses = []
    for day_offset in range(days):
        remaining = RATE_LIMIT_LIMIT - start_offset - day_offset
        responses.append(_create_mock_api_response([], remaining=remaining))
    return responses


def _setup_test_logging() -> None:
    """Setup logging for tests that need it."""
    main.setup_logging("INFO")


class TestExtractWorkflowDetails:
    """Tests for extract_workflow_details function."""
    
    def test_extract_workflow_details_basic(self):
        """Test extracting details from a basic workflow run."""
        runs = [_create_mock_workflow_run(
            run_id=TEST_RUN_ID,
            name=TEST_WORKFLOW_NAME,
            path=".github/workflows/ci.yml",
            created_at=datetime(2024, 1, 15, 10, 1, 0, tzinfo=timezone.utc)
        )]
        
        details = main.extract_workflow_details(runs)
        
        assert len(details) == 1
        detail = details[0]
        assert detail["workflow_name"] == TEST_WORKFLOW_NAME
        assert detail["workflow_file"] == ".github/workflows/ci.yml"
        assert detail["workflow_url"] == f"https://github.com/{TEST_OWNER}/{TEST_REPO}/actions/runs/{TEST_RUN_ID}"
        assert detail["status"] == "completed"
        assert detail["conclusion"] == "success"
        assert detail["run_started_at"] == "2024-01-15T10:01:00Z"
        assert detail["branch"] == "main"
        assert detail["commit_sha"] == "abcdef12"
        assert detail["event"] == "push"
    
    def test_extract_workflow_details_missing_fields(self):
        """Test extracting details when some fields are missing."""
        runs = [{
            "name": TEST_WORKFLOW_NAME,
            "status": "in_progress",
        }]
        
        details = main.extract_workflow_details(runs)
        
        assert len(details) == 1
        detail = details[0]
        assert detail["workflow_name"] == TEST_WORKFLOW_NAME
        assert detail["workflow_file"] == "N/A"
        assert detail["workflow_url"] == "N/A"
        assert detail["status"] == "in_progress"
        assert detail["conclusion"] == "N/A"
        assert detail["run_started_at"] == "N/A"
        assert detail["branch"] == "N/A"
        assert detail["commit_sha"] == "N/A"
        assert detail["event"] == "N/A"
    
    def test_extract_workflow_details_workflow_file(self):
        """Test extracting workflow file path."""
        runs = [_create_mock_workflow_run(path=".github/workflows/test.yml")]
        
        details = main.extract_workflow_details(runs)
        
        assert details[0]["workflow_file"] == ".github/workflows/test.yml"
    
    def test_extract_workflow_details_missing_workflow_file(self):
        """Test handling when workflow file path is missing."""
        runs = [{"name": TEST_WORKFLOW_NAME, "status": "completed"}]
        
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
        details = [{
            "workflow_name": TEST_WORKFLOW_NAME,
            "workflow_file": ".github/workflows/ci.yml",
            "workflow_url": f"https://github.com/{TEST_OWNER}/{TEST_REPO}/actions/runs/{TEST_RUN_ID}",
            "status": "completed",
            "conclusion": "success",
            "run_started_at": "2024-01-15T10:01:00Z",
            "branch": "main",
            "commit_sha": "abcdef12",
            "event": "push"
        }]
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            filename = f.name
        
        try:
            main.save_to_csv(details, filename)
            
            assert os.path.exists(filename)
            
            with open(filename, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                
                assert len(rows) == 1
                assert rows[0]["workflow_name"] == TEST_WORKFLOW_NAME
                assert rows[0]["workflow_file"] == ".github/workflows/ci.yml"
                assert rows[0]["status"] == "completed"
        finally:
            os.unlink(filename)
    
    def test_save_to_csv_empty_list(self, capsys):
        """Test saving empty list (should print message and not create file)."""
        _setup_test_logging()
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            filename = f.name
        
        try:
            main.save_to_csv([], filename)
            
            captured = capsys.readouterr()
            assert "No workflow runs to save" in captured.out
            
            if os.path.exists(filename):
                assert os.path.getsize(filename) == 0
        finally:
            if os.path.exists(filename):
                os.unlink(filename)
    
    def test_save_to_csv_multiple_rows(self):
        """Test saving multiple workflow runs to CSV."""
        details = [
            _create_mock_workflow_run(run_id=456, name="CI"),
            _create_mock_workflow_run(run_id=457, name="Deploy", conclusion="failure")
        ]
        details = main.extract_workflow_details(details)
        
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
    @patch('main.time.sleep')
    def test_get_workflow_runs_single_page(self, mock_sleep, mock_get):
        """Test fetching workflow runs from a single page."""
        _setup_test_logging()
        now = datetime.now(timezone.utc)
        
        # Create responses for 14 days, one day has a run
        mock_responses = _create_empty_day_responses(DEFAULT_DAYS)
        
        # Day 5 (5 days ago) will have a run
        # Calculate the exact day start for day 5 to ensure the run is within range
        day_5_start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=5)
        day_5_run_time = day_5_start + timedelta(hours=12)  # Noon on that day
        
        day_5_run = _create_mock_workflow_run(
            created_at=day_5_run_time
        )
        mock_responses[5] = _create_mock_api_response([day_5_run])
        
        mock_get.side_effect = mock_responses
        
        runs = main.get_workflow_runs("owner", "repo", "token", days=DEFAULT_DAYS)
        
        assert len(runs) == 1
        assert runs[0]["name"] == TEST_WORKFLOW_NAME
        assert mock_get.call_count == DEFAULT_DAYS
    
    @patch('main.requests.get')
    @patch('main.time.sleep')
    def test_get_workflow_runs_pagination(self, mock_sleep, mock_get):
        """Test fetching workflow runs across multiple pages within a day."""
        _setup_test_logging()
        now = datetime.now(timezone.utc)
        
        # Create responses for 14 days
        mock_responses = []
        for day_offset in range(DEFAULT_DAYS):
            if day_offset == 0:
                # Day 0 (today) will have pagination (2 pages)
                # Calculate today's start to ensure runs are within range
                today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
                runs_page1 = [
                    _create_mock_workflow_run(
                        run_id=i,
                        created_at=today_start + timedelta(hours=i)
                    )
                    for i in range(1, 6)  # 5 runs
                ]
                mock_responses.append(_create_mock_api_response(runs_page1, has_next=True))
                mock_responses.append(_create_mock_api_response([]))  # Empty second page
            else:
                mock_responses.append(_create_mock_api_response([]))
        
        mock_get.side_effect = mock_responses
        
        runs = main.get_workflow_runs("owner", "repo", "token", days=DEFAULT_DAYS, per_page=5)
        
        assert len(runs) == 5
        # 14 days + 1 extra page for day 0 = 15 calls
        assert mock_get.call_count == 15
    
    @patch('main.requests.get')
    @patch('main.time.sleep')
    def test_get_workflow_runs_date_filtering(self, mock_sleep, mock_get):
        """Test that runs outside the date range are filtered out."""
        _setup_test_logging()
        now = datetime.now(timezone.utc)
        
        # Create responses for 14 days
        mock_responses = _create_empty_day_responses(DEFAULT_DAYS)
        
        # Day 5 will have a run within range
        # Calculate the exact day start for day 5 to ensure the run is within range
        day_5_start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=5)
        day_5_run_time = day_5_start + timedelta(hours=12)  # Noon on that day
        
        day_5_run = _create_mock_workflow_run(
            run_id=1,
            created_at=day_5_run_time
        )
        mock_responses[5] = _create_mock_api_response([day_5_run])
        
        mock_get.side_effect = mock_responses
        
        runs = main.get_workflow_runs("owner", "repo", "token", days=DEFAULT_DAYS)
        
        assert len(runs) == 1
        assert runs[0]["id"] == 1
    
    @patch('main.requests.get')
    @patch('main.time.sleep')
    def test_get_workflow_runs_api_error(self, mock_sleep, mock_get):
        """Test handling of API errors."""
        _setup_test_logging()
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.headers = _create_mock_rate_limit_headers()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "404 Not Found", response=mock_response
        )
        mock_response.text = "Not Found"
        mock_get.return_value = mock_response
        
        with pytest.raises(SystemExit):
            main.get_workflow_runs("owner", "repo", "token", days=DEFAULT_DAYS)
    
    @patch('main.requests.get')
    @patch('main.time.sleep')
    def test_get_workflow_runs_correct_url_and_headers(self, mock_sleep, mock_get):
        """Test that the correct URL and headers are used."""
        _setup_test_logging()
        mock_responses = _create_empty_day_responses(7)
        mock_get.side_effect = mock_responses
        
        main.get_workflow_runs(TEST_OWNER, TEST_REPO, TEST_TOKEN, days=7)
        
        # Verify URL (check first call)
        first_call_url = mock_get.call_args_list[0][0][0]
        assert TEST_OWNER in first_call_url
        assert TEST_REPO in first_call_url
        
        # Verify headers (check first call)
        headers = mock_get.call_args_list[0][1]["headers"]
        assert headers["Authorization"] == f"token {TEST_TOKEN}"
        assert headers["Accept"] == "application/vnd.github.v3+json"
        
        # Verify SSL verification is enabled by default
        assert mock_get.call_args_list[0][1]["verify"] is True
        
        assert mock_get.call_count == 7
    
    @patch('main.requests.get')
    @patch('main.time.sleep')
    def test_get_workflow_runs_verify_ssl_false(self, mock_sleep, mock_get):
        """Test that verify_ssl=False is passed to requests."""
        _setup_test_logging()
        mock_responses = _create_empty_day_responses(7)
        mock_get.side_effect = mock_responses
        
        main.get_workflow_runs(TEST_OWNER, TEST_REPO, TEST_TOKEN, days=7, verify_ssl=False)
        
        for call in mock_get.call_args_list:
            assert call[1]["verify"] is False
    
    @patch('main.requests.get')
    @patch('main.time.sleep')
    def test_get_workflow_runs_verify_ssl_ca_bundle(self, mock_sleep, mock_get):
        """Test that verify_ssl with CA bundle path is passed to requests."""
        _setup_test_logging()
        mock_responses = _create_empty_day_responses(7)
        mock_get.side_effect = mock_responses
        
        ca_bundle_path = "/path/to/ca-bundle.crt"
        main.get_workflow_runs(
            TEST_OWNER, TEST_REPO, TEST_TOKEN, days=7, verify_ssl=ca_bundle_path
        )
        
        for call in mock_get.call_args_list:
            assert call[1]["verify"] == ca_bundle_path
    
    @patch('main.requests.get')
    @patch('main.time.sleep')
    def test_get_workflow_runs_ssl_error(self, mock_sleep, mock_get, capsys):
        """Test handling of SSL errors with helpful error message."""
        _setup_test_logging()
        mock_get.side_effect = requests.exceptions.SSLError("certificate verify failed")
        
        with pytest.raises(SystemExit) as exc_info:
            main.get_workflow_runs("owner", "repo", "token", days=DEFAULT_DAYS)
        
        assert exc_info.value.code == 1
        
        captured = capsys.readouterr()
        assert "SSL Error" in captured.out
        assert "--no-ssl-verify" in captured.out or "--ca-bundle" in captured.out
    
    @patch('main.requests.get')
    @patch('main.time.sleep')
    def test_get_workflow_runs_rate_limit_handling(self, mock_sleep, mock_get):
        """Test that rate limit errors are handled with retry."""
        _setup_test_logging()
        now = datetime.now(timezone.utc)
        reset_time = int((now + timedelta(seconds=5)).timestamp())
        
        # Create responses for 14 days
        mock_responses = []
        for day_offset in range(DEFAULT_DAYS):
            if day_offset == 0:
                # First call: rate limit error (403)
                mock_response_403 = Mock()
                mock_response_403.status_code = 403
                mock_response_403.headers = {
                    "X-RateLimit-Limit": str(RATE_LIMIT_LIMIT),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_time)
                }
                mock_responses.append(mock_response_403)
                
                # Second call: success after waiting
                mock_responses.append(_create_mock_api_response([]))
            else:
                mock_responses.append(_create_mock_api_response([]))
        
        mock_get.side_effect = mock_responses
        
        runs = main.get_workflow_runs("owner", "repo", "token", days=DEFAULT_DAYS)
        
        assert len(runs) == 0
        assert mock_sleep.called


class TestRateLimitHandling:
    """Tests for rate limit handling functions."""
    
    def test_check_rate_limit_normal(self, capsys):
        """Test rate limit checking with normal remaining requests."""
        mock_response = Mock()
        mock_response.headers = _create_mock_rate_limit_headers(
            remaining=RATE_LIMIT_REMAINING_NORMAL
        )
        
        main.check_rate_limit(mock_response)
        
        captured = capsys.readouterr()
        assert "Rate limit warning" not in captured.err
    
    def test_check_rate_limit_low(self, capsys):
        """Test rate limit checking when remaining is low."""
        _setup_test_logging()
        mock_response = Mock()
        mock_response.headers = _create_mock_rate_limit_headers(
            remaining=RATE_LIMIT_REMAINING_LOW
        )
        
        main.check_rate_limit(mock_response)
        
        captured = capsys.readouterr()
        assert "Rate limit warning" in captured.out
    
    def test_handle_rate_limit_error_with_reset_time(self):
        """Test handling rate limit error with reset time."""
        reset_timestamp = int(datetime.now(timezone.utc).timestamp()) + 10
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.headers = {"X-RateLimit-Reset": str(reset_timestamp)}
        
        with patch('main.time.sleep') as mock_sleep:
            result = main.handle_rate_limit_error(mock_response)
        
        assert result is True
        assert mock_sleep.called
    
    def test_handle_rate_limit_error_no_reset_time(self):
        """Test handling rate limit error without reset time."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.headers = {}
        
        with patch('main.time.sleep') as mock_sleep:
            result = main.handle_rate_limit_error(mock_response)
        
        assert result is True
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
            _create_mock_workflow_run(
                run_id=1,
                created_at=now - timedelta(days=5)
            ),
            _create_mock_workflow_run(
                run_id=2,
                created_at=now - timedelta(days=2)
            ),
            _create_mock_workflow_run(
                run_id=3,
                created_at=now - timedelta(days=1)
            )
        ]
        
        filtered = main.filter_latest_runs_per_workflow(runs)
        
        assert len(filtered) == 1
        assert filtered[0]["id"] == 3  # Most recent run
    
    def test_filter_latest_runs_multiple_workflows(self):
        """Test filtering with multiple different workflows."""
        now = datetime.now(timezone.utc)
        runs = [
            _create_mock_workflow_run(
                run_id=1,
                workflow_id=123,
                created_at=now - timedelta(days=5)
            ),
            _create_mock_workflow_run(
                run_id=2,
                workflow_id=123,
                created_at=now - timedelta(days=1)
            ),
            _create_mock_workflow_run(
                run_id=3,
                workflow_id=456,
                name="Deploy",
                created_at=now - timedelta(days=3)
            ),
            _create_mock_workflow_run(
                run_id=4,
                workflow_id=456,
                name="Deploy",
                created_at=now - timedelta(days=2)
            )
        ]
        
        filtered = main.filter_latest_runs_per_workflow(runs)
        
        assert len(filtered) == 2
        workflow_ids = {run["workflow_id"] for run in filtered}
        assert workflow_ids == {123, 456}
        
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
        runs = [_create_mock_workflow_run(
            run_id=1,
            created_at=now - timedelta(days=1)
        )]
        
        filtered = main.filter_latest_runs_per_workflow(runs)
        
        assert len(filtered) == 1
        assert filtered[0]["id"] == 1
    
    def test_filter_latest_runs_missing_workflow_id(self):
        """Test that runs without workflow_id are skipped."""
        now = datetime.now(timezone.utc)
        runs = [
            _create_mock_workflow_run(
                run_id=1,
                created_at=now - timedelta(days=1)
            ),
            {
                # Missing workflow_id
                "name": TEST_WORKFLOW_NAME,
                "id": 2,
                "created_at": _format_datetime(now - timedelta(days=1))
            }
        ]
        
        filtered = main.filter_latest_runs_per_workflow(runs)
        
        assert len(filtered) == 1
        assert filtered[0]["id"] == 1
    
    def test_filter_latest_runs_missing_created_at(self):
        """Test that runs without created_at are skipped."""
        runs = [
            _create_mock_workflow_run(
                run_id=1,
                created_at=datetime.now(timezone.utc) - timedelta(days=1)
            ),
            {
                "workflow_id": 456,
                "name": "Deploy",
                "id": 2,
                # Missing created_at
            }
        ]
        
        filtered = main.filter_latest_runs_per_workflow(runs)
        
        assert len(filtered) == 1
        assert filtered[0]["id"] == 1


class TestMain:
    """Tests for main function."""
    
    @patch('main.get_workflow_runs')
    @patch('main.filter_latest_runs_per_workflow')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_success(self, mock_save, mock_extract, mock_filter, mock_get_runs):
        """Test successful execution of main function."""
        mock_get_runs.return_value = [{"id": 1, "name": TEST_WORKFLOW_NAME}]
        mock_filter.return_value = [{"id": 1, "name": TEST_WORKFLOW_NAME}]
        mock_extract.return_value = [{"workflow_name": TEST_WORKFLOW_NAME}]
        
        test_args = [
            "--owner", TEST_OWNER,
            "--repo", TEST_REPO,
            "--token", TEST_TOKEN
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            main.main()
        
        mock_get_runs.assert_called_once_with(
            TEST_OWNER, TEST_REPO, TEST_TOKEN, DEFAULT_DAYS, verify_ssl=True
        )
        mock_extract.assert_called_once()
        execution_date = datetime.now(timezone.utc).date().isoformat()
        expected_path = os.path.join("./output", f"{TEST_OWNER}_{TEST_REPO}_runs_{execution_date}.csv")
        mock_save.assert_called_once_with([{"workflow_name": TEST_WORKFLOW_NAME}], expected_path)
    
    @patch('main.get_workflow_runs')
    @patch('main.filter_latest_runs_per_workflow')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_custom_days_and_output(self, mock_save, mock_extract, mock_filter, mock_get_runs):
        """Test main with custom days and output filename."""
        mock_get_runs.return_value = []
        mock_filter.return_value = []
        mock_extract.return_value = []
        
        test_args = [
            "--owner", TEST_OWNER,
            "--repo", TEST_REPO,
            "--token", TEST_TOKEN,
            "--days", "7",
            "--output", "custom.csv"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            main.main()
        
        mock_get_runs.assert_called_once_with(
            TEST_OWNER, TEST_REPO, TEST_TOKEN, 7, verify_ssl=True
        )
        expected_path = os.path.join("./output", "custom.csv")
        mock_save.assert_called_once_with([], expected_path)
    
    def test_main_missing_owner(self, capsys):
        """Test main with missing owner argument."""
        test_args = ["--repo", TEST_REPO, "--token", TEST_TOKEN]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            with pytest.raises(SystemExit):
                main.main()
        
        captured = capsys.readouterr()
        assert "Repository owner is required" in captured.out
    
    def test_main_missing_repo(self, capsys):
        """Test main with missing repo argument."""
        test_args = ["--owner", TEST_OWNER, "--token", TEST_TOKEN]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            with pytest.raises(SystemExit):
                main.main()
        
        captured = capsys.readouterr()
        assert "Repository name is required" in captured.out
    
    def test_main_missing_token(self, capsys):
        """Test main with missing token argument."""
        test_args = ["--owner", TEST_OWNER, "--repo", TEST_REPO]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            with pytest.raises(SystemExit):
                main.main()
        
        captured = capsys.readouterr()
        assert "GitHub token is required" in captured.out
    
    @patch.dict(os.environ, {
        'GITHUB_OWNER': 'envowner',
        'GITHUB_REPO': 'envrepo',
        'GITHUB_TOKEN': 'envtoken'
    })
    @patch('main.get_workflow_runs')
    @patch('main.filter_latest_runs_per_workflow')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_environment_variables(self, mock_save, mock_extract, mock_filter, mock_get_runs):
        """Test main using environment variables."""
        mock_get_runs.return_value = []
        mock_filter.return_value = []
        mock_extract.return_value = []
        
        with patch.object(sys, 'argv', ['main.py']):
            main.main()
        
        mock_get_runs.assert_called_once_with(
            "envowner", "envrepo", "envtoken", DEFAULT_DAYS, verify_ssl=True
        )
        execution_date = datetime.now(timezone.utc).date().isoformat()
        expected_path = os.path.join("./output", f"envowner_envrepo_runs_{execution_date}.csv")
        mock_save.assert_called_once_with([], expected_path)
    
    @patch('main.get_workflow_runs')
    @patch('main.filter_latest_runs_per_workflow')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_no_ssl_verify(self, mock_save, mock_extract, mock_filter, mock_get_runs):
        """Test main with --no-ssl-verify flag."""
        mock_get_runs.return_value = []
        mock_filter.return_value = []
        mock_extract.return_value = []
        
        test_args = [
            "--owner", TEST_OWNER,
            "--repo", TEST_REPO,
            "--token", TEST_TOKEN,
            "--no-ssl-verify"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            main.main()
        
        mock_get_runs.assert_called_once_with(
            TEST_OWNER, TEST_REPO, TEST_TOKEN, DEFAULT_DAYS, verify_ssl=False
        )
    
    @patch('main.get_workflow_runs')
    @patch('main.filter_latest_runs_per_workflow')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_ca_bundle(self, mock_save, mock_extract, mock_filter, mock_get_runs):
        """Test main with --ca-bundle flag."""
        mock_get_runs.return_value = []
        mock_filter.return_value = []
        mock_extract.return_value = []
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.crt') as f:
            ca_bundle_path = f.name
            f.write("fake CA certificate")
        
        try:
            test_args = [
                "--owner", TEST_OWNER,
                "--repo", TEST_REPO,
                "--token", TEST_TOKEN,
                "--ca-bundle", ca_bundle_path
            ]
            
            with patch.object(sys, 'argv', ['main.py'] + test_args):
                main.main()
            
            mock_get_runs.assert_called_once_with(
                TEST_OWNER, TEST_REPO, TEST_TOKEN, DEFAULT_DAYS, verify_ssl=ca_bundle_path
            )
        finally:
            if os.path.exists(ca_bundle_path):
                os.unlink(ca_bundle_path)
    
    def test_main_both_ssl_options_error(self, capsys):
        """Test that using both --no-ssl-verify and --ca-bundle causes an error."""
        test_args = [
            "--owner", TEST_OWNER,
            "--repo", TEST_REPO,
            "--token", TEST_TOKEN,
            "--no-ssl-verify",
            "--ca-bundle", "/path/to/ca.crt"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            with pytest.raises(SystemExit):
                main.main()
        
        captured = capsys.readouterr()
        assert "Cannot use both --no-ssl-verify and --ca-bundle" in captured.out
    
    @patch('main.get_workflow_runs')
    @patch('main.filter_latest_runs_per_workflow')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_custom_output_dir(self, mock_save, mock_extract, mock_filter, mock_get_runs):
        """Test main with custom output directory."""
        mock_get_runs.return_value = []
        mock_filter.return_value = []
        mock_extract.return_value = []
        
        test_args = [
            "--owner", TEST_OWNER,
            "--repo", TEST_REPO,
            "--token", TEST_TOKEN,
            "--output-dir", "custom_output"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            main.main()
        
        execution_date = datetime.now(timezone.utc).date().isoformat()
        expected_path = os.path.join("custom_output", f"{TEST_OWNER}_{TEST_REPO}_runs_{execution_date}.csv")
        mock_save.assert_called_once_with([], expected_path)
    
    @patch('main.get_workflow_runs')
    @patch('main.filter_latest_runs_per_workflow')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_absolute_output_path(self, mock_save, mock_extract, mock_filter, mock_get_runs):
        """Test that absolute output path overrides output directory."""
        mock_get_runs.return_value = []
        mock_filter.return_value = []
        mock_extract.return_value = []
        
        test_args = [
            "--owner", TEST_OWNER,
            "--repo", TEST_REPO,
            "--token", TEST_TOKEN,
            "--output", "/absolute/path/to/file.csv"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            main.main()
        
        mock_save.assert_called_once_with([], "/absolute/path/to/file.csv")
    
    @patch('main.get_workflow_runs')
    @patch('main.filter_latest_runs_per_workflow')
    @patch('main.extract_workflow_details')
    @patch('main.save_to_csv')
    def test_main_relative_output_path(self, mock_save, mock_extract, mock_filter, mock_get_runs):
        """Test that relative output path with directory overrides output directory."""
        mock_get_runs.return_value = []
        mock_filter.return_value = []
        mock_extract.return_value = []
        
        test_args = [
            "--owner", TEST_OWNER,
            "--repo", TEST_REPO,
            "--token", TEST_TOKEN,
            "--output", "subdir/file.csv"
        ]
        
        with patch.object(sys, 'argv', ['main.py'] + test_args):
            main.main()
        
        mock_save.assert_called_once_with([], "subdir/file.csv")
    
    def test_save_to_csv_creates_directory(self):
        """Test that save_to_csv creates the output directory if it doesn't exist."""
        details = [{
            "workflow_name": TEST_WORKFLOW_NAME,
            "workflow_file": ".github/workflows/ci.yml",
            "workflow_url": f"https://github.com/{TEST_OWNER}/{TEST_REPO}/actions/runs/{TEST_RUN_ID}",
            "status": "completed",
            "conclusion": "success",
            "run_started_at": "2024-01-15T10:01:00Z",
            "branch": "main",
            "commit_sha": "abcdef12",
            "event": "push"
        }]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = os.path.join(tmpdir, "nonexistent", "subdir")
            output_file = os.path.join(output_dir, "test.csv")
            
            assert not os.path.exists(output_dir)
            
            main.save_to_csv(details, output_file)
            
            assert os.path.exists(output_dir)
            assert os.path.exists(output_file)
            
            with open(output_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                assert len(rows) == 1
                assert rows[0]["workflow_name"] == TEST_WORKFLOW_NAME


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
