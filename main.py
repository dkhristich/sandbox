#!/usr/bin/env python3
"""
Script to fetch GitHub Actions workflow runs from the last 2 weeks and save to CSV.

This script queries the GitHub API to retrieve workflow runs, filters them to get
the latest run per workflow, and exports the results to a CSV file.
"""

import os
import sys
import csv
import re
import time
import logging
import argparse
import warnings
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple, Union

import requests
import urllib3

# Suppress urllib3 InsecureRequestWarning - we'll handle it with our own logging
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants
DEFAULT_DAYS = 14
DEFAULT_PER_PAGE = 100
DEFAULT_OUTPUT_DIR = "./output"
MAX_PAGES_PER_DAY = 100  # Safety limit: 100 pages = 10,000 results per day
API_RESULT_LIMIT = 1000  # GitHub API limit for workflow runs
RATE_LIMIT_WARNING_THRESHOLD = 20  # Percentage threshold for rate limit warnings
RATE_LIMIT_DETAIL_THRESHOLD = 100  # Remaining requests threshold for detailed logging
MAX_RETRIES = 3
REQUEST_DELAY = 0.1  # Seconds between API requests
DAY_DELAY = 0.2  # Seconds between day queries

# GitHub API endpoints
GITHUB_API_BASE = "https://api.github.com"
GITHUB_TOKEN_URL = "https://github.com/settings/tokens"

# Logging format
LOG_FORMAT = '%(asctime)s [%(levelname)-8s] %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# CSV field names
CSV_FIELDS = [
    "workflow_name",
    "workflow_file",
    "workflow_url",
    "status",
    "conclusion",
    "run_started_at",
    "branch",
    "commit_sha",
    "event"
]

# Configure logging
logger = logging.getLogger(__name__)


def setup_logging(log_level: str = "INFO") -> None:
    """
    Setup logging configuration with formatted output.
    
    Args:
        log_level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    
    Raises:
        ValueError: If log_level is invalid
    """
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {log_level}')
    
    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    logging.basicConfig(
        level=numeric_level,
        handlers=[console_handler],
        force=True  # Override any existing configuration
    )
    
    logger.setLevel(numeric_level)


def _parse_rate_limit_headers(response: requests.Response) -> Optional[Dict[str, int]]:
    """
    Parse rate limit headers from GitHub API response.
    
    Args:
        response: Response object from GitHub API
    
    Returns:
        Dictionary with 'limit', 'remaining', and 'reset' keys, or None if unavailable
    """
    try:
        headers = response.headers
        rate_limit = headers.get("X-RateLimit-Limit")
        rate_remaining = headers.get("X-RateLimit-Remaining")
        rate_reset = headers.get("X-RateLimit-Reset")
        
        if not (rate_limit and rate_remaining):
            return None
        
        return {
            'limit': int(rate_limit),
            'remaining': int(rate_remaining),
            'reset': int(rate_reset) if rate_reset else None
        }
    except (AttributeError, TypeError, ValueError):
        # Headers might not be available or invalid (e.g., in tests with incomplete mocks)
        return None


def _format_reset_time(reset_timestamp: int) -> str:
    """
    Format rate limit reset timestamp as a human-readable string.
    
    Args:
        reset_timestamp: Unix timestamp for rate limit reset
    
    Returns:
        Formatted date string
    """
    try:
        reset_time = datetime.fromtimestamp(reset_timestamp, tz=timezone.utc)
        return reset_time.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError):
        return "N/A"


def check_rate_limit(response: requests.Response) -> None:
    """
    Check and display rate limit information from GitHub API response headers.
    
    Args:
        response: Response object from GitHub API
    """
    rate_info = _parse_rate_limit_headers(response)
    if not rate_info:
        return
    
    remaining = rate_info['remaining']
    limit = rate_info['limit']
    percentage = (remaining / limit) * 100
    
    # Warn if we're running low on rate limit
    if percentage < RATE_LIMIT_WARNING_THRESHOLD:
        logger.warning(
            f"⚠️  Rate limit warning: {remaining}/{limit} requests remaining "
            f"({percentage:.1f}%)"
        )
    
    # Show detailed rate limit info when low or at round numbers
    if remaining < RATE_LIMIT_DETAIL_THRESHOLD or (remaining % 100 == 0 and remaining < limit):
        reset_str = _format_reset_time(rate_info['reset']) if rate_info['reset'] else "N/A"
        if reset_str != "N/A":
            logger.debug(f"Rate limit: {remaining}/{limit} remaining (resets at {reset_str})")


def print_final_rate_limit(response: requests.Response) -> None:
    """
    Print the final rate limit status at the end of execution.
    
    Args:
        response: Last response object from GitHub API
    """
    rate_info = _parse_rate_limit_headers(response)
    if not rate_info:
        return
    
    remaining = rate_info['remaining']
    limit = rate_info['limit']
    used = limit - remaining
    percentage = (remaining / limit) * 100
    
    reset_str = "N/A"
    if rate_info['reset']:
        reset_str = _format_reset_time(rate_info['reset'])
    
    logger.info(
        f"📊 Final rate limit status: {remaining}/{limit} remaining "
        f"({used} used, {percentage:.1f}% remaining)"
    )
    if reset_str != "N/A":
        logger.info(f"   Rate limit resets at: {reset_str}")


def handle_rate_limit_error(response: requests.Response, max_retries: int = MAX_RETRIES) -> bool:
    """
    Handle rate limit errors (HTTP 403) by waiting for the rate limit to reset.
    
    Args:
        response: Response object from GitHub API with 403 status
        max_retries: Maximum number of retries (default: MAX_RETRIES)
    
    Returns:
        True if we should retry, False otherwise
    """
    if response.status_code != 403:
        return False
    
    rate_info = _parse_rate_limit_headers(response)
    if not rate_info or not rate_info['reset']:
        logger.warning(
            "Rate limit exceeded, but reset time not available. "
            "Waiting 60 seconds..."
        )
        time.sleep(60)
        return True
    
    try:
        reset_timestamp = rate_info['reset']
        reset_time = datetime.fromtimestamp(reset_timestamp, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        wait_seconds = max(0, int((reset_timestamp - now.timestamp())) + 1)
        
        if wait_seconds <= 0:
            return False
        
        reset_str = reset_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        logger.warning(
            f"⏳ Rate limit exceeded. Waiting until {reset_str} "
            f"({wait_seconds} seconds)..."
        )
        
        # Show progress for long waits
        if wait_seconds > 60:
            while wait_seconds > 0:
                mins, secs = divmod(wait_seconds, 60)
                if wait_seconds % 60 == 0 or wait_seconds == 1:
                    logger.debug(f"   Waiting... {mins}m {secs}s remaining")
                time.sleep(min(60, wait_seconds))
                wait_seconds = max(0, wait_seconds - 60)
        else:
            time.sleep(wait_seconds)
        
        logger.info("✅ Rate limit reset. Retrying...")
        return True
    except (ValueError, OSError) as e:
        logger.error(f"Error parsing rate limit reset time: {e}. Waiting 60 seconds...")
        time.sleep(60)
        return True


def _parse_link_header(link_header: str) -> Optional[str]:
    """
    Parse Link header to extract next page URL.
    
    Args:
        link_header: Link header value from HTTP response
    
    Returns:
        Next page URL if found, None otherwise
    """
    next_match = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
    return next_match.group(1) if next_match else None


def _get_next_url(response: requests.Response) -> Optional[str]:
    """
    Extract next page URL from response Link header.
    
    Args:
        response: Response object from GitHub API
    
    Returns:
        Next page URL if available, None otherwise
    """
    # Try using response.links (requests library parses Link headers automatically)
    if hasattr(response, 'links') and response.links:
        next_link = response.links.get('next')
        if next_link:
            return next_link.get('url')
    
    # Fallback: manually parse Link header
    if 'Link' in response.headers:
        return _parse_link_header(response.headers.get('Link', ''))
    
    return None


def _filter_runs_by_date_range(
    runs: List[Dict[str, Any]],
    day_start: datetime,
    day_end: datetime
) -> Tuple[List[Dict[str, Any]], bool]:
    """
    Filter runs to only include those within the specified date range.
    
    Args:
        runs: List of workflow run dictionaries
        day_start: Start of the day (inclusive)
        day_end: End of the day (exclusive)
    
    Returns:
        Tuple of (filtered_runs, runs_outside_range)
        runs_outside_range is True if any runs were before day_start
    """
    filtered_runs = []
    runs_outside_range = False
    
    for run in runs:
        created_at_str = run.get("created_at")
        if not created_at_str:
            continue
        
        try:
            created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        
        if day_start <= created_at < day_end:
            filtered_runs.append(run)
        elif created_at < day_start:
            runs_outside_range = True
            break
    
    return filtered_runs, runs_outside_range


def _handle_api_error(error: Exception, verify_ssl: Union[bool, str]) -> None:
    """
    Handle API errors with appropriate error messages.
    
    Args:
        error: Exception raised during API request
        verify_ssl: SSL verification setting
    """
    if isinstance(error, requests.exceptions.SSLError):
        logger.error(f"SSL Error: {error}")
        logger.error("If you're behind a corporate VPN/proxy, try one of these options:")
        logger.error("  1. Use --no-ssl-verify (WARNING: insecure, use only if necessary)")
        logger.error("  2. Use --ca-bundle <path> to specify your corporate CA certificate")
        logger.error("  3. Export REQUESTS_CA_BUNDLE environment variable pointing to your CA bundle")
    elif isinstance(error, requests.exceptions.HTTPError):
        if hasattr(error, 'response') and error.response:
            status_code = error.response.status_code
            logger.error(f"HTTP Error {status_code}: {error}")
            if hasattr(error.response, 'text'):
                logger.debug(f"Response: {error.response.text}")
        else:
            logger.error(f"HTTP Error: {error}")
    elif isinstance(error, requests.exceptions.RequestException):
        logger.error(f"Error fetching workflow runs: {error}")
        if hasattr(error, 'response') and error.response:
            if hasattr(error.response, 'text'):
                logger.debug(f"Response: {error.response.text}")
    else:
        logger.error(f"Unexpected error: {error}")
    
    sys.exit(1)


def get_workflow_runs_for_day(
    owner: str,
    repo: str,
    token: str,
    day_start: datetime,
    day_end: datetime,
    per_page: int = DEFAULT_PER_PAGE,
    verify_ssl: Union[bool, str] = True,
    base_url: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None
) -> Tuple[List[Dict[str, Any]], Optional[requests.Response], bool]:
    """
    Fetch workflow runs for a single day.
    
    Args:
        owner: Repository owner (username or organization)
        repo: Repository name
        token: GitHub personal access token
        day_start: Start of the day (inclusive)
        day_end: End of the day (exclusive)
        per_page: Number of results per page (max 100)
        verify_ssl: SSL verification setting
        base_url: Base URL for API (for reuse)
        headers: Headers dict (for reuse)
    
    Returns:
        Tuple of (list of runs, last response, hit_limit_flag)
    """
    if base_url is None:
        base_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/actions/runs"
    if headers is None:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {token}"
        }
    
    day_start_iso = day_start.isoformat().replace("+00:00", "Z")
    day_end_iso = day_end.isoformat().replace("+00:00", "Z")
    
    all_runs: List[Dict[str, Any]] = []
    page = 1
    retry_count = 0
    next_url: Optional[str] = None
    last_response: Optional[requests.Response] = None
    hit_limit = False
    
    while True:
        # Use next_url from Link header if available, otherwise construct URL with params
        if next_url:
            url = next_url
            params = None  # URL already contains all params
        else:
            url = base_url
            params = {
                "per_page": per_page,
                "page": page,
                "created": f"{day_start_iso}..{day_end_iso}"
            }
        
        try:
            response = requests.get(url, headers=headers, params=params, verify=verify_ssl)
            
            # Check rate limit status
            check_rate_limit(response)
            
            # Handle rate limit errors (403)
            if response.status_code == 403:
                if handle_rate_limit_error(response, MAX_RETRIES):
                    retry_count += 1
                    if retry_count > MAX_RETRIES:
                        logger.error("Max retries exceeded for rate limit. Exiting.")
                        sys.exit(1)
                    continue
                else:
                    logger.error("Rate limit error could not be resolved. Exiting.")
                    sys.exit(1)
            
            # Raise for other HTTP errors
            response.raise_for_status()
            retry_count = 0  # Reset retry count on success
            last_response = response
            
            data = response.json()
            runs = data.get("workflow_runs", [])
            if not runs:
                break
            
            # Filter runs that are actually within our day range
            filtered_runs, runs_outside_day = _filter_runs_by_date_range(
                runs, day_start, day_end
            )
            all_runs.extend(filtered_runs)
            
            # If we got runs outside our day range, we're done with this day
            if runs_outside_day:
                break
            
            # Check for next page
            next_url = _get_next_url(response)
            
            # If no next link and we got fewer results than per_page, we're on the last page
            if not next_url and len(runs) < per_page:
                break
            
            # Check if we hit the 1000 result limit for this day
            if not next_url and len(all_runs) >= API_RESULT_LIMIT:
                got_full_page = len(runs) == per_page
                at_exact_limit = len(all_runs) == API_RESULT_LIMIT
                if got_full_page and at_exact_limit:
                    hit_limit = True
                break
            
            # If no next URL and no filtered runs, we're done
            if not next_url and not filtered_runs:
                break
            
            # If no next URL, increment page number for fallback
            if not next_url:
                page += 1
                # Safety check: if we've gone too many pages without a next URL, break
                if page > MAX_PAGES_PER_DAY:
                    break
            else:
                page += 1  # Keep track for logging
            
            # Small delay to avoid hitting rate limits too quickly
            time.sleep(REQUEST_DELAY)
            
        except requests.exceptions.SSLError as e:
            _handle_api_error(e, verify_ssl)
        except requests.exceptions.HTTPError as e:
            # Handle other HTTP errors (not rate limit)
            if e.response and e.response.status_code == 403:
                # This should have been handled above, but just in case
                if not handle_rate_limit_error(e.response, MAX_RETRIES):
                    _handle_api_error(e, verify_ssl)
                continue
            _handle_api_error(e, verify_ssl)
        except requests.exceptions.RequestException as e:
            _handle_api_error(e, verify_ssl)
    
    return all_runs, last_response, hit_limit


def get_workflow_runs(
    owner: str,
    repo: str,
    token: str,
    days: int = DEFAULT_DAYS,
    per_page: int = DEFAULT_PER_PAGE,
    verify_ssl: Union[bool, str] = True
) -> List[Dict[str, Any]]:
    """
    Fetch workflow runs from GitHub API for the specified repository.
    Splits the date range into daily requests to avoid API limits.
    
    Args:
        owner: Repository owner (username or organization)
        repo: Repository name
        token: GitHub personal access token
        days: Number of days to look back (default: DEFAULT_DAYS)
        per_page: Number of results per page (max 100)
        verify_ssl: SSL verification setting. True (default) to verify,
                   False to disable (not recommended), or path to CA bundle file
    
    Returns:
        List of workflow run dictionaries
    """
    base_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/actions/runs"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {token}"
    }
    
    # Calculate the overall cutoff date
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
    
    logger.info(f"Fetching workflow runs from the last {days} days (since {cutoff_date.date()})...")
    logger.info(f"Splitting into {days} daily requests to avoid API limits...")
    
    all_runs: List[Dict[str, Any]] = []
    days_with_limits: List[datetime.date] = []
    last_response: Optional[requests.Response] = None
    daily_stats: Dict[datetime.date, int] = {}
    
    # Process each day separately (from most recent to oldest)
    for day_offset in range(days):
        # Calculate day boundaries (start of day to start of next day)
        # day_offset=0 is today, day_offset=1 is yesterday, etc.
        day_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ) - timedelta(days=day_offset)
        day_end = day_start + timedelta(days=1)
        
        # Don't go beyond the cutoff date
        if day_start < cutoff_date:
            day_start = cutoff_date
            if day_start >= day_end:
                # We've reached the cutoff, no need to process more days
                break
        
        day_runs, response, hit_limit = get_workflow_runs_for_day(
            owner, repo, token, day_start, day_end, per_page, verify_ssl, base_url, headers
        )
        
        all_runs.extend(day_runs)
        if response:
            last_response = response
        
        # Track statistics for this day
        day_date = day_start.date()
        daily_stats[day_date] = len(day_runs)
        
        if hit_limit:
            days_with_limits.append(day_date)
        
        logger.info(
            f"  Day {day_offset + 1}/{days} ({day_date}): "
            f"{len(day_runs)} runs (total: {len(all_runs)})"
        )
        
        # Small delay between days
        if day_offset < days - 1:
            time.sleep(DAY_DELAY)
    
    # Print warnings for days that hit the limit
    if days_with_limits:
        logger.warning(f"⚠️  WARNING: Hit {API_RESULT_LIMIT} result limit for {len(days_with_limits)} day(s):")
        for day in days_with_limits:
            logger.warning(f"   - {day}: Some workflow runs may be missing")
        logger.warning("   Consider using smaller time windows or check GitHub API documentation.")
    
    logger.info(f"Total workflow runs found: {len(all_runs)}")
    
    # Print statistics by day
    if daily_stats:
        _print_daily_statistics(daily_stats, days_with_limits)
    
    # Print final rate limit status
    if last_response:
        print_final_rate_limit(last_response)
    
    return all_runs


def _print_daily_statistics(
    daily_stats: Dict[datetime.date, int],
    days_with_limits: List[datetime.date]
) -> None:
    """
    Print statistics by day.
    
    Args:
        daily_stats: Dictionary mapping dates to run counts
        days_with_limits: List of dates that hit the API limit
    """
    logger.info("📊 Statistics by day:")
    logger.info(f"   {'Date':<12} {'Runs':<8} {'Status'}")
    logger.info(f"   {'-' * 12} {'-' * 8} {'-' * 20}")
    
    # Sort by date (most recent first)
    sorted_days = sorted(daily_stats.items(), reverse=True)
    for day_date, count in sorted_days:
        status = "⚠️  Limit hit" if day_date in days_with_limits else "✓"
        logger.info(f"   {day_date}    {count:<8} {status}")
    
    # Summary
    total_days = len(daily_stats)
    days_with_runs = sum(1 for count in daily_stats.values() if count > 0)
    max_runs_day = max(daily_stats.items(), key=lambda x: x[1]) if daily_stats else None
    avg_runs = sum(daily_stats.values()) / total_days if total_days > 0 else 0
    
    logger.info("   Summary:")
    logger.info(f"   - Days processed: {total_days}")
    logger.info(f"   - Days with runs: {days_with_runs}")
    if max_runs_day:
        logger.info(f"   - Busiest day: {max_runs_day[0]} ({max_runs_day[1]} runs)")
    logger.info(f"   - Average runs per day: {avg_runs:.1f}")


def filter_latest_runs_per_workflow(runs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filter runs to keep only the most recent run for each workflow.
    
    Args:
        runs: List of workflow run dictionaries from GitHub API
    
    Returns:
        List of dictionaries containing only the latest run for each workflow_id
    """
    if not runs:
        return []
    
    # Group runs by workflow_id
    workflows: Dict[int, Dict[str, Any]] = {}
    for run in runs:
        workflow_id = run.get("workflow_id")
        if workflow_id is None:
            continue
        
        created_at_str = run.get("created_at")
        if not created_at_str:
            continue
        
        # Parse created_at timestamp
        try:
            created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        
        # Keep the run with the most recent created_at for each workflow_id
        if workflow_id not in workflows:
            workflows[workflow_id] = run
        else:
            existing_created_at = datetime.fromisoformat(
                workflows[workflow_id]["created_at"].replace("Z", "+00:00")
            )
            if created_at > existing_created_at:
                workflows[workflow_id] = run
    
    latest_runs = list(workflows.values())
    logger.info(f"Filtered to {len(latest_runs)} latest runs (one per workflow)")
    return latest_runs


def extract_workflow_details(runs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """
    Extract useful details from workflow runs.
    
    Args:
        runs: List of workflow run dictionaries from GitHub API
    
    Returns:
        List of dictionaries with extracted details
    """
    details: List[Dict[str, str]] = []
    
    for run in runs:
        # Get workflow file path - it might be in 'path' field
        workflow_file = run.get("path", "N/A")
        if workflow_file == "N/A":
            # Try alternative field names
            workflow_file = run.get("workflow_file", run.get("workflow_path", "N/A"))
        
        head_sha = run.get("head_sha", "")
        commit_sha = head_sha[:8] if head_sha else "N/A"
        
        detail = {
            "workflow_name": run.get("name", "N/A"),
            "workflow_file": workflow_file,
            "workflow_url": run.get("html_url", "N/A"),
            "status": run.get("status", "N/A"),
            "conclusion": run.get("conclusion", "N/A"),
            "run_started_at": run.get("run_started_at", "N/A"),
            "branch": run.get("head_branch", "N/A"),
            "commit_sha": commit_sha,
            "event": run.get("event", "N/A"),
        }
        details.append(detail)
    
    return details


def save_to_csv(details: List[Dict[str, str]], filepath: str) -> None:
    """
    Save workflow run details to a CSV file.
    
    Args:
        details: List of dictionaries with workflow run details
        filepath: Full path to output CSV file (including directory)
    """
    if not details:
        logger.warning("No workflow runs to save.")
        return
    
    # Create directory if it doesn't exist
    directory = os.path.dirname(filepath)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    
    with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(details)
    
    logger.info(f"Saved {len(details)} workflow runs to {filepath}")


def _validate_arguments(args: argparse.Namespace) -> None:
    """
    Validate command-line arguments.
    
    Args:
        args: Parsed command-line arguments
    
    Raises:
        SystemExit: If validation fails
    """
    if not args.owner:
        logger.error("Repository owner is required. Use --owner or set GITHUB_OWNER env var.")
        sys.exit(1)
    
    if not args.repo:
        logger.error("Repository name is required. Use --repo or set GITHUB_REPO env var.")
        sys.exit(1)
    
    if not args.token:
        logger.error("GitHub token is required. Use --token or set GITHUB_TOKEN env var.")
        logger.error(f"You can create a token at: {GITHUB_TOKEN_URL}")
        sys.exit(1)


def _configure_ssl_verification(args: argparse.Namespace) -> Union[bool, str]:
    """
    Configure SSL verification based on command-line arguments.
    
    Args:
        args: Parsed command-line arguments
    
    Returns:
        SSL verification setting (True, False, or path to CA bundle)
    
    Raises:
        SystemExit: If both --no-ssl-verify and --ca-bundle are specified
    """
    if args.no_ssl_verify and args.ca_bundle:
        logger.error("Cannot use both --no-ssl-verify and --ca-bundle. Choose one.")
        sys.exit(1)
    
    verify_ssl = True
    if args.no_ssl_verify:
        verify_ssl = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.warning("SSL verification is disabled. Connection is not secure!")
        logger.warning(
            "This makes your connection insecure! Only use this option if you're "
            "behind a corporate VPN/proxy and understand the risks."
        )
    elif args.ca_bundle:
        if not os.path.exists(args.ca_bundle):
            logger.error(f"CA bundle file not found: {args.ca_bundle}")
            sys.exit(1)
        verify_ssl = args.ca_bundle
        logger.info(f"Using custom CA bundle: {args.ca_bundle}")
    
    return verify_ssl


def _determine_output_path(args: argparse.Namespace) -> str:
    """
    Determine the output file path based on command-line arguments.
    
    Args:
        args: Parsed command-line arguments
    
    Returns:
        Full path to output CSV file
    """
    if args.output is None:
        # Use default filename in output directory
        output_filename = f"{args.owner}_{args.repo}_runs.csv"
        return os.path.join(args.output_dir, output_filename)
    elif os.path.isabs(args.output):
        # User provided an absolute path, use it as-is
        return args.output
    elif os.path.dirname(args.output):
        # User provided a relative path with directory component, use it as-is
        return args.output
    else:
        # User provided just a filename, use it in the output directory
        return os.path.join(args.output_dir, args.output)


def _create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure the argument parser.
    
    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        description="Fetch GitHub Actions workflow runs from the last 2 weeks and save to CSV"
    )
    parser.add_argument(
        "--owner",
        type=str,
        help="Repository owner (username or organization)",
        default=os.getenv("GITHUB_OWNER")
    )
    parser.add_argument(
        "--repo",
        type=str,
        help="Repository name",
        default=os.getenv("GITHUB_REPO")
    )
    parser.add_argument(
        "--token",
        type=str,
        help="GitHub personal access token",
        default=os.getenv("GITHUB_TOKEN")
    )
    parser.add_argument(
        "--days",
        type=int,
        default=DEFAULT_DAYS,
        help=f"Number of days to look back (default: {DEFAULT_DAYS} for 2 weeks)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for CSV file (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output CSV filename (default: <owner>_<repo>_runs.csv). "
             "If a full path is provided, it overrides --output-dir"
    )
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification (use only if behind corporate VPN/proxy). "
             "WARNING: This makes connections insecure!"
    )
    parser.add_argument(
        "--ca-bundle",
        type=str,
        help="Path to custom CA bundle file for SSL verification (useful for corporate VPN/proxy)"
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)"
    )
    
    return parser


def main() -> None:
    """Main entry point for the script."""
    parser = _create_argument_parser()
    args = parser.parse_args()
    
    # Setup logging first
    setup_logging(args.log_level)
    
    # Configure SSL verification
    verify_ssl = _configure_ssl_verification(args)
    
    # Validate required arguments
    _validate_arguments(args)
    
    # Determine output file path
    output_path = _determine_output_path(args)
    
    # Fetch workflow runs
    runs = get_workflow_runs(
        args.owner, args.repo, args.token, args.days, verify_ssl=verify_ssl
    )
    
    # Filter to keep only the latest run for each workflow
    runs = filter_latest_runs_per_workflow(runs)
    
    # Extract details
    details = extract_workflow_details(runs)
    
    # Save to CSV
    save_to_csv(details, output_path)


if __name__ == "__main__":
    main()
