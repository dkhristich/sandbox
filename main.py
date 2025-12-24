#!/usr/bin/env python3
"""
Script to fetch GitHub Actions workflow runs from the last 2 weeks and save to CSV.
"""

import os
import sys
import csv
import requests
import time
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Union
import argparse
import warnings


def check_rate_limit(response: requests.Response) -> None:
    """
    Check and display rate limit information from GitHub API response headers.
    
    Args:
        response: Response object from GitHub API
    """
    try:
        rate_limit = response.headers.get("X-RateLimit-Limit")
        rate_remaining = response.headers.get("X-RateLimit-Remaining")
        rate_reset = response.headers.get("X-RateLimit-Reset")
    except (AttributeError, TypeError):
        # Headers might not be available (e.g., in tests with incomplete mocks)
        return
    
    if rate_limit and rate_remaining:
        try:
            remaining = int(rate_remaining)
            limit = int(rate_limit)
        except (ValueError, TypeError):
            # Headers might not be valid integers (e.g., Mock objects in tests)
            return
        percentage = (remaining / limit) * 100
        
        # Warn if we're running low on rate limit
        if percentage < 20:
            print(f"⚠️  Rate limit warning: {remaining}/{limit} requests remaining ({percentage:.1f}%)", file=sys.stderr)
        
        # Show rate limit info every 10 pages or when low
        if remaining < 100 or (int(rate_remaining) % 100 == 0 and remaining < limit):
            reset_time = None
            if rate_reset:
                try:
                    reset_timestamp = int(rate_reset)
                    reset_time = datetime.fromtimestamp(reset_timestamp, tz=timezone.utc)
                    reset_str = reset_time.strftime("%Y-%m-%d %H:%M:%S UTC")
                    print(f"Rate limit: {remaining}/{limit} remaining (resets at {reset_str})")
                except (ValueError, OSError):
                    pass


def print_final_rate_limit(response: requests.Response) -> None:
    """
    Print the final rate limit status at the end of execution.
    
    Args:
        response: Last response object from GitHub API
    """
    try:
        rate_limit = response.headers.get("X-RateLimit-Limit")
        rate_remaining = response.headers.get("X-RateLimit-Remaining")
        rate_reset = response.headers.get("X-RateLimit-Reset")
    except (AttributeError, TypeError):
        return
    
    if rate_limit and rate_remaining:
        try:
            remaining = int(rate_remaining)
            limit = int(rate_limit)
            used = limit - remaining
            percentage = (remaining / limit) * 100
        except (ValueError, TypeError):
            return
        
        reset_str = "N/A"
        if rate_reset:
            try:
                reset_timestamp = int(rate_reset)
                reset_time = datetime.fromtimestamp(reset_timestamp, tz=timezone.utc)
                reset_str = reset_time.strftime("%Y-%m-%d %H:%M:%S UTC")
            except (ValueError, OSError):
                pass
        
        print(f"\n📊 Final rate limit status: {remaining}/{limit} remaining ({used} used, {percentage:.1f}% remaining)")
        if reset_str != "N/A":
            print(f"   Rate limit resets at: {reset_str}")


def handle_rate_limit_error(response: requests.Response, max_retries: int = 3) -> bool:
    """
    Handle rate limit errors (HTTP 403) by waiting for the rate limit to reset.
    
    Args:
        response: Response object from GitHub API with 403 status
        max_retries: Maximum number of retries (default: 3)
    
    Returns:
        True if we should retry, False otherwise
    """
    if response.status_code != 403:
        return False
    
    rate_reset = response.headers.get("X-RateLimit-Reset")
    if not rate_reset:
        print("Rate limit exceeded, but reset time not available. Waiting 60 seconds...", file=sys.stderr)
        time.sleep(60)
        return True
    
    try:
        reset_timestamp = int(rate_reset)
        reset_time = datetime.fromtimestamp(reset_timestamp, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        wait_seconds = max(0, int((reset_timestamp - now.timestamp())) + 1)
        
        if wait_seconds > 0:
            reset_str = reset_time.strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"\n⏳ Rate limit exceeded. Waiting until {reset_str} ({wait_seconds} seconds)...", file=sys.stderr)
            
            # Show progress for long waits
            if wait_seconds > 60:
                while wait_seconds > 0:
                    mins, secs = divmod(wait_seconds, 60)
                    if wait_seconds % 60 == 0 or wait_seconds == 1:
                        print(f"   Waiting... {mins}m {secs}s remaining", file=sys.stderr)
                    time.sleep(min(60, wait_seconds))
                    wait_seconds = max(0, wait_seconds - 60)
            else:
                time.sleep(wait_seconds)
            
            print("✅ Rate limit reset. Retrying...", file=sys.stderr)
            return True
    except (ValueError, OSError) as e:
        print(f"Error parsing rate limit reset time: {e}. Waiting 60 seconds...", file=sys.stderr)
        time.sleep(60)
        return True
    
    return False


def get_workflow_runs(
    owner: str,
    repo: str,
    token: str,
    days: int = 14,
    per_page: int = 100,
    verify_ssl: Union[bool, str] = True
) -> List[Dict]:
    """
    Fetch workflow runs from GitHub API for the specified repository.
    
    Args:
        owner: Repository owner (username or organization)
        repo: Repository name
        token: GitHub personal access token
        days: Number of days to look back (default: 14 for 2 weeks)
        per_page: Number of results per page (max 100)
        verify_ssl: SSL verification setting. True (default) to verify,
                   False to disable (not recommended), or path to CA bundle file
    
    Returns:
        List of workflow run dictionaries
    """
    base_url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {token}"
    }
    
    # Calculate the date 2 weeks ago
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
    cutoff_iso = cutoff_date.isoformat().replace("+00:00", "Z")
    
    all_runs = []
    page = 1
    retry_count = 0
    max_retries = 3
    next_url = None  # Will be set from Link header
    last_response = None  # Store last successful response for final rate limit check
    
    print(f"Fetching workflow runs from the last {days} days (since {cutoff_date.date()})...")
    
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
                "created": f">={cutoff_iso}"
            }
        
        try:
            response = requests.get(url, headers=headers, params=params, verify=verify_ssl)
            
            # Check rate limit status
            check_rate_limit(response)
            
            # Handle rate limit errors (403)
            if response.status_code == 403:
                if handle_rate_limit_error(response, max_retries):
                    retry_count += 1
                    if retry_count > max_retries:
                        print("Max retries exceeded for rate limit. Exiting.", file=sys.stderr)
                        sys.exit(1)
                    # Retry the same request
                    continue
                else:
                    print("Rate limit error could not be resolved. Exiting.", file=sys.stderr)
                    sys.exit(1)
            
            # Raise for other HTTP errors
            response.raise_for_status()
            retry_count = 0  # Reset retry count on success
            last_response = response  # Store last successful response
            
            data = response.json()
            
            runs = data.get("workflow_runs", [])
            if not runs:
                break
            
            # Filter runs that are actually within our date range
            filtered_runs = []
            for run in runs:
                created_at = datetime.fromisoformat(
                    run["created_at"].replace("Z", "+00:00")
                )
                if created_at >= cutoff_date:
                    filtered_runs.append(run)
            
            all_runs.extend(filtered_runs)
            
            # Check for next page using Link header (GitHub's recommended pagination method)
            next_url = None
            # Try using response.links (requests library parses Link headers automatically)
            if hasattr(response, 'links') and response.links:
                next_link = response.links.get('next')
                if next_link:
                    next_url = next_link.get('url')
            # Fallback: manually parse Link header if response.links is not available
            elif 'Link' in response.headers:
                import re
                link_header = response.headers.get('Link', '')
                # Parse Link header: <url>; rel="next"
                next_match = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
                if next_match:
                    next_url = next_match.group(1)
            
            # If no next link and we got fewer results than per_page, we're on the last page
            if not next_url and len(runs) < per_page:
                break
            
            # If no next link and we've hit exactly 1000 results, check if we need to continue
            # GitHub API may limit results to 1000, but we should try to get more by narrowing date range
            if not next_url and len(all_runs) >= 1000:
                # Check if we've actually reached the cutoff date
                if filtered_runs:
                    oldest_run = min(
                        datetime.fromisoformat(r["created_at"].replace("Z", "+00:00"))
                        for r in filtered_runs
                    )
                    if oldest_run >= cutoff_date:
                        # We hit 1000 results but haven't reached the cutoff date yet
                        print(f"⚠️  Warning: Fetched {len(all_runs)} runs. "
                              f"GitHub API may limit results to 1000 per query. "
                              f"Consider using a shorter --days period to get all runs.", file=sys.stderr)
                break
            
            # If the oldest run is before our cutoff, we can stop
            oldest_run = min(
                datetime.fromisoformat(r["created_at"].replace("Z", "+00:00"))
                for r in filtered_runs
            ) if filtered_runs else None
            
            if oldest_run and oldest_run < cutoff_date:
                break
            
            # If no next URL, increment page number for fallback
            if not next_url:
                page += 1
            else:
                page += 1  # Keep track for logging
            
            print(f"Fetched page {page - 1}, total runs so far: {len(all_runs)}")
            
            # Small delay to avoid hitting rate limits too quickly
            time.sleep(0.1)
            
        except requests.exceptions.SSLError as e:
            print(f"SSL Error: {e}", file=sys.stderr)
            print("\nIf you're behind a corporate VPN/proxy, try one of these options:", file=sys.stderr)
            print("  1. Use --no-ssl-verify (WARNING: insecure, use only if necessary)", file=sys.stderr)
            print("  2. Use --ca-bundle <path> to specify your corporate CA certificate", file=sys.stderr)
            print("  3. Export REQUESTS_CA_BUNDLE environment variable pointing to your CA bundle", file=sys.stderr)
            sys.exit(1)
        except requests.exceptions.HTTPError as e:
            # Handle other HTTP errors (not rate limit)
            if e.response and e.response.status_code == 403:
                # This should have been handled above, but just in case
                if not handle_rate_limit_error(e.response, max_retries):
                    print(f"HTTP Error {e.response.status_code}: {e}", file=sys.stderr)
                    if hasattr(e.response, 'text'):
                        print(f"Response: {e.response.text}", file=sys.stderr)
                    sys.exit(1)
                continue
            else:
                print(f"HTTP Error: {e}", file=sys.stderr)
                if hasattr(e, 'response') and e.response is not None:
                    if hasattr(e.response, 'text'):
                        print(f"Response: {e.response.text}", file=sys.stderr)
                sys.exit(1)
        except requests.exceptions.RequestException as e:
            print(f"Error fetching workflow runs: {e}", file=sys.stderr)
            if hasattr(e, 'response') and e.response is not None:
                if hasattr(e.response, 'text'):
                    print(f"Response: {e.response.text}", file=sys.stderr)
            sys.exit(1)
    
    print(f"Total workflow runs found: {len(all_runs)}")
    
    # Print final rate limit status
    if last_response:
        print_final_rate_limit(last_response)
    
    return all_runs


def filter_latest_runs_per_workflow(runs: List[Dict]) -> List[Dict]:
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
    workflows = {}
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
    print(f"Filtered to {len(latest_runs)} latest runs (one per workflow)")
    return latest_runs


def extract_workflow_details(runs: List[Dict]) -> List[Dict]:
    """
    Extract useful details from workflow runs.
    
    Args:
        runs: List of workflow run dictionaries from GitHub API
    
    Returns:
        List of dictionaries with extracted details
    """
    details = []
    
    for run in runs:
        # Get workflow file path - it might be in 'path' field
        workflow_file = run.get("path", "N/A")
        if workflow_file == "N/A":
            # Try alternative field names
            workflow_file = run.get("workflow_file", run.get("workflow_path", "N/A"))
        
        detail = {
            "workflow_name": run.get("name", "N/A"),
            "workflow_file": workflow_file,
            "workflow_url": run.get("html_url", "N/A"),
            "status": run.get("status", "N/A"),
            "conclusion": run.get("conclusion", "N/A"),
            "run_started_at": run.get("run_started_at", "N/A"),
            "branch": run.get("head_branch", "N/A"),
            "commit_sha": run.get("head_sha", "N/A")[:8] if run.get("head_sha") else "N/A",
            "event": run.get("event", "N/A"),
        }
        details.append(detail)
    
    return details


def save_to_csv(details: List[Dict], filepath: str = "workflow_runs.csv"):
    """
    Save workflow run details to a CSV file.
    
    Args:
        details: List of dictionaries with workflow run details
        filepath: Full path to output CSV file (including directory)
    """
    if not details:
        print("No workflow runs to save.")
        return
    
    # Create directory if it doesn't exist
    directory = os.path.dirname(filepath)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    
    fieldnames = [
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
    
    with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(details)
    
    print(f"Saved {len(details)} workflow runs to {filepath}")


def main():
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
        default=14,
        help="Number of days to look back (default: 14 for 2 weeks)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./output",
        help="Output directory for CSV file (default: ./output)"
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
    
    args = parser.parse_args()
    
    # Handle SSL verification
    if args.no_ssl_verify and args.ca_bundle:
        print("Error: Cannot use both --no-ssl-verify and --ca-bundle. Choose one.", file=sys.stderr)
        sys.exit(1)
    
    verify_ssl = True
    if args.no_ssl_verify:
        verify_ssl = False
        warnings.warn(
            "SSL verification is disabled. This makes your connection insecure! "
            "Only use this option if you're behind a corporate VPN/proxy and understand the risks.",
            UserWarning
        )
        print("WARNING: SSL verification is disabled. Connection is not secure!", file=sys.stderr)
    elif args.ca_bundle:
        if not os.path.exists(args.ca_bundle):
            print(f"Error: CA bundle file not found: {args.ca_bundle}", file=sys.stderr)
            sys.exit(1)
        verify_ssl = args.ca_bundle
        print(f"Using custom CA bundle: {args.ca_bundle}")
    
    # Validate required arguments
    if not args.owner:
        print("Error: Repository owner is required. Use --owner or set GITHUB_OWNER env var.", file=sys.stderr)
        sys.exit(1)
    
    if not args.repo:
        print("Error: Repository name is required. Use --repo or set GITHUB_REPO env var.", file=sys.stderr)
        sys.exit(1)
    
    if not args.token:
        print("Error: GitHub token is required. Use --token or set GITHUB_TOKEN env var.", file=sys.stderr)
        print("You can create a token at: https://github.com/settings/tokens", file=sys.stderr)
        sys.exit(1)
    
    # Determine output file path
    if args.output is None:
        # Use default filename in output directory
        output_filename = f"{args.owner}_{args.repo}_runs.csv"
        output_path = os.path.join(args.output_dir, output_filename)
    elif os.path.isabs(args.output):
        # User provided an absolute path, use it as-is
        output_path = args.output
    elif os.path.dirname(args.output):
        # User provided a relative path with directory component, use it as-is
        output_path = args.output
    else:
        # User provided just a filename, use it in the output directory
        output_path = os.path.join(args.output_dir, args.output)
    
    # Fetch workflow runs
    runs = get_workflow_runs(args.owner, args.repo, args.token, args.days, verify_ssl=verify_ssl)
    
    # Filter to keep only the latest run for each workflow
    runs = filter_latest_runs_per_workflow(runs)
    
    # Extract details
    details = extract_workflow_details(runs)
    
    # Save to CSV
    save_to_csv(details, output_path)


if __name__ == "__main__":
    main()

