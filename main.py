#!/usr/bin/env python3
"""
Script to fetch GitHub Actions workflow runs from the last 2 weeks and save to CSV.
"""

import os
import sys
import csv
import requests
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Union
import argparse
import warnings


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
    
    print(f"Fetching workflow runs from the last {days} days (since {cutoff_date.date()})...")
    
    while True:
        params = {
            "per_page": per_page,
            "page": page,
            "created": f">={cutoff_iso}"
        }
        
        try:
            response = requests.get(base_url, headers=headers, params=params, verify=verify_ssl)
            response.raise_for_status()
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
            
            # If we got fewer results than per_page, we're on the last page
            if len(runs) < per_page:
                break
            
            # If the oldest run is before our cutoff, we can stop
            oldest_run = min(
                datetime.fromisoformat(r["created_at"].replace("Z", "+00:00"))
                for r in filtered_runs
            ) if filtered_runs else None
            
            if oldest_run and oldest_run < cutoff_date:
                break
            
            page += 1
            print(f"Fetched page {page - 1}, total runs so far: {len(all_runs)}")
            
        except requests.exceptions.SSLError as e:
            print(f"SSL Error: {e}", file=sys.stderr)
            print("\nIf you're behind a corporate VPN/proxy, try one of these options:", file=sys.stderr)
            print("  1. Use --no-ssl-verify (WARNING: insecure, use only if necessary)", file=sys.stderr)
            print("  2. Use --ca-bundle <path> to specify your corporate CA certificate", file=sys.stderr)
            print("  3. Export REQUESTS_CA_BUNDLE environment variable pointing to your CA bundle", file=sys.stderr)
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            print(f"Error fetching workflow runs: {e}", file=sys.stderr)
            if hasattr(e, 'response') and e.response is not None:
                if hasattr(e.response, 'text'):
                    print(f"Response: {e.response.text}", file=sys.stderr)
            sys.exit(1)
    
    print(f"Total workflow runs found: {len(all_runs)}")
    return all_runs


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
        detail = {
            "workflow_name": run.get("name", "N/A"),
            "workflow_id": run.get("workflow_id", "N/A"),
            "run_id": run.get("id", "N/A"),
            "run_number": run.get("run_number", "N/A"),
            "status": run.get("status", "N/A"),
            "conclusion": run.get("conclusion", "N/A"),
            "created_at": run.get("created_at", "N/A"),
            "updated_at": run.get("updated_at", "N/A"),
            "run_started_at": run.get("run_started_at", "N/A"),
            "actor": run.get("actor", {}).get("login", "N/A") if run.get("actor") else "N/A",
            "branch": run.get("head_branch", "N/A"),
            "commit_sha": run.get("head_sha", "N/A")[:8] if run.get("head_sha") else "N/A",
            "commit_message": run.get("head_commit", {}).get("message", "N/A").split("\n")[0] if run.get("head_commit", {}).get("message") else "N/A",
            "event": run.get("event", "N/A"),
            "workflow_url": run.get("html_url", "N/A"),
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
        "workflow_id",
        "run_id",
        "run_number",
        "status",
        "conclusion",
        "created_at",
        "updated_at",
        "run_started_at",
        "actor",
        "branch",
        "commit_sha",
        "commit_message",
        "event",
        "workflow_url"
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
    
    # Extract details
    details = extract_workflow_details(runs)
    
    # Save to CSV
    save_to_csv(details, output_path)


if __name__ == "__main__":
    main()

