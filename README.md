# sandbox

## GitHub Actions Workflow Runs Exporter

This script fetches GitHub Actions workflow runs from the last 2 weeks (or custom period) and exports them to a CSV file.

### Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Get a GitHub Personal Access Token:
   - Go to https://github.com/settings/tokens
   - Generate a new token with `repo` scope (or `public_repo` for public repositories)

### Usage

#### Using command-line arguments:
```bash
python main.py --owner <owner> --repo <repo> --token <token>
```

#### Using environment variables:
```bash
export GITHUB_OWNER="your-username"
export GITHUB_REPO="your-repo"
export GITHUB_TOKEN="your-token"
python main.py
```

#### Custom options:
```bash
# Look back 7 days instead of 14
python main.py --owner <owner> --repo <repo> --token <token> --days 7

# Custom output filename (saved to ./output directory by default)
python main.py --owner <owner> --repo <repo> --token <token> --output my_workflows.csv

# Custom output directory
python main.py --owner <owner> --repo <repo> --token <token> --output-dir ./my_reports

# Custom output directory and filename
python main.py --owner <owner> --repo <repo> --token <token> --output-dir ./reports --output custom.csv

# Absolute or relative path (overrides --output-dir)
python main.py --owner <owner> --repo <repo> --token <token> --output /absolute/path/to/file.csv
python main.py --owner <owner> --repo <repo> --token <token> --output subdir/file.csv

# Behind corporate VPN/proxy with SSL issues
# Option 1: Disable SSL verification (NOT RECOMMENDED, use only if necessary)
python main.py --owner <owner> --repo <repo> --token <token> --no-ssl-verify

# Option 2: Use custom CA bundle (RECOMMENDED for corporate environments)
python main.py --owner <owner> --repo <repo> --token <token> --ca-bundle /path/to/ca-bundle.crt
```

### Output

The script generates a CSV file in the `./output` directory by default. The default filename is `<owner>_<repo>_runs.csv` (e.g., `octocat_hello-world_runs.csv`). The output directory is created automatically if it doesn't exist.

**Output file location:**
- Default: `./output/<owner>_<repo>_runs.csv`
- Use `--output-dir` to change the output directory
- Use `--output` to specify a custom filename (or full path to override directory)

The CSV file contains the following columns:
- `workflow_name`: Name of the workflow
- `workflow_id`: Workflow ID
- `run_id`: Unique run ID
- `run_number`: Run number for the workflow
- `status`: Current status (queued, in_progress, completed)
- `conclusion`: Conclusion (success, failure, cancelled, etc.)
- `created_at`: When the run was created
- `updated_at`: When the run was last updated
- `run_started_at`: When the run actually started
- `actor`: User who triggered the run
- `branch`: Branch name
- `commit_sha`: First 8 characters of commit SHA
- `commit_message`: Commit message (first line)
- `event`: Event that triggered the workflow (push, pull_request, etc.)
- `workflow_url`: URL to view the workflow run on GitHub

### Troubleshooting SSL/TLS Issues

If you encounter SSL certificate verification errors (common when behind corporate VPN/proxy):

1. **Best practice**: Use a custom CA bundle file:
   ```bash
   python main.py --owner <owner> --repo <repo> --token <token> --ca-bundle /path/to/your-ca-bundle.crt
   ```
   You can usually find your corporate CA certificate in your system's certificate store or from your IT department.

2. **Alternative** (not recommended): Disable SSL verification:
   ```bash
   python main.py --owner <owner> --repo <repo> --token <token> --no-ssl-verify
   ```
   ⚠️ **Warning**: This makes your connection insecure. Only use if absolutely necessary.

3. **Environment variable**: You can also set `REQUESTS_CA_BUNDLE` environment variable:
   ```bash
   export REQUESTS_CA_BUNDLE=/path/to/your-ca-bundle.crt
   python main.py --owner <owner> --repo <repo> --token <token>
   ```

### Testing

Run the test suite with pytest:

```bash
pytest test_main.py -v
```

Or with coverage:

```bash
pytest test_main.py --cov=main --cov-report=html
```

The test suite includes:
- Unit tests for `extract_workflow_details` function
- Unit tests for `save_to_csv` function
- Mocked API tests for `get_workflow_runs` function
- Integration tests for the `main` function
- Tests for error handling and edge cases
