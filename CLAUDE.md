# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python utility that filters Dependabot alerts to show only **open high/critical vulnerabilities** that are **currently installed** in your project. The script is designed to be self-contained and can run with just `uv` (or plain Python).

## Key Architecture

### Core Components

- `check_vulns.py` - Main script that serves as both a standalone executable and importable module
- Uses `packaging` library for version comparison and specifier parsing
- Auto-detects project type (Node.js, Go, Python) and collects installed package versions
- Fetches Dependabot alerts via GitHub API (with fallback from `gh` CLI to raw HTTP)

### Data Flow

1. **Alert Collection**: Fetches open Dependabot alerts from GitHub API or reads from file
2. **Version Detection**: Auto-detects repository type and collects installed package versions
3. **Filtering**: Applies severity (high/critical) and installation status filters
4. **Output**: Returns JSON array of actionable vulnerabilities

### Key Classes

- `AlertInfo` (check_vulns.py:176) - Dataclass containing essential alert fields (state, package_name, severity, vulnerable_version_range)

### Multi-Language Support

The script automatically detects and handles:
- **Node.js**: Uses `npm ls --all --json` and recursively walks dependency tree
- **Go**: Uses `go list -m -json all` to collect module versions  
- **Python**: Falls back when no other project type detected

## Development Commands

### Running the Script
```bash
# Direct execution with uv (auto-detects repo from Git)
uv run check_vulns.py

# With specific options
uv run check_vulns.py --dependabot-alerts alerts.json --installed-packages packages.json

# Check improvement mode
uv run check_vulns.py --check-improvement

# Install as global CLI tool
uv tool install "dependabot-check @ git+https://github.com/YBadiss/dependabot-check"
```

### Testing
```bash
# Run tests (using pytest)
pytest tests/

# Run specific test file
pytest tests/test_check_vulns.py
```

### Code Quality
```bash
# Format and lint code
ruff check .
ruff format .
```

## Environment Variables

- `GH_TOKEN` - GitHub token with `security_events:read` scope (required for API access)

## Key Arguments

- `--repo` - GitHub repository (auto-detected from Git if omitted)
- `--dependabot-alerts` - Path to Dependabot alerts JSON file
- `--installed-packages` - Path to installed packages JSON file
- `--check-improvement` - Success mode: compares total Dependabot alerts vs installed vulnerabilities
- `--output` - Output file path

## File Structure

- `check_vulns.py` - Main executable script with inline dependencies
- `tests/test_check_vulns.py` - Unit tests for filtering logic  
- `pyproject.toml` - Project metadata and dependencies
- `uv.lock` - Dependency lock file
- Example files: `dependabot_output_example.json`, `installed_versions_example.json`