# dependabot-check

A lightweight utility that filters Dependabot alerts so you only see **open** vulnerabilities that are **high/critical _and_ still installed** in your project.

The script is self-contained and declares its single runtime dependency inline, so you can run it with nothing but `uv` (or plain `python`).

---

## Installation

```bash
# Homebrew (macOS) – recommended
brew install uv

# Or universal install script
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Run directly from the repo:

```bash
uv run check_vulns.py [options]
```

Or install globally as a CLI:

```bash
uv tool install "dependabot-check @ git+https://github.com/YBadiss/dependabot-check"
```

---

## Usage

### Minimal – fully automatic

```bash
# GH_TOKEN must be set (see below)
dependabot-check
```

Behaviour:
1. Auto-detects the GitHub repository from Git remote origin.
2. Fetches all **open** Dependabot alerts for the repository using the GitHub API.
3. Detects the project type (Node, Go, or Python) and gathers installed versions.
4. Prints a JSON array of actionable alerts to STDOUT.

### Explicit file input

```bash
dependabot-check \
  --dependabot dependabot_alerts.json \
  --installed installed_versions.json \
  --output vulns_to_fix.json
```

### Command-line reference

| Option         | Required? | Description                                                               |
|----------------|-----------|---------------------------------------------------------------------------|
| `--repo`             | optional | GitHub repository in `owner/name` format. If omitted, auto-detects from Git remote origin. |
| `--dependabot-alerts` | optional  | Path to Dependabot alerts export. If omitted the script fetches alerts via the GitHub API, which requires `GH_TOKEN`. |
| `--installed-packages` | optional  | JSON mapping of `<package>: <version>`. If omitted the script auto-detects the repository type and collects versions itself. |
| `--output`           | optional  | Write filtered alerts to this file instead of STDOUT.                     |
| `--check-improvement` | optional  | Success mode: exit with code 0 if installed packages have fewer vulnerabilities than total Dependabot alerts, 1 otherwise. |

---

## Environment variables (for API fetch)

| Variable   | Description                                    |
|------------|------------------------------------------------|
| `GH_TOKEN` | GitHub token with `security_events:read` scope. |

If the GitHub CLI (`gh`) is available the script will prefer it; otherwise it falls back to a raw HTTPS request.

---

## CI example – fail pipeline on remaining vulns

```bash
set -euo pipefail

# Fetch alerts directly via API and let the script auto-detect installed pkgs
vuln_count=$(dependabot-check --repo owner/name | jq 'length')

if [ "$vuln_count" -gt 0 ]; then
  echo "❌ $vuln_count unresolved high/critical vulnerabilities detected!"
  exit 1
else
  echo "✅ No unresolved high/critical vulnerabilities."
fi
```

### Success mode – check improvement

```bash
# Check if installed packages have fewer vulnerabilities than Dependabot reports
dependabot-check --check-improvement

# This compares:
# - Total high/critical open Dependabot alerts
# - vs. How many of those actually affect installed packages
# Success = fewer installed vulnerabilities than total alerts
```

---

## Manual helpers for `--installed`

If you prefer to supply `--installed` yourself, here are handy one-liners that produce the expected JSON object:

### Python (pip / uv)

```bash
uv pip list --format=json \
  | jq -r 'map({ (.name): .version }) | add' > installed_versions.json
```

### Node (npm)

```bash
npm ls --all --json \
  | jq 'def rec: (.dependencies? // {}) | to_entries | map({ (.key): .value.version } + (.value | rec)) | add; rec' \
  > installed_versions.json
```

### Go modules

```bash
go list -m -json all \
  | jq -s 'map({ (.Path): .Version }) | add' > installed_versions.json
```

---

Made with ❤️ to keep your dependencies healthy.
