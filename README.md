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
# GH_TOKEN and GH_REPO must be set (see below)
dependabot-check
```

Behaviour:
1. Fetches all **open** Dependabot alerts for `$GH_REPO` using the GitHub API.
2. Detects the project type (Node, Go, or Python) and gathers installed versions.
3. Prints a JSON array of actionable alerts to STDOUT.

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
| `--dependabot` | optional  | Path to Dependabot alerts export. If omitted the script fetches alerts via the GitHub API, which requires `GH_TOKEN` & `GH_REPO`. |
| `--installed`  | optional  | JSON mapping of `<package>: <version>`. If omitted the script auto-detects the repository type and collects versions itself. |
| `--output`     | optional  | Write filtered alerts to this file instead of STDOUT.                     |

---

## Environment variables (for API fetch)

| Variable   | Description                                    |
|------------|------------------------------------------------|
| `GH_TOKEN` | GitHub token with `security_events:read` scope. |
| `GH_REPO`  | Repository in `owner/name` form.               |

If the GitHub CLI (`gh`) is available the script will prefer it; otherwise it falls back to a raw HTTPS request.

---

## CI example – fail pipeline on remaining vulns

```bash
set -euo pipefail

# Fetch alerts directly via API and let the script auto-detect installed pkgs
vuln_count=$(dependabot-check | jq 'length')

if [ "$vuln_count" -gt 0 ]; then
  echo "❌ $vuln_count unresolved high/critical vulnerabilities detected!"
  exit 1
else
  echo "✅ No unresolved high/critical vulnerabilities."
fi
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
