## Usage

This repository includes a standalone script **`check_vulns.py`** (located at the
project root). The script is completely self-contained and declares its own
runtime requirements via *inline* metadata that `uv` understands, so **there is
no separate `requirements.txt` or virtual-environment setup needed**.

### 1. Installation

`uv` is a modern, ultra-fast package & project manager written in Rust. Install
it once and reuse it across all your Python projects:

```bash
# macOS (Homebrew)
brew install uv

# Or, platform-agnostic install script
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Verify the installation:

```bash
uv --version
```

You can then run

```bash
uv tool install "dependabot-check @ git+https://github.com/YBadiss/dependabot-check"
```

to install the checker as a standalone script that can be run using `dependabot-check ...`.

### 2. Run the vulnerability check

Simply point the script at the Dependabot JSON export and a JSON map of the
currently installed package versions:

```bash
uv run check_vulns.py \
  --dependabot dependabot_output_example.json \
  --installed installed_versions_example.json \
  --output vulns_to_fix.json
```

The script will:

1. Create (or reuse) an isolated virtual environment managed by `uv`.
2. Install the single runtime dependency (`packaging`) declared inside the
   script itself.
3. Filter the Dependabot alerts such that **only** vulnerabilities that meet
   all **three** criteria remain:

   - alert **state** is `open`
   - **severity** is `high` or `critical`
   - the vulnerable package **version** is **still installed** in the local
     environment

4. Write the resulting list to `vulns_to_fix.json` (or `STDOUT` if
   `--output` is omitted).

### 3. Automating in CI / shell scripts

You can wire the tool into a Bash conditional to **fail** a pipeline when
critical/high vulnerabilities are still present:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Assuming the JSON files are already generated in your CI workspace
alerts_json=dependabot_alerts.json
installed_json=installed_versions.json

# Count how many actionable vulns remain
vuln_count=$(dependabot-check \
  --dependabot "$alerts_json" \
  --installed "$installed_json" | jq 'length')

if [ "$vuln_count" -gt 0 ]; then
  echo "❌ $vuln_count unresolved high/critical vulnerabilities detected!"
  exit 1
else
  echo "✅ No unresolved high/critical vulnerabilities."
fi
```

Explanation:

* `dependabot-check` outputs a JSON array of the remaining alerts.
* `jq 'length'` returns the number of elements in that array.
* The script exits with **non-zero** status when vulnerabilities remain, causing
  the CI job to fail.

If you don't have `jq` available, you could use a simple `grep` fallback:

```bash
if dependabot-check --dependabot "$alerts_json" --installed "$installed_json" | grep -q "\["; then
  echo "vulnerabilities present"
  exit 1
fi
```

### 4. Generating `installed_versions.json`

`dependabot-check` expects a simple JSON object mapping **package names → version strings**. Below are reference commands for the most common ecosystems. Each pipe uses `jq` to transform the tool's native JSON into the required flat object.

> Feel free to adjust depth flags (`--depth`) or filters depending on your repo layout.

#### a. Python (pip / uv)

```bash
# Using uv (preferred – falls back to pip under the hood)
uv pip list --format=json \
  | jq -r 'map({ (.name): .version }) | add' \
  > installed_versions.json
```

#### b. npm (JavaScript / TypeScript)

```bash
# Capture only top-level production deps; omit --depth=0 to include transitive ones
npm ls --json --depth=0 \
  | jq '.dependencies | map_values(.version)' \
  > installed_versions.json
```

If you're using **pnpm** or **yarn**:

```bash
pnpm list --json --depth=0 | jq '.[0].dependencies | map_values(.version)' > installed_versions.json
```

#### c. Go modules

```bash
# Collect all modules (main + dependencies)
go list -m -json all \
  | jq -s 'map({ (.Path): .Version }) | add' \
  > installed_versions.json
```

Once you have the file, run the checker as shown earlier.
