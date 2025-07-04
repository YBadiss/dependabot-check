Python script using `uv` that uses Dependabot's output + a list of installed packages to conclude if any vulnerabilities are being fixed.

- the vulns must be `open`
- the vulns must be `critical` or `high`
- output a new list of the vulns that are in the dependabot output, and still present in the installed versions

## Usage

This repository includes a standalone script **`check_vulns.py`** (located at the
project root). The script is completely self-contained and declares its own
runtime requirements via *inline* metadata that `uv` understands, so **there is
no separate `requirements.txt` or virtual-environment setup needed**.

### 1. Install `uv`

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

### 3. Make it executable (optional)

If you prefer a direct command (no `uv run` prefix), give the file an executable
bit and call it like any regular CLI tool:

```bash
chmod +x check_vulns.py
./check_vulns.py --dependabot my_alerts.json --installed my_versions.json
```

The shebang at the top of the script will ensure `uv` still manages the runtime
environment transparently.