#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "packaging>=23.0",
# ]
# ///
"""check_vulns.py

Filter Dependabot alerts to find high/critical open vulnerabilities that are still
present in the currently installed package versions.

Usage
-----
    uv run check_vulns.py --dependabot dependabot_output.json \
                          --installed installed_versions.json \
                          --output filtered.json

If --output is omitted, the filtered list is printed to STDOUT as JSON.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List
from dataclasses import dataclass
import subprocess
import shutil

from packaging.specifiers import SpecifierSet
from packaging.version import Version, InvalidVersion


SEVERITY_LEVELS = {"high", "critical"}


def _load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        sys.exit(f"[error] File not found: {path}")
    except json.JSONDecodeError as exc:
        sys.exit(f"[error] Failed to parse JSON in {path}: {exc}")


def _normalize_specifier(raw_range: str) -> str:
    """Convert GitHub's vulnerable_version_range to PEP 440 specifier format."""
    # Remove spaces to turn '>= 1.0.0, < 2.0.0' -> '>=1.0.0,<2.0.0'
    return raw_range.replace(" ", "")


def _is_version_vulnerable(version_str: str, vulnerable_range: str) -> bool:
    """Return True if *version_str* falls within *vulnerable_range*."""
    try:
        version = Version(version_str)
    except InvalidVersion:
        # Treat unparsable versions as vulnerable (conservative default)
        return True

    spec = SpecifierSet(_normalize_specifier(vulnerable_range))
    return version in spec

# ---------------------------------------------------------------------------
# Helpers for automatic installed-version collection
# ---------------------------------------------------------------------------

def _detect_and_collect_installed() -> Dict[str, str]:
    """Detect repository type and return mapping of installed packages."""

    cwd = Path.cwd()

    # Order of preference: Node, Go, Python (you can adjust)
    if (cwd / "package.json").exists():
        print("Detected Node repository")
        return _collect_node_packages()

    if (cwd / "go.mod").exists():
        print("Detected Go repository")
        return _collect_go_modules()

    # Default to Python
    print("Detected Python repository")
    return _collect_python_packages()


def _collect_node_packages() -> Dict[str, str]:
    """Return {package: version} for top-level npm dependencies."""

    npm_cmd = shutil.which("npm")
    if npm_cmd is None:
        sys.exit("[error] Detected Node repository but 'npm' command not found in PATH.")

    try:
        result = subprocess.run(
            [npm_cmd, "ls", "--json"],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        deps = data.get("dependencies", {})
        return {name: info.get("version", "") for name, info in deps.items()}
    except subprocess.CalledProcessError as exc:
        sys.exit(f"[error] Failed to run npm ls: {exc}")


def _collect_python_packages() -> Dict[str, str]:
    """Return {package: version} for currently installed Python packages."""

    pip_cmd = shutil.which("pip") or shutil.which("pip3")
    if pip_cmd is None:
        sys.exit("[error] 'pip' not found; cannot list Python packages.")

    try:
        result = subprocess.run(
            [pip_cmd, "list", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
        pkgs = json.loads(result.stdout)
        return {pkg["name"].lower(): pkg["version"] for pkg in pkgs}
    except subprocess.CalledProcessError as exc:
        sys.exit(f"[error] Failed to run pip list: {exc}")


def _collect_go_modules() -> Dict[str, str]:
    """Return {module: version} for Go modules in the current repo."""

    go_cmd = shutil.which("go")
    if go_cmd is None:
        sys.exit("[error] Detected Go repository but 'go' command not found in PATH.")

    try:
        result = subprocess.run(
            [go_cmd, "list", "-m", "-f", "{{.Path}} {{.Version}}", "all"],
            capture_output=True,
            text=True,
            check=True,
        )
        mapping: Dict[str, str] = {}
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            # Each line: 'path version'
            parts = line.split()
            if len(parts) >= 2:
                mapping[parts[0]] = parts[1]
        return mapping
    except subprocess.CalledProcessError as exc:
        sys.exit(f"[error] Failed to run go list: {exc}")

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class AlertInfo:
    """Minimal subset of fields required from a Dependabot alert.

    Only the attributes referenced by *filter_alerts* are included to keep the
    model purposely lightweight.
    """

    state: str
    package_name: str
    severity: str | None
    vulnerable_version_range: str | None

    # NOTE: we store *raw* dict as `source` merely for potential reference or
    # output. It's optional and not used by the filtering logic.
    source: dict[str, Any] | None = None

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "AlertInfo":
        """Create *AlertInfo* from the JSON alert structure returned by GitHub."""

        package_name = (
            raw.get("dependency", {}).get("package", {}).get("name")  # type: ignore[return-value]
        )

        vuln_block = raw.get("security_vulnerability", {})

        return cls(
            state=raw.get("state", ""),
            package_name=package_name or "",
            severity=vuln_block.get("severity"),
            vulnerable_version_range=vuln_block.get("vulnerable_version_range"),
            source=raw,
        )


def filter_alerts(alerts: List[AlertInfo], installed: Dict[str, str]) -> List[AlertInfo]:
    """Return subset of *alerts* that match criteria defined in README."""
    filtered: List[AlertInfo] = []

    for alert in alerts:
        # 1. Must be open
        if alert.state != "open":
            continue

        # 2. Severity must be high or critical
        if alert.severity is None or alert.severity.lower() not in SEVERITY_LEVELS:
            continue

        installed_version = installed.get(alert.package_name)
        if installed_version is None:
            # Package not installed — nothing to fix
            continue

        if not alert.vulnerable_version_range:
            continue

        if _is_version_vulnerable(installed_version, alert.vulnerable_version_range):
            # Append original dict (if available) for continuity
            filtered.append(alert)

    return filtered


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Filter Dependabot alerts.")
    parser.add_argument(
        "--dependabot",
        required=True,
        type=Path,
        help="Path to Dependabot alerts JSON file.",
    )
    parser.add_argument(
        "--installed",
        type=Path,
        help="Path to JSON file with installed package versions. If omitted, the script attempts to autodetect the current repository type (Python, Node, or Go) and gather installed versions automatically.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional output file. Prints to STDOUT if omitted.",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    args = parse_args(argv)

    alerts = [AlertInfo.from_raw(alert) for alert in _load_json(args.dependabot)]

    print("Collecting installed versions...")
    if args.installed:
        installed = _load_json(args.installed)
    else:
        installed = _detect_and_collect_installed()

    filtered = filter_alerts(alerts, installed)

    if args.output:
        args.output.write_text(json.dumps(filtered, indent=2))
    else:
        json.dump(filtered, sys.stdout, indent=2)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
