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
import os
import sys
from pathlib import Path
from typing import Any, Dict, List
from dataclasses import dataclass
import subprocess
import shutil
import urllib.request
import urllib.error

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
        return _collect_node_packages()

    if (cwd / "go.mod").exists():
        return _collect_go_modules()

    raise RuntimeError("No repository type detected")


def _collect_node_packages() -> Dict[str, str]:
    """Return a mapping of *all* (top-level and transitive) npm dependencies.

    The implementation mirrors the behavior of the following jq one-liner provided
    by the user, but is implemented directly in Python to remove the jq runtime
    requirement:

        npm ls --all --json \
          | jq '<recursive function shown in user message>'

    We invoke `npm ls --all --json` to obtain the full dependency tree and then
    traverse it recursively, collecting each package's declared version. The
    resulting dictionary uses lower-cased package names to match the
    normalisation applied elsewhere in this script (e.g. Python packages).
    """

    npm_cmd = shutil.which("npm")
    if npm_cmd is None:
        sys.exit(
            "[error] Detected Node repository but 'npm' command not found in PATH."
        )

    try:
        result = subprocess.run(
            [npm_cmd, "ls", "--all", "--json"],
            capture_output=True,
            text=True,
            check=True,
        )

        data = json.loads(result.stdout)

        def _walk(dep_tree: Dict[str, Any] | None, mapping: Dict[str, str]) -> None:
            """Recursively traverse *dep_tree*, filling *mapping* in-place."""

            if not dep_tree:
                return

            for pkg_name, info in dep_tree.items():
                version = info.get("version")
                if version:
                    mapping[pkg_name.lower()] = version

                # Recurse into nested dependencies, if any
                _walk(info.get("dependencies"), mapping)

        collected: Dict[str, str] = {}
        _walk(data.get("dependencies"), collected)
        return collected
    except subprocess.CalledProcessError as exc:
        sys.exit(f"[error] Failed to run npm ls: {exc}")


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


def filter_alerts(
    alerts: List[AlertInfo], installed: Dict[str, str]
) -> List[AlertInfo]:
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
        type=Path,
        help="Path to Dependabot alerts JSON file. If omitted, the script attempts to fetch alerts from GitHub.",
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

    if args.dependabot:
        alerts = [AlertInfo.from_raw(alert) for alert in _load_json(args.dependabot)]
    else:
        alerts = [
            AlertInfo.from_raw(alert)
            for alert in _fetch_dependabot_alerts_from_github()
        ]

    if args.installed:
        installed = _load_json(args.installed)
    else:
        installed = _detect_and_collect_installed()

    filtered = [alert.source for alert in filter_alerts(alerts, installed)]

    if args.output:
        args.output.write_text(json.dumps(filtered, indent=2))
    else:
        json.dump(filtered, sys.stdout, indent=2)
        sys.stdout.write("\n")


def _fetch_dependabot_alerts_from_github() -> list[dict[str, Any]]:
    """Fetch open Dependabot alerts using the GitHub API.

    Environment variables required:
      GH_TOKEN – a GitHub personal access token with `security_events:read` scope
      GH_REPO  – the repository in `owner/name` form

    The function first tries to invoke the `gh` CLI (preferred for simplicity).
    If `gh` is not available, it falls back to a direct HTTPS request using the
    token. In either case, it returns the parsed JSON list of alert objects or
    terminates the program with a descriptive error.
    """

    repo = os.environ.get("GH_REPO")
    token = os.environ.get("GH_TOKEN")

    if not repo:
        sys.exit("[error] GH_REPO environment variable not set (e.g. 'owner/repo').")
    if not token:
        sys.exit("[error] GH_TOKEN environment variable not set.")

    # 1) Try GitHub CLI ------------------------------------------------------
    gh_cmd = shutil.which("gh")
    if gh_cmd is not None:
        try:
            result = subprocess.run(
                [
                    gh_cmd,
                    "api",
                    f"/repos/{repo}/dependabot/alerts",
                    "--method",
                    "GET",
                    "--field",
                    "state=open",
                ],
                capture_output=True,
                text=True,
                check=True,
                env=os.environ.copy(),
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as exc:
            print(
                f"[warn] Failed to fetch alerts via gh CLI (will retry via HTTPS): {exc}",
                file=sys.stderr,
            )

    # 2) Fallback to raw HTTP request ---------------------------------------
    url = f"https://api.github.com/repos/{repo}/dependabot/alerts?state=open"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "dependabot-check-script",
    }

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        sys.exit(f"[error] Failed to fetch alerts via HTTPS: {exc}")


if __name__ == "__main__":
    main()
