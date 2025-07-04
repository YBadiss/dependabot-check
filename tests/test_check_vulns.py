from check_vulns import AlertInfo, filter_alerts


# Helper to build a minimal Dependabot alert dict


def build_alert(
    *,
    package: str = "pkg",
    severity: str = "high",
    version_range: str = ">=1.0.0, <2.0.0",
    state: str = "open",
) -> AlertInfo:
    return AlertInfo.from_raw(
        {
            "state": state,
            "dependency": {"package": {"name": package, "ecosystem": "pip"}},
            "security_vulnerability": {
                "severity": severity,
                "vulnerable_version_range": version_range,
                "first_patched_version": {"identifier": "9999.0.0"},
            },
        }
    )


def test_vuln_not_installed_returns_empty():
    alert = build_alert(package="foo")
    installed = {}  # package not present

    assert filter_alerts([alert], installed) == []


def test_non_critical_severity_returns_empty():
    alert = build_alert(package="foo", severity="medium")
    installed = {"foo": "1.1.0"}

    assert filter_alerts([alert], installed) == []


def test_version_not_in_range_returns_empty():
    alert = build_alert(package="foo", version_range=">=1.0.0, <2.0.0")
    # Installed version outside the vulnerable range
    installed = {"foo": "2.5.0"}

    assert filter_alerts([alert], installed) == []


def test_matching_vuln_returns_alert():
    alert = build_alert(
        package="foo", severity="critical", version_range=">=1.0.0, <2.0.0"
    )
    installed = {"foo": "1.5.0"}

    filtered = filter_alerts([alert], installed)
    assert len(filtered) == 1
    assert filtered[0] is alert
