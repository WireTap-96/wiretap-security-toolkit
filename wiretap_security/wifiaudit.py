"""WireTap WiFiAudit: inspect cached NetworkManager Wi-Fi survey data locally."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import shutil
import subprocess
import sys
from pathlib import Path

FIELDS = ("ssid", "bssid", "channel", "frequency", "signal", "security")


def split_nmcli_line(line: str) -> list[str]:
    """Split nmcli terse output on unescaped colons and decode backslash escapes."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line.rstrip("\r\n"):
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def classify_security(security: str) -> tuple[str, str]:
    value = security.strip().upper()
    if not value or value in {"--", "NONE", "OPEN"}:
        return "high", "Open network: traffic protection depends on application-level encryption."
    if "WEP" in value:
        return "critical", "WEP is obsolete and readily compromised; replace it with WPA2-AES or WPA3."
    if "WPA1" in value or "TKIP" in value or value.startswith("WPA "):
        return "high", "Legacy WPA/TKIP detected; use WPA2-AES or WPA3 and retire legacy compatibility."
    if "WPA3" in value or "SAE" in value:
        return "low", "WPA3/SAE advertised; verify router configuration and client compatibility."
    if "WPA2" in value or "RSN" in value:
        return "moderate", "WPA2/RSN advertised; prefer WPA3 where supported and use a strong unique passphrase."
    return "review", "Security advertisement is unrecognized; verify the access point configuration manually."


def parse_nmcli_output(text: str) -> list[dict]:
    access_points: list[dict] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = split_nmcli_line(line)
        parts += [""] * (len(FIELDS) - len(parts))
        row = dict(zip(FIELDS, parts[: len(FIELDS)]))
        severity, note = classify_security(row["security"])
        row["risk"] = severity
        row["assessment_note"] = note
        access_points.append(row)
    return access_points


def collect_cached_survey() -> str:
    if sys.platform != "linux":
        raise RuntimeError("live adapter survey currently requires Linux with NetworkManager/nmcli")
    if not shutil.which("nmcli"):
        raise RuntimeError("nmcli not found; install/use NetworkManager or provide a saved nmcli output file")
    command = [
        "nmcli", "--terse", "--fields", "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
        "--escape", "yes", "device", "wifi", "list", "--rescan", "no",
    ]
    completed = subprocess.run(command, check=True, capture_output=True, text=True, timeout=15)
    return completed.stdout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wifiaudit",
        description="Review cached Wi-Fi survey data and flag advertised encryption risks; no capture or active attack features.",
    )
    parser.add_argument("--input", help="read saved nmcli terse output instead of querying the local cache")
    parser.add_argument("--output", help="optional local JSON report path; stdout is used otherwise")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        text = Path(args.input).read_text(encoding="utf-8") if args.input else collect_cached_survey()
        access_points = parse_nmcli_output(text)
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        print(f"survey error: {exc}", file=sys.stderr)
        return 2
    report = {
        "format": "wiretap-wifiaudit/v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source": "saved local nmcli output" if args.input else "local NetworkManager cached scan results (rescan disabled)",
        "access_points_found": len(access_points),
        "access_points": access_points,
        "limitations": "This checks advertised security only; it does not test credentials, WPS, signal integrity, or access-point ownership.",
        "privacy": "SSID and BSSID can identify nearby networks; review and redact before sharing the JSON report.",
    }
    rendered = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        print(f"Saved local report: {args.output}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
