"""WireTap ServiceWalk: bounded, low-impact service metadata collection."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import os
import socket
import ssl
import sys
from pathlib import Path

from .common import ScopeError, dedupe_private_hosts, parse_ports, write_json

DEFAULT_PORTS = "22,80,443,8080,8443"
MAX_PROBES = 1024
HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
TLS_PORTS = {443, 8443, 9443}
SAFE_HTTP_HEADERS = {
    "server", "strict-transport-security", "content-security-policy",
    "x-content-type-options", "x-frame-options", "referrer-policy",
}


def service_hint(port: int) -> str:
    if port in HTTP_PORTS:
        return "http"
    if port in TLS_PORTS:
        return "https"
    if port == 22:
        return "ssh"
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def clean_line(value: bytes, limit: int = 200) -> str:
    text = value.decode("utf-8", errors="replace").strip()
    return "".join(ch for ch in text if ch.isprintable())[:limit]


def read_http_metadata(sock: socket.socket, host: str) -> dict:
    sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii"))
    headers: dict[str, str] = {}
    with sock.makefile("rb") as reader:
        status = clean_line(reader.readline(1024))
        total = len(status)
        while total < 4096:
            raw = reader.readline(min(1024, 4096 - total))
            if not raw or raw in (b"\r\n", b"\n"):
                break
            total += len(raw)
            if b":" not in raw:
                continue
            name, value = raw.split(b":", 1)
            key = clean_line(name).lower()
            if key in SAFE_HTTP_HEADERS:
                headers[key] = clean_line(value, 512)
    return {"http_status_line": status, "security_headers": headers}


def enumerate_port(host: str, port: int, timeout: float, hint: str | None = None) -> dict:
    """Connect once and, for selected protocols, read bounded public metadata."""
    result: dict = {"address": host, "port": port, "service_hint": hint or service_hint(port)}
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
    except (OSError, TimeoutError) as exc:
        return {**result, "state": "closed_or_filtered", "error": type(exc).__name__}

    with raw:
        result["state"] = "open"
        chosen_hint = (hint or service_hint(port)).lower()
        try:
            if chosen_hint == "ssh":
                result["banner"] = clean_line(raw.recv(256))
            elif chosen_hint in {"http", "https"}:
                sock = raw
                if chosen_hint == "https":
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    # Intentionally collect certificate/TLS metadata without treating it as trusted.
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(raw, server_hostname=host)
                    result["tls_version"] = sock.version()
                    cipher = sock.cipher()
                    result["tls_cipher"] = cipher[0] if cipher else None
                try:
                    result.update(read_http_metadata(sock, host))
                except (OSError, TimeoutError, ssl.SSLError) as exc:
                    result["metadata_error"] = type(exc).__name__
            else:
                result["note"] = "TCP connect only; no application payload was sent"
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            result["metadata_error"] = type(exc).__name__
    return result


def read_scan_hosts(path: str) -> list[str]:
    try:
        if os.path.getsize(path) > 1_048_576:
            raise ValueError("NetScout report exceeds the 1 MiB input limit")
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("NetScout report root must be a JSON object")
        if data.get("format") != "wiretap-netscout/v1":
            raise ValueError("input is not a wiretap-netscout/v1 report")
        entries = data.get("hosts", [])
        if not isinstance(entries, list) or len(entries) > 256:
            raise ValueError("NetScout report must contain at most 256 host entries")
        return [entry["address"] for entry in entries if isinstance(entry, dict) and entry.get("open_ports")]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"cannot read NetScout report: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="servicewalk",
        description="Enumerate limited service metadata on explicitly listed, authorized private IPv4 hosts.",
        epilog="HTTP requests are unauthenticated HEAD /. No login, exploit, fuzzing, or password attempts are made.",
    )
    parser.add_argument("targets", nargs="*", help="private IPv4 literals (up to 64 unique hosts)")
    parser.add_argument("--from-scan", help="local JSON output from wiretap-netscout/v1")
    parser.add_argument("--ports", default=DEFAULT_PORTS, help=f"comma-separated TCP ports (default: {DEFAULT_PORTS})")
    parser.add_argument("--timeout", type=float, default=0.8, help="connect/read timeout in seconds (0.1–2.0)")
    parser.add_argument("--workers", type=int, default=8, help="concurrent checks (1–32; default: 8)")
    parser.add_argument("--authorized", action="store_true", required=True, help="confirm you own the targets or have explicit written authorization")
    parser.add_argument("--output", help="optional local JSON report path; stdout is used otherwise")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if bool(args.from_scan) == bool(args.targets):
        print("error: provide either one or more positional targets or --from-scan, but not both", file=sys.stderr)
        return 2
    if not 0.1 <= args.timeout <= 2.0:
        print("error: --timeout must be between 0.1 and 2.0 seconds", file=sys.stderr)
        return 2
    if not 1 <= args.workers <= 32:
        print("error: --workers must be between 1 and 32", file=sys.stderr)
        return 2
    try:
        raw_hosts = read_scan_hosts(args.from_scan) if args.from_scan else args.targets
        hosts = dedupe_private_hosts(raw_hosts)
        ports = parse_ports(args.ports)
    except (ScopeError, ValueError) as exc:
        print(f"scope/input error: {exc}", file=sys.stderr)
        return 2
    if len(hosts) * len(ports) > MAX_PROBES:
        print(f"scope/input error: total enumeration-attempt budget is {MAX_PROBES}", file=sys.stderr)
        return 2

    checks = [(host, port) for host in hosts for port in ports]
    findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(enumerate_port, host, port, args.timeout): (host, port) for host, port in checks}
        for future in as_completed(futures):
            item = future.result()
            if item["state"] == "open":
                findings.append(item)
    findings.sort(key=lambda row: (row["address"], row["port"]))
    report = {
        "format": "wiretap-servicewalk/v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "method": "bounded TCP connect and selected unauthenticated metadata reads",
        "hosts_checked": hosts,
        "ports_checked": ports,
        "maximum_connection_attempts": MAX_PROBES,
        "open_services": findings,
        "limitations": "Service labels and banners are clues, not verified software versions or vulnerability findings.",
    }
    write_json(json.dumps(report, indent=2), args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
