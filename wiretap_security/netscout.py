"""WireTap NetScout: bounded TCP-connect discovery for authorized private IPv4 labs."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import socket
import sys

from .common import ScopeError, expand_private_target, parse_ports, write_json

DEFAULT_PORTS = "22,80,443,445,3389,8080,8443"
MAX_PROBES = 2048


def tcp_connect(host: str, port: int, timeout: float) -> bool:
    """Return True only when a normal TCP connect succeeds; no raw packets."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def scan_host(host: str, ports: list[int], timeout: float, workers: int) -> dict:
    open_ports: list[dict[str, int | str]] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(tcp_connect, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append({"port": port, "state": "open"})
    open_ports.sort(key=lambda item: int(item["port"]))
    return {"address": host, "open_ports": open_ports}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscout",
        description="Find responding hosts on a small, authorized private IPv4 scope using ordinary TCP connects.",
        epilog="Only RFC1918 or loopback IPv4 is accepted. This is not authorization to scan any network.",
    )
    parser.add_argument("target", help="one private IPv4 address or CIDR; CIDRs are limited to 256 hosts")
    parser.add_argument("--ports", default=DEFAULT_PORTS, help=f"comma-separated TCP ports (default: {DEFAULT_PORTS})")
    parser.add_argument("--timeout", type=float, default=0.5, help="per-connect timeout in seconds (0.1–2.0)")
    parser.add_argument("--workers", type=int, default=12, help="concurrent TCP connects (1–32; default: 12)")
    parser.add_argument("--authorized", action="store_true", required=True, help="confirm you own the target or have explicit written authorization")
    parser.add_argument("--output", help="optional local JSON report path; stdout is used otherwise")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 0.1 <= args.timeout <= 2.0:
        print("error: --timeout must be between 0.1 and 2.0 seconds", file=sys.stderr)
        return 2
    if not 1 <= args.workers <= 32:
        print("error: --workers must be between 1 and 32", file=sys.stderr)
        return 2
    try:
        hosts = expand_private_target(args.target)
        ports = parse_ports(args.ports)
    except (ScopeError, ValueError) as exc:
        print(f"scope/input error: {exc}", file=sys.stderr)
        return 2
    if len(hosts) * len(ports) > MAX_PROBES:
        print(f"scope/input error: total connection-attempt budget is {MAX_PROBES}", file=sys.stderr)
        return 2

    results = []
    for host in hosts:
        result = scan_host(host, ports, args.timeout, args.workers)
        if result["open_ports"]:
            results.append(result)
    report = {
        "format": "wiretap-netscout/v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "method": "TCP connect; no raw sockets, stealth, or service exploitation",
        "requested_network": args.target,
        "ports_checked": ports,
        "maximum_connection_attempts": MAX_PROBES,
        "hosts_checked": len(hosts),
        "responsive_hosts": len(results),
        "hosts": results,
    }
    write_json(json.dumps(report, indent=2), args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
