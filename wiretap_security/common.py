"""Shared safety and input helpers for WireTap's authorized assessment tools."""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Iterable

RFC1918 = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
LOOPBACK = ipaddress.ip_network("127.0.0.0/8")


class ScopeError(ValueError):
    """Raised when a target falls outside the tool's intentionally narrow scope."""


def parse_private_ipv4(value: str) -> ipaddress.IPv4Address:
    """Accept an RFC1918 or loopback IPv4 literal; reject names and public IPs."""
    if not isinstance(value, str):
        raise ScopeError("target address must be a string IPv4 literal")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ScopeError(f"not an IPv4 address literal: {value!r}") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise ScopeError("IPv6 is not supported by this bounded starter tool")
    if not any(address in network for network in (*RFC1918, LOOPBACK)):
        raise ScopeError(f"{address} is outside private/loopback IPv4 scope")
    if address.is_multicast or address.is_unspecified or address.is_reserved:
        raise ScopeError(f"{address} is not a valid unicast assessment target")
    return address


def expand_private_target(value: str, *, max_hosts: int = 256) -> list[str]:
    """Expand one private IPv4 address/CIDR, refusing broad ranges."""
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ScopeError(f"invalid IPv4 address or CIDR: {value!r}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ScopeError("IPv6 networks are not supported")
    host_count = network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
    if host_count > max_hosts:
        raise ScopeError(f"target expands to {host_count} hosts; limit is {max_hosts}")
    hosts = list(network.hosts())
    if not hosts:
        raise ScopeError("target network contains no usable hosts")
    for address in hosts:
        parse_private_ipv4(str(address))
    return [str(address) for address in hosts]


def parse_ports(value: str, *, max_ports: int = 32) -> list[int]:
    """Parse a comma-separated list of TCP ports, without ranges or duplicates."""
    try:
        ports = [int(part.strip()) for part in value.split(",") if part.strip()]
    except ValueError as exc:
        raise ValueError("ports must be comma-separated integers") from exc
    if not ports:
        raise ValueError("provide at least one port")
    if len(ports) > max_ports:
        raise ValueError(f"at most {max_ports} ports are allowed")
    if len(set(ports)) != len(ports):
        raise ValueError("duplicate ports are not allowed")
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError("ports must be between 1 and 65535")
    return ports


def dedupe_private_hosts(values: Iterable[str], *, max_hosts: int = 64) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for value in values:
        host = str(parse_private_ipv4(value))
        if host not in seen:
            seen.add(host)
            hosts.append(host)
        if len(hosts) > max_hosts:
            raise ScopeError(f"at most {max_hosts} unique hosts are allowed")
    if not hosts:
        raise ScopeError("no target hosts were provided")
    return hosts


def write_json(text: str, output: str | None) -> None:
    """Write JSON to stdout or a caller-selected file; never uploads data."""
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
        print(f"Saved local report: {output}")
    else:
        print(text)
