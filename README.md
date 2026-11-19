# WireTap Security Toolkit

**AI-assisted Python security utilities for authorized home labs and defensive review.** The toolkit contains three small, inspectable command-line programs: bounded private-network discovery, low-impact service metadata, and cached Wi-Fi security-mode review.

> Use only on devices or networks you own or have explicit written authorization to assess. The required `--authorized` flag is an acknowledgement—not proof of permission. These are educational tools, not a professional security assessment.

## Tools

| Tool | Purpose | Boundaries |
|---|---|---|
| **NetScout** | Find hosts answering selected TCP ports on a small private IPv4 subnet and save a JSON inventory. | RFC1918/loopback only, no DNS or IPv6, max 256 hosts, max 32 ports, max 2,048 connection attempts, max 32 workers. No raw packets, stealth, exploit, or service payload. |
| **ServiceWalk** | Read limited metadata from selected TCP services on explicit targets or NetScout JSON. | RFC1918/loopback only, re-validates every saved target, max 64 hosts and 1,024 connection attempts. Optional SSH banner is capped; HTTP uses unauthenticated `HEAD /`; no redirect following, login, password attempts, fuzzing, exploit, or vulnerability verdict. |
| **WiFiAudit** | Classify advertised security modes in cached NetworkManager Wi-Fi survey output. | Live view is Linux/NetworkManager-only and always requests `--rescan no`. No monitor mode, capture, handshake collection, password cracking, injection, deauthentication, WPS test, or access-point ownership check. |

NetScout is configurable and emits structured output; [HomePortMap](https://github.com/WireTap-96/homeportmap) remains the simpler fixed-port home-subnet inventory project. ServiceWalk complements [HomeConfigCheck](https://github.com/WireTap-96/homeconfigcheck): it observes limited service metadata, while HomeConfigCheck makes one narrowly scoped HTTP header request.

WiFiAudit is a defensive survey companion—not an Aircrack-ng clone. Its risk labels reflect only the security string reported by the local operating system. They are review prompts, not proof that a network is vulnerable or safe. SSIDs and BSSIDs may reveal nearby networks or location; sanitize reports before sharing.

## Install

Python 3.10+; no third-party runtime dependencies.

```bash
python -m venv .venv
# Linux / Kali
source .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install -e .
```

## Authorized private-lab examples

Only use the exact subnet listed in your written scope. Example addresses below are documentation examples, not targets to scan automatically.

```bash
netscout 192.168.56.0/24 --authorized --ports 22,80,443 --output netscout.json
servicewalk --from-scan netscout.json --authorized --ports 22,80,443 --output services.json
```

Both tools accept only RFC1918 or loopback IPv4 literals/CIDRs. They reject hostnames, public addresses, IPv6, overlarge target lists, port lists, worker counts, and timeouts. A successful TCP connection is evidence of reachability for that port at that moment—not a vulnerability.

On Linux with NetworkManager, inspect its existing cached Wi-Fi view (it may be stale or empty):

```bash
wifiaudit --output wifi-review.json
```

To parse a synthetic saved example without a wireless adapter:

```bash
wifiaudit --input samples/wifi-survey.txt
```

## Tests and current evidence

```bash
python -m unittest discover -s tests -v
```

The included 13 unit tests passed locally in a Linux sandbox. They use loopback listeners/HTTP fixtures and synthetic Wi-Fi rows; they do **not** scan external systems or validate results against a live wireless adapter. The test workflow is also configured for Python 3.10–3.12; its GitHub-hosted CI status should be checked after the first push.

This repository is AI-assisted educational work. Review the implementation, run the checks, and understand the limitations before using it or presenting it. Do not commit client inventories, real scan output, SSIDs/BSSIDs, credentials, or other sensitive data.

## License

MIT. See [LICENSE](LICENSE).
