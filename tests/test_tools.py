from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from wiretap_security.common import ScopeError, dedupe_private_hosts, expand_private_target, parse_ports, parse_private_ipv4
from wiretap_security.netscout import main as netscout_main, scan_host
from wiretap_security.servicewalk import enumerate_port, main as servicewalk_main
from wiretap_security.wifiaudit import classify_security, parse_nmcli_output


class ScopeTests(unittest.TestCase):
    def test_private_and_loopback_literals_are_accepted(self) -> None:
        self.assertEqual(str(parse_private_ipv4("192.168.1.12")), "192.168.1.12")
        self.assertEqual(str(parse_private_ipv4("127.0.0.1")), "127.0.0.1")

    def test_public_hostname_ipv6_and_special_targets_are_rejected(self) -> None:
        for value in ("8.8.8.8", "example.com", "::1", "0.0.0.0", "224.0.0.1"):
            with self.subTest(value=value), self.assertRaises(ScopeError):
                parse_private_ipv4(value)

    def test_cidr_is_bounded_and_private(self) -> None:
        self.assertEqual(len(expand_private_target("192.168.1.7/30")), 2)
        with self.assertRaises(ScopeError):
            expand_private_target("10.0.0.0/16")
        with self.assertRaises(ScopeError):
            expand_private_target("10.0.0.0/8")
        with self.assertRaises(ScopeError):
            expand_private_target("8.8.8.0/30")

    def test_port_list_is_bounded_and_validated(self) -> None:
        self.assertEqual(parse_ports("22, 443"), [22, 443])
        with self.assertRaises(ValueError):
            parse_ports("22,22")
        with self.assertRaises(ValueError):
            parse_ports(",".join(str(i) for i in range(1, 34)))
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_host_list_deduplicates_and_rejects_public_ip(self) -> None:
        self.assertEqual(dedupe_private_hosts(["127.0.0.1", "127.0.0.1"]), ["127.0.0.1"])
        with self.assertRaises(ScopeError):
            dedupe_private_hosts(["8.8.8.8"])


class LoopbackNetworkTests(unittest.TestCase):
    def test_netscout_connects_to_a_real_loopback_listener(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        stop = threading.Event()

        def accept_once() -> None:
            listener.settimeout(2)
            try:
                connection, _ = listener.accept()
                connection.close()
            except (OSError, TimeoutError):
                pass
            finally:
                stop.set()
                listener.close()

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        result = scan_host("127.0.0.1", [port], 0.5, 1)
        self.assertEqual(result["open_ports"], [{"port": port, "state": "open"}])
        thread.join(timeout=2)
        self.assertTrue(stop.is_set())

    def test_authorization_acknowledgement_is_required(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            netscout_main(["127.0.0.1", "--ports", "1"])

    def test_netscout_aggregate_probe_budget_stops_before_connecting(self) -> None:
        output = io.StringIO()
        ports = ",".join(str(value) for value in range(1, 10))
        with redirect_stderr(output):
            result = netscout_main(["192.168.10.0/24", "--authorized", "--ports", ports])
        self.assertEqual(result, 2)
        self.assertIn("budget", output.getvalue())

    def test_servicewalk_http_head_reads_only_security_metadata(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self) -> None:  # noqa: N802 - stdlib callback name
                self.send_response(200)
                self.send_header("Server", "FixtureHTTP/1.0")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Set-Cookie", "not-retained=secret")
                self.end_headers()

            def log_message(self, *_args) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = enumerate_port("127.0.0.1", server.server_port, 1, hint="http")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(result["state"], "open")
        self.assertIn("200", result["http_status_line"])
        self.assertEqual(result["security_headers"]["x-content-type-options"], "nosniff")
        self.assertNotIn("set-cookie", result["security_headers"])

    def test_servicewalk_rejects_public_ip_from_saved_scan_before_connecting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.json"
            path.write_text(json.dumps({
                "format": "wiretap-netscout/v1",
                "hosts": [{"address": "8.8.8.8", "open_ports": [{"port": 443}]}],
            }), encoding="utf-8")
            error = io.StringIO()
            with redirect_stderr(error):
                result = servicewalk_main(["--from-scan", str(path), "--authorized"])
        self.assertEqual(result, 2)
        self.assertIn("outside private/loopback", error.getvalue())

    def test_servicewalk_aggregate_probe_budget_stops_before_connecting(self) -> None:
        targets = [f"10.10.0.{value}" for value in range(1, 34)]
        ports = ",".join(str(value) for value in range(1, 33))
        error = io.StringIO()
        with redirect_stderr(error):
            result = servicewalk_main([*targets, "--authorized", "--ports", ports])
        self.assertEqual(result, 2)
        self.assertIn("budget", error.getvalue())


class WifiAuditTests(unittest.TestCase):
    def test_encryption_findings_are_limited_and_explicit(self) -> None:
        self.assertEqual(classify_security("" )[0], "high")
        self.assertEqual(classify_security("WEP")[0], "critical")
        self.assertEqual(classify_security("WPA1 WPA2 TKIP")[0], "high")
        self.assertEqual(classify_security("WPA3 SAE")[0], "low")
        self.assertEqual(classify_security("WPA2")[0], "moderate")

    def test_saved_nmcli_rows_parse_escaped_ssid_and_do_not_need_a_radio(self) -> None:
        rows = parse_nmcli_output("Lab\\:Guest:AA\\:BB\\:CC\\:DD\\:EE\\:FF:6:2437:81:WPA2\nCafe:::::--\n")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["ssid"], "Lab:Guest")
        self.assertEqual(rows[0]["risk"], "moderate")
        self.assertEqual(rows[1]["risk"], "high")


if __name__ == "__main__":
    unittest.main()
