#!/usr/bin/env python3
"""Isolated network rollback tests: never invoke system changes or real probes."""
from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

SOURCE = Path(__file__).with_name("net-rollback.py")
spec = importlib.util.spec_from_file_location("seep_net_rollback_test_module", SOURCE)
N = importlib.util.module_from_spec(spec)
spec.loader.exec_module(N)


class NetworkRollback(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="seep-net-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.hosts = self.root / "hosts"
        self.hosts.write_bytes(b"original hosts\n")
        self.snapshot = self.root / "snapshot.json"
        self.addCleanup(patch.stopall)
        patch.object(N, "HOSTS", str(self.hosts)).start()
        patch.object(N, "STORE", str(self.root / "store")).start()
        self.old = self.state()
        self.args = argparse.Namespace(from_file=str(self.snapshot), yes=True,
                                       dry_run=False, json=True)

    def state(self):
        return {"schema": "seep-net-snapshot/1", "hostname": N.socket.gethostname(),
                "taken_at": "2026-10-29T00:00:00Z", "collection_errors": [],
                "ipv4_addresses": [{"InterfaceIndex": 7, "InterfaceAlias": "fixture",
                    "IPAddress": "192.0.2.2", "PrefixLength": 24, "PrefixOrigin": "Dhcp"}],
                "adapters": [{"ifIndex": 7, "MacAddress": "00-11-22-33-44-55"}],
                "default_routes": [{"InterfaceIndex": 7, "NextHop": "192.0.2.1",
                                    "DestinationPrefix": "0.0.0.0/0", "RouteMetric": 1}],
                "dns_servers": [{"InterfaceIndex": 7, "ServerAddresses": ["192.0.2.1"]}],
                "winhttp_proxy": {"mode": "direct"}, "hosts_text": "original hosts\n",
                "hosts_nonblank_lines": ["original hosts"], "env_proxy": {}}

    def write_snapshot(self, value=None):
        self.snapshot.write_text(json.dumps(self.old if value is None else value), encoding="utf-8")

    def invoke(self, fn=None):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            code = (fn or N.do_restore)(self.args)
        return code, json.loads(output.getvalue())

    def test_bad_or_foreign_snapshots_refuse_before_any_system_command(self):
        invalid_ip = copy.deepcopy(self.old)
        invalid_ip["ipv4_addresses"][0]["IPAddress"] = 3221225986
        cases = [[], {}, invalid_ip, dict(self.old, hostname="another-machine"),
                 dict(self.old, collection_errors=["incomplete"]),
                 dict(self.old, ipv4_addresses=[]),
                 dict(self.old, winhttp_proxy={"mode": "unknown"})]
        for value in cases:
            with self.subTest(value=value):
                self.write_snapshot(value)
                with patch.object(N, "ps") as command, patch.object(N, "collect", return_value=self.old), \
                        patch.object(N, "verify_network", return_value=(True, {})):
                    code, result = self.invoke()
                self.assertEqual(code, 2, result)
                command.assert_not_called()
                self.assertEqual(self.hosts.read_bytes(), b"original hosts\n")

    def test_offline_empty_route_observation_is_valid_and_dry_run_still_works(self):
        snap = dict(self.old, default_routes=[])
        self.write_snapshot(snap)
        self.args.yes = False
        with patch.object(N, "collect", return_value=snap), patch.object(N, "ps") as command:
            code, result = self.invoke()
        self.assertEqual(code, 0, result)
        self.assertEqual(result["current_drift"], [])
        command.assert_not_called()
        # Empty route results must survive the real collector without hiding errors.
        with patch.object(N, "ps_json", side_effect=[snap["ipv4_addresses"], snap["adapters"],
                         [], snap["dns_servers"]]), patch.object(N, "ps", return_value="Direct access (no proxy server)."):
            current = N.collect()
        self.assertEqual(current["collection_errors"], [])
        N.validate_snapshot(current)

    def test_incomplete_current_collection_refuses_before_mutation(self):
        self.write_snapshot()
        current = dict(self.old, collection_errors=["cannot read hosts"])
        with patch.object(N, "ps") as command, patch.object(N, "collect", return_value=current), \
                patch.object(N, "verify_network", return_value=(True, {})):
            code, result = self.invoke()
        self.assertEqual(code, 2, result)
        command.assert_not_called()

    def test_dry_run_plans_real_current_state_without_running_changes(self):
        self.write_snapshot()
        self.args.yes = False
        current = copy.deepcopy(self.old)
        current["ipv4_addresses"].append({"InterfaceIndex": 7, "InterfaceAlias": "fixture",
            "IPAddress": "192.0.2.9", "PrefixLength": 32, "PrefixOrigin": "Manual"})
        with patch.object(N, "collect", return_value=current) as collect, \
                patch.object(N, "ps") as command, patch.object(N, "verify_network") as verify:
            code, result = self.invoke()
        self.assertEqual(code, 0, result)
        self.assertTrue(result["dry_run"])
        self.assertFalse(result["applied"])
        self.assertIn("192.0.2.9", json.dumps(result))
        collect.assert_called_once()
        command.assert_not_called()
        verify.assert_not_called()
        self.assertEqual(self.hosts.read_bytes(), b"original hosts\n")

    def test_command_failure_never_becomes_success_from_connectivity(self):
        self.write_snapshot()
        with patch.object(N, "collect", return_value=self.old), \
                patch.object(N, "subprocess") as shell, \
                patch.object(N, "verify_network", return_value=(True, {})):
            shell.run.return_value = subprocess.CompletedProcess([], 5, b"", b"denied")
            code, result = self.invoke()
        self.assertNotEqual(code, 0, result)
        self.assertFalse(result["ok"])

    def test_empty_and_binary_hosts_snapshots_restore_exact_bytes(self):
        for data in (b"", b"# legacy encoding \xff\xfe\n"):
            with self.subTest(data=data):
                snap = dict(self.old, hosts_base64=base64.b64encode(data).decode("ascii"),
                            hosts_text=data.decode("utf-8", "replace"))
                self.write_snapshot(snap)
                with patch.object(N, "collect", side_effect=[self.old, snap]), \
                        patch.object(N, "ps", return_value=""), \
                        patch.object(N, "verify_network", return_value=(True, {})):
                    code, result = self.invoke()
                self.assertEqual(code, 0, result)
                self.assertEqual(self.hosts.read_bytes(), data)

    def test_reachable_network_does_not_hide_restore_drift(self):
        self.write_snapshot()
        current = dict(self.old, winhttp_proxy={"mode": "proxy", "server": "127.0.0.1:9"})
        with patch.object(N, "collect", return_value=current), \
                patch.object(N, "ps", return_value=""), \
                patch.object(N, "verify_network", return_value=(True, {})):
            code, result = self.invoke()
        self.assertNotEqual(code, 0, result)
        self.assertFalse(result["ok"])
        self.assertTrue(result["remaining_drift"])

    def test_proxy_arguments_are_quoted_as_data(self):
        server = "fixture'; Write-Output unsafe; #"
        snap = dict(self.old, winhttp_proxy={"mode": "proxy", "server": server,
                                            "bypass": "<local>;*.example"})
        self.write_snapshot(snap)
        with patch.object(N, "collect", side_effect=[self.old, snap]), \
                patch.object(N, "ps", return_value="") as command, \
                patch.object(N, "verify_network", return_value=(True, {})):
            code, result = self.invoke()
        self.assertEqual(code, 0, result)
        commands = "\n".join(str(item.args[0]) for item in command.call_args_list)
        self.assertIn("fixture''; Write-Output unsafe; #", commands)
        self.assertIn("'proxy-server=", commands)

    def test_changed_adapter_identity_refuses_all_mutations(self):
        self.write_snapshot()
        current = copy.deepcopy(self.old)
        current["adapters"][0]["MacAddress"] = "66-77-88-99-AA-BB"
        current["ipv4_addresses"].append({"InterfaceIndex": 7, "IPAddress": "192.0.2.9",
                                         "PrefixLength": 32, "PrefixOrigin": "Manual"})
        with patch.object(N, "collect", return_value=current), patch.object(N, "ps") as command:
            code, result = self.invoke()
        self.assertEqual(code, 2, result)
        command.assert_not_called()

    def test_dhcp_and_unknown_origin_addresses_are_never_removed(self):
        current = copy.deepcopy(self.old)
        for index, origin in enumerate(("Dhcp", "WellKnown", "Other"), 10):
            current["ipv4_addresses"].append({"InterfaceIndex": 7,
                "IPAddress": "192.0.2.%d" % index, "PrefixLength": 24, "PrefixOrigin": origin})
        N.validate_snapshot(current)
        self.assertEqual(N._restore_plan(self.old, current), [])

    def test_virtual_adapter_without_mac_can_be_observed_but_not_removed_without_identity(self):
        current = copy.deepcopy(self.old)
        current["adapters"][0]["MacAddress"] = None
        N.validate_snapshot(current)
        current["ipv4_addresses"].append({"InterfaceIndex": 7, "IPAddress": "192.0.2.9",
                                         "PrefixLength": 32, "PrefixOrigin": "Manual"})
        with self.assertRaises(N.NetworkStateError):
            N._restore_plan(current, dict(current, ipv4_addresses=current["ipv4_addresses"] + [
                {"InterfaceIndex": 7, "IPAddress": "192.0.2.10", "PrefixLength": 32,
                 "PrefixOrigin": "Manual"}]))

    def test_preexisting_address_is_preserved_if_its_prefix_or_origin_changes(self):
        current = copy.deepcopy(self.old)
        current["ipv4_addresses"][0].update(PrefixLength=32, PrefixOrigin="Manual")
        self.assertEqual(N._restore_plan(self.old, current), [])
        self.assertTrue(N._drift(self.old, current))

    def test_snapshot_failure_keeps_previous_latest_and_creates_no_partial_latest(self):
        store = self.root / "store"
        store.mkdir()
        latest = store / "latest.json"
        latest.write_bytes(b"previous snapshot")
        real_replace = os.replace
        def denied(source, destination):
            if Path(destination) == latest:
                raise PermissionError("fixture")
            return real_replace(source, destination)
        with patch.object(N, "collect", return_value=self.old), \
                patch.object(N.os, "replace", side_effect=denied):
            code, result = self.invoke(N.do_snapshot)
        self.assertEqual(code, 2, result)
        self.assertEqual(latest.read_bytes(), b"previous snapshot")
        self.assertFalse(list(store.glob(".seep-net-*")))
        for snapshot in store.glob("net-*.json"):
            self.assertEqual(N.load_snapshot(str(snapshot)), self.old)

    def test_collection_failure_is_explicit_and_no_snapshot_is_published(self):
        with patch.object(N, "ps_json", side_effect=N.NetworkStateError("fixture")), \
                patch.object(N, "ps", side_effect=N.NetworkStateError("fixture")), \
                patch.object(N, "read_hosts_bytes", side_effect=PermissionError("fixture")):
            collected = N.collect()
        self.assertTrue(collected["collection_errors"])
        with patch.object(N, "collect", return_value=collected):
            code, result = self.invoke(N.do_snapshot)
        self.assertEqual(code, 2, result)
        self.assertFalse((self.root / "store/latest.json").exists())

    def test_powershell_quoting_and_exit_status_on_real_harmless_commands(self):
        import shutil
        if not shutil.which("powershell"):
            self.skipTest("PowerShell unavailable; command transport unverified")
        data = "fixture'; Write-Output unsafe; # 中文"
        self.assertEqual(N.ps("Write-Output " + N._ps_quote(data)), data)
        self.assertEqual(N.ps_json("[pscustomobject]@{Value='fixture'}"), [{"Value": "fixture"}])
        self.assertEqual(N.ps_json("@()"), [])
        with self.assertRaises(N.NetworkStateError):
            N.ps("exit 7")
        with self.assertRaises(N.NetworkStateError):
            N.ps("throw 'synthetic failure'")

    def test_verify_keeps_proxy_environment_unchanged(self):
        response = Mock(status=204)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        with patch.dict(os.environ, {"HTTP_PROXY": "http://fixture.invalid:9", "NO_PROXY": "fixture"}), \
                patch.object(N, "ps_json", return_value=[{"NextHop": "192.0.2.1"}]), \
                patch.object(N, "ps", return_value="Direct access (no proxy server)."), \
                patch.object(N, "collect", return_value=self.old), \
                patch.object(N.socket, "create_connection", return_value=connection), \
                patch.object(N.socket, "gethostbyname", return_value="192.0.2.1"), \
                patch.object(N.urllib.request, "urlopen", return_value=response), \
                patch.object(N.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = response
            before = dict(os.environ)
            N.verify_network()
            self.assertTrue(dict(os.environ) == before, "network verification must preserve process environment")


if __name__ == "__main__":
    unittest.main(verbosity=2)
