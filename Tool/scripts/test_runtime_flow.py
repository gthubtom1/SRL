"""Real harmless Windows launch flows; no customer binaries or network settings."""
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from lib.runtime_flow import launch_flow
from lib.runtime_risk import RiskError, RiskStore
import test_workbench_autonomy as fixtures


@unittest.skipUnless(os.name == "nt" and shutil.which("powershell"), "Windows shell flow fixture required")
class BoundedFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.Launcher.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.Launcher.tearDownClass()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="seep-flow-state-")
        self.addCleanup(self.temp.cleanup)
        env = patch.dict(os.environ, {"SEEP_RISK_ROOT": self.temp.name})
        env.start()
        self.addCleanup(env.stop)
        self.store = RiskStore()
        self.url = "https://flow-fixture.invalid"
        self.scope = self.store.grant(self.url, "flow-account")["scope_id"]

    def tearDown(self):
        # Only this process's uniquely compiled temporary fixture paths.
        for p in fixtures.Launcher.psutil.process_iter():
            try:
                if Path(p.exe()) in {fixtures.Launcher.exe, fixtures.Launcher.other}:
                    p.kill()
                    p.wait(timeout=5)
            except (fixtures.Launcher.psutil.NoSuchProcess, fixtures.Launcher.psutil.AccessDenied):
                pass

    def start(self):
        return launch_flow(fixtures.Launcher.exe, self.url, "flow-account", self.scope, wait_seconds=2)

    def test_real_start_reuse_and_retained_lease(self):
        first = self.start()
        self.assertTrue(first["ok"], first)
        self.assertTrue(first["new_launch_requested"])
        self.assertTrue(first["operation_retained"])
        self.assertIsNone(first["network_request_count"])
        reused = self.start()
        self.assertTrue(reused["ok"])
        self.assertFalse(reused["new_launch_requested"])
        self.assertEqual(self.store.status(self.url, "flow-account", self.scope)["scope"]["used"], 1)
        self.assertEqual(self.store.status(self.url, "flow-account")["unresolved_operations"], 1)
        self.tearDown()
        with self.assertRaisesRegex(RiskError, "unresolved"):
            self.start()
        self.store.resolve(first["operation_id"], "evidence-fixture-process-ended")
        with self.assertRaisesRegex(RiskError, "exhausted"):
            self.start()

    def test_observation_failure_after_real_start_does_not_allow_duplicate(self):
        from lib import runtime_flow
        invoke = runtime_flow._invoke

        def lose_observation(*args):
            code, observed = invoke(*args)
            if args[1] == "shell":
                self.assertTrue(observed["launchRequested"])
                return 4, {**observed, "launched": False, "status": "UNVERIFIED", "instances": []}
            return code, observed

        with patch.object(runtime_flow, "_invoke", side_effect=lose_observation):
            result = self.start()
        self.assertFalse(result["ok"])
        self.assertTrue(result["new_launch_requested"])
        self.assertEqual(self.store.status(self.url, "flow-account")["unresolved_operations"], 1)
        self.assertEqual(self.store.status(self.url, "flow-account", self.scope)["scope"]["used"], 1)

    def test_invalid_target_or_missing_scope_never_starts(self):
        with self.assertRaises(RiskError):
            launch_flow(fixtures.Launcher.exe, self.url, "flow-account", "", wait_seconds=0)
        self.assertFalse(any(p.info.get("exe") and Path(p.info["exe"]) == fixtures.Launcher.exe
                             for p in fixtures.Launcher.psutil.process_iter(["exe"])))
        with self.assertRaises(ValueError):
            launch_flow(fixtures.Launcher.exe, self.url, "flow-account", self.scope, wait_seconds=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
