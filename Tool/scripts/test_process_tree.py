"""Lifecycle tests for external commands, batch descendants and MCP launchers."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent
TOOL = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(TOOL / "mcp"))

from lib import process_tree  # noqa: E402
import tool_autodiscover as discovery  # noqa: E402

_readiness_spec = importlib.util.spec_from_file_location(
    "process_tree_readiness", SCRIPTS / "tool-readiness.py"
)
readiness = importlib.util.module_from_spec(_readiness_spec)
_readiness_spec.loader.exec_module(readiness)


def _pid_is_alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            exit_code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == 259
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _wait_for(paths: tuple[Path, ...], timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(path.exists() for path in paths):
            return True
        time.sleep(0.05)
    return False


def _batch_spawner(root: Path) -> tuple[Path, Path, Path, dict[str, str]]:
    marker = root / "late.marker"
    grandchild_pid = root / "grandchild.pid"
    batch = root / "spawner.cmd"
    grandchild_code = (
        "import os,pathlib,time;"
        "pathlib.Path(os.environ['SEEP_GRANDCHILD_PID']).write_text(str(os.getpid()));"
        "time.sleep(1.2);"
        "pathlib.Path(os.environ['SEEP_MARKER']).write_text('LEAK')"
    )
    batch.write_text(
        "@echo off\r\n"
        "echo BEFORE\r\n"
        'start "" /b "%SEEP_TEST_PYTHON%" -c "%SEEP_GRANDCHILD_CODE%"\r\n'
        '"%SEEP_TEST_PYTHON%" -c "import time;time.sleep(10)"\r\n',
        encoding="utf-8",
    )
    environment = dict(
        os.environ,
        SEEP_TEST_PYTHON=sys.executable,
        SEEP_GRANDCHILD_CODE=grandchild_code,
        SEEP_GRANDCHILD_PID=str(grandchild_pid),
        SEEP_MARKER=str(marker),
        HOME=str(root / "home"),
        USERPROFILE=str(root / "home"),
        PI_CODING_AGENT_DIR=str(root / "agent"),
    )
    return batch, marker, grandchild_pid, environment


class ProcessTreeRunTests(unittest.TestCase):
    def test_normal_stdout_stderr_and_return_code_are_preserved(self):
        completed = process_tree.run(
            [
                sys.executable,
                "-c",
                "import sys;print('OUT');print('ERR',file=sys.stderr);raise SystemExit(7)",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 7)
        self.assertEqual(completed.stdout, "OUT\n")
        self.assertEqual(completed.stderr, "ERR\n")

    @unittest.skipUnless(os.name == "nt", "Windows batch descendant probe")
    def test_batch_timeout_kills_the_grandchild_before_delayed_marker(self):
        with tempfile.TemporaryDirectory(prefix="seep-tree-timeout-") as temp:
            batch, marker, grandchild_pid, environment = _batch_spawner(Path(temp))
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                process_tree.run(
                    ["cmd", "/c", str(batch)],
                    capture_output=True,
                    text=True,
                    timeout=0.35,
                    env=environment,
                )
            self.assertIn("BEFORE", caught.exception.stdout or "")
            self.assertTrue(_wait_for((grandchild_pid,), timeout=3))
            self.assertFalse(_pid_is_alive(int(grandchild_pid.read_text())))
            time.sleep(1.5)
            self.assertFalse(marker.exists(), marker.read_text() if marker.exists() else "")

    @unittest.skipUnless(os.name == "nt", "Windows batch integration probe")
    def test_autodiscover_batch_route_kills_descendants_on_timeout(self):
        with tempfile.TemporaryDirectory(prefix="seep-autodiscover-tree-") as temp:
            batch, marker, grandchild_pid, environment = _batch_spawner(Path(temp))
            with self.assertRaises(subprocess.TimeoutExpired):
                discovery._run_tool_process(
                    [str(batch)],
                    capture_output=True,
                    text=True,
                    timeout=0.35,
                    env=environment,
                )
            self.assertTrue(_wait_for((grandchild_pid,), timeout=3))
            self.assertFalse(_pid_is_alive(int(grandchild_pid.read_text())))
            time.sleep(1.5)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "nt", "Windows batch integration probe")
    def test_readiness_timeout_kills_descendants_and_retains_diagnostic(self):
        with tempfile.TemporaryDirectory(prefix="seep-readiness-tree-") as temp:
            batch, marker, grandchild_pid, environment = _batch_spawner(Path(temp))
            with mock.patch.object(readiness, "CHILD_ENV", environment):
                result = readiness.verify(
                    {"kind": "exec", "args": [], "expect": "never", "timeoutSec": 0.35},
                    str(batch),
                )
            self.assertFalse(result["ok"])
            self.assertFalse(result["rc"] is not None)
            self.assertIn("自检超时", result["line"])
            self.assertTrue(_wait_for((grandchild_pid,), timeout=3))
            self.assertFalse(_pid_is_alive(int(grandchild_pid.read_text())))
            time.sleep(1.5)
            self.assertFalse(marker.exists())

    def test_mcp_launcher_preserves_service_stdio_and_exit_code(self):
        with tempfile.TemporaryDirectory(prefix="seep-mcp-launch-io-") as temp:
            root = Path(temp)
            scripts = root / "Tool" / "scripts"
            lib = scripts / "lib"
            server_dir = root / "Tool" / "mcp"
            lib.mkdir(parents=True)
            server_dir.mkdir(parents=True)
            shutil.copy2(SCRIPTS / "mcp-launch.py", scripts / "mcp-launch.py")
            shutil.copy2(SCRIPTS / "lib" / "process_tree.py", lib / "process_tree.py")
            (lib / "__init__.py").write_text("", encoding="utf-8")
            (server_dir / "seep_mcp_server.py").write_text(
                "import sys;print('SERVICE-OUT');print('SERVICE-ERR',file=sys.stderr);"
                "raise SystemExit(7)\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-X",
                    "utf8",
                    str(scripts / "mcp-launch.py"),
                    "--server",
                    "seep",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10,
                env=dict(
                    os.environ,
                    HOME=str(root / "home"),
                    USERPROFILE=str(root / "home"),
                    PI_CODING_AGENT_DIR=str(root / "agent"),
                ),
            )
            self.assertEqual(completed.returncode, 7)
            self.assertEqual(completed.stdout, "SERVICE-OUT\n")
            self.assertTrue(completed.stderr.endswith("SERVICE-ERR\n"), completed.stderr)

    @unittest.skipUnless(os.name == "nt", "Windows launcher termination probe")
    def test_terminating_mcp_launcher_kills_service_and_grandchild(self):
        with tempfile.TemporaryDirectory(prefix="seep-mcp-launch-tree-") as temp:
            root = Path(temp)
            scripts = root / "Tool" / "scripts"
            lib = scripts / "lib"
            server_dir = root / "Tool" / "mcp"
            lib.mkdir(parents=True)
            server_dir.mkdir(parents=True)
            shutil.copy2(SCRIPTS / "mcp-launch.py", scripts / "mcp-launch.py")
            shutil.copy2(SCRIPTS / "lib" / "process_tree.py", lib / "process_tree.py")
            (lib / "__init__.py").write_text("", encoding="utf-8")

            service_pid = root / "service.pid"
            grandchild_pid = root / "grandchild.pid"
            marker = root / "late.marker"
            grandchild_code = (
                "import os,pathlib,time;"
                "pathlib.Path(os.environ['SEEP_GRANDCHILD_PID']).write_text(str(os.getpid()));"
                "time.sleep(1.2);"
                "pathlib.Path(os.environ['SEEP_MARKER']).write_text('LEAK')"
            )
            service_lines = (
                "import os,pathlib,subprocess,sys,time\n"
                "pathlib.Path(os.environ['SEEP_SERVICE_PID']).write_text(str(os.getpid()))\n"
                "subprocess.Popen([sys.executable,'-c',os.environ['SEEP_GRANDCHILD_CODE']],"
                "env=os.environ.copy())\n"
                "time.sleep(30)\n"
            )
            (server_dir / "seep_mcp_server.py").write_text(service_lines, encoding="utf-8")
            environment = dict(
                os.environ,
                SEEP_SERVICE_PID=str(service_pid),
                SEEP_GRANDCHILD_PID=str(grandchild_pid),
                SEEP_GRANDCHILD_CODE=grandchild_code,
                SEEP_MARKER=str(marker),
                HOME=str(root / "home"),
                USERPROFILE=str(root / "home"),
                PI_CODING_AGENT_DIR=str(root / "agent"),
            )
            launcher = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    "-X",
                    "utf8",
                    str(scripts / "mcp-launch.py"),
                    "--server",
                    "seep",
                ],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP
                    | getattr(subprocess, "CREATE_NO_WINDOW", 0)
                ),
            )
            try:
                self.assertTrue(_wait_for((service_pid, grandchild_pid)), launcher.stderr)
                service = int(service_pid.read_text())
                grandchild = int(grandchild_pid.read_text())
                self.assertTrue(_pid_is_alive(service))
                self.assertTrue(_pid_is_alive(grandchild))
                launcher.kill()
                deadline = time.monotonic() + 5
                while launcher.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertIsNotNone(launcher.poll(), launcher.stderr)
                time.sleep(0.2)
                self.assertFalse(_pid_is_alive(service))
                self.assertFalse(_pid_is_alive(grandchild))
                time.sleep(1.5)
                self.assertFalse(marker.exists())
            finally:
                if launcher.poll() is None:
                    launcher.kill()
                if launcher.stderr is not None:
                    launcher.stderr.close()


class PosixProcessGroupContractTests(unittest.TestCase):
    def test_run_uses_a_new_session_and_kills_the_group(self):
        fake = mock.Mock()
        fake.pid = 4321
        fake.returncode = 0
        fake.communicate.return_value = ("", "")
        with mock.patch.object(process_tree.os, "name", "posix"), \
                mock.patch.object(process_tree.subprocess, "Popen", return_value=fake) as popen, \
                mock.patch.object(process_tree.os, "killpg", create=True) as killpg, \
                mock.patch.object(process_tree.signal, "SIGKILL", 9, create=True):
            completed = process_tree.run(["fixture"], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0)
        self.assertIs(popen.call_args.kwargs["start_new_session"], True)
        self.assertIn(mock.call(4321, 0), killpg.call_args_list)
        self.assertIn(mock.call(4321, 9), killpg.call_args_list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
