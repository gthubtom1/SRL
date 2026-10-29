"""Offline checks for decoded Android manifest summaries."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_runtime_install_delivery import (
    POWERSHELL, ROOT, TMP_ROOT, isolated_environment,
)


class ManifestSummaryTests(unittest.TestCase):
    def test_launcher_activity_alias_is_reported(self):
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="manifest-summary-", dir=TMP_ROOT) as folder:
            base = Path(folder)
            manifest = base / "AndroidManifest.xml"
            manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
                package="fixture.example"><application>
                <activity android:name=".Main"/>
                <activity-alias android:name=".Launcher" android:targetActivity=".Main"
                    android:exported="true"><intent-filter>
                    <action android:name="android.intent.action.MAIN"/>
                    <category android:name="android.intent.category.LAUNCHER"/>
                </intent-filter></activity-alias>
                </application></manifest>''', encoding="utf-8")
            proc = subprocess.run(
                [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                 str(ROOT / "Tool/scripts/apk/manifest-summary.ps1"),
                 "-ManifestPath", str(manifest)],
                cwd=base, env=isolated_environment(base), capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("activity_count=1", proc.stdout)
            self.assertIn("activity_alias_count=1", proc.stdout)
            self.assertIn("main_activity=.Launcher", proc.stdout)
            self.assertNotIn("main_activity=.Main", proc.stdout)


if __name__ == "__main__":
    unittest.main()
