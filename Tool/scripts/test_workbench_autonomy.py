"""Behavioral regressions for shared retry guidance and Windows process identity."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RetryAndBoundary(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node is required")
    def test_retry_repair_sessions_and_host_boundaries(self):
        script = r'''
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
const root=process.cwd();
const circuit=await import(pathToFileURL(path.join(root,'Tool/prompts/extensions/seep-circuit.ts')));
const guard=await import(pathToFileURL(path.join(root,'Tool/prompts/extensions/cmd-guard.ts')));
const events={};
circuit.default({on:(n,fn)=>events[n]=fn,registerCommand:()=>{}});
const A={sessionId:'repair-a'}, B={sessionId:'repair-b'};
const call=(ctx,id,command)=>events.tool_call({toolName:'bash',toolCallId:id,input:{command}},ctx);
const result=(ctx,id,extra={})=>events.tool_result({toolName:'bash',toolCallId:id,isError:true,content:'failure',...extra},ctx);
for(let i=0;i<2;i++){await call(A,'a'+i,'npm test');await result(A,'a'+i);}
assert.equal((await call(A,'blocked','npm test')).block,true);
assert.equal(await call(A,'build','npm run build'),undefined);
assert.equal(await call(A,'flag','npm test -- --filter=second'),undefined);
assert.equal(await call(B,'other-session','npm test'),undefined);
await events.tool_result({toolName:'edit',isError:true},A);
assert.equal((await call(A,'still-blocked','npm test')).block,true);
await events.tool_result({toolName:'read',isError:false},A);
assert.equal((await call(A,'read-does-not-repair','npm test')).block,true);
await call(A,'old-pending','npm test --old');
await call(A,'old-pending-2','npm test --old');
await events.tool_result({toolName:'edit',isError:false},A);
await result(A,'old-pending');
await result(A,'old-pending-2');
assert.equal(await call(A,'old-after-edit','npm test --old'),undefined);
assert.equal(await call(A,'retest','npm test'),undefined);
await result(A,'retest');
assert.equal(await call(A,'retest-2','npm test'),undefined);
await result(A,'retest-2');
assert.equal((await call(A,'reblocked','npm test')).block,true);
await events.tool_result({toolName:'write',isError:false},A);
assert.equal(await call(A,'retest-write','npm test'),undefined);
// Nonzero exit status is a failure even if a host omitted isError.
for(let i=0;i<2;i++){
 await call(A,'exit'+i,'npm run check');
 await result(A,'exit'+i,{isError:false,details:{exitCode:1}});
}
assert.equal((await call(A,'exit-blocked','npm run check')).block,true);
assert.equal(circuit.callSignature('mcp__test',{b:2,a:1}),circuit.callSignature('mcp__test',{a:1,b:2}));
assert.notEqual(circuit.callSignature('bash',{command:'test --port 1'}),circuit.callSignature('bash',{command:'test --port 2'}));
const secret='fixture-secret-value';
const sig=circuit.callSignature('mcp__test',{token:secret});
assert.ok(!sig.includes(secret));
const cfg=guard.effectiveConfig();
for(const command of ['python -m unittest','npm run build','Start-Process -FilePath "fixture.exe"']){
 const d=guard.decideCommand(command,cfg,null);
 assert.equal(d.verdict,'allow');
 assert.ok(!JSON.stringify(d).includes('推荐，让用户自己双击'));
}
for(const command of ['netsh winhttp set proxy 127.0.0.1:8888','Restart-Service TestFixture']){
 assert.equal(guard.decideCommand(command,cfg,null).verdict,'block');
}
// A real local development iteration, with tool outcomes fed back into the extension.
const dev=path.join(path.dirname(process.argv[1]),'development');
fs.mkdirSync(dev);
fs.writeFileSync(path.join(dev,'calculator.py'),'def add(a, b): return a - b\n');
fs.writeFileSync(path.join(dev,'test_calculator.py'),'import unittest\nfrom calculator import add\nclass Addition(unittest.TestCase):\n def test_add(self): self.assertEqual(add(2, 3), 5)\n');
const D={sessionId:'actual-development'};
for(let i=0;i<2;i++){
 assert.equal(await call(D,'dev'+i,'python -m unittest'),undefined);
 const run=spawnSync(process.argv[2],['-B','-m','unittest'],{cwd:dev,encoding:'utf8'});
 assert.equal(run.status,1);
 await result(D,'dev'+i,{details:{exitCode:run.status},content:run.stderr});
}
assert.equal((await call(D,'dev-repeat','python -m unittest')).block,true);
fs.writeFileSync(path.join(dev,'calculator.py'),'def add(a, b): return a + b\n');
await events.tool_result({toolName:'edit',isError:false},D);
assert.equal(await call(D,'dev-fixed','python -m unittest'),undefined);
const fixed=spawnSync(process.argv[2],['-B','-m','unittest'],{cwd:dev,encoding:'utf8'});
assert.equal(fixed.status,0,fixed.stderr);
await result(D,'dev-fixed',{isError:false,details:{exitCode:0},content:fixed.stderr});
console.log('retry repair, input isolation, session isolation and host boundaries passed');
'''
        with tempfile.TemporaryDirectory(prefix="seep-retry-") as folder:
            probe = Path(folder) / "probe.mjs"
            probe.write_text(script, encoding="utf-8")
            run = subprocess.run(
                [shutil.which("node"), "--experimental-strip-types", str(probe), os.sys.executable],
                cwd=ROOT, env=dict(os.environ, SEEP_CIRCUIT_N="2", NODE_NO_WARNINGS="1"),
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


@unittest.skipUnless(os.name == "nt" and shutil.which("powershell"), "Windows PowerShell required")
class Launcher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psutil
        cls.psutil = psutil
        cls.temp = tempfile.TemporaryDirectory(prefix="seep-launch-")
        cls.base = Path(cls.temp.name)
        cls.csc = Path(os.environ["SystemRoot"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
        if not cls.csc.exists():
            cls.temp.cleanup()
            raise unittest.SkipTest(".NET C# compiler required for harmless process fixture")
        source = cls.base / "fixture.cs"
        source.write_text(r'''
using System;
using System.IO;
using System.Diagnostics;
class Fixture {
    static void Main(string[] args) {
        string file=Process.GetCurrentProcess().MainModule.FileName;
        File.WriteAllText(file+".receipt",Environment.CurrentDirectory+"\n"+String.Join("\t",args));
        System.Threading.Thread.Sleep(30000);
    }
}
''', encoding="utf-8")
        cls.exe = cls.base / "one folder" / "seep-test-fixture.exe"
        cls.exe.parent.mkdir()
        built = subprocess.run([str(cls.csc), "/nologo", "/target:winexe", "/out:" + str(cls.exe), str(source)],
                               capture_output=True, text=True, timeout=30)
        if built.returncode:
            cls.temp.cleanup()
            raise RuntimeError(built.stdout + built.stderr)
        cls.other = cls.base / "other folder" / cls.exe.name
        cls.other.parent.mkdir()
        shutil.copy2(cls.exe, cls.other)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.owned = []
        self.children = []

    def tearDown(self):
        for process in self.owned:
            try:
                # psutil's instance checks creation time before kill (PID reuse).
                if Path(process.exe()).parent in (self.exe.parent, self.other.parent):
                    process.kill()
                    process.wait(timeout=5)
            except self.psutil.NoSuchProcess:
                pass
        for child in self.children:
            child.wait(timeout=5)

    def invoke(self, target=None, **args):
        cmd = [shutil.which("powershell"), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
               str(ROOT / "Tool/scripts/launch-gui.ps1"), "-Target", str(target or self.exe),
               "-Json", "-WaitSeconds", "2"]
        for key, value in args.items():
            cmd.append("-" + key)
            if value is not True:
                cmd.append(str(value))
        run = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
        try:
            data = json.loads(run.stdout)
        except ValueError:
            self.fail(run.stdout + run.stderr)
        for instance in data["instances"]:
            if data["launchRequested"] and data["launched"]:
                self.owned.append(self.psutil.Process(instance["pid"]))
        return run.returncode, data

    def spawn(self, path):
        child = subprocess.Popen([str(path)], creationflags=subprocess.CREATE_NO_WINDOW)
        self.children.append(child)
        self.owned.append(self.psutil.Process(child.pid))
        time.sleep(0.15)
        return child.pid

    def test_default_launch_records_arguments_cwd_and_real_identity(self):
        rc, data = self.invoke(Cwd=self.base, Arguments='"hello world" second', ListWindows=True)
        self.assertEqual(rc, 0, data)
        self.assertEqual(data["status"], "STARTED")
        self.assertTrue(data["launchRequested"])
        self.assertFalse(data["functionalityVerified"])
        self.assertIsNone(data["creationFlags"])
        self.assertNotIn("hello world", json.dumps(data))
        receipt = Path(str(self.exe) + ".receipt")
        deadline = time.monotonic() + 3
        while not receipt.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        lines = receipt.read_text().splitlines()
        self.assertEqual(Path(lines[0]), self.base)
        self.assertEqual(lines[1], "hello world\tsecond")
        rc, reused = self.invoke()
        self.assertEqual(rc, 0, reused)
        self.assertTrue(reused["reusedExisting"])
        self.assertFalse(reused["launchRequested"])

    def test_same_name_other_directory_is_not_target(self):
        self.spawn(self.other)
        rc, data = self.invoke(Mode="attach")
        self.assertEqual(rc, 4, data)
        self.assertFalse(data["launched"])
        self.assertEqual(data["instances"], [])

    def test_multiple_instances_require_explicit_pid(self):
        first = self.spawn(self.exe)
        second = self.spawn(self.exe)
        rc, data = self.invoke()
        self.assertEqual(rc, 6, data)
        self.assertFalse(data["launchRequested"])
        self.assertEqual({x["pid"] for x in data["instances"]}, {first, second})
        rc, selected = self.invoke(Mode="attach", InstancePid=second)
        self.assertEqual(rc, 0, selected)
        self.assertEqual([x["pid"] for x in selected["instances"]], [second])

    def test_missing_selected_pid_never_launches_and_user_mode_is_explicit(self):
        rc, absent = self.invoke(InstancePid=2147483647)
        self.assertEqual(rc, 4, absent)
        self.assertFalse(absent["launchRequested"])
        rc, manual = self.invoke(Mode="user")
        self.assertEqual(rc, 5, manual)
        self.assertEqual(manual["status"], "WAIT_USER")
        self.assertFalse(manual["launchRequested"])

    def test_existing_instance_does_not_silently_ignore_new_arguments(self):
        self.spawn(self.exe)
        rc, data = self.invoke(Arguments='--different-mode')
        self.assertEqual(rc, 2, data)
        self.assertFalse(data["launchRequested"])
        self.assertTrue(data["diagnostics"])

    def test_invalid_target_returns_structured_failure(self):
        rc, data = self.invoke(target=self.base / "missing.exe")
        self.assertEqual(rc, 2, data)
        self.assertTrue(data["diagnostics"])
        self.assertFalse(data["launchRequested"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
