"""Exercise real rewind command callbacks with synthetic session branches."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RewindBoundaries(unittest.TestCase):
    def test_earlier_turn_confirms_tools_in_later_turn_and_cancel_is_lossless(self):
        script = r'''
import assert from "node:assert/strict";
import {pathToFileURL} from "node:url";
const {default: extension} = await import(pathToFileURL(process.argv[2]));
const commands = new Map();
extension({on() {}, registerCommand: (name, command) => commands.set(name, command)});
const original = '  inspect C:\\folder\\a.bin\r\n<personality>literal</personality>  ';
const entries = [
  {type:"message", id:"u1", message:{role:"user", content:original}},
  {type:"message", id:"a1", message:{role:"assistant", content:"read only"}},
  {type:"message", id:"u2", message:{role:"user", content:"later operation"}},
  {type:"message", id:"a2", message:{role:"assistant", content:[{type:"toolCall", name:"write"}]}},
  {type:"message", id:"t2", message:{role:"toolResult", content:"written"}},
  {type:"message", id:"u3", message:{role:"user", content:"final plain turn"}},
  {type:"message", id:"a3", message:{role:"assistant", content:"done"}},
];
let confirms = 0, navigations = 0, editor = "existing draft", allow = false;
const ctx = {
  sessionManager:{getBranch:()=>entries},
  ui:{setStatus(){}, notify(){},
    select:async (_title, labels)=>labels.find(label=>label.startsWith("1.")),
    confirm:async ()=>{confirms++; return allow;},
    setEditorText:text=>{editor=text;},
  },
  navigateTree:async id=>{assert.equal(id,"u1"); navigations++; return {};},
};
await commands.get("rewind").handler("", ctx);
assert.equal(confirms,1,"rewinding earlier turn must confirm tools from later turns");
assert.equal(navigations,0,"cancellation must keep session branch");
assert.equal(editor,"existing draft","cancellation must keep existing draft");
allow=true;
await commands.get("rewind").handler("", ctx);
assert.equal(navigations,1);
assert.equal(editor,original,"restored text must preserve paths, tags and whitespace");
// Later tool work must not taint a final turn after that work.
ctx.navigateTree=async id=>{assert.equal(id,"u3"); navigations++; return {};};
await commands.get("undo-reply").handler("",ctx);
assert.equal(confirms,2,"plain final reply still permits one-command undo");
assert.equal(editor,"final plain turn");
console.log("PASS rewind later tools and original text");
'''
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node with TypeScript stripping is required")
        with tempfile.TemporaryDirectory(prefix="seep-rewind-") as folder:
            harness = Path(folder, "rewind.mjs")
            harness.write_text(script, encoding="utf-8")
            env = dict(os.environ, PI_CODING_AGENT_DIR=folder, NODE_NO_WARNINGS="1")
            env.pop("NODE_OPTIONS", None)
            proc = subprocess.run([node, "--experimental-strip-types", str(harness),
                                   str(ROOT / "Tool/prompts/packages/pi-seep-ext/extensions/rewind.ts")],
                                  cwd=folder, env=env, capture_output=True, text=True,
                                  encoding="utf-8", timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
