import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

function directory(value: string): string {
  try {
    const absolute = path.resolve(value);
    return fs.statSync(absolute).isDirectory() ? absolute : "";
  } catch {
    return "";
  }
}

/** A machine pointer is a candidate, not a binding to every new session. */
export function resolveCaseDirectory(cwd: string = process.cwd()): string {
  const explicit = process.env.SEEP_CASE_DIR?.trim();
  // An invalid explicit binding must not silently select another case.
  if (explicit) return path.isAbsolute(explicit) ? directory(explicit) : "";
  const workspace = path.resolve(cwd || process.cwd());
  const local = directory(path.join(workspace, ".seep-case"));
  if (local) return local;
  try {
    const pointer = fs.readFileSync(path.join(os.homedir(), ".seep", "current-case"), "utf8")
      .split(/\r?\n/).map(line => line.trim()).find(Boolean);
    if (!pointer || !path.isAbsolute(pointer)) return "";
    const candidate = directory(pointer);
    if (!candidate) return "";
    // A workspace may contain many projects. Mere containment is not a
    // binding; only being in the case itself can adopt the legacy pointer.
    const relative = path.relative(fs.realpathSync(workspace), fs.realpathSync(candidate));
    return relative === "" ? candidate : "";
  } catch {
    return "";
  }
}
