import { homedir } from "node:os";
import { join } from "node:path";

/**
 * The agent directory pi uses: `PI_CODING_AGENT_DIR` when set (with `~`
 * expanded), else `~/.pi/agent`. Same rule as pi's `getAgentDir()`, so an
 * extension and the CLI always read the same files.
 */
export function resolveAgentDir(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.PI_CODING_AGENT_DIR?.trim();
  if (!configured) return join(homedir(), ".pi", "agent");
  if (configured === "~") return homedir();
  if (configured.startsWith("~/") || configured.startsWith("~\\")) {
    return join(homedir(), configured.slice(2));
  }
  return configured;
}
