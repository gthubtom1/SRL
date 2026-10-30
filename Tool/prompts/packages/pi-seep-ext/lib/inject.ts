import type { ContextMessage } from "./pi-api.ts";

export const PERSONALITY_SECTION = "personality";

/** Options contain raw section text; transcript sections are already rendered by Pi. */
export function renderSection(name: string, text: string): string {
  return `<${name}>\n${text}\n</${name}>`;
}

/**
 * Repair only named system sections in a request-local transcript. Older system
 * messages are deltas, so changing the first message alone can be overridden by
 * a later delta. Leave conversation content and unrelated system text untouched.
 */
export function patchSystemSections(
  messages: ContextMessage[],
  desired: Record<string, string | null>,
): void {
  const systems = messages.filter((message) => message.role === "system");
  const last = systems.at(-1);
  if (!last) return;
  for (const [name, value] of Object.entries(desired)) {
    let current: string | null = null;
    for (const message of systems) {
      if (message.sections && Object.hasOwn(message.sections, name)) {
        current = message.sections[name];
      }
    }
    if (current === value) continue;
    last.sections ??= {};
    last.sections[name] = value;
  }
}
