import { readPersonaText, readSettings, type PersonaInjectMode, type PersonaSettings } from "./personas.ts";

/**
 * Per-conversation persona, stored in the conversation itself.
 *
 * Persona choices are conversation settings. Read all append-only entries in
 * append order, including entries outside the active branch: rewinding a turn
 * must not resurrect a persona that the user has since switched off.
 */
export const PERSONA_STATE_TYPE = "pi-seep-ext:persona";

/**
 * The persona entry the previous (fork) implementation wrote. Its ids are
 * generated (`p_k1udshge`) and no longer mean anything here, but its presence
 * still tells us this conversation's `personality` section was written by a
 * persona feature rather than by another extension — which is what makes it
 * safe to clean up when the conversation is switched to no persona.
 */
export const LEGACY_PERSONA_STATE_TYPES = ["pi-web:persona"] as const;

export function isPersonaStateType(customType: string | undefined): boolean {
  return customType === PERSONA_STATE_TYPE
    || (LEGACY_PERSONA_STATE_TYPES as readonly string[]).includes(customType ?? "");
}

export interface PersonaStateData {
  personaId: string | null;
  mode?: PersonaInjectMode;
}

interface EntryLike {
  type?: string;
  customType?: string;
  data?: unknown;
}

/** The last explicit choice, or `undefined` when it was never set. */
export function readPersonaState(entries: readonly EntryLike[]): string | null | undefined {
  let current: string | null | undefined;
  for (const entry of entries) {
    if (entry.type !== "custom" || entry.customType !== PERSONA_STATE_TYPE) continue;
    const data = entry.data;
    if (data === null || typeof data !== "object") continue;
    const personaId = (data as { personaId?: unknown }).personaId;
    // `null` is a decision ("no persona"), so it must win over an earlier pick.
    if (personaId === null) current = null;
    else if (typeof personaId === "string" && personaId.length > 0) current = personaId;
  }
  return current;
}

/**
 * Shared precedence with load-system-prompt: explicit choice (including off or
 * a missing selected card), then a usable directory default, then legacy.
 * `undefined` leaves PERSONALITY.md in charge; `null` explicitly suppresses it.
 */
export function resolvePersonaSelection(
  agentDir: string,
  entries: readonly EntryLike[],
  settings: PersonaSettings = readSettings(agentDir),
): string | null | undefined {
  const recorded = readPersonaState(entries);
  if (recorded !== undefined) return recorded && readPersonaText(agentDir, recorded) ? recorded : null;
  if (entries.some((entry) => entry.type === "custom" && isPersonaStateType(entry.customType))) return null;
  return settings.defaultId && readPersonaText(agentDir, settings.defaultId) ? settings.defaultId : undefined;
}
