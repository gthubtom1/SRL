import { randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { resolveAgentDir } from "./agent-dir.ts";

/**
 * Personas are a directory, not a database.
 *
 * `<agentDir>/personas/<name>.md` — the file name *is* the persona's name and
 * its id, so the working flow is the one a file manager gives you: drop a file
 * in to add a persona, rename it to rename the persona, move it out to retire
 * it. Nothing else is written when the set changes; `personas.json` only holds
 * the two settings that are not per-persona (`mode`, `defaultId`).
 */
export const PERSONAS_DIR_NAME = "personas";
export const PERSONAS_SETTINGS_NAME = "personas.json";
export const RULES_FILE_NAME = "RULES.md";
export const PERSONA_FILE_EXTENSION = ".md";

export interface PersonaFile {
  /** File name without the extension. Stable enough to put in a session entry. */
  id: string;
  /** What the picker shows. Same string as `id`, by design. */
  name: string;
  path: string;
}

export type PersonaInjectMode = "every-turn" | "cached";

export interface PersonaSettings {
  /** How a persona reaches the model. `cached` writes prompt sections once. */
  mode: PersonaInjectMode;
  /** Persona a *new* conversation starts with; `null` means none. */
  defaultId: string | null;
  /** Also show the persona as a widget line above the composer, not just the status line. */
  showBadge: boolean;
}

const DEFAULTS: PersonaSettings = { mode: "cached", defaultId: null, showBadge: false };
const MAX_PERSONA_BYTES = 512 * 1024;

export function personasDir(agentDir: string = resolveAgentDir()): string {
  return join(agentDir, PERSONAS_DIR_NAME);
}

export function settingsPath(agentDir: string = resolveAgentDir()): string {
  return join(agentDir, PERSONAS_SETTINGS_NAME);
}

/** A persona id is a file name without its extension, so it must survive a path join. */
export function isValidPersonaId(id: unknown): id is string {
  return typeof id === "string"
    && id.length > 0
    && id.length <= 120
    && id === id.trim()
    && !/[/\\:*?"<>|\u0000-\u001f]/.test(id)
    && !id.startsWith(".")
    && !id.endsWith(PERSONA_FILE_EXTENSION);
}

function isPersonaFile(name: string): boolean {
  return name.endsWith(PERSONA_FILE_EXTENSION)
    && name.length > PERSONA_FILE_EXTENSION.length
    && !name.startsWith(".");
}

/**
 * Every persona on disk, newest name order aside, sorted the way a Chinese or
 * English file listing reads. The directory is re-read on every call: a file
 * added while a session is open shows up the next time the picker opens.
 */
export function listPersonas(agentDir: string = resolveAgentDir()): PersonaFile[] {
  const dir = personasDir(agentDir);
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }

  const personas: PersonaFile[] = [];
  for (const name of names) {
    if (!isPersonaFile(name)) continue;
    const path = join(dir, name);
    try {
      if (!statSync(path).isFile()) continue;
    } catch {
      continue;
    }
    const id = name.slice(0, -PERSONA_FILE_EXTENSION.length);
    if (!isValidPersonaId(id)) continue;
    personas.push({ id, name: id, path });
  }
  return personas.sort((a, b) => a.name.localeCompare(b.name, "zh-Hans-CN"));
}

/** The persona's text, or null when the file is gone (a persona deleted mid-session). */
export function readPersonaText(agentDir: string, id: string | null | undefined): string | null {
  if (!id || !isValidPersonaId(id)) return null;
  const path = join(personasDir(agentDir), `${id}${PERSONA_FILE_EXTENSION}`);
  try {
    const stat = statSync(path);
    if (!stat.isFile() || stat.size > MAX_PERSONA_BYTES) return null;
    return readFileSync(path, "utf8").trim() || null;
  } catch {
    return null;
  }
}

/**
 * Global rules live beside identities but are not one: they apply to every
 * conversation whether or not a persona is picked, so switching personas never
 * switches the rules off (and vice versa).
 */
export function readRulesText(agentDir: string = resolveAgentDir()): string | null {
  try {
    const text = readFileSync(join(agentDir, RULES_FILE_NAME), "utf8").trim();
    return text || null;
  } catch {
    return null;
  }
}

function asMode(value: unknown): PersonaInjectMode {
  return value === "every-turn" ? "every-turn" : "cached";
}

function asDefaultId(value: unknown): string | null {
  return isValidPersonaId(value) ? value : null;
}

export function normalizeSettings(input: unknown): PersonaSettings {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return { ...DEFAULTS };
  const raw = input as Record<string, unknown>;
  return {
    mode: raw.mode === undefined ? DEFAULTS.mode : asMode(raw.mode),
    defaultId: raw.defaultId === undefined ? DEFAULTS.defaultId : asDefaultId(raw.defaultId),
    showBadge: raw.showBadge === undefined ? DEFAULTS.showBadge : raw.showBadge === true,
  };
}

export function readSettings(agentDir: string = resolveAgentDir()): PersonaSettings {
  try {
    return normalizeSettings(JSON.parse(readFileSync(settingsPath(agentDir), "utf8")));
  } catch {
    return { ...DEFAULTS };
  }
}

/** Merge `patch` into the settings file, keeping keys this version does not know. */
export function writeSettings(patch: Record<string, unknown>, agentDir: string = resolveAgentDir()): PersonaSettings {
  let stored: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(readFileSync(settingsPath(agentDir), "utf8"));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("personas.json must contain an object");
    }
    stored = parsed as Record<string, unknown>;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const current = normalizeSettings(stored);

  const next: PersonaSettings = {
    mode: patch.mode === undefined ? current.mode : asMode(patch.mode),
    defaultId: patch.defaultId === undefined ? current.defaultId : asDefaultId(patch.defaultId),
    showBadge: patch.showBadge === undefined ? current.showBadge : patch.showBadge === true,
  };
  const merged = { ...stored, ...patch, mode: next.mode, defaultId: next.defaultId, showBadge: next.showBadge };
  const temporary = `${settingsPath(agentDir)}.${randomUUID()}.tmp`;
  try {
    mkdirSync(agentDir, { recursive: true });
    writeFileSync(temporary, `${JSON.stringify(merged, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
    renameSync(temporary, settingsPath(agentDir));
  } finally {
    try { unlinkSync(temporary); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  return next;
}

/**
 * Give an existing file a different name without touching its contents. Used by
 * the rename path so a persona keeps its text byte for byte.
 */
export function renamePersonaFile(agentDir: string, from: string, to: string): void {
  if (!isValidPersonaId(from) || !isValidPersonaId(to) || from === to) {
    throw new Error("rename needs two different valid persona names");
  }
  const dir = personasDir(agentDir);
  renameSync(join(dir, `${from}${PERSONA_FILE_EXTENSION}`), join(dir, `${to}${PERSONA_FILE_EXTENSION}`));
}
