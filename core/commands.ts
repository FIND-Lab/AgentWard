import type { PluginConfig } from "../config.ts";
import { getLogger } from "../util/logger.ts";

type ConfigSetter = (config: PluginConfig) => void;

type CommandContext = {
  args?: string;
};

/** Recursively list all leaf keys of an object with dot-notation paths. */
function listAllKeys(obj: unknown, prefix = ""): string[] {
  if (obj === null || typeof obj !== "object") return [];
  const keys: string[] = [];
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      keys.push(...listAllKeys(v, path));
    } else {
      keys.push(path);
    }
  }
  return keys;
}

/** Get a value from a nested object by dot-path. */
function getConfigAtPath(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current === null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

/** Set a value in a nested object by dot-path (mutates). */
function setConfigAtPath(obj: Record<string, unknown>, path: string, value: unknown): boolean {
  const parts = path.split(".");
  let current: unknown = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (current === null || typeof current !== "object") return false;
    current = (current as Record<string, unknown>)[parts[i]];
  }
  if (current === null || typeof current !== "object") return false;
  (current as Record<string, unknown>)[parts[parts.length - 1]] = value;
  return true;
}

/** Parse a raw string value into the appropriate type. */
function parseValue(raw: string): unknown {
  if (raw === "true") return true;
  if (raw === "false") return false;
  const num = Number(raw);
  if (!Number.isNaN(num) && raw.trim() !== "") return num;
  return raw;
}

/** Check that the parsed value matches the runtime type of the existing config field. */
function isTypeCompatible(existing: unknown, parsed: unknown): boolean {
  if (typeof existing === "boolean") return typeof parsed === "boolean";
  if (typeof existing === "number") return typeof parsed === "number";
  if (typeof existing === "string") return typeof parsed === "string";
  return false;
}

/** Check if a config path is allowed to be modified at runtime. */
function isValidConfigPath(config: Record<string, unknown>, path: string): boolean {
  if (!(path.startsWith("layers.") || path.startsWith("notifications."))) return false;

  const parts = path.split(".");
  let current: unknown = config;
  for (let i = 0; i < parts.length; i++) {
    if (current === null || typeof current !== "object") return false;
    if (!(parts[i] in current)) return false;
    current = (current as Record<string, unknown>)[parts[i]];
  }
  // Must be a leaf value, not an intermediate object that would wipe children.
  return current === null || typeof current !== "object";
}

/** Format the entire config as a readable tree (leaf values only). */
function formatConfigTree(config: PluginConfig): string {
  const allKeys = listAllKeys(config);
  const writableKeys = allKeys.filter((k) => isValidConfigPath(config, k));
  const lines = writableKeys.map((k) => {
    const value = getConfigAtPath(config, k);
    return `  ${k}: ${JSON.stringify(value)}`;
  });
  return lines.join("\n");
}

export function handleAgentWardCommand(
  ctx: CommandContext,
  config: PluginConfig,
  startupConfig: PluginConfig,
  setConfig: ConfigSetter,
): { text: string } {
  const tokens = (ctx.args ?? "").trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) {
    return { text: "Usage:\n  /agentward config get [key]\n  /agentward config set <key> <value>\n  /agentward config reset" };
  }

  const [subCmd, action, ...rest] = tokens;

  if (subCmd !== "config") {
    return { text: `Unknown sub-command: /agentward ${subCmd}\nUsage: /agentward config [get|set|reset]` };
  }

  if (action === "get") {
    const key = rest[0];
    if (!key) {
      getLogger().info("[AgentWard Command] config get (all keys)");
      const tree = formatConfigTree(config);
      return { text: `AgentWard Configuration:\n${tree}` };
    }
    const value = getConfigAtPath(config, key);
    if (value === undefined) {
      getLogger().warn(`[AgentWard Command] config get: key not found: ${key}`);
      return { text: `Config key not found: ${key}` };
    }
    getLogger().info(`[AgentWard Command] config get ${key} = ${JSON.stringify(value)}`);
    return { text: `${key} = ${JSON.stringify(value)}` };
  }

  if (action === "set") {
    if (rest.length < 2) {
      getLogger().warn(`[AgentWard Command] config set: missing arguments: ${rest.join(" ")}`);
      return { text: "Usage: /agentward config set <key> <value>" };
    }
    const [key, rawValue] = rest;

    getLogger().info(`[AgentWard Command] config set ${key} ${rawValue}`);

    if (!isValidConfigPath(config, key)) {
      getLogger().warn(`[AgentWard Command] config set: invalid path: ${key}`);
      return { text: `Invalid config path: ${key}\nOnly layers.* and notifications.* can be modified at runtime.` };
    }

    const value = parseValue(rawValue);
    const existing = getConfigAtPath(config, key);
    getLogger().info(`[AgentWard Command] config set: parsed=${JSON.stringify(value)} (type: ${typeof value}), existing=${JSON.stringify(existing)} (type: ${typeof existing})`);
    if (!isTypeCompatible(existing, value)) {
      getLogger().warn(`[AgentWard Command] config set: type mismatch for ${key}: expected ${typeof existing}, got ${typeof value}`);
      return { text: `Type mismatch for ${key}: expected ${typeof existing}, got ${typeof value}.` };
    }

    const success = setConfigAtPath(config, key, value);
    if (!success) {
      getLogger().error(`[AgentWard Command] config set: setConfigAtPath failed for ${key}`);
      return { text: `Failed to set config path: ${key}` };
    }

    setConfig(config);
    getLogger().info(`[AgentWard Command] config set: ${key} = ${JSON.stringify(value)} OK`);
    return { text: `${key} set to ${JSON.stringify(value)}` };
  }

  if (action === "reset") {
    getLogger().info("[AgentWard Command] config reset: restoring to startup state");
    const allKeys = listAllKeys(startupConfig);
    const writableKeys = allKeys.filter((k) => isValidConfigPath(config, k));
    getLogger().info(`[AgentWard Command] config reset: restoring ${writableKeys.length} keys`);
    for (const key of writableKeys) {
      const value = getConfigAtPath(startupConfig, key);
      setConfigAtPath(config, key, value);
    }
    setConfig(config);
    getLogger().info("[AgentWard Command] config reset: OK");
    return { text: "AgentWard configuration reset to startup state." };
  }

  return { text: `Unknown action: ${action}\nUsage: /agentward config [get|set|reset]` };
}
