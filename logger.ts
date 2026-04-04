import { appendFileSync, mkdirSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";

type Logger = {
  info: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string) => void;
};

let globalLogger: Logger | null = null;
let globalApi: OpenClawPluginApi | null = null;
let logFilePath: string | null = null;

function writeToFile(level: string, msg: string) {
  if (!logFilePath) return;
  const line = JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    message: msg,
  }) + "\n";
  appendFileSync(logFilePath, line, "utf8");
}

export function initFileLog() {
  if (logFilePath) return;
  const stateDir = process.env.OPENCLAW_STATE_DIR?.trim()
    ?? join(homedir(), ".openclaw");
  const logDir = join(stateDir, "agentward", "logs");
  mkdirSync(logDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  logFilePath = join(logDir, `${timestamp}.log`);
}

export function initLogger(api: OpenClawPluginApi) {
  globalLogger = {
    info: (msg) => { api.logger.info(msg); writeToFile("info", msg); },
    warn: (msg) => { api.logger.warn(msg); writeToFile("warn", msg); },
    error: (msg) => { api.logger.error(msg); writeToFile("error", msg); },
  };
  globalApi = api;
}

export function getLogger(): Logger {
  if (!globalLogger) {
    throw new Error("Logger not initialized");
  }
  return globalLogger;
}

export function getApi(): OpenClawPluginApi {
  if (!globalApi) {
    throw new Error("API not initialized");
  }
  return globalApi;
}
