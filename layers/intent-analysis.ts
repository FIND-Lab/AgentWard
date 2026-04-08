import { SessionState } from "../core/state.ts";
import { getLogger } from "../util/logger.ts";
import { callLLMSimple } from "../worker/model-worker-manager.ts";

const MAX_TEXT_LEN = 500;
const MAX_CONTEXT_MESSAGES = 6;

export type IntentAnalysisResult = {
  summary: string;
  goal: string;
  constraints: string[];
  sensitiveTargets: string[];
  riskLevel: "low" | "medium" | "high";
  confidence: "low" | "medium" | "high";
  rationale: string;
};

function shortText(value: unknown, maxLen = MAX_TEXT_LEN): string {
  let text = "";
  if (typeof value === "string") text = value;
  else {
    try {
      text = JSON.stringify(value);
    } catch {
      text = String(value);
    }
  }
  text = text.replace(/\s+/g, " ").trim();
  return text.length > maxLen ? `${text.slice(0, maxLen - 3)}...` : text;
}

function asMessage(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object") return null;
  if ("role" in value) return value as Record<string, unknown>;
  if ("message" in value && value.message && typeof value.message === "object") {
    return value.message as Record<string, unknown>;
  }
  return null;
}

function summarizeMessage(message: Record<string, unknown>): string {
  const role = typeof message.role === "string" ? message.role : "unknown";
  return `${role}: ${shortText(message.content)}`;
}

function buildIntentInput(state: SessionState): string {
  const messages = [...(state.historyMessages ?? []), ...(state.currentMessages ?? [])]
    .map(asMessage)
    .filter((message): message is Record<string, unknown> => message !== null);

  const recentContext = messages.length === 0
    ? "- none"
    : messages.slice(-MAX_CONTEXT_MESSAGES).map((message) => `- ${summarizeMessage(message)}`).join("\n");

  return [
    "Analyze the user's real intent from the recent OpenClaw session context.",
    "Focus on the current task the assistant should follow.",
    "",
    "Recent context:",
    recentContext,
  ].join("\n");
}

function parseStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is string => typeof item === "string")
    .map((item) => item.trim())
    .filter(Boolean)
    .slice(0, 5);
}

function normalizeIntentResult(raw: string): IntentAnalysisResult {
  const fallback: IntentAnalysisResult = {
    summary: shortText(raw, 160) || "Unknown user intent.",
    goal: "Unknown current goal.",
    constraints: [],
    sensitiveTargets: [],
    riskLevel: "medium",
    confidence: "low",
    rationale: "The response could not be parsed as structured intent analysis.",
  };

  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const riskLevel = parsed.riskLevel === "low" || parsed.riskLevel === "medium" || parsed.riskLevel === "high"
      ? parsed.riskLevel
      : "medium";
    const confidence = parsed.confidence === "low" || parsed.confidence === "medium" || parsed.confidence === "high"
      ? parsed.confidence
      : "low";

    return {
      summary: typeof parsed.summary === "string" ? parsed.summary.trim() : fallback.summary,
      goal: typeof parsed.goal === "string" ? parsed.goal.trim() : fallback.goal,
      constraints: parseStringArray(parsed.constraints),
      sensitiveTargets: parseStringArray(parsed.sensitiveTargets),
      riskLevel,
      confidence,
      rationale: typeof parsed.rationale === "string" ? parsed.rationale.trim() : fallback.rationale,
    };
  } catch {
    return fallback;
  }
}

export function formatIntentAnalysis(result: IntentAnalysisResult): string {
  const constraints = result.constraints.length > 0 ? result.constraints.join("; ") : "none";
  const targets = result.sensitiveTargets.length > 0 ? result.sensitiveTargets.join("; ") : "none";

  return [
    `summary: ${result.summary}`,
    `goal: ${result.goal}`,
    `constraints: ${constraints}`,
    `sensitiveTargets: ${targets}`,
    `riskLevel: ${result.riskLevel}`,
    `confidence: ${result.confidence}`,
    `rationale: ${result.rationale}`,
  ].join("\n");
}

export function analyzeUserIntent(state: SessionState): IntentAnalysisResult | null {
  if (!state.llmContext) {
    getLogger().error("[IntentAnalysis] LLM context not found for intent analysis");
    return null;
  }

  try {
    const sysPrompt = [
      "You are an intent analysis module for AgentWard.",
      "Analyze the user's real current intent from the recent dialogue context.",
      "Keep the result short, concrete, and security-oriented.",
      "If the request is ambiguous, infer the most likely current goal conservatively.",
      "Return valid JSON only with these keys:",
      "summary, goal, constraints, sensitiveTargets, riskLevel, confidence, rationale",
      'riskLevel must be one of: "low", "medium", "high".',
      'confidence must be one of: "low", "medium", "high".',
      "constraints and sensitiveTargets must be arrays of short strings.",
    ].join("\n");

    const response = callLLMSimple(
      state.llmContext.model,
      sysPrompt,
      [{ role: "user", content: buildIntentInput(state) }],
      state.llmContext.options,
    );

    if (!response) {
      getLogger().error("[IntentAnalysis] No response from LLM in intent analysis");
      return null;
    }

    const result = normalizeIntentResult(response);
    state.latestIntentAnalysis = result;
    getLogger().info("[IntentAnalysis] " + formatIntentAnalysis(result));
    return result;
  } catch (err) {
    getLogger().error(`[IntentAnalysis] Error in intent analysis: ${JSON.stringify(err)}`);
    return null;
  }
}
