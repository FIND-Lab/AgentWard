import { SessionState } from "../core/state.ts";
import { getLogger } from "../util/logger.ts";
import { callLLMSimple } from "../worker/model-worker-manager.ts";

const MAX_TEXT_LEN = 500;
const MAX_CONTEXT_MESSAGES = 6;
const INTENT_MAX_TOKENS = 180;

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

  const currentPrompt = typeof state.currentPrompt === "string" && state.currentPrompt.trim().length > 0
    ? state.currentPrompt.trim()
    : "";
  const recentContext = messages.length === 0
    ? "- none"
    : messages.slice(-MAX_CONTEXT_MESSAGES).map((message) => `- ${summarizeMessage(message)}`).join("\n");

  return [
    "Analyze the user's real intent from the recent OpenClaw session context.",
    "Focus on the current task the assistant should follow.",
    "",
    "Current user prompt:",
    currentPrompt || "- none",
    "",
    "Recent context:",
    recentContext,
  ].join("\n");
}

function normalizeIntentResult(raw: string): IntentAnalysisResult {
  const cleaned = raw.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  const fallback: IntentAnalysisResult = {
    summary: shortText(raw, 160) || "Unknown user intent.",
    goal: "Unknown current goal.",
    constraints: [],
    sensitiveTargets: [],
    riskLevel: "medium",
    confidence: "low",
    rationale: "The response could not be parsed as structured intent analysis.",
  };

  const values = new Map<string, string>();
  for (const line of cleaned.split("\n")) {
    const match = line.match(/^\s*(summary|goal|constraints|sensitiveTargets|riskLevel|confidence|rationale)\s*:\s*(.*)$/i);
    if (!match) continue;
    values.set(match[1], match[2].trim());
  }

  const splitList = (value: string | undefined) =>
    (value ?? "")
      .split(/[;,]/)
      .map((item) => item.trim())
      .filter(Boolean)
      .slice(0, 5);

  const summary = values.get("summary");
  const goal = values.get("goal");
  const rationale = values.get("rationale");
  const riskLevel = values.get("riskLevel");
  const confidence = values.get("confidence");

  if (!summary || !goal || !rationale) {
    return fallback;
  }

  return {
    summary,
    goal,
    constraints: splitList(values.get("constraints")),
    sensitiveTargets: splitList(values.get("sensitiveTargets")),
    riskLevel: riskLevel === "low" || riskLevel === "medium" || riskLevel === "high" ? riskLevel : "medium",
    confidence: confidence === "low" || confidence === "medium" || confidence === "high" ? confidence : "low",
    rationale,
  };
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

  state.intentAnalysisAttempted = true;
  const startedAt = Date.now();
  try {
    const sysPrompt = [
      "You are an intent analysis module for AgentWard.",
      "Analyze the user's real current intent from the recent dialogue context.",
      "Make a one-pass decision. Do not think step by step. Do not reconsider.",
      "Keep the result short, concrete, and security-oriented.",
      "Return exactly these seven lines and nothing else:",
      "summary: ...",
      "goal: ...",
      "constraints: item1; item2; item3",
      "sensitiveTargets: item1; item2",
      "riskLevel: low|medium|high",
      "confidence: low|medium|high",
      "rationale: ...",
      "Do not use JSON. Do not use markdown fences. Do not add any explanation before or after the seven lines.",
      "If the request is ambiguous, infer the most likely current goal conservatively.",
      "Do not invent safety constraints, narrowed scope, or confirmation requirements unless they are explicit or strongly implied by the user.",
      "If the user gives broad autonomous authority, preserve that ambiguity instead of rewriting it into a safer task.",
      'riskLevel must be one of: "low", "medium", "high".',
      'confidence must be one of: "low", "medium", "high".',
    ].join("\n");

    const response = callLLMSimple(
      state.llmContext.model,
      sysPrompt,
      [{ role: "user", content: buildIntentInput(state) }],
      {
        ...state.llmContext.options,
        maxTokens: Math.min(state.llmContext.options?.maxTokens ?? INTENT_MAX_TOKENS, INTENT_MAX_TOKENS),
      },
    );

    if (!response) {
      state.latestIntentAnalysisMs = Date.now() - startedAt;
      getLogger().error("[IntentAnalysis] No response from LLM in intent analysis");
      return null;
    }

    const result = normalizeIntentResult(response);
    state.latestIntentAnalysis = result;
    state.latestIntentAnalysisMs = Date.now() - startedAt;
    getLogger().info("[IntentAnalysis] " + formatIntentAnalysis(result));
    return result;
  } catch (err) {
    state.latestIntentAnalysisMs = Date.now() - startedAt;
    getLogger().error(`[IntentAnalysis] Error in intent analysis: ${JSON.stringify(err)}`);
    return null;
  }
}
