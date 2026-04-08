import { Warning } from "../core/warnings.ts";
import type { DecisionAlignmentResult } from "./decision-alignment.ts";

export type DynamicDecisionAction = {
  disposition: "allow" | "review" | "block";
  warning: Warning | null;
  details: string;
};

export const DECISION_REVIEW = new Warning(
  "Decision Review Required",
  "The assistant action is not clearly aligned and requires manual confirmation.",
  ""
);

export const DECISION_BLOCK = new Warning(
  "Decision Misalignment Detected",
  "The assistant action is clearly misaligned with the user's intent.",
  ""
);

function formatDecisionResult(result: DecisionAlignmentResult): string {
  return [
    `alignment: ${result.alignment}`,
    `deviationLevel: ${result.deviationLevel}`,
    `confidence: ${result.confidence}`,
    `reason: ${result.reason}`,
  ].join("\n");
}

function buildWarning(base: Warning, result: DecisionAlignmentResult): Warning {
  return new Warning(base.type, base.description, formatDecisionResult(result));
}

export function dynamicResultAnalysis(
  result: DecisionAlignmentResult | null,
): DynamicDecisionAction {
  if (!result) {
    return {
      disposition: "allow",
      warning: null,
      details: "No decision-alignment result was produced.",
    };
  }

  if (result.alignment === "aligned") {
    return {
      disposition: "allow",
      warning: null,
      details: formatDecisionResult(result),
    };
  }

  if (result.alignment === "uncertain") {
    return {
      disposition: "review",
      warning: buildWarning(DECISION_REVIEW, result),
      details: formatDecisionResult(result),
    };
  }

  if (result.deviationLevel === "high") {
    return {
      disposition: "block",
      warning: buildWarning(DECISION_BLOCK, result),
      details: formatDecisionResult(result),
    };
  }

  if (result.deviationLevel === "medium" && result.confidence !== "low") {
    return {
      disposition: "block",
      warning: buildWarning(DECISION_BLOCK, result),
      details: formatDecisionResult(result),
    };
  }

  return {
    disposition: "review",
    warning: buildWarning(DECISION_REVIEW, result),
    details: formatDecisionResult(result),
  };
}
