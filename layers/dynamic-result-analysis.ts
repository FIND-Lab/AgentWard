import { Warning } from "../core/warnings.ts";
import type { DecisionAlignmentResult } from "./decision-alignment.ts";

export type DynamicDecisionAction = {
  disposition: "allow" | "review" | "block";
  warning: Warning | null;
  details: string;
};

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

  const details = [
    `alignment: ${result.alignment}`,
    `deviationLevel: ${result.deviationLevel}`,
    `confidence: ${result.confidence}`,
    `reason: ${result.reason}`,
  ].join("\n");

  if (result.alignment === "aligned") {
    return {
      disposition: "allow",
      warning: null,
      details,
    };
  }

  if (result.alignment === "uncertain") {
    return {
      disposition: "review",
      warning: new Warning(
        "Decision Review Required",
        "The assistant action is not clearly aligned and requires manual confirmation.",
        details,
      ),
      details,
    };
  }

  if (result.deviationLevel === "high") {
    return {
      disposition: "block",
      warning: new Warning(
        "Decision Misalignment Detected",
        "The assistant action is clearly misaligned with the user's intent.",
        details,
      ),
      details,
    };
  }

  if (result.deviationLevel === "medium" && result.confidence !== "low") {
    return {
      disposition: "block",
      warning: new Warning(
        "Decision Misalignment Detected",
        "The assistant action is clearly misaligned with the user's intent.",
        details,
      ),
      details,
    };
  }

  return {
    disposition: "review",
    warning: new Warning(
      "Decision Review Required",
      "The assistant action is not clearly aligned and requires manual confirmation.",
      details,
    ),
    details,
  };
}
