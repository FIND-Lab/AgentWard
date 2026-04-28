export type DetectionVerdict = "pass" | "requireApproval" | "block";

export interface DetectionResult {
  warning: Warning | null;
  verdict: DetectionVerdict;
  timeoutMs?: number;
  timeoutBehavior?: "allow" | "deny";
}

export function detectPass(): DetectionResult {
  return { warning: null, verdict: "pass" };
}

export function detectBlock(warning: Warning): DetectionResult {
  return { warning, verdict: "block" };
}

export function detectApprove(
  warning: Warning,
  opts?: { timeoutMs?: number; timeoutBehavior?: "allow" | "deny" },
): DetectionResult {
  return {
    warning,
    verdict: "requireApproval",
    timeoutMs: opts?.timeoutMs,
    timeoutBehavior: opts?.timeoutBehavior,
  };
}

export class Warning {
  type: string;
  description: string;
  details: string;
  constructor(type: string, description: string, details: string = "") {
    this.type = type;
    this.description = description;
    this.details = details;
  }
}

export function formatBasic(error: Warning | Warning[], header = "⚠️System Warning:"): string {
  if (Array.isArray(error)) {
    if (error)
      return error.map((e) => formatBasic(e, header)).join('\n');
    return `${header} Same reason as above`;
  }
  else {
    let baseMessage = `${header} ${error.type}\n${error.description}`;
    if (error.details)
      baseMessage = `${baseMessage}\n${error.details}`
    return baseMessage;
  }
}

export function formatCoverAssistantWarning(error: Warning | Warning[]): string {
  return `SYSTEM WARNING RECEIVED❗\n${formatBasic(error)}\nSorry, current task have been halted. Please rephrase and try again.`;
}

export function formatToolResultWarning(error: Warning | Warning[], blockHarmfulInput: boolean): string {
  if (blockHarmfulInput)
    return `${formatBasic(error)}\nThe tool result is blocked.`
  return formatBasic(error);
}

export function formatToolCallWarning(error: Warning | Warning[], level: number): string {
  // Backward compatible:
  // - legacy levels: 1(one-time) / 2(temp) / 3(perm)
  // - extended levels: 10(one-time) / 15(requireApproval) / 20(temp) / 30(perm)
  const normalizedLevel =
    level === 3 ? 30 : level === 2 ? 20 : level === 1 ? 10 : level;

  if (normalizedLevel >= 30) { // permanent (before user's next request)
    return `${formatBasic(error)}\nYour permission for any tool calls has been revoked. Stop the task immediately and tell the user to request again to recover the permission.`;
  } else if (normalizedLevel >= 20) { // temporary (until next assistant response)
    return `${formatBasic(error)}\nYour permission for tool calls has been temporarily suspended. The next assistant response will restore the permission.`;
  } else if (normalizedLevel >= 15) { // require approval
    return `${formatBasic(error)}\nThis action requires your confirmation before proceeding.`;
  } else if (normalizedLevel >= 10) { // one-time (only for this tool call)
    return `${formatBasic(error)}\nYour request for this tool call is rejected.`;
  }

  return formatBasic(error);
}

export function formatUserPrependWarning(error: Warning | Warning[], blockToolCall: boolean): string {
  if (blockToolCall)
    return `${formatBasic(error)}\nYour permission for any tool calls has been revoked. Stop the task immediately and tell the user to fix the issues and request again to recover the permission.`;
  return formatBasic(error);
}

export function formatMessageSendingWarning(error: Warning | Warning[], suspend_demo: string | null = null): string {
  if (suspend_demo)
    return `${formatBasic(error, "🛡️AgentWard Warning:")}\n${suspend_demo}`;
  return formatBasic(error, "🛡️AgentWard Warning:");
}
