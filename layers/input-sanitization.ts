import { Warning } from "../warnings.ts";
import { getLogger } from "../logger.ts";

export const INJECTION_DETECTED = new Warning(
  "Injection Detected",
  "The system detected potential prompt injection in the tool response.",
  ""
);

export const PROFANITY_DETECTED = new Warning(
  "Profanity Detected",
  "The system detected inappropriate language in the tool response.",
  ""
);

export function inputDetect(content: unknown): Warning | null {
  if (typeof content === "string") {

    const templatePattern = [
        /<role>ASSISTANT<\/role>[\s\S]*?<role>HUMAN<\/role>/i,
        /<\|user\|>[\s\S]*?<\|end\|>/i,
        /<\|im_start\|>[\s\S]*?<\|im_end\|>/i,
        /<step> Source: assistant[\s\S]*?Destination: user/i,
        /<\|user\|>[\s\S]*?<\|endoftext\|>/i,
        /<\|start_header_id\|>[\s\S]*?<\|end_header_id\|>/i,
        /<\|end_of_sentence\|>[\s\S]*?<\|User\|>/i,
        /<\|im_end\|>[\s\S]*?<\|im_start\|>/i,
        /<\|EOT\|>[\s\S]*?<\|Instruction\|>/i,
        /\[\|endofturn\|][\s\S]*?\[|user\|]/i,
        /\[\/INST\][\s\S]*?\[INST\]\[\/INST\]/i,
        /<\/s>[\s\S]*?<s>user[\s\S]*?<\/s>/i,
        /Assistant:[\s\S]*?<\|end_of_sentence\|>User:/i,
        /<\|Assistant\|>[\s\S]*?<\|end_of_sentence\|><\|User\|>/i,
        /<\|end\|>[\s\S]*?<\|user\|>/i,
        /<end_of_turn>\n<start_of_turn>user[\s\S]*?<end_of_turn>\n/i,
        /<\|start_of_role\|>assistant<\|end_of_role\|>[\s\S]*?<\|start_of_role\|>user<\|end_of_role\|>/i,
        /<|endoftext\|>[\s\S]*?<|endoftext\|>/i,
        /<\[begin▁of▁sentence\]><\[end▁of▁sentence\]>/i,
    ];

    const jeilBreakPatterns = [
        /bypass(\s)+(policy|guardrail|safety|restriction)/i,
        /act(\s)+as(\s)+(?:an? )?(?:unfiltered|jailbroken|developer mode)\b/i,
        /do(\s)+not(\s)+follow(\s)+your(\s)+(rules|policies|constraints)/i,
        /pretend(\s)+you(\s)+are(\s)+not(\s)+an(\s)+ai/i,
    ];

    const instructionPatterns = [
        /execute.*sudo(\s)+rm(\s)+-rf/i,
        /until(\s)+tokens(\s)+are(\s)+exhausted/i,
        /ignore(\s)+(all)?(\s)*(all|any|previous|prior)(\s)+(instruction|order|command|task|)s?/i,
        /(send|list|show|summarize|provide)(\s)+.*(\s)+(api[_ -]?key|token|secret|password|credential)/i,
    ];

    let instructionScore = false;
    instructionPatterns.forEach((pattern) => {
      if (pattern.test(content)) {
        instructionScore = true;
        getLogger().info(`[input-sanitization] Detected Injection Instruction: "${content.match(pattern)?.[0]}"`);
        return
      }
    });

    let jailbreakScore = false;
    jeilBreakPatterns.forEach((pattern) => {
      if (pattern.test(content)) {
        jailbreakScore = true;
        getLogger().info(`[input-sanitization] Detected Jailbreak Content: "${content.match(pattern)?.[0]}"`);
        return
      }
    });

    let templateScore = false;
    templatePattern.forEach((pattern) => {
      if (pattern.test(content)) {
        templateScore = true;
        getLogger().info(`[input-sanitization] Detected Template Content: "${content.match(pattern)?.[0]}"`);
        return
      }
    });

    const isInstruction = instructionScore || jailbreakScore || templateScore;

    if (isInstruction) {
      return INJECTION_DETECTED;
    }

    return null;
  }
  if (Array.isArray(content)) {
    for (const item of content) {
      const result = inputDetect(item);
      if (result) return result;
    }
    return null;
  }
  if (content && typeof content === "object") {
    for (const value of Object.values(content)) {
      const result = inputDetect(value);
      if (result) return result;
    }
    return null;
  }
  return null;
}
