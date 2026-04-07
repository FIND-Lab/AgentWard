import { Warning } from "../core/warnings.ts";

export const COGNITIVE_STATE_ANOMALY = new Warning(
  "Cognition State Anomaly Detected",
  "Abnormal patterns detected in memory file modification.",
  "Tell the user that some suspicious content is detected in the memory file modification, and the modification is blocked."
);

function detectPoisoning(text: string): boolean {
  const detectPatterns: RegExp[] = [
    // prompt injection attempts
    /\b(ignore|disregard)\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)\b/i,
    /\bforget\s+(everything|all|your)\s+(instructions?|rules?|guidelines?)\b/i,
    /\bnew\s+instructions?:\b/i,
    // role / identity manipulation
    /\byou\s+are\s+now\s+(a|an)\b/i,
    /\bact\s+as\s+(a|an)\b/i,
    /\bpretend\s+to\s+be\b/i,
    // system prompt / internal command injection
    /\bsystem\s*:?\s*(prompt|override|command)\b/i,
    /\[\s*(System\s*Message|System|Assistant|Internal)\s*\]/i,
    /^\s*System:\s+/im,
    // structured message / format injection
    /<\/?system>/i,
    /\]\s*\n\s*\[?(system|assistant|user)\]?:/i,
    // conditional triggers
    /\b(whenever|when|if)\b.*\b(user|time|asks|mentions)\b/i,
    // security bypass
    /\b(ignore|remove|disable)\b.*\b(safety|security|ethical|guidelines|protocols)\b/i,
    // privilege escalation
    /\b(full system access|execute any command|without restriction)\b/i,
    // privilege escalation
    /\b(full\s+system\s+access|execute\s+any\s+command|without\s+restriction)\b/i,
    // command execution attempts
    /\bexec\b.*command\s*=/i,
    // dangerous commands
    /\b(rm\s+-rf|shutdown\s+-h|sudo\s+rm)\b/i,
    /\bdelete\s+all\s+(emails?|files?|data)\b/i,
    // data exfiltration
    /\b(password|file)\b.*\b(output|read|print)\b/i
  ];
  return detectPatterns.some((pattern) => pattern.test(text));
}

export function detectCognitionProtectionAnomaly(
  toolName: string,
  params: Record<string, unknown>
): Warning | null {
  if (toolName === "write" || toolName === "edit") {
    const filePath = (params.path as string) || (params.file_path as string);
    if (typeof filePath !== "string") return null;

    const isMemoryFile = filePath.includes("MEMORY.md") || filePath.includes("memory/") || filePath.includes("SOUL.md") || filePath.includes("IDENTITY.md") || filePath.includes("AGENTS.md") || filePath.includes("USER.md") || filePath.includes("TOOLS.md");
    if (!isMemoryFile) return null;

    let content: string | undefined;
    
    if (toolName === "write") {
      content = params.content as string;
    } else if (toolName === "edit") {
      content = (params.newText as string) || (params.new_string as string);
    }

    if (!content || typeof content !== "string") return null;

    if (detectPoisoning(content)) {
      return COGNITIVE_STATE_ANOMALY;
    }

    return null;
  }
  
  if (toolName === "exec") {
    const command = params.command as string;
    if (!command || typeof command !== "string") return null;
    
    const memoryFilePatterns = [
      /MEMORY\.md/i,
      /memory\//i,
      /SOUL\.md/i,
      /IDENTITY\.md/i,
      /AGENTS\.md/i,
      /USER\.md/i,
      /TOOLS\.md/i,
    ];

    const hasWriteCommand = [
      /\becho\b.*>{1,2}/i,   // echo ... > / >> file
      /\becho.*\|.*tee/i,      // echo | tee
      /\bcat\b.*>{1,2}/i,    // cat ... > / >> file
      /\bcat.*\|.*tee/i,       // cat | tee
      /\bprintf\b.*>{1,2}/i,  // printf ... > / >> file
      /\btee\s+-a/i,           // tee -a file
      /\btee\s+>{1,2}/i,           // tee > / >> file
      /\bawk\b.*>{1,2}/i,    // awk ... > / >> file

      />{1,2}\s*\S+\s*<<\s*\w+/i, // > / >> file << EOF

      /\bsed\b.*\s-[a-z]*i/i,           // sed -i
      /\bpatch\b/i,                     // patch
      /\btruncate\b/i,                  // truncate

      /\bpython3?\b.*\s-c\b/i,          // python -c / python3 -c
      /\bnode\b.*\s-e\b/i,              // node -e
      /\bperl\b.*\s-e\b/i,             // perl -e
      /\bruby\b.*\s-e\b/i,             // ruby -e

      /\bcp\b/i,                        // cp source target
      /\bmv\b/i,                        // mv source target
      /\bdd\b.*\bof=/i,                 // dd of=file
      /\binstall\b.*\s-[a-z]*m\b/i,     // install -m

      /\bcurl\b.*\s-[A-Za-z]*o\b/i,     // curl -o file / curl -Lo file
      /\bwget\b.*\s-[A-Za-z]*[Oo]\b/i,  // wget -O file
    ].some(pattern => pattern.test(command));
    
    if (hasWriteCommand) {
      for (const pattern of memoryFilePatterns) {
        if (pattern.test(command)) {
          if (detectPoisoning(command)) {
            return COGNITIVE_STATE_ANOMALY;
          }
        }
      }
    }
    
    return null;
  }
  
  return null;
}