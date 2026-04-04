import { Warning } from "../warnings.ts";
import { getLogger } from "../logger.ts";

export const DANGEROUS_COMMAND_DETECTED = new Warning(
  "Dangerous Command Detected",
  "The system detected a potentially dangerous command in the tool call.",
  ""
);

export const INFINITE_LOOP_DETECTED = new Warning(
  "Infinite Loop Detected",
  "The system detected a potential infinite loop in the command.",
  ""
);

export const SYSTEM_DESTRUCTION_DETECTED = new Warning(
  "System Destruction Command Detected",
  "The system detected a command that could destroy system files or data.",
  "Commands like rm -rf /, dd to disk devices, or disk formatting are blocked."
);

export const PRIVILEGE_ESCALATION_DETECTED = new Warning(
  "Privilege Escalation Detected",
  "The system detected a command attempting to elevate privileges dangerously.",
  "Suspicious sudo usage or permission changes on critical paths are blocked."
);

export const REMOTE_CODE_EXECUTION_DETECTED = new Warning(
  "Remote Code Execution Detected",
  "The system detected an attempt to execute remote code.",
  "Piping curl/wget output directly to shell is dangerous and blocked."
);

export const SENSITIVE_DATA_ACCESS_DETECTED = new Warning(
  "Sensitive Data Access Detected",
  "The system detected an attempt to access sensitive files.",
  "Access to password files, SSH keys, API credentials, and environment variables is blocked."
);

export const REVERSE_SHELL_DETECTED = new Warning(
  "Reverse Shell Detected",
  "The system detected a potential reverse shell or backdoor command.",
  "Network redirects to interactive shells are blocked."
);

export const RESOURCE_EXHAUSTION_DETECTED = new Warning(
  "Resource Exhaustion Detected",
  "The system detected a command that could exhaust system resources.",
  "Fork bombs, disk fillers, and process killers are blocked."
);

// System destruction patterns - commands that could destroy data or system
const SYSTEM_DESTRUCTION_PATTERNS: RegExp[] = [
  // rm -rf / and variants targeting root or specific paths
  /\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(-[a-zA-Z]*r[a-zA-Z]*\s+)?\/{1,2}\s*($|;|&|\||<)/,
  /\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(-[a-zA-Z]*r[a-zA-Z]*\s+)?\/{1,2}[a-zA-Z0-9_\-\/]+/,  // rm -rf / followed by path
  /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(-[a-zA-Z]*f[a-zA-Z]*\s+)?\/{1,2}\s*($|;|&|\||<)/,
  /\brm\s+.*?\/[a-zA-Z0-9_\-\.]+\s*($|;|&|\||<)/,  // rm with any path ending
  /\brm\s+.*?\*\s*($|;|&|\||<)/,  // rm with wildcards

  // dd to disk devices
  /\bdd\s+.*\bof=\/dev\/[sh]d[a-z]/,
  /\bdd\s+.*\bof=\/dev\/disk/,
  /\bdd\s+.*\bof=\/dev\/nvme/,

  // Disk formatting
  /\bmkfs\.\w+\s+\/dev\//,
  /\bnewfs\s+\/dev\//,

  // Direct device overwriting
  />\s*\/dev\/[sh]d[a-z]/,
  />\s*\/dev\/disk/,

  // Wiping commands
  /\bshred\s+(?:-[a-zA-Z]*\s+)*\/dev\//,
];

// Privilege escalation patterns
const PRIVILEGE_ESCALATION_PATTERNS: RegExp[] = [
  // Dangerous sudo usage with destructive commands
  /\bsudo\s+rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(-[a-zA-Z]*r[a-zA-Z]*\s+)?\//,
  /\bsudo\s+dd\s/,
  /\bsudo\s+mkfs/,
  /\bsudo\s+newfs/,
  /\bsudo\s+(?:bash|sh|zsh|dash)\s+-c/,
  /\bsudo\s+.*?\|\s*(?:sh|bash|zsh|dash)\b/,

  // Dangerous chmod on critical paths
  /\bchmod\s+(?:-[a-zA-Z]*\s+)*777\s+\//,
  /\bchmod\s+(?:-[a-zA-Z]*\s+)*777\s+\/etc/,
  /\bchmod\s+(?:-[a-zA-Z]*\s+)*777\s+\/usr/,
  /\bchmod\s+(?:-[a-zA-Z]*\s+)*777\s+\/bin/,
  /\bchmod\s+(?:-[a-zA-Z]*\s+)*777\s+\/sbin/,

  // chown system directories
  /\bchown\s+(?:-[a-zA-Z]*\s+)*[^\s]+:\s*\/etc/,
  /\bchown\s+(?:-[a-zA-Z]*\s+)*[^\s]+:\s*\/usr/,
];

// Remote code execution patterns
const REMOTE_CODE_EXECUTION_PATTERNS: RegExp[] = [
  // curl | shell pipes
  /\bcurl\s+.*?\|\s*(?:sh|bash|zsh|dash)\b/,
  /\bcurl\s+.*?\|\s*\$?(?:SHELL|0)\b/,
  /\bcurl\s+.*?\|\s*eval\s/,

  // wget pipe execution
  /\bwget\s+.*?\s+-O-\s*.*?\|\s*(?:sh|bash|zsh|dash)\b/,
  /\bwget\s+.*?\s+-qO-\s*.*?\|\s*(?:sh|bash|zsh|dash)\b/,
  /\bwget\s+.*?\s+.*\|\s*(?:sh|bash|zsh|dash)\b/,

  // Download and execute patterns
  /\b(?:curl|wget)\s+.*?\s+&&\s+(?:sh|bash|chmod\s+\+x)/,
  /\b(?:curl|wget)\s+.*?\s+-o\s+.*\s+&&\s+chmod\s+\+x/,

  // eval with command substitution
  /\beval\s*\$?\s*[\(\`]/,

  // Source remote files
  /\.\s*\$\(curl/,
  /source\s*\$\(curl/,
];

// Reverse shell patterns
const REVERSE_SHELL_PATTERNS: RegExp[] = [
  // Bash reverse shell
  /\b(?:bash|sh)\s+-i\s+>&\s*\/dev\/tcp\//,
  /\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5}/,
  /\bbash\s+-i\s+.*?\/dev\/tcp\//,

  // Netcat reverse shell variants
  /\b(?:nc|ncat|netcat)\s+-[el].*?(?:-[c\s]+)?\/(?:ba)?sh/,
  /\b(?:nc|ncat|netcat)\s+-[el].*?exec:/,
  /\b(?:nc|ncat)\s+-[el].*?-c\s*\/(ba)?sh/,

  // Socat reverse shell
  /\bsocat\s+.*?exec:\/\/(?:ba)?sh/,
  /\bsocat\s+.*?EXEC:\/\/(?:ba)?sh/,

  // Socket connections to shell
  /\b(?:sh|bash|dash|zsh)\s+-i\s+.*?>\s*\/dev\/tcp\//,
  /\b(?:sh|bash|dash|zsh)\s+.*?\d+>&\d+/,

  // Python reverse shell
  /\bpython\w*\s+.*?socket.*?connect/,
  /\bpython\w*\s+.*?socket.*?exec/,

  // Perl reverse shell
  /\bperl\s+.*?socket.*?connect/,
  /\bperl\s+.*-e.*socket/,

  // Ruby reverse shell
  /\bruby\s+.*?socket.*?connect/,
  /\bruby\s+.*-rsocket.*-e/,
];

// Sensitive data access patterns
const SENSITIVE_DATA_ACCESS_PATTERNS: RegExp[] = [
  // Password files
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/etc\/shadow/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/etc\/gshadow/,
  /\b(?:cat|less|more|head|tail)\s+.*?\/etc\/master\.passwd/,  // BSD

  // SSH keys and config (allow cat of authorized_keys for legitimate use, but warn)
  /\b(?:cat|less|more|head|tail)\s+.*?\/\.ssh\/id_/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.ssh\/id_rsa/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.ssh\/id_dsa/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.ssh\/id_ecdsa/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.ssh\/id_ed25519/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.ssh\/config/,
  /\b(?:scp|rsync)\s+.*?\/\.ssh\//,

  // Cloud credentials
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.aws\/credentials/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.aws\/config/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.azure\/credentials/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.azure\//,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.gcp\/credentials/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.config\/gcloud\/credentials/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.config\/gcloud\/application_default_credentials/,

  // Docker credentials
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.docker\/config\.json/,

  // Kubernetes credentials
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.kube\/config/,

  // Environment variables (may contain secrets)
  /\benv\s*$/,
  /\bprintenv\s*$/,
  /\bset\s*$/,
  /\becho\s+\$.+$/,
  /\becho\s+\$[A-Z_]+/,  // Common env var pattern
  /\bexport\s+-p\s*$/,  // Export all variables

  // Shell history (may contain passwords)
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.bash_history/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.zsh_history/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.sh_history/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/history/,

  // Database credentials
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\.my\.cnf/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\.pgpass/,

  // API keys and tokens files
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\.(?:token|apikey|secret|password|passwd|key)$/,
  /\b(?:cat|less|more|head|tail|vim|nano)\s+.*?\/\.(?:token|apikey|secret|password|passwd|key)/,
];

// Resource exhaustion patterns
const RESOURCE_EXHAUSTION_PATTERNS: RegExp[] = [
  // Fork bombs - various syntax
  /:\s*\(\s*\)\s*\{\s*:.*?:.*?:\s*\}\s*;\s*:/,
  /:\s*\(\s*\)\s*\{\s*:.*?:.*?:\s*\}\s*;\s*:\s*\(\s*\)/,
  /\w+\s*\(\s*\)\s*\{\s*\w+.*\|\s*\w+.*&\s*\}\s*;\s*\w+/,
  // Classic fork bomb: :(){ :|:& };:
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
  // fork bomb with different spacing
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:.*&.*\}.*;.*:/,

  // Disk filling
  /\byes\s+.*?>\s*\/dev\/sd/,
  /\byes\s+.*?>\s*\/srv\/.*\//,

  // Memory exhaustion
  /\bfillmem/,
  /\bmalloc.*while.*true/,

  // Process killers
  /\bkill\s+-?9\s+1\b/,
  /\bkill\s+-?9\s+-1\b/,
  /\bpkill\s+-?9\s+/,
  /\bkillall\s+-?9/,

  // Fork/shell bomb patterns
  /\bbash\s+-c\s+.*?\|.*&.*\|/,
];

// Infinite loop patterns
const INFINITE_LOOP_PATTERNS: RegExp[] = [
  // while true variants
  /\bwhile\s*\(?\s*(?:true|:|1)\s*\)?\s*[;{]?\s*(?:do|:|\{)/,
  /\bwhile\s*\[\s*(?:1|true)\s*\]/,
  /\bwhile\s+:\s*;?\s*(?:do|\{)/,

  // for infinite loops
  /\bfor\s*\(\(\s*;\s*;\s*\)\)/,
  /\bfor\s+\(\s*;+\s*\)/,
  /\bfor\s*\(\s*;\s*;\s*\)\s*\{/,

  // until false
  /\buntil\s+(?:false|0)/,

  // C-style while
  /\bwhile\s*\(\s*(?:1|true)\s*\)/,
];

// Helper function to check if text matches any pattern in the list
function matchesAnyPattern(text: string, patterns: RegExp[]): boolean {
  return patterns.some(pattern => {
    const match = pattern.test(text);
    if (match) {
      getLogger().info(`[exec-control] Pattern matched: ${pattern.source}`);
    }
    return match;
  });
}

export function toolCallDetect(
  toolName: string,
  params: Record<string, unknown>
): Warning | null {
  if (toolName !== "exec") return null;

  const command = params.command;
  if (typeof command !== "string") return null;

  // System destruction detection
  if (matchesAnyPattern(command, SYSTEM_DESTRUCTION_PATTERNS)) {
    return SYSTEM_DESTRUCTION_DETECTED;
  }

  // Privilege escalation detection
  if (matchesAnyPattern(command, PRIVILEGE_ESCALATION_PATTERNS)) {
    return PRIVILEGE_ESCALATION_DETECTED;
  }

  // Remote code execution detection
  if (matchesAnyPattern(command, REMOTE_CODE_EXECUTION_PATTERNS)) {
    return REMOTE_CODE_EXECUTION_DETECTED;
  }

  // Reverse shell detection
  if (matchesAnyPattern(command, REVERSE_SHELL_PATTERNS)) {
    return REVERSE_SHELL_DETECTED;
  }

  // Sensitive data access detection
  if (matchesAnyPattern(command, SENSITIVE_DATA_ACCESS_PATTERNS)) {
    return SENSITIVE_DATA_ACCESS_DETECTED;
  }

  // Resource exhaustion detection
  if (matchesAnyPattern(command, RESOURCE_EXHAUSTION_PATTERNS)) {
    return RESOURCE_EXHAUSTION_DETECTED;
  }

  // Infinite loop detection
  if (matchesAnyPattern(command, INFINITE_LOOP_PATTERNS)) {
    return INFINITE_LOOP_DETECTED;
  }

  return null;
}
