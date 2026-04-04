export class PluginConfig {
  llm: {
    provider: string;
    model: string;
    api: string;
    baseUrl: string;
    apiKeyEnv: string;
  };
  layers: {
    foundationScan: {
      enableFoundationScanDetection: boolean;
      enableIntervention: boolean;
      blockToolCallOnFoundationScanWarning: boolean;
      detectMaliciousSkills: {
        enable: boolean;
        ruleBasedDetection: boolean;
        semanticDetection: boolean;
        maxContentLength: number;
        maxConcurrency: number;
      };
      detectMisConfiguration: {
        enable: boolean;
      };
    };
    inputSanitization: {
      enableInputDetection: boolean;
      enableIntervention: boolean;
      temporaryBlockToolCall: boolean;
      blockHarmfulInput: boolean;
      coverContaminatedResponse: boolean;
    };
    cognitionProtection: {
      enableMemWriteDetection: boolean;
      enableIntervention: boolean;
    };
    decisionAlignment: {
      enableDecisionAlignmentDetection: boolean;
      enableIntervention: boolean;
    };
    execControl: {
      enableToolCallDetection: boolean;
      enableIntervention: boolean;
    };
  };
  logging: {
    level: "off" | "basic" | "event" | "ctx" | "full";
    enableFileLog: boolean;
  };
  worker: {
    timeout: number;
    debug: boolean;
    logLevel: string;
  };

  constructor() {
    this.llm = {
      provider: "",
      model: "",
      api: "",
      baseUrl: "",
      apiKeyEnv: "AGENT_WARD_API_KEY",
    };

    this.layers = {
      foundationScan: {
        enableFoundationScanDetection: true,
        enableIntervention: true,
        blockToolCallOnFoundationScanWarning: false,
        detectMaliciousSkills: {
          enable: true,
          ruleBasedDetection: true,
          semanticDetection: true,
          maxContentLength: 65536,
          maxConcurrency: 10,
        },
        detectMisConfiguration: {
          enable: true,
        },
      },
      inputSanitization: {
        enableInputDetection: true,
        enableIntervention: true,
        temporaryBlockToolCall: true,
        blockHarmfulInput: false,
        coverContaminatedResponse: false,
      },
      cognitionProtection: {
        enableMemWriteDetection: true,
        enableIntervention: true,
      },
      decisionAlignment: {
        enableDecisionAlignmentDetection: true,
        enableIntervention: true,
      },
      execControl: {
        enableToolCallDetection: true,
        enableIntervention: true,
      },
    };
    this.logging = {
      level: "basic",
      enableFileLog: true,
    };
    this.worker = {
      timeout: 60000,
      debug: false,
      logLevel: 'info',
    };
  }

  static fromPluginConfig(raw: unknown): PluginConfig {
    const config = new PluginConfig();
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      return config;
    }

    const layers = (raw as Record<string, unknown>).layers;
    if (layers && typeof layers === "object") {
      const foundationScan = (layers as Record<string, unknown>).foundationScan as Record<string, unknown> | undefined;
      if (foundationScan) {
        if (typeof foundationScan.enableFoundationScanDetection === "boolean")
          config.layers.foundationScan.enableFoundationScanDetection = foundationScan.enableFoundationScanDetection;
        if (typeof foundationScan.enableIntervention === "boolean")
          config.layers.foundationScan.enableIntervention = foundationScan.enableIntervention;
        if (typeof foundationScan.blockToolCallOnFoundationScanWarning === "boolean")
          config.layers.foundationScan.blockToolCallOnFoundationScanWarning = foundationScan.blockToolCallOnFoundationScanWarning;
        
        const detectMaliciousSkills = (foundationScan as Record<string, unknown>).detectMaliciousSkills as Record<string, unknown> | undefined;
        if (detectMaliciousSkills) {
          if (typeof detectMaliciousSkills.enable === "boolean")
            config.layers.foundationScan.detectMaliciousSkills.enable = detectMaliciousSkills.enable;
          if (typeof detectMaliciousSkills.ruleBasedDetection === "boolean")
            config.layers.foundationScan.detectMaliciousSkills.ruleBasedDetection = detectMaliciousSkills.ruleBasedDetection;
          if (typeof detectMaliciousSkills.semanticDetection === "boolean")
            config.layers.foundationScan.detectMaliciousSkills.semanticDetection = detectMaliciousSkills.semanticDetection;
          if (typeof detectMaliciousSkills.maxContentLength === "number" && detectMaliciousSkills.maxContentLength > 0)
            config.layers.foundationScan.detectMaliciousSkills.maxContentLength = detectMaliciousSkills.maxContentLength;
          if (typeof detectMaliciousSkills.maxConcurrency === "number" && detectMaliciousSkills.maxConcurrency > 0)
            config.layers.foundationScan.detectMaliciousSkills.maxConcurrency = detectMaliciousSkills.maxConcurrency;
        }
        
        const detectMisConfiguration = (foundationScan as Record<string, unknown>).detectMisConfiguration as Record<string, unknown> | undefined;
        if (detectMisConfiguration) {
          if (typeof detectMisConfiguration.enable === "boolean")
            config.layers.foundationScan.detectMisConfiguration.enable = detectMisConfiguration.enable;
        }
      }

      const inputSanitization = (layers as Record<string, unknown>).inputSanitization as Record<string, unknown> | undefined;
      if (inputSanitization) {
        if (typeof inputSanitization.enableInputDetection === "boolean")
          config.layers.inputSanitization.enableInputDetection = inputSanitization.enableInputDetection;
        if (typeof inputSanitization.enableIntervention === "boolean")
          config.layers.inputSanitization.enableIntervention = inputSanitization.enableIntervention;
        if (typeof inputSanitization.temporaryBlockToolCall === "boolean")
          config.layers.inputSanitization.temporaryBlockToolCall = inputSanitization.temporaryBlockToolCall;
        if (typeof inputSanitization.blockHarmfulInput === "boolean")
          config.layers.inputSanitization.blockHarmfulInput = inputSanitization.blockHarmfulInput;
        if (typeof inputSanitization.coverContaminatedResponse === "boolean")
          config.layers.inputSanitization.coverContaminatedResponse = inputSanitization.coverContaminatedResponse;
      }

      const cognitionProtection = (layers as Record<string, unknown>).cognitionProtection as Record<string, unknown> | undefined;
      if (cognitionProtection) {
        if (typeof cognitionProtection.enableMemWriteDetection === "boolean")
          config.layers.cognitionProtection.enableMemWriteDetection = cognitionProtection.enableMemWriteDetection;
        if (typeof cognitionProtection.enableIntervention === "boolean")
          config.layers.cognitionProtection.enableIntervention = cognitionProtection.enableIntervention;
      }

      const decisionAlignment = (layers as Record<string, unknown>).decisionAlignment as Record<string, unknown> | undefined;
      if (decisionAlignment) {
        if (typeof decisionAlignment.enableDecisionAlignmentDetection === "boolean")
          config.layers.decisionAlignment.enableDecisionAlignmentDetection = decisionAlignment.enableDecisionAlignmentDetection;
        if (typeof decisionAlignment.enableIntervention === "boolean")
          config.layers.decisionAlignment.enableIntervention = decisionAlignment.enableIntervention;
      }

      const execControl = (layers as Record<string, unknown>).execControl as Record<string, unknown> | undefined;
      if (execControl) {
        if (typeof execControl.enableToolCallDetection === "boolean")
          config.layers.execControl.enableToolCallDetection = execControl.enableToolCallDetection;
        if (typeof execControl.enableIntervention === "boolean")
          config.layers.execControl.enableIntervention = execControl.enableIntervention;
      }
    }

    const llm = (raw as Record<string, unknown>).llm;
    if (llm && typeof llm === "object") {
      const provider = (llm as Record<string, unknown>).provider;
      if (typeof provider === "string") config.llm.provider = provider.trim();

      const model = (llm as Record<string, unknown>).model;
      if (typeof model === "string") config.llm.model = model.trim();

      const api = (llm as Record<string, unknown>).api;
      if (typeof api === "string") config.llm.api = api.trim();

      const baseUrl = (llm as Record<string, unknown>).baseUrl;
      if (typeof baseUrl === "string") config.llm.baseUrl = baseUrl.trim();

      const apiKeyEnv = (llm as Record<string, unknown>).apiKeyEnv;
      if (typeof apiKeyEnv === "string" && apiKeyEnv.trim().length > 0) {
        config.llm.apiKeyEnv = apiKeyEnv.trim();
      }
    }

    const logging = (raw as Record<string, unknown>).logging;
    if (logging && typeof logging === "object") {
      const level = (logging as Record<string, unknown>).level as string | undefined;
      if (level && ["off", "basic", "event", "ctx", "full"].includes(level)) {
        config.logging.level = level as "off" | "basic" | "event" | "ctx" | "full";
      }
      const enableFileLog = (logging as Record<string, unknown>).enableFileLog;
      if (typeof enableFileLog === "boolean") {
        config.logging.enableFileLog = enableFileLog;
      }
    }

    const worker = (raw as Record<string, unknown>).worker;
    if (worker && typeof worker === "object") {
      const timeout = (worker as Record<string, unknown>).timeout as number | undefined;
      if (timeout && typeof timeout === "number" && timeout > 0) {
        config.worker.timeout = timeout;
      }
      const debug = (worker as Record<string, unknown>).debug as boolean | undefined;
      if (typeof debug === "boolean") {
        config.worker.debug = debug;
      }
      const logLevel = (worker as Record<string, unknown>).logLevel as string | undefined;
      if (logLevel && typeof logLevel === "string") {
        config.worker.logLevel = logLevel;
      }
    }

    return config;
  }
}

export const ConfigSchema = {
  parse(value: unknown): PluginConfig {
    return PluginConfig.fromPluginConfig(value);
  },
  uiHints: {
    "llm.provider": {
      label: "LLM Provider",
      help: "Optional override. If set with model/api/baseUrl + env key, AgentWard uses this first before runtime model resolution.",
    },
    "llm.model": {
      label: "LLM Model",
      help: "Optional override model id for decision alignment, e.g. gpt-4o-mini.",
    },
    "llm.api": {
      label: "LLM API Type",
      help: "Optional provider API type, e.g. openai-completions or anthropic-messages.",
    },
    "llm.baseUrl": {
      label: "LLM Base URL",
      help: "Optional provider base URL used for decision alignment LLM calls.",
    },
    "llm.apiKeyEnv": {
      label: "LLM API Key Env",
      help: "Environment variable name for API key. Default: AGENT_WARD_API_KEY.",
    },
    "layers.foundationScan.enableFoundationScanDetection": {
      label: "Enable Foundation Scan",
      help: "When enabled, detects security bypass instructions in system prompt files.",
    },
    "layers.foundationScan.enableIntervention": {
      label: "Enable Foundation Scan Intervention",
      help: "When true, blocks tool calls when threats are detected. When false, only logs and sends warnings without blocking.",
    },
    "layers.foundationScan.blockToolCallOnFoundationScanWarning": {
      label: "Block Tool Calls on System Prompt Warning",
      help: "When true, tool calls are blocked when security bypass is detected in system prompt files.",
    },
    "layers.foundationScan.detectMaliciousSkills.enable": {
      label: "Enable Malicious Skills Detection",
      help: "When enabled, scans skill files (SKILL.md) for malicious instructions.",
    },
    "layers.foundationScan.detectMaliciousSkills.ruleBasedDetection": {
      label: "Enable Rule-Based Detection (Skills)",
      help: "When enabled, uses regex patterns to detect malicious content in skill files.",
    },
    "layers.foundationScan.detectMaliciousSkills.semanticDetection": {
      label: "Enable Semantic Detection (Skills)",
      help: "When enabled, uses LLM to semantically analyze skill files for malicious content.",
    },
    "layers.foundationScan.detectMaliciousSkills.maxContentLength": {
      label: "Max Content Length for Semantic Detection",
      help: "Maximum number of characters to analyze in semantic detection. Default: 65536 (64KB). Higher values improve accuracy but increase LLM costs.",
    },
    "layers.foundationScan.detectMaliciousSkills.maxConcurrency": {
      label: "Max Concurrency for Skill Scanning",
      help: "Maximum number of skills to scan in parallel. Default: 10. Higher values improve speed but may cause API rate limits.",
    },
    "layers.foundationScan.detectMisConfiguration.enable": {
      label: "Enable Misconfiguration Detection",
      help: "When enabled, scans configuration files for security misconfigurations.",
    },
    "layers.inputSanitization.enableInputDetection": {
      label: "Enable Input Detection",
      help: "When enabled, detects profanity and injection attempts in tool results.",
    },
    "layers.inputSanitization.enableIntervention": {
      label: "Enable Input Sanitization Intervention",
      help: "When true, blocks tool calls and modifies tool result content when threats are detected. When false, only logs and sends warnings without blocking or content modification.",
    },
    "layers.inputSanitization.temporaryBlockToolCall": {
      label: "Temporary Block Tool Call",
      help: "When true and enableIntervention is true, blocks tool calls only until the next assistant response (level 2). When false, blocks until the next user request (level 3).",
    },
    "layers.inputSanitization.blockHarmfulInput": {
      label: "Block Harmful Input",
      help: "When true and temporaryBlockToolCall is false, replaces the harmful tool result content with a warning. When false, appends a warning to the original content. Only effective when temporaryBlockToolCall is false.",
    },
    "layers.inputSanitization.coverContaminatedResponse": {
      label: "Cover Contaminated Response",
      help: "When true and blockHarmfulInput is true and temporaryBlockToolCall is false, replaces the assistant's response with warning messages. Only effective when both blockHarmfulInput is true and temporaryBlockToolCall is false.",
    },
    "layers.cognitionProtection.enableMemWriteDetection": {
      label: "Enable Memory Write Detection",
      help: "When enabled, detects abnormal patterns in memory file modifications.",
    },
    "layers.cognitionProtection.enableIntervention": {
      label: "Enable Cognition State Intervention",
      help: "When true, blocks tool calls when memory anomalies are detected. When false, only logs and sends warnings without blocking.",
    },
    "layers.decisionAlignment.enableDecisionAlignmentDetection": {
      label: "Enable Decision Alignment Detection",
      help: "When enabled, monitors assistant responses for decision alignment issues.",
    },
    "layers.decisionAlignment.enableIntervention": {
      label: "Enable Decision Align Intervention",
      help: "When true, temporarily blocks tool calls when decision misalignment is detected. When false, only logs and sends warnings without blocking.",
    },
    "layers.execControl.enableToolCallDetection": {
      label: "Enable Tool Call Detection",
      help: "When enabled, detects and blocks dangerous commands in tool calls.",
    },
    "layers.execControl.enableIntervention": {
      label: "Enable Exec Control Intervention",
      help: "When true, blocks dangerous tool calls. When false, only logs and sends warnings without blocking.",
    },
    "logging.level": {
      label: "Logging Level",
      help: "Control log verbosity: off (no logs), basic (Log ... only), event (show event data), ctx (show context), full (show both event and ctx)",
    },
    "logging.enableFileLog": {
      label: "Enable File Logging",
      help: "When enabled, all logs are also written to a dedicated JSONL file at $OPENCLAW_STATE_DIR/agentward/logs/agentward.log (defaults to ~/.openclaw/agentward/logs/).",
    },
    "worker.timeout": {
      label: "Worker Timeout (ms)",
      help: "Timeout for worker requests in milliseconds. Default: 60000",
    },
    "worker.debug": {
      label: "Debug Mode",
      help: "Enable debug logging for worker. Default: false",
    },
    "worker.logLevel": {
      label: "Worker Log Level",
      help: "Log level for worker: info, debug, warn, error. Default: info",
    },
  },
};
