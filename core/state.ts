import type { Warning } from "./warnings.ts";
import type { Model, Api, ProviderStreamOptions } from "@mariozechner/pi-ai";
import type { OpenClawConfig, OpenClawPluginApi } from "openclaw/plugin-sdk";
import { PROVIDER_BASE_URLS, PROVIDER_API_TYPES } from "../util/map.ts";
import { getLogger } from "../util/logger.ts";
import type { IntentAnalysisResult } from "../layers/intent-analysis.ts";

export type LlmCallContext = {
  model: Model<Api>;
  
  options: ProviderStreamOptions;
  
  apiKey: string;
  
  modelRef: string;
};

export class SessionState {
  block_tool_call: boolean;
  block_persistence: boolean;
  cover_response_by_warning: boolean;
  temp_block_tool_call: boolean;
  warning_queue: Warning[];
  warning_head: number;
  blockedToolCalls: Set<string>;
  
  historyMessages?: unknown[];
  currentMessages?: unknown[];
  systemPrompt?: string;
  decisionAlignmentInfo: string[];
  latestIntentAnalysis?: IntentAnalysisResult;
  latestIntentAnalysis?: IntentAnalysisResult;

  channelId?: string;
  targetId?: string;

  llmContext?: LlmCallContext;
  
  defaultModelRef?: string;

  clear_tags() {
    this.block_tool_call = false;
    this.block_persistence = false;
    this.cover_response_by_warning = false;
    this.temp_block_tool_call = false;
    this.warning_queue = [];
    this.warning_head = 0;
    this.blockedToolCalls = new Set();
  }

  constructor(api: OpenClawPluginApi,event, ctx ) {
    this.clear_tags();

    this.historyMessages = event?.messages;
    this.currentMessages = [];
    this.decisionAlignmentInfo = [];
    this.latestIntentAnalysis = undefined;

    const messageProvider = ctx?.messageProvider;
    if (messageProvider?.toLowerCase() == "feishu") {
      this.channelId = 'feishu';
      this.targetId = ctx.sessionKey.split(":").pop();
    }
  }

  private static readString(value: unknown): string {
    return typeof value === "string" ? value.trim() : "";
  }

  private trySetLLMContextFromPluginConfig(api: OpenClawPluginApi): boolean {
    const pluginConfig = api.pluginConfig as Record<string, unknown> | undefined;
    const llm = (pluginConfig?.llm ?? null) as Record<string, unknown> | null;
    if (!llm || typeof llm !== "object") return false;

    const provider = SessionState.readString(llm.provider);
    const modelId = SessionState.readString(llm.model);
    const apiType = SessionState.readString(llm.api);
    const baseUrl = SessionState.readString(llm.baseUrl);
    const apiKeyEnv = SessionState.readString(llm.apiKeyEnv) || "AGENT_WARD_API_KEY";
    const apiKey = SessionState.readString(process.env[apiKeyEnv]);

    if (!provider || !modelId || !apiType || !baseUrl || !apiKey) {
      return false;
    }

    const model: Model<Api> = {
      id: modelId,
      name: modelId,
      provider,
      api: apiType as Api,
      baseUrl,
      headers: (llm.headers as Record<string, string> | undefined),
      input: ["text"],
    } as Model<Api>;

    this.defaultModelRef = `${provider}/${modelId}`;
    this.llmContext = {
      model,
      options: {
        apiKey,
      },
      apiKey,
      modelRef: this.defaultModelRef,
    };

    getLogger().info(`[SessionState] LLM context initialized from plugin config using env ${apiKeyEnv}`);
    return true;
  }
  
  async setLLMContext(api: OpenClawPluginApi): Promise<void> {
    if (this.trySetLLMContextFromPluginConfig(api)) {
      return;
    }

    const config: OpenClawConfig = api.config;
    if (!config ) {
      getLogger().error(`[SessionState] No config available, cannot initialize LLM context`);
      return;
    }
    
    const modelConfig = config.agents?.defaults?.model;
    this.defaultModelRef = typeof modelConfig === 'string' 
      ? modelConfig 
      : modelConfig?.primary;
    
    if (!this.defaultModelRef) {
        getLogger().error(`[SessionState] No model reference found in config or session, cannot initialize LLM context`);
      return;
    }
    
    const idx = this.defaultModelRef.indexOf("/");
    const provider = this.defaultModelRef.substring(0, idx);
    const modelId = this.defaultModelRef.substring(idx + 1);
    
    try {
      const authInfo = await api.runtime.modelAuth.resolveApiKeyForProvider({
        provider,
        cfg: config,
      });
      
      if (!authInfo.apiKey) {
        getLogger().warn(`[SessionState] No API key found for provider ${provider}`);
        return;
      }
      let model: Model<Api> = null as any;

      const providerConfig = config.models?.providers?.[provider];
      if (providerConfig) {
        for (const m of providerConfig.models) {
          if (m.id === modelId) {
            model = m as Model<Api>;
            model.baseUrl = providerConfig.baseUrl;
            model.api = providerConfig.api;
          }
        }
      }

      model = model || {
        id: modelId,
        name: modelId,
        provider: provider,
        baseUrl: config.models?.providers?.[provider]?.baseUrl || PROVIDER_BASE_URLS[provider],
        api: config.models?.providers?.[provider]?.api || PROVIDER_API_TYPES[provider],
      } as Model<Api>;

      model = {
        ...model,
        input: ["text"],
        headers: (providerConfig as Record<string, unknown> | undefined)?.headers as Record<string, string> | undefined,
      }
      
      this.llmContext = {
        model,
        options: {
          apiKey: authInfo.apiKey,
          maxTokens: model.maxTokens || undefined, 
        },
        apiKey: authInfo.apiKey,
        modelRef: this.defaultModelRef,
      };
    } catch (error) {
      getLogger().error(`[SessionState] Failed to initialize LLM context: ${JSON.stringify(error)}`);
    }
  }
}
