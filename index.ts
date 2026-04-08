import { spawnSync } from 'child_process';
import {type OpenClawPluginApi} from "openclaw/plugin-sdk";
import { resolvePreferredOpenClawTmpDir } from "openclaw/plugin-sdk/sandbox";
import { PluginConfig, ConfigSchema } from "./config.ts";
import { SessionState } from "./core/state.ts";
import {
  formatUserPrependWarning,
  formatToolResultWarning,
  formatToolCallWarning,
  formatCoverAssistantWarning,
  formatMessageSendingWarning
} from "./core/warnings.ts";
import { detectFoundationScan,type FoundationScanConfig } from "./layers/foundation-scan.ts";
import { inputDetect } from "./layers/input-sanitization.ts";
import { detectCognitionProtectionAnomaly } from "./layers/cognition-protection.ts";
import { decisionAlignmentDetect } from "./layers/decision-alignment.ts";
import { analyzeUserIntent } from "./layers/intent-analysis.ts";
import { toolCallDetect } from "./layers/exec-control.ts";
import { initLogger, getLogger, initFileLog } from "./util/logger.ts";
import { PersistentWorker, getWorker, setWorker, restartWorker} from "./worker/model-worker-manager.ts";
import { Warning } from "./core/warnings.ts";
import { handleAgentWardCommand } from "./core/commands.ts";

/** Inline implementation of extractToolResultId — reads toolCallId or toolUseId
 *  from a message object. Mirrors src/agents/tool-call-id.ts:71-83. */
function extractToolResultId(message: Record<string, unknown>): string | undefined {
  return (message.toolCallId ?? message.toolUseId) as string | undefined;
}

function send_message(state: SessionState, content: string) {
  if (!plugin.config!.notifications.enableProactiveNotifications) return;
  if (state.channelId && state.targetId)
    spawnSync('openclaw', [
      'message', 'send',
      '--channel', state.channelId,
      '--target', state.targetId,
      '--message', content
    ], { stdio: 'inherit' });
  else
    getLogger().error("[Enforcement] No channel to send message.");
}

function ensureWorkerRunning() {
  const worker = getWorker();
  if (worker && worker.isRunning()) return;

  getLogger().warn('[AgentWard] Worker is not running, restarting...');
  restartWorker({
    tmpDir: resolvePreferredOpenClawTmpDir(),
    config: {
      timeout: plugin.config!.worker.timeout ?? 60000,
      debug: plugin.config!.worker.debug ?? false,
      logLevel: plugin.config!.worker.logLevel ?? 'info',
    },
  });
}

const plugin = {
  id: "agent-ward",
  name: "AgentWard",
  description: "AgentWard provides multi-layer security protection for the agent system, including input sanitization, execution control, decision alignment monitoring, and foundation scan.",
  configSchema: ConfigSchema,
  config: null as PluginConfig | null,
  startupConfig: null as PluginConfig | null,
  status: new Map<string, SessionState>(),
  register(api: OpenClawPluginApi) {
    initLogger(api);
    if (!plugin.config) {
      // First-time initialization only — register() may be called again
      // if the plugin registry is reloaded (e.g., cache eviction).
      const config = PluginConfig.fromPluginConfig(api.pluginConfig);
      plugin.config = config;
      plugin.startupConfig = structuredClone(config);
    }
    if (plugin.config!.logging.enableFileLog) {
      initFileLog();
    }

    api.registerService({
      id: "agent-ward-worker",
      start: async (ctx) => {
        const worker = new PersistentWorker({
          tmpDir: resolvePreferredOpenClawTmpDir(),
          config: {
            timeout: plugin.config!.worker.timeout ?? 60000,
            debug: plugin.config!.worker.debug ?? false,
            logLevel: plugin.config!.worker.logLevel ?? 'info',
          },
        });
        
        setWorker(worker);
      },
      stop: async (ctx) => {
        const worker = getWorker();
        if (worker) {
          worker.shutdown();
          setWorker(null);
        }
      },
    });

    api.registerCommand({
      name: "agentward",
      description: "View and modify AgentWard security configuration",
      acceptsArgs: true,
      requireAuth: true,
      handler: (ctx) => {
        const cfg = plugin.config!;
        return handleAgentWardCommand(ctx, cfg, plugin.startupConfig!, (newCfg) => { plugin.config = newCfg; });
      },
    });

    api.on("before_prompt_build", async (event, ctx) => {
      let state = plugin.status.get(ctx.sessionKey!);
      if (!state) {
        state = new SessionState(api, event, ctx);
        await state.setLLMContext(api);
        plugin.status.set(ctx.sessionKey!, state);
      } else {
        await state.setLLMContext(api);
        state.clear_tags();
        state.historyMessages = event?.messages;
        state.currentMessages = [];
        state.decisionAlignmentInfo = [];
        state.latestIntentAnalysis = undefined;
      }

      if (plugin.config!.layers.decisionAlignment.enableDecisionAlignmentDetection) {
        ensureWorkerRunning();
      }

      if (plugin.config!.layers.foundationScan.enableFoundationScanDetection && ctx.workspaceDir) {
        const warning = await detectFoundationScan(
          ctx.workspaceDir,
          getLogger(),
          state,
          api.config,
          plugin.config!.layers.foundationScan as FoundationScanConfig
        );
        if (warning) {
          send_message(state, formatMessageSendingWarning(warning));
          getLogger().warn(`[FoundationScan] Malicious skill detected in ${ctx.workspaceDir}:` + JSON.stringify(warning));

          if (plugin.config!.layers.foundationScan.enableIntervention) {
            if (plugin.config!.layers.foundationScan.blockToolCallOnFoundationScanWarning){
              state.warning_queue.push(warning);
              // In this case, the reason of tool call blocking is here. Show the assistant later by warning_queue.
            }
            if (plugin.config!.layers.foundationScan.blockToolCallOnFoundationScanWarning) {
              getLogger().warn("[Enforcement] Blocking tool calls due to system prompt security bypass detection.");
              state.block_tool_call = true;
            }
            return { prependContext: formatUserPrependWarning(warning, plugin.config!.layers.foundationScan.blockToolCallOnFoundationScanWarning) }; 
          }
        }
      }
    });

    api.on("llm_input", (event, ctx) => {
      plugin.status.get(ctx.sessionKey!)!.systemPrompt = event!.systemPrompt;
    });

    api.on("before_message_write", (event, ctx) => {
      const state = plugin.status.get(ctx.sessionKey!)!;

      if (state.block_persistence)
        return {block: true};
      if (event.message.role == "assistant" && state.cover_response_by_warning){
        getLogger().warn("[Enforcement] Informing user about input detection warning...");
        state.block_persistence = true;
        const content = state.warning_queue.slice(state.warning_head).map((warning) => ({type: "text", text: formatCoverAssistantWarning(warning)}));
        state.warning_head = state.warning_queue.length;
        return {
          block: false,
          message: {
            ...event.message,
            content: content
          },
        }
      }

      if (event.message.role == "assistant") {
        state.temp_block_tool_call = false;
        const daEnabled = plugin.config!.layers.decisionAlignment.enableDecisionAlignmentDetection;
        getLogger().info(`[DecisionAlignment] before_message_write: enabled=${daEnabled}, stopReason=${event.message.stopReason}`);
        if (daEnabled && event.message.stopReason == "toolUse") { // Only check for tool calling

          ensureWorkerRunning();

          analyzeUserIntent(state);

          const warning = decisionAlignmentDetect(
            state,
            event.message
          );
          if (warning) {
            send_message(state, formatMessageSendingWarning(warning));
            getLogger().warn(`[DecisionAlignment] Decision alignment warning: ${warning.type}`);
            if (plugin.config!.layers.decisionAlignment.enableIntervention) {
              state.warning_queue.push(warning);
              state.temp_block_tool_call = true;
            }
          }
        }
      }

      state.currentMessages!.push(event.message);

      if (event.message.role == "toolResult" && plugin.config!.layers.inputSanitization.enableInputDetection) {
        const tcId = extractToolResultId(event.message as Record<string, unknown>);
        if (tcId && state.blockedToolCalls.has(tcId)) {
          getLogger().info(`[InputSanitization] Skipping input sanitization for failed tool call ${tcId}.`);
        } else {
          const warning = inputDetect(event.message.content);
          if (warning) {
            const shouldCoverResponse =
              plugin.config!.layers.inputSanitization.enableIntervention
              && !plugin.config!.layers.inputSanitization.temporaryBlockToolCall
              && plugin.config!.layers.inputSanitization.blockHarmfulInput
              && plugin.config!.layers.inputSanitization.coverContaminatedResponse;

            if (shouldCoverResponse)
              send_message(state, formatMessageSendingWarning(warning, "The later contaminated response will not be persisted."));
            else
              send_message(state, formatMessageSendingWarning(warning));

            getLogger().warn(`[InputSanitization] Detecting ${warning.type}.`);

            if (plugin.config!.layers.inputSanitization.enableIntervention) {
              state.warning_queue.push(warning);

              if (plugin.config!.layers.inputSanitization.temporaryBlockToolCall) {
                state.temp_block_tool_call = true;
                getLogger().warn(`[InputSanitization] ${warning.type}. Temporary blocking tool calls until next assistant response...`);
              } else {
                state.block_tool_call = true;
                getLogger().warn(`[InputSanitization] ${warning.type}. Permanently blocking tool calls until next user input...`);

                const warningText = formatToolResultWarning(warning, plugin.config!.layers.inputSanitization.blockHarmfulInput);
                if (plugin.config!.layers.inputSanitization.blockHarmfulInput) {
                  const content = [{ type: "text", text: warningText }];
                  if (plugin.config!.layers.inputSanitization.coverContaminatedResponse) {
                    state.cover_response_by_warning = true;
                  }
                  return {
                    block: false,
                    message: {
                      ...event.message,
                      content: content
                    },
                  };
                } else {
                  const content = [...event.message.content, { type: "text", text: warningText }];
                  return {
                    block: false,
                    message: {
                      ...event.message,
                      content: content
                    },
                  };
                }
              }
            }
          }
        }
      }
    });

    api.on("before_tool_call", (event, ctx) => {
      const state = plugin.status.get(ctx.sessionKey!)!;

      let instant_warning: Warning | null = null;

      if (plugin.config!.layers.execControl.enableToolCallDetection) {
        const warning = toolCallDetect(event.toolName, event.params);
        if (warning) {
          send_message(state, formatMessageSendingWarning(warning));
          getLogger().warn(`[ExecControl] Dangerous command detected: ${event.params.command}`);
          if (plugin.config!.layers.execControl.enableIntervention) {
            instant_warning = warning;
          }
        }
      }

      if (plugin.config!.layers.cognitionProtection.enableMemWriteDetection && !instant_warning) {
        const warning = detectCognitionProtectionAnomaly(event.toolName, event.params);
        if (warning) {
          send_message(state, formatMessageSendingWarning(warning));
          getLogger().warn(`[CognitionProtection] Cognition state anomaly detected: ${event.toolName}`);
          if (plugin.config!.layers.cognitionProtection.enableIntervention) {
            instant_warning = warning;
          }
        }
      }

      const level = state.block_tool_call ? 3 : state.temp_block_tool_call || state.warning_queue.length > state.warning_head ? 2 : instant_warning ? 1 : 0;
      
      if (level == 3)
        getLogger().warn(`[Enforcement] Tool call permanently blocked due to ${JSON.stringify(state.warning_queue.slice(state.warning_head))}.`);
      else if (level == 2)
        getLogger().warn(`[Enforcement] Tool call temporarily blocked due to ${JSON.stringify(state.warning_queue.slice(state.warning_head))}.`);

      let warningText = formatToolCallWarning(state.warning_queue.slice(state.warning_head), level);
      state.warning_head = state.warning_queue.length;
      if (instant_warning) {
        if (level > 1) {
          warningText = formatToolCallWarning(instant_warning, 1) + "\n" + warningText;
          getLogger().warn(`[Enforcement] Additional instant warning for this tool call: ${instant_warning.type}.`);
        } else {
          warningText = formatToolCallWarning(instant_warning, 1); // level: one-time (only for this tool call)
          getLogger().warn(`[Enforcement] Tool call one-time blocked due to ${JSON.stringify(instant_warning)}.`);
        }
      }

      if (level > 0) {
        return {
          block: true,
          blockReason: warningText,
        };
      }
    });

    api.on("after_tool_call", (event, ctx) => {
      // Attention: If no 'await' in this handler, it is treated as synchronous.
      const state = plugin.status.get(ctx.sessionKey!);
      if (state && event.error && event.toolCallId) {
        state.blockedToolCalls.add(event.toolCallId);
      }
    });
  }
}

export default plugin;
