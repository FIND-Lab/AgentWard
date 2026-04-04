import { spawnSync } from 'child_process';
import {type OpenClawPluginApi} from "openclaw/plugin-sdk";
import { resolvePreferredOpenClawTmpDir } from "openclaw/plugin-sdk/sandbox";
import { PluginConfig, ConfigSchema } from "./config.ts";
import { SessionState } from "./state.ts";
import {
  formatUserPrependWarning,
  formatToolResultWarning,
  formatToolCallWarning,
  formatCoverAssistantWarning,
  formatMessageSendingWarning
} from "./warnings.ts";
import { detectFoundationScan,type FoundationScanConfig } from "./layers/foundation-scan.ts";
import { inputDetect } from "./layers/input-sanitization.ts";
import { detectCognitionProtectionAnomaly } from "./layers/cognition-protection.ts";
import { decisionAlignmentDetect } from "./layers/decision-alignment.ts";
import { toolCallDetect } from "./layers/exec-control.ts";
import { initLogger, getLogger, initFileLog } from "./logger.ts";
import { PersistentWorker, getWorker, setWorker} from "./model-worker-manager.ts";
import { Warning } from "./warnings.ts";

function send_message(state: SessionState, content: string) {
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

const plugin = {
  id: "agent-ward",
  name: "AgentWard",
  description: "AgentWard provides multi-layer security protection for the agent system, including input sanitization, execution control, decision alignment monitoring, and foundation scan.",
  configSchema: ConfigSchema,
  status: new Map<string, SessionState>(),
  register(api: OpenClawPluginApi) {
    initLogger(api);
    const config = PluginConfig.fromPluginConfig(api.pluginConfig);
    if (config.logging.enableFileLog) {
      initFileLog();
    }
    
    api.registerService({
      id: "agent-ward-worker",
      start: async (ctx) => {
        const worker = new PersistentWorker({
          tmpDir: resolvePreferredOpenClawTmpDir(),
          config: {
            timeout: config.worker.timeout ?? 60000,
            debug: config.worker.debug ?? false,
            logLevel: config.worker.logLevel ?? 'info',
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
      }

      if (config.layers.foundationScan.enableFoundationScanDetection && ctx.workspaceDir) {
        const warning = await detectFoundationScan(
          ctx.workspaceDir,
          getLogger(),
          state,
          api.config,
          config.layers.foundationScan as FoundationScanConfig
        );
        if (warning) {
          send_message(state, formatMessageSendingWarning(warning));
          getLogger().warn(`[FoundationScan] Malicious skill detected in ${ctx.workspaceDir}:` + JSON.stringify(warning));

          if (config.layers.foundationScan.enableIntervention) {
            if (config.layers.foundationScan.blockToolCallOnFoundationScanWarning){
              state.warning_queue.push(warning);
              // In this case, the reason of tool call blocking is here. Show the assistant later by warning_queue.
            }
            if (config.layers.foundationScan.blockToolCallOnFoundationScanWarning) {
              getLogger().warn("[Enforcement] Blocking tool calls due to system prompt security bypass detection.");
              state.block_tool_call = true;
            }
            return { prependContext: formatUserPrependWarning(warning, config.layers.foundationScan.blockToolCallOnFoundationScanWarning) }; 
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
        if (config.layers.decisionAlignment.enableDecisionAlignmentDetection && event.message.stopReason == "toolUse") { // Only check for tool calling
          const warning = decisionAlignmentDetect(
            state,
            event.message
          );
          if (warning) {
            send_message(state, formatMessageSendingWarning(warning));
            getLogger().warn(`[DecisionAlignment] Decision alignment warning: ${warning.type}`);
            if (config.layers.decisionAlignment.enableIntervention) {
              state.warning_queue.push(warning);
              state.temp_block_tool_call = true;
            }
          }
        }
      }

      state.currentMessages!.push(event.message);

      if (event.message.role == "toolResult" && config.layers.inputSanitization.enableInputDetection) {
        const warning = inputDetect(event.message.content);
        if (warning) {
          if (config.layers.inputSanitization.coverContaminatedResponse)
            send_message(state, formatMessageSendingWarning(warning, "The later contaminated response will not be persisted."));
          else
            send_message(state, formatMessageSendingWarning(warning));

          const warningText = formatToolResultWarning(warning, config.layers.inputSanitization.blockHarmfulInput);
          getLogger().warn(`[InputSanitization] Detecting ${warning.type}. Blocking future tool calls...`);
          if (config.layers.inputSanitization.enableIntervention) {
            state.warning_queue.push(warning);
            state.block_tool_call = true;
            if (config.layers.inputSanitization.coverContaminatedResponse)
              state.cover_response_by_warning = true;
          }
          let content = config.layers.inputSanitization.blockHarmfulInput ? [{
            type: "text",
            text: warningText
          }] : [...event.message.content, {
            type: "text",
            text: warningText 
          }];
          const message = {
            ...event.message,
            content: content
          };
          return {
            block: false,
            message: message,
            isError: true
          }
        }
      }
    });

    api.on("before_tool_call", (event, ctx) => {
      const state = plugin.status.get(ctx.sessionKey!)!;

      let instant_warning: Warning | null = null;

      if (config.layers.execControl.enableToolCallDetection) {
        const warning = toolCallDetect(event.toolName, event.params);
        if (warning) {
          send_message(state, formatMessageSendingWarning(warning));
          getLogger().warn(`[ExecControl] Dangerous command detected: ${event.params.command}`);
          if (config.layers.execControl.enableIntervention) {
            instant_warning = warning;
          }
        }
      }

      if (config.layers.cognitionProtection.enableMemWriteDetection && !instant_warning) {
        const warning = detectCognitionProtectionAnomaly(event.toolName, event.params);
        if (warning) {
          send_message(state, formatMessageSendingWarning(warning));
          getLogger().warn(`[CognitionProtection] Cognition state anomaly detected: ${event.toolName}`);
          if (config.layers.cognitionProtection.enableIntervention) {
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
  }
}

export default plugin;
