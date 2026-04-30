import { spawnSync } from 'child_process';
import { createHash } from "crypto";
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
import { toolCallDetect } from "./layers/exec-control.ts";
import { initLogger, getLogger, initFileLog } from "./util/logger.ts";
import { PersistentWorker, getWorker, setWorker, restartWorker} from "./worker/model-worker-manager.ts";
import { type Warning, type DetectionResult, detectBlock } from "./core/warnings.ts";
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

function clampText(text: string, maxChars: number): string {
  if (maxChars <= 0) return "";
  const normalized = text ?? "";
  if (normalized.length <= maxChars) return normalized;
  if (maxChars <= 1) return normalized.slice(0, maxChars);
  return normalized.slice(0, maxChars - 1) + "…";
}

function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return String(value);
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => stableStringify(v)).join(",")}]`;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(record[k])}`).join(",")}}`;
}

function computeOperationKey(toolName: string, params: Record<string, unknown>): string {
  // "Exact match" key: stable stringify + hash for compact storage.
  // Include toolName because different tools can share param shapes.
  const raw = `${toolName}:${stableStringify(params)}`;
  const digest = createHash("sha256").update(raw).digest("hex");
  return `sha256:${digest}`;
}

function resolveApprovalTimeoutMs(config: PluginConfig): number | undefined {
  const timeoutMs = config.approvals?.timeoutMs;
  // Undefined -> let OpenClaw use its default (currently 120s).
  if (timeoutMs === undefined) return undefined;
  // null -> "infinite" (best-effort). OpenClaw gateway caps approvals at 10 minutes.
  // We'll request the maximum cap to approximate infinity.
  if (timeoutMs === null) return 600000;
  if (typeof timeoutMs === "number" && Number.isFinite(timeoutMs) && timeoutMs > 0) return Math.trunc(timeoutMs);
  // <=0 treated as "infinite" in config parser; but be defensive.
  return 600000;
}

const plugin = {
  id: "agent-ward",
  name: "AgentWard",
  description: "AgentWard provides multi-layer security protection for the agent system, including input sanitization, execution control, decision alignment monitoring, and foundation scan.",
  configSchema: ConfigSchema,
  config: null as PluginConfig | null,
  startupConfig: null as PluginConfig | null,
  status: new Map<string, SessionState>(),
  // Example-only: allow-always cache for exact operation matches during this process lifetime.
  allowAlwaysOps: new Set<string>(),
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

          // Ensure worker is alive before any detection that may use LLM
          const worker = getWorker();
          if (!worker || !worker.isRunning()) {
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

      let instant_result: DetectionResult | null = null;
      let instant_warning: Warning | null = null;

      const baseLevel =
        state.block_tool_call
          ? 30
          : state.temp_block_tool_call || state.warning_queue.length > state.warning_head
            ? 20
            : 0;

      if (plugin.config!.layers.execControl.enableToolCallDetection) {
        const operationKey = computeOperationKey(event.toolName, event.params);
        if (baseLevel === 0 && plugin.allowAlwaysOps.has(operationKey)) {
          getLogger().info(`[ExecControl] allow-always match; skipping approval tool=${event.toolName} toolCallId=${event.toolCallId ?? ""}`);
          return;
        }
        const execResult = toolCallDetect(event.toolName, event.params);
        if (execResult?.warning) {
          send_message(state, formatMessageSendingWarning(execResult.warning));
          getLogger().warn(`[ExecControl] Dangerous command detected: ${event.params.command}`);
          if (plugin.config!.layers.execControl.enableIntervention) {
            instant_result = execResult;
            instant_warning = execResult.warning;
          }
        }
      }

      if (plugin.config!.layers.cognitionProtection.enableMemWriteDetection && !instant_warning) {
        const warning = detectCognitionProtectionAnomaly(event.toolName, event.params);
        if (warning) {
          send_message(state, formatMessageSendingWarning(warning));
          getLogger().warn(`[CognitionProtection] Cognition state anomaly detected: ${event.toolName}`);
          if (plugin.config!.layers.cognitionProtection.enableIntervention) {
            instant_result = detectBlock(warning);
            instant_warning = warning;
          }
        }
      }

      const isRequireApproval = instant_result?.verdict === "requireApproval";
      const level = baseLevel > 0 ? baseLevel : isRequireApproval ? 15 : instant_warning ? 10 : 0;
      
      if (level >= 30)
        getLogger().warn(`[Enforcement] Tool call permanently blocked due to ${JSON.stringify(state.warning_queue.slice(state.warning_head))}.`);
      else if (level >= 20)
        getLogger().warn(`[Enforcement] Tool call temporarily blocked due to ${JSON.stringify(state.warning_queue.slice(state.warning_head))}.`);

      let warningText = formatToolCallWarning(state.warning_queue.slice(state.warning_head), level);
      state.warning_head = state.warning_queue.length;
      if (instant_warning) {
        const instantLevel = isRequireApproval ? 15 : 10;
        if (level > instantLevel) {
          warningText = formatToolCallWarning(instant_warning, instantLevel) + "\n" + warningText;
          getLogger().warn(`[Enforcement] Additional instant warning for this tool call: ${instant_warning.type}.`);
        } else {
          warningText = formatToolCallWarning(instant_warning, instantLevel); // level: one-time / requireApproval
          if (isRequireApproval) {
            getLogger().warn(`[Enforcement] Tool call pending approval due to ${JSON.stringify(instant_warning)}.`);
          } else {
            getLogger().warn(`[Enforcement] Tool call one-time blocked due to ${JSON.stringify(instant_warning)}.`);
          }
        }
      }

      if (level > 0) {
        if (instant_result?.verdict === "requireApproval" && baseLevel === 0 && instant_warning) {
          if (!plugin.config!.approvals.enableUserApproval) {
            getLogger().warn(`[Enforcement] Approval disabled by config; denying tool call tool=${event.toolName} toolCallId=${event.toolCallId ?? ""}`);
            return {
              block: true,
              blockReason: warningText,
            };
          }
          getLogger().info(`[Enforcement] Tool call requires approval: ${JSON.stringify(instant_warning)}.`);
          const commandPreview =
            typeof event.params.command === "string"
              ? event.params.command
              : JSON.stringify(event.params);
          // IMPORTANT: `plugin.approval.request` validates `description` length (<= 256 chars).
          // Keep this description compact to avoid gateway INVALID_REQUEST failures.
          //
          // Previous verbose variant (kept for reference):
          // const description = `Tool: ${event.toolName}\nCommand: ${commandPreview}\n\n${warningText}`;
          const toolCallIdLine = event.toolCallId ? `ToolCallId: ${event.toolCallId}` : "";
          // Keep the approval card/body focused on the exact tool call being approved.
          // The warning/analysis is already sent via `send_message(...)`.
          const compactDescription = clampText(
            [
              `Tool: ${event.toolName}`,
              toolCallIdLine,
              typeof event.params.command === "string" ? `Command: ${commandPreview}` : `Params: ${commandPreview}`,
            ]
              .filter(Boolean)
              .join("\n"),
            240,
          );

          // Some channels (e.g. QQ) may not surface `requireApproval.description` reliably.
          // Send the concrete tool call details via proactive message as a fallback.
          send_message(
            state,
            clampText(
              [
                `🛡️ AgentWard approval required`,
                `Type: ${instant_warning.type}`,
                `Tool: ${event.toolName}`,
                toolCallIdLine,
                typeof event.params.command === "string" ? `Command: ${commandPreview}` : `Params: ${commandPreview}`,
              ]
                .filter(Boolean)
                .join("\n"),
              1500,
            ),
          );

          const operationKey = computeOperationKey(event.toolName, event.params);
          return {
            requireApproval: {
              title: `AgentWard: ${instant_warning?.type ?? "Approval required"}`,
              description: compactDescription,
              severity: "warning",
              timeoutMs: resolveApprovalTimeoutMs(plugin.config!) ?? instant_result.timeoutMs,
              timeoutBehavior: instant_result.timeoutBehavior,
              onResolution: (decision) => {
                if (decision === "allow-always") {
                  plugin.allowAlwaysOps.add(operationKey);
                  getLogger().info(`[Approval] allow-always recorded op=${operationKey} tool=${event.toolName}`);
                }
              },
            },
          };
        }
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
