import { Worker } from 'worker_threads';
import { writeFileSync, readFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getLogger } from "../util/logger.ts";
import { type Model, type Context, type SimpleStreamOptions, type AssistantMessage, type UserMessage ,type Api} from "@mariozechner/pi-ai";
import { generateKey, encrypt, decrypt, type AesKey } from "../util/crypto-util.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const SHARED_BUFFER_SIZE = 524;
const DATA_BUFFER_BYTE_OFFSET = 4;
const REQUEST_FILENAME_DATA_OFFSET = 8 - DATA_BUFFER_BYTE_OFFSET;
const RESPONSE_FILENAME_LENGTH_INDEX = 66;
const RESPONSE_FILENAME_DATA_OFFSET = 268 - DATA_BUFFER_BYTE_OFFSET;
const FILENAME_MAX_LENGTH = 256;

export type ContentBlock =
  | { type: "text"; text: string }
  | { type: "image"; imageUrl?: string; imageData?: string }
  | { type: "toolCall"; id: string; name: string; params: Record<string, unknown> }
  | { type: "toolResult"; toolCallId: string; toolName: string; content: string }
  | { type: "reasoning"; text: string };

export type Message = {
  role: "user" | "assistant" | "system" | "toolResult";
  content: string | ContentBlock[];
  timestamp?: number;
  toolCallId?: string;
  toolName?: string;
};

export type ToolDefinition = {
  name: string;
  description?: string;
  parameters?: Record<string, unknown>;
};

export type syncLLMRequest<TApi extends Api> = {
  model: Model<TApi>;
  context: Context;
  options?: SimpleStreamOptions;
};

export type syncLLMResponse = AssistantMessage;

export type WorkerRequest =
  | { type: 'add'; requestId: string; data: { a: number; b: number }; timestamp: number }
  | { type: 'llm'; requestId: string; data: syncLLMRequest<any>; timestamp: number };

export type WorkerResponse =
  | { requestId: string; success: true; data: { calculation: string; sum: number } | syncLLMResponse }
  | { requestId: string; success: false; error: string };

export class PersistentWorker {
  private worker: Worker;
  private view: Int32Array;
  private dataBuffer: Uint8Array;
  private running = true;
  private encoder = new TextEncoder();
  private decoder = new TextDecoder();
  private tmpDir: string;
  private timeout: number;
  private aesKey: AesKey;

  constructor(
    options: {
      tmpDir: string;
      config: {
        timeout: number;
        debug: boolean;
        logLevel: string;
      };
    }
  ) {
    this.tmpDir = options.tmpDir;
    this.timeout = options.config.timeout;
    this.aesKey = generateKey();

    const shared = new SharedArrayBuffer(SHARED_BUFFER_SIZE);
    this.view = new Int32Array(shared);
    this.dataBuffer = new Uint8Array(shared, 4, SHARED_BUFFER_SIZE - 4);

    this.worker = new Worker(join(__dirname, 'model-worker.ts'), {
      workerData: {
        tmpDir: options.tmpDir,
        config: options.config,
        aesKey: this.aesKey,
        shared,
      },
    });
    
    this.worker.on('online', () => {
      getLogger().info('[WorkerManager] Worker Online');
    });
    
    this.worker.on('message', (msg) => {
      if (msg.type === 'log') {
        if (msg.level === 'warn') {
          getLogger().warn(`[WorkerManager] ${msg.message}`);
        } else if (msg.level === 'error') {
          getLogger().error(`[WorkerManager] ${msg.message}`);
        } else {
          getLogger().info(`[WorkerManager] ${msg.message}`);
        }
      }
    });
    
    this.worker.on('error', (err) => {
      getLogger().error(`[WorkerManager] Error: ${err}`);
      this.running = false;
    });
    
    this.worker.on('exit', (code) => {
      getLogger().warn(`[WorkerManager] Worker Exit: ${code}`);
      this.running = false;
    });
    
    getLogger().info('[WorkerManager] Worker Started');
  }

  call(request: WorkerRequest): WorkerResponse | null {
    const requestId = request.requestId;
    const requestFile = `agent-ward-request-${requestId}.json`;
    const responseFile = `agent-ward-response-${requestId}.json`;
    
    const requestFilePath = join(this.tmpDir, requestFile);
    const responseFilePath = join(this.tmpDir, responseFile);
    
    try {
      const encryptedRequest = encrypt(JSON.stringify(request), this.aesKey);
      writeFileSync(requestFilePath, encryptedRequest);

      const requestFileEncoded = this.encoder.encode(requestFile);
      if (requestFileEncoded.length > FILENAME_MAX_LENGTH) {
        getLogger().error(`[WorkerManager] Request filename too long: ${requestFileEncoded.length} > ${FILENAME_MAX_LENGTH}`);
        return null;
      }
      this.view[1] = requestFileEncoded.length;
      this.dataBuffer.set(requestFileEncoded, REQUEST_FILENAME_DATA_OFFSET);
      
      const responseFileEncoded = this.encoder.encode(responseFile);
      if (responseFileEncoded.length > FILENAME_MAX_LENGTH) {
        getLogger().error(`[WorkerManager] Response filename too long: ${responseFileEncoded.length} > ${FILENAME_MAX_LENGTH}`);
        return null;
      }
      this.view[RESPONSE_FILENAME_LENGTH_INDEX] = responseFileEncoded.length;
      this.dataBuffer.set(responseFileEncoded, RESPONSE_FILENAME_DATA_OFFSET);
      
      const beforeStatus = Atomics.load(this.view, 0);
      Atomics.and(this.view, 0, ~0b010);
      Atomics.or(this.view, 0, 0b001);
      Atomics.notify(this.view, 0);
      
      const status = Atomics.wait(this.view, 0, 0b001, this.timeout);
      Atomics.and(this.view, 0, ~0b010);
      Atomics.and(this.view, 0, ~0b001);
      
      if (status === 'timed-out') {
        getLogger().error('[WorkerManager] Timeout');
        const currentStatus = Atomics.load(this.view, 0);
        getLogger().error(`[WorkerManager] Current status: ${currentStatus.toString(2)}`);
        getLogger().error(`[WorkerManager] Worker is running: ${this.running}`);
        return null;
      }
      
      const responseBuffer = readFileSync(responseFilePath);
      const responseJson = decrypt(new Uint8Array(responseBuffer), this.aesKey);
      const response = JSON.parse(responseJson) as WorkerResponse;
      
      return response;
    } catch (error) {
      getLogger().error(`[WorkerManager] Call failed: ${error}`);
      return null;
    } finally {
      rmSync(requestFilePath, { force: true });
      rmSync(responseFilePath, { force: true });
    }
  }

  shutdown() {
    if (!this.running) return;
    
    getLogger().info('[WorkerManager] Shutdown');
    
    Atomics.or(this.view, 0, 0b100);
    Atomics.notify(this.view, 0);
    
    const timeout = setTimeout(() => {
      getLogger().error('[WorkerManager] Shutdown timeout, force terminate');
      this.worker.terminate();
    }, 5000);
    
    this.worker.on('exit', () => {
      clearTimeout(timeout);
      getLogger().info('[WorkerManager] Shutdown completed');
    });
  }

  isRunning(): boolean {
    return this.running;
  }
}

let workerInstance: PersistentWorker | null = null;
let requestCounter = 0;

export function getWorker(): PersistentWorker | null {
  return workerInstance;
}

export function setWorker(worker: PersistentWorker | null) {
  workerInstance = worker;
}

export function generateRequestId(): string {
  return `${Date.now()}-${process.pid}-${requestCounter++}`;
}

export function restartWorker(
  options: {
    tmpDir: string;
    config: { timeout: number; debug: boolean; logLevel: string };
  }
): PersistentWorker {
  const existing = getWorker();
  if (existing) {
    try { existing.shutdown(); } catch {}
    setWorker(null);
  }
  const worker = new PersistentWorker(options);
  setWorker(worker);
  return worker;
}

export function callLLMSync(
  request: syncLLMRequest<any>
): syncLLMResponse | null {
  const worker = getWorker();
  if (!worker || !worker.isRunning()) {
    getLogger().error('[WorkerManager] Worker is not running, skip LLM call');
    return null;
  }
  
  const workerRequest: WorkerRequest = {
    requestId: generateRequestId(),
    type: 'llm',
    data: request,
    timestamp: Date.now(),
  };
  
  const response = worker.call(workerRequest);
  if (response && response.success) {
    return response.data as syncLLMResponse;
  } else {
    getLogger().error(`[WorkerManager] LLM call failed: ${response?.error || 'unknown error'}`);
    return null;
  }
}

export function callLLMSimple(
  model: Model<any>,
  systemPrompt: string,
  conversation: Array<{ role: 'user' | 'assistant'; content: string }>,
    options?: SimpleStreamOptions
): string | null {
  const context: Context = {
    systemPrompt,
    messages: conversation.map(msg => {
      const contentBlock = { type: 'text' as const, text: msg.content };
      
      if (msg.role === 'user') {
        return {
          role: 'user' as const,
          content: [contentBlock],
        } as UserMessage;
      } else {
        return {
          role: 'assistant' as const,
          content: [contentBlock],
        } as AssistantMessage;
      }
    }),
  };
  const response = callLLMSync({
    model,
    context,
    options
  });
  
  if (!response || !response.content) {
    getLogger().error('[WorkerManager] LLM call response is empty');
    return null;
  }
  
  if (typeof response.content === 'string') {
    return response.content;
  }
  
  if (Array.isArray(response.content)) {
    const textContent = response.content.find((c) => c.type === 'text');
    return textContent && 'text' in textContent ? (textContent as { text: string }).text : null;
  }
  
  return null;
}
