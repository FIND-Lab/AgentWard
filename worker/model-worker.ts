import { workerData, parentPort } from 'worker_threads';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { completeSimple, type Model, type Api } from "@mariozechner/pi-ai";
import type {syncLLMRequest, syncLLMResponse } from './model-worker-manager.ts';
import { decrypt, encrypt, type AesKey } from "../util/crypto-util.ts";

const SHARED_BUFFER_SIZE = 524;
const DATA_BUFFER_BYTE_OFFSET = 4;
const REQUEST_FILENAME_DATA_OFFSET = 8 - DATA_BUFFER_BYTE_OFFSET;
const RESPONSE_FILENAME_LENGTH_INDEX = 66;
const RESPONSE_FILENAME_DATA_OFFSET = 268 - DATA_BUFFER_BYTE_OFFSET;
const FILENAME_MAX_LENGTH = 256;

async function callLLM(request: syncLLMRequest<any>): Promise<syncLLMResponse | null> {
  try {
    const result = await completeSimple(request.model, request.context, request.options);
    
    return result;
    
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    log('error', `[Worker] LLM call failed: ${errorMessage}`);
    return null;
  }
}

const data = workerData as {
  tmpDir: string;
  config: {
    timeout: number;
    debug: boolean;
    logLevel: string;
  };
  aesKey: AesKey;
  shared: SharedArrayBuffer;
};

const { tmpDir, config, aesKey } = data;
const view = new Int32Array(data.shared);
const dataBuffer = new Uint8Array(data.shared, 4, SHARED_BUFFER_SIZE - 4);

const decoder = new TextDecoder();

function log(level: 'info' | 'warn' | 'error', message: string) {
  if (parentPort) {
    parentPort.postMessage({
      type: 'log',
      level,
      message,
      timestamp: Date.now(),
    });
  }
}

log('info', '[Worker] Started');
log('info', `[Worker] Config: tmpDir=${tmpDir}, timeout=${config.timeout}, debug=${config.debug}`);

try {
  Atomics.store(view, 0, 0);
} catch (err) {
  log('error', `[Worker] Shared memory initialization failed: ${err}`);
  process.exit(1);
}

let running = true;
let processing = false;

function finishProcessing(
  responseFile: string,
  requestId: string,
  success: boolean,
  data?: any,
  error?: string,
  callback?: () => void
) {
  try {
    const responseFileLen = view[RESPONSE_FILENAME_LENGTH_INDEX];
    if (responseFileLen > 0 && responseFileLen <= FILENAME_MAX_LENGTH) {
      const responseFilePath = join(tmpDir, responseFile);
      
      const finalResponse = {
        requestId,
        success,
        data: success ? data : undefined,
        error: error,
      };

      const encryptedResponse = encrypt(JSON.stringify(finalResponse), aesKey);
      writeFileSync(responseFilePath, encryptedResponse);
      
      Atomics.or(view, 0, 0b010);
      Atomics.notify(view, 0);
      
      if (callback) {
        callback();
      }
    }
  } catch (err) {
    log('error', `[Worker] Failed to write response file: ${err}`);
  } finally {
    processing = false;
    Atomics.and(view, 0, ~0b001);
  }
}

async function processRequestAsync(): Promise<void> {
  let requestFile = '';
  let responseFile = '';
  let requestId = 'unknown';
  
  try {
    const requestFileLen = view[1];
    if (requestFileLen <= 0 || requestFileLen > FILENAME_MAX_LENGTH) {
      log('error', `[Worker] Invalid request filename length: ${requestFileLen}`);
      finishProcessing('', 'unknown', false, undefined, 'Invalid request filename length');
      return;
    }
    
    requestFile = decoder.decode(
      dataBuffer.slice(REQUEST_FILENAME_DATA_OFFSET, REQUEST_FILENAME_DATA_OFFSET + requestFileLen)
    );
    const requestFilePath = join(tmpDir, requestFile);
    
    const responseFileLen = view[RESPONSE_FILENAME_LENGTH_INDEX];
    if (responseFileLen <= 0 || responseFileLen > FILENAME_MAX_LENGTH) {
      log('error', `[Worker] Invalid response filename length: ${responseFileLen}`);
      finishProcessing('', 'unknown', false, undefined, 'Invalid response filename length');
      return;
    }
    
    responseFile = decoder.decode(
      dataBuffer.slice(RESPONSE_FILENAME_DATA_OFFSET, RESPONSE_FILENAME_DATA_OFFSET + responseFileLen)
    );
    
    const requestJson = decrypt(new Uint8Array(readFileSync(requestFilePath)), aesKey);
    const request = JSON.parse(requestJson);
    requestId = request.requestId;
    
    let result: any;
    
    if (request.type === 'llm') {
      const llmResponse = await callLLM(request.data as syncLLMRequest<Api>);
      if (llmResponse) {
        result = llmResponse;
      } else {
        throw new Error('LLM call returned null');
      }
    } else if (request.type === 'add') {
      const { a, b } = request.data as { a: number; b: number };
      result = {
        calculation: `${a} + ${b}`,
        sum: a + b,
        processedAt: Date.now(),
      };
    } else {
      result = {
        message: 'Unknown operation',
        type: request.type,
        processedAt: Date.now(),
      };
    }
    
    finishProcessing(responseFile, requestId, true, result);
    
  } catch (err) {
    log('error', `[Worker] Failed to process request: ${err}`);
    finishProcessing(responseFile, requestId, false, undefined, String(err));
  }
}

async function runWorker() {
  while (running) {
    const currentStatus = Atomics.load(view, 0);
    
    if (currentStatus & 0b100) {
      running = false;
      break;
    }
    
    if ((currentStatus & 0b001) && !processing) {
      processing = true;
      
      await processRequestAsync();
      
    } else if (!processing) {
      Atomics.wait(view, 0, currentStatus);
    }
    
    await new Promise(resolve => setTimeout(resolve, 1));
  }
  
  log('info', '[Worker] Exiting');
}

runWorker().then(() => {
  process.exit(0);
}).catch((err) => {
  log('error', `[Worker] Error: ${err}`);
  process.exit(1);
});
