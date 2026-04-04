import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

export type AesKey = Uint8Array; // 32 bytes for AES-256

/** File layout: [12 bytes nonce][ciphertext][16 bytes GCM tag] */
const NONCE_SIZE = 12;
const TAG_SIZE = 16;

export function generateKey(): AesKey {
  return randomBytes(32);
}

export function encrypt(data: string, key: AesKey): Uint8Array {
  const nonce = randomBytes(NONCE_SIZE);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = cipher.update(data, 'utf8');
  cipher.final();
  const tag = cipher.getAuthTag();
  const result = new Uint8Array(NONCE_SIZE + ciphertext.length + TAG_SIZE);
  result.set(nonce, 0);
  result.set(ciphertext, NONCE_SIZE);
  result.set(tag, NONCE_SIZE + ciphertext.length);
  return result;
}

export function decrypt(buffer: Uint8Array, key: AesKey): string {
  const nonce = buffer.subarray(0, NONCE_SIZE);
  const tag = buffer.subarray(buffer.length - TAG_SIZE);
  const ciphertext = buffer.subarray(NONCE_SIZE, buffer.length - TAG_SIZE);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  const plaintext = decipher.update(ciphertext);
  decipher.final();
  return plaintext.toString('utf8');
}
