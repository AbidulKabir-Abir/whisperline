/**
 * Encrypted local storage using IndexedDB + AES-GCM
 * Keys are derived from a device-specific master key
 * Private keys NEVER stored in plaintext
 */

import { openDB, IDBPDatabase } from 'idb';
import { randomBytes, toBase64, fromBase64 } from './engine';
import type { RatchetState } from './engine';
import type { DecryptedMessage } from '../types';

const DB_NAME = 'whisperline_vault';
const DB_VERSION = 1;

interface VaultDB {
  keyMaterial: { key: string; value: string };
  identityKeys: { key: string; value: string };
  sessions: { key: string; value: string };
  messages: { key: string; value: string };
  metadata: { key: string; value: string };
}

let db: IDBPDatabase<VaultDB>;
let masterKey: CryptoKey;

/** Open / create the encrypted vault */
export async function openVault(): Promise<void> {
  db = await openDB<VaultDB>(DB_NAME, DB_VERSION, {
    upgrade(database) {
      database.createObjectStore('keyMaterial');
      database.createObjectStore('identityKeys');
      database.createObjectStore('sessions');
      database.createObjectStore('messages');
      database.createObjectStore('metadata');
    },
  });
  await initMasterKey();
}

async function initMasterKey(): Promise<void> {
  // Derive master key from a device salt stored in the vault
  let saltB64 = await db.get('keyMaterial', 'device_salt');
  if (!saltB64) {
    const salt = randomBytes(32);
    saltB64 = toBase64(salt);
    await db.put('keyMaterial', saltB64, 'device_salt');
  }

  const salt = fromBase64(saltB64);
  // Use a constant "password" mixed with device salt — real apps would use WebAuthn PRF
  const rawKeyMaterial = await window.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode('whisperline-local-vault-v1'),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  masterKey = await window.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
    rawKeyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encrypt(data: string): Promise<string> {
  const iv = randomBytes(12);
  const ct = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    masterKey,
    new TextEncoder().encode(data)
  );
  const out = new Uint8Array(iv.length + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), iv.length);
  return toBase64(out);
}

async function decrypt(b64: string): Promise<string> {
  const buf = fromBase64(b64);
  const iv = buf.slice(0, 12);
  const ct = buf.slice(12);
  const plain = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, masterKey, ct);
  return new TextDecoder().decode(plain);
}

// ── Identity keys ─────────────────────────────────────────────────────────

export async function saveIdentityKeys(keys: {
  identityPriv: string;
  identityPub: string;
  signedPrekeyPriv: string;
  signedPrekeyPub: string;
  signedPrekeyId: number;
}): Promise<void> {
  const enc = await encrypt(JSON.stringify(keys));
  await db.put('identityKeys', enc, 'identity');
}

export async function loadIdentityKeys(): Promise<{
  identityPriv: string;
  identityPub: string;
  signedPrekeyPriv: string;
  signedPrekeyPub: string;
  signedPrekeyId: number;
} | null> {
  const enc = await db.get('identityKeys', 'identity');
  if (!enc) return null;
  return JSON.parse(await decrypt(enc));
}

// ── Session (ratchet) state ───────────────────────────────────────────────

export async function saveSession(
  conversationId: string,
  state: RatchetState
): Promise<void> {
  const enc = await encrypt(JSON.stringify(state));
  await db.put('sessions', enc, conversationId);
}

export async function loadSession(
  conversationId: string
): Promise<RatchetState | null> {
  const enc = await db.get('sessions', conversationId);
  if (!enc) return null;
  return JSON.parse(await decrypt(enc));
}

// ── Messages cache ────────────────────────────────────────────────────────

export async function saveMessage(msg: DecryptedMessage): Promise<void> {
  const enc = await encrypt(JSON.stringify(msg));
  await db.put('messages', enc, msg.id);
}

export async function loadMessages(
  conversationId: string,
  limit = 50
): Promise<DecryptedMessage[]> {
  const allKeys = await db.getAllKeys('messages');
  const msgs: DecryptedMessage[] = [];

  for (const key of allKeys) {
    const enc = await db.get('messages', key);
    if (!enc) continue;
    try {
      const msg = JSON.parse(await decrypt(enc)) as DecryptedMessage;
      if (msg.conversationId === conversationId) msgs.push(msg);
    } catch { /* skip corrupted */ }
  }

  return msgs
    .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())
    .slice(-limit);
}

// ── Metadata ──────────────────────────────────────────────────────────────

export async function saveMeta(key: string, value: string): Promise<void> {
  const enc = await encrypt(value);
  await db.put('metadata', enc, key);
}

export async function loadMeta(key: string): Promise<string | null> {
  const enc = await db.get('metadata', key);
  if (!enc) return null;
  return decrypt(enc);
}

export async function clearVault(): Promise<void> {
  await db.clear('identityKeys');
  await db.clear('sessions');
  await db.clear('messages');
  await db.clear('metadata');
}
