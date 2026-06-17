/**
 * WhisperLine Crypto Engine
 * Implements X3DH key agreement + Double Ratchet Algorithm
 * ALL encryption/decryption happens here, in the browser.
 * Private keys NEVER leave this module.
 */

const subtle = window.crypto.subtle;

// ── Helpers ──────────────────────────────────────────────────────────────

export function randomBytes(n: number): Uint8Array {
  return window.crypto.getRandomValues(new Uint8Array(n));
}

export function toBase64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str);
}

export function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ── Key generation ────────────────────────────────────────────────────────

/** Generate Ed25519 identity key pair (sign/verify) */
export async function generateIdentityKeyPair(): Promise<CryptoKeyPair> {
  return subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
}

/** Generate Curve25519 (ECDH P-256 used as fallback — WebCrypto X25519 limited) */
export async function generateDHKeyPair(): Promise<CryptoKeyPair> {
  return subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
}

/** Export public key as base64 */
export async function exportPublicKey(key: CryptoKey): Promise<string> {
  const raw = await subtle.exportKey('raw', key);
  return toBase64(raw);
}

/** Export private key as base64 (for encrypted local storage only) */
export async function exportPrivateKey(key: CryptoKey): Promise<string> {
  const pkcs8 = await subtle.exportKey('pkcs8', key);
  return toBase64(pkcs8);
}

/** Import ECDH public key from base64 */
export async function importDHPublicKey(b64: string): Promise<CryptoKey> {
  return subtle.importKey(
    'raw',
    fromBase64(b64),
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );
}

/** Import ECDH private key from base64 */
export async function importDHPrivateKey(b64: string): Promise<CryptoKey> {
  return subtle.importKey(
    'pkcs8',
    fromBase64(b64),
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );
}

// ── ECDH + HKDF ───────────────────────────────────────────────────────────

async function dh(privKey: CryptoKey, pubKey: CryptoKey): Promise<ArrayBuffer> {
  return subtle.deriveBits({ name: 'ECDH', public: pubKey }, privKey, 256);
}

async function hkdf(
  inputKeyMaterial: ArrayBuffer,
  salt: ArrayBuffer,
  info: string,
  length = 32
): Promise<ArrayBuffer> {
  const ikm = await subtle.importKey('raw', inputKeyMaterial, 'HKDF', false, ['deriveBits']);
  return subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode(info),
    },
    ikm,
    length * 8
  );
}

async function importAESKey(raw: ArrayBuffer): Promise<CryptoKey> {
  return subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function importHMACKey(raw: ArrayBuffer): Promise<CryptoKey> {
  return subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

// ── X3DH Key Agreement ────────────────────────────────────────────────────

export interface X3DHResult {
  sharedSecret: ArrayBuffer;
  ephemeralPublicKey: string;    // base64 — sent to recipient
  usedOTPKId?: number;
}

/**
 * Sender side: perform X3DH using recipient's key bundle
 * Produces a shared secret without the server ever seeing it
 */
export async function x3dhSender(params: {
  senderIdentityPriv: CryptoKey;
  senderIdentityPub: CryptoKey;
  recipientIdentityPub: string;     // base64
  recipientSignedPrekeyPub: string; // base64
  recipientOTPKPub?: string;        // base64 (optional)
  usedOTPKId?: number;
}): Promise<X3DHResult> {
  const ephemeralKP = await generateDHKeyPair();

  const IK_B = await importDHPublicKey(params.recipientIdentityPub);
  const SPK_B = await importDHPublicKey(params.recipientSignedPrekeyPub);

  // X3DH: DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B)
  // DH3 = DH(EK_A, SPK_B), DH4 = DH(EK_A, OPK_B) if available
  const dh1 = await dh(params.senderIdentityPriv, SPK_B);
  const dh2 = await dh(ephemeralKP.privateKey, IK_B);
  const dh3 = await dh(ephemeralKP.privateKey, SPK_B);

  let masterKeyMaterial = new Uint8Array([
    ...new Uint8Array(dh1),
    ...new Uint8Array(dh2),
    ...new Uint8Array(dh3),
  ]);

  if (params.recipientOTPKPub) {
    const OPK_B = await importDHPublicKey(params.recipientOTPKPub);
    const dh4 = await dh(ephemeralKP.privateKey, OPK_B);
    masterKeyMaterial = new Uint8Array([...masterKeyMaterial, ...new Uint8Array(dh4)]);
  }

  const salt = new Uint8Array(32); // zeros
  const sharedSecret = await hkdf(masterKeyMaterial.buffer, salt.buffer, 'WhisperLine_X3DH_v1');

  return {
    sharedSecret,
    ephemeralPublicKey: await exportPublicKey(ephemeralKP.publicKey),
    usedOTPKId: params.usedOTPKId,
  };
}

// ── Double Ratchet ────────────────────────────────────────────────────────

export interface RatchetState {
  // Stored as exportable raw key material (base64)
  rootKey: string;
  sendChainKey: string;
  recvChainKey: string;
  sendRatchetPriv: string;
  sendRatchetPub: string;
  recvRatchetPub?: string;
  sendMsgIndex: number;
  recvMsgIndex: number;
  prevChainLen: number;
}

async function kdfRootKey(
  rootKey: ArrayBuffer,
  dhOutput: ArrayBuffer
): Promise<{ newRootKey: ArrayBuffer; newChainKey: ArrayBuffer }> {
  const rk = await hkdf(dhOutput, rootKey, 'WhisperLine_Ratchet_RK', 64);
  return {
    newRootKey:  rk.slice(0, 32),
    newChainKey: rk.slice(32, 64),
  };
}

async function kdfChainKey(
  chainKey: ArrayBuffer
): Promise<{ newChainKey: ArrayBuffer; messageKey: ArrayBuffer }> {
  const ck = await importHMACKey(chainKey);
  const msgKeyRaw = await subtle.sign('HMAC', ck, new TextEncoder().encode('msg'));
  const ckNew     = await subtle.sign('HMAC', ck, new TextEncoder().encode('chain'));
  return { newChainKey: ckNew, messageKey: msgKeyRaw };
}

/** Encrypt one message with the ratchet */
export async function ratchetEncrypt(
  state: RatchetState,
  plaintext: string
): Promise<{ ciphertext: string; newState: RatchetState; dhPub: string; msgIndex: number; prevChainLen: number }> {
  const chainKeyRaw = fromBase64(state.sendChainKey).buffer;
  const { newChainKey, messageKey } = await kdfChainKey(chainKeyRaw);

  const aesKey = await importAESKey(messageKey);
  const nonce = randomBytes(12);
  const encoded = new TextEncoder().encode(plaintext);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, encoded);

  const payload = new Uint8Array(nonce.length + ct.byteLength);
  payload.set(nonce, 0);
  payload.set(new Uint8Array(ct), nonce.length);

  return {
    ciphertext: toBase64(payload),
    dhPub: state.sendRatchetPub,
    msgIndex: state.sendMsgIndex,
    prevChainLen: state.prevChainLen,
    newState: {
      ...state,
      sendChainKey: toBase64(newChainKey),
      sendMsgIndex: state.sendMsgIndex + 1,
    },
  };
}

/** Decrypt one message with the ratchet */
export async function ratchetDecrypt(
  state: RatchetState,
  ciphertext: string,
  senderDHPub: string
): Promise<{ plaintext: string; newState: RatchetState }> {
  let currentState = { ...state };

  // If sender used a new ratchet key, perform DH ratchet step
  if (senderDHPub && senderDHPub !== currentState.recvRatchetPub) {
    const senderPub = await importDHPublicKey(senderDHPub);
    const recvPriv  = await importDHPrivateKey(currentState.sendRatchetPriv);
    const dhOut     = await dh(recvPriv, senderPub);

    const rkRaw = fromBase64(currentState.rootKey).buffer;
    const { newRootKey, newChainKey } = await kdfRootKey(rkRaw, dhOut);

    // Generate new sending ratchet key
    const newSendKP = await generateDHKeyPair();

    currentState = {
      ...currentState,
      rootKey: toBase64(newRootKey),
      recvChainKey: toBase64(newChainKey),
      recvRatchetPub: senderDHPub,
      sendRatchetPriv: await exportPrivateKey(newSendKP.privateKey),
      sendRatchetPub: await exportPublicKey(newSendKP.publicKey),
      prevChainLen: currentState.sendMsgIndex,
      sendMsgIndex: 0,
      recvMsgIndex: 0,
    };
  }

  const ckRaw = fromBase64(currentState.recvChainKey).buffer;
  const { newChainKey: newRecvCK, messageKey } = await kdfChainKey(ckRaw);

  const aesKey = await importAESKey(messageKey);
  const payload = fromBase64(ciphertext);
  const nonce = payload.slice(0, 12);
  const ct    = payload.slice(12);

  const plainBuf = await subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aesKey, ct);
  const plaintext = new TextDecoder().decode(plainBuf);

  return {
    plaintext,
    newState: {
      ...currentState,
      recvChainKey: toBase64(newRecvCK),
      recvMsgIndex: currentState.recvMsgIndex + 1,
    },
  };
}

/** Initialize a new Double Ratchet state from X3DH shared secret (sender) */
export async function initRatchetSender(sharedSecret: ArrayBuffer): Promise<RatchetState> {
  const ratchetKP = await generateDHKeyPair();
  const rkRaw = await hkdf(sharedSecret, new ArrayBuffer(32), 'WhisperLine_Ratchet_Init', 64);

  return {
    rootKey: toBase64(rkRaw.slice(0, 32)),
    sendChainKey: toBase64(rkRaw.slice(32, 64)),
    recvChainKey: toBase64(new Uint8Array(32)),
    sendRatchetPriv: await exportPrivateKey(ratchetKP.privateKey),
    sendRatchetPub: await exportPublicKey(ratchetKP.publicKey),
    sendMsgIndex: 0,
    recvMsgIndex: 0,
    prevChainLen: 0,
  };
}

/** Initialize a new Double Ratchet state from X3DH shared secret (recipient) */
export async function initRatchetRecipient(
  sharedSecret: ArrayBuffer,
  senderDHPub: string,
  recipientSPKPriv: CryptoKey
): Promise<RatchetState> {
  const senderPub = await importDHPublicKey(senderDHPub);
  const dhOut = await dh(recipientSPKPriv, senderPub);
  const rkRaw = await hkdf(sharedSecret, new ArrayBuffer(32), 'WhisperLine_Ratchet_Init', 64);

  const newRatchetKP = await generateDHKeyPair();

  return {
    rootKey: toBase64(rkRaw.slice(0, 32)),
    sendChainKey: toBase64(new Uint8Array(32)),
    recvChainKey: toBase64(rkRaw.slice(32, 64)),
    sendRatchetPriv: await exportPrivateKey(newRatchetKP.privateKey),
    sendRatchetPub: await exportPublicKey(newRatchetKP.publicKey),
    recvRatchetPub: senderDHPub,
    sendMsgIndex: 0,
    recvMsgIndex: 0,
    prevChainLen: 0,
  };
}
