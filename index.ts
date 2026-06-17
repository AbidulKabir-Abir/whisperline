export interface User {
  id: string;
  userTag: string;
  displayName?: string;
  lastSeen?: string;
}

export interface Conversation {
  id: string;
  otherUser: User;
  lastMessage?: DecryptedMessage;
  unreadCount: number;
  createdAt: string;
}

export interface EncryptedMessage {
  id: string;
  conversationId: string;
  senderId: string;
  ciphertext: string;       // base64 — opaque blob from server
  dhPub?: string;
  prevChainLen?: number;
  msgIndex?: number;
  deliveredAt?: string;
  readAt?: string;
  createdAt: string;
}

export interface DecryptedMessage {
  id: string;
  conversationId: string;
  senderId: string;
  content: string;          // Only visible client-side after decryption
  type: 'text' | 'file' | 'image';
  fileRefId?: string;
  fileName?: string;
  deliveredAt?: string;
  readAt?: string;
  createdAt: string;
  pending?: boolean;
  failed?: boolean;
}

export interface KeyBundle {
  userId: string;
  userTag: string;
  displayName?: string;
  identityKey: string;      // base64 Ed25519 public key
  signedPrekey: {
    keyId: number;
    publicKey: string;
    signature: string;
  };
  oneTimePrekey?: {
    keyId: number;
    publicKey: string;
  } | null;
}

export interface SessionKeys {
  rootKey: CryptoKey;
  sendingChainKey: CryptoKey;
  receivingChainKey: CryptoKey;
  sendingRatchetKeyPair: CryptoKeyPair;
  receivingRatchetKey?: CryptoKey;
  sendingMsgIndex: number;
  receivingMsgIndex: number;
  prevChainLen: number;
}

export interface AuthState {
  token: string | null;
  userId: string | null;
  userTag: string | null;
}

export type CallState = 'idle' | 'calling' | 'ringing' | 'connected' | 'ended';

export interface ActiveCall {
  callId: string;
  remoteUserId: string;
  remoteUserTag: string;
  type: 'audio' | 'video' | 'screen';
  state: CallState;
  startedAt?: number;
}
