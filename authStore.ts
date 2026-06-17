import { create } from 'zustand';
import { setAuthToken } from '../services/api';
import { connectSocket, disconnectSocket } from '../services/socket';
import { openVault, clearVault, saveIdentityKeys, loadIdentityKeys } from '../crypto/storage';
import {
  generateIdentityKeyPair,
  generateDHKeyPair,
  exportPublicKey,
  exportPrivateKey,
  toBase64,
  randomBytes,
} from '../crypto/engine';
import { api } from '../services/api';

interface AuthStore {
  token: string | null;
  userId: string | null;
  userTag: string | null;
  displayName: string | null;
  isInitialized: boolean;

  initialize: () => Promise<void>;
  register: (displayName?: string) => Promise<void>;
  loginWithWebAuthn: (userTag: string) => Promise<void>;
  logout: () => Promise<void>;
}

export const useAuthStore = create<AuthStore>((set, get) => ({
  token: null,
  userId: null,
  userTag: null,
  displayName: null,
  isInitialized: false,

  initialize: async () => {
    await openVault();
    const token = localStorage.getItem('wl_token');
    const userId = localStorage.getItem('wl_userId');
    const userTag = localStorage.getItem('wl_userTag');

    if (token && userId && userTag) {
      setAuthToken(token);
      connectSocket(token);
      set({ token, userId, userTag, isInitialized: true });
    } else {
      set({ isInitialized: true });
    }
  },

  register: async (displayName?: string) => {
    // 1. Generate key pairs in browser
    const identityKP = await generateIdentityKeyPair();
    const signedPrekeyKP = await generateDHKeyPair();
    const spkId = 1;

    // 2. Generate one-time prekeys
    const oneTimePrekeys: { keyId: number; pubKey: string; privKey: string }[] = [];
    for (let i = 0; i < 50; i++) {
      const kp = await generateDHKeyPair();
      oneTimePrekeys.push({
        keyId: i + 1,
        pubKey: await exportPublicKey(kp.publicKey),
        privKey: await exportPrivateKey(kp.privateKey),
      });
    }

    // 3. Sign the signed prekey with identity key
    const spkPubRaw = await window.crypto.subtle.exportKey('raw', signedPrekeyKP.publicKey);
    const spkSig = await window.crypto.subtle.sign(
      'Ed25519',
      identityKP.privateKey,
      spkPubRaw
    );

    // 4. Register with server (public keys only)
    const { userId, userTag, token } = await api.register({
      displayName,
      ikPub: await exportPublicKey(identityKP.publicKey as CryptoKey),
      spkPub: await exportPublicKey(signedPrekeyKP.publicKey),
      spkSig: toBase64(spkSig),
      oneTimePrekeys: oneTimePrekeys.map(({ keyId, pubKey }) => ({ keyId, pubKey })),
    });

    // 5. Store private keys encrypted in vault
    await saveIdentityKeys({
      identityPriv: await exportPrivateKey(identityKP.privateKey as CryptoKey),
      identityPub: await exportPublicKey(identityKP.publicKey as CryptoKey),
      signedPrekeyPriv: await exportPrivateKey(signedPrekeyKP.privateKey),
      signedPrekeyPub: await exportPublicKey(signedPrekeyKP.publicKey),
      signedPrekeyId: spkId,
    });

    localStorage.setItem('wl_token', token);
    localStorage.setItem('wl_userId', userId);
    localStorage.setItem('wl_userTag', userTag);

    setAuthToken(token);
    connectSocket(token);
    set({ token, userId, userTag, displayName: displayName ?? null });
  },

  loginWithWebAuthn: async (userTag: string) => {
    const { startAuthentication } = await import('@simplewebauthn/browser');
    const { options, userId } = await api.webauthnAuthStart(userTag);
    const credential = await startAuthentication(options as Parameters<typeof startAuthentication>[0]);
    const { token, userTag: tag } = await api.webauthnAuthFinish(userId, credential);

    localStorage.setItem('wl_token', token);
    localStorage.setItem('wl_userId', userId);
    localStorage.setItem('wl_userTag', tag);

    setAuthToken(token);
    connectSocket(token);
    set({ token, userId, userTag: tag });
  },

  logout: async () => {
    disconnectSocket();
    setAuthToken(null);
    localStorage.removeItem('wl_token');
    localStorage.removeItem('wl_userId');
    localStorage.removeItem('wl_userTag');
    await clearVault();
    set({ token: null, userId: null, userTag: null, displayName: null });
  },
}));
