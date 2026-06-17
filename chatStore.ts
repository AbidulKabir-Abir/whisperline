import { create } from 'zustand';
import { api } from '../services/api';
import { emitMessage } from '../services/socket';
import { saveSession, loadSession, saveMessage, loadMessages } from '../crypto/storage';
import {
  ratchetEncrypt,
  ratchetDecrypt,
  x3dhSender,
  initRatchetSender,
  importDHPrivateKey,
  toBase64,
  randomBytes,
} from '../crypto/engine';
import { loadIdentityKeys } from '../crypto/storage';
import type { Conversation, DecryptedMessage, EncryptedMessage } from '../types';

interface ChatStore {
  conversations: Conversation[];
  activeConversationId: string | null;
  messages: Record<string, DecryptedMessage[]>;
  typingUsers: Record<string, string[]>;

  loadConversations: () => Promise<void>;
  openConversation: (conversationId: string) => Promise<void>;
  startConversation: (recipientTag: string) => Promise<string>;
  sendMessage: (conversationId: string, content: string, recipientId: string) => Promise<void>;
  receiveMessage: (envelope: EncryptedMessage & { conversationId: string }) => Promise<void>;
  setTyping: (conversationId: string, userId: string, isTyping: boolean) => void;
  setActiveConversation: (id: string | null) => void;
}

export const useChatStore = create<ChatStore>((set, get) => ({
  conversations: [],
  activeConversationId: null,
  messages: {},
  typingUsers: {},

  loadConversations: async () => {
    const { conversations } = await api.getConversations();
    set({ conversations });
  },

  openConversation: async (conversationId: string) => {
    set({ activeConversationId: conversationId });

    // Load from local encrypted cache first
    const cached = await loadMessages(conversationId);
    if (cached.length > 0) {
      set(s => ({ messages: { ...s.messages, [conversationId]: cached } }));
    }

    // Then fetch from server (encrypted) and decrypt
    try {
      const { messages } = await api.getMessages(conversationId);
      const decrypted = await Promise.all(messages.map(m => decryptIncoming(m)));
      const valid = decrypted.filter(Boolean) as DecryptedMessage[];

      for (const msg of valid) await saveMessage(msg);
      set(s => ({ messages: { ...s.messages, [conversationId]: valid } }));
    } catch (e) {
      console.error('[Chat] Failed to load messages:', e);
    }
  },

  startConversation: async (recipientTag: string) => {
    const user = await api.lookupUser(recipientTag);
    const { conversationId } = await api.createConversation(user.id);
    await get().loadConversations();
    return conversationId;
  },

  sendMessage: async (conversationId: string, content: string, recipientId: string) => {
    const messageId = toBase64(randomBytes(16)).replace(/[+/=]/g, '').slice(0, 22);
    const userId = localStorage.getItem('wl_userId')!;

    // Optimistic UI update
    const optimistic: DecryptedMessage = {
      id: messageId,
      conversationId,
      senderId: userId,
      content,
      type: 'text',
      createdAt: new Date().toISOString(),
      pending: true,
    };
    set(s => ({
      messages: {
        ...s.messages,
        [conversationId]: [...(s.messages[conversationId] || []), optimistic],
      }
    }));

    try {
      // Load or init ratchet state
      let state = await loadSession(conversationId);

      if (!state) {
        // First message: perform X3DH
        const keys = await loadIdentityKeys();
        if (!keys) throw new Error('No identity keys found');

        const bundle = await api.getKeyBundle(
          (await api.lookupUser(recipientId + '')).userTag ||
          get().conversations.find(c => c.id === conversationId)?.otherUser.userTag || ''
        );

        const identityPriv = await importDHPrivateKey(keys.identityPriv);
        const identityPub = keys.identityPub;

        const { sharedSecret, ephemeralPublicKey } = await x3dhSender({
          senderIdentityPriv: identityPriv,
          senderIdentityPub: await importDHPrivateKey(identityPub) as unknown as CryptoKey,
          recipientIdentityPub: bundle.identityKey,
          recipientSignedPrekeyPub: bundle.signedPrekey.publicKey,
          recipientOTPKPub: bundle.oneTimePrekey?.publicKey,
          usedOTPKId: bundle.oneTimePrekey?.keyId,
        });

        state = await initRatchetSender(sharedSecret);
      }

      const { ciphertext, newState, dhPub, msgIndex, prevChainLen } =
        await ratchetEncrypt(state, content);

      await saveSession(conversationId, newState);

      // Send via WebSocket (server only sees ciphertext)
      emitMessage({
        conversationId,
        messageId,
        recipientId,
        ciphertext,
        dhPub,
        prevChainLen,
        msgIndex,
      });

      // Also persist to server for offline delivery
      await api.sendMessage({
        conversationId,
        encryptedFor: { [recipientId]: ciphertext },
        dhPub,
        prevChainLen,
        msgIndex,
      });

      // Update optimistic message as sent
      const sent: DecryptedMessage = { ...optimistic, pending: false };
      await saveMessage(sent);
      set(s => ({
        messages: {
          ...s.messages,
          [conversationId]: s.messages[conversationId]?.map(m =>
            m.id === messageId ? sent : m
          ) || [],
        }
      }));
    } catch (err) {
      console.error('[Chat] Send failed:', err);
      set(s => ({
        messages: {
          ...s.messages,
          [conversationId]: s.messages[conversationId]?.map(m =>
            m.id === messageId ? { ...m, pending: false, failed: true } : m
          ) || [],
        }
      }));
    }
  },

  receiveMessage: async (envelope) => {
    const { conversationId } = envelope;
    if (!envelope.ciphertext) return;

    try {
      let state = await loadSession(conversationId);
      if (!state) {
        console.warn('[Chat] No session state for conversation:', conversationId);
        return;
      }

      const { plaintext, newState } = await ratchetDecrypt(
        state,
        envelope.ciphertext,
        envelope.dhPub || ''
      );

      await saveSession(conversationId, newState);

      const msg: DecryptedMessage = {
        id: envelope.id,
        conversationId,
        senderId: envelope.senderId,
        content: plaintext,
        type: 'text',
        deliveredAt: envelope.deliveredAt,
        readAt: envelope.readAt,
        createdAt: envelope.createdAt,
      };

      await saveMessage(msg);
      set(s => ({
        messages: {
          ...s.messages,
          [conversationId]: [...(s.messages[conversationId] || []), msg],
        }
      }));
    } catch (err) {
      console.error('[Chat] Decrypt failed:', err);
    }
  },

  setTyping: (conversationId, userId, isTyping) => {
    set(s => {
      const current = s.typingUsers[conversationId] || [];
      const updated = isTyping
        ? [...new Set([...current, userId])]
        : current.filter(id => id !== userId);
      return { typingUsers: { ...s.typingUsers, [conversationId]: updated } };
    });
  },

  setActiveConversation: (id) => set({ activeConversationId: id }),
}));

async function decryptIncoming(msg: EncryptedMessage): Promise<DecryptedMessage | null> {
  if (!msg.ciphertext) return null;
  try {
    const state = await loadSession(msg.conversationId);
    if (!state) return null;
    const { plaintext, newState } = await ratchetDecrypt(state, msg.ciphertext, msg.dhPub || '');
    await saveSession(msg.conversationId, newState);
    return {
      id: msg.id,
      conversationId: msg.conversationId,
      senderId: msg.senderId,
      content: plaintext,
      type: 'text',
      deliveredAt: msg.deliveredAt,
      readAt: msg.readAt,
      createdAt: msg.createdAt,
    };
  } catch {
    return null;
  }
}
