const BASE = import.meta.env.VITE_API_URL || '/api';

let authToken: string | null = null;

export function setAuthToken(token: string | null) {
  authToken = token;
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };
  if (authToken) headers['Authorization'] = `Bearer ${authToken}`;

  const res = await fetch(`${BASE}${path}`, { ...options, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'network_error' }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export const api = {
  // Auth
  register: (body: object) => request<{ userId: string; userTag: string; token: string }>('/auth/register', { method: 'POST', body: JSON.stringify(body) }),
  webauthnRegisterStart: (userId: string) => request<object>('/auth/webauthn/register/start', { method: 'POST', body: JSON.stringify({ userId }) }),
  webauthnRegisterFinish: (userId: string, credential: object) => request<{ verified: boolean }>('/auth/webauthn/register/finish', { method: 'POST', body: JSON.stringify({ userId, credential }) }),
  webauthnAuthStart: (userTag: string) => request<{ options: object; userId: string }>('/auth/webauthn/auth/start', { method: 'POST', body: JSON.stringify({ userTag }) }),
  webauthnAuthFinish: (userId: string, credential: object) => request<{ token: string; userId: string; userTag: string }>('/auth/webauthn/auth/finish', { method: 'POST', body: JSON.stringify({ userId, credential }) }),

  // Users
  getMe: () => request<{ id: string; userTag: string; displayName: string; otpkCount: number }>('/users/me'),
  updateMe: (displayName: string) => request<{ updated: boolean }>('/users/me', { method: 'PATCH', body: JSON.stringify({ displayName }) }),
  lookupUser: (userTag: string) => request<{ id: string; userTag: string; displayName: string }>(`/users/lookup/${userTag}`),

  // Keys
  getKeyBundle: (userTag: string) => request<import('../types').KeyBundle>(`/keys/bundle/${userTag}`),
  uploadPrekeys: (oneTimePrekeys: { keyId: number; pubKey: string }[]) => request<{ uploaded: number }>('/keys/prekeys', { method: 'POST', body: JSON.stringify({ oneTimePrekeys }) }),

  // Conversations
  getConversations: () => request<{ conversations: import('../types').Conversation[] }>('/messages/conversations'),
  createConversation: (recipientId: string) => request<{ conversationId: string; existing: boolean }>('/messages/conversations', { method: 'POST', body: JSON.stringify({ recipientId }) }),

  // Messages
  getMessages: (conversationId: string, limit = 50) => request<{ messages: import('../types').EncryptedMessage[] }>(`/messages/conversation/${conversationId}?limit=${limit}`),
  sendMessage: (body: object) => request<{ messageId: string; createdAt: string }>('/messages/send', { method: 'POST', body: JSON.stringify(body) }),
  markDelivered: (messageId: string) => request<{ ok: boolean }>(`/messages/delivered/${messageId}`, { method: 'POST' }),

  // Calls
  getTurnCredentials: () => request<{ urls: string[]; username: string; credential: string; ttl: number }>('/call/turn-credentials'),
};
