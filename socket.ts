import { io, Socket } from 'socket.io-client';

const WS_URL = import.meta.env.VITE_WS_URL || '/';

let socket: Socket | null = null;

export function connectSocket(token: string): Socket {
  if (socket?.connected) return socket;

  socket = io(WS_URL, {
    path: '/ws',
    auth: { token },
    transports: ['websocket'],
    reconnection: true,
    reconnectionAttempts: 10,
    reconnectionDelay: 1000,
  });

  socket.on('connect', () => console.log('[Socket] Connected'));
  socket.on('disconnect', (reason) => console.log('[Socket] Disconnected:', reason));
  socket.on('connect_error', (err) => console.error('[Socket] Error:', err.message));

  // Heartbeat every 2 minutes to maintain presence
  const heartbeat = setInterval(() => {
    if (socket?.connected) socket.emit('heartbeat');
  }, 120_000);

  socket.on('disconnect', () => clearInterval(heartbeat));

  return socket;
}

export function disconnectSocket(): void {
  socket?.disconnect();
  socket = null;
}

export function getSocket(): Socket | null {
  return socket;
}

export function emitMessage(data: {
  conversationId: string;
  messageId: string;
  recipientId: string;
  ciphertext: string;
  dhPub?: string;
  prevChainLen?: number;
  msgIndex?: number;
}): void {
  socket?.emit('message:send', data);
}

export function emitTypingStart(conversationId: string, recipientId: string): void {
  socket?.emit('typing:start', { conversationId, recipientId });
}

export function emitTypingStop(conversationId: string, recipientId: string): void {
  socket?.emit('typing:stop', { conversationId, recipientId });
}

export function emitCallOffer(data: {
  recipientId: string;
  offer: RTCSessionDescriptionInit;
  callId: string;
  callType: 'audio' | 'video' | 'screen';
}): void {
  socket?.emit('call:offer', data);
}

export function emitCallAnswer(data: {
  callerId: string;
  answer: RTCSessionDescriptionInit;
  callId: string;
}): void {
  socket?.emit('call:answer', data);
}

export function emitIceCandidate(data: {
  recipientId: string;
  candidate: RTCIceCandidateInit;
  callId: string;
}): void {
  socket?.emit('call:ice-candidate', data);
}

export function emitCallEnd(recipientId: string, callId: string): void {
  socket?.emit('call:end', { recipientId, callId });
}

export function emitCallReject(callerId: string, callId: string): void {
  socket?.emit('call:reject', { callerId, callId });
}
