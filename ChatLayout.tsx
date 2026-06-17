import { useEffect, useState } from 'react';
import { getSocket } from '../../services/socket';
import { useChatStore } from '../../store/chatStore';
import { useAuthStore } from '../../store/authStore';
import ConversationList from './ConversationList';
import MessagePanel from './MessagePanel';
import NewConversation from './NewConversation';
import type { EncryptedMessage } from '../../types';

export default function ChatLayout() {
  const { loadConversations, activeConversationId, receiveMessage, setTyping } = useChatStore();
  const { userTag, userId, logout } = useAuthStore();
  const [showNew, setShowNew] = useState(false);
  const [showSidebar, setShowSidebar] = useState(true);

  useEffect(() => {
    loadConversations();
  }, [loadConversations]);

  // Attach socket listeners
  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;

    const onMessage = (data: EncryptedMessage & { conversationId: string }) => {
      receiveMessage(data);
    };
    const onTypingStart = ({ conversationId, userId: uid }: { conversationId: string; userId: string }) => {
      setTyping(conversationId, uid, true);
    };
    const onTypingStop = ({ conversationId, userId: uid }: { conversationId: string; userId: string }) => {
      setTyping(conversationId, uid, false);
    };

    socket.on('message:receive', onMessage);
    socket.on('typing:start', onTypingStart);
    socket.on('typing:stop', onTypingStop);

    return () => {
      socket.off('message:receive', onMessage);
      socket.off('typing:start', onTypingStart);
      socket.off('typing:stop', onTypingStop);
    };
  }, [receiveMessage, setTyping]);

  return (
    <div className="flex h-screen bg-slate-950 overflow-hidden">
      {/* Sidebar */}
      <div className={`${showSidebar ? 'flex' : 'hidden'} md:flex flex-col w-full md:w-80 border-r border-slate-800 bg-slate-900 flex-shrink-0`}>
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-4 border-b border-slate-800">
          <div>
            <h1 className="font-semibold text-white">WhisperLine</h1>
            <p className="text-xs text-slate-400 font-mono">{userTag}</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowNew(true)}
              className="w-8 h-8 rounded-lg bg-brand-600 hover:bg-brand-700 flex items-center justify-center text-white transition-colors"
              title="New conversation"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
            </button>
            <button
              onClick={logout}
              className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 flex items-center justify-center text-slate-400 transition-colors"
              title="Logout"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
            </button>
          </div>
        </div>

        <ConversationList onSelect={() => setShowSidebar(false)} />
      </div>

      {/* Main panel */}
      <div className={`${!showSidebar || activeConversationId ? 'flex' : 'hidden'} md:flex flex-col flex-1 min-w-0`}>
        {activeConversationId ? (
          <MessagePanel onBack={() => { setShowSidebar(true); }} />
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-slate-600 gap-3">
            <svg className="w-12 h-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
            <p className="text-sm">Select a conversation or start a new one</p>
            <button
              onClick={() => setShowNew(true)}
              className="text-brand-500 hover:text-brand-400 text-sm transition-colors"
            >
              + New conversation
            </button>
          </div>
        )}
      </div>

      {showNew && <NewConversation onClose={() => setShowNew(false)} />}
    </div>
  );
}
