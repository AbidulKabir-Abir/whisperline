import { useEffect } from 'react';
import { useAuthStore } from './store/authStore';
import AuthScreen from './components/auth/AuthScreen';
import ChatLayout from './components/chat/ChatLayout';

export default function App() {
  const { token, isInitialized, initialize } = useAuthStore();

  useEffect(() => {
    initialize();
  }, [initialize]);

  if (!isInitialized) {
    return (
      <div className="flex h-screen items-center justify-center bg-slate-950">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-slate-400 text-sm">Loading WhisperLine…</p>
        </div>
      </div>
    );
  }

  return token ? <ChatLayout /> : <AuthScreen />;
}
