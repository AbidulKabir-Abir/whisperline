import { useState } from 'react';
import { useAuthStore } from '../../store/authStore';
import toast from 'react-hot-toast';

type Mode = 'welcome' | 'register' | 'login';

export default function AuthScreen() {
  const [mode, setMode] = useState<Mode>('welcome');
  const [displayName, setDisplayName] = useState('');
  const [userTag, setUserTag] = useState('');
  const [loading, setLoading] = useState(false);
  const { register, loginWithWebAuthn } = useAuthStore();

  const handleRegister = async () => {
    setLoading(true);
    try {
      await register(displayName || undefined);
      toast.success('Account created!');
    } catch (e: unknown) {
      toast.error((e as Error).message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async () => {
    if (!userTag.startsWith('@')) {
      toast.error('User tag must start with @');
      return;
    }
    setLoading(true);
    try {
      await loginWithWebAuthn(userTag);
      toast.success('Welcome back!');
    } catch (e: unknown) {
      toast.error((e as Error).message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-brand-600 mb-4">
            <svg className="w-8 h-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h1 className="text-3xl font-semibold text-white">WhisperLine</h1>
          <p className="text-slate-400 mt-2 text-sm">Zero-trust encrypted messaging</p>
        </div>

        <div className="bg-slate-900 border border-slate-700/50 rounded-2xl p-6">
          {mode === 'welcome' && (
            <div className="space-y-3">
              <button
                onClick={() => setMode('register')}
                className="w-full py-3 px-4 bg-brand-600 hover:bg-brand-700 text-white font-medium rounded-xl transition-colors"
              >
                Create new account
              </button>
              <button
                onClick={() => setMode('login')}
                className="w-full py-3 px-4 bg-slate-800 hover:bg-slate-700 text-slate-100 font-medium rounded-xl transition-colors"
              >
                Sign in with biometrics
              </button>
              <p className="text-center text-slate-500 text-xs pt-2">
                No email. No phone. No password. Just keys.
              </p>
            </div>
          )}

          {mode === 'register' && (
            <div className="space-y-4">
              <div>
                <h2 className="text-lg font-medium text-white mb-1">Create account</h2>
                <p className="text-slate-400 text-sm">Your encryption keys are generated locally and never leave your device.</p>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Display name (optional)</label>
                <input
                  type="text"
                  value={displayName}
                  onChange={e => setDisplayName(e.target.value)}
                  placeholder="e.g. Alice"
                  maxLength={64}
                  className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-brand-500"
                />
              </div>
              <button
                onClick={handleRegister}
                disabled={loading}
                className="w-full py-3 bg-brand-600 hover:bg-brand-700 disabled:opacity-50 text-white font-medium rounded-xl transition-colors flex items-center justify-center gap-2"
              >
                {loading && <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />}
                {loading ? 'Generating keys…' : 'Create account'}
              </button>
              <button onClick={() => setMode('welcome')} className="w-full text-slate-400 hover:text-white text-sm py-2 transition-colors">
                ← Back
              </button>
            </div>
          )}

          {mode === 'login' && (
            <div className="space-y-4">
              <div>
                <h2 className="text-lg font-medium text-white mb-1">Sign in</h2>
                <p className="text-slate-400 text-sm">Enter your WhisperLine tag to authenticate with your device biometrics.</p>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Your tag</label>
                <input
                  type="text"
                  value={userTag}
                  onChange={e => setUserTag(e.target.value)}
                  placeholder="@A7K2M9X4"
                  className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-2.5 text-white placeholder-slate-500 font-mono focus:outline-none focus:border-brand-500"
                />
              </div>
              <button
                onClick={handleLogin}
                disabled={loading || !userTag}
                className="w-full py-3 bg-brand-600 hover:bg-brand-700 disabled:opacity-50 text-white font-medium rounded-xl transition-colors flex items-center justify-center gap-2"
              >
                {loading && <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />}
                {loading ? 'Verifying…' : 'Continue with biometrics'}
              </button>
              <button onClick={() => setMode('welcome')} className="w-full text-slate-400 hover:text-white text-sm py-2 transition-colors">
                ← Back
              </button>
            </div>
          )}
        </div>

        <p className="text-center text-slate-600 text-xs mt-6">
          End-to-end encrypted • Open source • Zero knowledge
        </p>
      </div>
    </div>
  );
}
