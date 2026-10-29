'use client';
import {FormEvent, useState} from 'react';

const ERRORS: Record<string, string> = {
  INVALID_TOKEN: 'That token is not the right length. Paste the full service token.',
  ORIGIN_DENIED: 'This console is not allowed to sign in from this address.',
};

export default function Login() {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError('');
    const token = new FormData(event.currentTarget).get('token');
    const response = await fetch('/api/session', {method: 'POST', headers: {'Content-Type': 'application/json'},
                                                  body: JSON.stringify({token})});
    if (response.ok) { location.assign('/'); return; }
    const code = (await response.json().catch(() => ({}))).code;
    setError(ERRORS[code] || `Sign-in failed (${code || response.status}).`);
    setBusy(false);
  }
  return <div className="login panel">
    <h1>Sign in to AgentGuard</h1>
    <p className="muted">Use your access token. It is kept in a secure, HTTP-only cookie and is not readable by this page.</p>
    <form onSubmit={submit}>
      <label className="field">Access token
        <input name="token" type="password" minLength={32} maxLength={256} autoComplete="off" required autoFocus/></label>
      {error && <p className="notice error" role="alert">{error}</p>}
      <button className="primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
    </form>
  </div>;
}
