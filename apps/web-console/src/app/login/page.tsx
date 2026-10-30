'use client';
import {FormEvent, useState} from 'react';
import {useT} from '@/lib/i18n';

export default function Login() {
  const {t} = useT();
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
    setError(`${t('login.signIn')}: ${code || response.status}`);
    setBusy(false);
  }
  return <div className="login panel">
    <h1>{t('login.title')}</h1>
    <p className="muted">{t('login.note')}</p>
    <form onSubmit={submit}>
      <label className="field">{t('login.token')}
        <input name="token" type="password" minLength={32} maxLength={256} autoComplete="off" required autoFocus/></label>
      {error && <p className="notice error" role="alert">{error}</p>}
      <button className="primary" disabled={busy}>{busy ? t('login.signingIn') : t('login.signIn')}</button>
    </form>
  </div>;
}
