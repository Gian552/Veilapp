import { useState } from 'react';
import type { AccountExport } from '@veil/client';
import { ErrorText } from '../../components/ErrorText';
import { useClient } from '../../lib/context';
import { downloadJson } from '../../lib/format';

export function DataSection() {
  const client = useClient();
  const [serverData, setServerData] = useState<AccountExport | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [plainAck, setPlainAck] = useState(false);
  const [signOutConfirm, setSignOutConfirm] = useState(false);

  async function run(name: string, fn: () => Promise<void>) {
    setBusy(name);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <h1>Data</h1>
      <p className="page-lede">See and export what exists about you, and control this device.</p>

      <section className="card" aria-labelledby="server-h">
        <h3 id="server-h">What the server holds</h3>
        <p className="small muted">
          Fetches the complete record the server keeps for your account. It contains no message contents, because the server has none.
        </p>
        <div className="btn-row">
          <button type="button" className="btn" disabled={busy !== null} onClick={() => run('server', async () => setServerData(await client.exportServerData()))}>
            {busy === 'server' ? 'Loading…' : 'Show server data'}
          </button>
          {serverData && (
            <button type="button" className="btn btn-ghost" onClick={() => downloadJson(serverData, 'veil-server-data.json')}>
              Download JSON
            </button>
          )}
        </div>
        {serverData && (
          <pre className="code-block" tabIndex={0} aria-label="Server data">
            {JSON.stringify(serverData, null, 2)}
          </pre>
        )}
      </section>

      <section className="card" aria-labelledby="local-h">
        <h3 id="local-h">Export conversations from this device</h3>
        <div className="notice notice-warn">
          <div>
            <p>
              The export is an <strong>unencrypted</strong> file. Anyone who gets it can read your messages, and VEIL cannot delete
              it for you later, not even with Panic Reset.
            </p>
          </div>
        </div>
        <label className="checkbox">
          <input type="checkbox" checked={plainAck} onChange={(e) => setPlainAck(e.target.checked)} />
          <span className="checkbox-text">I understand the file is not encrypted.</span>
        </label>
        <button
          type="button"
          className="btn"
          disabled={!plainAck || busy !== null}
          onClick={() => run('local', async () => downloadJson(await client.exportLocalData(), 'veil-conversations.json'))}
        >
          {busy === 'local' ? 'Exporting…' : 'Download plaintext export'}
        </button>
      </section>

      <section className="card" aria-labelledby="device-h">
        <h3 id="device-h">This device</h3>
        <p className="small muted">
          Locking clears all keys from memory; your data stays encrypted on this device. Signing out ends this session and, on a
          secondary device, removes it from your account.
        </p>
        {signOutConfirm ? (
          <div className="notice notice-warn">
            <div>
              <p>Sign out of VEIL on this device?</p>
              <div className="btn-row">
                <button type="button" className="btn btn-danger btn-sm" onClick={() => run('signout', () => client.signOut())}>
                  Sign out
                </button>
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => setSignOutConfirm(false)}>
                  Cancel
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="btn-row">
            <button type="button" className="btn" onClick={() => run('lock', () => client.lock())}>
              Lock now
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => setSignOutConfirm(true)}>
              Sign out…
            </button>
          </div>
        )}
      </section>
      <ErrorText error={error} />
    </>
  );
}
