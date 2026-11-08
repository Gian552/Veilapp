import { type FormEvent, useEffect, useState } from 'react';
import { ErrorText } from '../../components/ErrorText';
import { useClient, useSnapshot } from '../../lib/context';

const STORED: [string, string][] = [
  ['Username', 'Random two-word name; your public address.'],
  ['Public keys', 'Identity key, signed device list, device keys, prekeys.'],
  ['Password verifier', 'Argon2id hash of a key derived from your password. Not the password.'],
  ['Queued messages', 'Encrypted, without sender, deleted on delivery (or after 30 days).'],
  ['Attachments', 'Encrypted blobs without owner, deleted after download (or 30 days).'],
  ['Sessions', 'One per signed-in device, with a coarse expiry day.'],
  ['Recovery backup', 'Only if enabled; encrypted with your recovery key.'],
  ['Profile', 'Only if shared; encrypted, readable by your contacts only.'],
];

const NOT_STORED = [
  'Real name, phone number, email',
  'Your password or any private key',
  'Message contents',
  'Who sent a message (sealed sender)',
  'Message or login timestamps',
  'IP addresses or device fingerprints',
  'Online status or last seen',
  'Your contact list',
];

export function PrivacySection() {
  const client = useClient();
  const snap = useSnapshot();
  const [displayName, setDisplayName] = useState(snap.settings.displayName);
  const [error, setError] = useState<unknown>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => setDisplayName(snap.settings.displayName), [snap.settings.displayName]);

  async function update(patch: Parameters<typeof client.updateSettings>[0]) {
    setError(null);
    setSaved(false);
    try {
      await client.updateSettings(patch);
      setSaved(true);
    } catch (err) {
      setError(err);
    }
  }

  function saveName(e: FormEvent) {
    e.preventDefault();
    void update({ displayName: displayName.trim().slice(0, 64) });
  }

  return (
    <>
      <h1>Privacy</h1>
      <p className="page-lede">What VEIL keeps about you, and the few optional features that reveal more.</p>

      <section className="card" aria-labelledby="stored-h">
        <h3 id="stored-h">Stored on the server</h3>
        <div className="table-wrap">
          <table className="table">
            <tbody>
              {STORED.map(([k, v]) => (
                <tr key={k}>
                  <th scope="row">{k}</th>
                  <td>{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card" aria-labelledby="notstored-h">
        <h3 id="notstored-h">Never stored</h3>
        <ul className="check-list no small">
          {NOT_STORED.map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ul>
        <p className="xsmall muted">
          The server and the network still see connection details (such as your IP address and when you are connected) while a
          request is handled. VEIL does not write them down, but cannot make them invisible.
        </p>
      </section>

      <section className="card" aria-labelledby="optin-h">
        <h3 id="optin-h">Optional features</h3>
        <p className="small muted">Off by default. Each reveals some metadata, explained below.</p>
        <div className="switch-row">
          <label className="switch-text" htmlFor="opt-receipts">
            <strong>Send read receipts</strong>
            <span>
              Tells contacts when you read their messages. Receipts are end-to-end encrypted, but they reveal your reading times to
              your contacts and create extra traffic the server can observe.
            </span>
          </label>
          <input
            id="opt-receipts"
            type="checkbox"
            role="switch"
            className="switch"
            checked={snap.settings.readReceipts}
            onChange={(e) => void update({ readReceipts: e.target.checked })}
          />
        </div>
        <div className="switch-row">
          <label className="switch-text" htmlFor="opt-profile">
            <strong>Share a display name</strong>
            <span>
              Your contacts see a name you choose next to your username. It is encrypted and the server cannot read it, but any name
              you choose may identify you to the people you share it with.
            </span>
          </label>
          <input
            id="opt-profile"
            type="checkbox"
            role="switch"
            className="switch"
            checked={snap.settings.shareProfile}
            onChange={(e) => void update({ shareProfile: e.target.checked })}
          />
        </div>
        {snap.settings.shareProfile && (
          <form onSubmit={saveName} className="field">
            <label htmlFor="display-name">Display name</label>
            <div className="btn-row">
              <input
                id="display-name"
                className="input"
                maxLength={64}
                autoComplete="off"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
              />
              <button type="submit" className="btn">
                Save
              </button>
            </div>
          </form>
        )}
        <ErrorText error={error} />
        {saved && (
          <p className="field-hint" role="status">
            Saved.
          </p>
        )}
      </section>
    </>
  );
}
