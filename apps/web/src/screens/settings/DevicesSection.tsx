import { useCallback, useEffect, useState } from 'react';
import type { DeviceInfo, PendingLink, SessionSummary } from '@veil/client';
import { ErrorText } from '../../components/ErrorText';
import { useClient, useSnapshot } from '../../lib/context';

const LINK_POLL_MS = 5000;

export function DevicesSection() {
  return (
    <>
      <h1>Devices &amp; sessions</h1>
      <p className="page-lede">
        Every device has its own keys. Messages are encrypted separately to each device listed here. Only a primary device holds
        your identity key and can add or remove devices.
      </p>
      <PendingLinks />
      <Devices />
      <Sessions />
    </>
  );
}

function PendingLinks() {
  const client = useClient();
  const snap = useSnapshot();
  const [links, setLinks] = useState<PendingLink[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setLinks(await client.pendingLinks());
    } catch (err) {
      setError(err);
    }
  }, [client]);

  useEffect(() => {
    if (!snap.isPrimary) return;
    void load();
    const t = window.setInterval(() => void load(), LINK_POLL_MS);
    return () => window.clearInterval(t);
  }, [load, snap.isPrimary]);

  if (!snap.isPrimary) {
    return (
      <section className="card">
        <h3>Add a device</h3>
        <p className="small muted">This is not a primary device. Approve new devices from your primary device.</p>
      </section>
    );
  }

  async function act(linkId: string, approve: boolean) {
    setBusy(true);
    setError(null);
    try {
      if (approve) await client.approveLink(linkId, code);
      else await client.rejectLink(linkId);
      setConfirming(null);
      setCode('');
      await load();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" aria-labelledby="links-h">
      <div className="card-title">
        <h3 id="links-h">Link requests</h3>
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => void load()}>
          Refresh
        </button>
      </div>
      <p className="small muted">
        To add a device, sign in on it and choose "Approve from another device". Its request appears here. Type the code the
        new device shows. Only that device knows it, so a request from anyone else, including the server, cannot match.
      </p>
      {links.length === 0 ? (
        <p className="small faint" role="status">
          No pending requests.
        </p>
      ) : (
        <ul className="row-list">
          {links.map((l) => (
            <li key={l.linkId}>
              <div className="row-main">
                <span>New device request</span>
                {confirming === l.linkId && (
                  <div className="field">
                    <label htmlFor={`link-code-${l.linkId}`}>Code shown on the new device</label>
                    <input
                      id={`link-code-${l.linkId}`}
                      className="input mono"
                      autoComplete="off"
                      autoCapitalize="characters"
                      spellCheck={false}
                      placeholder="XXXX-XXXX-XXXX-XXXX"
                      value={code}
                      onChange={(e) => setCode(e.target.value)}
                    />
                  </div>
                )}
              </div>
              <div className="btn-row">
                {confirming === l.linkId ? (
                  <>
                    <button type="button" className="btn btn-primary btn-sm" disabled={code.replace(/[\s-]/g, '').length !== 16 || busy} onClick={() => act(l.linkId, true)}>
                      Approve
                    </button>
                    <button type="button" className="btn btn-ghost btn-sm" onClick={() => setConfirming(null)}>
                      Cancel
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      type="button"
                      className="btn btn-sm"
                      onClick={() => {
                        setConfirming(l.linkId);
                        setCode('');
                      }}
                    >
                      Enter code &amp; approve
                    </button>
                    <button type="button" className="btn btn-danger btn-sm" disabled={busy} onClick={() => act(l.linkId, false)}>
                      Reject
                    </button>
                  </>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
      <ErrorText error={error} />
    </section>
  );
}

function Devices() {
  const client = useClient();
  const snap = useSnapshot();
  const [devices, setDevices] = useState<DeviceInfo[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [removing, setRemoving] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setDevices(await client.devices());
    } catch (err) {
      setError(err);
    }
  }, [client]);

  useEffect(() => {
    void load();
  }, [load]);

  async function remove(id: string) {
    setError(null);
    try {
      await client.removeDevice(id);
      setRemoving(null);
      await load();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <section className="card" aria-labelledby="devices-h">
      <h3 id="devices-h">Your devices</h3>
      {devices === null ? (
        <p className="small muted">Loading…</p>
      ) : (
        <ul className="row-list">
          {devices.map((d) => (
            <li key={d.deviceId}>
              <div className="row-main">
                <span className="tags">
                  {d.current && <span className="badge">This device</span>}
                  {d.primary && <span className="badge">Primary</span>}
                </span>
                <span className="mono small" title="Device key fingerprint">
                  {d.fingerprint}
                </span>
              </div>
              {snap.isPrimary && !d.current && (
                <div className="btn-row">
                  {removing === d.deviceId ? (
                    <>
                      <button type="button" className="btn btn-danger-solid btn-sm" onClick={() => remove(d.deviceId)}>
                        Remove device
                      </button>
                      <button type="button" className="btn btn-ghost btn-sm" onClick={() => setRemoving(null)}>
                        Cancel
                      </button>
                    </>
                  ) : (
                    <button type="button" className="btn btn-danger btn-sm" onClick={() => setRemoving(d.deviceId)}>
                      Remove
                    </button>
                  )}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      <p className="xsmall muted">
        Removing a device signs it out, deletes its queued messages and keys on the server, and stops contacts from encrypting to
        it. Data already on that device stays there until it is wiped.
      </p>
      <ErrorText error={error} />
    </section>
  );
}

function Sessions() {
  const client = useClient();
  const [sessions, setSessions] = useState<SessionSummary[] | null>(null);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(async () => {
    try {
      setSessions(await client.sessions());
    } catch (err) {
      setError(err);
    }
  }, [client]);

  useEffect(() => {
    void load();
  }, [load]);

  async function revoke(id: string) {
    setError(null);
    try {
      await client.revokeSession(id);
      await load();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <section className="card" aria-labelledby="sessions-h">
      <h3 id="sessions-h">Active sessions</h3>
      <p className="small muted">
        VEIL keeps no login history: no times, no locations, no IP addresses. You only see which sessions currently exist.
      </p>
      {sessions === null ? (
        <p className="small muted">Loading…</p>
      ) : (
        <ul className="row-list">
          {sessions.map((s) => (
            <li key={s.sessionId}>
              <div className="row-main">
                <span className="tags">
                  {s.current && <span className="badge">This session</span>}
                  <span className="badge">{s.kind === 'device' ? 'Device session' : 'Password-only (not enrolled)'}</span>
                </span>
                <span className="mono xsmall faint">{s.deviceId ?? 'no device'}</span>
              </div>
              {!s.current && (
                <button type="button" className="btn btn-danger btn-sm" onClick={() => revoke(s.sessionId)}>
                  Revoke
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      <ErrorText error={error} />
    </section>
  );
}
