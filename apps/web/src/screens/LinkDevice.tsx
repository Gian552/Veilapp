import { type FormEvent, useEffect, useRef, useState } from 'react';
import { FlowLayout } from '../components/FlowLayout';
import { IconBack } from '../components/Icons';
import { ErrorText } from '../components/ErrorText';
import { useClient, useSnapshot } from '../lib/context';
import { useFlow } from '../lib/flow';

type View = 'choose' | 'link' | 'restore' | 'delete';

/** This device is signed in with a password but not yet enrolled. */
export function LinkDevice() {
  const client = useClient();
  const snap = useSnapshot();
  const [view, setView] = useState<View>(snap.linkCode ? 'link' : 'choose');
  const [leaving, setLeaving] = useState(false);

  async function leave() {
    setLeaving(true);
    try {
      await client.signOut();
    } finally {
      setLeaving(false);
    }
  }

  return (
    <FlowLayout>
      {view === 'choose' && (
        <>
          <h1>Add this device</h1>
          <p className="flow-lede">
            Your password proves who you are, but it cannot add a device by itself. A device you already use must approve
            this one, or you can restore your identity with your recovery key.
          </p>
          <div className="choice-grid">
            <button type="button" className="choice" onClick={() => setView('link')}>
              <strong>Approve from another device</strong>
              <span>Type a short code from this screen into your primary device. Contacts and settings are copied; old messages are not.</span>
            </button>
            <button type="button" className="choice" onClick={() => setView('restore')}>
              <strong>Restore with recovery key</strong>
              <span>Use this if you no longer have your primary device. This device becomes the primary device.</span>
            </button>
          </div>
          <div className="flow-foot">
            <button type="button" className="link-btn" onClick={leave} disabled={leaving}>
              Sign out
            </button>
            {' · '}
            <button type="button" className="link-btn" onClick={() => setView('delete')}>
              Delete this account (Panic Reset)
            </button>
          </div>
        </>
      )}
      {view === 'link' && <LinkFlow onBack={() => setView('choose')} />}
      {view === 'restore' && <RestoreFlow onBack={() => setView('choose')} />}
      {view === 'delete' && <DeleteAccount onBack={() => setView('choose')} />}
    </FlowLayout>
  );
}

function LinkFlow({ onBack }: { onBack: () => void }) {
  const client = useClient();
  const snap = useSnapshot();
  const [code, setCode] = useState<string | null>(snap.linkCode);
  const [waiting, setWaiting] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => () => abort.current?.abort(), []);

  async function start() {
    setError(null);
    try {
      const r = code ? { code } : await client.requestLink();
      setCode(r.code);
      const ctrl = new AbortController();
      abort.current = ctrl;
      setWaiting(true);
      await client.waitForLinkApproval(ctrl.signal);
    } catch (err) {
      if (!abort.current?.signal.aborted) setError(err);
    } finally {
      setWaiting(false);
    }
  }

  function cancel() {
    abort.current?.abort();
    setWaiting(false);
    onBack();
  }

  return (
    <>
      <h1>Approve this device</h1>
      {!code ? (
        <>
          <p className="flow-lede">
            VEIL will create keys for this device and send a link request. On your primary device, open Settings → Devices.
          </p>
          <ErrorText error={error} />
          <div className="btn-row">
            <button type="button" className="btn btn-primary" onClick={start}>
              Request link
            </button>
            <button type="button" className="btn btn-ghost" onClick={onBack}>
              Back
            </button>
          </div>
        </>
      ) : (
        <>
          <p className="flow-lede">On your primary device, open Settings → Devices and type this code into the pending request:</p>
          <output className="link-code" aria-label="Link code">
            {code}
          </output>
          <div className="notice notice-info">
            <div>
              <p>
                The code never leaves this screen except through you. It proves to your primary device that the request came from
                here, and proves to this device that the approval came from your primary device, not from the server.
              </p>
            </div>
          </div>
          <p className="muted small" aria-live="polite">
            {waiting ? (
              <>
                <span className="spinner" aria-hidden="true" /> Waiting for approval…
              </>
            ) : null}
          </p>
          <ErrorText error={error} />
          <div className="btn-row">
            {!waiting && (
              <button type="button" className="btn btn-primary" onClick={start}>
                {error ? 'Try again' : 'Wait for approval'}
              </button>
            )}
            <button type="button" className="btn btn-ghost" onClick={cancel}>
              Cancel
            </button>
          </div>
        </>
      )}
    </>
  );
}

function RestoreFlow({ onBack }: { onBack: () => void }) {
  const client = useClient();
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!key.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await client.restoreWithRecoveryKey(key.trim());
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h1>Restore with recovery key</h1>
      <p className="flow-lede">
        Your identity key is restored from its encrypted backup and this device becomes your primary device. Devices you
        no longer have can then be removed in Settings.
      </p>
      <div className="notice notice-warn">
        <div>
          <p>Old message history is not restored: it only ever existed on your devices.</p>
        </div>
      </div>
      <form onSubmit={submit} noValidate aria-busy={busy}>
        <div className="field">
          <label htmlFor="restore-key">Recovery key</label>
          <textarea
            id="restore-key"
            className="textarea input mono"
            rows={3}
            autoComplete="off"
            autoCapitalize="characters"
            spellCheck={false}
            value={key}
            onChange={(e) => setKey(e.target.value)}
          />
        </div>
        <ErrorText error={error} />
        <div className="btn-row">
          <button type="submit" className="btn btn-primary" disabled={busy || !key.trim()}>
            {busy ? 'Restoring…' : 'Restore'}
          </button>
          <button type="button" className="btn btn-ghost" onClick={onBack}>
            Back
          </button>
        </div>
      </form>
    </>
  );
}

/** Panic Reset from a password-only session: for when every device is lost or seized. */
function DeleteAccount({ onBack }: { onBack: () => void }) {
  const flow = useFlow();
  const [confirm, setConfirm] = useState('');

  function submit(e: FormEvent) {
    e.preventDefault();
    if (confirm !== 'RESET') return;
    flow.startReset({ createNewIdentity: false, wipeLocallyIfServerUnreachable: false });
  }

  return (
    <>
      <button type="button" className="link-btn" onClick={onBack}>
        <IconBack size={16} />
        Back
      </button>
      <h1>Delete this account</h1>
      <p className="flow-lede">
        Use this if your devices are lost or seized. The server deletes the account, its keys, devices, sessions, queued messages and
        recovery backup in one step, and the username is retired. Messages your contacts already received stay on their devices.
        Devices of yours that are offline keep their encrypted data until they are erased.
      </p>
      <form className="card danger-zone" onSubmit={submit} noValidate>
        <div className="field">
          <label htmlFor="delete-confirm">
            Type <strong>RESET</strong> to confirm
          </label>
          <input id="delete-confirm" className="input" autoComplete="off" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </div>
        <button type="submit" className="btn btn-danger" disabled={confirm !== 'RESET'}>
          Delete this account
        </button>
      </form>
    </>
  );
}
