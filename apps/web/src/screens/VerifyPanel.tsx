import { useMemo, useState } from 'react';
import { ErrorText } from '../components/ErrorText';
import { IconClose } from '../components/Icons';

import { useClient, useSnapshot } from '../lib/context';

export function VerifyPanel({ peer, onClose, onOpenSecurity }: { peer: string; onClose: () => void; onOpenSecurity: () => void }) {
  const client = useClient();
  const snap = useSnapshot();
  const summary = snap.conversations.find((c) => c.peer === peer);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const groups = useMemo(() => {
    try {
      return client.safetyNumber(peer).split(/\s+/).filter(Boolean);
    } catch {
      return null;
    }
    // Recompute when the verification state changes (e.g. after accepting a new key).
  }, [client, peer, summary?.verification]);

  const verified = summary?.verification === 'verified';
  const keyChanged = summary?.verification === 'key-changed';

  async function toggle() {
    setBusy(true);
    setError(null);
    try {
      await client.setVerified(peer, !verified);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <aside className="side-panel" aria-label={`Verify ${peer}`}>
      <div className="card-title">
        <h3>Safety number</h3>
        <button type="button" className="btn btn-ghost btn-sm btn-icon" onClick={onClose} aria-label="Close verification panel">
          <IconClose />
        </button>
      </div>
      <p className="small muted">
        {verified ? (
          <span className="tag tag-verified">Verified</span>
        ) : keyChanged ? (
          <span className="tag tag-warn">Safety number changed</span>
        ) : (
          <span className="tag">Not verified</span>
        )}
      </p>
      {groups ? (
        <div className="account-plate" role="group" aria-label={`Safety number with ${peer}`}>
          <span className="account-plate-label">Shared with {peer}</span>
          <div className="account-plate-digits">
            {groups.map((g, i) => (
              <span key={i}>{g}</span>
            ))}
          </div>
        </div>
      ) : (
        <p className="muted small">The safety number is not available yet.</p>
      )}
      <p className="small">
        {peer} sees the same twelve groups. Compare them in person or by voice. If they match, nobody is in between, not even the server.
      </p>
      <ErrorText error={error} />
      {keyChanged ? (
        <p className="small">Accept the new key from the banner first, after comparing numbers.</p>
      ) : (
        <button type="button" className={verified ? 'btn btn-block' : 'btn btn-primary btn-block'} onClick={toggle} disabled={busy || !groups}>
          {verified ? 'Remove verification' : 'Numbers match: mark as verified'}
        </button>
      )}
      <p className="xsmall faint">
        <button type="button" className="link-btn" onClick={onOpenSecurity}>
          How VEIL encryption works
        </button>
      </p>
    </aside>
  );
}
