import { useState } from 'react';
import { FlowLayout } from '../components/FlowLayout';
import { RecoveryKeyConfirm, RecoveryKeyDisplay } from '../components/RecoveryKey';

/** Shown right after registration: the recovery key appears exactly once. */
export function RecoveryKeyInterstitial({ username, recoveryKey, onDone }: { username: string; recoveryKey: string; onDone: () => void }) {
  const [stage, setStage] = useState<'show' | 'confirm'>('show');
  return (
    <FlowLayout>
      <h1>{stage === 'show' ? 'Write down your recovery key' : 'Confirm your recovery key'}</h1>
      {stage === 'show' ? (
        <>
          <p className="flow-lede">
            Welcome, <strong>{username}</strong>. This key is shown only now. Write it on paper and keep it somewhere safe and
            offline. Anyone holding it, together with your username, can take over your identity.
          </p>
          <RecoveryKeyDisplay recoveryKey={recoveryKey} />
          <div className="notice notice-warn">
            <div>
              <strong>Do not store it next to your password, in screenshots, or in cloud notes.</strong>
              <p>VEIL cannot show this key again. You can create a new one later in Settings.</p>
            </div>
          </div>
          <button type="button" className="btn btn-primary btn-block" onClick={() => setStage('confirm')}>
            I have written it down
          </button>
        </>
      ) : (
        <>
          <RecoveryKeyConfirm recoveryKey={recoveryKey} onConfirmed={onDone} />
          <div className="flow-foot">
            <button type="button" className="link-btn" onClick={() => setStage('show')}>
              Show the key again
            </button>
          </div>
        </>
      )}
    </FlowLayout>
  );
}
