import { type FormEvent, useEffect, useState } from 'react';
import type { PublicConfig } from '@veil/client';
import { PasswordFields, passwordsValid } from '../../components/PasswordFields';
import { useClient } from '../../lib/context';
import { useFlow } from '../../lib/flow';

const PHRASE = 'RESET';

export function PanicResetSection() {
  const client = useClient();
  const flow = useFlow();
  const [config, setConfig] = useState<PublicConfig | null>(null);
  const [stage, setStage] = useState<'explain' | 'configure'>('explain');
  const [newIdentity, setNewIdentity] = useState<'now' | 'later'>('later');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [recovery, setRecovery] = useState(true);
  const [wipeAnyway, setWipeAnyway] = useState(true);
  const [phrase, setPhrase] = useState('');
  const [submitted, setSubmitted] = useState(false);

  useEffect(() => {
    client.publicConfig().then(setConfig, () => setConfig(null));
  }, [client]);

  const backupDays = config ? `${config.retention.backupDays} days` : 'the backup retention period';
  const queuedDays = config ? `${config.retention.undeliveredMessageDays} days` : 'the retention period';
  const attachmentDays = config ? `${config.retention.attachmentDays} days` : 'the retention period';

  const ready = phrase === PHRASE && (newIdentity === 'later' || passwordsValid(password, confirm));

  function submit(e: FormEvent) {
    e.preventDefault();
    setSubmitted(true);
    if (!ready) return;
    flow.startReset({
      createNewIdentity: newIdentity === 'now',
      ...(newIdentity === 'now' ? { newPassword: password, enableRecovery: recovery } : {}),
      wipeLocallyIfServerUnreachable: wipeAnyway,
    });
  }

  return (
    <>
      <h1>Panic Reset</h1>
      <p className="page-lede">Abandon this identity completely: invalidate it, delete it from the server and wipe this device.</p>

      <section className="card danger-zone" aria-labelledby="panic-what">
        <h3 id="panic-what">What happens</h3>
        <ol className="small">
          <li>All sessions and devices of this identity are signed out and cannot be reactivated.</li>
          <li>
            The server deletes, in a single transaction, your account, password verifier, devices and keys, queued messages for
            you, link requests, profile and recovery backup. Attachments you uploaded are deleted too.
          </li>
          <li>Your username is retired and will never be given to anyone else.</li>
          <li>This device's encryption key is destroyed and its local database deleted.</li>
          <li>Optionally, a completely new identity is created, with a new random name, new keys and a new recovery key.</li>
        </ol>
        <p className="small">Each step is reported only once VEIL has confirmation that it happened.</p>
      </section>

      <section className="card" aria-labelledby="panic-limits">
        <h3 id="panic-limits">What it cannot do</h3>
        <ul className="check-list danger small">
          <li>Messages already delivered stay on your contacts' devices. Destroying your keys cannot erase what they have decrypted.</li>
          <li>Screenshots, exports and copies made outside VEIL are not affected.</li>
          <li>
            Your other devices are signed out, but their local data is wiped only when they next connect. A device that stays
            offline (for example, a lost or seized phone) keeps its encrypted data.
          </li>
          <li>Messages you sent that are still waiting for a recipient cannot be identified by the server; they are delivered or expire within {queuedDays}.</li>
          <li>Server backups made before the reset rotate out within {backupDays}. Unretrieved attachments expire within {attachmentDays}.</li>
          <li>Your contacts are not told. They will see that your old account no longer exists. Notifying them would link old and new identities.</li>
        </ul>
      </section>

      {stage === 'explain' ? (
        <button type="button" className="btn btn-danger" onClick={() => setStage('configure')}>
          I understand, continue
        </button>
      ) : (
        <form className="card danger-zone" onSubmit={submit} noValidate aria-labelledby="panic-confirm">
          <h3 id="panic-confirm">Confirm Panic Reset</h3>

          <fieldset className="field">
            <legend className="field-label">After the reset</legend>
            <label className="checkbox">
              <input type="radio" name="new-identity" checked={newIdentity === 'later'} onChange={() => setNewIdentity('later')} />
              <span className="checkbox-text">
                Return to the start screen
                <small>Create a new identity later, ideally from a different network, so the two cannot be linked by timing.</small>
              </span>
            </label>
            <label className="checkbox">
              <input type="radio" name="new-identity" checked={newIdentity === 'now'} onChange={() => setNewIdentity('now')} />
              <span className="checkbox-text">
                Create a new identity right away
                <small>Convenient, but the server sees a reset and a registration from the same connection moments apart.</small>
              </span>
            </label>
          </fieldset>

          {newIdentity === 'now' && (
            <>
              <PasswordFields password={password} confirm={confirm} onPassword={setPassword} onConfirm={setConfirm} label="New password" showErrors={submitted} />
              <label className="checkbox">
                <input type="checkbox" checked={recovery} onChange={(e) => setRecovery(e.target.checked)} />
                <span className="checkbox-text">Create a new recovery key</span>
              </label>
            </>
          )}

          <label className="checkbox">
            <input type="checkbox" checked={wipeAnyway} onChange={(e) => setWipeAnyway(e.target.checked)} />
            <span className="checkbox-text">
              Wipe this device even if the server cannot be reached
              <small>
                Your account would then remain on the server until you sign in with your password from any device and reset again.
              </small>
            </span>
          </label>

          <div className="field">
            <label htmlFor="panic-phrase">
              Type <strong className="mono">{PHRASE}</strong> to confirm
            </label>
            <input
              id="panic-phrase"
              className="input mono"
              autoComplete="off"
              autoCapitalize="characters"
              spellCheck={false}
              value={phrase}
              onChange={(e) => setPhrase(e.target.value)}
              aria-invalid={submitted && phrase !== PHRASE}
            />
            {submitted && phrase !== PHRASE && <span className="field-error">Type the phrase exactly, in capitals.</span>}
          </div>

          <div className="btn-row">
            <button type="submit" className="btn btn-danger-solid" disabled={!ready}>
              Destroy this identity
            </button>
            <button type="button" className="btn btn-ghost" onClick={() => setStage('explain')}>
              Cancel
            </button>
          </div>
        </form>
      )}
    </>
  );
}
