import { type FormEvent, useCallback, useEffect, useState } from 'react';
import { FlowLayout } from '../components/FlowLayout';
import { IconBack } from '../components/Icons';
import { ErrorText } from '../components/ErrorText';
import { PasswordFields, passwordsValid } from '../components/PasswordFields';
import { ProgressSteps } from '../components/ProgressSteps';
import { useClient } from '../lib/context';
import { useFlow } from '../lib/flow';
import { Plate } from '../components/Plate';

type Step = 'intro' | 'identity' | 'creating';

export function Onboarding({ onSignInInstead }: { onSignInInstead: () => void }) {
  const [step, setStep] = useState<Step>('intro');
  if (step === 'intro') return <Intro onContinue={() => setStep('identity')} onSignIn={onSignInInstead} />;
  return <CreateIdentity onBack={() => setStep('intro')} creating={step === 'creating'} setCreating={(c) => setStep(c ? 'creating' : 'identity')} />;
}

function Intro({ onContinue, onSignIn }: { onContinue: () => void; onSignIn: () => void }) {
  return (
    <FlowLayout wide>
      <div className="intro">
        <div className="intro-copy">
          <h1>Talk without handing over who you are.</h1>
          <p className="flow-lede">
            You get a random name instead of a profile. Keys are made on this device, and messages are sealed before they leave it.
          </p>
          <div className="btn-row">
            <button type="button" className="btn btn-primary btn-lg" onClick={onContinue}>
              Create an identity
            </button>
            <button type="button" className="btn btn-ghost btn-lg" onClick={onSignIn}>
              I already have one
            </button>
          </div>
          <p className="intro-warning">
            There is no password reset by email. Lose your password, your recovery key and every device, and the identity is gone for good.
          </p>
        </div>
        <figure className="ledger" aria-label="What the VEIL server holds about you">
          <figcaption>What the server holds about you</figcaption>
          <dl>
            <div>
              <dt>Name</dt>
              <dd className="none">Not held</dd>
            </div>
            <div>
              <dt>Phone, email</dt>
              <dd className="none">Not held</dd>
            </div>
            <div>
              <dt>IP addresses</dt>
              <dd className="none">Not stored</dd>
            </div>
            <div>
              <dt>Message times</dt>
              <dd className="none">Not stored</dd>
            </div>
            <div>
              <dt>Messages</dt>
              <dd>Sealed, until delivered</dd>
            </div>
            <div>
              <dt>Identity</dt>
              <dd className="number">A random name, like VelvetFalcon</dd>
            </div>
          </dl>
        </figure>
      </div>
    </FlowLayout>
  );
}

function CreateIdentity({ onBack, creating, setCreating }: { onBack: () => void; creating: boolean; setCreating: (c: boolean) => void }) {
  const client = useClient();
  const flow = useFlow();
  const [suggestion, setSuggestion] = useState<{ username: string; reservation: string } | null>(null);
  const [rolling, setRolling] = useState(false);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [recovery, setRecovery] = useState(true);
  const [understood, setUnderstood] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [progress, setProgress] = useState<string[]>([]);

  const roll = useCallback(async () => {
    setRolling(true);
    setError(null);
    try {
      setSuggestion(await client.suggestUsername());
    } catch (e) {
      setError(e);
    } finally {
      setRolling(false);
    }
  }, [client]);

  useEffect(() => {
    void roll();
  }, [roll]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setSubmitted(true);
    if (!suggestion || !passwordsValid(password, confirm) || !understood) return;
    setError(null);
    setProgress([]);
    setCreating(true);
    try {
      const result = await client.register({
        reservation: suggestion.reservation,
        password,
        enableRecovery: recovery,
        onProgress: (s) => setProgress((p) => (p[p.length - 1] === s ? p : [...p, s])),
      });
      setPassword('');
      setConfirm('');
      if (result.recoveryKey) flow.showRecoveryKey(result.username, result.recoveryKey);
    } catch (err) {
      setError(err);
      setCreating(false);
      // A username can be taken in a race; offer a fresh one.
      if (typeof err === 'object' && err && (err as { code?: string }).code === 'conflict') void roll();
    }
  }

  if (creating) {
    return (
      <FlowLayout>
        <h1>Creating your identity</h1>
        <p className="flow-lede">
          Keys are being generated on this device and your password is being stretched with Argon2id. This can take a few seconds.
        </p>
        <div aria-live="polite">
          <ProgressSteps
            label="Registration progress"
            steps={(progress.length ? progress : ['Preparing']).map((label, i, all) => ({
              label,
              state: i < all.length - 1 ? 'done' : 'active',
            }))}
          />
        </div>
      </FlowLayout>
    );
  }

  return (
    <FlowLayout>
      <div className="back-row">
        <button type="button" className="btn btn-ghost btn-sm" onClick={onBack}>
          <IconBack size={16} />
          Back
        </button>
      </div>
      <h1>Your identity</h1>
      <p className="flow-lede">
        Chosen at random, it says nothing about you. Share it only with people you want to hear from.
      </p>
      <form onSubmit={submit} noValidate>
        <div className="username-display">
          {suggestion && <Plate name={suggestion.username} size="lg" own />}
          <output aria-live="polite" aria-label="Suggested username">
            {suggestion?.username ?? '…'}
          </output>
          <button type="button" className="btn btn-sm" onClick={roll} disabled={rolling}>
            {rolling ? 'Rolling…' : 'Another name'}
          </button>
        </div>
        <p className="field-hint">It stays yours until you abandon it with Panic Reset.</p>
        <hr className="divider" />

        <PasswordFields password={password} confirm={confirm} onPassword={setPassword} onConfirm={setConfirm} showErrors={submitted} />
        <p className="field-hint">
          Your password never leaves this device.
        </p>

        <label className="checkbox">
          <input type="checkbox" checked={recovery} onChange={(e) => setRecovery(e.target.checked)} />
          <span className="checkbox-text">
            Create a recovery key (recommended)
            <small>
              The only way back if you forget your password or lose this device.
            </small>
          </span>
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} aria-invalid={submitted && !understood} />
          <span className="checkbox-text">
            I understand that nobody can reset my password or recover my messages for me.
            {submitted && !understood && <small className="field-error">Please confirm before continuing.</small>}
          </span>
        </label>

        <ErrorText error={error} />
        <button type="submit" className="btn btn-primary btn-block" disabled={!suggestion}>
          Create identity
        </button>
      </form>
    </FlowLayout>
  );
}
