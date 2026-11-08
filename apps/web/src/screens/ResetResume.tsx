import { type FormEvent, useState } from 'react';
import { FlowLayout } from '../components/FlowLayout';
import { ErrorText } from '../components/ErrorText';
import { useFlow } from '../lib/flow';

/** A Panic Reset was interrupted (crash, closed tab, lost network). */
export function ResetResume() {
  const flow = useFlow();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<unknown>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!password) return;
    setError(null);
    try {
      await flow.resumeReset(password);
    } catch (err) {
      setError(err);
    }
  }

  return (
    <FlowLayout>
      <h1>Finish the Panic Reset</h1>
      <p className="flow-lede">
        A Panic Reset started on this device but did not finish. Until it does, your old identity may still exist on the
        server, on this device, or both.
      </p>
      <div className="notice notice-danger">
        <div>
          <p>Enter the password of the identity being reset. VEIL needs it to unlock the reset record on this device and continue.</p>
        </div>
      </div>
      <form onSubmit={submit} noValidate>
        <div className="field">
          <label htmlFor="resume-password">Password</label>
          <input
            id="resume-password"
            className="input"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <ErrorText error={error} />
        <button type="submit" className="btn btn-danger-solid btn-block" disabled={!password}>
          Continue reset
        </button>
      </form>
    </FlowLayout>
  );
}
