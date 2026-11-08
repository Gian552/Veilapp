import { type FormEvent, useId, useMemo, useState } from 'react';

/** Shows the recovery key once, grouped for writing down. Never copied to the clipboard by us. */
export function RecoveryKeyDisplay({ recoveryKey }: { recoveryKey: string }) {
  const groups = recoveryKey.split('-');
  return (
    <div className="key-grid" aria-label="Recovery key" role="group">
      {groups.map((g, i) => (
        <span key={i}>{g}</span>
      ))}
    </div>
  );
}

function pickGroups(count: number, take: number): number[] {
  const picked = new Set<number>();
  const rnd = new Uint32Array(1);
  while (picked.size < Math.min(take, count)) {
    crypto.getRandomValues(rnd);
    picked.add(rnd[0]! % count);
  }
  return [...picked].sort((a, b) => a - b);
}

const normalise = (s: string) => s.trim().toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1');

/**
 * Asks the user to re-type three randomly chosen groups of the key they just
 * wrote down. This checks that it was actually recorded, not memorised.
 */
export function RecoveryKeyConfirm({ recoveryKey, onConfirmed }: { recoveryKey: string; onConfirmed: () => void }) {
  const groups = recoveryKey.split('-');
  const indices = useMemo(() => pickGroups(groups.length, 3), [groups.length]);
  const [values, setValues] = useState<Record<number, string>>({});
  const [error, setError] = useState(false);
  const id = useId();

  function submit(e: FormEvent) {
    e.preventDefault();
    const ok = indices.every((i) => normalise(values[i] ?? '') === groups[i]);
    setError(!ok);
    if (ok) onConfirmed();
  }

  return (
    <form onSubmit={submit} noValidate>
      <p className="muted small">Enter the following groups from the key you wrote down.</p>
      {indices.map((i) => (
        <div className="field" key={i}>
          <label htmlFor={`${id}-${i}`}>Group {i + 1}</label>
          <input
            id={`${id}-${i}`}
            className="input mono"
            autoComplete="off"
            autoCapitalize="characters"
            spellCheck={false}
            maxLength={4}
            value={values[i] ?? ''}
            onChange={(e) => setValues({ ...values, [i]: e.target.value })}
          />
        </div>
      ))}
      {error && (
        <p className="error-text" role="alert">
          At least one group does not match. Check what you wrote down.
        </p>
      )}
      <button type="submit" className="btn btn-primary btn-block">
        Confirm recovery key
      </button>
    </form>
  );
}
