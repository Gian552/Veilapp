import { useId } from 'react';
import { checkPassword } from '../lib/password';

interface Props {
  password: string;
  confirm: string;
  onPassword: (v: string) => void;
  onConfirm: (v: string) => void;
  label?: string;
  showErrors: boolean;
}

export function passwordsValid(password: string, confirm: string): boolean {
  return checkPassword(password).ok && password === confirm;
}

export function PasswordFields({ password, confirm, onPassword, onConfirm, label = 'Password', showErrors }: Props) {
  const id = useId();
  const check = checkPassword(password);
  const mismatch = confirm.length > 0 && confirm !== password;
  return (
    <>
      <div className="field">
        <label htmlFor={`${id}-pw`}>{label}</label>
        <input
          id={`${id}-pw`}
          className="input"
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(e) => onPassword(e.target.value)}
          aria-describedby={`${id}-pw-hint`}
          required
        />
        <div className="meter" data-strength={password ? check.strength : 0} aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
        <span id={`${id}-pw-hint`} className={showErrors && !check.ok ? 'field-error' : 'field-hint'}>
          {password ? check.hint : 'At least 10 characters. A passphrase of several unrelated words works well.'}
        </span>
      </div>
      <div className="field">
        <label htmlFor={`${id}-confirm`}>Confirm {label.toLowerCase()}</label>
        <input
          id={`${id}-confirm`}
          className="input"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => onConfirm(e.target.value)}
          aria-invalid={mismatch}
          aria-describedby={`${id}-confirm-hint`}
          required
        />
        {(mismatch || (showErrors && confirm !== password)) && (
          <span id={`${id}-confirm-hint`} className="field-error">
            The passwords do not match.
          </span>
        )}
      </div>
    </>
  );
}
