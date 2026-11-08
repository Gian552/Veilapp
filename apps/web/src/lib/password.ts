export const MIN_PASSWORD_LENGTH = 10;

export interface PasswordCheck {
  ok: boolean;
  hint: string;
  strength: 0 | 1 | 2 | 3;
}

/**
 * Coarse guidance only. Length dominates: a long passphrase of unrelated words
 * beats short complex passwords. Nothing here is sent anywhere.
 */
export function checkPassword(pw: string): PasswordCheck {
  if (pw.length < MIN_PASSWORD_LENGTH) {
    return { ok: false, strength: 0, hint: `Use at least ${MIN_PASSWORD_LENGTH} characters.` };
  }
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  const unique = new Set(pw).size;
  if (unique < 6) return { ok: true, strength: 1, hint: 'Many repeated characters. Consider a longer passphrase.' };
  if (pw.length >= 20 || (pw.length >= 14 && classes >= 3)) {
    return { ok: true, strength: 3, hint: 'Strong. Make sure you will remember it.' };
  }
  return { ok: true, strength: 2, hint: 'Acceptable. A passphrase of four or more random words is stronger.' };
}
