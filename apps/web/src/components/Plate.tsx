// An engraved monogram plate: the initials of the two words of a username
// (VelvetFalcon → VF). Your own plate is brass; everyone else's is green.
// Identity is shown by name and verified by safety number, so the plate
// carries no generated pattern that could be mistaken for a fingerprint.

export function initials(username: string): string {
  const parts = username.match(/[A-Z][a-z]*/g);
  if (parts && parts.length >= 2) return parts[0]![0]! + parts[1]![0]!;
  return username.slice(0, 2).toUpperCase();
}

export function Plate({ name, size = 'md', own = false }: { name: string; size?: 'sm' | 'md' | 'lg' | 'xl'; own?: boolean }) {
  return (
    <span className={`plate plate-${size}${own ? ' plate-own' : ''}`} aria-hidden="true">
      {initials(name)}
    </span>
  );
}

/** A username set as two engraved words, so long names stay readable. */
export function Username({ name }: { name: string }) {
  return <span className="username">{name}</span>;
}
