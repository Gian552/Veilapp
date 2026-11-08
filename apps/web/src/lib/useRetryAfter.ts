import { useEffect, useState } from 'react';

/** Disables a form until a server-provided Retry-After has elapsed. */
export function useRetryAfter(): { blocked: boolean; remaining: number; block: (seconds: number | undefined) => void } {
  const [until, setUntil] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (until <= now) return;
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, [until, now]);
  const remaining = Math.max(0, Math.ceil((until - now) / 1000));
  return {
    blocked: remaining > 0,
    remaining,
    block: (seconds) => {
      if (!seconds) return;
      setNow(Date.now());
      setUntil(Date.now() + seconds * 1000);
    },
  };
}
