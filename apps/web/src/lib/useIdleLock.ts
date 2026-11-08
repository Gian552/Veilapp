import { useEffect } from 'react';
import type { VeilClientApi } from '@veil/client';

/** Vault auto-lock after this much inactivity. */
export const IDLE_LOCK_MS = 15 * 60 * 1000;

const ACTIVITY_EVENTS = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const;

export function useIdleLock(client: VeilClientApi, active: boolean, timeoutMs = IDLE_LOCK_MS): void {
  useEffect(() => {
    if (!active) return;
    let timer = window.setTimeout(fire, timeoutMs);
    function fire() {
      void client.lock();
    }
    function reset() {
      window.clearTimeout(timer);
      timer = window.setTimeout(fire, timeoutMs);
    }
    for (const e of ACTIVITY_EVENTS) window.addEventListener(e, reset, { passive: true });
    return () => {
      window.clearTimeout(timer);
      for (const e of ACTIVITY_EVENTS) window.removeEventListener(e, reset);
    };
  }, [client, active, timeoutMs]);
}
