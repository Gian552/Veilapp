import { createContext, useContext, useEffect, useState, useSyncExternalStore } from 'react';
import type { ClientSnapshot, VeilClientApi } from '@veil/client';

const ClientContext = createContext<VeilClientApi | null>(null);

export const ClientProvider = ClientContext.Provider;

export function useClient(): VeilClientApi {
  const client = useContext(ClientContext);
  if (!client) throw new Error('VEIL client missing from context');
  return client;
}

/** Re-renders whenever the engine publishes a new snapshot. */
export function useSnapshot(): ClientSnapshot {
  const client = useClient();
  return useSyncExternalStore(
    (onChange) => client.subscribe(() => onChange()),
    () => client.snapshot(),
  );
}

/** A counter that bumps whenever the given conversation changes. */
export function useConversationVersion(peer: string | null): number {
  const client = useClient();
  const [version, setVersion] = useState(0);
  useEffect(() => {
    if (!peer) return;
    setVersion((v) => v + 1);
    return client.onConversation((changed) => {
      if (changed === peer) setVersion((v) => v + 1);
    });
  }, [client, peer]);
  return version;
}
