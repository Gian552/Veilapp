// App-level flows that must outlive the status they started in: the recovery
// key confirmation right after registration (status already 'ready'), and a
// Panic Reset run (status changes underneath it several times).
import { createContext, useContext } from 'react';
import type { ResetOptions, ResetReport } from '@veil/client';

export interface ResetRun {
  report: ResetReport | null;
  running: boolean;
  error: unknown;
  expectNewIdentity: boolean;
}

export interface FlowApi {
  showRecoveryKey(username: string, recoveryKey: string): void;
  startReset(options: ResetOptions): void;
  resumeReset(password: string): Promise<void>;
}

const FlowContext = createContext<FlowApi | null>(null);
export const FlowProvider = FlowContext.Provider;

export function useFlow(): FlowApi {
  const f = useContext(FlowContext);
  if (!f) throw new Error('flow context missing');
  return f;
}
