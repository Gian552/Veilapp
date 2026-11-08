import type { ReactNode } from 'react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ResetOptions, ResetReport } from '@veil/client';
import { useClient, useSnapshot } from './lib/context';
import { type FlowApi, FlowProvider, type ResetRun } from './lib/flow';
import { useIdleLock } from './lib/useIdleLock';
import { describeError } from './lib/errors';
import { Welcome } from './screens/Welcome';
import { SignIn } from './screens/SignIn';
import { LinkDevice } from './screens/LinkDevice';
import { ResetResume } from './screens/ResetResume';
import { ResetProgress } from './screens/ResetProgress';
import { RecoveryKeyInterstitial } from './screens/RecoveryKeyInterstitial';
import { Shell } from './screens/Shell';

type InitState = { kind: 'loading' } | { kind: 'ready' } | { kind: 'error'; error: unknown };

export function App() {
  const client = useClient();
  const snap = useSnapshot();
  const [init, setInit] = useState<InitState>({ kind: 'loading' });
  const [recovery, setRecovery] = useState<{ username: string; key: string } | null>(null);
  const [reset, setReset] = useState<ResetRun | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    client.init().then(
      () => setInit({ kind: 'ready' }),
      (error: unknown) => setInit({ kind: 'error', error }),
    );
  }, [client]);

  useIdleLock(client, snap.status === 'ready' && reset === null);

  const onProgress = useCallback((report: ResetReport) => {
    setReset((r) => (r ? { ...r, report } : r));
  }, []);

  const runReset = useCallback(
    (run: () => Promise<ResetReport>, expectNewIdentity: boolean) => {
      setReset({ report: null, running: true, error: null, expectNewIdentity });
      run().then(
        (report) => setReset((r) => ({ ...(r ?? { expectNewIdentity, error: null }), report, running: false })),
        (error: unknown) => setReset((r) => ({ ...(r ?? { expectNewIdentity, report: null }), running: false, error })),
      );
    },
    [],
  );

  const flow: FlowApi = useMemo(
    () => ({
      showRecoveryKey: (username, key) => setRecovery({ username, key }),
      startReset: (options: ResetOptions) => runReset(() => client.panicReset(options, onProgress), options.createNewIdentity),
      resumeReset: async (password: string) => {
        runReset(() => client.resumeReset(password, onProgress), false);
      },
    }),
    [client, onProgress, runReset],
  );

  let content: ReactNode;
  if (reset) {
    content = <ResetProgress run={reset} onDone={() => setReset(null)} />;
  } else if (recovery) {
    content = <RecoveryKeyInterstitial username={recovery.username} recoveryKey={recovery.key} onDone={() => setRecovery(null)} />;
  } else if (init.kind === 'loading') {
    content = (
      <main className="flow" aria-busy="true">
        <p className="muted" role="status">
          <span className="spinner" aria-hidden="true" /> Opening VEIL…
        </p>
      </main>
    );
  } else if (init.kind === 'error') {
    content = (
      <main className="flow">
        <div className="flow-body" role="alert">
          <h1>VEIL could not start</h1>
          <p className="flow-lede">{describeError(init.error)}</p>
          <p className="muted small">
            VEIL needs local browser storage (IndexedDB) for its encrypted vault. Private browsing modes may block it.
          </p>
        </div>
      </main>
    );
  } else {
    switch (snap.status) {
      case 'no-vault':
        content = <Welcome />;
        break;
      case 'locked':
        content = <SignIn mode="unlock" />;
        break;
      case 'needs-link':
        content = <LinkDevice />;
        break;
      case 'reset-pending':
        content = <ResetResume />;
        break;
      case 'ready':
        content = <Shell />;
        break;
    }
  }

  return <FlowProvider value={flow}>{content}</FlowProvider>;
}
