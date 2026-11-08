import { useState } from 'react';
import type { ResetPhase, ResetReport } from '@veil/client';
import { FlowLayout } from '../components/FlowLayout';
import { ProgressSteps, type Step, type StepState } from '../components/ProgressSteps';
import { RecoveryKeyDisplay } from '../components/RecoveryKey';
import { describeError } from '../lib/errors';
import type { ResetRun } from '../lib/flow';

const TERMINAL: ResetPhase[] = ['completed', 'partial', 'failed'];

const HEADLINE: Record<ResetPhase, string> = {
  initiated: 'Reset initiated',
  'server-deleting': 'Reset in progress',
  'server-deleted': 'Reset in progress',
  'local-wiped': 'Reset in progress',
  'new-identity': 'Reset in progress',
  completed: 'Reset completed',
  partial: 'Reset partially completed',
  failed: 'Reset failed',
};

/**
 * Each step's state is derived from evidence in the report (server
 * confirmation, local wipe flag, new identity), never from the phase alone, so
 * nothing is shown as deleted before the engine has confirmed it.
 */
function buildSteps(report: ResetReport | null, running: boolean, expectNewIdentity: boolean): Step[] {
  const phase = report?.phase ?? 'initiated';
  const terminal = !running && TERMINAL.includes(phase);
  const state = (done: boolean, active: boolean): StepState => (done ? 'done' : terminal ? 'failed' : active ? 'active' : 'pending');

  const server = report?.server ?? null;
  const serverDeleted = server?.accountRecordsDeleted === true;
  const steps: Step[] = [
    { label: 'Reset initiated', state: report ? 'done' : 'active' },
    {
      label: 'Server deletion requested',
      state: state(server !== null, phase === 'server-deleting' || phase === 'initiated'),
      detail: phase === 'server-deleting' && !server ? 'Contacting the server. Retries automatically if the connection drops.' : undefined,
    },
    {
      label: 'Server confirmed account records deleted',
      state: state(serverDeleted, phase === 'server-deleting'),
      detail: serverDeleted ? 'Credentials, sessions, devices, keys, queued messages and profile.' : undefined,
    },
  ];
  if (server) {
    const pending = server.attachmentsPending;
    steps.push({
      label: 'Uploaded attachments deleted',
      state: pending === 0 && serverDeleted ? 'done' : terminal ? 'failed' : 'active',
      detail:
        pending > 0
          ? `${pending} still pending. The server keeps retrying; unretrieved files expire within ${server.attachmentRetentionDays} days regardless.`
          : `${server.attachmentsDeleted} deleted${server.attachmentsNotFound ? `, ${server.attachmentsNotFound} already gone` : ''}.`,
    });
  }
  steps.push({
    label: 'This device wiped',
    state: state(report?.localWiped === true, phase === 'server-deleted'),
    detail: report?.localWiped ? 'Vault key destroyed and local database deleted.' : undefined,
  });
  if (expectNewIdentity || report?.newIdentity) {
    const ni = report?.newIdentity ?? null;
    steps.push({
      label: 'New identity created',
      state: state(ni !== null, phase === 'local-wiped'),
      detail: ni ? (ni.distinctFromOld ? 'Verified distinct from the old identity.' : 'Warning: could not verify it is distinct.') : undefined,
    });
  }
  return steps;
}

export function ResetProgress({ run, onDone }: { run: ResetRun; onDone: () => void }) {
  const { report, running, error, expectNewIdentity } = run;
  const phase: ResetPhase = report?.phase ?? 'initiated';
  const [keySaved, setKeySaved] = useState(false);
  const steps = buildSteps(report, running, expectNewIdentity);
  const finished = !running;
  const newIdentity = report?.newIdentity ?? null;
  const needsKeyAck = finished && newIdentity?.recoveryKey && !keySaved;

  const headline = error && finished ? 'Reset could not continue' : running ? HEADLINE[phase === 'completed' ? 'new-identity' : phase] : HEADLINE[phase];

  return (
    <FlowLayout>
      <h1 aria-live="polite">{headline}</h1>
      {running && <p className="flow-lede">Keep this page open until the reset finishes.</p>}

      <div aria-live="polite">
        <ProgressSteps label="Panic Reset progress" steps={steps} />
      </div>

      {report?.server && (
        <div className="stat-row" aria-label="Server deletion counts">
          <div className="stat">
            <b>{report.server.attachmentsDeleted}</b>
            <span>attachments deleted</span>
          </div>
          <div className="stat">
            <b>{report.server.attachmentsPending}</b>
            <span>pending deletion</span>
          </div>
          <div className="stat">
            <b>{report.server.attachmentsNotFound}</b>
            <span>already gone</span>
          </div>
        </div>
      )}

      {error !== null && finished && (
        <div className="notice notice-danger" role="alert">
          <div>
            <strong>{describeError(error)}</strong>
            <p>Nothing beyond the steps marked done above has been confirmed.</p>
          </div>
        </div>
      )}

      {report && report.problems.length > 0 && (
        <div className="notice notice-warn" role="status">
          <div>
            <strong>Not confirmed</strong>
            <ul>
              {report.problems.map((p, i) => (
                <li key={i}>{p}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {finished && report && report.notes.length > 0 && (
        <div className="muted small">
          <strong>Limits that apply to every reset</strong>
          <ul>
            {report.notes.map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>
        </div>
      )}

      {finished && newIdentity && (
        <div className="card">
          <h3>Your new identity</h3>
          <p>
            <strong className="username">{newIdentity.username}</strong>
          </p>
          <p className="muted small">
            It shares nothing with the old one. Your contacts were not notified, so give them this name yourself, ideally over
            a different channel than before.
          </p>
          {newIdentity.recoveryKey && (
            <>
              <p className="small">New recovery key. Write it down now; the old one no longer works.</p>
              <RecoveryKeyDisplay recoveryKey={newIdentity.recoveryKey} />
              <label className="checkbox">
                <input type="checkbox" checked={keySaved} onChange={(e) => setKeySaved(e.target.checked)} />
                <span className="checkbox-text">I have written down the new recovery key.</span>
              </label>
            </>
          )}
        </div>
      )}

      {finished && (
        <div className="btn-row">
          <button type="button" className="btn btn-primary" onClick={onDone} disabled={!!needsKeyAck}>
            Continue
          </button>
        </div>
      )}
    </FlowLayout>
  );
}
