import { IconAlert, IconCheck } from './Icons';

export type StepState = 'pending' | 'active' | 'done' | 'failed';

export interface Step {
  label: string;
  state: StepState;
  detail?: string | undefined;
}

export function ProgressSteps({ steps, label }: { steps: Step[]; label: string }) {
  return (
    <ol className="steps" aria-label={label}>
      {steps.map((s) => (
        <li key={s.label} className={`step ${s.state}`}>
          <span className="step-dot" aria-hidden="true">
            {s.state === 'done' ? <IconCheck size={12} /> : s.state === 'failed' ? <IconAlert size={12} /> : null}
          </span>
          <span>
            {s.label}
            <span className="visually-hidden">: {s.state}</span>
            {s.detail && <span className="step-detail">{s.detail}</span>}
          </span>
        </li>
      ))}
    </ol>
  );
}
