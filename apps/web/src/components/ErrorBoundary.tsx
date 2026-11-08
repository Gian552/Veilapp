import { Component, type ErrorInfo, type ReactNode } from 'react';

interface State {
  failed: boolean;
}

/**
 * Last-resort error screen. It deliberately shows no error details: stack
 * traces and messages could contain conversation data. Nothing is reported
 * anywhere (no telemetry).
 */
export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  override state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  override componentDidCatch(_error: unknown, _info: ErrorInfo): void {
    // Intentionally not logged.
  }

  override render() {
    if (!this.state.failed) return this.props.children;
    return (
      <main className="flow">
        <div className="flow-body" role="alert">
          <h1>Something went wrong</h1>
          <p className="flow-lede">
            VEIL hit an unexpected error. No details were sent anywhere. Reloading the page locks your vault; you will need your
            password again.
          </p>
          <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>
            Reload
          </button>
        </div>
      </main>
    );
  }
}
