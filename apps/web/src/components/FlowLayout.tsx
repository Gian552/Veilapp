import type { ReactNode } from 'react';
import { Brand } from './Brand';

export function FlowLayout({ children, wide = false }: { children: ReactNode; wide?: boolean }) {
  return (
    <div className="flow">
      <header className={wide ? 'flow-header wide' : 'flow-header'}>
        <Brand />
      </header>
      <main className={wide ? 'flow-body wide' : 'flow-body'} id="main">
        {children}
      </main>
    </div>
  );
}
