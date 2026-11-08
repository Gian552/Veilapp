import { useState } from 'react';
import { CopyButton } from '../components/CopyButton';
import { IconLock } from '../components/Icons';
import { Plate } from '../components/Plate';
import { useClient, useSnapshot } from '../lib/context';
import { ChatList, ChatMain } from './Chats';
import { SECTIONS, SettingsPage, type SettingsSection } from './settings/Settings';
import { SecurityInfo } from './SecurityInfo';

type View = 'chats' | 'settings' | 'security';

const CONNECTION_LABEL = { online: 'Connected', connecting: 'Connecting', offline: 'Offline' } as const;

/**
 * The app frame: one rail that holds who you are, where you are, and the list
 * for that place; the main area holds the open item. On phones the two are
 * separate screens (data-pane decides which one shows).
 */
export function Shell() {
  const client = useClient();
  const snap = useSnapshot();
  const [view, setView] = useState<View>('chats');
  const [section, setSection] = useState<SettingsSection>('privacy');
  const [peer, setPeer] = useState<string | null>(null);
  const [pane, setPane] = useState<'rail' | 'main'>('rail');

  const go = (v: View) => {
    setView(v);
    setPane(v === 'security' ? 'main' : 'rail');
  };
  const openPeer = (p: string) => {
    setPeer(p);
    setPane('main');
  };
  const openSection = (s: SettingsSection) => {
    setSection(s);
    setView('settings');
    setPane('main');
  };

  return (
    <div className="shell" data-pane={pane}>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <aside className="rail" aria-label="VEIL">
        <div className="rail-top">
          <span className="wordmark">VEIL</span>
          <span className="conn" data-state={snap.connection} role="status" title="This device's connection to the VEIL server">
            {CONNECTION_LABEL[snap.connection]}
          </span>
        </div>

        {snap.username && (
          <div className="me-plate">
            <Plate name={snap.username} size="lg" own />
            <div className="me-text">
              <span className="me-name">{snap.username}</span>
              <span className="me-sub">Your username</span>
            </div>
            <CopyButton text={snap.username} />
          </div>
        )}

        <nav className="rail-nav" aria-label="Main">
          <button type="button" aria-current={view === 'chats' ? 'page' : undefined} onClick={() => go('chats')}>
            Chats
          </button>
          <button type="button" aria-current={view === 'settings' ? 'page' : undefined} onClick={() => go('settings')}>
            Settings
          </button>
          <button type="button" aria-current={view === 'security' ? 'page' : undefined} onClick={() => go('security')}>
            Security
          </button>
        </nav>

        <div className="rail-body">
          {view === 'chats' && <ChatList active={peer} onOpen={openPeer} />}
          {view === 'settings' && (
            <ul className="rail-sections">
              {SECTIONS.map((s) => (
                <li key={s.id}>
                  <button
                    type="button"
                    className={s.danger ? 'danger' : undefined}
                    aria-current={section === s.id ? 'page' : undefined}
                    onClick={() => openSection(s.id)}
                  >
                    {s.label}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="rail-foot">
          <button type="button" className="lock-btn" onClick={() => void client.lock()} title="Clears every key from memory">
            <IconLock size={16} />
            Lock VEIL
          </button>
        </div>
      </aside>

      <main className="stage" id="main">
        {view === 'chats' && <ChatMain peer={peer} onBack={() => setPane('rail')} onOpenSecurity={() => go('security')} />}
        {view === 'settings' && <SettingsPage section={section} onBack={() => setPane('rail')} />}
        {view === 'security' && <SecurityInfo onOpenSettings={openSection} />}
      </main>
    </div>
  );
}
