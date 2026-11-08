import { type FormEvent, useState } from 'react';
import { ErrorText } from '../components/ErrorText';
import { IconPlus } from '../components/Icons';
import { Plate } from '../components/Plate';
import { useClient, useSnapshot } from '../lib/context';
import { Conversation } from './Conversation';

/** Rail content for Chats: start a conversation, then the ruled list of plates. */
export function ChatList({ active, onOpen }: { active: string | null; onOpen: (peer: string) => void }) {
  const snap = useSnapshot();
  const current = active ? (snap.conversations.find((c) => c.peer.toLowerCase() === active.toLowerCase())?.peer ?? null) : null;

  return (
    <div className="chat-list">
      <NewConversation onStarted={onOpen} />
      {snap.conversations.length === 0 ? (
        <p className="rail-note">No conversations yet. Ask someone for their VEIL username; there is no directory to browse.</p>
      ) : (
        <ul className="conv-list" aria-label="Conversations">
          {snap.conversations.map((c) => (
            <li key={c.peer}>
              <button type="button" className="conv-item" aria-current={c.peer === current ? 'true' : undefined} onClick={() => onOpen(c.peer)}>
                <Plate name={c.peer} />
                <span className="conv-text">
                  <span className="conv-name">{c.displayName ?? c.peer}</span>
                  <span className={c.verification === 'key-changed' ? 'conv-preview alert' : 'conv-preview'}>
                    {c.verification === 'key-changed' ? 'Safety number changed' : c.preview || 'No messages yet'}
                  </span>
                </span>
                <span className="conv-side">
                  {c.unread > 0 && (
                    <span className="count" aria-label={`${c.unread} unread`}>
                      {c.unread}
                    </span>
                  )}
                  {c.verification === 'verified' && <span className="seal" title="Verified" aria-label="Verified" />}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Main area for Chats: the open conversation, or a quiet resting state. */
export function ChatMain({ peer, onBack, onOpenSecurity }: { peer: string | null; onBack: () => void; onOpenSecurity: () => void }) {
  const snap = useSnapshot();
  const active = peer ? (snap.conversations.find((c) => c.peer.toLowerCase() === peer.toLowerCase())?.peer ?? null) : null;
  if (active) return <Conversation key={active} peer={active} onBack={onBack} onOpenSecurity={onOpenSecurity} />;
  return (
    <div className="resting">
      {snap.username && <Plate name={snap.username} size="xl" own />}
      <h2>{snap.username}</h2>
      <p>Pick a conversation, or start one with a username. Everything you read here was decrypted on this device.</p>
    </div>
  );
}

function NewConversation({ onStarted }: { onStarted: (peer: string) => void }) {
  const client = useClient();
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const username = name.trim();
    if (!username) return;
    setBusy(true);
    setError(null);
    try {
      await client.startConversation(username);
      setName('');
      onStarted(username);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="new-chat" onSubmit={submit} noValidate>
      <label htmlFor="new-chat" className="visually-hidden">
        Start a conversation with username
      </label>
      <div className="new-chat-row">
        <input
          id="new-chat"
          className="input"
          placeholder="Username, e.g. SilentComet"
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          aria-describedby="new-chat-hint"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <button type="submit" className="btn btn-icon btn-primary" disabled={busy || !name.trim()} aria-label="Start conversation">
          <IconPlus />
        </button>
      </div>
      <p id="new-chat-hint" className="new-chat-hint">
        If this person exists, they will receive your messages.
      </p>
      <ErrorText error={error} />
    </form>
  );
}
