import { type ChangeEvent, type FormEvent, type KeyboardEvent, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { AttachmentRef, ChatMessage, SystemNotice } from '@veil/client';
import { ErrorText } from '../components/ErrorText';
import { IconAlert, IconBack, IconCheck, IconClock, IconDoubleCheck, IconPaperclip, IconSend, IconShield } from '../components/Icons';
import { Plate } from '../components/Plate';
import { useClient, useConversationVersion, useSnapshot } from '../lib/context';
import { downloadBlob, formatBytes, toBlobPart } from '../lib/format';
import { VerifyPanel } from './VerifyPanel';

const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;
/** Raster formats only: SVG previews could carry active content. */
const PREVIEWABLE = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp']);

const NOTICE_TEXT: Record<SystemNotice, string> = {
  'key-changed': 'Their safety number changed. They may have reset or deleted their account, or someone may be intercepting.',
  'device-added': 'They added a new device. Messages are now also encrypted to it.',
  'device-removed': 'They removed a device.',
  verified: 'You marked this contact as verified.',
  unverified: 'Verification was removed.',
  'account-gone': 'This account no longer exists.',
  'session-started': 'Encrypted conversation started.',
};

interface Props {
  peer: string;
  onBack: () => void;
  onOpenSecurity: () => void;
}

export function Conversation({ peer, onBack, onOpenSecurity }: Props) {
  const client = useClient();
  const snap = useSnapshot();
  const version = useConversationVersion(peer);
  const summary = snap.conversations.find((c) => c.peer === peer);
  // messages() reads the decrypted in-memory view; version bumps on change.
  const messages = useMemo(() => client.messages(peer), [client, peer, version]);
  const [panel, setPanel] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  const keyChanged = summary?.verification === 'key-changed';
  const gone = summary?.accountGone === true;

  // Detect key changes / deleted accounts when the conversation is opened.
  useEffect(() => {
    client.refreshContact(peer).catch(() => undefined);
  }, [client, peer]);

  // Mark as read while the conversation is on screen and the tab is visible.
  useEffect(() => {
    if (document.visibilityState === 'visible' && (summary?.unread ?? 0) > 0) {
      client.markRead(peer).catch(() => undefined);
    }
  }, [client, peer, version, summary?.unread]);

  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState === 'visible') client.markRead(peer).catch(() => undefined);
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => document.removeEventListener('visibilitychange', onVisible);
  }, [client, peer]);

  useLayoutEffect(() => {
    const el = listRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages.length]);

  return (
    <div className="conv-wrap">
      <div className="conversation">
        <header className="conv-head">
          <div className="conv-head-title">
            <button type="button" className="btn btn-ghost btn-icon conv-back" onClick={onBack} aria-label="Back to conversations">
              <IconBack />
            </button>
            <Plate name={peer} />
            <div className="conv-head-names">
              <h2>{summary?.displayName ?? peer}</h2>
              <span className={summary?.verification === 'verified' ? 'conv-head-state verified' : 'conv-head-state'}>
                {summary?.displayName ? `${peer}, ` : ''}
                {summary?.verification === 'verified' ? 'Verified' : summary?.verification === 'key-changed' ? 'Safety number changed' : 'Not verified'}
              </span>
            </div>
          </div>
          <button type="button" className="btn btn-sm verify-toggle" aria-expanded={panel} onClick={() => setPanel((p) => !p)}>
            <IconShield size={16} />
            Verify
          </button>
        </header>

        {(keyChanged || gone) && (
          <div className="banner-area">
            {gone ? (
              <div className="notice notice-danger" role="alert">
                <div>
                  <strong>This account no longer exists.</strong>
                  <p>The person may have used Panic Reset or deleted their account. You cannot send further messages. If they have a new identity, they must tell you themselves.</p>
                </div>
              </div>
            ) : (
              <KeyChangedBanner peer={peer} onReview={() => setPanel(true)} />
            )}
          </div>
        )}

        <div className="messages" ref={listRef} role="log" aria-live="polite" aria-label={`Messages with ${peer}`} tabIndex={0}>
          {!messages.some((m) => m.direction === 'in') && (
            <aside className="exists-card" aria-label="About this conversation">
              <p className="exists-title">If {peer} exists, they will receive your messages.</p>
              <p>VEIL never confirms that an account exists. Their first reply does.</p>
            </aside>
          )}
          {messages.map((m, i) => (
            <MessageView key={m.id} message={m} peer={peer} grouped={i > 0 && messages[i - 1]!.direction === m.direction && m.direction !== 'system'} />
          ))}
        </div>

        <Composer peer={peer} disabled={keyChanged || gone} reason={gone ? 'This account no longer exists.' : keyChanged ? 'Review the key change above before sending.' : null} />
      </div>
      {panel && <VerifyPanel peer={peer} onClose={() => setPanel(false)} onOpenSecurity={onOpenSecurity} />}
    </div>
  );
}

function KeyChangedBanner({ peer, onReview }: { peer: string; onReview: () => void }) {
  const client = useClient();
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function accept() {
    setError(null);
    try {
      await client.acceptKeyChange(peer);
      setConfirming(false);
    } catch (err) {
      setError(err);
    }
  }

  return (
    <div className="notice notice-warn" role="alert">
      <div>
        <strong>{peer}'s safety number changed.</strong>
        <p>They may have reset their account, or someone may be in between. Sending is paused until you compare the new number with them.</p>
        <ErrorText error={error} />
        {confirming ? (
          <div className="btn-row">
            <button type="button" className="btn btn-sm btn-primary" onClick={accept}>
              Yes, accept the new key
            </button>
            <button type="button" className="btn btn-sm btn-ghost" onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </div>
        ) : (
          <div className="btn-row">
            <button type="button" className="btn btn-sm" onClick={onReview}>
              Review safety number
            </button>
            <button type="button" className="btn btn-sm btn-ghost" onClick={() => setConfirming(true)}>
              Accept new key
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function MessageView({ message: m, peer, grouped }: { message: ChatMessage; peer: string; grouped: boolean }) {
  if (m.direction === 'system') {
    const warn = m.notice === 'key-changed' || m.notice === 'account-gone';
    return (
      <p className={warn ? 'sys warn' : 'sys'} role="note">
        {(m.notice && NOTICE_TEXT[m.notice]) || m.text}
      </p>
    );
  }
  const out = m.direction === 'out';
  return (
    <div className={`msg ${out ? 'out' : 'in'}${grouped ? ' grouped' : ''}`}>
      <span className="visually-hidden">{out ? 'You: ' : `${peer}: `}</span>
      {m.text && <span className="msg-text">{m.text}</span>}
      {m.attachments.map((a) => (
        <AttachmentView key={a.attachmentId} peer={peer} messageId={m.id} attachment={a} />
      ))}
      {out && <MessageStatus message={m} />}
    </div>
  );
}

/** Sender-side state only. "Delivered" is not shown: VEIL keeps no delivery history. */
function MessageStatus({ message: m }: { message: ChatMessage }) {
  if (m.status === 'failed') {
    return (
      <span className="msg-meta failed">
        <IconAlert size={13} /> Not sent
      </span>
    );
  }
  const [icon, label] =
    m.status === 'sending' ? [<IconClock size={13} />, 'Sending'] : m.readByPeer ? [<IconDoubleCheck size={14} />, 'Read'] : [<IconCheck size={13} />, 'Sent'];
  return (
    <span className="msg-meta" title={label}>
      {icon}
      <span className="visually-hidden">{label}</span>
    </span>
  );
}

function AttachmentView({ peer, messageId, attachment }: { peer: string; messageId: string; attachment: AttachmentRef }) {
  const client = useClient();
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(
    () => () => {
      if (preview) URL.revokeObjectURL(preview);
    },
    [preview],
  );

  const canPreview = PREVIEWABLE.has(attachment.mime);

  async function fetchFile(action: 'save' | 'preview') {
    setBusy(true);
    setError(null);
    try {
      const file = await client.downloadAttachment(peer, messageId, attachment.attachmentId);
      if (action === 'preview' && PREVIEWABLE.has(file.mime)) {
        setPreview(URL.createObjectURL(new Blob([toBlobPart(file.bytes)], { type: file.mime })));
      } else {
        downloadBlob(toBlobPart(file.bytes), file.name, 'application/octet-stream');
      }
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="attachment">
        <span className="attachment-info">
          <span>{attachment.name}</span>
          <span className="faint xsmall">{formatBytes(attachment.size)}, end-to-end encrypted</span>
        </span>
        {canPreview && !preview && (
          <button type="button" className="btn btn-sm" onClick={() => fetchFile('preview')} disabled={busy}>
            View
          </button>
        )}
        <button type="button" className="btn btn-sm" onClick={() => fetchFile('save')} disabled={busy}>
          {busy ? '…' : 'Save'}
        </button>
      </div>
      {preview && <img className="attachment-preview" src={preview} alt={attachment.name} />}
      <ErrorText error={error} />
    </div>
  );
}

function Composer({ peer, disabled, reason }: { peer: string; disabled: boolean; reason: string | null }) {
  const client = useClient();
  const [text, setText] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [sending, setSending] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const area = useRef<HTMLTextAreaElement>(null);

  // Grow with the content up to the CSS max-height (CSSOM writes are CSP-safe).
  useLayoutEffect(() => {
    const el = area.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${el.scrollHeight}px`;
  }, [text]);

  function pickFile(e: ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0] ?? null;
    e.target.value = '';
    setFileError(null);
    if (f && f.size > MAX_ATTACHMENT_BYTES) {
      setFileError(`Files are limited to ${formatBytes(MAX_ATTACHMENT_BYTES)}.`);
      return;
    }
    setFile(f);
  }

  async function send(e?: FormEvent) {
    e?.preventDefault();
    const body = text.trim();
    // Text can be sent back to back (the engine orders sends); only uploads block the composer.
    if (disabled || sending || (!body && !file)) return;
    const pending = file;
    setError(null);
    // Clear right away so typing the next message is never wiped by a send finishing.
    if (body) setText('');
    if (pending) {
      setFile(null);
      setSending(true);
    }
    try {
      if (pending) {
        const bytes = new Uint8Array(await pending.arrayBuffer());
        await client.sendAttachment(peer, { name: pending.name, mime: pending.type || 'application/octet-stream', bytes });
      }
      if (body) await client.sendText(peer, body);
    } catch (err) {
      setError(err);
      // Give the text back if the box is still empty, so nothing the user wrote is lost.
      if (body) setText((t) => (t ? t : body));
      if (pending) setFile((f) => f ?? pending);
    } finally {
      if (pending) setSending(false);
    }
  }

  function onKey(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault();
      void send();
    }
  }

  return (
    <div>
      {file && (
        <div className="composer-file">
          <span>
            {file.name} · {formatBytes(file.size)}
          </span>
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => setFile(null)}>
            Remove
          </button>
        </div>
      )}
      {(fileError || error !== null || reason) && (
        <div className="composer-file">
          {fileError && <span className="field-error">{fileError}</span>}
          {reason && <span>{reason}</span>}
          <ErrorText error={error} />
        </div>
      )}
      <form className="composer" onSubmit={send}>
        <input ref={fileInput} type="file" hidden onChange={pickFile} tabIndex={-1} aria-hidden="true" />
        <button type="button" className="btn btn-ghost btn-icon" onClick={() => fileInput.current?.click()} disabled={disabled || sending} aria-label="Attach a file">
          <IconPaperclip />
        </button>
        <label htmlFor="composer-input" className="visually-hidden">
          Message to {peer}
        </label>
        <textarea
          id="composer-input"
          ref={area}
          className="composer-input"
          rows={1}
          placeholder={disabled ? '' : `Message ${peer}`}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={onKey}
          disabled={disabled}
          maxLength={8000}
        />
        <button type="submit" className="btn btn-primary btn-icon composer-send" disabled={disabled || sending || (!text.trim() && !file)} aria-label="Send">
          <IconSend />
        </button>
      </form>
    </div>
  );
}
