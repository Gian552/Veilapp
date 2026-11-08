// In-memory registry of authenticated WebSockets. Sockets carry notifications
// only ("you have mail"), never content. Nothing here is persisted or logged.

import type { WsServerFrame } from '@veil/shared';
import { toHex } from '@veil/crypto';

export interface SocketLike {
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

interface Entry {
  socket: SocketLike;
  sessionId: string;
  accountId: string;
  deviceId: string | null;
}

export class Hub {
  private bySession = new Map<string, Set<Entry>>();

  add(socket: SocketLike, sessionId: Uint8Array, accountId: string, deviceId: Uint8Array | null): () => void {
    const entry: Entry = { socket, sessionId: toHex(sessionId), accountId, deviceId: deviceId ? toHex(deviceId) : null };
    let set = this.bySession.get(entry.sessionId);
    if (!set) this.bySession.set(entry.sessionId, (set = new Set()));
    set.add(entry);
    return () => {
      set!.delete(entry);
      if (set!.size === 0) this.bySession.delete(entry.sessionId);
    };
  }

  private *entries(): Iterable<Entry> {
    for (const set of this.bySession.values()) yield* set;
  }

  private send(e: Entry, frame: WsServerFrame): void {
    try {
      e.socket.send(JSON.stringify(frame));
    } catch {
      // socket already gone
    }
  }

  notifyDevices(deviceIds: Uint8Array[], frame: WsServerFrame): void {
    const wanted = new Set(deviceIds.map(toHex));
    for (const e of this.entries()) if (e.deviceId && wanted.has(e.deviceId)) this.send(e, frame);
  }

  notifyAccountDevices(accountId: string, frame: WsServerFrame): void {
    for (const e of this.entries()) if (e.accountId === accountId && e.deviceId) this.send(e, frame);
  }

  /** Tells sockets of revoked sessions and closes them. */
  revokeSessions(sessionIds: Uint8Array[]): void {
    for (const id of sessionIds) {
      const set = this.bySession.get(toHex(id));
      if (!set) continue;
      for (const e of [...set]) {
        this.send(e, { type: 'revoked' });
        try {
          e.socket.close(4001, 'revoked');
        } catch {
          // ignore
        }
      }
      this.bySession.delete(toHex(id));
    }
  }

  revokeDevices(deviceIds: Uint8Array[]): void {
    const wanted = new Set(deviceIds.map(toHex));
    const sessions: Uint8Array[] = [];
    for (const e of this.entries()) if (e.deviceId && wanted.has(e.deviceId)) sessions.push(hexToBytes(e.sessionId));
    this.revokeSessions(sessions);
  }

  closeAll(): void {
    for (const e of [...this.entries()]) {
      try {
        e.socket.close(1001, 'shutdown');
      } catch {
        // ignore
      }
    }
    this.bySession.clear();
  }

  get size(): number {
    let n = 0;
    for (const s of this.bySession.values()) n += s.size;
    return n;
  }
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
