// Project-specific static analysis: patterns that must never appear in VEIL
// source code. Cheaper and more targeted than a general linter for the
// properties we actually care about (no weak randomness, no dynamic code, no
// browser storage of secrets, no request logging, no third-party requests).
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = join(import.meta.dirname, '..', '..', '..');
const SOURCE_DIRS = ['packages/crypto/src', 'packages/shared/src', 'packages/client/src', 'apps/server/src', 'apps/web/src'];

function files(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...files(p));
    else if (/\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name)) out.push(p);
  }
  return out;
}

const all = SOURCE_DIRS.flatMap((d) => files(join(ROOT, d))).map((p) => ({ path: relative(ROOT, p), text: readFileSync(p, 'utf8') }));

function offenders(pattern: RegExp, scope: (path: string) => boolean = () => true) {
  return all.filter((f) => scope(f.path) && pattern.test(f.text)).map((f) => f.path);
}

describe('static analysis', () => {
  it('scans a non-trivial amount of source', () => {
    expect(all.length).toBeGreaterThan(40);
  });

  it('never uses Math.random (all randomness must come from the CSPRNG)', () => {
    expect(offenders(/Math\.random\s*\(/)).toEqual([]);
  });

  it('never evaluates dynamic code', () => {
    expect(offenders(/\beval\s*\(|new Function\s*\(/)).toEqual([]);
  });

  it('never writes raw HTML into the DOM', () => {
    expect(offenders(/dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(/)).toEqual([]);
  });

  it('never uses localStorage, sessionStorage or cookies (secrets live only in the encrypted vault or memory)', () => {
    expect(offenders(/localStorage|sessionStorage|document\.cookie/)).toEqual([]);
  });

  it('has no console.log/debug/info outside the CLI and startup entrypoints (no diagnostic leakage)', () => {
    const scope = (p: string) => p !== 'apps/server/src/main.ts' && p !== 'apps/server/src/admin.ts';
    expect(offenders(/console\.(log|debug|info|trace)\s*\(/, scope)).toEqual([]);
  });

  it('server code reads the client address in exactly one place: the in-memory rate-limit helper', () => {
    const uses = all
      .filter((f) => f.path.startsWith('apps/server/src'))
      .flatMap((f) => [...f.text.matchAll(/\breq(uest)?\.(ips?|socket\.remoteAddress)\b/g)].map(() => f.path));
    expect(new Set(uses)).toEqual(new Set(['apps/server/src/context.ts']));
    const ctx = all.find((f) => f.path === 'apps/server/src/context.ts')!.text;
    const fn = ctx.slice(ctx.indexOf('export function clientAddress'), ctx.indexOf('export function limitByAddress'));
    expect(fn).toMatch(/req\.ip/);
    expect(offenders(/user-agent|x-real-ip/i, (p) => p.startsWith('apps/server/src'))).toEqual([]);
    // The address only ever flows into the HMAC tagger.
    expect(ctx.match(/clientAddress\(/g)!.length).toBe(2); // definition + the single call in limitByAddress
  });

  it('the web app references no external origins', () => {
    const scope = (p: string) => p.startsWith('apps/web/src');
    expect(offenders(/https?:\/\/(?!127\.0\.0\.1|localhost)[a-z0-9.-]+\.[a-z]{2,}/i, scope)).toEqual([]);
  });

  it('crypto code does not import non-audited crypto libraries', () => {
    const imports = all
      .filter((f) => f.path.startsWith('packages/crypto/src'))
      .flatMap((f) => [...f.text.matchAll(/from '([^'.][^']*)'/g)].map((m) => m[1]!));
    expect(new Set(imports.filter((i) => !i.startsWith('@noble/') && i !== 'hash-wasm'))).toEqual(new Set());
  });
});
