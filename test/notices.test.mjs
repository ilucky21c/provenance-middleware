import { handler, prepare, sendNotice, NOTICES_PATH } from '../src/index.js';
import { generateProvenanceKeyPair } from 'provenance-protocol/keygen';
import { verifyNotice, declarationDigest } from 'provenance-protocol/verify';
import { validateNotice } from 'provenance-protocol/validate';

let pass = 0, fail = 0;
const t = (name, ok, extra = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + extra}`);
  ok ? pass++ : fail++;
};
process.removeAllListeners('warning');
const warnings = [];
process.on('warning', (w) => warnings.push(w.message));

const ID = 'provenance:domain:agent.example.com';
const { publicKey, privateKey } = generateProvenanceKeyPair();
const declaration = {
  provenance: '0.2', name: 'Agent', description: 'Does things.', version: '4.2.0',
  provenance_id: ID, identity: { public_key: publicKey, algorithm: 'ed25519' },
};

const p = await prepare({ declaration, privateKey });
const r = await verifyNotice(p.published, { publicKey });
t('published notice verifies against the agent key', r.valid && r.event === 'declaration-published', r.reason);
t('published notice is schema-valid', validateNotice(p.published).valid, JSON.stringify(validateNotice(p.published).errors));
t('it names the served declaration by digest', p.published.claims.declaration_digest === await declarationDigest(p.declaration));
t('it names the standard location', p.published.claims.declaration_url === 'https://agent.example.com/.well-known/provenance.json');
t('it carries the running version', p.published.claims.running_version === '4.2.0');

// Notices feed.
const fn = await handler({ declaration, privateKey });
const res = await fn(new Request(`https://agent.example.com${NOTICES_PATH}`));
const feed = await res.json();
t('notices feed served', res.status === 200 && Array.isArray(feed) && feed[0]?.event === 'declaration-published');

// Push: only to watchers named, never by default.
const sent = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => { sent.push({ url, body: JSON.parse(init.body) }); return new Response('{}', { status: 202 }); };
await handler({ declaration, privateKey });
await new Promise((r) => setTimeout(r, 20));
t('nothing is sent when no watcher is named', sent.length === 0);

const results = [];
await handler({ declaration, privateKey, notify: ['https://watcher-a.example/in', 'https://watcher-b.example/in'], onNotify: (x) => results.push(x) });
await new Promise((r) => setTimeout(r, 20));
t('the signed notice goes to each named watcher', sent.length === 2 && sent.every((s) => s.body.event === 'declaration-published'));
t('each delivery outcome is reported', results.length === 2 && results.every((x) => x.ok));

globalThis.fetch = async () => { throw new Error('connection refused'); };
const out = await sendNotice(p.published, ['https://down.example/in']);
await new Promise((r) => setImmediate(r));
t('an unreachable watcher is reported, not swallowed', out[0].ok === false && warnings.some((w) => w.includes('down.example')));
const plain = await sendNotice(p.published, ['http://insecure.example/in']);
t('plain http watcher refused', plain[0].ok === false && /https/.test(plain[0].error));
globalThis.fetch = realFetch;

// Internal service: the declaration travels inside the notice.
const { openDeliveredDeclaration } = await import('provenance-protocol');
const internal = { ...declaration, provenance_id: 'provenance:domain:hr.corp.internal' };
const pi = await prepare({ declaration: internal, privateKey, deliverDeclaration: true });
const opened = await openDeliveredDeclaration(pi.published);
t('an internal service delivers its declaration inside the notice', opened.valid && opened.declaration?.provenance_id === 'provenance:domain:hr.corp.internal', opened.reason);
t('without deliverDeclaration the notice carries only the digest', !('declaration' in p.published.claims));

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
