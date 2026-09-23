import { handler, prepare, DECLARATION_PATH, CHALLENGE_PATH, ProvenanceMiddlewareError } from '../src/index.js';
import { generateProvenanceKeyPair, signAgentRevocation } from 'provenance-protocol/keygen';
import { verifyDeclaration, verifyAgentChallenge, verifyAgentRevocation } from 'provenance-protocol/verify';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let pass = 0, fail = 0;
const t = (name, ok, extra = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + extra}`);
  ok ? pass++ : fail++;
};

const ID = 'provenance:github:alice/research-agent';
const { publicKey, privateKey } = generateProvenanceKeyPair();

const yaml = `# A declaration with comments and odd formatting, to prove neither matters.
provenance: "0.2"
name: "Research Agent"
description: >
  Searches the web and summarises papers.
capabilities:
  - read:web
  - write:summaries
constraints:
  - no:pii            # a public commitment
  - no:financial:transact
provenance_id: "${ID}"
identity:
  public_key: "${publicKey}"
  algorithm: ed25519
`;
const dir = mkdtempSync(join(tmpdir(), 'prov-'));
const file = join(dir, 'PROVENANCE.yml');
writeFileSync(file, yaml);

const fn = await handler({ declaration: file, privateKey });
const origin = 'https://agent.example.com';

// --- serving the declaration ---
const res = await fn(new Request(`${origin}${DECLARATION_PATH}`));
t('serves the declaration', res?.status === 200);
const served = await res.json();
t('signature was added at startup', typeof served.identity?.signature === 'string');
t('comments and formatting are gone but content survived',
  served.constraints?.length === 2 && served.name === 'Research Agent');

// The service is the publication point, so the location check must pass there.
const v = await verifyDeclaration(served, { retrievedFrom: `${origin}${DECLARATION_PATH}` });
t('served declaration verifies offline', v.valid === true, v.reason ?? '');
t('coverage is the whole declaration', v.coverage === 'declaration');

// --- tampering in transit ---
const tampered = { ...served, constraints: ['no:pii'] };
const vt = await verifyDeclaration(tampered);
t('deleting a constraint breaks it', vt.valid === false);

// --- the challenge endpoint ---
const ch = await fn(new Request(`${origin}${CHALLENGE_PATH}`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ nonce: 'a7f3c1e9b2d84056' }),
}));
t('answers a challenge', ch?.status === 200);
const proof = await ch.json();
t('challenge signature verifies',
  await verifyAgentChallenge(publicKey, ID, 'a7f3c1e9b2d84056', proof.signature) === true);
t('reports which domain it signed', proof.payload_domain === 'provenance-challenge-v1');

// --- THE ATTACK: can a caller get a revocation out of the endpoint? ---
const evil = await fn(new Request(`${origin}${CHALLENGE_PATH}`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ nonce: 'REVOKE' }),
}));
const evilBody = await evil.json();
t('nonce "REVOKE" does NOT yield a revocation',
  await verifyAgentRevocation(publicKey, ID, evilBody.signature) === false);
t('and it differs from a real revocation',
  evilBody.signature !== signAgentRevocation(privateKey, ID));

// --- nonce hygiene ---
for (const [label, nonce, expected] of [
  ['rejects an empty nonce', '', 400],
  ['rejects an over-long nonce', 'a'.repeat(300), 400],
  ['rejects odd characters', 'a b\n<script>', 400],
]) {
  const r = await fn(new Request(`${origin}${CHALLENGE_PATH}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ nonce }),
  }));
  t(label, r?.status === expected, `got ${r?.status}`);
}
const bad = await fn(new Request(`${origin}${CHALLENGE_PATH}`, { method: 'POST', body: 'not json' }));
t('rejects a non-JSON body', bad?.status === 400);
const wrongMethod = await fn(new Request(`${origin}${CHALLENGE_PATH}`));
t('rejects GET on the challenge path', wrongMethod?.status === 405);

// --- routing ---
t('ignores unrelated paths', (await fn(new Request(`${origin}/api/orders`))) === null);

// --- refusing to serve something misleading ---
try {
  await prepare({ declaration: { ...JSON.parse(JSON.stringify(served)), provenance: '0.1' }, privateKey });
  t('refuses to sign a file that claims 0.1', false);
} catch (e) {
  t('refuses to sign a file that claims 0.1', e instanceof ProvenanceMiddlewareError);
}
try {
  await prepare({ declaration: { provenance: '0.2', name: 'x', description: 'y' }, privateKey });
  t('refuses a declaration with no provenance_id', false);
} catch (e) {
  t('refuses a declaration with no provenance_id', e instanceof ProvenanceMiddlewareError);
}
try {
  await prepare({ declaration: file });
  t('refuses to run with no key', false);
} catch (e) {
  t('refuses to run with no key', e instanceof ProvenanceMiddlewareError);
}

// --- a stale signature must never survive a restart ---
const second = await prepare({ declaration: { ...served, constraints: ['no:pii'] }, privateKey });
const vs = await verifyDeclaration(second.declaration);
t('re-signs on load rather than serving a stale signature', vs.valid === true);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
