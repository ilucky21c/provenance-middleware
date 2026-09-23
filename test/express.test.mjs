/**
 * Runs the Express middleware against a real HTTP server, so the Node
 * request/response bridging is exercised rather than assumed.
 */
import { createServer } from 'node:http';
import { provenance, DECLARATION_PATH, CHALLENGE_PATH } from '../src/index.js';
import { generateProvenanceKeyPair } from 'provenance-protocol/keygen';
import { verifyDeclaration, verifyAgentChallenge } from 'provenance-protocol/verify';

let pass = 0, fail = 0;
const t = (name, ok, extra = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + extra}`);
  ok ? pass++ : fail++;
};

const { publicKey, privateKey } = generateProvenanceKeyPair();
const HOST = '127.0.0.1';
const ID = `provenance:domain:${HOST}`;

const mw = provenance({
  declaration: {
    provenance: '0.2', name: 'Research Agent', description: 'Searches and summarises.',
    capabilities: ['read:web'], constraints: ['no:pii'],
    provenance_id: ID,
    identity: { public_key: publicKey, algorithm: 'ed25519' },
  },
  privateKey,
  version: 'build-1234',
});

// Minimal Connect-style app: the middleware, then a fallthrough route.
const server = createServer((req, res) => {
  mw(req, res, () => {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/plain');
    res.end('app route reached');
  });
});

await new Promise((resolve) => server.listen(0, HOST, resolve));
const port = server.address().port;
const origin = `http://${HOST}:${port}`;

try {
  const res = await fetch(`${origin}${DECLARATION_PATH}`);
  t('serves the declaration over HTTP', res.status === 200);
  t('content type is JSON', (res.headers.get('content-type') ?? '').includes('application/json'));
  t('is fetchable cross-origin', res.headers.get('access-control-allow-origin') === '*');

  const served = await res.json();
  t('version override applied', served.version === 'build-1234');

  // The service IS the location its identifier names, so this must be trustworthy.
  const v = await verifyDeclaration(served, { retrievedFrom: `${origin}${DECLARATION_PATH}` });
  t('verifies as the operator\'s own declaration',
    v.valid === true && v.location === 'match' && v.trustworthy === true,
    `valid=${v.valid} location=${v.location} trustworthy=${v.trustworthy} reason=${v.reason}`);

  const nonce = 'f3a1c9' + Date.now().toString(36);
  const ch = await fetch(`${origin}${CHALLENGE_PATH}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nonce }),
  });
  t('answers a challenge over HTTP', ch.status === 200);
  const proof = await ch.json();
  t('live proof verifies against the declared key',
    await verifyAgentChallenge(publicKey, ID, nonce, proof.signature) === true);

  const other = await fetch(`${origin}/api/orders`);
  t('passes other routes to the app', other.status === 200 && (await other.text()) === 'app route reached');

  const preflight = await fetch(`${origin}${CHALLENGE_PATH}`, { method: 'OPTIONS' });
  t('answers CORS preflight', preflight.status === 204);

  const head = await fetch(`${origin}${DECLARATION_PATH}`, { method: 'HEAD' });
  t('supports HEAD', head.status === 200);
} finally {
  await new Promise((resolve) => server.close(resolve));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
