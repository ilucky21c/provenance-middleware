/**
 * provenance-middleware
 *
 * One line that makes a service self-describing:
 *
 *   import { provenance } from 'provenance-middleware';
 *   app.use(provenance({ declaration: './PROVENANCE.yml' }));
 *
 * From then on the service serves its own signed declaration, proves on demand
 * that it holds the declared key, and reports which version is running. Nobody
 * has to remember to re-sign a file or keep a copy in a repository up to date —
 * the running service is the publication point.
 *
 * Three things it does NOT do, on purpose:
 *
 *   - It never sends the private key anywhere. Signing happens in this process.
 *   - It never signs a caller-supplied value in the legacy 0.1 challenge form.
 *     That payload is indistinguishable from a revocation, so an endpoint using
 *     it would let a stranger revoke the key. Only the domain-separated form is
 *     ever signed. See provenance-protocol SPEC.md § Signing and Verification.
 *   - It does not report anything about your traffic, users or requests. The
 *     only thing it sends anywhere is your public declaration and version.
 */

import { readFile } from 'node:fs/promises';
import { parse as parseYaml } from 'yaml';
import { signDeclaration, signAgentChallenge } from 'provenance-protocol/keygen';

/** Where a declaration is served from. Same shape as robots.txt: a fixed path. */
export const DECLARATION_PATH = '/.well-known/provenance.json';
/** Where key-control challenges are answered. */
export const CHALLENGE_PATH = '/.well-known/provenance/challenge';

const MAX_NONCE_LENGTH = 256;
const NONCE_PATTERN = /^[A-Za-z0-9._~:-]+$/;

export class ProvenanceMiddlewareError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ProvenanceMiddlewareError';
  }
}

function requirePrivateKey(privateKey) {
  const key = privateKey ?? process.env.PROVENANCE_PRIVATE_KEY;
  if (!key) {
    throw new ProvenanceMiddlewareError(
      'No private key. Set PROVENANCE_PRIVATE_KEY (base64 PKCS8 DER, from `npx provenance-protocol keygen`) ' +
        'or pass privateKey. Generate it on your own machine — it must never reach a third party.'
    );
  }
  return key;
}

/**
 * Read a declaration from a file path, a string, or an already-parsed object.
 * YAML and JSON both work; the signature covers the parsed value, so formatting
 * and comments are irrelevant to it.
 */
async function loadDeclaration(declaration) {
  if (declaration === null || declaration === undefined) {
    throw new ProvenanceMiddlewareError('declaration is required (a path, a string, or a parsed object)');
  }
  if (typeof declaration === 'object') return declaration;
  if (typeof declaration !== 'string') {
    throw new ProvenanceMiddlewareError('declaration must be a path, a string, or a parsed object');
  }

  // A path if it looks like one; otherwise treat the string as the document.
  const looksLikePath = !declaration.includes('\n') && /\.(ya?ml|json)$/i.test(declaration.trim());
  const text = looksLikePath ? await readFile(declaration, 'utf8') : declaration;

  try {
    return parseYaml(text);
  } catch (e) {
    throw new ProvenanceMiddlewareError(`Declaration could not be parsed: ${e.message}`);
  }
}

/**
 * Prepare the signed declaration this service will serve.
 *
 * Signing happens here, at startup, rather than being something a developer
 * does by hand — which is the whole point. Edit the declaration, restart, and
 * the signature matches. There is no state in which the file says one thing and
 * the signature covers another.
 *
 * @param {object} options
 * @param {string|object} options.declaration  Path, document text, or parsed object
 * @param {string} [options.privateKey]        Defaults to PROVENANCE_PRIVATE_KEY
 * @param {string} [options.version]           Overrides the declaration's version
 * @returns {Promise<{ declaration: object, provenanceId: string, publicKey: string, json: string }>}
 */
export async function prepare({ declaration, privateKey, version } = {}) {
  const key = requirePrivateKey(privateKey);
  const parsed = await loadDeclaration(declaration);

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new ProvenanceMiddlewareError('Declaration must be a mapping');
  }

  const provenanceId = parsed.provenance_id;
  if (typeof provenanceId !== 'string' || provenanceId.length === 0) {
    throw new ProvenanceMiddlewareError(
      'Declaration needs provenance_id — it is what a verifier checks the retrieval location against'
    );
  }

  const identity = parsed.identity;
  const publicKey = identity && typeof identity === 'object' ? identity.public_key : undefined;
  if (typeof publicKey !== 'string' || publicKey.length === 0) {
    throw new ProvenanceMiddlewareError(
      'Declaration needs identity.public_key — the public half of the key this service signs with'
    );
  }

  // Spec 0.2 signs the whole declaration, so anything served must say 0.2.
  // Refuse to silently upgrade a file that claims 0.1: the author should know
  // their signature is about to cover every field rather than just the identity.
  if (parsed.provenance !== undefined && parsed.provenance !== '0.2') {
    throw new ProvenanceMiddlewareError(
      `Declaration says provenance: "${parsed.provenance}". This middleware signs the whole declaration ` +
        '(spec 0.2). Set provenance: "0.2" — under 0.1 the signature would not cover your declared ' +
        'capabilities or constraints.'
    );
  }

  const body = { ...parsed, provenance: '0.2' };
  if (version) body.version = version;
  // The signature cannot cover itself, and a stale one must never be served.
  body.identity = { ...identity };
  delete body.identity.signature;
  body.identity.signature = signDeclaration(key, body);

  // A repo-shaped identifier on a service that serves its own declaration means
  // verifiers will report the retrieval location as 'unchecked', so nobody can
  // conclude the declaration is genuinely the operator's. Say so once, at
  // startup, rather than letting every vendor discover it from a silent
  // trustworthy: false.
  if (!provenanceId.startsWith('provenance:domain:')) {
    warn(
      `provenance_id is "${provenanceId}". Served from this service, a verifier cannot confirm that ` +
        'location, so it will report trustworthy: false. Either use provenance:domain:<your-hostname> ' +
        'or also publish this declaration at the location the id names.'
    );
  }

  return {
    declaration: body,
    provenanceId,
    publicKey,
    json: `${JSON.stringify(body, null, 2)}\n`,
  };
}

/** Warnings go to stderr once and never throw — a log must not take a service down. */
function warn(message) {
  try {
    process.emitWarning(message, 'ProvenanceWarning');
  } catch {
    /* ignore */
  }
}

function json(status, value, extraHeaders = {}) {
  return new Response(`${JSON.stringify(value, null, 2)}\n`, {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extraHeaders,
    },
  });
}

/**
 * The framework-agnostic core: a handler over web-standard Request/Response.
 *
 * Returns a Response for the two paths it owns and `null` for everything else,
 * so it composes with any router — Next.js route handlers, Hono, Fastify,
 * Cloudflare Workers, Deno.
 *
 * @param {object} options  Same as `prepare`, plus:
 * @param {string} [options.declarationPath]  Defaults to /.well-known/provenance.json
 * @param {string} [options.challengePath]    Defaults to /.well-known/provenance/challenge
 * @returns {Promise<(request: Request) => Promise<Response|null>>}
 */
export async function handler(options = {}) {
  const {
    declarationPath = DECLARATION_PATH,
    challengePath = CHALLENGE_PATH,
    privateKey,
  } = options;

  const prepared = await prepare(options);
  const key = requirePrivateKey(privateKey);

  return async function provenanceHandler(request) {
    const { pathname } = new URL(request.url);

    if (pathname === declarationPath) {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return json(405, { error: 'Method not allowed' }, { Allow: 'GET, HEAD' });
      }
      return new Response(request.method === 'HEAD' ? null : prepared.json, {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          // Anyone may verify a declaration, including from a browser page.
          'Access-Control-Allow-Origin': '*',
          // Short: a declaration changes when the service is redeployed, and a
          // verifier that caches a withdrawn one for a day is worse than one
          // that asks again.
          'Cache-Control': 'public, max-age=300',
        },
      });
    }

    if (pathname === challengePath) {
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
          },
        });
      }
      if (request.method !== 'POST') {
        return json(405, { error: 'Method not allowed' }, { Allow: 'POST, OPTIONS' });
      }

      let nonce;
      try {
        const body = await request.json();
        nonce = body?.nonce;
      } catch {
        return json(400, { error: 'Body must be JSON: { "nonce": "..." }' });
      }

      // The signed payload is domain-separated, so no nonce can be turned into
      // a revocation or a declaration signature. These limits are belt and
      // braces: a bounded, predictable character set keeps the signed string
      // free of surprises and keeps the endpoint cheap to serve.
      if (typeof nonce !== 'string' || nonce.length === 0) {
        return json(400, { error: 'nonce is required' });
      }
      if (nonce.length > MAX_NONCE_LENGTH) {
        return json(400, { error: `nonce must be at most ${MAX_NONCE_LENGTH} characters` });
      }
      if (!NONCE_PATTERN.test(nonce)) {
        return json(400, { error: 'nonce must be unreserved URL characters only (A-Z a-z 0-9 . _ ~ : -)' });
      }

      return json(
        200,
        {
          provenance_id: prepared.provenanceId,
          public_key: prepared.publicKey,
          algorithm: 'ed25519',
          nonce,
          // Verify with verifyAgentChallenge() from provenance-protocol/verify.
          signature: signAgentChallenge(key, prepared.provenanceId, nonce),
          payload_domain: 'provenance-challenge-v1',
        },
        { 'Access-Control-Allow-Origin': '*' }
      );
    }

    return null;
  };
}

/**
 * Express / Connect middleware.
 *
 *   app.use(provenance({ declaration: './PROVENANCE.yml' }));
 *
 * Mounting is asynchronous underneath — the declaration has to be read and
 * signed — so requests arriving before that finishes wait rather than 404. If
 * preparation fails, every request to these paths reports why instead of
 * quietly serving nothing: a service that silently stops publishing its
 * declaration looks identical to one that never had it.
 *
 * @param {object} options  Same as `handler`
 * @returns {(req, res, next) => void}
 */
export function provenance(options = {}) {
  const ready = handler(options).then(
    (fn) => ({ fn, error: null }),
    (error) => ({ fn: null, error })
  );

  const paths = new Set([
    options.declarationPath ?? DECLARATION_PATH,
    options.challengePath ?? CHALLENGE_PATH,
  ]);

  return function provenanceMiddleware(req, res, next) {
    const pathname = (req.originalUrl ?? req.url ?? '').split('?')[0];
    if (!paths.has(pathname)) return next();

    ready
      .then(async ({ fn, error }) => {
        if (error) {
          res.statusCode = 500;
          res.setHeader('Content-Type', 'application/json; charset=utf-8');
          res.end(`${JSON.stringify({ error: 'Provenance declaration unavailable', reason: error.message }, null, 2)}\n`);
          return;
        }

        const host = req.headers?.host ?? 'localhost';
        const scheme = req.headers?.['x-forwarded-proto'] ?? (req.socket?.encrypted ? 'https' : 'http');
        const request = new Request(`${scheme}://${host}${pathname}`, {
          method: req.method,
          headers: new Headers(req.headers ?? {}),
          body: ['GET', 'HEAD'].includes(req.method) ? undefined : await readBody(req),
          duplex: 'half',
        });

        const response = await fn(request);
        if (!response) return next();

        res.statusCode = response.status;
        response.headers.forEach((value, name) => res.setHeader(name, value));
        res.end(response.body ? Buffer.from(await response.arrayBuffer()) : undefined);
      })
      .catch(next);
  };
}

function readBody(req) {
  if (req.body !== undefined) {
    return typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      // A challenge body is a short nonce. Nothing legitimate is large.
      if (size > 8192) {
        reject(new ProvenanceMiddlewareError('Request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
