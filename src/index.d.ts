/**
 * provenance-middleware — TypeScript definitions
 *
 * Makes a service self-describing: serves its own signed declaration, proves it
 * holds the declared key, and reports which version is running.
 */

/** Where the declaration is served from. */
export const DECLARATION_PATH: '/.well-known/provenance.json';
/** Where key-control challenges are answered. */
export const CHALLENGE_PATH: '/.well-known/provenance/challenge';

export class ProvenanceMiddlewareError extends Error {
  name: 'ProvenanceMiddlewareError';
}

export interface ProvenanceOptions {
  /**
   * The declaration: a path to a .yml/.yaml/.json file, the document as a
   * string, or an already-parsed object. It must declare `provenance: "0.2"`,
   * a `provenance_id`, and `identity.public_key`.
   */
  declaration: string | object;
  /**
   * Base64 PKCS8 DER private key. Defaults to `PROVENANCE_PRIVATE_KEY`.
   * Generate it on your own machine; it is used in this process and never sent
   * anywhere.
   */
  privateKey?: string;
  /** Overrides the declaration's `version` — useful for a build identifier. */
  version?: string;
  /** Defaults to `/.well-known/provenance.json`. */
  declarationPath?: string;
  /** Defaults to `/.well-known/provenance/challenge`. */
  challengePath?: string;
}

export interface PreparedDeclaration {
  /** The declaration as served, with a freshly computed signature. */
  declaration: object;
  provenanceId: string;
  publicKey: string;
  /** The serialised body served at the declaration path. */
  json: string;
}

/**
 * Read and sign the declaration without mounting anything.
 *
 * Signing happens at load, so there is no state in which the file says one
 * thing and the signature covers another.
 */
export function prepare(options: ProvenanceOptions): Promise<PreparedDeclaration>;

/**
 * Framework-agnostic handler over web-standard Request/Response.
 *
 * Returns a Response for the two paths it owns and `null` for anything else, so
 * it composes with any router — Next.js route handlers, Hono, Fastify, Workers,
 * Deno.
 */
export function handler(
  options: ProvenanceOptions
): Promise<(request: Request) => Promise<Response | null>>;

/**
 * Express / Connect middleware.
 *
 * ```js
 * app.use(provenance({ declaration: './PROVENANCE.yml' }));
 * ```
 */
export function provenance(
  options: ProvenanceOptions
): (req: unknown, res: unknown, next: (err?: unknown) => void) => void;
