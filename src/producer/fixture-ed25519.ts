import {
  createPrivateKey,
  sign as signBytes,
  type KeyObject,
} from "node:crypto";
import { assertFixtureAuthority, type EvidenceMode } from "../core/evidence-mode.ts";

const ED25519_PKCS8_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
type SigningAuthority = Readonly<{
  readonly kind: "fixture";
  readonly deploymentMode: "fixture";
}> | Readonly<{
  readonly kind: "production";
  readonly deploymentMode: Exclude<EvidenceMode, "fixture">;
  readonly retainListing: (keyClaim: string, binding: SignedListingKeyBinding) => void;
  readonly signCurrent: (keyClaim: string, payload: Uint8Array) => Uint8Array;
}>;

const SIGNING_AUTHORITIES = new WeakMap<object, SigningAuthority>();
const FIXTURE_SIGNER_CLAIMS = new Set<string>([
  "key:65d31f88c2bc3a02b1af294824d1e1150942d7399398a628ff24d285c70b2ee9",
  "key:4e027c3f626240679d58dbd688591dc8572ceb9d6969966e87d1185b2cbee5e7",
  "key:5e11242fb2821416b73078217b831e4d66acbb13a64672948c0297c9779aa2ad",
  "key:cb5eeb76472f655992ddb3515ee52a2143be7c86e8a162080fdf1afdaf4fff6e",
]);

export interface ArtifactSigner {
  readonly algorithm: "ed25519";
  readonly signer: string;
  sign(payload: Uint8Array, context: SigningContext): string;
}

export interface FixtureSignerOptions {
  readonly deploymentMode: EvidenceMode;
  readonly authorityMode: EvidenceMode;
}

export interface SigningContext {
  readonly deploymentMode: EvidenceMode;
  readonly requestMode: EvidenceMode;
}

export type FixtureSigningContext = SigningContext;

export interface NonExportingEd25519Provider {
  readonly providerId: string;
  publicKey(keyHandle: string): Uint8Array;
  sign(keyHandle: string, payload: Uint8Array): Uint8Array;
}

export interface ProviderBackedSignerOptions {
  readonly deploymentMode: Exclude<EvidenceMode, "fixture">;
  readonly keyHandle: string;
  readonly provider: NonExportingEd25519Provider;
}

export interface SignedListingKeyBinding {
  readonly contentHash: string;
  readonly listingId: string;
  readonly listingVersion: number;
}

interface LifecycleBoundSignerOptions extends ProviderBackedSignerOptions {
  readonly retainListing: (keyClaim: string, binding: SignedListingKeyBinding) => void;
  readonly signCurrent: (keyClaim: string, payload: Uint8Array) => Uint8Array;
}

export function createFixtureEd25519Signer(
  seed: Uint8Array,
  options: FixtureSignerOptions,
): ArtifactSigner {
  assertFixtureAuthority(options.deploymentMode, options.authorityMode);
  if (seed.byteLength !== 32) throw new TypeError("Ed25519 fixture seed must be exactly 32 bytes");
  const privateKey = fixturePrivateKey(Uint8Array.from(seed));
  const publicJwk = privateKey.export({ format: "jwk" });
  if (typeof publicJwk.x !== "string") {
    throw new Error("Ed25519 public-key export has an unexpected shape");
  }
  const publicKey = Buffer.from(publicJwk.x, "base64url");
  if (publicKey.byteLength !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  const signer = `key:${publicKey.toString("hex")}`;

  const artifactSigner: ArtifactSigner = {
    algorithm: "ed25519" as const,
    signer,
    sign(payload: Uint8Array, context: FixtureSigningContext): string {
      assertFixtureSigningContext(context);
      const signature = signBytes(null, Buffer.from(payload), privateKey);
      if (signature.byteLength !== 64) throw new Error("Ed25519 signer returned an invalid length");
      return signature.toString("base64");
    },
  };
  SIGNING_AUTHORITIES.set(artifactSigner, Object.freeze({
    kind: "fixture",
    deploymentMode: "fixture",
  }));
  FIXTURE_SIGNER_CLAIMS.add(signer);
  return Object.freeze(artifactSigner);
}

export function resolveProviderBackedEd25519Claim(
  options: ProviderBackedSignerOptions,
): string {
  return providerBinding(options).signer;
}

export function createLifecycleBoundEd25519Signer(
  options: LifecycleBoundSignerOptions,
): ArtifactSigner {
  assertExactKeys(options, [
    "deploymentMode", "keyHandle", "provider", "retainListing", "signCurrent",
  ]);
  if (typeof options.signCurrent !== "function" || typeof options.retainListing !== "function") {
    throw new TypeError("Lifecycle-bound signer requires currentness and Listing-retention hooks");
  }
  const binding = providerBinding(options);
  const signer = binding.signer;

  const artifactSigner: ArtifactSigner = {
    algorithm: "ed25519",
    signer,
    sign(payload: Uint8Array, context: SigningContext): string {
      assertArtifactSigningAuthority(artifactSigner, context);
      const signature = Uint8Array.from(options.signCurrent(signer, Uint8Array.from(payload)));
      if (signature.byteLength !== 64) {
        throw new Error("Provider Ed25519 signer returned an invalid length");
      }
      return Buffer.from(signature).toString("base64");
    },
  };
  SIGNING_AUTHORITIES.set(artifactSigner, Object.freeze({
    kind: "production",
    deploymentMode: binding.deploymentMode,
    retainListing: options.retainListing,
    signCurrent: options.signCurrent,
  }));
  return Object.freeze(artifactSigner);
}

export function retainSignedListing(
  signer: ArtifactSigner,
  binding: SignedListingKeyBinding,
): void {
  const authority = signingAuthority(signer);
  if (authority?.kind === "production") {
    authority.retainListing(signer.signer, Object.freeze({ ...binding }));
  }
}

function providerBinding(options: ProviderBackedSignerOptions): Readonly<{
  readonly deploymentMode: Exclude<EvidenceMode, "fixture">;
  readonly keyHandle: string;
  readonly provider: NonExportingEd25519Provider;
  readonly signer: string;
}> {
  if (options.deploymentMode !== "local-chain" && options.deploymentMode !== "live") {
    throw new TypeError("Provider-backed signer requires local-chain or live deployment");
  }
  validateBoundedText(options.keyHandle, "Provider key handle");
  if (options.provider === null || typeof options.provider !== "object"
    || typeof options.provider.publicKey !== "function"
    || typeof options.provider.sign !== "function") {
    throw new TypeError("Provider-backed signer requires a non-exporting provider interface");
  }
  validateBoundedText(options.provider.providerId, "Provider id");
  const publicKey = Uint8Array.from(options.provider.publicKey(options.keyHandle));
  if (publicKey.byteLength !== 32) throw new TypeError("Provider Ed25519 public key must be 32 bytes");
  const signer = `key:${Buffer.from(publicKey).toString("hex")}`;
  if (FIXTURE_SIGNER_CLAIMS.has(signer)) {
    throw new TypeError("Production signer resolves to a recognized fixture key fingerprint");
  }
  return Object.freeze({
    deploymentMode: options.deploymentMode,
    keyHandle: options.keyHandle,
    provider: options.provider,
    signer,
  });
}

export function assertFixtureSigningAuthority(
  signer: ArtifactSigner,
  context: FixtureSigningContext,
): void {
  const authority = signingAuthority(signer);
  if (authority?.kind !== "fixture") {
    throw new TypeError("Artifact signer is not a fixture-authority capability");
  }
  if (context === null || typeof context !== "object") {
    throw new TypeError("Fixture signing requires an evidence-mode context");
  }
  assertFixtureSigningContext(context);
}

export function assertArtifactSigningAuthority(
  signer: ArtifactSigner,
  context: SigningContext,
): void {
  const authority = signingAuthority(signer);
  if (authority === undefined) {
    if (context !== null && typeof context === "object"
      && context.deploymentMode === "fixture" && context.requestMode === "fixture") {
      throw new TypeError("Artifact signer is not a fixture-authority capability");
    }
    throw new TypeError("Artifact signer is not an authenticated signing capability");
  }
  if (authority.kind === "fixture") {
    assertFixtureSigningContext(context);
    return;
  }
  if (context === null || typeof context !== "object"
    || context.deploymentMode !== authority.deploymentMode
    || context.requestMode !== authority.deploymentMode) {
    throw new TypeError("Production signing authority does not match deployment and request mode");
  }
  if (FIXTURE_SIGNER_CLAIMS.has(signer.signer)) {
    throw new TypeError("Production signer uses a recognized fixture key fingerprint");
  }
}

export function isRecognizedFixtureSignerClaim(claim: string): boolean {
  return FIXTURE_SIGNER_CLAIMS.has(claim);
}

function assertFixtureSigningContext(context: FixtureSigningContext): void {
  if (context === null || typeof context !== "object") {
    throw new TypeError("Fixture signing requires an evidence-mode context");
  }
  assertFixtureAuthority(context.deploymentMode, context.requestMode);
}

function fixturePrivateKey(seed: Uint8Array): KeyObject {
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_SEED_PREFIX, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
}

function signingAuthority(signer: ArtifactSigner): SigningAuthority | undefined {
  if ((typeof signer !== "object" && typeof signer !== "function") || signer === null) {
    return undefined;
  }
  return SIGNING_AUTHORITIES.get(signer);
}

function assertExactKeys(value: object, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.length !== canonical.length || actual.some((key, index) => key !== canonical[index])) {
    throw new TypeError(`Provider-backed signer options require exactly ${canonical.join(", ")}`);
  }
}

function validateBoundedText(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 1_024
    || value !== value.normalize("NFC")) {
    throw new TypeError(`${label} must be bounded NFC text`);
  }
}
