import {
  createPrivateKey,
  sign as signBytes,
  type KeyObject,
} from "node:crypto";
import { assertFixtureAuthority, type EvidenceMode } from "../core/evidence-mode.ts";

const ED25519_PKCS8_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const FIXTURE_SIGNERS = new WeakSet<object>();

export interface ArtifactSigner {
  readonly algorithm: "ed25519";
  readonly signer: string;
  sign(payload: Uint8Array, context: FixtureSigningContext): string;
}

export interface FixtureSignerOptions {
  readonly deploymentMode: EvidenceMode;
  readonly authorityMode: EvidenceMode;
}

export interface FixtureSigningContext {
  readonly deploymentMode: EvidenceMode;
  readonly requestMode: EvidenceMode;
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
  FIXTURE_SIGNERS.add(artifactSigner);
  return Object.freeze(artifactSigner);
}

export function assertFixtureSigningAuthority(
  signer: ArtifactSigner,
  context: FixtureSigningContext,
): void {
  if ((typeof signer !== "object" && typeof signer !== "function") || signer === null
    || !FIXTURE_SIGNERS.has(signer)) {
    throw new TypeError("Artifact signer is not a fixture-authority capability");
  }
  if (context === null || typeof context !== "object") {
    throw new TypeError("Fixture signing requires an evidence-mode context");
  }
  assertFixtureSigningContext(context);
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
