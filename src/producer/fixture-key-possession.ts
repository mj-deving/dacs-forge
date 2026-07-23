import { canonicalize, deepFreezeJson, withoutFields } from "../protocol/canonical-json.ts";
import { canonicalizeClaimReference } from "../protocol/claim-reference.ts";
import {
  encodeComponentSignatureValue,
  importLegacyComponentSignatureValue,
} from "../protocol/component-signature-codec.ts";
import { sha256Hex } from "../protocol/hash.ts";
import { encodeCf4Segment } from "../protocol/logical-address.ts";
import {
  assertFixtureSigningAuthority,
  type ArtifactSigner,
  type FixtureSigningContext,
} from "./fixture-ed25519.ts";

export const FIXTURE_KEY_POSSESSION_DOMAIN = "dacs-x-fixture-key-possession:v1:";

export interface FixtureKeyPossessionInput {
  readonly bundleHash: string;
  readonly evaluatedParty: string;
  readonly jobId: string;
  readonly observedAt: number;
}

export interface SignedFixtureKeyPossession {
  readonly assertion: Readonly<Record<string, unknown>>;
  readonly canonicalJson: string;
  readonly contentHash: string;
  readonly logicalAddress: string;
}

const HASH = /^[0-9a-f]{64}$/;
const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const INPUT_FIELDS = new Set(["bundleHash", "evaluatedParty", "jobId", "observedAt"]);

export function fixtureKeyPossessionLogicalAddress(jobId: string, evaluatedParty: string): string {
  if (!ULID.test(jobId)) throw new TypeError("Fixture key-possession jobId must be a canonical ULID");
  const party = canonicalizeClaimReference(evaluatedParty).canonicalReference;
  if (party !== evaluatedParty) throw new TypeError("Fixture key-possession party must be canonical");
  return `dacs-x:fixture-key-possession:${jobId}:${encodeCf4Segment(party)}`;
}

export function signFixtureKeyPossession(
  input: FixtureKeyPossessionInput,
  signer: ArtifactSigner,
  context: FixtureSigningContext,
): SignedFixtureKeyPossession {
  assertFixtureSigningAuthority(signer, context);
  if (Object.keys(input).some((key) => !INPUT_FIELDS.has(key))
    || input.evaluatedParty !== signer.signer || !HASH.test(input.bundleHash)
    || !Number.isSafeInteger(input.observedAt) || input.observedAt < 0) {
    throw new TypeError("Fixture key-possession binding is invalid");
  }
  const logicalAddress = fixtureKeyPossessionLogicalAddress(input.jobId, input.evaluatedParty);
  const unsigned = {
    assertionVersion: "1",
    method: "self-signed",
    jobId: input.jobId,
    evaluatedParty: input.evaluatedParty,
    bundleHash: input.bundleHash,
    possessionVerified: true,
    observedAt: input.observedAt,
    evidenceMode: "fixture",
  };
  const semanticHash = sha256Hex(canonicalize(withoutFields(unsigned, "signature")));
  const signature = encodeComponentSignatureValue(importLegacyComponentSignatureValue(
    signer.sign(new TextEncoder().encode(`${FIXTURE_KEY_POSSESSION_DOMAIN}${semanticHash}`), context),
    "standard-base64-padded",
    64,
  ));
  const assertion = deepFreezeJson({
    ...unsigned,
    signature: { algorithm: "ed25519", signer: signer.signer, value: signature },
  }) as Readonly<Record<string, unknown>>;
  const canonicalJson = canonicalize(assertion);
  return Object.freeze({ assertion, canonicalJson, contentHash: sha256Hex(canonicalJson), logicalAddress });
}
