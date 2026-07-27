import { canonicalize, withoutFields } from "../protocol/canonical-json.ts";
import { sha256Hex } from "../protocol/hash.ts";
import { verifyCanonicalListingJson } from "../consumer/listing-verifier.ts";
import type { ListingVersionRecord } from "../substrate/sqlite/listing-store.ts";

const MAX_FIELD_LENGTH = 4_096;

export interface RegistrationOperatorScope {
  readonly instanceId: string;
  readonly audience: string;
  readonly principal: string;
  readonly operation: "directory:register";
  readonly expiresAtMs: number;
}

export interface RegistrationAdapter {
  readonly executionMode: "fixture-no-spend";
  readonly authorizeOperator: (input: Readonly<{
    readonly capability: string;
    readonly scope: RegistrationOperatorScope;
  }>) => boolean;
  readonly readAnchor: (input: Readonly<{
    readonly nativeAddress: string;
  }>) =>
    | Readonly<{ readonly disposition: "verified"; readonly canonicalJson: string;
      readonly contentHash: string; readonly anchorTx: string }>
    | Readonly<{ readonly disposition: "absent" | "indeterminate" }>;
  readonly register: (input: Readonly<{ readonly listing: ListingVersionRecord }>) => Readonly<{
    readonly disposition: "submitted";
    readonly registrationId: string;
  }>;
  readonly readRegistration: (input: Readonly<{ readonly registrationId: string }>) =>
    | Readonly<{ readonly disposition: "registered"; readonly listingId: string;
      readonly listingVersion: number; readonly contentHash: string;
      readonly nativeAddress: string }>
    | Readonly<{ readonly disposition: "absent" | "indeterminate" }>;
}

export interface RegistrationCommandInput {
  readonly operatorCapability: string;
  readonly operatorScope: RegistrationOperatorScope;
  readonly listing: ListingVersionRecord;
}

export interface RegistrationReceipt {
  readonly schema: "dacs-directory-registration/v1";
  readonly registrationId: string;
  readonly listingId: string;
  readonly listingVersion: number;
  readonly contentHash: string;
  readonly nativeAddress: string;
}

export function executeRegistrationCommand(
  input: RegistrationCommandInput,
  adapter: RegistrationAdapter,
): RegistrationReceipt {
  const snapshot = normalizeInput(input);
  if (adapter?.executionMode !== "fixture-no-spend") {
    throw new Error("Directory registration requires a fixture/no-spend adapter");
  }
  if (!hasCurrentOperatorAuthority(snapshot, adapter)) {
    throw new Error("Directory registration requires current operator authority");
  }

  const anchor = snapshotAnchor(adapter.readAnchor(Object.freeze({
    nativeAddress: snapshot.listing.nativeAddress,
  })));
  if (anchor.disposition !== "verified"
    || anchor.canonicalJson !== snapshot.listing.canonicalJson
    || anchor.anchorTx !== snapshot.listing.anchorTx
    || sha256Hex(anchor.canonicalJson) !== anchor.contentHash) {
    throw new Error("Directory registration requires exact independent anchor read-back");
  }

  if (!hasCurrentOperatorAuthority(snapshot, adapter)) {
    throw new Error("Directory registration requires current operator authority at submission");
  }

  const submitted = snapshotSubmission(adapter.register(Object.freeze({ listing: snapshot.listing })));
  const observed = snapshotRegistration(adapter.readRegistration(Object.freeze({
    registrationId: submitted.registrationId,
  })));
  if (observed.disposition !== "registered"
    || observed.listingId !== snapshot.listing.listingId
    || observed.listingVersion !== snapshot.listing.listingVersion
    || observed.contentHash !== snapshot.listing.contentHash
    || observed.nativeAddress !== snapshot.listing.nativeAddress) {
    throw new Error("Directory registration read-back did not confirm the submitted Listing");
  }
  return Object.freeze({
    schema: "dacs-directory-registration/v1",
    registrationId: submitted.registrationId,
    listingId: observed.listingId,
    listingVersion: observed.listingVersion,
    contentHash: observed.contentHash,
    nativeAddress: observed.nativeAddress,
  });
}

function normalizeInput(input: RegistrationCommandInput): Readonly<RegistrationCommandInput> {
  const scope = input?.operatorScope;
  if (scope?.operation !== "directory:register") {
    throw new TypeError("Registration operator scope must allow directory:register");
  }
  const listing = input.listing;
  const canonicalJson = field("listing.canonicalJson", listing?.canonicalJson);
  const contentHash = lowerHex64("listing.contentHash", listing?.contentHash);
  const version = listing?.listingVersion;
  const anchorVerifiedAt = listing?.anchorVerifiedAt;
  if (!Number.isSafeInteger(version) || version < 1
    || !Number.isSafeInteger(anchorVerifiedAt) || anchorVerifiedAt < 0) {
    throw new TypeError("Registration Listing version or anchor time is invalid");
  }
  const verification = verifyCanonicalListingJson(canonicalJson, {
    nowMs: anchorVerifiedAt,
    revocationCheck: () => "absent",
    paymentRailCheck: () => ({ status: "resolved", phaseHandler: "fixture" }),
  });
  if (verification.disposition !== "accepted"
    || verification.listingId !== listing.listingId
    || verification.listingVersion !== version
    || verification.contentHash !== contentHash) {
    const reason = verification.disposition === "accepted"
      ? "Listing identity does not match verified bytes"
      : `${verification.stage}: ${verification.reason}`;
    throw new TypeError(`Registration Listing verification failed: ${reason}`);
  }
  try {
    const parsed = JSON.parse(canonicalJson) as unknown;
    if (canonicalize(parsed) !== canonicalJson || parsed === null || typeof parsed !== "object"
      || Array.isArray(parsed)) throw new Error();
    const document = parsed as Record<string, unknown>;
    const seller = document["seller"];
    const identity = seller !== null && typeof seller === "object" && !Array.isArray(seller)
      ? (seller as Record<string, unknown>)["identity"] : null;
    const presentedBy = identity !== null && typeof identity === "object" && !Array.isArray(identity)
      ? (identity as Record<string, unknown>)["presentedBy"] : undefined;
    if (document["listingId"] !== listing.listingId
      || document["listingVersion"] !== listing.listingVersion
      || presentedBy !== listing.sellerPrimaryClaim
      || sha256Hex(canonicalize(withoutFields(document, "signature"))) !== contentHash
      || listing.logicalAddress !== `dacs1:${encodeURIComponent(listing.sellerPrimaryClaim)}:${listing.listingId}:v${listing.listingVersion}`) {
      throw new Error();
    }
  } catch {
    throw new TypeError("Registration Listing canonical bytes do not match its identity bindings");
  }
  return Object.freeze({
    operatorCapability: lowerHex64("operatorCapability", input.operatorCapability),
    operatorScope: Object.freeze({
      instanceId: field("operatorScope.instanceId", scope.instanceId),
      audience: field("operatorScope.audience", scope.audience),
      principal: field("operatorScope.principal", scope.principal),
      operation: "directory:register" as const,
      expiresAtMs: timestamp("operatorScope.expiresAtMs", scope.expiresAtMs),
    }),
    listing: Object.freeze({
      sellerPrimaryClaim: field("listing.sellerPrimaryClaim", listing.sellerPrimaryClaim),
      listingId: field("listing.listingId", listing.listingId),
      listingVersion: version,
      contentHash,
      canonicalJson,
      logicalAddress: field("listing.logicalAddress", listing.logicalAddress),
      nativeAddress: field("listing.nativeAddress", listing.nativeAddress),
      anchorTx: field("listing.anchorTx", listing.anchorTx),
      anchorVerifiedAt,
      createdAt: field("listing.createdAt", listing.createdAt),
    }),
  });
}

function snapshotAnchor(value: ReturnType<RegistrationAdapter["readAnchor"]>): ReturnType<RegistrationAdapter["readAnchor"]> {
  if (value?.disposition === "absent" || value?.disposition === "indeterminate") {
    return Object.freeze({ disposition: value.disposition });
  }
  if (value?.disposition !== "verified") return Object.freeze({ disposition: "indeterminate" });
  return Object.freeze({
    disposition: "verified",
    canonicalJson: field("anchor.canonicalJson", value.canonicalJson),
    contentHash: lowerHex64("anchor.contentHash", value.contentHash),
    anchorTx: field("anchor.anchorTx", value.anchorTx),
  });
}

function snapshotSubmission(value: ReturnType<RegistrationAdapter["register"]>): Readonly<{
  readonly disposition: "submitted"; readonly registrationId: string;
}> {
  if (value?.disposition !== "submitted") throw new Error("Directory registration submission failed");
  return Object.freeze({ disposition: "submitted", registrationId: field("registrationId", value.registrationId) });
}

function snapshotRegistration(value: ReturnType<RegistrationAdapter["readRegistration"]>): ReturnType<RegistrationAdapter["readRegistration"]> {
  if (value?.disposition === "absent" || value?.disposition === "indeterminate") {
    return Object.freeze({ disposition: value.disposition });
  }
  if (value?.disposition !== "registered") return Object.freeze({ disposition: "indeterminate" });
  if (!Number.isSafeInteger(value.listingVersion) || value.listingVersion < 1) {
    return Object.freeze({ disposition: "indeterminate" });
  }
  return Object.freeze({
    disposition: "registered",
    listingId: field("registered.listingId", value.listingId),
    listingVersion: value.listingVersion,
    contentHash: lowerHex64("registered.contentHash", value.contentHash),
    nativeAddress: field("registered.nativeAddress", value.nativeAddress),
  });
}

function field(name: string, value: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_FIELD_LENGTH
    || value !== value.normalize("NFC")) throw new TypeError(`${name} is invalid`);
  return value;
}

function lowerHex64(name: string, value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new TypeError(`${name} is invalid`);
  return value;
}

function timestamp(name: string, value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${name} is invalid`);
  return value;
}

function safeNow(): number {
  let value: number;
  try { value = Date.now(); } catch { throw new Error("Registration clock failed"); }
  return timestamp("registration clock", value);
}

function hasCurrentOperatorAuthority(
  input: Readonly<RegistrationCommandInput>,
  adapter: RegistrationAdapter,
): boolean {
  if (input.operatorScope.expiresAtMs <= safeNow()) return false;
  const authorized = adapter.authorizeOperator(Object.freeze({
    capability: input.operatorCapability,
    scope: input.operatorScope,
  })) === true;
  return authorized && input.operatorScope.expiresAtMs > safeNow();
}
