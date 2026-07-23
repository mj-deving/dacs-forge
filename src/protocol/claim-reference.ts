import { domainToASCII } from "node:url";

const SCHEME = /^[A-Za-z][A-Za-z0-9-]*$/;
const RESERVED_PARAMETER_CHARACTER = /[:?&=%]/g;
const DID_IDENTIFIER = /^(?<method>[a-z0-9]+):(?<specific>(?:(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})*:)*(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+)$/;
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MAX_CLAIM_REFERENCE_LENGTH = 4_096;
const UINT256_MAX = (1n << 256n) - 1n;
const REGISTERED_SCHEMES = new Set([
  "domain", "did", "key", "erc8004", "cci-xm", "cci-ud", "cci-nomis", "cci-tlsn",
  "cci-web2", "cci-pqc", "cci-humanpassport", "cci-ethos", "lei", "finra-crd",
  "sam-uei", "naics", "fedramp", "cmmc", "stor-cred", "substrate-validator-set",
]);

export class ClaimReferenceError extends TypeError {
  override readonly name = "ClaimReferenceError";
}

export interface CanonicalClaimReference {
  readonly canonicalReference: string;
  readonly scheme: string;
  readonly identifier: string;
}

export interface GenericCanonicalClaimReference {
  readonly canonicalReference: string;
  readonly scheme: string;
  readonly identifier: string;
}

export function canonicalizeGenericClaimReference(reference: string): GenericCanonicalClaimReference {
  assertUnicodeScalarValue(reference);
  if (reference.length === 0 || reference.length > MAX_CLAIM_REFERENCE_LENGTH) {
    throw new ClaimReferenceError("ClaimReference must be non-empty bounded text");
  }
  const normalized = reference.normalize("NFC");
  const colon = normalized.indexOf(":");
  if (colon <= 0) throw new ClaimReferenceError("ClaimReference must contain scheme:identifier");
  const rawScheme = normalized.slice(0, colon);
  if (!SCHEME.test(rawScheme)) throw new ClaimReferenceError("ClaimReference scheme is invalid");
  const scheme = rawScheme.toLowerCase();
  const remainder = normalized.slice(colon + 1);
  const question = remainder.indexOf("?");
  const identifier = (question === -1 ? remainder : remainder.slice(0, question)).normalize("NFC");
  if (identifier.length === 0 || /[\u0000-\u001f\u007f]/.test(identifier)) {
    throw new ClaimReferenceError("ClaimReference identifier is invalid");
  }
  const parameters = question === -1 ? null : canonicalizeParameters(remainder.slice(question + 1));
  const canonicalReference = `${scheme}:${identifier}${parameters === null ? "" : `?${parameters}`}`;
  if (canonicalReference.length > MAX_CLAIM_REFERENCE_LENGTH) {
    throw new ClaimReferenceError("Canonical ClaimReference exceeds the length limit");
  }
  return { canonicalReference, scheme, identifier };
}

/** Parse DACS CORE CF-2 bytes and derive the parameter-free CF-3 identity. */
export function canonicalizeClaimReference(reference: string): CanonicalClaimReference {
  assertUnicodeScalarValue(reference);
  if (reference.length === 0 || reference.length > MAX_CLAIM_REFERENCE_LENGTH) {
    throw new ClaimReferenceError("ClaimReference must be non-empty bounded text");
  }
  const normalizedReference = reference.normalize("NFC");

  const colon = normalizedReference.indexOf(":");
  if (colon <= 0) throw new ClaimReferenceError("ClaimReference must contain scheme:identifier");

  const rawScheme = normalizedReference.slice(0, colon);
  if (!SCHEME.test(rawScheme)) throw new ClaimReferenceError("ClaimReference scheme is invalid");
  const scheme = rawScheme.toLowerCase();

  const remainder = normalizedReference.slice(colon + 1);
  const question = remainder.indexOf("?");
  const rawIdentifier = question === -1 ? remainder : remainder.slice(0, question);
  if (rawIdentifier.length === 0) {
    throw new ClaimReferenceError("ClaimReference identifier must be non-empty");
  }
  const identifier = canonicalizeIdentifier(scheme, rawIdentifier);

  const rawParameters = question === -1 ? null : remainder.slice(question + 1);
  const parameters = rawParameters === null ? "" : canonicalizeParameters(rawParameters);
  const canonicalReference = `${scheme}:${identifier}${rawParameters === null ? "" : `?${parameters}`}`;
  if (canonicalReference.length > MAX_CLAIM_REFERENCE_LENGTH) {
    throw new ClaimReferenceError("Canonical ClaimReference exceeds the length limit");
  }
  return {
    canonicalReference,
    scheme,
    identifier,
  };
}

export function sameClaimIdentity(left: string, right: string): boolean {
  const leftClaim = canonicalizeClaimReference(left);
  const rightClaim = canonicalizeClaimReference(right);
  return leftClaim.scheme === rightClaim.scheme && leftClaim.identifier === rightClaim.identifier;
}

export function isRegisteredClaimScheme(scheme: string): boolean {
  return REGISTERED_SCHEMES.has(scheme.toLowerCase());
}

function canonicalizeIdentifier(scheme: string, identifier: string): string {
  const normalized = identifier.normalize("NFC");
  switch (scheme) {
    case "domain":
      return canonicalizeDomain(normalized);
    case "did":
      return canonicalizeDid(normalized);
    case "key":
      if (!/^[0-9A-Fa-f]+$/.test(normalized) || normalized.length % 2 !== 0) {
        throw new ClaimReferenceError(
          "key identifier must be byte-aligned hexadecimal without 0x",
        );
      }
      return normalized.toLowerCase();
    case "erc8004":
      return canonicalizeErc8004(normalized);
    case "cci-xm":
      return canonicalizeCciXm(normalized);
    case "cci-ud":
      return canonicalizeDomain(normalized);
    case "cci-nomis":
      return canonicalizeEvmAddress(normalized, "cci-nomis");
    case "cci-tlsn":
      return canonicalizeLowerHex(normalized, 64, "cci-tlsn proof hash");
    case "cci-web2":
      return canonicalizeWeb2(normalized);
    case "cci-pqc":
      return canonicalizePqc(normalized);
    case "cci-humanpassport":
    case "cci-ethos":
      return canonicalizeOpaque(normalized, `${scheme} identifier`);
    case "lei":
      return canonicalizeUpperAlphaNumeric(normalized, 20, `${scheme} identifier`);
    case "finra-crd":
      return canonicalizePositiveDecimal(normalized, `${scheme} identifier`);
    case "sam-uei":
      return canonicalizeUpperAlphaNumeric(normalized, 12, `${scheme} identifier`);
    case "naics":
      if (!/^[0-9]{6}$/.test(normalized)) {
        throw new ClaimReferenceError(`${scheme} identifier must contain exactly six digits`);
      }
      return normalized;
    case "fedramp":
    case "cmmc":
      return canonicalizeOpaque(normalized, `${scheme} identifier`);
    case "stor-cred":
      return canonicalizeStorCredential(normalized);
    case "substrate-validator-set":
      return canonicalizeValidatorSet(normalized);
    default:
      throw new ClaimReferenceError(`ClaimReference scheme "${scheme}" is not supported safely`);
  }
}

function canonicalizeWeb2(identifier: string): string {
  const separator = identifier.indexOf(":");
  if (separator <= 0 || separator === identifier.length - 1) {
    throw new ClaimReferenceError("cci-web2 identifier must be platform:username");
  }
  const platform = identifier.slice(0, separator).toLowerCase();
  if (!["twitter", "github", "discord", "telegram"].includes(platform)) {
    throw new ClaimReferenceError(`cci-web2 platform "${platform}" is not registered`);
  }
  const username = canonicalizeOpaque(identifier.slice(separator + 1), "cci-web2 username");
  const usernamePattern = platform === "discord"
    ? /^[A-Za-z0-9._#-]+$/
    : /^[A-Za-z0-9._-]+$/;
  if (!usernamePattern.test(username)) {
    throw new ClaimReferenceError("cci-web2 username must be provider-safe ASCII");
  }
  // Demos GCR stores and reverse-resolves provider usernames by exact bytes.
  // Stable alias binding belongs to the DACS-2 proof's provider userId.
  return `${platform}:${username}`;
}

function canonicalizePqc(identifier: string): string {
  const separator = identifier.indexOf(":");
  if (separator <= 0 || separator === identifier.length - 1) {
    throw new ClaimReferenceError("cci-pqc identifier must be algorithm:pubkey");
  }
  const algorithm = identifier.slice(0, separator).toLowerCase();
  if (!["falcon", "ml-dsa"].includes(algorithm)) {
    throw new ClaimReferenceError(`cci-pqc algorithm "${algorithm}" is not registered`);
  }
  return `${algorithm}:${canonicalizeOpaque(identifier.slice(separator + 1), "cci-pqc pubkey")}`;
}

function canonicalizeStorCredential(identifier: string): string {
  const separator = identifier.indexOf(":");
  if (separator <= 0 || separator === identifier.length - 1) {
    throw new ClaimReferenceError("stor-cred identifier must be credential-type:identifier");
  }
  const credentialType = identifier.slice(0, separator).toLowerCase();
  if (!/^[a-z][a-z0-9-]*$/.test(credentialType)) {
    throw new ClaimReferenceError("stor-cred credential type is invalid");
  }
  return `${credentialType}:${canonicalizeOpaque(
    identifier.slice(separator + 1),
    "stor-cred identifier",
  )}`;
}

function canonicalizeValidatorSet(identifier: string): string {
  const separator = identifier.indexOf(":");
  if (separator <= 0 || separator === identifier.length - 1) {
    throw new ClaimReferenceError(
      "substrate-validator-set identifier must be substrateId:epochOrSetId",
    );
  }
  const substrateId = identifier.slice(0, separator).toLowerCase();
  if (substrateId !== "demos-mainnet" && substrateId !== "demos-testnet") {
    throw new ClaimReferenceError(
      `substrate-validator-set substrateId "${substrateId}" is not registered`,
    );
  }
  return `${substrateId}:${canonicalizeOpaque(
    identifier.slice(separator + 1),
    "substrate-validator-set epochOrSetId",
  )}`;
}

function canonicalizeOpaque(identifier: string, label: string): string {
  assertUnicodeScalarValue(identifier);
  if (identifier.length === 0 || /[\u0000-\u001f\u007f]/.test(identifier)) {
    throw new ClaimReferenceError(`${label} must be non-empty text without control characters`);
  }
  return identifier;
}

function assertUnicodeScalarValue(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new ClaimReferenceError("ClaimReference contains a lone high surrogate");
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new ClaimReferenceError("ClaimReference contains a lone low surrogate");
    }
  }
}

function canonicalizeCciXm(identifier: string): string {
  const match = /^(?<chain>[A-Za-z0-9-]+):(?<subchain>[A-Za-z0-9-]+):(?<address>.+)$/.exec(
    identifier,
  );
  if (match?.groups === undefined) {
    throw new ClaimReferenceError("cci-xm identifier must be chain:subchain:address");
  }
  const chain = (match.groups["chain"] as string).toLowerCase();
  const subchain = (match.groups["subchain"] as string).toLowerCase();
  const address = match.groups["address"] as string;
  switch (chain) {
    case "evm":
      return `${chain}:${subchain}:${canonicalizeEvmAddress(address, "cci-xm EVM")}`;
    case "demos":
      return `${chain}:${subchain}:0x${canonicalizeLowerHex(
        address.startsWith("0x") ? address.slice(2) : address,
        64,
        "cci-xm Demos address",
      )}`;
    case "solana":
      if (base58DecodedLength(address) !== 32) {
        throw new ClaimReferenceError("cci-xm Solana address must encode exactly 32 bytes");
      }
      return `${chain}:${subchain}:${address}`;
    default:
      throw new ClaimReferenceError(`cci-xm chain "${chain}" is not supported safely`);
  }
}

function base58DecodedLength(value: string): number {
  if (value.length < 32 || value.length > 44) return -1;
  let decoded = 0n;
  for (const character of value) {
    const digit = BASE58_ALPHABET.indexOf(character);
    if (digit === -1) return -1;
    decoded = decoded * 58n + BigInt(digit);
  }

  let byteLength = 0;
  for (let remaining = decoded; remaining > 0n; remaining >>= 8n) byteLength += 1;
  let leadingZeroes = 0;
  while (value[leadingZeroes] === "1") leadingZeroes += 1;
  return leadingZeroes + byteLength;
}

function canonicalizeEvmAddress(identifier: string, label: string): string {
  if (!/^0x[0-9A-Fa-f]{40}$/.test(identifier)) {
    throw new ClaimReferenceError(`${label} identifier must be a 20-byte 0x address`);
  }
  return identifier.toLowerCase();
}

function canonicalizeLowerHex(identifier: string, length: number, label: string): string {
  if (identifier.length !== length || !/^[0-9A-Fa-f]+$/.test(identifier)) {
    throw new ClaimReferenceError(`${label} must be ${length} hexadecimal characters`);
  }
  return identifier.toLowerCase();
}

function canonicalizeUpperAlphaNumeric(identifier: string, length: number, label: string): string {
  if (identifier.length !== length || !/^[A-Za-z0-9]+$/.test(identifier)) {
    throw new ClaimReferenceError(`${label} must be ${length} alphanumeric characters`);
  }
  return identifier.toUpperCase();
}

function canonicalizePositiveDecimal(identifier: string, label: string): string {
  if (!/^[1-9][0-9]*$/.test(identifier)) {
    throw new ClaimReferenceError(`${label} must be digits without leading zeros`);
  }
  return identifier;
}

function canonicalizeDid(identifier: string): string {
  const match = DID_IDENTIFIER.exec(identifier);
  if (match?.groups === undefined) {
    throw new ClaimReferenceError("did identifier must be method:method-specific-id");
  }
  const method = match.groups["method"] as string;
  const specific = match.groups["specific"] as string;
  return `${method}:${specific.replace(
    /%[0-9A-Fa-f]{2}/g,
    (escape) => escape.toUpperCase(),
  )}`;
}

function canonicalizeDomain(identifier: string): string {
  const ascii = domainToASCII(identifier);
  if (ascii.length === 0 || ascii.length > 253) {
    throw new ClaimReferenceError("domain identifier must be valid IDNA DNS text");
  }
  const labels = ascii.split(".");
  if (labels.some((label) =>
    label.length === 0
      || label.length > 63
      || !/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label)
  )) {
    throw new ClaimReferenceError("domain identifier must contain valid DNS labels");
  }
  return ascii.toLowerCase();
}

function canonicalizeErc8004(identifier: string): string {
  const match = /^(0|[1-9][0-9]*):(0x[0-9A-Fa-f]{40}):(0|[1-9][0-9]*)$/.exec(identifier);
  if (match === null) {
    throw new ClaimReferenceError("erc8004 identifier must be chainId:contract:tokenId");
  }
  const chainId = match[1] as string;
  const contract = match[2] as string;
  const tokenId = match[3] as string;
  if (chainId.length > 32) {
    throw new ClaimReferenceError("erc8004 chainId must fit the CAIP-2 reference bound");
  }
  if (tokenId.length > 78) {
    throw new ClaimReferenceError("erc8004 tokenId must fit uint256");
  }
  if (BigInt(tokenId) > UINT256_MAX) {
    throw new ClaimReferenceError("erc8004 tokenId must fit uint256");
  }
  return `${chainId}:${contract.toLowerCase()}:${tokenId}`;
}

function canonicalizeParameters(parameters: string): string {
  if (parameters.length === 0) {
    throw new ClaimReferenceError("ClaimReference parameters must not be empty");
  }

  const entries = parameters.split("&").map((entry, index) => {
    const separator = entry.indexOf("=");
    if (separator <= 0) {
      throw new ClaimReferenceError("ClaimReference parameters must use non-empty key=value pairs");
    }
    const key = decodeParameterComponent(entry.slice(0, separator));
    const value = decodeParameterComponent(entry.slice(separator + 1));
    return { index, key, value };
  });

  entries.sort((left, right) => compareCodePoints(left.key, right.key) || left.index - right.index);
  return entries
    .map(({ key, value }) => `${encodeParameterComponent(key)}=${encodeParameterComponent(value)}`)
    .join("&");
}

function decodeParameterComponent(component: string): string {
  if (/%(?![0-9A-Fa-f]{2})/.test(component)) {
    throw new ClaimReferenceError("ClaimReference parameter has invalid percent encoding");
  }
  const decoded = component.replace(/%([0-9A-Fa-f]{2})/g, (_escape, byte: string) => {
    const character = String.fromCodePoint(Number.parseInt(byte, 16));
    if (!":?&=%".includes(character)) {
      throw new ClaimReferenceError(
        "ClaimReference parameters may percent-encode only reserved delimiters",
      );
    }
    return character;
  }).normalize("NFC");
  if (/[\u0000-\u001f\u007f]/.test(decoded)) {
    throw new ClaimReferenceError("ClaimReference parameter contains a control character");
  }
  return decoded;
}

function encodeParameterComponent(component: string): string {
  return component.replace(RESERVED_PARAMETER_CHARACTER, (character) =>
    `%${character.codePointAt(0)?.toString(16).toUpperCase().padStart(2, "0")}`,
  );
}

function compareCodePoints(left: string, right: string): number {
  const leftPoints = [...left].map((character) => character.codePointAt(0) as number);
  const rightPoints = [...right].map((character) => character.codePointAt(0) as number);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftPoints[index] as number) - (rightPoints[index] as number);
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}
