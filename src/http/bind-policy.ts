import { isIP } from "node:net";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
} from "node:fs";
import { dirname, isAbsolute } from "node:path";
import { X509Certificate, createPrivateKey, timingSafeEqual } from "node:crypto";

/**
 * Bind admission for the terminal HTTP transport.
 *
 * Every decision here is reached before a listener exists. The server calls
 * {@link assertBindAllowed} first and never reaches `Bun.serve` for a refused class, so an
 * invalid bind cannot briefly expose a socket while the check runs.
 *
 * Scope: this module answers only "may this process bind this target". Capability issuance,
 * rotation, revocation storage, admission rate limiting, and the wider service authority model
 * are owned elsewhere and are deliberately absent.
 */

export const BIND_OPERATION = "http.bind" as const;

/** Channels a secret may arrive through. Only file-0600 and secret-reference are approved. */
export type SecretChannel =
  | "argv"
  | "environment"
  | "file-0600"
  | "inline"
  | "secret-reference";

const APPROVED_SECRET_CHANNELS: ReadonlySet<string> = new Set<SecretChannel>([
  "file-0600",
  "secret-reference",
]);

export type BindRefusalCode =
  | "administrator-expired"
  | "administrator-malformed"
  | "administrator-missing"
  | "administrator-revoked"
  | "administrator-scope-mismatch"
  | "administrator-unauthenticated"
  | "administrator-wrong-operation"
  | "administrator-wrong-principal"
  | "hostname-invalid"
  | "port-invalid"
  | "secret-channel-not-approved"
  | "tls-certificate-hostname-mismatch"
  | "tls-certificate-invalid"
  | "tls-missing"
  | "unix-socket-path-invalid"
  | "unix-socket-not-protected";

/** A capability scoped to exactly one bind target. It carries no lifecycle of its own. */
export interface BindAdministratorCapability {
  readonly id: string;
  readonly principal: string;
  readonly operations: readonly string[];
  readonly expiresAt: string;
  readonly boundHostname: string;
  readonly boundPort: number;
}

/**
 * Where a secret actually came from, stated as something admission can check instead of something
 * it is asked to believe. The channel alone is a caller-set label: material read from argv, an
 * environment variable, or an inline literal can be labelled `file-0600` and would otherwise pass
 * the approved-channel gate unchanged. A `file-0600` claim therefore carries the path the material
 * was read from, which admission opens once to check owner-only permissions, a trusted owner, and
 * that the file actually holds the secret presented beside it, and a
 * `secret-reference` claim carries the reference, which admission resolves through the
 * deployment-injected resolver and compares against the secret presented. Both fail closed: a
 * claim whose evidence cannot be taken is refused, never downgraded to the label.
 *
 * Only the two approved channels have a provenance form. That is the point — an unapproved channel
 * has no shape here to launder itself into.
 */
export type SecretProvenance =
  | { readonly kind: "file-0600"; readonly path: string }
  | { readonly kind: "secret-reference"; readonly reference: string };

export interface AdministratorPresentation {
  readonly channel: SecretChannel;
  readonly capability: BindAdministratorCapability;
  /**
   * Evidence for {@link AdministratorPresentation.channel}. For a resolved reference the secret
   * compared is the capability id, which is the part of the presentation a secret channel carries;
   * whether that id authenticates its holder is the later capability-authority contract, not this
   * admission decision.
   */
  readonly provenance: SecretProvenance;
}

/**
 * The certificate is public material and carries no channel requirement; only the private key
 * must arrive through an approved secret channel.
 */
export interface TlsMaterial {
  readonly certificatePem: string;
  readonly privateKeyPem: string;
  readonly privateKeyChannel: SecretChannel;
  /** Evidence for {@link TlsMaterial.privateKeyChannel}, checked against the private key. */
  readonly privateKeyProvenance: SecretProvenance;
  /**
   * Issuer certificates from the one that signed {@link TlsMaterial.certificatePem} up to a
   * self-signed anchor. Omitted for self-signed material, which is its own anchor. A leaf naming
   * an issuer it does not supply cannot be validated here and is refused: admission holds no trust
   * store, so the trust anchor has to arrive with the material or not at all.
   */
  readonly issuerChainPem?: readonly string[];
}

export interface TcpBindRequest {
  readonly kind: "tcp";
  readonly hostname: string;
  readonly port: number;
  /**
   * The names clients will actually use to reach this service, which are not the same thing as the
   * address it listens on. A wildcard bind such as `0.0.0.0` or `::` is an address and never an
   * identity: no certificate a client can validate identifies it, so matching the certificate
   * against the listener address would either refuse every ordinary public deployment or admit a
   * certificate clients reject for the name they typed. Supplying the identities separates the two.
   * Omitted for a bind to one concrete address, where the address is the identity.
   */
  readonly serverIdentities?: readonly string[];
  readonly tls?: TlsMaterial;
  readonly administrator?: AdministratorPresentation;
}

export interface UnixSocketBindRequest {
  readonly kind: "unix-socket";
  readonly path: string;
}

export type BindRequest = TcpBindRequest | UnixSocketBindRequest;

export interface BindPolicyOptions {
  /** Principal the deployment currently accepts for bind-scoped administration. */
  readonly administratorPrincipal?: string;
  /** Capability identifiers the deployment currently refuses. */
  readonly revokedCapabilityIds?: readonly string[];
  readonly now?: () => Date;
  /** Injected for tests; defaults to a real filesystem probe. */
  readonly statPath?: (path: string) => PathFacts;
  /**
   * Observes a cited secret file's metadata and contents together, from one descriptor. Injected
   * for tests; defaults to a real read. Kept separate from {@link BindPolicyOptions.statPath}
   * because a secret file must be read to be believed, while a socket parent must only be stat-ed.
   */
  readonly observeSecretFile?: (path: string) => SecretFileFacts;
  /**
   * Fully resolved form of a path, with every symlink followed. Injected for tests; defaults to
   * `realpathSync`. Admission compares the resolution against the lexical path so that a
   * protected-looking directory reached through a symlink is refused rather than admitted.
   */
  readonly realPath?: (path: string) => string;
  /**
   * Resolves a secret reference to the material it holds. Deployment-supplied, never caller-
   * supplied: a `secret-reference` provenance claim is refused outright when no resolver is
   * configured, because an unresolvable reference is a label again.
   */
  readonly resolveSecretReference?: (reference: string) => string;
  /**
   * Decides whether a presented capability is authentic — that this deployment actually issued it
   * and still stands behind it. Mandatory for a non-loopback bind: every field of a capability is
   * caller-controlled, so shape, expiry, revocation, principal, operation, target scope, and even
   * secret-channel provenance together only prove that a well-formed capability arrived through a
   * protected channel, never that this deployment ever issued it. Without this seam a caller who
   * can write through an approved channel can mint authority by construction.
   *
   * This lane owns the seam and its fail-closed contract, not its production implementation:
   * issuance entropy, instance and audience binding, lifecycle storage, and proof-of-possession are
   * the later authority contracts and are deliberately absent here. A deployment that has not yet
   * supplied a verifier therefore gets refusal, not a default yes — an absent verifier, a throwing
   * verifier, and a negative verdict are all the same answer: the bind does not happen.
   */
  readonly verifyAdministratorAuthenticity?: (
    capability: BindAdministratorCapability,
  ) => boolean;
  /** Account this service runs as; defaults to the current process user where one exists. */
  readonly serviceUid?: number;
}

export type BindExposure = "loopback" | "public" | "unix-socket";

export interface AllowedBind {
  readonly status: "allowed";
  readonly exposure: BindExposure;
  readonly transport: "http" | "https" | "unix";
  readonly target: string;
  /** True only when a bind-scoped administrator capability was required and verified. */
  readonly administratorVerified: boolean;
}

export interface RefusedBind {
  readonly status: "refused";
  readonly code: BindRefusalCode;
  readonly reason: string;
}

export type BindDecision = AllowedBind | RefusedBind;

export class BindPolicyError extends Error {
  readonly code: BindRefusalCode;

  constructor(refusal: RefusedBind) {
    super(refusal.reason);
    this.name = "BindPolicyError";
    this.code = refusal.code;
  }
}

const LOOPBACK_HOSTNAMES: ReadonlySet<string> = new Set(["127.0.0.1", "::1"]);
/** Anything an X.509 `iPAddress` entry could cover: bare IPv4, or a colon-bearing IPv6 form. */
const IP_LITERAL = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]*)$/i;
const MAX_PRINCIPAL_LENGTH = 256;
const MAX_CAPABILITY_ID_LENGTH = 256;
const MAX_OPERATIONS = 32;
const MAX_PEM_LENGTH = 65_536;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

function refuse(code: BindRefusalCode, reason: string): RefusedBind {
  return Object.freeze({ status: "refused", code, reason });
}

function boundedToken(value: unknown, maxLength: number): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maxLength
    && value === value.normalize("NFC");
}

function boundedControlFreeToken(value: unknown, maxLength: number): value is string {
  return boundedToken(value, maxLength) && !CONTROL_CHARACTERS.test(value);
}

/** One RFC 1123 label: alphanumeric, inner hyphens, 1 to 63 characters. */
const HOSTNAME_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

/**
 * The endpoint identity every later decision is stated against: a bracketed IPv6 literal, a bare
 * IPv6 literal wrapped here, or the host and port joined. Bracketing is the whole point — an
 * unbracketed IPv6 result is not an RFC 3986 authority, so the same admitted endpoint would read
 * differently depending on how the caller spelled the host.
 *
 * `isIP` is a pure string predicate from `node:net`; no socket API from that module is used here,
 * and this module still opens nothing.
 */
export function bindTarget(hostname: string, port: number): string {
  if (hostname.startsWith("[") && hostname.endsWith("]")) return `${hostname}:${port}`;
  return isIP(hostname) === 6 ? `[${hostname}]:${port}` : `${hostname}:${port}`;
}

/**
 * The identity a scope comparison must use, so the capability check agrees with this module's own
 * definition of a target. An IP literal folds to its canonical bytes: `2001:db8::1` and
 * `2001:0db8:0:0:0:0:0:1` are one endpoint, as are the bracketed and IPv4-mapped spellings, and a
 * raw string compare would refuse a correctly scoped capability over the difference. A DNS name has
 * no byte form, so it folds ASCII-lowercase instead, which is how `checkHost` already compares it.
 * The two families are tagged apart so a hostname can never collide with an address literal.
 */
function normalizedTarget(hostname: string, port: number): string {
  const bare = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  const bytes = ipAddressBytes(bare);
  if (bytes !== null) {
    return `ip:${Buffer.from(bytes).toString("hex")}:${port}`;
  }
  return `dns:${bare.replace(/[A-Z]/g, (letter) => letter.toLowerCase())}:${port}`;
}

/**
 * Whether the string is a bind target at all: a bracketed IPv6 literal, a bare IP literal, or an
 * RFC 1123 hostname. Without this, anything free of control characters reaches the loopback and
 * TLS branches, so a target like `"host "`, `" 127.0.0.1"` or `"127.0.0.1:8080"` is reported as a
 * TLS failure instead of the malformed target it is.
 */
export function isBindableHostname(hostname: string): boolean {
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    return isIP(hostname.slice(1, -1)) === 6;
  }
  if (isIP(hostname) !== 0) return true;
  const bare = hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
  if (bare.length === 0 || bare.length > 253) return false;
  return bare.split(".").every((label) => HOSTNAME_LABEL.test(label));
}

/**
 * The 16 canonical bytes of an IP literal, or `null` if the string is not one. IPv4 and the
 * IPv4-mapped IPv6 form both fold to the same v4-mapped 16 bytes, so `127.0.0.1`,
 * `::ffff:127.0.0.1`
 * and `::ffff:7f00:1` are one address here rather than three spellings a text matcher would split.
 * `isIP` decides membership; this only turns a literal it already accepts into bytes.
 */
function ipAddressBytes(literal: string): Uint8Array | null {
  const kind = isIP(literal);
  if (kind === 4) return ipv4MappedBytes(literal);
  if (kind === 6) return ipv6Bytes(literal);
  return null;
}

function ipv4MappedBytes(literal: string): Uint8Array | null {
  const octets = literal.split(".").map((part) => Number(part));
  if (octets.length !== 4
    || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
    return null;
  }
  const bytes = new Uint8Array(16);
  bytes[10] = 0xff;
  bytes[11] = 0xff;
  bytes[12] = octets[0] ?? 0;
  bytes[13] = octets[1] ?? 0;
  bytes[14] = octets[2] ?? 0;
  bytes[15] = octets[3] ?? 0;
  return bytes;
}

function ipv6Bytes(literal: string): Uint8Array | null {
  let text = literal;
  // An embedded IPv4 tail (e.g. `::ffff:127.0.0.1`) becomes two hex groups so the rest of the
  // parse sees eight 16-bit groups and one address family.
  const dot = text.indexOf(".");
  if (dot !== -1) {
    const lastColon = text.lastIndexOf(":", dot);
    const v4 = text.slice(lastColon + 1);
    if (isIP(v4) !== 4) return null;
    const octet = v4.split(".").map((part) => Number(part));
    const high = ((octet[0] ?? 0) << 8) | (octet[1] ?? 0);
    const low = ((octet[2] ?? 0) << 8) | (octet[3] ?? 0);
    text = `${text.slice(0, lastColon + 1)}${high.toString(16)}:${low.toString(16)}`;
  }
  const [headText, tailText, extra] = text.split("::");
  if (extra !== undefined) return null;
  const head = headText === undefined || headText === "" ? [] : headText.split(":");
  const tail = tailText === undefined || tailText === "" ? [] : tailText.split(":");
  const groups = tailText === undefined
    ? head
    : [...head, ...new Array(8 - head.length - tail.length).fill("0"), ...tail];
  if (groups.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let index = 0; index < 8; index += 1) {
    const value = Number.parseInt(groups[index] ?? "", 16);
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) return null;
    bytes[index * 2] = value >> 8;
    bytes[index * 2 + 1] = value & 0xff;
  }
  return bytes;
}

function isLoopbackBytes(bytes: Uint8Array): boolean {
  const v4Mapped = bytes[10] === 0xff && bytes[11] === 0xff
    && bytes.slice(0, 10).every((byte) => byte === 0);
  if (v4Mapped) return bytes[12] === 127;
  return bytes.slice(0, 15).every((byte) => byte === 0) && bytes[15] === 1;
}

/**
 * IPv4/IPv6 loopback detection, over the canonical bytes so every spelling of the same address
 * classifies alike: dotted or hexadecimal, IPv4-mapped or bare, compressed or expanded. A loopback
 * spelled `::ffff:7f00:1` is the same 127.0.0.1 as the dotted form and must not fall to the
 * exposed branch that demands TLS and administrator authority.
 */
export function isLoopbackHostname(hostname: string): boolean {
  const bare = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  if (LOOPBACK_HOSTNAMES.has(bare)) return true;
  const bytes = ipAddressBytes(bare);
  return bytes !== null && isLoopbackBytes(bytes);
}

/**
 * The outcome of validating offered TLS material. The parsed certificate is carried out so the
 * exposed path can bind it to the target without parsing the PEM a second time.
 */
type TlsAdmission =
  | { readonly refusal: RefusedBind; readonly certificate?: undefined }
  | { readonly refusal: null; readonly certificate: X509Certificate };

function refusedTls(refusal: RefusedBind): TlsAdmission {
  return { refusal };
}

function validatedTlsMaterial(
  tls: TlsMaterial,
  now: Date,
  options: BindPolicyOptions,
): TlsAdmission {
  if (tls === null || typeof tls !== "object") {
    return refusedTls(refuse("tls-certificate-invalid", "the TLS material must be an object"));
  }
  if (!APPROVED_SECRET_CHANNELS.has(tls.privateKeyChannel)) {
    return refusedTls(refuse(
      "secret-channel-not-approved",
      "the TLS private key must arrive through an approved secret channel",
    ));
  }
  if (!boundedToken(tls.certificatePem, MAX_PEM_LENGTH)
    || !boundedToken(tls.privateKeyPem, MAX_PEM_LENGTH)) {
    return refusedTls(refuse("tls-certificate-invalid", "TLS material must be bounded PEM text"));
  }
  const keyProvenance = unverifiedProvenance(
    tls.privateKeyChannel,
    tls.privateKeyProvenance,
    tls.privateKeyPem,
    options,
    "the TLS private key",
  );
  if (keyProvenance !== null) return refusedTls(keyProvenance);
  let certificate: X509Certificate;
  try {
    certificate = new X509Certificate(tls.certificatePem);
  } catch {
    return refusedTls(refuse("tls-certificate-invalid", "the TLS certificate could not be parsed"));
  }
  let matchesKey = false;
  try {
    matchesKey = certificate.checkPrivateKey(createPrivateKey(tls.privateKeyPem));
  } catch {
    return refusedTls(refuse("tls-certificate-invalid", "the TLS private key could not be parsed"));
  }
  if (!matchesKey) {
    return refusedTls(refuse(
      "tls-certificate-invalid",
      "the TLS private key does not match the certificate",
    ));
  }
  const validFrom = new Date(certificate.validFrom);
  const validTo = new Date(certificate.validTo);
  if (Number.isNaN(validFrom.getTime()) || Number.isNaN(validTo.getTime())) {
    return refusedTls(refuse(
      "tls-certificate-invalid",
      "the TLS certificate validity window is unreadable",
    ));
  }
  if (now.getTime() < validFrom.getTime()) {
    return refusedTls(refuse("tls-certificate-invalid", "the TLS certificate is not yet valid"));
  }
  if (now.getTime() >= validTo.getTime()) {
    return refusedTls(refuse("tls-certificate-invalid", "the TLS certificate is expired"));
  }
  const signatureRefusal = unverifiedCertificateSignature(certificate, tls, now);
  if (signatureRefusal !== null) return refusedTls(signatureRefusal);
  return { refusal: null, certificate };
}

/** Extended-key-usage OID a certificate needs to be usable by a TLS server. */
const SERVER_AUTH_EKU = "1.3.6.1.5.5.7.3.1";

/** Anchors are reached in a handful of hops; a longer claim is a loop or a denial-of-service. */
const MAX_ISSUER_CHAIN_LENGTH = 8;

/**
 * Whether the certificate is cryptographically what it claims to be, rather than merely parseable.
 *
 * Parsing, key matching, dates, and hostname all read fields the presenter wrote. None of them
 * touches the signature, so material whose signature bytes are corrupt — or which was never signed
 * by the issuer it names — passes every one of them while every real client rejects the handshake.
 * Admission would then have declared TLS valid for a listener that cannot serve it.
 *
 * Trust is established from the material itself because this module holds no trust store: a
 * self-issued leaf must carry a signature its own key verifies, and an issued leaf must supply the
 * chain up to a self-signed anchor, each link verified against the next one's key and each issuer
 * current at the same instant. Server usage is checked where the certificate restricts it; an
 * unrestricted certificate carries no extended-key-usage list to contradict.
 */
function unverifiedCertificateSignature(
  certificate: X509Certificate,
  tls: TlsMaterial,
  now: Date,
): RefusedBind | null {
  const usage = certificate.keyUsage;
  if (Array.isArray(usage) && !usage.includes(SERVER_AUTH_EKU)) {
    return refuse("tls-certificate-invalid", "the TLS certificate is not valid for server use");
  }
  const chainPem = tls.issuerChainPem;
  if (chainPem !== undefined && !Array.isArray(chainPem)) {
    return refuse("tls-certificate-invalid", "the TLS issuer chain must be a list of certificates");
  }
  if (chainPem === undefined || chainPem.length === 0) {
    if (certificate.subject !== certificate.issuer) {
      return refuse(
        "tls-certificate-invalid",
        "the TLS certificate names an issuer whose certificate was not supplied",
      );
    }
    return verifiedAgainst(certificate, certificate);
  }
  if (chainPem.length > MAX_ISSUER_CHAIN_LENGTH) {
    return refuse("tls-certificate-invalid", "the TLS issuer chain is longer than admission reads");
  }
  const chain: X509Certificate[] = [];
  for (const pem of chainPem) {
    if (!boundedToken(pem, MAX_PEM_LENGTH)) {
      return refuse("tls-certificate-invalid", "an issuer certificate is not bounded PEM text");
    }
    try {
      chain.push(new X509Certificate(pem));
    } catch {
      return refuse("tls-certificate-invalid", "an issuer certificate could not be parsed");
    }
  }
  let subject = certificate;
  for (const issuer of chain) {
    // A certificate that signs another certificate is a CA, and every real validator refuses a
    // chain whose issuer says otherwise. Without this an end-entity certificate — one anybody can
    // be issued — is accepted as an intermediate, and admission declares TLS valid for a listener
    // no client will validate. Asked of issuers only: the leaf itself is not signing anything, and
    // an ordinary self-signed server certificate carries `cA=false` legitimately.
    if (issuer.ca !== true) {
      return refuse(
        "tls-certificate-invalid",
        "a TLS issuer certificate is not a certificate authority",
      );
    }
    const currency = expiredCertificate(issuer, now);
    if (currency !== null) return currency;
    const link = verifiedAgainst(subject, issuer);
    if (link !== null) return link;
    subject = issuer;
  }
  // The chain ends where something vouches for itself. Without this the last certificate would be
  // trusted for no reason beyond having been supplied by the same caller as the leaf, so an
  // intermediate could be presented as an anchor. Verifying it against itself is the whole test:
  // that requires its issuer name to be its own subject and its signature to verify under its own
  // key, so no separate self-signed comparison is needed here.
  const anchor = chain[chain.length - 1];
  if (anchor === undefined) {
    return refuse("tls-certificate-invalid", "the TLS issuer chain reaches no self-signed anchor");
  }
  return verifiedAgainst(anchor, anchor);
}

function verifiedAgainst(subject: X509Certificate, issuer: X509Certificate): RefusedBind | null {
  if (subject.issuer !== issuer.subject) {
    return refuse(
      "tls-certificate-invalid",
      "a TLS certificate does not name its issuer's subject",
    );
  }
  let verified = false;
  try {
    verified = subject.verify(issuer.publicKey);
  } catch {
    return refuse("tls-certificate-invalid", "a TLS certificate signature could not be checked");
  }
  if (!verified) {
    return refuse("tls-certificate-invalid", "a TLS certificate signature does not verify");
  }
  return null;
}

function expiredCertificate(certificate: X509Certificate, now: Date): RefusedBind | null {
  const from = new Date(certificate.validFrom).getTime();
  const to = new Date(certificate.validTo).getTime();
  if (Number.isNaN(from) || Number.isNaN(to)) {
    return refuse("tls-certificate-invalid", "an issuer validity window is unreadable");
  }
  if (now.getTime() < from || now.getTime() >= to) {
    return refuse("tls-certificate-invalid", "an issuer certificate is not current");
  }
  return null;
}

/**
 * Bind the certificate to the target that is about to be exposed. Material can be perfectly
 * well-formed and still name something else, in which case every client rejects the handshake;
 * checking here keeps that failure in admission instead of moving it past the listener.
 * Applied to the exposed class only — a loopback listener has no name to impersonate.
 */
function certificateIdentityRefusal(
  certificate: X509Certificate,
  request: TcpBindRequest,
): RefusedBind | null {
  const declared = request.serverIdentities;
  const wildcard = isWildcardBindAddress(request.hostname);
  if (declared === undefined || declared.length === 0) {
    // A wildcard address identifies nothing, so admission has no name to check the certificate
    // against and cannot establish that clients will accept it. Refused rather than admitted
    // unchecked: the alternative is a listener whose TLS identity was never examined.
    if (wildcard) {
      return refuse(
        "tls-certificate-hostname-mismatch",
        "a wildcard bind must declare the server identities clients will use",
      );
    }
    return identifiedBy(certificate, request.hostname);
  }
  if (!Array.isArray(declared) || declared.length > MAX_SERVER_IDENTITIES) {
    return refuse(
      "tls-certificate-hostname-mismatch",
      "the declared server identities are not a bounded list",
    );
  }
  // Every declared identity must be carried by the certificate, not merely one of them: a client
  // reaching the service by any of these names has to be able to validate it, and one unmatched
  // name is one client population that cannot connect.
  for (const identity of declared) {
    if (!boundedControlFreeToken(identity, MAX_HOSTNAME_LENGTH)) {
      return refuse(
        "tls-certificate-hostname-mismatch",
        "a declared server identity is not a bounded name",
      );
    }
    const refusal = identifiedBy(certificate, identity);
    if (refusal !== null) return refusal;
  }
  return null;
}

/** How many names one listener may claim before the list stops being a deployment description. */
const MAX_SERVER_IDENTITIES = 64;

/** A DNS name is bounded at 253 octets; the bracket form of an IPv6 literal fits well inside it. */
const MAX_HOSTNAME_LENGTH = 253;

function identifiedBy(certificate: X509Certificate, name: string): RefusedBind | null {
  const bare = name.startsWith("[") && name.endsWith("]") ? name.slice(1, -1) : name;
  let identified = false;
  try {
    identified = IP_LITERAL.test(bare)
      ? certificate.checkIP(bare) !== undefined
      : certificate.checkHost(bare) !== undefined;
  } catch {
    identified = false;
  }
  return identified
    ? null
    : refuse(
      "tls-certificate-hostname-mismatch",
      "the TLS certificate does not identify the bind target",
    );
}

/**
 * Whether a hostname is an any-address wildcard rather than one interface. These are the spellings
 * a service binds to when it means "every interface"; none of them is a name a certificate can
 * carry, which is the whole reason the identity has to be declared separately.
 */
function isWildcardBindAddress(hostname: string): boolean {
  const bare = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  if (bare === "0.0.0.0" || bare === "*") return true;
  if (!IP_LITERAL.test(bare) || isIP(bare) !== 6) return false;
  // Every all-zero IPv6 spelling: `::`, `0:0:0:0:0:0:0:0`, `::0`, and the mapped `::ffff:0.0.0.0`.
  return /^[0:]+$/.test(bare) || bare.toLowerCase() === "::ffff:0.0.0.0";
}

/**
 * Check the bind-scoped administrator capability ISC-23.1 requires for a non-loopback bind.
 *
 * What this establishes: that a capability was presented, that it is well-formed and unexpired,
 * that its principal is the one the deployment currently declares, that it carries the bind
 * operation, that its scope names this exact target, and that its identifier is not on the
 * deployment's revocation list. Those facts are checked against deployment configuration, not
 * against the request, so a caller cannot supply them.
 *
 * What it does NOT establish: that the presented capability is authentic. Its bearer proof is
 * unverified — there is no signature, issuer resolution, or instance/audience binding here — and
 * `channel` is a claim about how the value arrived, which a value alone cannot evidence. A
 * caller able to reach this code path can therefore mint a shape that passes. Making that
 * authority real is ISC-23.4 (capability entropy, deployment-instance and audience scoping) with
 * ISC-23.3.1/ISC-23.5 for admission proofs, none of which are in this lane; this function is the
 * scope-and-currentness half of the check and is documented as such so no caller reads it as
 * authentication.
 */
function validatedAdministrator(
  presentation: AdministratorPresentation | undefined,
  request: TcpBindRequest,
  options: BindPolicyOptions,
  now: Date,
): RefusedBind | null {
  if (presentation === undefined || presentation === null) {
    return refuse(
      "administrator-missing",
      "a non-loopback bind requires a bind-scoped administrator capability",
    );
  }
  if (typeof presentation !== "object") {
    return refuse("administrator-malformed", "the administrator presentation must be an object");
  }
  if (!APPROVED_SECRET_CHANNELS.has(presentation.channel)) {
    return refuse(
      "secret-channel-not-approved",
      "the administrator capability must arrive through an approved secret channel",
    );
  }
  const capability = presentation.capability;
  if (capability === null || typeof capability !== "object"
    || !boundedControlFreeToken(capability.id, MAX_CAPABILITY_ID_LENGTH)
    || !boundedControlFreeToken(capability.principal, MAX_PRINCIPAL_LENGTH)
    || !Array.isArray(capability.operations)
    || capability.operations.length === 0
    || capability.operations.length > MAX_OPERATIONS
    || !capability.operations.every((operation) => boundedControlFreeToken(operation, 128))
    || !boundedControlFreeToken(capability.boundHostname, 256)
    || !Number.isSafeInteger(capability.boundPort)
    || capability.boundPort < 1
    || capability.boundPort > 65_535
    || typeof capability.expiresAt !== "string"
    || !UTC_TIMESTAMP.test(capability.expiresAt)) {
    return refuse("administrator-malformed", "the administrator capability shape is invalid");
  }
  const expiresAt = new Date(capability.expiresAt);
  if (Number.isNaN(expiresAt.getTime())) {
    return refuse("administrator-malformed", "the capability expiry must be a UTC timestamp");
  }
  const revoked = options.revokedCapabilityIds ?? [];
  if (revoked.includes(capability.id)) {
    return refuse("administrator-revoked", "the administrator capability is revoked");
  }
  if (expiresAt.getTime() <= now.getTime()) {
    return refuse("administrator-expired", "the administrator capability is expired");
  }
  const expectedPrincipal = options.administratorPrincipal;
  if (!boundedControlFreeToken(expectedPrincipal, MAX_PRINCIPAL_LENGTH)) {
    return refuse(
      "administrator-wrong-principal",
      "the deployment declares no current bind administrator principal",
    );
  }
  if (capability.principal !== expectedPrincipal) {
    return refuse(
      "administrator-wrong-principal",
      "the capability principal is not the current bind administrator",
    );
  }
  if (!capability.operations.includes(BIND_OPERATION)) {
    return refuse(
      "administrator-wrong-operation",
      `the capability does not carry the ${BIND_OPERATION} operation`,
    );
  }
  if (normalizedTarget(capability.boundHostname, capability.boundPort)
    !== normalizedTarget(request.hostname, request.port)) {
    return refuse(
      "administrator-scope-mismatch",
      "the capability is scoped to a different bind target",
    );
  }
  const provenanceRefusal = unverifiedProvenance(
    presentation.channel,
    presentation.provenance,
    capability.id,
    options,
    "the administrator capability",
  );
  if (provenanceRefusal !== null) return provenanceRefusal;
  // Last, and only on a presentation that already passed every check above: is this capability one
  // this deployment actually issued? Everything before this point is satisfiable by a caller who
  // constructs the fields it wants, so this is the check that makes the difference between
  // "well-formed authority arrived" and "authority was verified" — and the only one that may set
  // administratorVerified.
  const verify = options.verifyAdministratorAuthenticity;
  if (verify === undefined) {
    return refuse(
      "administrator-unauthenticated",
      "this deployment supplies no administrator authenticity verifier, "
        + "so bind authority cannot be verified",
    );
  }
  let authentic: boolean;
  try {
    authentic = verify(capability);
  } catch {
    return refuse(
      "administrator-unauthenticated",
      "the administrator authenticity verifier failed, so bind authority is not verified",
    );
  }
  if (authentic !== true) {
    return refuse(
      "administrator-unauthenticated",
      "the administrator capability is not authentic for this deployment",
    );
  }
  return null;
}

/**
 * `sockaddr_un.sun_path` is 108 bytes on Linux and 104 on macOS, both including the terminator.
 * Admission uses the smaller bound so an allowed path is bindable on either, instead of passing
 * a filesystem-legal path that `listen` then rejects — the class this module exists to decide.
 */
const MAX_UNIX_SOCKET_PATH_BYTES = 103;

/**
 * What admission needs to know about one path. Mode alone is not protection: a mode-0700
 * directory owned by another account is writable by that account, which can unlink and replace
 * the socket after this service binds it, and a mode-0600 regular file has no mode bit that says
 * "not a directory". Ownership and type are therefore part of the observation, not derived
 * later from it.
 */
export interface PathFacts {
  readonly mode: number;
  readonly isSocket: boolean;
  readonly isDirectory: boolean;
  /**
   * Whether the observed entry is itself a symbolic link. Stated as a fact because the entry and
   * whatever it points at are two different objects, and admission decides about the entry: the
   * socket path is a name this service is about to create or reuse, not a name to follow.
   */
  readonly isSymbolicLink: boolean;
  readonly uid: number;
}

/**
 * Facts about the entry at a path, not about whatever it resolves to. `lstat`, not `stat`: a
 * following observation reports a dangling symlink as absent, and absence is the one answer that
 * lets a bind proceed — so the entry already occupying the name would be admitted and `bind` would
 * then fail on it. A symlink to a live socket is the same mistake in the other direction, read as
 * an ordinary leftover this service may reuse.
 *
 * The parent directory and its ancestors are unaffected by the difference: admission already
 * requires `realpath(parent) === parent`, so no component above the socket can be a symlink, and
 * there `lstat` and `stat` observe the same object.
 */
function defaultStatPath(path: string): PathFacts {
  const stats = lstatSync(path);
  return {
    mode: stats.mode,
    isSocket: stats.isSocket(),
    isDirectory: stats.isDirectory(),
    isSymbolicLink: stats.isSymbolicLink(),
    uid: stats.uid,
  };
}

/**
 * One file, observed once. The metadata and the contents must describe the same object or the
 * check they feed is decidable by whoever can swap the path between the two calls: a stat of a
 * root-owned mode-0600 file followed by a read of a replacement is a passing observation of a file
 * that never held the secret. So both come from a single descriptor.
 */
export interface SecretFileFacts extends PathFacts {
  /**
   * Whether the observed object is a regular file. Stated positively rather than left to the
   * absence of the directory and socket flags: a FIFO, a device and a pseudo-file are none of
   * those three and are all things a secret cannot have been read from.
   */
  readonly isFile: boolean;
  readonly contents: string;
}

/**
 * A secret file holds one PEM or one capability id, never a payload. The bound is generous enough
 * for a certificate chain in a key file and small enough that admission cannot be made to read an
 * arbitrary file into memory by citing it.
 */
const MAX_SECRET_FILE_BYTES = 64 * 1024;

function defaultObserveSecretFile(path: string): SecretFileFacts {
  // Opened non-blocking, because the path is an untrusted input and `open` on a FIFO blocks until
  // a writer appears — admission would hang before it ever got to decide anything. O_NONBLOCK on a
  // regular file changes nothing, so this costs the honest case nothing.
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const stats = fstatSync(descriptor);
    // Established before any read. A device or pseudo-file can report a small size and then
    // produce unbounded data, so the size bound alone is not a bound on what a read yields; only
    // a regular file makes `size` mean what the bound assumes. Reported as a fact rather than
    // thrown, so the policy refuses it for what the path is; a throw here would arrive at the
    // caller as "could not be observed", which is what an unreadable regular file also looks like.
    if (!stats.isFile()) {
      return {
        mode: stats.mode,
        isSocket: stats.isSocket(),
        isDirectory: stats.isDirectory(),
        // `fstat` describes the object the descriptor was opened on, and `open` follows a final
        // link, so what is observed here is never the link itself. Stated rather than left out so
        // the fact means the same thing on every path that produces it.
        isSymbolicLink: false,
        isFile: false,
        uid: stats.uid,
        contents: "",
      };
    }
    if (stats.size > MAX_SECRET_FILE_BYTES) {
      throw new Error("the secret file exceeds the readable bound");
    }
    // Read from the descriptor, not the path, so this is the object that was just stat-ed, and
    // bounded at the read itself rather than trusting the size that was just observed.
    const buffer = Buffer.alloc(MAX_SECRET_FILE_BYTES + 1);
    let filled = 0;
    for (;;) {
      const read = readSync(descriptor, buffer, filled, buffer.length - filled, null);
      if (read === 0) break;
      filled += read;
      if (filled > MAX_SECRET_FILE_BYTES) {
        throw new Error("the secret file exceeds the readable bound");
      }
    }
    return {
      mode: stats.mode,
      isSocket: stats.isSocket(),
      isDirectory: stats.isDirectory(),
      isSymbolicLink: false,
      isFile: true,
      uid: stats.uid,
      contents: buffer.subarray(0, filled).toString("utf8"),
    };
  } finally {
    closeSync(descriptor);
  }
}

/**
 * Whether a file's contents are the secret that cited it. Compared in constant time so admission
 * does not answer "how much of this secret is right" to a caller who can retry, and length-first
 * because `timingSafeEqual` throws on a length mismatch. One trailing newline is tolerated: a key
 * file written by any ordinary tool ends with one, and refusing that would push deployments toward
 * hand-trimmed secret files rather than toward correctness.
 */
function secretFileHolds(contents: string, secret: string): boolean {
  const candidates = contents.endsWith("\n") ? [contents, contents.slice(0, -1)] : [contents];
  const expected = Buffer.from(secret, "utf8");
  return candidates.some((candidate) => {
    const actual = Buffer.from(candidate, "utf8");
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  });
}

/**
 * Whether this service can trust a path owned by `uid`. Root and the service's own account are
 * the only owners that cannot substitute the socket behind it; on a platform without user ids
 * the question does not arise and ownership is not asserted.
 */
/**
 * Whether a failed `stat` means the path does not exist. Anything else is a path whose state was
 * not established, which is not the same answer and must not be treated as one.
 */
function absentPath(error: unknown): boolean {
  if (error === null || typeof error !== "object") return false;
  return (error as { code?: unknown }).code === "ENOENT";
}

function trustedOwner(uid: number, serviceUid: number | undefined): boolean {
  return serviceUid === undefined || uid === 0 || uid === serviceUid;
}

/** Bits that must be clear on a secret file: every group and other bit, and every execute bit. */
const SECRET_FILE_FORBIDDEN_MODE = 0o177;

/**
 * A secret file path is not a `sun_path`, so it does not share the socket limit; `PATH_MAX` is the
 * bound that actually applies to a file admission is asked to observe.
 */
const MAX_SECRET_PATH_LENGTH = 4_096;

/**
 * Whether a secret's stated channel is backed by evidence. Returns a refusal to hand back, or
 * `null` when the provenance holds. The label must agree with its own evidence first: a
 * presentation claiming `file-0600` while carrying a resolved reference is refused before either
 * form is checked, so the two paths cannot be mixed to satisfy neither.
 */
function unverifiedProvenance(
  channel: SecretChannel,
  provenance: SecretProvenance,
  secret: string,
  options: BindPolicyOptions,
  subject: string,
): RefusedBind | null {
  const refuseChannel = (detail: string): RefusedBind =>
    refuse("secret-channel-not-approved", `${subject} ${detail}`);
  if (provenance === null || typeof provenance !== "object" || provenance.kind !== channel) {
    return refuseChannel("declares a secret channel its own provenance does not support");
  }
  if (provenance.kind === "file-0600") {
    const path = provenance.path;
    if (!boundedControlFreeToken(path, MAX_SECRET_PATH_LENGTH) || !isAbsolute(path)) {
      return refuseChannel("names no absolute path for the file it was read from");
    }
    let facts: SecretFileFacts;
    try {
      facts = (options.observeSecretFile ?? defaultObserveSecretFile)(path);
    } catch {
      return refuseChannel("names a file that cannot be observed");
    }
    if (!facts.isFile || facts.isDirectory || facts.isSocket) {
      return refuseChannel("names something other than a file it could have been read from");
    }
    if ((facts.mode & SECRET_FILE_FORBIDDEN_MODE) !== 0) {
      return refuseChannel("was read from a file that grants access beyond its owner");
    }
    if (!trustedOwner(facts.uid, options.serviceUid ?? process.getuid?.())) {
      return refuseChannel("was read from a file owned by an untrusted account");
    }
    // The file's protection is evidence about the file, never about the secret presented beside
    // it. Without this last check any material — from argv, the environment, or a literal — could
    // cite any trusted mode-0600 file on the host and inherit its provenance.
    if (!secretFileHolds(facts.contents, secret)) {
      return refuseChannel("does not match the contents of the file it claims to come from");
    }
    return null;
  }
  if (!boundedControlFreeToken(provenance.reference, MAX_CAPABILITY_ID_LENGTH)) {
    return refuseChannel("carries no usable secret reference");
  }
  const resolver = options.resolveSecretReference;
  if (resolver === undefined) {
    return refuseChannel("claims a secret reference this deployment cannot resolve");
  }
  let resolved: string;
  try {
    resolved = resolver(provenance.reference);
  } catch {
    return refuseChannel("carries a secret reference that failed to resolve");
  }
  if (resolved !== secret) {
    return refuseChannel("does not match the material its secret reference resolves to");
  }
  return null;
}

/**
 * Whether the service can actually create its socket inside a parent directory. This is the second
 * of two independent questions the parent must answer, never a replacement for the first:
 * {@link trustedOwner} asks who could substitute the socket, this asks who can create it, and a
 * parent is admitted only when both hold. The parent is already required to be mode-0700, and a
 * 0700 directory is traversable and writable by its owner alone. A root-owned 0700 parent is safe
 * from substitution yet unusable by a non-root service — the bind would fail `EACCES` after
 * admission said yes — so the parent must also be owned by the service itself, unless the service
 * runs as root or the platform exposes no uid. Root passing this check is not root trusting the
 * owner: a root service can traverse a 0700 directory owned by an untrusted account, but that
 * account can still unlink and replace the socket afterwards, which is why {@link trustedOwner}
 * still has to refuse it.
 */
function serviceCanCreateIn(
  parentUid: number,
  parentMode: number,
  serviceUid: number | undefined,
): boolean {
  if (serviceUid === undefined || serviceUid === 0) return true;
  if (parentUid !== serviceUid) return false;
  // Ownership is not permission. A service-owned directory at mode 0500, 0400 or 0000 satisfies
  // every protection check above and still cannot receive a socket: creating an entry needs owner
  // write, and reaching it needs owner execute. Without both, `listen` fails EACCES after
  // admission already said yes — the failure moves past the listener instead of being refused.
  return (parentMode & OWNER_CREATE_BITS) === OWNER_CREATE_BITS;
}

/** Owner write and execute: what creating an entry inside a directory actually requires. */
const OWNER_CREATE_BITS = 0o300;

/** Directories walked upward before admission stops asking; a deeper path is pathological. */
const MAX_ANCESTOR_DEPTH = 64;

/**
 * Whether every directory above the socket parent is protected against having that parent swapped.
 *
 * Checking the parent alone protects the wrong thing. If the parent sits inside a directory another
 * account can write, that account renames or replaces the parent after admission observed it, and
 * the admitted path then leads to a directory nobody checked. Resolving the path first does not
 * help: `realpath` is a snapshot of where the name pointed, not a lock on where it will point.
 *
 * So every ancestor must be owned by an account that cannot be an attacker, and must not be
 * writable by group or other unless it carries the sticky bit — in a sticky directory only an
 * entry's own owner may rename it, and the parent is already required to be owned by a trusted
 * account, which is what makes shared directories like `/tmp` admissible rather than special-cased.
 *
 * What this does not do, deliberately and per the bound threat model: it does not defend against a
 * privileged or same-UID adversary acting after admission, and it is not an atomic bind against a
 * held directory descriptor. Both are outside this lane. This closes the unowned and unprotected
 * ancestor class; the remaining window belongs to the bind executor.
 */
function unprotectedAncestor(
  parentPath: string,
  stat: (path: string) => PathFacts,
  serviceUid: number | undefined,
): RefusedBind | null {
  let current = dirname(parentPath);
  for (let depth = 0; depth < MAX_ANCESTOR_DEPTH; depth += 1) {
    let facts: PathFacts;
    try {
      facts = stat(current);
    } catch {
      return refuse("unix-socket-path-invalid", "a directory above the socket is unreadable");
    }
    if (!facts.isDirectory) {
      return refuse(
        "unix-socket-path-invalid",
        "a path component above the socket is not a directory",
      );
    }
    if (!trustedOwner(facts.uid, serviceUid)) {
      return refuse(
        "unix-socket-not-protected",
        "a directory above the socket is owned by an account that could replace it",
      );
    }
    const writableByOthers = (facts.mode & 0o022) !== 0;
    const sticky = (facts.mode & 0o1000) !== 0;
    if (writableByOthers && !sticky) {
      return refuse(
        "unix-socket-not-protected",
        "a directory above the socket is writable by other accounts without the sticky bit",
      );
    }
    const next = dirname(current);
    if (next === current) return null;
    current = next;
  }
  return refuse(
    "unix-socket-path-invalid",
    "the socket path is nested deeper than admission reads",
  );
}

function unixSocketDecision(
  request: UnixSocketBindRequest,
  options: BindPolicyOptions,
): BindDecision {
  if (!boundedControlFreeToken(request.path, 4_096) || !isAbsolute(request.path)) {
    return refuse("unix-socket-path-invalid", "the socket path must be a bounded absolute path");
  }
  if (Buffer.byteLength(request.path, "utf8") > MAX_UNIX_SOCKET_PATH_BYTES) {
    return refuse("unix-socket-path-invalid", "the socket path exceeds the sun_path limit");
  }
  const stat = options.statPath ?? defaultStatPath;
  const resolve = options.realPath ?? realpathSync;
  const serviceUid = options.serviceUid ?? process.getuid?.();
  const parentPath = dirname(request.path);
  // `stat` follows symlinks and reports only the directory it landed on, so a parent reached
  // through a symlink can present someone else's protected directory at admission time. Resolving
  // first and demanding the resolution equal the lexical path refuses that whole class: any
  // symlinked component, and any non-canonical spelling, resolves to something else. It fails
  // closed, because a path that cannot be resolved is not a path whose protection was observed.
  let resolvedParent: string;
  try {
    resolvedParent = resolve(parentPath);
  } catch {
    return refuse("unix-socket-path-invalid", "the socket parent directory is unreadable");
  }
  if (resolvedParent !== parentPath) {
    return refuse(
      "unix-socket-not-protected",
      "the socket parent directory is reached through a symlink or a non-canonical path",
    );
  }
  let parent: PathFacts;
  try {
    parent = stat(parentPath);
  } catch {
    return refuse("unix-socket-path-invalid", "the socket parent directory is unreadable");
  }
  if (!parent.isDirectory) {
    return refuse("unix-socket-path-invalid", "the socket parent is not a directory");
  }
  if ((parent.mode & 0o077) !== 0) {
    return refuse(
      "unix-socket-not-protected",
      "the socket parent directory grants group or other access",
    );
  }
  if (!trustedOwner(parent.uid, serviceUid)) {
    return refuse(
      "unix-socket-not-protected",
      "the socket parent directory is owned by an account that could substitute the socket",
    );
  }
  if (!serviceCanCreateIn(parent.uid, parent.mode, serviceUid)) {
    return refuse(
      "unix-socket-not-protected",
      "the socket parent directory is not writable by this service account",
    );
  }
  const ancestorRefusal = unprotectedAncestor(parentPath, stat, serviceUid);
  if (ancestorRefusal !== null) return ancestorRefusal;
  let existing: PathFacts | null;
  try {
    existing = stat(request.path);
  } catch (error) {
    // Only "there is nothing here" means the socket may be created. `ELOOP`, `EACCES`, `EIO` and
    // the rest say the path could not be observed, and reading them as absence admits a bind that
    // then fails at `listen` — the failure moving past the listener is exactly what admission
    // exists to prevent, so an unobservable path is refused rather than assumed free.
    if (!absentPath(error)) {
      return refuse("unix-socket-path-invalid", "the socket path could not be observed");
    }
    existing = null;
  }
  if (existing !== null) {
    // The name is occupied by a link, so what admission would hand to `bind` is a name resolving
    // somewhere else — possibly outside the parent directory whose protection was just established,
    // and possibly nowhere at all. Refused as its own class rather than folded into the file-type
    // check below, because a following observation would have reported the target's type here and
    // said nothing about the link that is actually in the way.
    if (existing.isSymbolicLink) {
      return refuse("unix-socket-path-invalid", "the socket path is occupied by a symbolic link");
    }
    if (!existing.isSocket) {
      return refuse("unix-socket-path-invalid", "the socket path is occupied by another file type");
    }
    // No mode check on the socket itself, deliberately. Its mode is not chosen by anyone: the
    // kernel derives it from the umask at `bind`, so a service running under the common 022
    // leaves a 0755 socket behind and would refuse its own leftover on the next start, needing an
    // operator to unlink it by hand before the service could come back. The check would also buy
    // nothing — reaching the socket means traversing the parent directory, which is already
    // required to grant nothing to group or other and to be owned by a trusted account. Ownership
    // is the load-bearing question here, and it is asked below.
    if (!trustedOwner(existing.uid, serviceUid)) {
      return refuse(
        "unix-socket-not-protected",
        "the existing socket is owned by another account",
      );
    }
  }
  return Object.freeze({
    status: "allowed",
    exposure: "unix-socket",
    transport: "unix",
    target: request.path,
    administratorVerified: false,
  });
}

/**
 * Decide whether one bind target may be opened. Pure with respect to the network: it never
 * creates a socket, so every refusal happens before a listener could accept a connection.
 */
export function evaluateBindPolicy(
  request: BindRequest,
  options: BindPolicyOptions = {},
): BindDecision {
  if (request === null || typeof request !== "object") {
    return refuse("hostname-invalid", "a bind request object is required");
  }
  if (request.kind === "unix-socket") return unixSocketDecision(request, options);
  if (request.kind !== "tcp") {
    return refuse("hostname-invalid", "the bind request kind is unsupported");
  }
  if (!boundedControlFreeToken(request.hostname, 256)) {
    return refuse("hostname-invalid", "the bind hostname must be a bounded token");
  }
  if (!isBindableHostname(request.hostname)) {
    return refuse("hostname-invalid", "the bind hostname is not a host literal or RFC 1123 name");
  }
  if (!Number.isSafeInteger(request.port) || request.port < 0 || request.port > 65_535) {
    return refuse("port-invalid", "the bind port must be an integer from 0 through 65535");
  }
  const now = options.now === undefined ? new Date() : options.now();
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    return refuse("administrator-malformed", "the policy clock is unreadable");
  }
  if (isLoopbackHostname(request.hostname)) {
    // Loopback needs no TLS, but material that is offered is still validated: the decision
    // reports the transport it admitted, and reporting `https` over unusable material would
    // move the failure past this check into the listener.
    if (request.tls !== undefined) {
      const loopbackTls = validatedTlsMaterial(request.tls, now, options);
      if (loopbackTls.refusal !== null) return loopbackTls.refusal;
    }
    return Object.freeze({
      status: "allowed",
      exposure: "loopback",
      transport: request.tls === undefined ? "http" : "https",
      target: bindTarget(request.hostname, request.port),
      administratorVerified: false,
    });
  }
  if (request.tls === undefined) {
    return refuse(
      "tls-missing",
      "a non-loopback bind requires application TLS; plaintext is refused",
    );
  }
  const tls = validatedTlsMaterial(request.tls, now, options);
  if (tls.refusal !== null) return tls.refusal;
  const identityRefusal = certificateIdentityRefusal(tls.certificate, request);
  if (identityRefusal !== null) return identityRefusal;
  const administratorRefusal = validatedAdministrator(request.administrator, request, options, now);
  if (administratorRefusal !== null) return administratorRefusal;
  return Object.freeze({
    status: "allowed",
    exposure: "public",
    transport: "https",
    target: bindTarget(request.hostname, request.port),
    administratorVerified: true,
  });
}

/** Throw unless the bind is admitted. Callers must run this before opening any listener. */
export function assertBindAllowed(
  request: BindRequest,
  options: BindPolicyOptions = {},
): AllowedBind {
  const decision = evaluateBindPolicy(request, options);
  if (decision.status === "refused") throw new BindPolicyError(decision);
  return decision;
}
