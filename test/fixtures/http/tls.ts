import { createPrivateKey, generateKeyPairSync, sign } from "node:crypto";

/**
 * Lane-local TLS material for bind-policy probes.
 *
 * The certificates are generated in-process rather than committed, so no private key ever
 * enters the tracked tree. The DER is written by hand because Node exposes X.509 parsing but
 * not issuance; the result is a real certificate that `X509Certificate` parses and
 * `checkPrivateKey` verifies, which is what the bind policy actually depends on.
 */

function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  let rest = length;
  while (rest > 0) {
    bytes.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function sequence(...parts: readonly Buffer[]): Buffer {
  return tlv(0x30, Buffer.concat(parts));
}

function derSet(...parts: readonly Buffer[]): Buffer {
  return tlv(0x31, Buffer.concat(parts));
}

const OID_ED25519 = Buffer.from([0x06, 0x03, 0x2b, 0x65, 0x70]);
const OID_COMMON_NAME = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]);
const OID_SUBJECT_ALT_NAME = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x11]);
const OID_BASIC_CONSTRAINTS = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x13]);
const DER_TRUE = Buffer.from([0xff]);
const PEM_DELIMITER = "-".repeat(5);

const GENERAL_NAME_DNS = 0x82;
const GENERAL_NAME_IP = 0x87;

function ipv4Octets(literal: string): Buffer | null {
  const parts = literal.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => Number(part));
  const valid = octets.every((octet, index) =>
    /^\d{1,3}$/.test(parts[index] ?? "") && Number.isSafeInteger(octet)
    && octet >= 0 && octet <= 255);
  return valid ? Buffer.from(octets) : null;
}

/** One side of a `::` elision, as 16-bit groups; a trailing dotted quad counts as two. */
function ipv6Groups(section: string): readonly number[] | null {
  if (section.length === 0) return [];
  const parts = section.split(":");
  const groups: number[] = [];
  for (const [index, part] of parts.entries()) {
    if (index === parts.length - 1 && part.includes(".")) {
      const embedded = ipv4Octets(part);
      if (embedded === null) return null;
      const [a = 0, b = 0, c = 0, d = 0] = embedded;
      groups.push((a << 8) | b, (c << 8) | d);
      continue;
    }
    if (!/^[0-9a-f]{1,4}$/i.test(part)) return null;
    groups.push(Number.parseInt(part, 16));
  }
  return groups;
}

function ipv6Octets(literal: string): Buffer | null {
  if (!literal.includes(":")) return null;
  const halves = literal.split("::");
  if (halves.length > 2) return null;
  const head = ipv6Groups(halves[0] ?? "");
  const tail = halves.length === 2 ? ipv6Groups(halves[1] ?? "") : [];
  if (head === null || tail === null) return null;
  const elided = 8 - head.length - tail.length;
  // Without `::` the address must already be eight groups; with it, the elision must stand for
  // at least one. Accepting a zero-width elision would make two spellings of different
  // addresses collide on one certificate entry.
  if (halves.length === 2 ? elided < 1 : elided !== 0) return null;
  const groups = [...head, ...Array.from({ length: Math.max(elided, 0) }, () => 0), ...tail];
  const octets = Buffer.alloc(16);
  for (const [index, group] of groups.entries()) octets.writeUInt16BE(group, index * 2);
  return octets;
}

function ipAddressOctets(literal: string): Buffer | null {
  return ipv4Octets(literal) ?? ipv6Octets(literal);
}

/**
 * subjectAltName, the extension a modern client actually reads. Names that parse as an IP
 * literal are emitted as `iPAddress` — four octets for IPv4, sixteen for IPv6 — and everything
 * else as `dNSName`, which is the same split `X509Certificate.checkIP` and `checkHost` make on
 * the verifying side. An IPv6 name reaching `dNSName` instead would never match a bind target,
 * because `checkIP` is the only side of that split an address literal is compared against.
 */
function subjectAltNameExtension(names: readonly string[]): Buffer {
  const generalNames = names.map((name) => {
    const octets = ipAddressOctets(name);
    return octets === null
      ? tlv(GENERAL_NAME_DNS, Buffer.from(name, "ascii"))
      : tlv(GENERAL_NAME_IP, octets);
  });
  const extensionValue = sequence(...generalNames);
  return sequence(OID_SUBJECT_ALT_NAME, tlv(0x04, extensionValue));
}

/**
 * basicConstraints with `cA` set, marked critical. A certificate that signs another certificate is
 * a CA, and every real validator refuses to treat one without this extension as an issuer; a
 * fixture that omitted it would be asking admission to accept a chain no client would.
 */
function basicConstraintsExtension(): Buffer {
  return sequence(
    OID_BASIC_CONSTRAINTS,
    tlv(0x01, DER_TRUE),
    tlv(0x04, sequence(tlv(0x01, DER_TRUE))),
  );
}

function utcTime(date: Date): Buffer {
  const pad = (value: number): string => String(value).padStart(2, "0");
  const text = `${pad(date.getUTCFullYear() % 100)}${pad(date.getUTCMonth() + 1)}`
    + `${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}`
    + `${pad(date.getUTCSeconds())}Z`;
  return tlv(0x17, Buffer.from(text, "ascii"));
}

function distinguishedName(commonName: string): Buffer {
  return sequence(derSet(sequence(OID_COMMON_NAME, tlv(0x0c, Buffer.from(commonName, "utf8")))));
}

/** Wrap DER as a labelled PEM block. */
export function pemBlock(label: string, der: Buffer): string {
  const body = der.toString("base64").replace(/(.{64})/g, "$1\n").trimEnd();
  const open = `${PEM_DELIMITER}BEGIN ${label}${PEM_DELIMITER}`;
  const close = `${PEM_DELIMITER}END ${label}${PEM_DELIMITER}`;
  return `${open}\n${body}\n${close}\n`;
}

export interface GeneratedTlsMaterial {
  readonly certificatePem: string;
  readonly privateKeyPem: string;
}

export interface CertificateWindow {
  readonly commonName?: string;
  /** Names placed in subjectAltName. Omitted entirely when empty, leaving a CN-only certificate. */
  readonly dnsNames?: readonly string[];
  /** Whether the certificate carries `basicConstraints: cA=TRUE`; required of any issuer. */
  readonly ca?: boolean;
  readonly notBefore: Date;
  readonly notAfter: Date;
}

/** Who signed a certificate. Absent means the certificate signs itself. */
export interface CertificateIssuer {
  readonly commonName: string;
  readonly privateKeyPem: string;
}

/**
 * Issue an Ed25519 certificate valid across the requested window, signed by `issuer` or by its own
 * key when no issuer is given. The issuer's name goes in the issuer field and the issuer's key
 * makes the signature, so a certificate produced here verifies against exactly the certificate a
 * chain would have to supply for it — which is what admission checks.
 */
export function issuedTlsMaterial(
  window: CertificateWindow,
  issuer?: CertificateIssuer,
): GeneratedTlsMaterial {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const subjectPublicKeyInfo = publicKey.export({ type: "spki", format: "der" });
  const algorithm = sequence(OID_ED25519);
  const commonName = window.commonName ?? "dacs-forge-lane";
  const alternativeNames = window.dnsNames ?? [];
  const declared = [
    ...(alternativeNames.length === 0 ? [] : [subjectAltNameExtension(alternativeNames)]),
    ...(window.ca === true ? [basicConstraintsExtension()] : []),
  ];
  const extensions = declared.length === 0 ? [] : [tlv(0xa3, sequence(...declared))];
  const tbsCertificate = sequence(
    tlv(0xa0, tlv(0x02, Buffer.from([0x02]))),
    tlv(0x02, Buffer.from([0x01])),
    algorithm,
    distinguishedName(issuer?.commonName ?? commonName),
    sequence(utcTime(window.notBefore), utcTime(window.notAfter)),
    distinguishedName(commonName),
    subjectPublicKeyInfo,
    ...extensions,
  );
  let signer = privateKey;
  if (issuer !== undefined) {
    signer = createPrivateKey(issuer.privateKeyPem);
  }
  const signature = sign(null, tbsCertificate, signer);
  const certificate = sequence(
    tbsCertificate,
    algorithm,
    tlv(0x03, Buffer.concat([Buffer.from([0x00]), signature])),
  );
  return Object.freeze({
    certificatePem: pemBlock("CERTIFICATE", certificate),
    privateKeyPem: String(privateKey.export({ type: "pkcs8", format: "pem" })),
  });
}

/** Issue a self-signed Ed25519 certificate valid across the requested window. */
export function selfSignedTlsMaterial(window: CertificateWindow): GeneratedTlsMaterial {
  return issuedTlsMaterial(window);
}

/** A clock inside the window of {@link currentTlsMaterial}, pinned so probes never rot. */
export const FIXED_NOW = new Date("2030-06-01T00:00:00Z");

export function currentTlsMaterial(dnsNames: readonly string[] = []): GeneratedTlsMaterial {
  return selfSignedTlsMaterial({
    dnsNames,
    notBefore: new Date("2026-01-01T00:00:00Z"),
    notAfter: new Date("2040-01-01T00:00:00Z"),
  });
}

/** Independent key material used to prove certificate/key mismatch is detected. */
export function unrelatedPrivateKeyPem(): string {
  return selfSignedTlsMaterial({
    commonName: "unrelated",
    notBefore: new Date("2026-01-01T00:00:00Z"),
    notAfter: new Date("2040-01-01T00:00:00Z"),
  }).privateKeyPem;
}
