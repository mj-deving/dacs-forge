import { describe, expect, test } from "bun:test";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  BIND_OPERATION,
  BindPolicyError,
  assertBindAllowed,
  evaluateBindPolicy,
  isLoopbackHostname,
  type AdministratorPresentation,
  type BindDecision,
  type BindPolicyOptions,
  type PathFacts,
  type TcpBindRequest,
  type TlsMaterial,
} from "../../src/http/bind-policy.ts";
import {
  FIXED_NOW,
  currentTlsMaterial,
  issuedTlsMaterial,
  pemBlock,
  selfSignedTlsMaterial,
  unrelatedPrivateKeyPem,
} from "../fixtures/http/tls.ts";

/**
 * The same certificate with one signature byte flipped. Everything a presenter controls — subject,
 * key, dates, names — is untouched, so only a real signature check can tell the two apart.
 */
function corruptedSignature(certificatePem: string): string {
  const parts = certificatePem.split("-----");
  const der = Buffer.from((parts[2] ?? "").replace(/\s/g, ""), "base64");
  const last = der.length - 1;
  der[last] = (der[last] ?? 0) ^ 0xff;
  return pemBlock("CERTIFICATE", der);
}

const PRINCIPAL = "bind-administrator@dacs-forge.invalid";
const PUBLIC_HOSTNAME = "service.dacs-forge.invalid";
const PUBLIC_PORT = 8443;

/**
 * Real mode-0600 files owned by whoever runs the suite, so the provenance every fixture carries is
 * evidence the policy actually observes on the filesystem rather than a stub answer. Admission
 * opens these paths; a fabricated one would be refused, which is the point of the contract.
 */
const SECRET_DIRECTORY = realpathSync(mkdtempSync(join(tmpdir(), "dacs-bind-secret-")));
const SECRET_FILES = new Map<string, string>();

/**
 * Provenance for a secret, backed by a file that holds exactly that secret. Written per secret
 * rather than once, because a single shared file would make every fixture cite a file it did not
 * come from — which is the defect these probes exist to catch, not a convenience to keep.
 */
function fileProvenance(secret: string): { readonly kind: "file-0600"; readonly path: string } {
  const existing = SECRET_FILES.get(secret);
  if (existing !== undefined) return { kind: "file-0600", path: existing };
  const path = join(SECRET_DIRECTORY, `secret-${SECRET_FILES.size}.pem`);
  writeFileSync(path, secret, { mode: 0o600 });
  chmodSync(path, 0o600);
  SECRET_FILES.set(secret, path);
  return { kind: "file-0600", path };
}

const CAPABILITY_ID = "cap-bind-001";
const CAPABILITY_PROVENANCE = fileProvenance(CAPABILITY_ID);

/**
 * The directories above `/run/dacs` as an ordinary host has them: root-owned and not writable by
 * other accounts. Admission walks the whole chain, so a stub that answered only for the immediate
 * parent would be describing a host where the socket's grandparent does not exist.
 */
const ORDINARY_ANCESTORS: Readonly<Record<string, PathFacts>> = {
  "/run": { mode: 0o755, isSocket: false, isDirectory: true, isSymbolicLink: false, uid: 0 },
  "/": { mode: 0o755, isSocket: false, isDirectory: true, isSymbolicLink: false, uid: 0 },
};

/**
 * Every path a stub is not asked about is absent. Thrown with the `code` a real `stat` carries,
 * because admission distinguishes absence from a path it could not observe and a bare `Error`
 * would be the second thing while the fixture means the first.
 */
function raiseMissing(): never {
  throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
}

/** Facts for an ancestor of the socket parent, or `undefined` when the path is not one. */
function ancestorFacts(path: string): PathFacts | undefined {
  return ORDINARY_ANCESTORS[path];
}
/** One unrelated key, hoisted so the file backing it stays the file that holds it. */
const UNRELATED_PRIVATE_KEY = unrelatedPrivateKeyPem();

function tlsMaterial(overrides: Partial<TlsMaterial> = {}): TlsMaterial {
  const material = currentTlsMaterial([PUBLIC_HOSTNAME]);
  return {
    certificatePem: material.certificatePem,
    privateKeyPem: material.privateKeyPem,
    privateKeyChannel: "file-0600",
    privateKeyProvenance: fileProvenance(material.privateKeyPem),
    ...overrides,
  };
}

type BindCapability = AdministratorPresentation["capability"];

function capabilityShape(overrides: Partial<BindCapability> = {}): BindCapability {
  return {
    id: CAPABILITY_ID,
    principal: PRINCIPAL,
    operations: [BIND_OPERATION],
    expiresAt: "2030-12-01T00:00:00Z",
    boundHostname: PUBLIC_HOSTNAME,
    boundPort: PUBLIC_PORT,
    ...overrides,
  };
}

/**
 * What this deployment actually issued. Authenticity is membership here, compared over every field
 * the capability carries. Matching on `id` alone would admit a capability that kept the issued
 * identifier and rewrote everything else — an extended `expiresAt` reviving a capability the
 * deployment let lapse — which is precisely the forgery the authenticity seam exists to refuse, so
 * a verifier that shape would leave every allow probe below proving nothing about it.
 */
const ISSUED: BindCapability[] = [];

function issue(overrides: Partial<BindCapability> = {}): BindCapability {
  const capability = capabilityShape(overrides);
  ISSUED.push(capability);
  return capability;
}

function sameCapability(issued: BindCapability, presented: BindCapability): boolean {
  return issued.id === presented.id
    && issued.principal === presented.principal
    && issued.expiresAt === presented.expiresAt
    && issued.boundHostname === presented.boundHostname
    && issued.boundPort === presented.boundPort
    && issued.operations.length === presented.operations.length
    && issued.operations.every((operation, index) => operation === presented.operations[index]);
}

function administrator(
  overrides: Partial<BindCapability> = {},
  channel: AdministratorPresentation["channel"] = "file-0600",
  provenance: AdministratorPresentation["provenance"] = CAPABILITY_PROVENANCE,
): AdministratorPresentation {
  return { channel, provenance, capability: capabilityShape(overrides) };
}

/**
 * `tls` and `administrator` are optional on the request, so an override that removes them must
 * omit the property rather than set it to `undefined`; the policy distinguishes the two.
 */
interface PublicBindOverrides {
  readonly hostname?: string;
  readonly port?: number;
  readonly tls?: TlsMaterial | undefined;
  readonly administrator?: AdministratorPresentation | undefined;
}

function publicBind(overrides: PublicBindOverrides = {}): TcpBindRequest {
  const tls = "tls" in overrides ? overrides.tls : tlsMaterial();
  const admin = "administrator" in overrides ? overrides.administrator : administrator();
  return {
    kind: "tcp",
    hostname: overrides.hostname ?? PUBLIC_HOSTNAME,
    port: overrides.port ?? PUBLIC_PORT,
    ...(tls === undefined ? {} : { tls }),
    ...(admin === undefined ? {} : { administrator: admin }),
  };
}

/**
 * A deployment that authenticates exactly the capabilities it issued, field for field. Modelled as
 * knowledge rather than as `() => true`, because a verifier that says yes to everything is the very
 * failure this seam exists to prevent and would make every allow-case below prove nothing.
 */
const options: BindPolicyOptions = {
  administratorPrincipal: PRINCIPAL,
  now: () => FIXED_NOW,
  verifyAdministratorAuthenticity: (capability) =>
    ISSUED.some((record) => sameCapability(record, capability)),
};

// The capability every ordinary probe presents, and the only one issued until a test issues more.
issue();

describe("bind admission for the terminal HTTP transport", () => {
  test("allows every loopback form over plaintext without administrator authority", () => {
    // The last four are one address each in a different spelling: hexadecimal IPv4-mapped,
    // compressed and fully-expanded `::1`, and the bracket form. All are 127-block or `::1` and
    // must classify as loopback, not fall to the exposed branch that would demand TLS.
    for (const hostname of ["127.0.0.1", "::1", "127.0.0.7", "::ffff:127.0.0.1", "[::1]",
      "::ffff:7f00:1", "::ffff:7f00:0001", "0:0:0:0:0:0:0:1", "[::ffff:127.0.0.1]"]) {
      expect(isLoopbackHostname(hostname)).toBe(true);
      const decision = evaluateBindPolicy({ kind: "tcp", hostname, port: 0 }, options);
      expect(decision).toMatchObject({
        status: "allowed",
        exposure: "loopback",
        transport: "http",
        administratorVerified: false,
      });
    }
  });

  test("validates TLS material offered on loopback instead of assuming https", () => {
    const valid = currentTlsMaterial();
    expect(evaluateBindPolicy(
      { kind: "tcp", hostname: "127.0.0.1", port: 0, tls: tlsMaterial() },
      options,
    )).toMatchObject({ status: "allowed", exposure: "loopback", transport: "https" });

    expect(evaluateBindPolicy(
      {
        kind: "tcp",
        hostname: "127.0.0.1",
        port: 0,
        tls: {
          certificatePem: valid.certificatePem,
          privateKeyPem: UNRELATED_PRIVATE_KEY,
          privateKeyChannel: "file-0600",
          privateKeyProvenance: fileProvenance(UNRELATED_PRIVATE_KEY),
        },
      },
      options,
    )).toMatchObject({ status: "refused", code: "tls-certificate-invalid" });

    expect(evaluateBindPolicy(
      {
        kind: "tcp",
        hostname: "127.0.0.1",
        port: 0,
        tls: tlsMaterial({ privateKeyChannel: "environment" }),
      },
      options,
    )).toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
  });

  test("reports an IPv6 target as a bracketed authority however the caller spelled it", () => {
    // `::1:0` is not an RFC 3986 authority, and the bracketed and bare spellings of the same
    // admitted endpoint must not produce two different identities.
    expect(evaluateBindPolicy({ kind: "tcp", hostname: "::1", port: 0 }, options))
      .toMatchObject({ status: "allowed", target: "[::1]:0" });
    expect(evaluateBindPolicy({ kind: "tcp", hostname: "[::1]", port: 0 }, options))
      .toMatchObject({ status: "allowed", target: "[::1]:0" });
    expect(evaluateBindPolicy({ kind: "tcp", hostname: "127.0.0.1", port: 8080 }, options))
      .toMatchObject({ status: "allowed", target: "127.0.0.1:8080" });
  });

  test("matches capability scope on the normalized target, not the raw spelling", () => {
    const address = "2001:DB8::1";
    // The certificate must name every requested target, because identity is checked *before*
    // scope: a certificate that does not name the target refuses at `tls-certificate-hostname-
    // mismatch` and the capability comparison never runs, which would make each row below pass
    // no matter how scope were compared.
    const material = currentTlsMaterial([PUBLIC_HOSTNAME, "2001:db8::1"]);
    const scoped = (boundHostname: string): AdministratorPresentation => {
      // Every spelling below is a capability the deployment issued for that endpoint. The one row
      // that must refuse is scoped elsewhere and is deliberately left unissued, so it refuses on
      // scope — which is checked before authenticity — either way.
      issue({ boundHostname, boundPort: PUBLIC_PORT });
      return administrator({ boundHostname, boundPort: PUBLIC_PORT });
    };

    // Case, bracket, and compression spellings of one endpoint are one identity, so a capability
    // issued for any form admits any request for it. The fully-expanded row is the one a purely
    // textual compare fails: `2001:db8::1` and `2001:0db8:0:0:0:0:0:1` are the same 16 bytes and
    // must not refuse a correctly scoped capability over the difference.
    for (const [bound, requested] of [
      ["2001:db8::1", "[2001:DB8::1]"],
      ["[2001:db8::1]", "2001:db8::1"],
      ["2001:0db8:0:0:0:0:0:1", "2001:db8::1"],
      ["2001:db8::1", "2001:0DB8:0000:0000:0000:0000:0000:0001"],
      [PUBLIC_HOSTNAME.toUpperCase(), PUBLIC_HOSTNAME],
    ] as const) {
      const decision = evaluateBindPolicy({
        kind: "tcp",
        hostname: requested,
        port: PUBLIC_PORT,
        tls: {
          certificatePem: material.certificatePem,
          privateKeyPem: material.privateKeyPem,
          privateKeyChannel: "file-0600",
          privateKeyProvenance: fileProvenance(material.privateKeyPem),
        },
        administrator: scoped(bound),
      }, options);
      expect(decision).toMatchObject({
        status: "allowed",
        exposure: "public",
        administratorVerified: true,
      });
    }

    expect(evaluateBindPolicy(publicBind({ administrator: scoped(address) }), options))
      .toMatchObject({ status: "refused", code: "administrator-scope-mismatch" });
  });

  test("refuses a socket parent that is not a trusted service-owned directory", () => {
    // Mode bits alone are not protection. A mode-0600 regular file has no bit that says "not a
    // directory", and a mode-0700 directory owned by another account is writable by that
    // account, which can unlink the socket after this service binds it and answer in its place.
    const facts = (overrides: Partial<PathFacts>): PathFacts => ({
      mode: 0o700,
      isSocket: false,
      isDirectory: true,
      isSymbolicLink: false,
      uid: 1_000,
      ...overrides,
    });
    const decide = (parent: PathFacts, target?: PathFacts): BindDecision =>
      evaluateBindPolicy({ kind: "unix-socket", path: "/run/dacs/forge.sock" }, {
        serviceUid: 1_000,
        realPath: (path) => path,
        statPath: (path) => {
          if (path === "/run/dacs") return parent;
          const ancestor = ancestorFacts(path);
          if (ancestor !== undefined) return ancestor;
          if (target === undefined) raiseMissing();
          return target;
        },
      });

    expect(decide(facts({}))).toMatchObject({ status: "allowed", exposure: "unix-socket" });
    expect(decide(facts({ isDirectory: false, mode: 0o600 })))
      .toMatchObject({ status: "refused", code: "unix-socket-path-invalid" });
    expect(decide(facts({ uid: 4_242 })))
      .toMatchObject({ status: "refused", code: "unix-socket-not-protected" });
    // A root-owned mode-0700 parent is safe from substitution but a service running as uid 1000
    // cannot traverse or write it, so the bind would fail EACCES after admission said yes.
    // Admission refuses it rather than admit a path this service cannot create the socket in.
    expect(decide(facts({ uid: 0 })))
      .toMatchObject({ status: "refused", code: "unix-socket-not-protected" });
    // The same root-owned parent is usable when the service itself is root, which can traverse it.
    expect(evaluateBindPolicy({ kind: "unix-socket", path: "/run/dacs/forge.sock" }, {
      serviceUid: 0,
      realPath: (path) => path,
      statPath: (path) => {
        if (path === "/run/dacs") return facts({ uid: 0 });
        return ancestorFacts(path) ?? raiseMissing();
      },
    })).toMatchObject({ status: "allowed", exposure: "unix-socket" });
    // Root can traverse a 0700 directory owned by anyone, so "can this service create the socket
    // here" answers yes for every owner when the service is root. That must not be read as "this
    // owner is trustworthy": uid 4242 still owns the directory and can unlink the socket after
    // bind and answer in the service's place. Both questions are asked, so this is refused.
    expect(evaluateBindPolicy({ kind: "unix-socket", path: "/run/dacs/forge.sock" }, {
      serviceUid: 0,
      realPath: (path) => path,
      statPath: (path) => {
        if (path === "/run/dacs") return facts({ uid: 4_242 });
        return ancestorFacts(path) ?? raiseMissing();
      },
    })).toMatchObject({ status: "refused", code: "unix-socket-not-protected" });
    // A symlinked parent presents someone else's protected directory: `stat` follows the link and
    // reports the 0700 service-owned directory it landed on, so every fact above says protected
    // while the path admitted is the link. Admission compares the resolution to the lexical path
    // and refuses the mismatch, so protection is asserted about the path that was named.
    // Both resolution probes answer facts only for the parent and ENOENT for the socket itself,
    // which is the shape that would otherwise be ALLOWED. A stub answering for the socket path too
    // would refuse it as the wrong file type and pass this assertion without the check existing.
    const resolutionStub = (path: string): PathFacts => {
      if (path === "/run/dacs") return facts({});
      return ancestorFacts(path) ?? raiseMissing();
    };
    expect(evaluateBindPolicy({ kind: "unix-socket", path: "/run/dacs/forge.sock" }, {
      serviceUid: 1_000,
      realPath: () => "/srv/attacker/run",
      statPath: resolutionStub,
    })).toMatchObject({ status: "refused", code: "unix-socket-not-protected" });
    // Fails closed: a parent whose resolution cannot be taken is not a parent whose protection was
    // observed, so admission refuses rather than fall back to the unresolved path.
    expect(evaluateBindPolicy({ kind: "unix-socket", path: "/run/dacs/forge.sock" }, {
      serviceUid: 1_000,
      realPath: () => { throw new Error("ELOOP"); },
      statPath: resolutionStub,
    })).toMatchObject({ status: "refused", code: "unix-socket-path-invalid" });
    const foreignSocket = facts({ isSocket: true, isDirectory: false, mode: 0o600, uid: 4_242 });
    expect(decide(facts({}), foreignSocket))
      .toMatchObject({ status: "refused", code: "unix-socket-not-protected" });
    expect(decide(facts({}), facts({ isSocket: true, isDirectory: false, mode: 0o600 })))
      .toMatchObject({ status: "allowed" });
    // A leftover socket this service itself created: `bind` derives the mode from the umask, so
    // under the common 022 the kernel writes 0755 and no caller chose it. Refusing that would
    // make a restart need an operator to unlink the file by hand, and would refuse nothing an
    // attacker could reach — the parent directory already grants group and other nothing.
    expect(decide(facts({}), facts({ isSocket: true, isDirectory: false, mode: 0o755 })))
      .toMatchObject({ status: "allowed", exposure: "unix-socket" });
    const foreignLeftover = facts({ isSocket: true, isDirectory: false, mode: 0o755, uid: 4_242 });
    expect(decide(facts({}), foreignLeftover))
      .toMatchObject({ status: "refused", code: "unix-socket-not-protected" });
  });

  test("refuses a socket path the kernel could not bind", () => {
    const longPath = `/tmp/${"s".repeat(120)}.sock`;
    expect(evaluateBindPolicy({ kind: "unix-socket", path: longPath }))
      .toMatchObject({ status: "refused", code: "unix-socket-path-invalid" });
  });

  test("refuses an exposed bind whose certificate names something else", () => {
    const foreign = currentTlsMaterial(["other.dacs-forge.invalid"]);
    expect(evaluateBindPolicy(
      publicBind({
        tls: {
          certificatePem: foreign.certificatePem,
          privateKeyPem: foreign.privateKeyPem,
          privateKeyChannel: "file-0600",
          privateKeyProvenance: fileProvenance(foreign.privateKeyPem),
        },
      }),
      options,
    )).toMatchObject({ status: "refused", code: "tls-certificate-hostname-mismatch" });

    // A certificate carrying the target in subjectAltName is what admission actually requires.
    expect(evaluateBindPolicy(publicBind(), options)).toMatchObject({ status: "allowed" });
  });

  test("binds certificate identity for an exposed IP literal through iPAddress", () => {
    const address = "203.0.113.7";
    const matching = currentTlsMaterial([address]);
    const mismatched = currentTlsMaterial(["203.0.113.8"]);
    // Issued for this endpoint, so the allow row below turns on identity and scope rather than on
    // the deployment happening to authenticate a capability it never issued.
    issue({ boundHostname: address });
    const capability = administrator({ boundHostname: address });
    const bindRequest = (
      source: { certificatePem: string; privateKeyPem: string },
    ): TcpBindRequest => ({
      kind: "tcp",
      hostname: address,
      port: PUBLIC_PORT,
      tls: {
        certificatePem: source.certificatePem,
        privateKeyPem: source.privateKeyPem,
        privateKeyChannel: "file-0600",
        privateKeyProvenance: fileProvenance(source.privateKeyPem),
      },
      administrator: capability,
    });

    expect(evaluateBindPolicy(bindRequest(mismatched), options))
      .toMatchObject({ status: "refused", code: "tls-certificate-hostname-mismatch" });
    expect(evaluateBindPolicy(bindRequest(matching), options))
      .toMatchObject({ status: "allowed", exposure: "public", transport: "https" });
  });

  test("does not mistake a neighbouring address for loopback", () => {
    for (const hostname of ["128.0.0.1", "10.0.0.1", "::2", "127.0.0.256", "evil.127.0.0.1"]) {
      expect(isLoopbackHostname(hostname)).toBe(false);
    }
    const decision = evaluateBindPolicy({ kind: "tcp", hostname: "128.0.0.1", port: 443 }, options);
    expect(decision).toMatchObject({ status: "refused", code: "tls-missing" });
  });

  test("allows a protected Unix socket and refuses an exposed one", () => {
    // Canonical: admission refuses a parent whose resolution differs from its lexical path, and
    // `tmpdir()` is itself a symlink on some platforms. Resolving here keeps the probe a real
    // filesystem probe while asking the question a deployment actually asks, about a real path.
    const directory = realpathSync(mkdtempSync(join(tmpdir(), "dacs-bind-socket-")));
    try {
      chmodSync(directory, 0o700);
      const socketPath = join(directory, "terminal.sock");
      // No `statPath` override: the allow case must run against the real filesystem with the
      // socket absent, which is the shape a server actually hits. A stub that answers for both
      // the parent directory and the target would assert the outcome it is meant to prove.
      const allowed = evaluateBindPolicy({ kind: "unix-socket", path: socketPath });
      expect(allowed).toMatchObject({
        status: "allowed",
        exposure: "unix-socket",
        transport: "unix",
        administratorVerified: false,
      });

      chmodSync(directory, 0o755);
      const exposed = evaluateBindPolicy({ kind: "unix-socket", path: socketPath });
      expect(exposed).toMatchObject({
        status: "refused",
        code: "unix-socket-not-protected",
      });

      chmodSync(directory, 0o700);
      writeFileSync(socketPath, "not a socket");
      const occupied = evaluateBindPolicy({ kind: "unix-socket", path: socketPath });
      expect(occupied).toMatchObject({
        status: "refused",
        code: "unix-socket-path-invalid",
      });
      expect(evaluateBindPolicy({ kind: "unix-socket", path: "relative.sock" })).toMatchObject({
        status: "refused",
        code: "unix-socket-path-invalid",
      });
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  });

  test("the socket path is judged as the entry it is, not as whatever it points at", () => {
    // A following observation reports a dangling symlink as ENOENT, and absence is the one answer
    // that lets a bind proceed — so the entry already occupying the name is admitted and `bind`
    // then fails on it, past the listener. This is a real-filesystem probe because that is where
    // the difference between `stat` and `lstat` lives; a stub could assert either answer.
    const directory = realpathSync(mkdtempSync(join(tmpdir(), "dacs-bind-entry-")));
    try {
      chmodSync(directory, 0o700);
      const socketPath = join(directory, "terminal.sock");
      const target = join(directory, "elsewhere");
      const decide = (): BindDecision =>
        evaluateBindPolicy({ kind: "unix-socket", path: socketPath });

      // Absent: the only shape that may proceed, and the baseline every row below departs from.
      expect(decide()).toMatchObject({ status: "allowed", exposure: "unix-socket" });

      // Dangling symlink: the name is occupied, nothing resolves, and a following stat calls this
      // absent. THE regression — this row is what the old behavior admitted.
      symlinkSync(join(directory, "absent-target"), socketPath);
      expect(decide()).toMatchObject({
        status: "refused",
        code: "unix-socket-path-invalid",
        reason: expect.stringContaining("symbolic link"),
      });
      rmSync(socketPath);

      // Symlink to a regular file, and to a directory: both resolve, so a following stat reports
      // the target's type and says nothing about the link that is actually in the way.
      writeFileSync(target, "not a socket");
      symlinkSync(target, socketPath);
      expect(decide()).toMatchObject({
        status: "refused",
        code: "unix-socket-path-invalid",
        reason: expect.stringContaining("symbolic link"),
      });
      rmSync(socketPath);
      rmSync(target);
      mkdirSync(target);
      symlinkSync(target, socketPath);
      expect(decide()).toMatchObject({
        status: "refused",
        code: "unix-socket-path-invalid",
        reason: expect.stringContaining("symbolic link"),
      });
      rmSync(socketPath);
      rmSync(target, { recursive: true });

      // A symlink pointing outside the parent whose protection was just established is the same
      // class: what `bind` would receive is a name resolving somewhere admission never looked.
      symlinkSync(tmpdir(), socketPath);
      expect(decide()).toMatchObject({
        status: "refused",
        code: "unix-socket-path-invalid",
        reason: expect.stringContaining("symbolic link"),
      });
      rmSync(socketPath);

      // The non-link occupants still refuse for what they are, so the new class took nothing over.
      writeFileSync(socketPath, "not a socket");
      expect(decide()).toMatchObject({
        status: "refused",
        code: "unix-socket-path-invalid",
        reason: expect.stringContaining("another file type"),
      });
      rmSync(socketPath);
      mkdirSync(socketPath);
      expect(decide()).toMatchObject({ status: "refused", code: "unix-socket-path-invalid" });
      rmSync(socketPath, { recursive: true });
      // And absence still means absence once the entry is gone.
      expect(decide()).toMatchObject({ status: "allowed", exposure: "unix-socket" });
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  });

  test("a link to a live socket is not the leftover socket it resolves to", () => {
    // The sibling a real filesystem cannot show without opening a listener: an entry a following
    // observation would have called a service-owned socket, admissible as this service's own
    // leftover, while the entry itself is a link that resolves out of the protected directory.
    const parent: PathFacts = {
      mode: 0o700, isSocket: false, isDirectory: true, isSymbolicLink: false, uid: 1_000,
    };
    const entry = (overrides: Partial<PathFacts>): PathFacts => ({
      mode: 0o755, isSocket: true, isDirectory: false, isSymbolicLink: false, uid: 1_000,
      ...overrides,
    });
    const decide = (existing: PathFacts): BindDecision =>
      evaluateBindPolicy({ kind: "unix-socket", path: "/run/dacs/forge.sock" }, {
        serviceUid: 1_000,
        realPath: (path) => path,
        statPath: (path) => {
          if (path === "/run/dacs") return parent;
          return ancestorFacts(path) ?? existing;
        },
      });

    // Byte-for-byte what a following stat reports for a link to this service's own socket.
    expect(decide(entry({}))).toMatchObject({ status: "allowed", exposure: "unix-socket" });
    // The same facts plus the one the entry itself carries.
    expect(decide(entry({ isSymbolicLink: true }))).toMatchObject({
      status: "refused",
      code: "unix-socket-path-invalid",
      reason: expect.stringContaining("symbolic link"),
    });
  });

  test("refuses a plaintext non-loopback bind before any listener exists", () => {
    const decision = evaluateBindPolicy(
      publicBind({ tls: undefined, administrator: administrator() }),
      options,
    );
    expect(decision).toMatchObject({ status: "refused", code: "tls-missing" });
  });

  test("refuses every invalid certificate class", () => {
    const valid = currentTlsMaterial();

    expect(evaluateBindPolicy(
      publicBind({ tls: tlsMaterial({ certificatePem: "not-a-certificate" }) }),
      options,
    )).toMatchObject({ status: "refused", code: "tls-certificate-invalid" });

    expect(evaluateBindPolicy(
      publicBind({
        tls: {
          certificatePem: valid.certificatePem,
          privateKeyPem: UNRELATED_PRIVATE_KEY,
          privateKeyChannel: "file-0600",
          privateKeyProvenance: fileProvenance(UNRELATED_PRIVATE_KEY),
        },
      }),
      options,
    )).toMatchObject({ status: "refused", code: "tls-certificate-invalid" });

    const expired = selfSignedTlsMaterial({
      notBefore: new Date("2026-01-01T00:00:00Z"),
      notAfter: new Date("2027-01-01T00:00:00Z"),
    });
    expect(evaluateBindPolicy(
      publicBind({
        tls: {
          certificatePem: expired.certificatePem,
          privateKeyPem: expired.privateKeyPem,
          privateKeyChannel: "file-0600",
          privateKeyProvenance: fileProvenance(expired.privateKeyPem),
        },
      }),
      options,
    )).toMatchObject({ status: "refused", code: "tls-certificate-invalid" });

    const future = selfSignedTlsMaterial({
      notBefore: new Date("2039-01-01T00:00:00Z"),
      notAfter: new Date("2040-01-01T00:00:00Z"),
    });
    expect(evaluateBindPolicy(
      publicBind({
        tls: {
          certificatePem: future.certificatePem,
          privateKeyPem: future.privateKeyPem,
          privateKeyChannel: "file-0600",
          privateKeyProvenance: fileProvenance(future.privateKeyPem),
        },
      }),
      options,
    )).toMatchObject({ status: "refused", code: "tls-certificate-invalid" });
  });

  test("refuses TLS keys and capabilities from unapproved secret channels", () => {
    for (const channel of ["argv", "environment", "inline"] as const) {
      expect(evaluateBindPolicy(
        publicBind({ tls: tlsMaterial({ privateKeyChannel: channel }) }),
        options,
      )).toMatchObject({ status: "refused", code: "secret-channel-not-approved" });

      expect(evaluateBindPolicy(
        publicBind({ administrator: administrator({}, channel) }),
        options,
      )).toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
    }
  });

  test("refuses every invalid bind-scoped administrator class", () => {
    const cases: readonly (readonly [string, TcpBindRequest, BindPolicyOptions])[] = [
      ["administrator-missing", publicBind({ administrator: undefined }), options],
      [
        "administrator-malformed",
        publicBind({
          administrator: administrator({ operations: [] as unknown as readonly string[] }),
        }),
        options,
      ],
      [
        "administrator-malformed",
        publicBind({ administrator: administrator({ expiresAt: "not-a-timestamp" }) }),
        options,
      ],
      [
        "administrator-expired",
        publicBind({ administrator: administrator({ expiresAt: "2029-01-01T00:00:00Z" }) }),
        options,
      ],
      [
        "administrator-revoked",
        publicBind(),
        { ...options, revokedCapabilityIds: ["cap-bind-001"] },
      ],
      [
        "administrator-wrong-principal",
        publicBind({ administrator: administrator({ principal: "someone-else@invalid" }) }),
        options,
      ],
      [
        "administrator-wrong-operation",
        publicBind({ administrator: administrator({ operations: ["http.read"] }) }),
        options,
      ],
      [
        "administrator-scope-mismatch",
        publicBind({ administrator: administrator({ boundPort: 9443 }) }),
        options,
      ],
      [
        "administrator-scope-mismatch",
        publicBind({ administrator: administrator({ boundHostname: "other.invalid" }) }),
        options,
      ],
    ];

    for (const [code, request, caseOptions] of cases) {
      expect(evaluateBindPolicy(request, caseOptions)).toMatchObject({ status: "refused", code });
    }
  });

  test("refuses a non-loopback bind when the deployment declares no administrator", () => {
    expect(evaluateBindPolicy(publicBind(), { now: () => FIXED_NOW })).toMatchObject({
      status: "refused",
      code: "administrator-wrong-principal",
    });
  });

  test("admits a non-loopback bind only with valid TLS and current bind authority", () => {
    const decision = evaluateBindPolicy(publicBind(), options);
    expect(decision).toEqual({
      status: "allowed",
      exposure: "public",
      transport: "https",
      target: `${PUBLIC_HOSTNAME}:${PUBLIC_PORT}`,
      administratorVerified: true,
    });
  });

  test("refuses malformed hostnames and ports before evaluating any authority", () => {
    expect(evaluateBindPolicy({ kind: "tcp", hostname: "", port: 443 }, options))
      .toMatchObject({ status: "refused", code: "hostname-invalid" });
    expect(evaluateBindPolicy({ kind: "tcp", hostname: "host ", port: 443 }, options))
      .toMatchObject({ status: "refused", code: "hostname-invalid" });
    // A target that is not a host at all must refuse as `hostname-invalid`, not fall through to
    // the TLS branch and be reported as a TLS configuration failure.
    for (const hostname of [
      "host ",
      " 127.0.0.1",
      "127.0.0.1:8080",
      "*",
      "-leading.example",
      "trailing-.example",
      "[::1",
      "[not-an-address]",
    ]) {
      expect(evaluateBindPolicy({ kind: "tcp", hostname, port: 443 }, options))
        .toMatchObject({ status: "refused", code: "hostname-invalid" });
    }
    // The forms admission does accept stay accepted.
    for (const hostname of ["127.0.0.1", "[::1]", "::ffff:127.0.0.1", "service.example."]) {
      expect(evaluateBindPolicy({ kind: "tcp", hostname, port: 443 }, options))
        .not.toMatchObject({ code: "hostname-invalid" });
    }
    expect(evaluateBindPolicy({ kind: "tcp", hostname: "127.0.0.1", port: 65_536 }, options))
      .toMatchObject({ status: "refused", code: "port-invalid" });
    expect(evaluateBindPolicy({ kind: "tcp", hostname: "127.0.0.1", port: 1.5 }, options))
      .toMatchObject({ status: "refused", code: "port-invalid" });
  });

  test("assertBindAllowed throws the refusal code and never returns a refused decision", () => {
    expect(() => assertBindAllowed(publicBind({ tls: undefined }), options))
      .toThrow(BindPolicyError);
    try {
      assertBindAllowed(publicBind({ administrator: undefined }), options);
      throw new Error("the refused bind was admitted");
    } catch (error) {
      expect(error).toBeInstanceOf(BindPolicyError);
      expect((error as BindPolicyError).code).toBe("administrator-missing");
    }
    expect(assertBindAllowed({ kind: "tcp", hostname: "127.0.0.1", port: 0 }, options).exposure)
      .toBe("loopback");
  });

  test("keeps secret material out of every refusal reason", () => {
    const material = currentTlsMaterial();
    const refusal = evaluateBindPolicy(
      publicBind({
        tls: {
          certificatePem: material.certificatePem,
          privateKeyPem: UNRELATED_PRIVATE_KEY,
          privateKeyChannel: "file-0600",
          privateKeyProvenance: fileProvenance(UNRELATED_PRIVATE_KEY),
        },
      }),
      options,
    );
    expect(refusal.status).toBe("refused");
    const serialized = JSON.stringify(refusal);
    expect(serialized).not.toContain("PRIVATE KEY");
    expect(serialized).not.toContain(material.certificatePem.slice(40, 80));
  });

  test("an approved channel must be backed by provenance, not asserted as a label", () => {
    // The channel is caller-set. Material read from argv or the environment can be labelled
    // `file-0600` and would pass the approved-channel gate on its own word, so every row here
    // keeps that label and varies only the evidence behind it.
    const material = tlsMaterial();
    // Holds the real key, so the only thing wrong with it is who may read it. A file with the
    // wrong contents would refuse for the wrong reason and prove nothing about permissions.
    const exposedFile = join(SECRET_DIRECTORY, "exposed.pem");
    writeFileSync(exposedFile, material.privateKeyPem, { mode: 0o644 });
    chmodSync(exposedFile, 0o644);

    const withProvenance = (provenance: TlsMaterial["privateKeyProvenance"]): BindDecision =>
      evaluateBindPolicy(publicBind({ tls: { ...material, privateKeyProvenance: provenance } }),
        options);

    // The baseline: the same request with real 0600 evidence is admitted, so each refusal below is
    // the provenance failing and not some other part of the request.
    expect(withProvenance(material.privateKeyProvenance)).toMatchObject({ status: "allowed" });
    // A file anyone can read is not a secret channel, whatever the label says.
    expect(withProvenance({ kind: "file-0600", path: exposedFile }))
      .toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
    // Fails closed on a path that cannot be observed at all, rather than trusting the label.
    expect(withProvenance({ kind: "file-0600", path: join(SECRET_DIRECTORY, "absent.pem") }))
      .toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
    // A relative path names nothing admission can resolve to one file.
    expect(withProvenance({ kind: "file-0600", path: "key.pem" }))
      .toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
    // The label and its own evidence must agree: a `file-0600` claim carrying a reference instead
    // is refused before either form is checked, so the two cannot be mixed to satisfy neither.
    expect(withProvenance({ kind: "secret-reference", reference: "vault://key" }))
      .toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
    // A directory is not a file the key could have been read from.
    expect(withProvenance({ kind: "file-0600", path: SECRET_DIRECTORY }))
      .toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
    // Owner-only permissions on a file owned by someone else still hand that account the secret.
    // The contents are made to match, so ownership is the only thing left that can refuse.
    expect(evaluateBindPolicy(publicBind({ tls: material }), {
      ...options,
      serviceUid: 1_000,
      observeSecretFile: (path) => ({
        mode: 0o600,
        isSocket: false,
        isDirectory: false,
        isSymbolicLink: false,
        isFile: true,
        uid: 4_242,
        contents: path === fileProvenance(material.privateKeyPem).path
          ? material.privateKeyPem
          : CAPABILITY_ID,
      }),
    })).toMatchObject({ status: "refused", code: "secret-channel-not-approved" });

    // The capability presentation carries its own channel and is checked on its own evidence. TLS
    // provenance stays valid in both rows below, so only the administrator's provenance can decide
    // — otherwise the TLS check would refuse first and these would pass without the second check
    // existing at all.
    expect(evaluateBindPolicy(publicBind({
      administrator: administrator({}, "file-0600", { kind: "file-0600", path: exposedFile }),
    }), options)).toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
    expect(evaluateBindPolicy(publicBind({
      administrator: administrator({}, "file-0600",
        { kind: "secret-reference", reference: "vault://cap" }),
    }), options)).toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
  });

  test("a cited file must hold the secret citing it, not merely be protected", () => {
    // A protected file is evidence about that file. Without comparing contents, material from argv,
    // the environment, or a literal can cite any trusted mode-0600 file on the host — even an
    // unrelated one — and inherit provenance it never had.
    const material = tlsMaterial();
    const unrelatedFile = fileProvenance("an unrelated root-owned secret");

    // Baseline: citing the file that actually holds the key is admitted.
    expect(evaluateBindPolicy(publicBind({ tls: material }), options))
      .toMatchObject({ status: "allowed" });
    // The same key, same protected-file label, pointing at a file holding something else.
    expect(evaluateBindPolicy(publicBind({
      tls: { ...material, privateKeyProvenance: unrelatedFile },
    }), options)).toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
    // Same for the capability id, which is the part of the presentation the channel carries.
    expect(evaluateBindPolicy(publicBind({
      administrator: administrator({}, "file-0600", unrelatedFile),
    }), options)).toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
    // A file holding the secret with one trailing newline is the ordinary on-disk form and holds.
    const newlineTerminated = join(SECRET_DIRECTORY, "trailing-newline.pem");
    writeFileSync(newlineTerminated, `${material.privateKeyPem}\n`, { mode: 0o600 });
    chmodSync(newlineTerminated, 0o600);
    expect(evaluateBindPolicy(publicBind({
      tls: {
        ...material,
        privateKeyProvenance: { kind: "file-0600", path: newlineTerminated },
      },
    }), options)).toMatchObject({ status: "allowed" });
    // A prefix of the secret is not the secret, and neither is a file that merely contains it.
    const prefixFile = join(SECRET_DIRECTORY, "prefix.pem");
    writeFileSync(prefixFile, material.privateKeyPem.slice(0, 40), { mode: 0o600 });
    chmodSync(prefixFile, 0o600);
    expect(evaluateBindPolicy(publicBind({
      tls: { ...material, privateKeyProvenance: { kind: "file-0600", path: prefixFile } },
    }), options)).toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
  });

  test("the certificate must be signed, not merely well-formed", () => {
    // Parsing, key matching, dates and hostname all read fields the presenter wrote. None touches
    // the signature, so a certificate whose signature bytes are corrupt passes every one of them
    // while every real client rejects the handshake.
    const material = tlsMaterial();
    const withCertificate = (certificatePem: string): BindDecision =>
      evaluateBindPolicy(publicBind({ tls: { ...material, certificatePem } }), options);

    expect(withCertificate(material.certificatePem)).toMatchObject({ status: "allowed" });
    expect(withCertificate(corruptedSignature(material.certificatePem)))
      .toMatchObject({ status: "refused", code: "tls-certificate-invalid" });

    // A leaf signed by someone else cannot be validated from itself, and this module holds no
    // trust store, so the anchor has to arrive with the material or the bind does not happen.
    const authority = selfSignedTlsMaterial({
      commonName: "dacs-forge-issuing-authority",
      ca: true,
      notBefore: new Date("2026-01-01T00:00:00Z"),
      notAfter: new Date("2040-01-01T00:00:00Z"),
    });
    const issued = issuedTlsMaterial({
      dnsNames: [PUBLIC_HOSTNAME],
      notBefore: new Date("2026-01-01T00:00:00Z"),
      notAfter: new Date("2040-01-01T00:00:00Z"),
    }, { commonName: "dacs-forge-issuing-authority", privateKeyPem: authority.privateKeyPem });
    const issuedTls = (issuerChainPem?: readonly string[]): TlsMaterial => ({
      certificatePem: issued.certificatePem,
      privateKeyPem: issued.privateKeyPem,
      privateKeyChannel: "file-0600",
      privateKeyProvenance: fileProvenance(issued.privateKeyPem),
      ...(issuerChainPem === undefined ? {} : { issuerChainPem }),
    });

    expect(evaluateBindPolicy(publicBind({ tls: issuedTls() }), options))
      .toMatchObject({ status: "refused", code: "tls-certificate-invalid" });
    // Supplied with its issuer, the same leaf verifies to a self-signed anchor and is admitted.
    expect(evaluateBindPolicy(
      publicBind({ tls: issuedTls([authority.certificatePem]) }),
      options,
    )).toMatchObject({ status: "allowed", exposure: "public", transport: "https" });
    // An issuer whose own signature is corrupt anchors nothing.
    expect(evaluateBindPolicy(
      publicBind({ tls: issuedTls([corruptedSignature(authority.certificatePem)]) }),
      options,
    )).toMatchObject({ status: "refused", code: "tls-certificate-invalid" });
    // A chain of the wrong certificate does not vouch for this leaf, however valid it is itself.
    expect(evaluateBindPolicy(
      publicBind({ tls: issuedTls([material.certificatePem]) }),
      options,
    )).toMatchObject({ status: "refused", code: "tls-certificate-invalid" });
    // An intermediate is not an anchor. A chain that stops before something signs itself is a
    // chain whose last certificate is trusted only for having arrived with the leaf.
    const intermediate = issuedTlsMaterial({
      commonName: "dacs-forge-intermediate",
      ca: true,
      notBefore: new Date("2026-01-01T00:00:00Z"),
      notAfter: new Date("2040-01-01T00:00:00Z"),
    }, { commonName: "dacs-forge-issuing-authority", privateKeyPem: authority.privateKeyPem });
    const deepLeaf = issuedTlsMaterial({
      dnsNames: [PUBLIC_HOSTNAME],
      notBefore: new Date("2026-01-01T00:00:00Z"),
      notAfter: new Date("2040-01-01T00:00:00Z"),
    }, { commonName: "dacs-forge-intermediate", privateKeyPem: intermediate.privateKeyPem });
    const deepTls = (issuerChainPem: readonly string[]): TlsMaterial => ({
      certificatePem: deepLeaf.certificatePem,
      privateKeyPem: deepLeaf.privateKeyPem,
      privateKeyChannel: "file-0600",
      privateKeyProvenance: fileProvenance(deepLeaf.privateKeyPem),
      issuerChainPem,
    });
    expect(evaluateBindPolicy(
      publicBind({ tls: deepTls([intermediate.certificatePem]) }),
      options,
    )).toMatchObject({ status: "refused", code: "tls-certificate-invalid" });
    // Carried all the way to the self-signed root, the same leaf is admitted.
    expect(evaluateBindPolicy(
      publicBind({
        tls: deepTls([intermediate.certificatePem, authority.certificatePem]),
      }),
      options,
    )).toMatchObject({ status: "allowed", exposure: "public", transport: "https" });

    // An expired issuer is not current authority even when the leaf itself is inside its window.
    const staleAuthority = selfSignedTlsMaterial({
      commonName: "dacs-forge-stale-authority",
      notBefore: new Date("2026-01-01T00:00:00Z"),
      notAfter: new Date("2027-01-01T00:00:00Z"),
    });
    const staleIssued = issuedTlsMaterial({
      dnsNames: [PUBLIC_HOSTNAME],
      notBefore: new Date("2026-01-01T00:00:00Z"),
      notAfter: new Date("2040-01-01T00:00:00Z"),
    }, { commonName: "dacs-forge-stale-authority", privateKeyPem: staleAuthority.privateKeyPem });
    expect(evaluateBindPolicy(publicBind({
      tls: {
        certificatePem: staleIssued.certificatePem,
        privateKeyPem: staleIssued.privateKeyPem,
        privateKeyChannel: "file-0600",
        privateKeyProvenance: fileProvenance(staleIssued.privateKeyPem),
        issuerChainPem: [staleAuthority.certificatePem],
      },
    }), options)).toMatchObject({ status: "refused", code: "tls-certificate-invalid" });
  });

  test("a secret reference is resolved by the deployment, never taken on the caller's word", () => {
    const material = currentTlsMaterial([PUBLIC_HOSTNAME]);
    const referenced = (
      extra: Partial<BindPolicyOptions> = {},
    ): BindDecision => evaluateBindPolicy(publicBind({
      tls: {
        certificatePem: material.certificatePem,
        privateKeyPem: material.privateKeyPem,
        privateKeyChannel: "secret-reference",
        privateKeyProvenance: { kind: "secret-reference", reference: "vault://tls-key" },
      },
      administrator: administrator({}, "secret-reference",
        { kind: "secret-reference", reference: "vault://cap" }),
    }), { ...options, ...extra });

    // No resolver: the reference is a label again, so it is refused rather than believed.
    expect(referenced()).toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
    // A resolver that returns something else means the presented material is not what the
    // reference holds — the case a caller fabricating a reference would land in.
    expect(referenced({ resolveSecretReference: () => "other material" }))
      .toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
    // A resolver that throws fails closed.
    expect(referenced({ resolveSecretReference: () => { throw new Error("unreachable"); } }))
      .toMatchObject({ status: "refused", code: "secret-channel-not-approved" });
    // Resolving to exactly the presented secrets admits the bind: the private key for the TLS
    // material, and the capability id for the administrator presentation.
    expect(referenced({
      resolveSecretReference: (reference) => (
        reference === "vault://tls-key" ? material.privateKeyPem : CAPABILITY_ID
      ),
    })).toMatchObject({ status: "allowed", exposure: "public", administratorVerified: true });
  });

  test("authority must be authenticated by the deployment, never assembled by the caller", () => {
    // Every field of a capability is caller-controlled. A caller can therefore present the correct
    // shape, principal, operation, target and a future expiry, through a genuinely protected
    // channel, for a capability this deployment never issued. Nothing before this seam can tell
    // the difference, so admission asks the deployment and refuses unless it says yes.
    // Its provenance cites a file that really holds it: a caller who can write through an approved
    // channel writes their own forged id there, so every earlier check passes and the seam is the
    // only thing left that can refuse. Citing a file holding something else would refuse one step
    // sooner and prove nothing about authenticity.
    const forged = administrator(
      { id: "forged-by-any-caller" },
      "file-0600",
      fileProvenance("forged-by-any-caller"),
    );
    const { verifyAdministratorAuthenticity: _omitted, ...withoutVerifier } = options;

    // A deployment that supplies no verifier cannot verify authority, so it does not bind. This is
    // the exact state the lane shipped before this correction, when it answered "allowed".
    expect(evaluateBindPolicy(publicBind(), withoutVerifier))
      .toMatchObject({ status: "refused", code: "administrator-unauthenticated" });
    // A capability the deployment does not recognize is refused though every other check passes.
    expect(evaluateBindPolicy(publicBind({ administrator: forged }), options))
      .toMatchObject({ status: "refused", code: "administrator-unauthenticated" });
    // A verifier that throws is a verdict of no, not an exception that escapes admission.
    expect(evaluateBindPolicy(publicBind(), {
      ...options,
      verifyAdministratorAuthenticity: () => { throw new Error("issuer unreachable"); },
    })).toMatchObject({ status: "refused", code: "administrator-unauthenticated" });
    // Only exactly `true` is a yes: a truthy non-boolean from an untyped caller is not consent.
    expect(evaluateBindPolicy(publicBind(), {
      ...options,
      verifyAdministratorAuthenticity: (() => "yes") as unknown as (
        capability: AdministratorPresentation["capability"],
      ) => boolean,
    })).toMatchObject({ status: "refused", code: "administrator-unauthenticated" });
    // The verifier receives the capability actually presented, so it can answer about that one.
    const seen: string[] = [];
    expect(evaluateBindPolicy(publicBind(), {
      ...options,
      verifyAdministratorAuthenticity: (capability) => {
        seen.push(capability.id);
        return capability.id === CAPABILITY_ID;
      },
    })).toMatchObject({ status: "allowed", administratorVerified: true });
    expect(seen).toEqual([CAPABILITY_ID]);

    // The seam is last, not first. An expired capability refuses as expired even when the verifier
    // would throw, which proves admission never reached it: a verifier consulted before the cheap
    // caller-controlled checks would leak the deployment's authority questions to any caller and
    // would report the wrong refusal class here.
    expect(evaluateBindPolicy(publicBind({
      administrator: administrator({ expiresAt: "2020-01-01T00:00:00Z" }),
    }), {
      ...options,
      verifyAdministratorAuthenticity: () => { throw new Error("must not be reached"); },
    })).toMatchObject({ status: "refused", code: "administrator-expired" });

    // Loopback requires no administrator authority at all, so a deployment without a verifier still
    // binds loopback. The seam must not turn into a service-wide startup requirement.
    expect(evaluateBindPolicy({ kind: "tcp", hostname: "127.0.0.1", port: 0 }, withoutVerifier))
      .toMatchObject({ status: "allowed", exposure: "loopback", administratorVerified: false });
    // A protected Unix socket carries no administrator presentation either.
    expect(evaluateBindPolicy({ kind: "unix-socket", path: "/run/dacs/forge.sock" }, {
      ...withoutVerifier,
      serviceUid: 1_000,
      realPath: (path) => path,
      statPath: (path) => {
        if (path === "/run/dacs") {
          return {
            mode: 0o700, isSocket: false, isDirectory: true, isSymbolicLink: false, uid: 1_000,
          };
        }
        return ancestorFacts(path) ?? raiseMissing();
      },
    })).toMatchObject({ status: "allowed", exposure: "unix-socket" });
  });

  test("an unauthenticated bind refusal throws before a listener can exist", () => {
    // assertBindAllowed is what the server calls, so the new refusal class must stop startup there
    // and not merely be reported by the pure decision function.
    let thrown: unknown;
    try {
      assertBindAllowed(publicBind({
        administrator: administrator({ id: "forged" }, "file-0600", fileProvenance("forged")),
      }), options);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(BindPolicyError);
    expect((thrown as BindPolicyError).code).toBe("administrator-unauthenticated");
    // The refusal must not carry the capability id or any secret material into an error surface.
    expect(JSON.stringify((thrown as BindPolicyError).message)).not.toContain("forged");
  });

  test("an issuer must be a certificate authority, not merely something that signed", () => {
    // Signature, names and dates are all satisfied by an ordinary end-entity certificate, and one
    // of those can be obtained for any name its holder controls. Without the basicConstraints
    // check such a certificate is accepted as an intermediate and admission calls the material
    // valid while every real client rejects the chain as having a non-CA issuer.
    const window = {
      notBefore: new Date("2026-01-01T00:00:00Z"),
      notAfter: new Date("2040-01-01T00:00:00Z"),
    } as const;
    const authority = issuedTlsMaterial({ ...window, commonName: "issuing-authority", ca: true });
    const endEntity = issuedTlsMaterial({ ...window, commonName: "issuing-authority" });
    const leafFrom = (issuerKey: string): TlsMaterial => {
      const leaf = issuedTlsMaterial(
        { ...window, dnsNames: [PUBLIC_HOSTNAME] },
        { commonName: "issuing-authority", privateKeyPem: issuerKey },
      );
      return {
        certificatePem: leaf.certificatePem,
        privateKeyPem: leaf.privateKeyPem,
        privateKeyChannel: "file-0600",
        privateKeyProvenance: fileProvenance(leaf.privateKeyPem),
      };
    };

    // Same subject name, same key type, same window, same self-signature: the two issuers differ in
    // nothing a chain walk reads except `cA`.
    const fromAuthority = leafFrom(authority.privateKeyPem);
    const fromEndEntity = leafFrom(endEntity.privateKeyPem);
    expect(evaluateBindPolicy(publicBind({
      tls: { ...fromAuthority, issuerChainPem: [authority.certificatePem] },
    }), options)).toMatchObject({ status: "allowed", exposure: "public", transport: "https" });
    expect(evaluateBindPolicy(publicBind({
      tls: { ...fromEndEntity, issuerChainPem: [endEntity.certificatePem] },
    }), options)).toMatchObject({ status: "refused", code: "tls-certificate-invalid" });

    // The rule holds at every link, not only the anchor: an intermediate without `cA` signs the
    // leaf just as effectively and is refused just the same.
    const intermediate = issuedTlsMaterial(
      { ...window, commonName: "intermediate" },
      { commonName: "issuing-authority", privateKeyPem: authority.privateKeyPem },
    );
    const deepLeaf = issuedTlsMaterial(
      { ...window, dnsNames: [PUBLIC_HOSTNAME] },
      { commonName: "intermediate", privateKeyPem: intermediate.privateKeyPem },
    );
    expect(evaluateBindPolicy(publicBind({
      tls: {
        certificatePem: deepLeaf.certificatePem,
        privateKeyPem: deepLeaf.privateKeyPem,
        privateKeyChannel: "file-0600",
        privateKeyProvenance: fileProvenance(deepLeaf.privateKeyPem),
        issuerChainPem: [intermediate.certificatePem, authority.certificatePem],
      },
    }), options)).toMatchObject({ status: "refused", code: "tls-certificate-invalid" });
    // The leaf itself is not asked to be a CA: an ordinary self-signed server certificate carries
    // `cA=false` legitimately and is still admitted.
    expect(evaluateBindPolicy(publicBind(), options)).toMatchObject({ status: "allowed" });
  });

  test("a socket path that could not be observed is not a socket path that is free", () => {
    // `stat` failing says one of two different things. Only ENOENT means the socket may be
    // created; ELOOP, EACCES and EIO mean the path's state was never established, and reading
    // those as absence admits a bind that then fails at listen — the failure moving past the
    // listener, which is the one thing admission exists to prevent.
    const parent: PathFacts = {
      mode: 0o700, isSocket: false, isDirectory: true, isSymbolicLink: false, uid: 1_000,
    };
    const decide = (raise: () => never): BindDecision =>
      evaluateBindPolicy({ kind: "unix-socket", path: "/run/dacs/forge.sock" }, {
        serviceUid: 1_000,
        realPath: (path) => path,
        statPath: (path) => {
          if (path === "/run/dacs") return parent;
          const ancestor = ancestorFacts(path);
          if (ancestor !== undefined) return ancestor;
          raise();
        },
      });

    expect(decide(raiseMissing)).toMatchObject({ status: "allowed", exposure: "unix-socket" });
    for (const code of ["ELOOP", "EACCES", "EIO", "ENOTDIR", "ENAMETOOLONG"]) {
      expect(decide(() => {
        throw Object.assign(new Error(code), { code });
      })).toMatchObject({ status: "refused", code: "unix-socket-path-invalid" });
    }
    // A failure carrying no code at all is a failure whose meaning is unknown, which is not
    // absence either.
    expect(decide(() => { throw new Error("ENOENT"); }))
      .toMatchObject({ status: "refused", code: "unix-socket-path-invalid" });
    expect(decide(() => { throw "ENOENT"; }))
      .toMatchObject({ status: "refused", code: "unix-socket-path-invalid" });
  });

  test("keeping an issued identifier is not keeping the capability it was issued with", () => {
    // The deployment authenticates capabilities, not identifiers. A holder of a real capability can
    // reissue itself one carrying the same id and a different body, and every check before the
    // authenticity seam reads the body it was handed — so a seam that compared only the id would
    // admit a capability the deployment let lapse, or one scoped to another endpoint.
    const tampered = (overrides: Partial<BindCapability>): BindDecision =>
      evaluateBindPolicy(publicBind({ administrator: administrator(overrides) }), options);

    expect(evaluateBindPolicy(publicBind(), options))
      .toMatchObject({ status: "allowed", administratorVerified: true });
    // Revived: the issued capability lapses in 2030, this one claims a decade more, same id.
    expect(tampered({ expiresAt: "2040-12-01T00:00:00Z" }))
      .toMatchObject({ status: "refused", code: "administrator-unauthenticated" });
    // Widened: the bind operation is still there, so the operation check passes and only the
    // comparison against what was issued can refuse it.
    expect(tampered({ operations: [BIND_OPERATION, "publish"] }))
      .toMatchObject({ status: "refused", code: "administrator-unauthenticated" });
    // Narrowed the same way: an issued capability is one exact list, not any list containing bind.
    expect(tampered({ operations: [BIND_OPERATION, BIND_OPERATION] }))
      .toMatchObject({ status: "refused", code: "administrator-unauthenticated" });
    // Untampered again, so none of the above refused for a reason that outlives the tampering.
    expect(tampered({})).toMatchObject({ status: "allowed", administratorVerified: true });
  });

  test("protection is asserted about every directory above the socket, not just the parent", () => {
    // Checking the parent alone protects the wrong thing. A parent sitting inside a directory
    // another account can write is a parent that account renames or replaces after admission
    // observed it, and the admitted path then leads to a directory nobody checked. Resolving the
    // path first does not help: `realpath` says where the name pointed, not where it will point.
    const parent: PathFacts = {
      mode: 0o700, isSocket: false, isDirectory: true, isSymbolicLink: false, uid: 1_000,
    };
    const directory = (overrides: Partial<PathFacts> = {}): PathFacts => ({
      mode: 0o755, isSocket: false, isDirectory: true, isSymbolicLink: false, uid: 0, ...overrides,
    });
    const decide = (ancestors: Readonly<Record<string, PathFacts>>): BindDecision =>
      evaluateBindPolicy({ kind: "unix-socket", path: "/run/dacs/forge.sock" }, {
        serviceUid: 1_000,
        realPath: (path) => path,
        statPath: (path) => {
          if (path === "/run/dacs") return parent;
          return ancestors[path] ?? raiseMissing();
        },
      });

    // Baseline: ordinary root-owned ancestors, so every refusal below is the ancestor and not the
    // parent, which is identical in all rows.
    expect(decide({ "/run": directory(), "/": directory() }))
      .toMatchObject({ status: "allowed", exposure: "unix-socket" });
    // A world-writable `/run` hands any account the rename that swaps `/run/dacs`.
    expect(decide({ "/run": directory({ mode: 0o777 }), "/": directory() }))
      .toMatchObject({ status: "refused", code: "unix-socket-not-protected" });
    // The sticky bit is what makes shared directories admissible rather than special-cased: in a
    // sticky directory only an entry's own owner may rename it, which is exactly that swap.
    expect(decide({ "/run": directory({ mode: 0o1777 }), "/": directory() }))
      .toMatchObject({ status: "allowed", exposure: "unix-socket" });
    // Group-writable is the same defect with a smaller audience, and is refused the same way.
    expect(decide({ "/run": directory({ mode: 0o775 }), "/": directory() }))
      .toMatchObject({ status: "refused", code: "unix-socket-not-protected" });
    // Depth does not end the question: the defect two levels up admits the same substitution, so a
    // walk that stopped after one ancestor would pass this row while the socket stayed replaceable.
    expect(decide({ "/run": directory(), "/": directory({ mode: 0o777 }) }))
      .toMatchObject({ status: "refused", code: "unix-socket-not-protected" });
    // An ancestor owned by an untrusted account can replace the parent outright, whatever its mode.
    expect(decide({ "/run": directory({ uid: 4_242, mode: 0o755 }), "/": directory() }))
      .toMatchObject({ status: "refused", code: "unix-socket-not-protected" });
    // Service-owned ancestors are trusted for the same reason the parent may be service-owned.
    expect(decide({ "/run": directory({ uid: 1_000, mode: 0o700 }), "/": directory() }))
      .toMatchObject({ status: "allowed", exposure: "unix-socket" });
    // Fails closed: an ancestor that cannot be observed is not an ancestor whose protection was
    // observed, so admission refuses rather than assume the rest of the chain is fine.
    expect(decide({ "/run": directory() }))
      .toMatchObject({ status: "refused", code: "unix-socket-path-invalid" });
    // A component above the socket that is not a directory is not a chain this socket lives under.
    expect(decide({ "/run": directory({ isDirectory: false }), "/": directory() }))
      .toMatchObject({ status: "refused", code: "unix-socket-path-invalid" });
  });

  test("a service-owned parent must also be one this service could create the socket in", () => {
    // Ownership is not permission. Every mode below grants group and other nothing and is owned by
    // the service, so each passes the substitution checks; only owner write plus execute lets the
    // socket be created there. Without both, `listen` fails EACCES after admission said yes, which
    // moves the failure past the listener instead of refusing it.
    const decide = (mode: number, serviceUid = 1_000, parentUid = serviceUid): BindDecision =>
      evaluateBindPolicy({ kind: "unix-socket", path: "/run/dacs/forge.sock" }, {
        serviceUid,
        realPath: (path) => path,
        statPath: (path) => {
          if (path === "/run/dacs") {
            return {
              mode, isSocket: false, isDirectory: true, isSymbolicLink: false, uid: parentUid,
            };
          }
          return ancestorFacts(path) ?? raiseMissing();
        },
      });

    expect(decide(0o700)).toMatchObject({ status: "allowed", exposure: "unix-socket" });
    // 0500 and 0400 are readable and traversable but grant the owner no write; 0600 grants write
    // but no traversal; 0000 grants neither. All four are unusable and all four are refused.
    for (const mode of [0o500, 0o400, 0o600, 0o000]) {
      expect(decide(mode)).toMatchObject({
        status: "refused",
        code: "unix-socket-not-protected",
      });
    }
    // Root can create an entry in any directory it can traverse, so the owner-bit rule does not
    // apply to it. The platform-without-uid case cannot be reached from here — `serviceUid`
    // defaults to `process.getuid()`, so only a platform that exposes none produces it.
    expect(decide(0o500, 0)).toMatchObject({ status: "allowed", exposure: "unix-socket" });
    // Root is exempt from the owner-bit rule, not from the ownership rule: a parent owned by an
    // untrusted account is still refused when the service is root.
    expect(decide(0o700, 0, 4_242)).toMatchObject({
      status: "refused",
      code: "unix-socket-not-protected",
    });
  });

  test("the certificate is checked against the names clients use, not the address bound", () => {
    // A wildcard address is not a name any certificate can carry, so checking the certificate
    // against the bind target would either refuse every wildcard bind or, if waived, admit a
    // listener whose TLS identity was never examined at all.
    const material = tlsMaterial();
    const wildcardBind = (
      hostname: string,
      serverIdentities?: readonly string[],
    ): BindDecision => evaluateBindPolicy({
      kind: "tcp",
      hostname,
      port: PUBLIC_PORT,
      tls: material,
      administrator: administrator({ boundHostname: hostname }),
      ...(serverIdentities === undefined ? {} : { serverIdentities }),
    }, options);
    for (const wildcard of ["0.0.0.0", "::", "0:0:0:0:0:0:0:0", "[::]", "::ffff:0.0.0.0"]) {
      issue({ boundHostname: wildcard });
    }

    for (const wildcard of ["0.0.0.0", "::", "0:0:0:0:0:0:0:0", "[::]", "::ffff:0.0.0.0"]) {
      // Undeclared: refused, because admission has no name to establish clients will accept it.
      expect(wildcardBind(wildcard)).toMatchObject({
        status: "refused",
        code: "tls-certificate-hostname-mismatch",
      });
      // Declared and carried by the certificate: admitted, and the address is never checked.
      expect(wildcardBind(wildcard, [PUBLIC_HOSTNAME]))
        .toMatchObject({ status: "allowed", exposure: "public", transport: "https" });
    }
    // Every declared name must be carried, not merely one: a client reaching the service by an
    // unmatched name is a client population that cannot validate this listener.
    expect(wildcardBind("0.0.0.0", [PUBLIC_HOSTNAME, "other.dacs-forge.invalid"]))
      .toMatchObject({ status: "refused", code: "tls-certificate-hostname-mismatch" });
    // The list is deployment description, not caller input: unbounded, malformed or oversized
    // declarations are refused rather than iterated.
    expect(wildcardBind("0.0.0.0", Array.from({ length: 65 }, () => PUBLIC_HOSTNAME)))
      .toMatchObject({ status: "refused", code: "tls-certificate-hostname-mismatch" });
    expect(wildcardBind("0.0.0.0", ["service\u0000.invalid"]))
      .toMatchObject({ status: "refused", code: "tls-certificate-hostname-mismatch" });
    // A declaration cannot loosen a named bind either: the names still have to be carried.
    expect(evaluateBindPolicy({
      kind: "tcp",
      hostname: PUBLIC_HOSTNAME,
      port: PUBLIC_PORT,
      tls: material,
      administrator: administrator(),
      serverIdentities: ["other.dacs-forge.invalid"],
    }, options)).toMatchObject({ status: "refused", code: "tls-certificate-hostname-mismatch" });
    // And a named bind with no declaration is still checked against the target it names.
    expect(evaluateBindPolicy(publicBind(), options)).toMatchObject({ status: "allowed" });
    // A wildcard address is not loopback, so this is the exposed class throughout.
    expect(isLoopbackHostname("0.0.0.0")).toBe(false);
  });

  test("a secret file is opened as a file, without blocking on what the path really is", () => {
    // The observation is an open followed by a read. A path naming a FIFO passes every fact a
    // `stat` reports about permissions and ownership, and reading it blocks until a writer appears
    // — a caller-named path that stalls startup indefinitely. The open is non-blocking and the
    // descriptor's own type is checked, so the FIFO is refused instead of waited on.
    const material = tlsMaterial();
    const fifoPath = join(SECRET_DIRECTORY, "secret.fifo");
    const made = Bun.spawnSync(["mkfifo", "-m", "600", fifoPath]);
    expect(made.exitCode).toBe(0);
    expect(evaluateBindPolicy(publicBind({
      tls: { ...material, privateKeyProvenance: { kind: "file-0600", path: fifoPath } },
    }), options)).toMatchObject({
      status: "refused",
      code: "secret-channel-not-approved",
      // Refused for what the path is, not for a read that failed on it: an open that merely could
      // not be read would refuse a FIFO by accident and a regular file by the same accident.
      reason: expect.stringContaining("names something other than a file"),
    });

    // A file larger than admission will read is refused rather than read into memory on a caller's
    // word: the path is caller-named, and an unbounded read is the caller choosing the allocation.
    const oversizedPath = join(SECRET_DIRECTORY, "oversized.pem");
    writeFileSync(oversizedPath, material.privateKeyPem.padEnd(70_000, "x"), { mode: 0o600 });
    chmodSync(oversizedPath, 0o600);
    expect(evaluateBindPolicy(publicBind({
      tls: { ...material, privateKeyProvenance: { kind: "file-0600", path: oversizedPath } },
    }), options)).toMatchObject({
      status: "refused",
      code: "secret-channel-not-approved",
      // Refused while observing it, not after comparing 64 KiB of it against the secret.
      reason: expect.stringContaining("cannot be observed"),
    });

    // A file just inside the bound still holds nothing but its own contents, so it refuses on the
    // contents check rather than the size one — the bound is a bound, not a second rejection rule.
    const largePath = join(SECRET_DIRECTORY, "large.pem");
    writeFileSync(largePath, "x".repeat(60_000), { mode: 0o600 });
    chmodSync(largePath, 0o600);
    expect(evaluateBindPolicy(publicBind({
      tls: { ...material, privateKeyProvenance: { kind: "file-0600", path: largePath } },
    }), options)).toMatchObject({
      status: "refused",
      code: "secret-channel-not-approved",
      reason: expect.stringContaining("does not match the contents"),
    });
    // And the ordinary file it really came from is still admitted, so nothing above refuses by
    // being a file at all.
    expect(evaluateBindPolicy(publicBind({ tls: material }), options))
      .toMatchObject({ status: "allowed" });
  });
});
