import {
  assertDoctorReport,
  doctorPackageVersion,
  runDoctor,
  serializeDoctorReport,
  type DoctorReport,
} from "../readiness/doctor.ts";
import {
  createTerminalLogger,
  enforceTerminalSchema,
  terminalErrorResponse,
  terminalJsonResponse,
  validateTerminalPayload,
  TERMINAL_JSON_HEADERS,
  type HttpErrorCode,
  type TerminalLogRecord,
  type TerminalVerbosity,
} from "./terminal-server.ts";
import { assertBindAllowed } from "./bind-policy.ts";

export const HEALTH_SCHEMA = "dacs-health/v1" as const;
export const READINESS_SCHEMA = "dacs-readiness/v1" as const;
export const HTTP_ERROR_SCHEMA = "dacs-http-error/v1" as const;

const SERVICE_ID = "dacs-forge" as const;
const MAX_REQUEST_URL_LENGTH = 2048;
const PUBLIC_BLOCKER_IDS = Object.freeze(new Set([
  "runtime.bun",
  "package.contract",
  "execution.read-only",
  "binding.live-resolution",
  "registration.directory",
  "transport.http",
  "conformance.external-rig",
]));

export interface AdministratorAuthorizationRequest {
  readonly method: "GET";
  readonly path: "/admin/readiness";
  readonly authorization: string | null;
}

export interface ReadinessHttpOptions {
  readonly authorizeAdministrator?: (request: AdministratorAuthorizationRequest) => boolean;
  readonly doctor?: () => DoctorReport;
}

export interface ReadinessServerOptions extends ReadinessHttpOptions {
  readonly hostname?: "127.0.0.1" | "::1";
  readonly port?: number;
  /** Where terminal-contract violations are reported. Defaults to the process log sink. */
  readonly logSink?: (line: string) => void;
  /** Secret values this deployment must never emit. Forwarded to the transport logger. */
  readonly logSentinels?: readonly string[];
  /** Highest verbosity this deployment emits. Forwarded to the transport logger. */
  readonly logLevel?: TerminalVerbosity;
}

export interface RunningReadinessServer {
  readonly hostname: "127.0.0.1" | "::1";
  readonly port: number;
  readonly url: string;
  stop(): Promise<void>;
}

/**
 * Every readiness response is a terminal result, so both helpers delegate to the versioned
 * terminal contract: the payload is validated against its declared schema before a response
 * exists, and a non-conforming payload degrades to the versioned error document. The byte budget
 * is the boundary's alone — a second, smaller one here would serialize the same body twice and
 * put two unrelated limits on it, so the same oversized payload would be refused by one number
 * from this emitter and a different number from any other.
 */
function jsonResponse(
  value: unknown,
  status: number,
  extraHeaders?: Readonly<Record<string, string>>,
): Response {
  return terminalJsonResponse(value, status, extraHeaders);
}

function errorResponse(status: number, code: HttpErrorCode): Response {
  return terminalErrorResponse(status, code);
}

function doctorReport(options: ReadinessHttpOptions): DoctorReport {
  const report = options.doctor === undefined ? runDoctor() : options.doctor();
  assertDoctorReport(report);
  return report;
}

function healthResponse(): Response {
  return jsonResponse(Object.freeze({
    schema: HEALTH_SCHEMA,
    service: SERVICE_ID,
    version: doctorPackageVersion(),
    status: "ok",
    timestamp: new Date().toISOString(),
  }), 200);
}

function publicReadinessResponse(options: ReadinessHttpOptions): Response {
  const report = doctorReport(options);
  const blockerIds = report.checks
    .filter((check) => check.required && check.status !== "passed"
      && PUBLIC_BLOCKER_IDS.has(check.id))
    .map((check) => check.id);
  return jsonResponse(Object.freeze({
    schema: READINESS_SCHEMA,
    service: report.service,
    version: report.version,
    status: report.ready ? "ready" : "not-ready",
    evidenceMode: report.evidenceMode,
    blockerIds: Object.freeze(blockerIds),
    timestamp: report.generatedAt,
  }), report.ready ? 200 : 503);
}

function detailedReadinessResponse(request: Request, options: ReadinessHttpOptions): Response {
  const authorize = options.authorizeAdministrator;
  if (authorize === undefined) return errorResponse(404, "not-found");
  let authorized = false;
  try {
    authorized = authorize(Object.freeze({
      method: "GET",
      path: "/admin/readiness",
      authorization: request.headers.get("authorization"),
    }));
  } catch {
    return errorResponse(500, "internal-error");
  }
  if (authorized !== true) return errorResponse(401, "unauthorized");
  const report = doctorReport(options);
  if (!validateTerminalPayload(report).valid) return errorResponse(500, "internal-error");
  // `serializeDoctorReport` refuses anything past its own 16 KiB wire budget, well under the
  // terminal boundary's 64 KiB cap, so an oversized report throws here and the handler's outer
  // catch degrades it to `internal-error`. No second byte check belongs at this emitter: it could
  // never be reached — and in practice `doctorReport`'s `assertDoctorReport` sits in front of even
  // that, so a report large enough to matter has usually failed a shape rule first.
  // The headers are the contract's own, imported rather than restated: this is the authenticated
  // diagnostic body, the one place where a cached or sniffed response is worst, and a local copy
  // of the set is exactly how that path ends up governed by a constant nothing else updates.
  const body = `${serializeDoctorReport(report)}\n`;
  return new Response(body, {
    status: report.ready ? 200 : 503,
    headers: TERMINAL_JSON_HEADERS,
  });
}

export function createReadinessHttpHandler(
  options: ReadinessHttpOptions = {},
): (request: Request) => Response {
  return createBoundReadinessHttpHandler(options);
}

function createBoundReadinessHttpHandler(
  options: ReadinessHttpOptions,
  expectedBinding?: () => Readonly<{ hostname: "127.0.0.1" | "::1"; port: number }> | undefined,
): (request: Request) => Response {
  return (request: Request): Response => {
    try {
      if (request.url.length > MAX_REQUEST_URL_LENGTH) {
        return errorResponse(404, "not-found");
      }
      if (request.method !== "GET") {
        return errorResponse(405, "method-not-allowed");
      }
      const url = new URL(request.url);
      const binding = expectedBinding?.();
      if (binding === undefined) {
        if (url.protocol !== "http:"
          || (url.hostname !== "127.0.0.1" && url.hostname !== "[::1]")) {
          return errorResponse(421, "misdirected-request");
        }
      } else if (!requestMatchesReadinessBinding(request, binding.hostname, binding.port)) {
        return errorResponse(421, "misdirected-request");
      }
      if (request.url.includes("?") || request.url.includes("#")) {
        return errorResponse(404, "not-found");
      }
      if (url.pathname === "/healthz") return healthResponse();
      if (url.pathname === "/readyz") return publicReadinessResponse(options);
      if (url.pathname === "/admin/readiness") return detailedReadinessResponse(request, options);
      return errorResponse(404, "not-found");
    } catch {
      return errorResponse(500, "internal-error");
    }
  };
}

function effectiveHttpPort(url: URL): number | undefined {
  if (url.protocol !== "http:") return undefined;
  if (url.port === "") return 80;
  const port = Number(url.port);
  return Number.isSafeInteger(port) && port > 0 && port <= 65_535 ? port : undefined;
}

export function requestMatchesReadinessBinding(
  request: Request,
  hostname: "127.0.0.1" | "::1",
  port: number,
): boolean {
  try {
    const expectedHostname = hostname === "::1" ? "[::1]" : hostname;
    const requestUrl = new URL(request.url);
    if (requestUrl.username !== "" || requestUrl.password !== ""
      || requestUrl.hostname !== expectedHostname || effectiveHttpPort(requestUrl) !== port) {
      return false;
    }
    const host = request.headers.get("host");
    if (host === null) return false;
    const match = hostname === "127.0.0.1"
      ? /^(127\.0\.0\.1)(?::([0-9]{1,5}))?$/.exec(host)
      : /^\[([0-9A-Fa-f:]+)\](?::([0-9]{1,5}))?$/.exec(host);
    if (match === null) return false;
    const hostPort = match[2] === undefined ? 80 : Number(match[2]);
    if (!Number.isSafeInteger(hostPort) || hostPort < 1 || hostPort > 65_535 || hostPort !== port) {
      return false;
    }
    if (hostname === "127.0.0.1") return match[1] === hostname;
    const normalizedHost = new URL(`http://[${match[1]}]/`).hostname;
    return normalizedHost === expectedHostname;
  } catch {
    return false;
  }
}

/**
 * Path as the client asked for it, with any query elided to its parameter count; an unparseable
 * URL still has to log something.
 *
 * The query is where a credential reaches a transport log in practice — a token pasted into a
 * link, a one-time URL forwarded — and the logger's redaction is exact-substring matching over
 * the sentinels a deployment enumerated, so a value nobody enumerated, or a key rotated since
 * the list was written, would survive it and land in the sink in cleartext. The sink must not be
 * the last line of defence for that. Nothing here needs the content: this handler answers 404 to
 * any request carrying a query at all, so the count is the whole diagnostic.
 */
function requestTarget(request: Request): string {
  try {
    const url = new URL(request.url);
    const parameters = [...url.searchParams].length;
    return parameters === 0 ? url.pathname : `${url.pathname} <${parameters} query elided>`;
  } catch {
    return "<unparseable>";
  }
}

function normalizedHostname(hostname: unknown): "127.0.0.1" | "::1" {
  if (hostname === undefined || hostname === "127.0.0.1") return "127.0.0.1";
  if (hostname === "::1") return "::1";
  throw new TypeError("The readiness server binds only to an explicit loopback address");
}

function normalizedPort(port: unknown): number {
  if (port === undefined) return 0;
  if (!Number.isSafeInteger(port) || (port as number) < 0 || (port as number) > 65_535) {
    throw new TypeError("The readiness server port must be an integer from 0 through 65535");
  }
  return port as number;
}

export function startReadinessServer(
  options: ReadinessServerOptions = {},
): RunningReadinessServer {
  const hostname = normalizedHostname(options.hostname);
  const port = normalizedPort(options.port);
  let expectedBinding: Readonly<{ hostname: "127.0.0.1" | "::1"; port: number }> | undefined;
  // The bind policy is the enforcement point its own contract claims, so it runs here rather
  // than only in its probes. This server is pinned to loopback by `normalizedHostname`, which
  // makes the call cheap; what it buys is that no listener in this module can open without
  // passing admission, including after a future change to how the hostname is chosen.
  // Sentinels and level are forwarded, not hardcoded: a logger the deployment cannot configure
  // satisfies "zero configured sentinel matches" only because nothing can ever be configured.
  const logger = createTerminalLogger({
    ...(options.logSink === undefined ? {} : { sink: options.logSink }),
    ...(options.logSentinels === undefined ? {} : { sentinels: options.logSentinels }),
    ...(options.logLevel === undefined ? {} : { level: options.logLevel }),
  });
  assertBindAllowed({ kind: "tcp", hostname, port });
  // A diagnostic surface must never decide the response. A configured sink or clock that throws
  // would otherwise escape to Bun's own error handling, which owes no registered terminal
  // schema, so every log call is contained here and the logging itself sits inside the
  // enforcement wrapper rather than in front of it.
  const safeLog = (record: TerminalLogRecord): void => {
    try {
      logger.log(record);
    } catch {
      // Nothing to report it to: the reporting channel is what failed.
    }
  };
  const bound = createBoundReadinessHttpHandler(options, () => expectedBinding);
  const handler = enforceTerminalSchema(
    (request: Request): Response => {
      // One request-scoped record, at `debug`, carrying the request target as `requestTarget`
      // narrows it: the path, and a query reduced to how many parameters it had. The path still
      // reaches the logger, so the redaction pass is exercised by the transport and not only by
      // the logger's own probes, while the field that carries credentials in practice never gets
      // that far. At the default level nothing here is emitted at all.
      safeLog({
        level: "debug",
        event: "request.received",
        fields: { method: request.method, target: requestTarget(request) },
      });
      return bound(request);
    },
    {
      onViolation: (reason): void => {
        safeLog({ level: "failure", event: "terminal.violation", fields: { reason } });
      },
    },
  );
  const server = Bun.serve({ hostname, port, fetch: handler });
  const actualPort = server.port;
  if (actualPort === undefined) {
    void server.stop(true);
    throw new TypeError("The readiness server did not expose a TCP port");
  }
  const authority = hostname === "::1" ? `[${hostname}]` : hostname;
  expectedBinding = Object.freeze({ hostname, port: actualPort });
  let stopPromise: Promise<void> | undefined;
  return Object.freeze({
    hostname,
    port: actualPort,
    url: `http://${authority}:${actualPort}`,
    stop(): Promise<void> {
      stopPromise ??= server.stop(true);
      return stopPromise;
    },
  });
}
