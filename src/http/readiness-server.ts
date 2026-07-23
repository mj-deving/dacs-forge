import {
  assertDoctorReport,
  doctorPackageVersion,
  runDoctor,
  serializeDoctorReport,
  type DoctorReport,
} from "../readiness/doctor.ts";

export const HEALTH_SCHEMA = "dacs-health/v1" as const;
export const READINESS_SCHEMA = "dacs-readiness/v1" as const;
export const HTTP_ERROR_SCHEMA = "dacs-http-error/v1" as const;

const SERVICE_ID = "dacs-forge" as const;
const MAX_REQUEST_URL_LENGTH = 2048;
const JSON_HEADERS = Object.freeze({
  "cache-control": "no-store",
  "content-type": "application/json; charset=utf-8",
  "x-content-type-options": "nosniff",
});
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
}

export interface RunningReadinessServer {
  readonly hostname: "127.0.0.1" | "::1";
  readonly port: number;
  readonly url: string;
  stop(): Promise<void>;
}

type HttpErrorCode = "internal-error" | "method-not-allowed" | "misdirected-request"
  | "not-found" | "unauthorized";

function jsonResponse(
  value: unknown,
  status: number,
  extraHeaders?: Readonly<Record<string, string>>,
): Response {
  const body = JSON.stringify(value);
  if (body === undefined || Buffer.byteLength(body, "utf8") > 16_384) {
    return errorResponse(500, "internal-error");
  }
  return new Response(`${body}\n`, {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders },
  });
}

function errorResponse(status: number, code: HttpErrorCode): Response {
  const body = JSON.stringify(Object.freeze({
    schema: HTTP_ERROR_SCHEMA,
    status,
    code,
  }));
  return new Response(`${body}\n`, {
    status,
    headers: JSON_HEADERS,
  });
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
  return new Response(`${serializeDoctorReport(report)}\n`, {
    status: report.ready ? 200 : 503,
    headers: JSON_HEADERS,
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
  const handler = createBoundReadinessHttpHandler(options, () => expectedBinding);
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
