import type {
  AdmissionInput,
  AdmissionResult,
  ChallengeAllocationInput,
  SessionRecord,
  SessionStore,
} from "../substrate/sqlite/session-store.ts";
import { HttpResourceGuards } from "./resource-guards.ts";
import {
  boundedTerminalJsonResponse,
  enforceTerminalSchema,
  terminalErrorResponse,
} from "./terminal-server.ts";

export const SESSION_CHALLENGE_ROUTE = "session-challenge";
export const SESSION_CREATE_ROUTE = "session-create";

const MAX_RESPONSE_BYTES = 16_384;
const MAX_REQUEST_URL_LENGTH = 2_048;
const MAX_AUTHORIZATION_LENGTH = 128;

export interface FixtureAdministratorAuthorizationRequest {
  readonly authorization: string;
  readonly admission: AdmissionInput;
}

export interface FixtureAdministratorAdmission {
  admitAuthorized(input: FixtureAdministratorAuthorizationRequest): AdmissionResult;
}

export interface SessionAdmissionHttpOptions {
  readonly guards: HttpResourceGuards;
  readonly sessionStore: SessionStore;
  readonly fixtureAdministratorAdmission?: FixtureAdministratorAdmission;
}

/** Protected challenge/session endpoints; the resource guard runs before either store call. */
export function createSessionAdmissionHttpHandler(
  options: SessionAdmissionHttpOptions,
): (request: Request) => Promise<Response> {
  if (options?.guards === undefined || options.sessionStore === undefined) {
    throw new TypeError("Session admission HTTP requires guards and a session store");
  }
  const handler = async (request: Request): Promise<Response> => {
    if (request.url.length > MAX_REQUEST_URL_LENGTH) {
      return terminalErrorResponse(404, "not-found");
    }
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      return terminalErrorResponse(404, "not-found");
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return terminalErrorResponse(421, "misdirected-request");
    }
    if (url.search !== "" || url.hash !== "") return terminalErrorResponse(404, "not-found");
    if (request.method !== "POST") return terminalErrorResponse(405, "method-not-allowed");

    if (url.pathname === "/v1/session-challenges") {
      return options.guards.run(SESSION_CHALLENGE_ROUTE, request, (_request, body) => {
        const input = decodeJson(body);
        if (input === undefined) return terminalErrorResponse(400, "schema-violation");
        const result = options.sessionStore.allocateChallenge(input as ChallengeAllocationInput);
        if (result.disposition === "conflict") return terminalErrorResponse(409, "conflict");
        if (result.disposition === "quota-exceeded") {
          return terminalErrorResponse(429, "rate-limited");
        }
        if (result.disposition === "rejected") return terminalErrorResponse(401, "unauthorized");
        if (!("challenge" in result)) return terminalErrorResponse(500, "internal-error");
        return boundedTerminalJsonResponse(Object.freeze({
          schema: "dacs-session-challenge/v1",
          disposition: result.disposition,
          challenge: result.challenge,
        }), result.disposition === "created" ? 201 : 200, MAX_RESPONSE_BYTES);
      });
    }

    if (url.pathname === "/v1/sessions") {
      return options.guards.run(SESSION_CREATE_ROUTE, request, (guardedRequest, body) => {
        const input = decodeJson(body);
        if (!plainRecord(input)) return terminalErrorResponse(400, "schema-violation");
        let result: AdmissionResult;
        if (input["kind"] === "external" && exactKeys(input, ["admission", "kind"])) {
          result = options.sessionStore.admit(input["admission"] as AdmissionInput);
        } else if (input["kind"] === "fixture-admin" && exactKeys(input, ["admission", "kind"])) {
          const authorization = guardedRequest.headers.get("authorization");
          if (authorization === null || authorization.length === 0
            || authorization.length > MAX_AUTHORIZATION_LENGTH
            || options.fixtureAdministratorAdmission === undefined) {
            return terminalErrorResponse(401, "unauthorized");
          }
          const admission = input["admission"] as AdmissionInput;
          try {
            result = options.fixtureAdministratorAdmission.admitAuthorized(Object.freeze({
              authorization,
              admission,
            }));
          } catch {
            return terminalErrorResponse(500, "internal-error");
          }
        } else {
          return terminalErrorResponse(400, "schema-violation");
        }
        if (result.disposition === "conflict") return terminalErrorResponse(409, "conflict");
        if (result.disposition === "rejected") return terminalErrorResponse(401, "unauthorized");
        return sessionResponse(result.session);
      });
    }
    return terminalErrorResponse(404, "not-found");
  };
  return enforceTerminalSchema(handler);
}

function sessionResponse(session: SessionRecord): Response {
  return boundedTerminalJsonResponse(Object.freeze({
    schema: "dacs-session/v1",
    disposition: "created",
    session: Object.freeze({
      instanceId: session.instanceId,
      audience: session.audience,
      jobId: session.jobId,
      evidenceMode: session.evidenceMode,
      requestHash: session.requestHash,
      admissionFingerprint: session.admissionFingerprint,
      status: session.status,
      version: String(session.version),
      createdAt: session.createdAt,
    }),
  }), 201, MAX_RESPONSE_BYTES);
}

function decodeJson(body: Uint8Array): unknown | undefined {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(body);
    if (text.length === 0) return undefined;
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}
