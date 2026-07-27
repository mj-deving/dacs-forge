import {
  CapabilityHistoryLimitError,
  CapabilityPreparationLimitError,
  AdministratorSessionLimitError,
  type PartyAuthorityLifecycle,
} from "../substrate/sqlite/party-authority-lifecycle.ts";
import { HttpResourceGuards } from "./resource-guards.ts";
import {
  boundedTerminalJsonResponse,
  enforceTerminalSchema,
  terminalErrorResponse,
} from "./terminal-server.ts";

export const PARTY_CHALLENGE_ROUTE = "party-capability-challenge";
export const PARTY_EXCHANGE_ROUTE = "party-capability-exchange";
export const CAPABILITY_REPLACEMENT_ROUTE = "capability-replacement";
export const CAPABILITY_RENEW_ROUTE = "capability-renew";
export const CAPABILITY_REVOKE_ROUTE = "capability-revoke";
export const ADMINISTRATOR_ROTATE_ROUTE = "administrator-rotate";
export const ADMINISTRATOR_SESSIONS_ROUTE = "administrator-sessions";

const MAX_RESPONSE_BYTES = 16_384;
const MAX_REQUEST_URL_LENGTH = 2_048;
const MAX_AUTHORIZATION_LENGTH = 128;

export interface PartyAuthorityHttpOptions {
  readonly authority: PartyAuthorityLifecycle;
  readonly guards: HttpResourceGuards;
}

export function createPartyAuthorityHttpHandler(
  options: PartyAuthorityHttpOptions,
): (request: Request) => Promise<Response> {
  if (options?.authority === undefined || options.guards === undefined) {
    throw new TypeError("Party authority HTTP requires lifecycle authority and resource guards");
  }
  const handler = async (request: Request): Promise<Response> => {
    if (request.url.length > MAX_REQUEST_URL_LENGTH) return terminalErrorResponse(404, "not-found");
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      return terminalErrorResponse(404, "not-found");
    }
    if ((url.protocol !== "http:" && url.protocol !== "https:")
      || url.search !== "" || url.hash !== "") return terminalErrorResponse(404, "not-found");

    if (url.pathname === "/v1/administrator/sessions") {
      if (request.method !== "GET") return terminalErrorResponse(405, "method-not-allowed");
      return options.guards.run(ADMINISTRATOR_SESSIONS_ROUTE, request, (guarded) => {
        const token = bearer(guarded);
        if (token === null) return terminalErrorResponse(401, "unauthorized");
        try {
          return boundedTerminalJsonResponse(Object.freeze({
            schema: "dacs-administrator-sessions/v1",
            sessions: options.authority.listAdministratorSessions(token),
          }), 200, MAX_RESPONSE_BYTES);
        } catch (error) {
          return error instanceof AdministratorSessionLimitError
            ? terminalErrorResponse(413, "payload-too-large")
            : terminalErrorResponse(401, "unauthorized");
        }
      });
    }
    if (request.method !== "POST") return terminalErrorResponse(405, "method-not-allowed");

    if (url.pathname === "/v1/party-capability-challenges") {
      return options.guards.run(PARTY_CHALLENGE_ROUTE, request, (_guarded, body) => {
        const input = decodedRecord(body);
        if (input === null || !exactKeys(input, [
          "clientIdempotencyKey", "clientNonce", "jobId", "operations",
          "principal", "proof", "requestedAtMs", "role",
        ])) return terminalErrorResponse(400, "schema-violation");
        const result = options.authority.allocatePartyChallenge(input as never);
        if (result.disposition === "conflict") return terminalErrorResponse(409, "conflict");
        if (result.disposition === "quota-exceeded") return terminalErrorResponse(429, "rate-limited");
        if (result.disposition === "rejected") return terminalErrorResponse(401, "unauthorized");
        if (!("challenge" in result)) return terminalErrorResponse(500, "internal-error");
        return boundedTerminalJsonResponse(Object.freeze({
          schema: "dacs-party-capability-challenge/v1",
          disposition: result.disposition,
          challenge: result.challenge,
        }), result.disposition === "created" ? 201 : 200, MAX_RESPONSE_BYTES);
      });
    }

    if (url.pathname === "/v1/party-capabilities") {
      return options.guards.run(PARTY_EXCHANGE_ROUTE, request, (_guarded, body) => {
        const input = decodedRecord(body);
        if (input === null || !exactKeys(input, [
          "expiresAtMs", "nonce", "proof", "replacementToken",
        ])) {
          return terminalErrorResponse(400, "schema-violation");
        }
        const result = options.authority.exchangePartyChallenge(input as never);
        if (result.disposition === "quota-exceeded") return terminalErrorResponse(429, "rate-limited");
        if (result.disposition !== "created") return terminalErrorResponse(401, "unauthorized");
        return capabilityResponse("dacs-party-capability/v1", result.grant, 201);
      });
    }

    if (url.pathname === "/v1/capability-replacements") {
      return options.guards.run(CAPABILITY_REPLACEMENT_ROUTE, request, (_guarded, body) => {
        const input = decodedRecord(body);
        if (input === null || !exactKeys(input, [])) {
          return terminalErrorResponse(400, "schema-violation");
        }
        try {
          return boundedTerminalJsonResponse(Object.freeze({
            schema: "dacs-capability-replacement/v1",
            token: options.authority.prepareCapabilityReplacement(),
          }), 201, MAX_RESPONSE_BYTES);
        } catch (error) {
          return error instanceof CapabilityPreparationLimitError
            ? terminalErrorResponse(429, "rate-limited")
            : terminalErrorResponse(500, "internal-error");
        }
      });
    }

    if (url.pathname === "/v1/capabilities/renew") {
      return options.guards.run(CAPABILITY_RENEW_ROUTE, request, (guarded, body) => {
        const input = decodedRecord(body);
        const token = bearer(guarded);
        if (input === null || !exactKeys(input, [
          "expiresAtMs", "proof", "replacementToken", "requestedAtMs",
        ])
          || token === null) return terminalErrorResponse(401, "unauthorized");
        try {
          const grant = options.authority.renew({
            token,
            expiresAtMs: input["expiresAtMs"] as number,
            proof: input["proof"] as string,
            replacementToken: input["replacementToken"] as string,
            requestedAtMs: input["requestedAtMs"] as number,
          });
          return capabilityResponse("dacs-capability-renewal/v1", grant, 201);
        } catch (error) {
          return error instanceof CapabilityHistoryLimitError
            ? terminalErrorResponse(429, "rate-limited")
            : terminalErrorResponse(401, "unauthorized");
        }
      });
    }

    if (url.pathname === "/v1/capabilities/revoke") {
      return options.guards.run(CAPABILITY_REVOKE_ROUTE, request, (guarded, body) => {
        const input = decodedRecord(body);
        const authorization = bearer(guarded);
        if (input === null || !exactKeys(input, ["proof", "requestedAtMs", "targetToken"])
          || authorization === null) return terminalErrorResponse(401, "unauthorized");
        try {
          options.authority.revoke({
            authorization,
            targetToken: input["targetToken"] as string,
            proof: input["proof"] as string,
            requestedAtMs: input["requestedAtMs"] as number,
          });
          return boundedTerminalJsonResponse(Object.freeze({
            schema: "dacs-capability-revocation/v1",
            revoked: true,
          }), 200, MAX_RESPONSE_BYTES);
        } catch {
          return terminalErrorResponse(401, "unauthorized");
        }
      });
    }

    if (url.pathname === "/v1/administrators/rotate") {
      return options.guards.run(ADMINISTRATOR_ROTATE_ROUTE, request, (guarded, body) => {
        const input = decodedRecord(body);
        const authorization = bearer(guarded);
        if (input === null || !exactKeys(input, [
          "expiresAtMs", "newConfiguredKey", "newKeyProof", "newPrincipal", "operations",
          "proof", "replacementToken", "requestedAtMs",
        ]) || authorization === null) return terminalErrorResponse(401, "unauthorized");
        try {
          const grant = options.authority.rotateAdministrator({
            authorization,
            expiresAtMs: input["expiresAtMs"] as number,
            newConfiguredKey: input["newConfiguredKey"] as string,
            newKeyProof: input["newKeyProof"] as string,
            newPrincipal: input["newPrincipal"] as string,
            operations: input["operations"] as readonly string[],
            proof: input["proof"] as string,
            replacementToken: input["replacementToken"] as string,
            requestedAtMs: input["requestedAtMs"] as number,
          });
          return capabilityResponse("dacs-administrator-rotation/v1", grant, 201);
        } catch (error) {
          return error instanceof CapabilityHistoryLimitError
            ? terminalErrorResponse(429, "rate-limited")
            : terminalErrorResponse(401, "unauthorized");
        }
      });
    }
    return terminalErrorResponse(404, "not-found");
  };
  return enforceTerminalSchema(handler);
}

function capabilityResponse(schema: string, grant: Readonly<{
  readonly token: string;
  readonly scope: unknown;
}>, status: number): Response {
  return boundedTerminalJsonResponse(Object.freeze({ schema, grant }), status, MAX_RESPONSE_BYTES);
}

function decodedRecord(body: Uint8Array): Record<string, unknown> | null {
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(body);
    const value = JSON.parse(decoded) as unknown;
    if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
    const prototype = Object.getPrototypeOf(value) as unknown;
    return prototype === Object.prototype || prototype === null
      ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function bearer(request: Request): string | null {
  const value = request.headers.get("authorization");
  if (value === null || value.length > MAX_AUTHORIZATION_LENGTH || !value.startsWith("Bearer ")) {
    return null;
  }
  const token = value.slice(7);
  return /^[0-9a-f]{64}$/.test(token) ? token : null;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length
    && actual.every((item, index) => item === sorted[index]);
}
