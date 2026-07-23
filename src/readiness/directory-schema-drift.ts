import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { types as utilTypes } from "node:util";
import type { EvidenceMode } from "../core/evidence-mode.ts";
import { sha256Hex } from "../protocol/hash.ts";
import {
  LIVE_LISTING_SUMMARY_SCHEMA_SHA256,
} from "../protocol/directory-summary-schema.ts";

export const DIRECTORY_SCHEMA_DRIFT_CHECK_ID = "directory.schema-drift" as const;
export const DIRECTORY_LISTING_SUMMARY_SCHEMA_URL =
  "https://community-production-9ab1.up.railway.app/schemas/listing-summary.schema.json" as const;

const MAX_SCHEMA_BYTES = 65_536;
const ACCEPTED_CONTENT_TYPES = Object.freeze([
  "application/json",
  "application/schema+json",
]);
const preparedProbes = new WeakSet<object>();

export type DirectorySchemaDriftDisposition = "match" | "drift" | "unavailable" | "invalid";

export interface DirectorySchemaReadResponse {
  readonly finalUrl: string;
  readonly status: number;
  readonly contentType: string;
  readonly body: Uint8Array;
}

export type DirectorySchemaReader = (
  url: typeof DIRECTORY_LISTING_SUMMARY_SCHEMA_URL,
) => Promise<DirectorySchemaReadResponse>;

interface DirectorySchemaDriftCheck {
  readonly id: typeof DIRECTORY_SCHEMA_DRIFT_CHECK_ID;
  readonly required: false;
  readonly status: "passed" | "blocked";
  readonly protocolDisposition: "pass" | "indeterminate";
  readonly evidenceMode: EvidenceMode;
  readonly sourceRef: typeof DIRECTORY_LISTING_SUMMARY_SCHEMA_URL;
  readonly observed: Readonly<Record<string, boolean | number | string>>;
  readonly reason?: string;
}

export interface DirectorySchemaDriftProbe {
  readonly id: typeof DIRECTORY_SCHEMA_DRIFT_CHECK_ID;
  readonly required: false;
  readonly run: () => DirectorySchemaDriftCheck;
}

export interface PrepareDirectorySchemaDriftProbeOptions {
  readonly evidenceMode: EvidenceMode;
  readonly readCurrentSchema: DirectorySchemaReader;
}

export async function prepareDirectorySchemaDriftProbe(
  options: PrepareDirectorySchemaDriftProbeOptions,
): Promise<DirectorySchemaDriftProbe> {
  const snapshot = snapshotOptions(options);

  let response: DirectorySchemaReadResponse;
  try {
    response = await snapshot.readCurrentSchema(DIRECTORY_LISTING_SUMMARY_SCHEMA_URL);
  } catch {
    return preparedProbe(blockedCheck("unavailable", snapshot.evidenceMode));
  }
  let check: DirectorySchemaDriftCheck;
  try {
    check = inspectResponse(response, snapshot.evidenceMode);
  } catch {
    check = blockedCheck("invalid", snapshot.evidenceMode);
  }
  return preparedProbe(check);
}

function preparedProbe(check: DirectorySchemaDriftCheck): DirectorySchemaDriftProbe {
  const run = Object.freeze(() => check);
  const probe = Object.freeze({
    id: DIRECTORY_SCHEMA_DRIFT_CHECK_ID,
    required: false as const,
    run,
  });
  preparedProbes.add(probe);
  return probe;
}

export function isPreparedDirectorySchemaDriftProbe(value: unknown): value is DirectorySchemaDriftProbe {
  return (typeof value === "object" && value !== null) || typeof value === "function"
    ? preparedProbes.has(value as object)
    : false;
}

function inspectResponse(value: unknown, evidenceMode: EvidenceMode): DirectorySchemaDriftCheck {
  const response = snapshotResponse(value);
  if (response === null) return blockedCheck("invalid", evidenceMode);
  if (response.finalUrl !== DIRECTORY_LISTING_SUMMARY_SCHEMA_URL) {
    return blockedCheck("invalid", evidenceMode);
  }
  if (response.status !== 200) {
    return blockedCheck("unavailable", evidenceMode, { httpStatus: response.status });
  }
  if (!acceptedContentType(response.contentType)) {
    return blockedCheck("invalid", evidenceMode, { httpStatus: response.status });
  }

  const bodyBytes = response.body.byteLength;
  if (bodyBytes === 0 || bodyBytes > MAX_SCHEMA_BYTES) {
    return blockedCheck("invalid", evidenceMode, {
      httpStatus: response.status,
      schemaBytes: bodyBytes,
    });
  }

  const body = new Uint8Array(response.body);
  const currentSha256 = sha256Hex(body);
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(body);
    const schema = JSON.parse(decoded) as unknown;
    if (!validJsonSchema(schema)) {
      return blockedCheck("invalid", evidenceMode, {
        httpStatus: response.status,
        schemaBytes: bodyBytes,
        currentSha256,
      });
    }
  } catch {
    return blockedCheck("invalid", evidenceMode, {
      httpStatus: response.status,
      schemaBytes: bodyBytes,
      currentSha256,
    });
  }

  const disposition: DirectorySchemaDriftDisposition =
    currentSha256 === LIVE_LISTING_SUMMARY_SCHEMA_SHA256 ? "match" : "drift";
  return Object.freeze({
    id: DIRECTORY_SCHEMA_DRIFT_CHECK_ID,
    required: false,
    status: disposition === "match" ? "passed" : "blocked",
    protocolDisposition: disposition === "match" ? "pass" : "indeterminate",
    evidenceMode,
    sourceRef: DIRECTORY_LISTING_SUMMARY_SCHEMA_URL,
    observed: Object.freeze({
      disposition,
      pinnedSha256: LIVE_LISTING_SUMMARY_SCHEMA_SHA256,
      currentSha256,
      schemaBytes: bodyBytes,
      httpStatus: response.status,
    }),
    ...(disposition === "match" ? {} : {
      reason: "Current Directory ListingSummary schema differs from the pinned compatibility schema",
    }),
  });
}

function blockedCheck(
  disposition: "unavailable" | "invalid",
  evidenceMode: EvidenceMode,
  observed: Readonly<Record<string, boolean | number | string>> = {},
): DirectorySchemaDriftCheck {
  return Object.freeze({
    id: DIRECTORY_SCHEMA_DRIFT_CHECK_ID,
    required: false,
    status: "blocked",
    protocolDisposition: "indeterminate",
    evidenceMode,
    sourceRef: DIRECTORY_LISTING_SUMMARY_SCHEMA_URL,
    observed: Object.freeze({
      disposition,
      pinnedSha256: LIVE_LISTING_SUMMARY_SCHEMA_SHA256,
      ...observed,
    }),
    reason: disposition === "unavailable"
      ? "Current Directory ListingSummary schema is unavailable"
      : "Current Directory ListingSummary schema response is invalid",
  });
}

function acceptedContentType(value: string): boolean {
  if (value.length > 256) return false;
  const match = /^(application\/(?:json|schema\+json))(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|"utf-8"))?[ \t]*$/i
    .exec(value);
  return match !== null && ACCEPTED_CONTENT_TYPES.includes(match[1]!.toLowerCase());
}

function snapshotResponse(value: unknown): DirectorySchemaReadResponse | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype) return null;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 4 || keys.some((key) => typeof key !== "string")
    || !["finalUrl", "status", "contentType", "body"].every((key) => keys.includes(key))) return null;

  const fields: Record<string, unknown> = {};
  for (const key of keys as string[]) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) return null;
    fields[key] = descriptor.value;
  }
  const body = fields["body"];
  if (typeof fields["finalUrl"] !== "string"
    || !Number.isInteger(fields["status"]) || (fields["status"] as number) < 100
    || (fields["status"] as number) > 599
    || typeof fields["contentType"] !== "string"
    || !utilTypes.isUint8Array(body)) return null;
  return Object.freeze({
    finalUrl: fields["finalUrl"],
    status: fields["status"],
    contentType: fields["contentType"],
    body,
  }) as DirectorySchemaReadResponse;
}

function validJsonSchema(value: unknown): boolean {
  if (typeof value !== "boolean"
    && (typeof value !== "object" || value === null || Array.isArray(value))) return false;
  try {
    const validator = new Ajv2020({ strict: true });
    addFormats(validator);
    if (!validator.validateSchema(value)) return false;
    validator.compile(value);
    return true;
  } catch {
    return false;
  }
}

function snapshotOptions(value: unknown): PrepareDirectorySchemaDriftProbeOptions {
  if (typeof value !== "object" || value === null || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError("Directory schema-drift options must be an object");
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 2 || !keys.includes("evidenceMode") || !keys.includes("readCurrentSchema")) {
    throw new TypeError("Directory schema-drift options are invalid");
  }
  const mode = Object.getOwnPropertyDescriptor(value, "evidenceMode");
  const reader = Object.getOwnPropertyDescriptor(value, "readCurrentSchema");
  if (mode === undefined || !("value" in mode) || !mode.enumerable
    || !["fixture", "local-chain", "live"].includes(mode.value as string)
    || reader === undefined || !("value" in reader) || !reader.enumerable
    || typeof reader.value !== "function") {
    throw new TypeError("Directory schema-drift options are invalid");
  }
  return Object.freeze({
    evidenceMode: mode.value as EvidenceMode,
    readCurrentSchema: reader.value as DirectorySchemaReader,
  });
}
