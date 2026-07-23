import type { AnySchemaObject } from "ajv";
import type { EvidenceMode } from "../core/evidence-mode.ts";
import { canonicalize, deepFreezeJson } from "../protocol/canonical-json.ts";

const MAX_RECEIPT_METADATA_BYTES = 8_192;

export interface ServiceDescriptor {
  readonly id: string;
  readonly version: string;
  readonly title: string;
  readonly deliverableKind: string;
}

export interface ServiceSchemaDescriptor {
  readonly id: string;
  readonly version: string;
  readonly schema: AnySchemaObject;
}

export interface ServiceExecutionContext {
  readonly evidenceMode: EvidenceMode;
  readonly jobId: string;
  readonly seed: string;
}

export type ServiceHandler<TInput, TOutput> = (
  input: Readonly<TInput>,
  context: ServiceExecutionContext,
) => TOutput | Promise<TOutput>;

export interface ServiceContract<TInput, TOutput> {
  readonly service: ServiceDescriptor;
  readonly input: ServiceSchemaDescriptor;
  readonly output: ServiceSchemaDescriptor;
  readonly handler: ServiceHandler<TInput, TOutput>;
}

export function defineServiceContract<TInput, TOutput>(
  contract: ServiceContract<TInput, TOutput>,
): ServiceContract<TInput, TOutput> {
  assertDescriptor(contract.service);
  assertSchemaDescriptor("input", contract.input);
  assertSchemaDescriptor("output", contract.output);
  assertReceiptMetadataBound(contract);
  if (typeof contract.handler !== "function") throw new TypeError("Service handler is required");
  return Object.freeze({
    service: Object.freeze({ ...contract.service }),
    input: Object.freeze({ ...contract.input, schema: snapshotSchema(contract.input.schema) }),
    output: Object.freeze({ ...contract.output, schema: snapshotSchema(contract.output.schema) }),
    handler: contract.handler,
  });
}

function snapshotSchema(schema: AnySchemaObject): AnySchemaObject {
  return deepFreezeJson(JSON.parse(canonicalize(schema)) as AnySchemaObject);
}

function assertDescriptor(descriptor: ServiceDescriptor): void {
  if (descriptor === null || typeof descriptor !== "object") {
    throw new TypeError("Service descriptor is required");
  }
  assertBoundedString("Service id", descriptor.id, 128);
  assertBoundedString("Service version", descriptor.version, 64);
  assertBoundedString("Service title", descriptor.title);
  assertBoundedString("Service deliverableKind", descriptor.deliverableKind, 256);
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(descriptor.id)) {
    throw new TypeError("Service id must be lowercase kebab-case");
  }
  if (!/^\d+\.\d+\.\d+$/.test(descriptor.version)) {
    throw new TypeError("Service version must be an exact semantic version");
  }
}

function assertSchemaDescriptor(label: string, descriptor: ServiceSchemaDescriptor): void {
  if (descriptor === null || typeof descriptor !== "object") {
    throw new TypeError(`Service ${label} schema descriptor is required`);
  }
  assertBoundedString(`Service ${label} schema id`, descriptor.id, 2_048);
  assertBoundedString(`Service ${label} schema version`, descriptor.version, 64);
  if (!isAbsoluteUri(descriptor.id)) {
    throw new TypeError(`Service ${label} schema id must be an absolute URI`);
  }
  if (!/^[A-Za-z0-9._-]+$/.test(descriptor.version)) {
    throw new TypeError(`Service ${label} schema version must be a compact ASCII token`);
  }
  if (descriptor.schema === null || typeof descriptor.schema !== "object") {
    throw new TypeError(`Service ${label} schema must be an object`);
  }
  if (descriptor.schema.$id !== descriptor.id) {
    throw new TypeError(`Service ${label} schema $id must match its descriptor id`);
  }
}

function assertReceiptMetadataBound<TInput, TOutput>(
  contract: ServiceContract<TInput, TOutput>,
): void {
  const metadata = canonicalize({
    service: { id: contract.service.id, version: contract.service.version },
    inputSchema: { id: contract.input.id, version: contract.input.version },
    output: {
      kind: contract.service.deliverableKind,
      schema: { id: contract.output.id, version: contract.output.version },
    },
  });
  if (Buffer.byteLength(metadata, "utf8") > MAX_RECEIPT_METADATA_BYTES) {
    throw new TypeError("Service receipt metadata exceeds its startup-safe byte budget");
  }
}

function isAbsoluteUri(value: string): boolean {
  try {
    return new URL(value).protocol.length > 1;
  } catch {
    return false;
  }
}

function assertBoundedString(
  label: string,
  value: unknown,
  maxLength = 4_096,
): asserts value is string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > maxLength
    || value !== value.normalize("NFC")
  ) throw new TypeError(`${label} must be a bounded NFC string`);
}
