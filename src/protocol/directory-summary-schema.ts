import Ajv2020, { type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

export const COMMUNITY_DIRECTORY_COMMIT = "634caef4b952838281c8c602402e657d41074703";
export const LIVE_LISTING_SUMMARY_SCHEMA_SHA256 =
  "cbd8f545c03929acbd9cc6eccad53268eb267c8270d0d63e492651633f0048ab";

export const PINNED_LISTING_SUMMARY_SCHEMA_JSON =
  '{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"/schemas/listing-summary.schema.json","title":"DACS Directory ListingSummary","type":"object","required":["listingId","version","contentHash","anchor","seller","offering","pricing","status","catalogObservedAt"],"properties":{"listingId":{"type":"string","minLength":1},"version":{"type":"integer","minimum":1},"contentHash":{"type":"string","minLength":1},"anchor":{"type":"object","required":["kind","locator"],"additionalProperties":false,"properties":{"kind":{"type":"string"},"locator":{"type":"string"}}},"seller":{"type":"object","required":["primaryClaim","displayName"],"additionalProperties":false,"properties":{"primaryClaim":{"type":"string"},"displayName":{"type":"string"}}},"artifactProfile":{"enum":["dacs-v0.1","legacy-sdk-v0.1","fixture-listing"]},"publicEndpoint":{"type":"string","format":"uri"},"offering":{"type":"object","required":["title","category","tags"],"properties":{"title":{"type":"string"},"description":{"type":"string"},"category":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}},"rails":{"type":"array","items":{"type":"string"}},"delivery":{"type":"array","items":{"type":"string"}},"negotiation":{"type":"array","items":{"type":"string"}},"deliverable":{"type":"object"}}},"pricing":{"type":"object","properties":{"kind":{"enum":["fixed","negotiable","auction"]},"priceHint":{"type":"string"},"currency":{"type":"string"},"unit":{"type":"string"},"minPct":{"type":"number"},"maxPct":{"type":"number"},"selectionRule":{"type":"string"}}},"status":{"enum":["active","revoked"]},"catalogObservedAt":{"type":"integer"},"reputationHint":{"type":"object"}}}';

export interface DirectorySummaryValidation {
  readonly valid: boolean;
  readonly errors: readonly Readonly<ErrorObject>[];
}

const validator = buildValidator();

export function validateDirectoryListingSummary(value: unknown): DirectorySummaryValidation {
  const valid = validator(value) as boolean;
  const errors = valid
    ? []
    : (validator.errors ?? []).map((error) => Object.freeze({ ...error }));
  return Object.freeze({ valid, errors: Object.freeze(errors) });
}

function buildValidator(): ValidateFunction {
  const ajv = new Ajv2020({
    allErrors: true,
    coerceTypes: false,
    removeAdditional: false,
    strict: true,
    useDefaults: false,
    validateFormats: true,
  });
  addFormats(ajv);
  return ajv.compile(JSON.parse(PINNED_LISTING_SUMMARY_SCHEMA_JSON) as object);
}
