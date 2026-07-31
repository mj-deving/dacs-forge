import { contentHash } from "../../src/protocol/hash.ts";
import type { AttestedPublicDataInput, AttestedPublicDataOutput } from "../handler.ts";
import { ATTESTED_PUBLIC_DATA_FIXTURE_SET, PUBLIC_DATA_SOURCE } from "./public-data.ts";

const no2 = PUBLIC_DATA_SOURCE.records.find((record) =>
  record.stationId === "DEBE034" && record.metric === "no2"
)!;
const pm25 = PUBLIC_DATA_SOURCE.records.find((record) =>
  record.stationId === "DEBE034" && record.metric === "pm25"
)!;

const limitations = Object.freeze([
  Object.freeze({ code: "fixture-only" as const, text: "The result is derived only from a pinned local public-data fixture." }),
  Object.freeze({ code: "not-live" as const, text: "The result is not a current observation or live upstream read." }),
  Object.freeze({ code: "no-source-truth" as const, text: "The attestation binds delivered bytes and does not establish source truth." }),
  Object.freeze({ code: "not-safety-critical" as const, text: "The result must not be used as a health, safety, or regulatory decision." }),
]);

const sourceDescriptors = Object.freeze([Object.freeze({
  sourceId: PUBLIC_DATA_SOURCE.sourceId,
  fixtureLocator: PUBLIC_DATA_SOURCE.fixtureLocator,
  publisher: PUBLIC_DATA_SOURCE.publisher,
  capturedAt: PUBLIC_DATA_SOURCE.capturedAt,
})]);

export const BASIC_FIXTURE = Object.freeze({
  jobId: "01J00000000000000000000001",
  seed: ATTESTED_PUBLIC_DATA_FIXTURE_SET,
  producedAt: "2026-07-17T08:00:00.000Z",
  input: Object.freeze({
    datasetId: "berlin-air-quality-hourly" as const,
    stationIds: Object.freeze(["DEBE034"]),
    metrics: Object.freeze(["pm25" as const, "no2" as const]),
  }) satisfies AttestedPublicDataInput,
  alternateInput: Object.freeze({
    datasetId: "berlin-air-quality-hourly" as const,
    stationIds: Object.freeze(["DEBE065"]),
    metrics: Object.freeze(["pm25" as const, "no2" as const]),
  }) satisfies AttestedPublicDataInput,
  invalidInputs: Object.freeze([
    Object.freeze({ datasetId: "berlin-air-quality-hourly", stationIds: Object.freeze([]), metrics: Object.freeze(["no2"]) }),
    Object.freeze({ datasetId: "other", stationIds: Object.freeze(["DEBE034"]), metrics: Object.freeze(["no2"]) }),
    Object.freeze({ datasetId: "berlin-air-quality-hourly", stationIds: Object.freeze(["DEBE034"]), metrics: Object.freeze(["ozone"]) }),
    Object.freeze({ datasetId: "berlin-air-quality-hourly", stationIds: Object.freeze(["bad id"]), metrics: Object.freeze(["no2"]), extra: true }),
  ]),
  invalidOutput: null,
  behaviorVectors: Object.freeze([
    Object.freeze({
      input: Object.freeze({
        datasetId: "berlin-air-quality-hourly" as const,
        stationIds: Object.freeze(["DEBE999"]),
        metrics: Object.freeze(["pm10" as const]),
      }) satisfies AttestedPublicDataInput,
      output: Object.freeze({
        evidenceMode: "fixture" as const,
        fixtureSet: ATTESTED_PUBLIC_DATA_FIXTURE_SET,
        datasetId: "berlin-air-quality-hourly" as const,
        sourceDescriptors,
        observations: Object.freeze([]),
        availability: Object.freeze([Object.freeze({ stationId: "DEBE999", metric: "pm10" as const, status: "not-found" as const })]),
        limitations,
      }) satisfies AttestedPublicDataOutput,
    }),
  ]),
  output: Object.freeze({
    evidenceMode: "fixture" as const,
    fixtureSet: ATTESTED_PUBLIC_DATA_FIXTURE_SET,
    datasetId: "berlin-air-quality-hourly" as const,
    sourceDescriptors,
    observations: Object.freeze([
      Object.freeze({ ...no2, sourceId: PUBLIC_DATA_SOURCE.sourceId, contentHash: contentHash(no2) }),
      Object.freeze({ ...pm25, sourceId: PUBLIC_DATA_SOURCE.sourceId, contentHash: contentHash(pm25) }),
    ]),
    availability: Object.freeze([
      Object.freeze({ stationId: "DEBE034", metric: "no2" as const, status: "available" as const }),
      Object.freeze({ stationId: "DEBE034", metric: "pm25" as const, status: "available" as const }),
    ]),
    limitations,
  }) satisfies AttestedPublicDataOutput,
});
