import type { ServiceHandler } from "../src/service/contract.ts";
import { contentHash } from "../src/protocol/hash.ts";
import {
  ATTESTED_PUBLIC_DATA_FIXTURE_SET,
  PUBLIC_DATA_SOURCE,
  type PublicDataMetric,
} from "./fixtures/public-data.ts";

export interface AttestedPublicDataInput {
  readonly datasetId: "berlin-air-quality-hourly";
  readonly stationIds: readonly string[];
  readonly metrics: readonly PublicDataMetric[];
}

export interface PublicDataObservation {
  readonly stationId: string;
  readonly metric: PublicDataMetric;
  readonly value: string;
  readonly unit: "ug/m3";
  readonly observedAt: string;
  readonly sourceId: "berlin-open-data-air-quality";
  readonly contentHash: string;
}

export interface PublicDataAvailability {
  readonly stationId: string;
  readonly metric: PublicDataMetric;
  readonly status: "available" | "not-found";
}

export interface AttestedPublicDataOutput {
  readonly evidenceMode: "fixture";
  readonly fixtureSet: string;
  readonly datasetId: "berlin-air-quality-hourly";
  readonly sourceDescriptors: readonly Readonly<{
    sourceId: "berlin-open-data-air-quality";
    fixtureLocator: string;
    publisher: "Berlin Open Data fixture";
    capturedAt: string;
  }>[];
  readonly observations: readonly PublicDataObservation[];
  readonly availability: readonly PublicDataAvailability[];
  readonly limitations: readonly Readonly<{
    code: "fixture-only" | "not-live" | "no-source-truth" | "not-safety-critical";
    text: string;
  }>[];
}

const LIMITATIONS: AttestedPublicDataOutput["limitations"] = Object.freeze([
  Object.freeze({ code: "fixture-only", text: "The result is derived only from a pinned local public-data fixture." }),
  Object.freeze({ code: "not-live", text: "The result is not a current observation or live upstream read." }),
  Object.freeze({ code: "no-source-truth", text: "The attestation binds delivered bytes and does not establish source truth." }),
  Object.freeze({ code: "not-safety-critical", text: "The result must not be used as a health, safety, or regulatory decision." }),
]);

export const handler: ServiceHandler<AttestedPublicDataInput, AttestedPublicDataOutput> = (
  input,
  context,
) => {
  if (context.seed !== ATTESTED_PUBLIC_DATA_FIXTURE_SET) {
    throw new Error(`Unsupported fixture set: ${context.seed}`);
  }
  const requestedStations = [...input.stationIds].sort();
  const requestedMetrics = [...input.metrics].sort();
  const observations: PublicDataObservation[] = [];
  const availability: PublicDataAvailability[] = [];

  for (const stationId of requestedStations) {
    for (const metric of requestedMetrics) {
      const record = PUBLIC_DATA_SOURCE.records.find((candidate) =>
        candidate.stationId === stationId && candidate.metric === metric
      );
      availability.push({ stationId, metric, status: record === undefined ? "not-found" : "available" });
      if (record !== undefined) {
        observations.push({
          ...record,
          sourceId: PUBLIC_DATA_SOURCE.sourceId,
          contentHash: contentHash(record),
        });
      }
    }
  }

  return {
    evidenceMode: "fixture",
    fixtureSet: ATTESTED_PUBLIC_DATA_FIXTURE_SET,
    datasetId: input.datasetId,
    sourceDescriptors: [Object.freeze({
      sourceId: PUBLIC_DATA_SOURCE.sourceId,
      fixtureLocator: PUBLIC_DATA_SOURCE.fixtureLocator,
      publisher: PUBLIC_DATA_SOURCE.publisher,
      capturedAt: PUBLIC_DATA_SOURCE.capturedAt,
    })],
    observations,
    availability,
    limitations: LIMITATIONS,
  };
};
