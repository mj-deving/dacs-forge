export type PublicDataMetric = "no2" | "pm10" | "pm25";

export const ATTESTED_PUBLIC_DATA_FIXTURE_SET = "attested-public-data-fixture-v1";

export const PUBLIC_DATA_SOURCE = Object.freeze({
  sourceId: "berlin-open-data-air-quality" as const,
  fixtureLocator: "fixture://attested-public-data/berlin-air-quality/2026-07-01T10:00:00Z",
  publisher: "Berlin Open Data fixture" as const,
  capturedAt: "2026-07-01T10:05:00.000Z",
  records: Object.freeze([
    Object.freeze({ stationId: "DEBE034", metric: "no2" as const, value: "18.2", unit: "ug/m3" as const, observedAt: "2026-07-01T10:00:00.000Z" }),
    Object.freeze({ stationId: "DEBE034", metric: "pm10" as const, value: "21.7", unit: "ug/m3" as const, observedAt: "2026-07-01T10:00:00.000Z" }),
    Object.freeze({ stationId: "DEBE034", metric: "pm25" as const, value: "12.4", unit: "ug/m3" as const, observedAt: "2026-07-01T10:00:00.000Z" }),
    Object.freeze({ stationId: "DEBE065", metric: "no2" as const, value: "11.9", unit: "ug/m3" as const, observedAt: "2026-07-01T10:00:00.000Z" }),
    Object.freeze({ stationId: "DEBE065", metric: "pm25" as const, value: "8.6", unit: "ug/m3" as const, observedAt: "2026-07-01T10:00:00.000Z" }),
  ]),
});
