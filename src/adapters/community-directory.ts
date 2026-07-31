import type { EffectReconciliation } from "../live/effect-runner.ts";
import type { LiveDirectoryAdapter } from "../live/listing-publication.ts";

interface DirectoryResult extends Record<string, unknown> {
  readonly externalRef: string;
  readonly projection: Readonly<Record<string, unknown>>;
}

export interface CommunityDirectoryAdapterConfig {
  readonly endpoint: string;
}

/** Optional live-only adapter for the Community catalog; discovery remains non-authoritative. */
export function createCommunityDirectoryAdapter(
  config: CommunityDirectoryAdapterConfig,
): LiveDirectoryAdapter {
  const base = httpsBase(config.endpoint);
  const adapter: LiveDirectoryAdapter = {
    reconcile: async ({ payload }): Promise<EffectReconciliation<DirectoryResult>> => {
      const registration = payload.registration;
      const expectedProjection = payload.expectedProjection;
      const listingId = expectedProjection["listingId"];
      const version = expectedProjection["version"];
      if (typeof listingId !== "string" || !Number.isSafeInteger(version)) {
        return { disposition: "indeterminate", reason: "Directory projection identity is invalid" };
      }
      let response: Response;
      try {
        const catalogUrl = new URL("listings", base);
        catalogUrl.searchParams.set("primaryClaim", registration.primaryClaim);
        catalogUrl.searchParams.set("limit", "100");
        response = await fetch(catalogUrl, { headers: { accept: "application/json" } });
      } catch (error) {
        return { disposition: "indeterminate", reason: error instanceof Error ? error.message : String(error) };
      }
      if (response.status === 404) return { disposition: "absent" };
      if (!response.ok) return { disposition: "indeterminate", reason: `Directory read failed with HTTP ${response.status}` };
      const catalog = await response.json() as unknown;
      if (!isRecord(catalog) || !Array.isArray(catalog["listings"])) {
        return { disposition: "indeterminate", reason: "Directory read returned malformed JSON" };
      }
      const projection = catalog["listings"].find((candidate) => isRecord(candidate)
        && candidate["listingId"] === listingId && candidate["version"] === version);
      if (!isRecord(projection)) return { disposition: "absent" };
      if (projection["contentHash"] !== expectedProjection["contentHash"]
        || (projection["anchor"] as Record<string, unknown> | undefined)?.["locator"]
          !== (expectedProjection["anchor"] as Record<string, unknown> | undefined)?.["locator"]) {
        return { disposition: "indeterminate", reason: "Directory projection disagrees with verified chain Listing" };
      }
      return Object.freeze({
        externalRef: response.url,
        projection: Object.freeze(projection),
      });
    },
    submit: async ({ payload }) => {
      const response = await fetch(new URL("register", base), {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(payload.registration),
      });
      if (!response.ok) throw new Error(`Directory registration failed with HTTP ${response.status}`);
      const body = await response.json() as unknown;
      if (!isRecord(body) || body["ok"] !== true || body["queued"] !== true) {
        throw new Error("Directory registration did not return the queued contract");
      }
      return Object.freeze({
        externalRef: `${base.href}register#${encodeURIComponent(payload.registration.primaryClaim)}`,
        projection: payload.expectedProjection,
      });
    },
  };
  return Object.freeze(adapter);
}

function httpsBase(value: string): URL {
  const url = new URL(value.endsWith("/") ? value : `${value}/`);
  if (url.protocol !== "https:") throw new TypeError("Community Directory endpoint must use HTTPS");
  return url;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
