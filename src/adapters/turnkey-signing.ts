import type { TurnkeyClient } from "@turnkey/http";
import type {
  TurnkeyActivity,
  TurnkeyActivityClient,
  TurnkeySignRawPayloadRequest,
} from "../live/turnkey-signing-activity.ts";

type OfficialTurnkeyClient = Pick<TurnkeyClient, "getActivity" | "signRawPayload">;

/**
 * Binds Forge's purpose-specific recovery protocol to Turnkey's official server SDK.
 * Credential loading and API-key stamping remain owned by the injected SDK client.
 */
export function connectOfficialTurnkeyActivityClient(
  client: OfficialTurnkeyClient,
): TurnkeyActivityClient {
  return Object.freeze({
    submitSignRawPayload: async (request: TurnkeySignRawPayloadRequest) => {
      assertTurnkeyRequestUsesEd25519RawSigning(request);
      return normalizeActivity((await client.signRawPayload(request)).activity);
    },
    getActivity: async (input: Readonly<{ organizationId: string; activityId: string }>) => normalizeActivity((await client.getActivity({
      organizationId: input.organizationId,
      activityId: input.activityId,
    })).activity),
  });
}

function normalizeActivity(value: Awaited<ReturnType<OfficialTurnkeyClient["getActivity"]>>["activity"]): TurnkeyActivity {
  const intent = value.intent.signRawPayloadIntentV2;
  if (intent === undefined) throw new Error("Turnkey SDK returned an Activity without the expected signing intent");
  const signature = value.result.signRawPayloadResult;
  return Object.freeze({
    id: value.id,
    organizationId: value.organizationId,
    status: value.status,
    type: value.type,
    intent: Object.freeze({ signRawPayloadIntentV2: Object.freeze({ ...intent }) }),
    ...(signature === undefined
      ? {}
      : { result: Object.freeze({ signRawPayloadResult: Object.freeze({ ...signature }) }) }),
    ...(value.failure === undefined ? {} : { failure: Object.freeze({
      code: value.failure.code,
      message: value.failure.message,
    }) }),
  });
}

export function assertTurnkeyRequestUsesEd25519RawSigning(
  request: TurnkeySignRawPayloadRequest,
): void {
  if (request.type !== "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2"
    || request.parameters.encoding !== "PAYLOAD_ENCODING_HEXADECIMAL"
    || request.parameters.hashFunction !== "HASH_FUNCTION_NOT_APPLICABLE") {
    throw new Error("Turnkey request is not the admitted Ed25519 raw-signing shape");
  }
}
