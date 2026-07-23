export const EVIDENCE_MODES = ["fixture", "local-chain", "live"] as const;
export type EvidenceMode = (typeof EVIDENCE_MODES)[number];

export class EvidenceModeError extends Error {
  override readonly name = "EvidenceModeError";
}

export function parseEvidenceMode(value: unknown): EvidenceMode {
  if (typeof value === "string" && EVIDENCE_MODES.includes(value as EvidenceMode)) {
    return value as EvidenceMode;
  }
  throw new EvidenceModeError(
    `Invalid evidence mode; expected ${EVIDENCE_MODES.join(" | ")}`,
  );
}

export function assertFixtureAuthority(
  deploymentMode: EvidenceMode,
  signedRequestMode: EvidenceMode,
): void {
  if (deploymentMode !== "fixture" || signedRequestMode !== "fixture") {
    throw new EvidenceModeError(
      "Administrator fixture authority requires fixture deployment and fixture-bound request",
    );
  }
}
