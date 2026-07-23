export class ArtifactSizeLimitError extends RangeError {
  override readonly name = "ArtifactSizeLimitError";

  constructor(
    readonly artifact: string,
    readonly actualBytes: number,
    readonly limitBytes: number,
  ) {
    super(`${artifact} exceeds ${limitBytes} canonical UTF-8 bytes`);
  }
}

export function assertArtifactSizeLimit(
  artifact: string,
  canonicalJson: string,
  limitBytes: number,
): void {
  const actualBytes = Buffer.byteLength(canonicalJson, "utf8");
  if (actualBytes > limitBytes) {
    throw new ArtifactSizeLimitError(artifact, actualBytes, limitBytes);
  }
}
