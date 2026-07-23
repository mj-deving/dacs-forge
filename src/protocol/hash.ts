import { canonicalize } from "./canonical-json.ts";

const LOWER_HEX_64 = /^[0-9a-f]{64}$/;

export function sha256Hex(value: string | Uint8Array): string {
  const digest = new Bun.CryptoHasher("sha256").update(value).digest("hex");
  if (!LOWER_HEX_64.test(digest)) {
    throw new Error("SHA-256 provider returned an invalid digest");
  }
  return digest;
}

export function contentHash(value: unknown): string {
  return sha256Hex(canonicalize(value));
}
