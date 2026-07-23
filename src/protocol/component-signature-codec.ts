const BASE64URL_UNPADDED = /^[A-Za-z0-9_-]+$/;
const BASE64_PADDED = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const LOWERCASE_HEX = /^(?:[0-9a-f]{2})+$/;

export class ComponentSignatureEncodingError extends TypeError {
  override readonly name = "ComponentSignatureEncodingError";
}

export function encodeComponentSignatureValue(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) {
    throw new ComponentSignatureEncodingError("Signature bytes must be non-empty");
  }
  return Buffer.from(bytes).toString("base64url");
}

export function decodeComponentSignatureValue(
  value: string,
  expectedBytes?: number,
): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new ComponentSignatureEncodingError("Signature value must be a non-empty string");
  }
  if (!BASE64URL_UNPADDED.test(value)) {
    throw new ComponentSignatureEncodingError("Signature must use the unpadded base64url alphabet");
  }
  if (value.length % 4 === 1) {
    throw new ComponentSignatureEncodingError("Signature has an impossible base64url length");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) {
    throw new ComponentSignatureEncodingError("Signature is not canonical unpadded base64url");
  }
  return checkedLength(decoded, expectedBytes);
}

export type LegacySignatureValueEncoding = "standard-base64-padded" | "lowercase-hex";

export function importLegacyComponentSignatureValue(
  value: string,
  declaredEncoding: LegacySignatureValueEncoding,
  expectedBytes?: number,
): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new ComponentSignatureEncodingError("Legacy signature value must be a non-empty string");
  }
  let decoded: Buffer;
  if (declaredEncoding === "standard-base64-padded") {
    if (!BASE64_PADDED.test(value)) {
      throw new ComponentSignatureEncodingError("Legacy signature is not canonical standard base64");
    }
    decoded = Buffer.from(value, "base64");
    if (decoded.toString("base64") !== value) {
      throw new ComponentSignatureEncodingError("Legacy signature has a non-canonical standard base64 spelling");
    }
  } else if (declaredEncoding === "lowercase-hex") {
    if (!LOWERCASE_HEX.test(value)) {
      throw new ComponentSignatureEncodingError("Legacy signature is not canonical lowercase hex");
    }
    decoded = Buffer.from(value, "hex");
    if (decoded.toString("hex") !== value) {
      throw new ComponentSignatureEncodingError("Legacy signature has a non-canonical lowercase hex spelling");
    }
  } else {
    throw new ComponentSignatureEncodingError("Legacy signature source encoding is unsupported");
  }
  return checkedLength(decoded, expectedBytes);
}

function checkedLength(decoded: Buffer, expectedBytes: number | undefined): Uint8Array {
  if (expectedBytes !== undefined && decoded.byteLength !== expectedBytes) {
    throw new ComponentSignatureEncodingError(`Signature must decode to ${expectedBytes} bytes`);
  }
  return Uint8Array.from(decoded);
}
