const CANONICAL_DECIMAL = /^(?:0|[1-9]\d*)(?:\.\d*[1-9])?$/;

interface DecimalParts {
  readonly coefficient: bigint;
  readonly scale: number;
}

export function isCanonicalNonNegativeDecimal(value: unknown): value is string {
  return typeof value === "string" && CANONICAL_DECIMAL.test(value);
}

export function isCanonicalPositiveDecimal(value: unknown): value is string {
  return isCanonicalNonNegativeDecimal(value) && value !== "0";
}

export function compareCanonicalDecimals(left: string, right: string): number {
  const a = parseCanonicalDecimal(left);
  const b = parseCanonicalDecimal(right);
  const scale = Math.max(a.scale, b.scale);
  const av = a.coefficient * 10n ** BigInt(scale - a.scale);
  const bv = b.coefficient * 10n ** BigInt(scale - b.scale);
  return av < bv ? -1 : av > bv ? 1 : 0;
}

export function multiplyCanonicalDecimalByInteger(value: string, multiplier: string): string {
  const decimal = parseCanonicalDecimal(value);
  if (!/^(?:0|[1-9]\d*)$/.test(multiplier)) {
    throw new TypeError("Multiplier must be a canonical non-negative integer string");
  }
  return formatCanonicalDecimal(decimal.coefficient * BigInt(multiplier), decimal.scale);
}

export function negotiableBoundsHalfUp(
  center: string,
  minPct: number,
  maxPct: number,
): { readonly lower: string; readonly upper: string } {
  if (!supportedPercentage(minPct) || minPct >= 100 || !supportedPercentage(maxPct)) {
    throw new TypeError("Negotiable percentages are invalid");
  }
  const parsed = parseCanonicalDecimal(center);
  return Object.freeze({
    lower: applyPercentageHalfUp(parsed, minPct, "subtract"),
    upper: applyPercentageHalfUp(parsed, maxPct, "add"),
  });
}

function parseCanonicalDecimal(value: string): DecimalParts {
  if (!isCanonicalNonNegativeDecimal(value)) {
    throw new TypeError("Value is not a CD-1 canonical non-negative decimal");
  }
  const [whole = "0", fraction = ""] = value.split(".");
  return { coefficient: BigInt(`${whole}${fraction}`), scale: fraction.length };
}

function supportedPercentage(value: number): boolean {
  return Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER;
}

function applyPercentageHalfUp(
  center: DecimalParts,
  percentage: number,
  direction: "add" | "subtract",
): string {
  const ratio = decimalNumberRatio(percentage);
  const hundred = 100n * ratio.denominator;
  const factor = direction === "add" ? hundred + ratio.numerator : hundred - ratio.numerator;
  const numerator = center.coefficient * factor;
  const quotient = numerator / hundred;
  const remainder = numerator % hundred;
  return formatCanonicalDecimal(quotient + (remainder * 2n >= hundred ? 1n : 0n), center.scale);
}

function decimalNumberRatio(value: number): { readonly numerator: bigint; readonly denominator: bigint } {
  const [mantissa = "0", exponentText] = value.toString().toLowerCase().split("e");
  const exponent = exponentText === undefined ? 0 : Number(exponentText);
  const [whole = "0", fraction = ""] = mantissa.split(".");
  const digits = BigInt(`${whole}${fraction}`);
  const scale = fraction.length - exponent;
  return scale >= 0
    ? { numerator: digits, denominator: 10n ** BigInt(scale) }
    : { numerator: digits * 10n ** BigInt(-scale), denominator: 1n };
}

function formatCanonicalDecimal(coefficient: bigint, scale: number): string {
  if (coefficient === 0n) return "0";
  let digits = coefficient.toString();
  if (scale === 0) return digits;
  digits = digits.padStart(scale + 1, "0");
  const whole = digits.slice(0, -scale);
  const fraction = digits.slice(-scale).replace(/0+$/, "");
  return fraction.length === 0 ? whole : `${whole}.${fraction}`;
}
