import { createHash } from "node:crypto";

export const CALIBRATION_SOURCE_SHA256 =
  "3b292127159a019dfe054da603fb3fe7acb5c5fd48cea6acb5def316f43c487a";

export const CALIBRATION_MUTATOR_COUNTS = Object.freeze({
  ArithmeticOperator: 1,
  BlockStatement: 2,
  BooleanLiteral: 1,
  ConditionalExpression: 6,
  EqualityOperator: 3,
  StringLiteral: 4,
});

export const PROTOCOL_CRITICAL_FILES = Object.freeze([
  "src/protocol/canonical-json.ts",
  "src/protocol/component-signature-codec.ts",
  "src/protocol/decimal.ts",
  "src/protocol/logical-address.ts",
]);

export const PROTOCOL_APPLICABLE_FILES = Object.freeze([
  ...PROTOCOL_CRITICAL_FILES,
  "src/protocol/settlement-address.ts",
]);

export const PROTOCOL_SOURCE_SHA256 = Object.freeze({
  "src/protocol/canonical-json.ts": "46aee9aeef7a63721ba5795debf9a3b4f17ed0fa2778607fe35766c025dff65f",
  "src/protocol/component-signature-codec.ts": "5eff71ce8622290f06beff6e0535c65cde5f83ed560af8dc34659aa6c41243e4",
  "src/protocol/decimal.ts": "f1b3fd73870be84b57fdc98e8b058934a04d0d678a7e0e08c4cc1c21d71547fd",
  "src/protocol/logical-address.ts": "e8a9611d3cfdc5f50ccc2c37c956c6e60716da7d3291d1d9ba3cd590473ea88b",
  "src/protocol/settlement-address.ts": "fdabe3ea1fe000d963bb9564a5f21aa91118038414dd5912494ebd543195ac8e",
});

export const SURVIVOR_DISPOSITIONS = Object.freeze({
  equivalentOrUnreachable: Object.freeze({
    ids: Object.freeze([
      "12", "15", "90", "92", "93", "106", "184", "187", "188", "189", "190",
      "301", "304", "305", "382", "390", "425", "431", "436", "438", "441",
      "442", "443", "446", "472", "473", "474", "475", "496", "497",
    ]),
    identitySha256: "4d9fcaf120dd53af170bf5d16ca6639817041a28e72af2cae24c02b5df95b32f",
    reason: "Equivalent under validated input invariants or unreachable through the public function contract.",
  }),
  diagnosticOnly: Object.freeze({
    ids: Object.freeze(["260", "288", "527"]),
    identitySha256: "82b69c684db4a9f43e9a1f7ecf10339040b65d589479ce46da1cfcac400f9da8",
    reason: "Changes only diagnostic text after the same typed rejection; no accepted protocol value changes.",
  }),
  acceptedThresholdResidual: Object.freeze({
    ids: Object.freeze(["48", "130", "142", "167", "208", "214", "215", "284", "287", "524", "526"]),
    identitySha256: "c6c691b3f7782f05c381f549fbdca18248c5c9ba589751bef5759f25ce80a5a4",
    reason: "Observable assertion gap retained as an explicit survivor after both required aggregate thresholds passed.",
  }),
});

interface MutationLocation {
  readonly end: { readonly column: number; readonly line: number };
  readonly start: { readonly column: number; readonly line: number };
}

export interface MutationRecord {
  readonly id: string;
  readonly location: MutationLocation;
  readonly mutatorName: string;
  readonly replacement: string;
  readonly status: string;
}

export interface ScoredMutationRecord extends MutationRecord {
  readonly fileName: string;
}

interface MutationFile {
  readonly mutants: readonly MutationRecord[];
}

export interface MutationReport {
  readonly files: Readonly<Record<string, MutationFile>>;
  readonly schemaVersion: string;
}

export function assertCommandEquivalence(
  releaseCommand: string,
  mutationCommand: string,
  assertionFiles: readonly string[],
): void {
  const expected = `${releaseCommand} ${assertionFiles.join(" ")}`;
  if (mutationCommand !== expected) {
    throw new Error(`Mutation assertions differ from the release command: expected ${expected}`);
  }
  if (releaseCommand !== "bun test --timeout 10000") {
    throw new Error("Release test command changed without mutation recalibration");
  }
  for (const path of assertionFiles) {
    if (!path.startsWith("test/") || !path.endsWith(".test.ts")) {
      throw new Error(`Mutation assertion is not release-discovered: ${path}`);
    }
  }
}

export function assertCalibrationCatalog(
  report: MutationReport,
  sourceBytes: Uint8Array,
): void {
  const sourceSha256 = createHash("sha256").update(sourceBytes).digest("hex");
  if (sourceSha256 !== CALIBRATION_SOURCE_SHA256) {
    throw new Error("Calibration source changed without catalog recalibration");
  }
  const file = report.files["test/mutation/calibration-target.ts"];
  if (file === undefined || Object.keys(report.files).length !== 1) {
    throw new Error("Calibration report does not contain exactly the fixed target");
  }
  const actualCounts = new Map<string, number>();
  for (const mutant of file.mutants) {
    actualCounts.set(mutant.mutatorName, (actualCounts.get(mutant.mutatorName) ?? 0) + 1);
    if (mutant.status !== "Killed") {
      throw new Error(`Calibration mutant ${mutant.id} was not killed: ${mutant.status}`);
    }
  }
  const expectedTotal = Object.values(CALIBRATION_MUTATOR_COUNTS)
    .reduce((sum, count) => sum + count, 0);
  if (file.mutants.length !== expectedTotal) {
    throw new Error(`Calibration catalog size mismatch: ${file.mutants.length}/${expectedTotal}`);
  }
  for (const [name, count] of Object.entries(CALIBRATION_MUTATOR_COUNTS)) {
    if (actualCounts.get(name) !== count) {
      throw new Error(`Calibration mutator count mismatch for ${name}`);
    }
  }
  if (actualCounts.size !== Object.keys(CALIBRATION_MUTATOR_COUNTS).length) {
    throw new Error("Calibration report contains an unapproved mutator class");
  }
}

export function mutationScore(
  report: MutationReport,
  selectedFiles: readonly string[],
): { readonly applicable: number; readonly detected: number; readonly score: number; readonly survivors: readonly ScoredMutationRecord[] } {
  let detected = 0;
  let applicable = 0;
  const survivors: ScoredMutationRecord[] = [];
  for (const path of selectedFiles) {
    for (const mutant of report.files[path]?.mutants ?? []) {
      switch (mutant.status) {
        case "Killed":
        case "Timeout":
          detected += 1;
          applicable += 1;
          break;
        case "Survived":
        case "NoCoverage":
          applicable += 1;
          survivors.push({ ...mutant, fileName: path });
          break;
        default:
          throw new Error(`Ambiguous mutation status ${mutant.status} in ${path}`);
      }
    }
  }
  if (applicable === 0) throw new Error("Mutation report contains no applicable mutants");
  return Object.freeze({
    applicable,
    detected,
    score: (detected / applicable) * 100,
    survivors: Object.freeze(survivors),
  });
}

export function assertMutationFileSet(
  report: MutationReport,
  expectedFiles: readonly string[],
): void {
  const actual = Object.keys(report.files).sort();
  const expected = [...expectedFiles].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`Mutation file set mismatch: ${actual.join(",")}`);
  }
}

export function assertProtocolSourceHashes(
  sourceBytes: Readonly<Record<string, Uint8Array>>,
): Readonly<Record<string, string>> {
  const actualFiles = Object.keys(sourceBytes).sort();
  const expectedFiles = [...PROTOCOL_APPLICABLE_FILES].sort();
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    throw new Error(`Protocol source file set mismatch: ${actualFiles.join(",")}`);
  }
  const actualHashes = Object.fromEntries(actualFiles.map((path) => [
    path,
    createHash("sha256").update(sourceBytes[path]!).digest("hex"),
  ]));
  for (const path of expectedFiles) {
    if (actualHashes[path] !== PROTOCOL_SOURCE_SHA256[path as keyof typeof PROTOCOL_SOURCE_SHA256]) {
      throw new Error(`Protocol source changed without survivor recalibration: ${path}`);
    }
  }
  return Object.freeze(actualHashes);
}

export function assertSurvivorDispositions(
  survivors: readonly ScoredMutationRecord[],
  sourceSha256: Readonly<Record<string, string>>,
): void {
  const expected = Object.values(SURVIVOR_DISPOSITIONS)
    .flatMap(({ ids }) => ids)
    .sort();
  const actual = survivors.map(({ id }) => id).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`Mutation survivor disposition mismatch: ${actual.join(",")}`);
  }
  for (const { ids, identitySha256 } of Object.values(SURVIVOR_DISPOSITIONS)) {
    const idSet = new Set(ids);
    const identities = survivors
      .filter(({ id }) => idSet.has(id))
      .map((mutant) => JSON.stringify([
        mutant.fileName,
        sourceSha256[mutant.fileName],
        mutant.id,
        mutant.mutatorName,
        mutant.replacement,
        mutant.status,
        mutant.location.start.line,
        mutant.location.start.column,
        mutant.location.end.line,
        mutant.location.end.column,
      ]))
      .sort();
    const actualSha256 = createHash("sha256")
      .update(`${identities.join("\n")}\n`)
      .digest("hex");
    if (actualSha256 !== identitySha256) {
      throw new Error(`Mutation survivor identity mismatch: ${actualSha256}`);
    }
  }
}
