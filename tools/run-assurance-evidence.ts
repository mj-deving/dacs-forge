import { createHash } from "node:crypto";
import { canonicalize } from "../src/protocol/canonical-json.ts";

const evidenceRoot = `${import.meta.dir}/../evidence/assurance`;

type Verdict = "pass" | "fail";
type Admission = "included" | "excluded";
type Disposition = "verified" | "rejected" | "indeterminate";
type JsonObject = Record<string, unknown>;

interface AssuranceManifest extends JsonObject {
  readonly forgeBase: string;
  readonly dacsStandardPin: string;
  readonly slices: readonly {
    readonly id: string;
    readonly code: readonly { readonly path: string; readonly sha256: string }[];
  }[];
}

interface ClaimRequirementFixture extends JsonObject {
  readonly id: string;
  readonly now: number;
  readonly requirement: {
    readonly scheme: string;
    readonly verificationRequired?: boolean;
    readonly recipeVersion?: number;
    readonly maxAge?: number;
    readonly parameters?: JsonObject;
  };
  readonly cases: readonly {
    readonly caseId: string;
    readonly results: readonly VetResult[];
    readonly expected: Verdict;
    readonly killedMutation?: "scheme-only";
  }[];
}

interface VetResult {
  readonly scheme: string;
  readonly decision: string;
  readonly recipeVersion?: number;
  readonly verifiedAt?: number;
  readonly data?: JsonObject;
}

interface SettlementReputationFixture extends JsonObject {
  readonly id: string;
  readonly agreementPrice: string;
  readonly cases: readonly {
    readonly caseId: string;
    readonly outcome: "completed" | "failed-perm";
    readonly evidence: readonly SettlementAuthority[];
    readonly expected: Admission;
    readonly killedMutation?: SettlementMutation;
  }[];
}

interface SettlementAuthority {
  readonly disposition: "verified" | "rejected" | "indeterminate";
  readonly amount?: boolean;
  readonly payer?: boolean;
  readonly payee?: boolean;
  readonly session?: boolean;
  readonly phase?: boolean;
  readonly rail?: boolean;
  readonly finality?: boolean;
}

type SettlementMutation = "cryptographic-only" | "skip-session-authority" | "skip-phase-authority";

interface BijectionFixture extends JsonObject {
  readonly id: string;
  readonly referenceDefinitions: Readonly<Record<string, {
    readonly phaseKey: string;
    readonly st8: "ordinary" | "interim" | "resolved";
    readonly supersedes?: string;
  }>>;
  readonly cases: readonly BijectionCase[];
}

interface BijectionCase {
  readonly caseId: string;
  readonly expectedPhases: readonly string[];
  readonly topLevel: readonly string[];
  readonly pointers: Readonly<Record<string, string>>;
  readonly st8Terminal?: {
    readonly phaseKey: string;
    readonly state: "resolved" | "expired";
    readonly interimRef: string;
    readonly resolvedRef?: string;
  };
  readonly unrelatedAuthority?: "verified" | "indeterminate";
  readonly expected: Disposition;
  readonly killedMutation?: BijectionMutation;
}

type BijectionMutation =
  | "count-only"
  | "dedupe-before-uniqueness"
  | "membership-only"
  | "skip-st8-raw"
  | "reject-all-st8-interim"
  | "uncertainty-first"
  | "pointer-required"
  | "bundle-derived-plan";

interface CheckResult {
  readonly disposition: Disposition;
  readonly reasonCode:
    | "ok"
    | "raw-multiplicity"
    | "exact-cardinality"
    | "exact-phase-mapping"
    | "pointer-agreement"
    | "st8-raw-admissibility"
    | "unrelated-authority-indeterminate";
}

export async function runAssuranceEvidence() {
  const manifest = await readJson<AssuranceManifest>(`${evidenceRoot}/manifest.json`);
  const claim = await readJson<ClaimRequirementFixture>(`${evidenceRoot}/fixtures/claim-requirement.json`);
  const settlement = await readJson<SettlementReputationFixture>(`${evidenceRoot}/fixtures/settlement-reputation.json`);
  const bijection = await readJson<BijectionFixture>(`${evidenceRoot}/fixtures/settlement-bijection.json`);

  return {
    schema: "dacs-forge-assurance-results/v1",
    forgeBase: manifest.forgeBase,
    dacsStandardPin: manifest.dacsStandardPin,
    evaluationSource: "runner-model",
    productCodeRole: "digest-pinned anchors with separately recorded focused product tests",
    manifestDigest: digest(manifest),
    codeDigestChecks: await verifyCodeDigests(manifest),
    slices: [
      runClaimRequirement(claim),
      runSettlementReputation(settlement),
      runSettlementBijection(bijection),
    ],
  } as const;
}

async function verifyCodeDigests(manifest: AssuranceManifest) {
  const root = `${evidenceRoot}/../..`;
  const checks = [];
  for (const slice of manifest.slices) {
    for (const entry of slice.code) {
      const bytes = new Uint8Array(await Bun.file(`${root}/${entry.path}`).arrayBuffer());
      const observed = createHash("sha256").update(bytes).digest("hex");
      if (observed !== entry.sha256) {
        throw new Error(
          `${slice.id}: evidence-snapshot digest mismatch for ${entry.path}; `
          + "update manifest.json, regenerate with `bun tools/run-assurance-evidence.ts --write`, "
          + "refresh docs/SOURCE-PROVENANCE.json, and re-run the recorded gates",
        );
      }
      checks.push({ sliceId: slice.id, path: entry.path, sha256: observed, matched: true });
    }
  }
  return checks;
}

function runClaimRequirement(fixture: ClaimRequirementFixture) {
  return {
    id: fixture.id,
    fixtureDigest: digest(fixture),
    cases: fixture.cases.map((testCase) => {
      const observed = qualifyClaim(testCase.results, fixture.requirement, fixture.now, false);
      assertExpected(fixture.id, testCase.caseId, testCase.expected, observed);
      return {
        caseId: testCase.caseId,
        expected: testCase.expected,
        observed,
        ...(testCase.killedMutation === undefined ? {} : {
          mutation: mutationResult(
            testCase.killedMutation,
            observed,
            qualifyClaim(testCase.results, fixture.requirement, fixture.now, true),
          ),
        }),
      };
    }),
  };
}

function qualifyClaim(
  results: readonly VetResult[],
  requirement: ClaimRequirementFixture["requirement"],
  now: number,
  schemeOnly: boolean,
): Verdict {
  const passes = results.filter((result) => result.scheme === requirement.scheme
    && result.decision === "pass");
  if (schemeOnly) return passes.length > 0 ? "pass" : "fail";
  return passes.some((result) => {
    if (requirement.recipeVersion !== undefined && result.recipeVersion !== requirement.recipeVersion) return false;
    if (requirement.maxAge !== undefined) {
      if (result.verifiedAt === undefined) return false;
      const expiresAt = result.verifiedAt + requirement.maxAge * 1_000;
      if (!Number.isSafeInteger(expiresAt) || now > expiresAt) return false;
    }
    if (requirement.parameters === undefined) return true;
    if (result.data === undefined) return false;
    return Object.entries(requirement.parameters).every(([key, expected]) =>
      Object.hasOwn(result.data!, key) && jsonEqual(result.data![key], expected));
  }) ? "pass" : "fail";
}

function jsonEqual(left: unknown, right: unknown): boolean {
  try {
    return canonicalize(left) === canonicalize(right);
  } catch {
    return false;
  }
}

function runSettlementReputation(fixture: SettlementReputationFixture) {
  return {
    id: fixture.id,
    fixtureDigest: digest(fixture),
    cases: fixture.cases.map((testCase) => {
      const observed = settlementAdmission(testCase, fixture.agreementPrice);
      assertExpected(fixture.id, testCase.caseId, testCase.expected, observed.admission);
      const mutated = testCase.killedMutation === undefined
        ? undefined
        : settlementAdmission(testCase, fixture.agreementPrice, testCase.killedMutation);
      return {
        caseId: testCase.caseId,
        expected: testCase.expected,
        observed,
        ...(mutated === undefined ? {} : {
          mutation: mutationResult(testCase.killedMutation!, observed.admission, mutated.admission, mutated),
        }),
      };
    }),
  };
}

function settlementAdmission(
  testCase: SettlementReputationFixture["cases"][number],
  agreementPrice: string,
  mutation?: SettlementMutation,
) {
  const included = testCase.evidence.every((authority) => {
    if (mutation === "cryptographic-only") return authority.disposition === "verified";
    if (authority.disposition !== "verified") return false;
    const checks = [authority.amount, authority.payer, authority.payee, authority.rail, authority.finality];
    if (checks.some((value) => value === false)) return false;
    if (mutation !== "skip-session-authority" && authority.session === false) return false;
    if (mutation !== "skip-phase-authority" && authority.phase === false) return false;
    return true;
  });
  const admission: Admission = included ? "included" : "excluded";
  return {
    admission,
    completionNumerator: included && testCase.outcome === "completed" ? 1 : 0,
    partyFaultDenominator: included ? 1 : 0,
    counterpartyAdjustedDenominator: included ? 1 : 0,
    volumeByCurrency: included && testCase.outcome === "completed" && testCase.evidence.length > 0
      ? [agreementPrice] : [],
    disposition: included ? "eligible" : "excluded-without-fault",
  } as const;
}

function runSettlementBijection(fixture: BijectionFixture) {
  return {
    id: fixture.id,
    fixtureDigest: digest(fixture),
    cases: fixture.cases.map((testCase) => {
      const observed = checkBijection(testCase, fixture.referenceDefinitions);
      assertExpected(fixture.id, testCase.caseId, testCase.expected, observed.disposition);
      const mutated = testCase.killedMutation === undefined
        ? undefined
        : checkBijection(testCase, fixture.referenceDefinitions, testCase.killedMutation);
      return {
        caseId: testCase.caseId,
        expected: testCase.expected,
        observed,
        ...(mutated === undefined ? {} : {
          mutation: mutationResult(testCase.killedMutation!, observed.disposition, mutated.disposition, mutated),
        }),
      };
    }),
  };
}

function checkBijection(
  testCase: BijectionCase,
  definitions: BijectionFixture["referenceDefinitions"],
  mutation?: BijectionMutation,
): CheckResult {
  if (mutation === "uncertainty-first" && testCase.unrelatedAuthority === "indeterminate") {
    return indeterminate();
  }
  const refs = testCase.topLevel.map((id) => {
    const definition = definitions[id];
    if (definition === undefined) throw new Error(`Unknown reference ${id}`);
    return { id, ...definition };
  });
  if (mutation === "reject-all-st8-interim" && refs.some((ref) => ref.st8 === "interim")) {
    return rejected("st8-raw-admissibility");
  }
  if (mutation !== "skip-st8-raw") {
    const st8Refs = refs.filter((ref) => ref.st8 !== "ordinary");
    const terminal = testCase.st8Terminal;
    if (st8Refs.length > 0 && terminal === undefined) return rejected("st8-raw-admissibility");
    if (terminal !== undefined) {
      const interim = definitions[terminal.interimRef];
      if (interim?.st8 !== "interim" || interim.phaseKey !== terminal.phaseKey) {
        return rejected("st8-raw-admissibility");
      }
      if (terminal.state === "expired") {
        if (terminal.resolvedRef !== undefined || !testCase.topLevel.includes(terminal.interimRef)
          || st8Refs.some((ref) => ref.id !== terminal.interimRef)) {
          return rejected("st8-raw-admissibility");
        }
      } else {
        const resolvedRef = terminal.resolvedRef;
        const resolved = resolvedRef === undefined ? undefined : definitions[resolvedRef];
        if (resolvedRef === undefined || resolved?.st8 !== "resolved"
          || resolved.phaseKey !== terminal.phaseKey || resolved.supersedes !== terminal.interimRef
          || !testCase.topLevel.includes(resolvedRef) || testCase.topLevel.includes(terminal.interimRef)
          || st8Refs.some((ref) => ref.id !== resolvedRef)) {
          return rejected("st8-raw-admissibility");
        }
      }
    }
  }

  const uniqueIds = [...new Set(testCase.topLevel)];
  if (mutation !== "count-only" && mutation !== "dedupe-before-uniqueness"
    && uniqueIds.length !== testCase.topLevel.length) {
    return rejected("raw-multiplicity");
  }
  const comparedIds = mutation === "dedupe-before-uniqueness" ? uniqueIds : testCase.topLevel;
  const comparedRefs = comparedIds.map((id) => ({ id, ...definitions[id]! }));
  const expectedPhases = mutation === "bundle-derived-plan"
    ? [...new Set(comparedRefs.map((ref) => ref.phaseKey))]
    : [...testCase.expectedPhases];

  if (mutation === "count-only") {
    if (testCase.topLevel.length !== expectedPhases.length) return rejected("exact-cardinality");
  } else {
    if (comparedRefs.length !== expectedPhases.length) return rejected("exact-cardinality");
    const actualPhases = comparedRefs.map((ref) => ref.phaseKey);
    if (new Set(actualPhases).size !== actualPhases.length
      || actualPhases.some((phase) => !expectedPhases.includes(phase))
      || expectedPhases.some((phase) => !actualPhases.includes(phase))) {
      return rejected("exact-phase-mapping");
    }
  }

  if (mutation !== "membership-only") {
    const pointerEntries = Object.entries(testCase.pointers);
    if (mutation === "pointer-required"
      && expectedPhases.some((phase) => !Object.hasOwn(testCase.pointers, phase))) {
      return rejected("pointer-agreement");
    }
    const used = new Set<string>();
    for (const [phase, refId] of pointerEntries) {
      const definition = definitions[refId];
      if (!testCase.topLevel.includes(refId) || definition?.phaseKey !== phase || used.has(refId)) {
        return rejected("pointer-agreement");
      }
      used.add(refId);
    }
  }

  if (testCase.unrelatedAuthority === "indeterminate") return indeterminate();
  return { disposition: "verified", reasonCode: "ok" };
}

function rejected(reasonCode: Exclude<CheckResult["reasonCode"], "ok" | "unrelated-authority-indeterminate">): CheckResult {
  return { disposition: "rejected", reasonCode };
}

function indeterminate(): CheckResult {
  return { disposition: "indeterminate", reasonCode: "unrelated-authority-indeterminate" };
}

function mutationResult(name: string, green: string, red: string, details?: unknown) {
  if (green === red) throw new Error(`Mutation ${name} was not killed: ${green}`);
  return { name, expectedGreen: green, observedRed: red, killed: true, ...(details === undefined ? {} : { details }) };
}

function assertExpected(slice: string, caseId: string, expected: string, observed: string): void {
  if (expected !== observed) throw new Error(`${slice}/${caseId}: expected ${expected}, observed ${observed}`);
}

function digest(value: unknown): string {
  return createHash("sha256").update(canonicalize(value)).digest("hex");
}

async function readJson<T>(path: string): Promise<T> {
  return await Bun.file(path).json() as T;
}

if (import.meta.main) {
  const results = await runAssuranceEvidence();
  const rendered = `${JSON.stringify(results, null, 2)}\n`;
  if (process.argv.includes("--write")) {
    await Bun.write(`${evidenceRoot}/results.json`, rendered);
  } else {
    process.stdout.write(rendered);
  }
}
