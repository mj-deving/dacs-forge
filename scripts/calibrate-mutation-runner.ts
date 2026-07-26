import { readFile } from "node:fs/promises";
import {
  assertCalibrationCatalog,
  assertCommandEquivalence,
  assertMutationFileSet,
  assertProtocolSourceHashes,
  assertSurvivorDispositions,
  mutationScore,
  PROTOCOL_APPLICABLE_FILES,
  PROTOCOL_CRITICAL_FILES,
  SURVIVOR_DISPOSITIONS,
  type MutationReport,
} from "../tools/mutation/report.ts";
import calibrationConfig from "../tools/mutation/stryker-calibration.config.mjs";
import protocolConfig, {
  assertionFiles as protocolAssertionFiles,
} from "../tools/mutation/stryker-protocol.config.mjs";

const calibrationAssertionFiles = Object.freeze([
  "test/mutation/calibration.test.ts",
]);
const calibrationContractFiles = Object.freeze([
  ...calibrationAssertionFiles,
  "test/mutation/runner-contract.test.ts",
]);
const packageJson = await Bun.file("package.json").json() as {
  readonly scripts?: Readonly<Record<string, string>>;
};
const releaseCommand = packageJson.scripts?.["test"];
if (releaseCommand === undefined) throw new Error("package.json has no release test command");

assertCommandEquivalence(
  releaseCommand,
  calibrationConfig.commandRunner.command,
  calibrationAssertionFiles,
);
assertCommandEquivalence(
  releaseCommand,
  protocolConfig.commandRunner.command,
  protocolAssertionFiles,
);

await run(releaseCommand, calibrationContractFiles);
await runStryker("tools/mutation/stryker-calibration.config.mjs");
const calibrationReport = await loadReport(".stryker-tmp/calibration-report.json");
assertCalibrationCatalog(
  calibrationReport,
  await readFile("test/mutation/calibration-target.ts"),
);

if (!process.argv.includes("--calibration-only")) {
  await readProtocolSourceHashes();
  await run(releaseCommand, protocolAssertionFiles);
  await runStryker("tools/mutation/stryker-protocol.config.mjs");
  const protocolReport = await loadReport(".stryker-tmp/protocol-report.json");
  assertMutationFileSet(protocolReport, PROTOCOL_APPLICABLE_FILES);
  const critical = mutationScore(protocolReport, PROTOCOL_CRITICAL_FILES);
  const overall = mutationScore(protocolReport, PROTOCOL_APPLICABLE_FILES);
  assertSurvivorDispositions(overall.survivors, await readProtocolSourceHashes());
  if (critical.score < 90) {
    throw new Error(`Protocol-critical mutation score is ${critical.score.toFixed(2)}%, expected >= 90%`);
  }
  if (overall.score < 80) {
    throw new Error(`Overall mutation score is ${overall.score.toFixed(2)}%, expected >= 80%`);
  }
  console.log(JSON.stringify({
    runner: "@stryker-mutator/core@9.6.1",
    assertionCommand: protocolConfig.commandRunner.command,
    calibration: { killed: 17, total: 17 },
    critical: {
      applicable: critical.applicable,
      detected: critical.detected,
      score: critical.score,
      survivors: critical.survivors.length,
    },
    overall: {
      applicable: overall.applicable,
      detected: overall.detected,
      score: overall.score,
      survivors: overall.survivors.length,
    },
    survivorDispositions: SURVIVOR_DISPOSITIONS,
  }, null, 2));
} else {
  console.log(JSON.stringify({
    runner: "@stryker-mutator/core@9.6.1",
    assertionCommand: calibrationConfig.commandRunner.command,
    calibration: { killed: 17, total: 17 },
  }, null, 2));
}

async function loadReport(path: string): Promise<MutationReport> {
  return JSON.parse(await readFile(path, "utf8")) as MutationReport;
}

async function readProtocolSourceHashes(): Promise<Readonly<Record<string, string>>> {
  const sourceBytes = Object.fromEntries(await Promise.all(
    PROTOCOL_APPLICABLE_FILES.map(async (path) => [path, await readFile(path)] as const),
  ));
  return assertProtocolSourceHashes(sourceBytes);
}

async function run(releaseTestCommand: string, files: readonly string[]): Promise<void> {
  const [executable, ...baseArguments] = releaseTestCommand.split(" ");
  if (executable === undefined) throw new Error("Release command is empty");
  const process = Bun.spawn([executable, ...baseArguments, ...files], {
    stderr: "inherit",
    stdout: "inherit",
  });
  if (await process.exited !== 0) throw new Error("Release-equivalent assertion run failed");
}

async function runStryker(configPath: string): Promise<void> {
  const process = Bun.spawn([
    "./node_modules/.bin/stryker",
    "run",
    configPath,
  ], { stderr: "inherit", stdout: "inherit" });
  if (await process.exited !== 0) throw new Error(`Stryker failed for ${configPath}`);
}
