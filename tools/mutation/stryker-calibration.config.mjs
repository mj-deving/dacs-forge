export default {
  testRunner: "command",
  commandRunner: {
    command: "bun test --timeout 10000 test/mutation/calibration.test.ts",
  },
  coverageAnalysis: "off",
  // Stryker's sandbox tsconfig rewriter does not yet understand TypeScript 7.
  // Bun executes the instrumented TypeScript directly, so no tsconfig rewrite is needed.
  tsconfigFile: "tools/mutation/no-tsconfig.json",
  mutate: ["test/mutation/calibration-target.ts"],
  reporters: ["clear-text", "json"],
  jsonReporter: {
    fileName: ".stryker-tmp/calibration-report.json",
  },
  tempDirName: ".stryker-tmp/calibration",
  cleanTempDir: "always",
  concurrency: 1,
  timeoutMS: 10_000,
  thresholds: {
    high: 100,
    low: 100,
    break: 100,
  },
};
