export const assertionFiles = Object.freeze([
  "test/protocol/canonical-json.test.ts",
  "test/protocol/component-signature-codec.test.ts",
  "test/protocol/decimal.test.ts",
  "test/protocol/hash.test.ts",
  "test/protocol/logical-address.test.ts",
  "test/protocol/settlement-address.test.ts",
  "test/mutation/protocol-pure-modules.test.ts",
]);

export default {
  testRunner: "command",
  commandRunner: {
    command: `bun test --timeout 10000 ${assertionFiles.join(" ")}`,
  },
  coverageAnalysis: "off",
  tsconfigFile: "tools/mutation/no-tsconfig.json",
  mutate: [
    "src/protocol/canonical-json.ts",
    "src/protocol/component-signature-codec.ts",
    "src/protocol/decimal.ts",
    "src/protocol/logical-address.ts",
    "src/protocol/settlement-address.ts",
  ],
  reporters: ["clear-text", "json"],
  jsonReporter: {
    fileName: ".stryker-tmp/protocol-report.json",
  },
  tempDirName: ".stryker-tmp/protocol",
  cleanTempDir: "always",
  concurrency: 2,
  timeoutMS: 10_000,
  thresholds: {
    high: 90,
    low: 80,
    break: 80,
  },
};
