import { resolve } from "node:path";
import {
  assertTrustedVerifierCheckout,
  formatFindings,
  scanCriticalTree,
} from "../tools/exemplar-policy.ts";

function option(name: string): string {
  const index = process.argv.indexOf(name);
  const value = index < 0 ? undefined : process.argv[index + 1];
  if (!value) throw new Error(`missing ${name}`);
  return value;
}

const trustedRoot = resolve(import.meta.dir, "..");
const repository = resolve(option("--repository"));
const base = option("--base");
const tip = option("--tip");

assertTrustedVerifierCheckout(trustedRoot, base);
const findings = await scanCriticalTree(repository, tip);
if (findings.length > 0) throw new Error(`critical-path scan rejected:\n${formatFindings(findings)}`);
console.log(`critical-path scan verified: ${tip}; no forbidden markers, focused/skipped tests, or empty exported functions`);
