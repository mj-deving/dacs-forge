import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  completeAuthorityBootstrap,
  type AuthorityBootstrapCompletion,
  type AuthorityFileStage,
} from "../../src/substrate/authority-offline.ts";

const [inputPath, databasePath, crashStage, nowText] = process.argv.slice(2);
if (inputPath === undefined || databasePath === undefined || crashStage === undefined
  || nowText === undefined) throw new Error("offline crash worker arguments are required");
const now = Number(nowText);
const completion = JSON.parse(readFileSync(inputPath, "utf8")) as AuthorityBootstrapCompletion;
let sequence = 100n;
completeAuthorityBootstrap(completion, {
  databasePath,
  now: () => now,
  keyCurrentness: { resolve: ({ keyClaim, checkedAt }) => ({
    disposition: "current",
    currentClaim: keyClaim,
    recipeVersion: 1,
    checkedAt,
  }) },
  proofVerifier: { verify: ({ key, proof, signedBytes }) =>
    proof === createHmac("sha256", key).update(signedBytes).digest("hex") },
  randomBytes: (size) => {
    const bytes = new Uint8Array(size);
    new DataView(bytes.buffer).setBigUint64(size - 8, sequence++);
    return bytes;
  },
  fault: (stage: AuthorityFileStage) => {
    if (stage === crashStage) process.kill(process.pid, "SIGKILL");
  },
});
