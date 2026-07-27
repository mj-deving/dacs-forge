import {
  createPrivateKey,
  sign as signBytes,
  type KeyObject,
} from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  Dacs2KeyCurrentnessResolver,
  KeyCurrentnessResolution,
} from "../../src/substrate/keys/production-key-lifecycle.ts";
import { ProductionKeyLifecycle } from "../../src/substrate/keys/production-key-lifecycle.ts";
import type { NonExportingEd25519Provider } from "../../src/producer/fixture-ed25519.ts";
import { openDatabase, type DacsDatabase } from "../../src/substrate/sqlite/database.ts";

const ED25519_PKCS8_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export class TestSignerProvider implements NonExportingEd25519Provider {
  readonly providerId = "test-non-exporting-provider";
  readonly #keys = new Map<string, KeyObject>();

  add(keyHandle: string, seed: Uint8Array): this {
    if (seed.byteLength !== 32) throw new TypeError("test seed must be 32 bytes");
    this.#keys.set(keyHandle, createPrivateKey({
      key: Buffer.concat([ED25519_PKCS8_SEED_PREFIX, Buffer.from(seed)]),
      format: "der",
      type: "pkcs8",
    }));
    return this;
  }

  publicKey(keyHandle: string): Uint8Array {
    const key = this.#key(keyHandle);
    const jwk = key.export({ format: "jwk" });
    if (typeof jwk.x !== "string") throw new Error("test public key unavailable");
    return Uint8Array.from(Buffer.from(jwk.x, "base64url"));
  }

  sign(keyHandle: string, payload: Uint8Array): Uint8Array {
    return Uint8Array.from(signBytes(null, Buffer.from(payload), this.#key(keyHandle)));
  }

  claim(keyHandle: string): string {
    return `key:${Buffer.from(this.publicKey(keyHandle)).toString("hex")}`;
  }

  #key(keyHandle: string): KeyObject {
    const key = this.#keys.get(keyHandle);
    if (key === undefined) throw new Error(`unknown test key handle: ${keyHandle}`);
    return key;
  }
}

export class TestCurrentnessResolver implements Dacs2KeyCurrentnessResolver {
  #currentClaim: string | null = null;
  readonly #revoked = new Set<string>();
  readonly #superseded = new Set<string>();

  current(claim: string): void {
    if (this.#currentClaim !== null && this.#currentClaim !== claim) {
      this.#superseded.add(this.#currentClaim);
    }
    this.#currentClaim = claim;
    this.#revoked.delete(claim);
    this.#superseded.delete(claim);
  }

  revoke(claim: string): void {
    this.#revoked.add(claim);
    if (this.#currentClaim === claim) this.#currentClaim = null;
  }

  resolve(input: Readonly<{ readonly keyClaim: string; readonly checkedAt: number }> ):
    KeyCurrentnessResolution {
    if (input.keyClaim === this.#currentClaim) {
      return Object.freeze({
        disposition: "current",
        currentClaim: input.keyClaim,
        recipeVersion: 1,
        checkedAt: input.checkedAt,
      });
    }
    if (this.#revoked.has(input.keyClaim)) {
      return Object.freeze({
        disposition: "revoked",
        currentClaim: this.#currentClaim ?? input.keyClaim,
        recipeVersion: 1,
        checkedAt: input.checkedAt,
      });
    }
    if (this.#superseded.has(input.keyClaim)) {
      return Object.freeze({
        disposition: "superseded",
        currentClaim: this.#currentClaim ?? input.keyClaim,
        recipeVersion: 1,
        checkedAt: input.checkedAt,
      });
    }
    return Object.freeze({
      disposition: "indeterminate",
      recipeVersion: 1,
      checkedAt: input.checkedAt,
    });
  }
}

export async function withProductionKeyLifecycle<T>(
  callback: (context: Readonly<{
    readonly database: DacsDatabase;
    readonly lifecycle: ProductionKeyLifecycle;
    readonly path: string;
    readonly provider: TestSignerProvider;
    readonly resolver: TestCurrentnessResolver;
  }>) => T | Promise<T>,
): Promise<T> {
  const directory = await mkdtemp(join(tmpdir(), "dacs-production-keys-"));
  const path = join(directory, "state.sqlite");
  const database = openDatabase(path);
  const provider = new TestSignerProvider()
    .add("primary-v1", Buffer.alloc(32, 21))
    .add("primary-v2", Buffer.alloc(32, 22));
  const resolver = new TestCurrentnessResolver();
  const lifecycle = new ProductionKeyLifecycle(database, {
    deploymentMode: "local-chain",
    provider,
    resolver,
  });
  try {
    return await callback({ database, lifecycle, path, provider, resolver });
  } finally {
    database.close(false);
    await rm(directory, { force: true, recursive: true });
  }
}
