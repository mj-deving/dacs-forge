import type { ServiceHandler } from "../src/service/contract.ts";

export interface ReferenceTransformInput {
  readonly document: Readonly<Record<string, string>>;
  readonly select: readonly string[];
}

export interface ReferenceTransformOutput {
  readonly evidenceMode: "fixture";
  readonly missing: readonly string[];
  readonly selected: Readonly<Record<string, string>>;
  readonly seed: string;
}

export const handler: ServiceHandler<ReferenceTransformInput, ReferenceTransformOutput> = (
  input,
  context,
) => {
  const selected = Object.create(null) as Record<string, string>;
  const missing: string[] = [];
  for (const key of [...input.select].sort()) {
    if (!Object.hasOwn(input.document, key)) missing.push(key);
    else selected[key] = input.document[key] as string;
  }
  return {
    evidenceMode: "fixture",
    missing,
    selected,
    seed: context.seed,
  };
};
