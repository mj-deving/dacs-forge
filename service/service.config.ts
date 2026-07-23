import inputSchema from "./input.schema.json";
import outputSchema from "./output.schema.json";
import { defineServiceContract } from "../src/service/contract.ts";
import {
  handler,
  type ReferenceTransformInput,
  type ReferenceTransformOutput,
} from "./handler.ts";

export const serviceContract = defineServiceContract<
  ReferenceTransformInput,
  ReferenceTransformOutput
>({
  service: {
    id: "reference-json-transform",
    version: "1.0.0",
    title: "Reference JSON Transform",
    deliverableKind: "attested-payload",
  },
  input: {
    id: inputSchema.$id,
    version: "1",
    schema: inputSchema,
  },
  output: {
    id: outputSchema.$id,
    version: "1",
    schema: outputSchema,
  },
  handler,
});
