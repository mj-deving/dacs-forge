import inputSchema from "./input.schema.json";
import outputSchema from "./output.schema.json";
import serviceDescriptor from "./fixtures/service-descriptor.json";
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
  service: serviceDescriptor,
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
