import { describe, expect, test } from "bun:test";
import { inspect } from "node:util";
import packageMetadataJson from "../../package.json" with { type: "json" };
import {
  assertDoctorReport,
  DOCTOR_STATUSES,
  doctorExitCode,
  runDoctor,
  serializeDoctorReport,
  type DoctorCheck,
  type DoctorOptions,
} from "../../src/readiness/doctor.ts";

const base = {
  evidenceMode: "fixture" as const,
  sourceRef: "test:probe",
  observed: Object.freeze({ value: "ok" }),
};

function synthetic(
  status: DoctorCheck["status"],
  required = true,
  id = `probe.${status}`,
): DoctorCheck {
  return Object.freeze({
    ...base,
    id,
    required,
    status,
    ...(status === "passed" ? { protocolDisposition: "pass" as const } : {}),
    ...(status === "failed" ? { protocolDisposition: "fail" as const } : {}),
    ...(status === "blocked" || status === "not-run" || status === "not-applicable"
      ? { reason: `synthetic ${status}` } : {}),
  });
}

function captureError(call: () => unknown): unknown {
  try {
    call();
    return null;
  } catch (error) {
    return error;
  }
}

function expectOutputFreeRejection(value: unknown): void {
  expect(typeof value).toBe("object");
  expect(value).not.toBeNull();
  expect(Object.getPrototypeOf(value)).toBeNull();
  expect(Object.isFrozen(value)).toBe(true);
  expect(String(value)).toBe("");
}

function expectDetachedDiagnostic(value: unknown, message: string): void {
  expect(typeof value).toBe("object");
  expect(value).not.toBeNull();
  expect(Object.getPrototypeOf(value)).toBeNull();
  expect(Object.isFrozen(value)).toBe(true);
  expect(String(value)).toContain(message);
}

describe("Doctor Core", () => {
  test("keeps status and package provenance immutable across callbacks", async () => {
    expect(Object.isFrozen(DOCTOR_STATUSES)).toBe(true);
    expect(() => (DOCTOR_STATUSES as unknown as string[]).splice(0, 1)).toThrow();

    const originalVersion = packageMetadataJson.version;
    let report;
    try {
      report = await runDoctor({
        now: () => {
          packageMetadataJson.version = "callback-forged";
          return "2026-07-20T10:30:00.000Z";
        },
        probes: [{
          id: "probe.status-registry",
          required: true,
          run: () => {
            expect(() => (DOCTOR_STATUSES as unknown as string[]).splice(0, 1)).toThrow();
            throw new Error("status registry remained frozen");
          },
        }],
      });
    } finally {
      packageMetadataJson.version = originalVersion;
    }
    expect(report?.version).toBe("0.1.1");
    expect(report?.exitCode).toBe(4);
    assertDoctorReport(report);
  });

  test("uses captured slicing and rejects canonical-evidence secret collisions", async () => {
    const originalSlice = String.prototype.slice;
    let prototypeError;
    try {
      prototypeError = captureError(() => runDoctor({
        probes: [{
          id: "probe.slice-intrinsic",
          required: true,
          run: () => {
            String.prototype.slice = (() => { throw new Error("live slice invoked"); }) as typeof String.prototype.slice;
            throw new Error("x".repeat(4096));
          },
        }],
      }));
    } finally {
      String.prototype.slice = originalSlice;
    }
    expectDetachedDiagnostic(prototypeError, "Doctor report prototype chain is unsafe");

    const bounded = await runDoctor({
      probes: [{
        id: "probe.bounded-error",
        required: true,
        run: () => { throw new Error("x".repeat(4096)); },
      }],
    });
    expect(bounded.exitCode).toBe(4);
    expect(bounded.checks[0]?.reason?.length).toBe(1024);
    assertDoctorReport(bounded);

    const collision = captureError(() => runDoctor({ sensitiveValues: ["1.3.9"] }));
    expectOutputFreeRejection(collision);
    expect(String(collision)).not.toContain("1.3.9");
  });

  test("rejects mutable RegExp exec and replace protocols", async () => {
    const originalExec = RegExp.prototype.exec;
    let execError;
    try {
      execError = captureError(() => runDoctor({
        probes: [{
          id: "probe.regex-exec",
          required: true,
          run: () => {
            RegExp.prototype.exec = (() => null) as typeof RegExp.prototype.exec;
            return {
              ...synthetic("passed", true, "probe.regex-exec"),
              sourceRef: "test:\u0000invalid",
            };
          },
        }],
      }));
    } finally {
      RegExp.prototype.exec = originalExec;
    }
    expect(String(execError)).toContain("Doctor report prototype chain is unsafe");

    const replaceDescriptor = Object.getOwnPropertyDescriptor(RegExp.prototype, Symbol.replace);
    let replaceError;
    try {
      Object.defineProperty(RegExp.prototype, Symbol.replace, {
        configurable: true,
        value: () => "forged normalization",
      });
      replaceError = captureError(() => runDoctor({
        probes: [{
          id: "probe.regex-replace",
          required: true,
          run: () => ({
            ...synthetic("failed", true, "probe.regex-replace"),
            reason: "expected failure",
          }),
        }],
      }));
    } finally {
      if (replaceDescriptor === undefined) {
        delete (RegExp.prototype as { [Symbol.replace]?: unknown })[Symbol.replace];
      } else Object.defineProperty(RegExp.prototype, Symbol.replace, replaceDescriptor);
    }
    expect(String(replaceError)).toContain("Doctor report prototype chain is unsafe");
  });

  test("redacts complete diagnostics without Symbol.split dispatch", async () => {
    const longSecret = "A".repeat(1500);
    const longReport = await runDoctor({
      sensitiveValues: [longSecret],
      probes: [{
        id: "probe.long-secret",
        required: true,
        run: () => { throw new Error(`prefix-${longSecret}-suffix`); },
      }],
    });
    expect(longReport.exitCode).toBe(4);
    expect(longReport.checks[0]?.reason).toBe("prefix--suffix");
    expect(serializeDoctorReport(longReport)).not.toContain("A".repeat(100));
    assertDoctorReport(longReport);

    const splitDescriptor = Object.getOwnPropertyDescriptor(String.prototype, Symbol.split);
    let splitCalls = 0;
    let splitError;
    try {
      Object.defineProperty(String.prototype, Symbol.split, {
        configurable: true,
        value: () => {
          splitCalls += 1;
          throw new Error("Symbol.split invoked");
        },
      });
      splitError = captureError(() => runDoctor({
        sensitiveValues: ["split-secret"],
        probes: [{
          id: "probe.split-hook",
          required: true,
          run: () => ({
            ...synthetic("failed", true, "probe.split-hook"),
            reason: "split-secret failure",
          }),
        }],
      }));
    } finally {
      if (splitDescriptor === undefined) {
        delete (String.prototype as { [Symbol.split]?: unknown })[Symbol.split];
      } else Object.defineProperty(String.prototype, Symbol.split, splitDescriptor);
    }
    expect(splitCalls).toBe(0);
    expectOutputFreeRejection(splitError);
    expect(String(splitError)).toBe("");
  });

  test("bypasses inherited setters when committing options and probe results", async () => {
    const arrayIndex = Object.getOwnPropertyDescriptor(Array.prototype, "8");
    const arrayLength = Array.prototype.length;
    let arrayError;
    try {
      arrayError = captureError(() => runDoctor({
        probes: [
          {
            id: "probe.setter-install",
            required: false,
            run: () => {
              Object.defineProperty(Array.prototype, "8", {
                configurable: true,
                set(this: unknown[], value: unknown) {
                  const item = value as Partial<DoctorCheck>;
                  const committed = item.id === "probe.setter-target"
                    ? synthetic("passed", true, "probe.setter-target") : value;
                  Object.defineProperty(this, "8", {
                    configurable: true,
                    enumerable: true,
                    value: committed,
                    writable: true,
                  });
                },
              });
              return synthetic("passed", false, "probe.setter-install");
            },
          },
          {
            id: "probe.setter-target",
            required: true,
            run: () => synthetic("failed", true, "probe.setter-target"),
          },
        ],
      }));
    } finally {
      if (arrayIndex === undefined) {
        delete (Array.prototype as unknown as Record<string, unknown>)["8"];
        Array.prototype.length = arrayLength;
      }
      else Object.defineProperty(Array.prototype, "8", arrayIndex);
    }
    expectDetachedDiagnostic(arrayError, "Doctor report prototype chain is unsafe");

    const optionDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "sensitiveValues");
    const secret = "prototype-setter-secret";
    let optionError;
    try {
      Object.defineProperty(Object.prototype, "sensitiveValues", {
        configurable: true,
        get: () => [],
        set: () => undefined,
      });
      optionError = captureError(() => runDoctor({
        sensitiveValues: [secret],
        probes: [{
          id: "probe.option-setter",
          required: false,
          run: () => ({
            ...synthetic("passed", false, "probe.option-setter"),
            observed: { detail: secret },
          }),
        }],
      }));
    } finally {
      if (optionDescriptor === undefined) {
        delete (Object.prototype as { sensitiveValues?: unknown }).sensitiveValues;
      } else Object.defineProperty(Object.prototype, "sensitiveValues", optionDescriptor);
    }
    expectOutputFreeRejection(optionError);
    expect(String(optionError)).not.toContain(secret);
  });

  test("captures runtime evidence before caller hooks", async () => {
    const report = await runDoctor({
      now: () => {
        expect(Reflect.set(Bun, "version", "forged")).toBe(false);
        return "2026-07-20T10:30:00.000Z";
      },
    });
    expect(report?.checks.find((item) => item.id === "runtime.bun")?.observed["version"])
      .toBe("1.3.9");
    assertDoctorReport(report);

    const originalTypeError = globalThis.TypeError;
    let attackerConstructorRuns = 0;
    let capturedTypeErrorReport;
    try {
      capturedTypeErrorReport = await runDoctor({
        now: () => {
          globalThis.TypeError = class AttackerTypeError extends Error {
            constructor() {
              attackerConstructorRuns += 1;
              super("attacker TypeError ran");
            }
          } as typeof TypeError;
          return "invalid timestamp";
        },
      });
    } finally {
      globalThis.TypeError = originalTypeError;
    }
    expect(attackerConstructorRuns).toBe(0);
    expect(capturedTypeErrorReport?.exitCode).toBe(4);
    assertDoctorReport(capturedTypeErrorReport);
  });

  test("ignores inherited accessors for omitted options and optional check fields", async () => {
    const evidenceModeDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "evidenceMode");
    let inheritedModeReads = 0;
    let prototypeError;
    try {
      Object.defineProperty(Object.prototype, "evidenceMode", {
        configurable: true,
        get: () => {
          inheritedModeReads += 1;
          return "live";
        },
      });
      prototypeError = captureError(() => runDoctor({}));
    } finally {
      if (evidenceModeDescriptor === undefined) {
        delete (Object.prototype as { evidenceMode?: unknown }).evidenceMode;
      } else Object.defineProperty(Object.prototype, "evidenceMode", evidenceModeDescriptor);
    }
    expect(inheritedModeReads).toBe(0);
    expectDetachedDiagnostic(prototypeError, "Doctor report prototype chain is unsafe");

    const valueDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "value");
    let descriptorAccessorRan = false;
    const accessorProbe = Object.defineProperties({}, {
      id: {
        enumerable: true,
        get: () => {
          descriptorAccessorRan = true;
          return "probe.descriptor-accessor";
        },
      },
      required: { enumerable: true, value: false },
      run: { enumerable: true, value: () => synthetic("passed", false, "probe.descriptor-accessor") },
    });
    let descriptorError;
    try {
      Object.defineProperty(Object.prototype, "value", {
        configurable: true,
        value: "probe.descriptor-accessor",
      });
      descriptorError = captureError(() => runDoctor({ probes: [accessorProbe as never] }));
    } finally {
      if (valueDescriptor === undefined) delete (Object.prototype as { value?: unknown }).value;
      else Object.defineProperty(Object.prototype, "value", valueDescriptor);
    }
    expect(descriptorAccessorRan).toBe(false);
    expect(descriptorError).toBeInstanceOf(Error);

    const external = JSON.parse(JSON.stringify(await runDoctor())) as {
      checks: Array<Record<string, unknown>>;
    };
    external.checks.push({
      id: "probe.inherited-reason",
      required: false,
      status: "passed",
      protocolDisposition: "pass",
      evidenceMode: "fixture",
      sourceRef: "test:inherited-reason",
      observed: { completed: true },
    });
    const reasonDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "reason");
    let inheritedReasonReads = 0;
    let validationError: unknown;
    try {
      Object.defineProperty(Object.prototype, "reason", {
        configurable: true,
        get(this: Record<string, unknown>) {
          if (this["id"] === "probe.inherited-reason") {
            inheritedReasonReads += 1;
            Object.defineProperty(this, "reason", {
              enumerable: true,
              value: "invalid\u0000reason",
            });
          }
          return undefined;
        },
      });
      try {
        serializeDoctorReport(external as unknown as Awaited<ReturnType<typeof runDoctor>>);
      } catch (error) {
        validationError = error;
      }
    } finally {
      if (reasonDescriptor === undefined) {
        delete (Object.prototype as { reason?: unknown }).reason;
      } else Object.defineProperty(Object.prototype, "reason", reasonDescriptor);
    }
    expect(inheritedReasonReads).toBe(0);
    expect(validationError).toBeInstanceOf(Error);
  });

  test("fails output-free on poisoned prototype chains and rejection coercion", async () => {
    const arrayPrototype = Object.getPrototypeOf(Array.prototype);
    const proxyPrototype = new Proxy(arrayPrototype, {
      getOwnPropertyDescriptor: () => undefined,
      get: (target, property, receiver) => property === "toJSON"
        ? () => ({ checks: "forged" }) : Reflect.get(target, property, receiver),
    });
    let chainError;
    try {
      chainError = captureError(() => runDoctor({
        sensitiveValues: ["Doctor"],
        probes: [{
          id: "probe.prototype-chain",
          required: false,
          run: () => {
            Object.setPrototypeOf(Array.prototype, proxyPrototype);
            return synthetic("passed", false, "probe.prototype-chain");
          },
        }],
      }));
    } finally {
      Object.setPrototypeOf(Array.prototype, arrayPrototype);
    }
    expectOutputFreeRejection(chainError);
    expect(String(chainError)).toBe("");

    const arrayValueOfDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "valueOf");
    const arrayValueSecret = "array-value-secret";
    let arrayValueError;
    try {
      Object.defineProperty(Array.prototype, "valueOf", {
        configurable: true,
        value: () => arrayValueSecret,
      });
      arrayValueError = captureError(() => runDoctor({ sensitiveValues: [arrayValueSecret] }));
    } finally {
      if (arrayValueOfDescriptor === undefined) {
        delete (Array.prototype as { valueOf?: unknown }).valueOf;
      } else Object.defineProperty(Array.prototype, "valueOf", arrayValueOfDescriptor);
    }
    expectOutputFreeRejection(arrayValueError);
    expect(String(arrayValueError)).toBe("");

    const iteratorDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, Symbol.iterator)!;
    const iteratorSecret = "array-iterator-secret";
    let iteratorError;
    try {
      Object.defineProperty(Array.prototype, Symbol.iterator, {
        ...iteratorDescriptor,
        value: function* poisonedIterator() {
          yield iteratorSecret;
        },
      });
      iteratorError = captureError(() => runDoctor({ sensitiveValues: [iteratorSecret] }));
    } finally {
      Object.defineProperty(Array.prototype, Symbol.iterator, iteratorDescriptor);
    }
    expectOutputFreeRejection(iteratorError);
    expect(String(iteratorError)).toBe("");

    const unscopables = Array.prototype[Symbol.unscopables] as Record<string, unknown>;
    const unscopablesMap = Object.getOwnPropertyDescriptor(unscopables, "map");
    let unscopablesError;
    try {
      Object.defineProperty(unscopables, "map", {
        configurable: true,
        enumerable: true,
        value: true,
        writable: true,
      });
      unscopablesError = captureError(() => runDoctor());
    } finally {
      if (unscopablesMap === undefined) delete unscopables["map"];
      else Object.defineProperty(unscopables, "map", unscopablesMap);
    }
    expect(Object.getPrototypeOf(unscopablesError)).toBeNull();
    expect(Object.isFrozen(unscopablesError)).toBe(true);
    expect(String(unscopablesError)).toContain("Doctor report prototype chain is unsafe");

    const errorPrimitive = Object.getOwnPropertyDescriptor(Error.prototype, Symbol.toPrimitive);
    let primitiveRuns = 0;
    let detachedDiagnostic: unknown;
    try {
      Object.defineProperty(Error.prototype, Symbol.toPrimitive, {
        configurable: true,
        value: () => {
          primitiveRuns += 1;
          return "probe-controlled-error";
        },
      });
      Object.defineProperty(unscopables, "map", {
        configurable: true,
        enumerable: true,
        value: true,
        writable: true,
      });
      detachedDiagnostic = captureError(() => runDoctor());
    } finally {
      if (errorPrimitive === undefined) {
        delete (Error.prototype as { [Symbol.toPrimitive]?: unknown })[Symbol.toPrimitive];
      } else Object.defineProperty(Error.prototype, Symbol.toPrimitive, errorPrimitive);
      if (unscopablesMap === undefined) delete unscopables["map"];
      else Object.defineProperty(unscopables, "map", unscopablesMap);
    }
    expect(Object.getPrototypeOf(detachedDiagnostic)).toBeNull();
    expect(Object.isFrozen(detachedDiagnostic)).toBe(true);
    expect(String(detachedDiagnostic)).toContain("Doctor report prototype chain is unsafe");
    expect(primitiveRuns).toBe(0);

    const mapThen = Object.getOwnPropertyDescriptor(Array.prototype.map, "then");
    let callableThenRuns = 0;
    let callableError: unknown;
    try {
      Object.defineProperty(Array.prototype.map, "then", {
        configurable: true,
        value: () => {
          callableThenRuns += 1;
        },
      });
      callableError = captureError(() => runDoctor());
    } finally {
      if (mapThen === undefined) delete (Array.prototype.map as { then?: unknown }).then;
      else Object.defineProperty(Array.prototype.map, "then", mapThen);
    }
    expectDetachedDiagnostic(callableError, "Doctor report prototype chain is unsafe");
    expect(callableThenRuns).toBe(0);

    const iteratorPrototypes = [
      Object.getPrototypeOf([][Symbol.iterator]()) as object,
      Object.getPrototypeOf(""[Symbol.iterator]()) as object,
    ];
    for (let index = 0; index < iteratorPrototypes.length; index += 1) {
      const prototype = iteratorPrototypes[index]!;
      const nextDescriptor = Object.getOwnPropertyDescriptor(prototype, "next")!;
      const iteratorPrototypeSecret = `iterator-prototype-secret-${index}`;
      let iteratorPrototypeError;
      try {
        Object.defineProperty(prototype, "next", {
          ...nextDescriptor,
          value: () => { throw new Error(iteratorPrototypeSecret); },
        });
        iteratorPrototypeError = captureError(() => runDoctor({
          sensitiveValues: [iteratorPrototypeSecret],
        }));
      } finally {
        Object.defineProperty(prototype, "next", nextDescriptor);
      }
      expectOutputFreeRejection(iteratorPrototypeError);
      expect(String(iteratorPrototypeError)).toBe("");
    }

    const primitiveDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, Symbol.toPrimitive);
    const toStringDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, "toString");
    const secret = "coercion-secret";
    let coercionError;
    try {
      Object.defineProperty(Error.prototype, Symbol.toPrimitive, {
        configurable: true,
        value: () => secret,
      });
      Object.defineProperty(Error.prototype, "toString", {
        configurable: true,
        value: () => secret,
      });
      coercionError = captureError(() => runDoctor({ sensitiveValues: ["true", secret] }));
    } finally {
      if (primitiveDescriptor === undefined) {
        delete (Error.prototype as { [Symbol.toPrimitive]?: unknown })[Symbol.toPrimitive];
      } else Object.defineProperty(Error.prototype, Symbol.toPrimitive, primitiveDescriptor);
      if (toStringDescriptor === undefined) delete (Error.prototype as { toString?: unknown }).toString;
      else Object.defineProperty(Error.prototype, "toString", toStringDescriptor);
    }
    expectOutputFreeRejection(coercionError);
    expect(String(coercionError)).toBe("");
    let serializationError: unknown;
    try {
      JSON.stringify(coercionError);
    } catch (error) {
      serializationError = error;
    }
    expect(serializationError).toBe(coercionError);

    const inheritedTagDescriptor = Object.getOwnPropertyDescriptor(
      Error.prototype,
      Symbol.toStringTag,
    );
    const inheritedThenDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, "then");
    const inheritedMatchDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, Symbol.match);
    let inheritedTagRuns = 0;
    let inheritedThenRuns = 0;
    let inheritedMatchRuns = 0;
    let protocolError: unknown;
    let tagErrorResult: unknown;
    let assimilatedError: unknown;
    try {
      Object.defineProperty(Error.prototype, Symbol.toStringTag, {
        configurable: true,
        get: () => {
          inheritedTagRuns += 1;
          return secret;
        },
      });
      Object.defineProperty(Error.prototype, "then", {
        configurable: true,
        get: () => {
          inheritedThenRuns += 1;
          return () => undefined;
        },
      });
      Object.defineProperty(Error.prototype, Symbol.match, {
        configurable: true,
        get: () => {
          inheritedMatchRuns += 1;
          return () => secret;
        },
      });
      protocolError = captureError(() => runDoctor({ sensitiveValues: ['"'] }));
      tagErrorResult = captureError(() => Object.prototype.toString.call(protocolError));
      assimilatedError = await Promise.resolve(protocolError);
      "x".match(protocolError as RegExp);
    } finally {
      if (inheritedTagDescriptor === undefined) {
        delete (Error.prototype as { [Symbol.toStringTag]?: unknown })[Symbol.toStringTag];
      } else Object.defineProperty(Error.prototype, Symbol.toStringTag, inheritedTagDescriptor);
      if (inheritedThenDescriptor === undefined) delete (Error.prototype as { then?: unknown }).then;
      else Object.defineProperty(Error.prototype, "then", inheritedThenDescriptor);
      if (inheritedMatchDescriptor === undefined) {
        delete (Error.prototype as { [Symbol.match]?: unknown })[Symbol.match];
      } else Object.defineProperty(Error.prototype, Symbol.match, inheritedMatchDescriptor);
    }
    expect(tagErrorResult).toBe(protocolError);
    expect(assimilatedError).toBe(protocolError);
    expect(inheritedTagRuns).toBe(0);
    expect(inheritedThenRuns).toBe(0);
    expect(inheritedMatchRuns).toBe(0);

    const functionThen = Object.getOwnPropertyDescriptor(Function.prototype, "then");
    const functionPrimitive = Object.getOwnPropertyDescriptor(
      Function.prototype,
      Symbol.toPrimitive,
    );
    let functionThenRuns = 0;
    let functionPrimitiveRuns = 0;
    let callableRejection: unknown;
    let resolvedCallable: unknown;
    let callableCoercion: unknown;
    try {
      Object.defineProperty(Function.prototype, "then", {
        configurable: true,
        get: () => {
          functionThenRuns += 1;
          return () => undefined;
        },
      });
      Object.defineProperty(Function.prototype, Symbol.toPrimitive, {
        configurable: true,
        value: () => {
          functionPrimitiveRuns += 1;
          return "function-prototype-secret";
        },
      });
      callableRejection = captureError(() => runDoctor({ sensitiveValues: ['"'] }));
      const toString = (callableRejection as { toString: unknown }).toString;
      resolvedCallable = await Promise.resolve(toString);
      callableCoercion = captureError(() => String(toString));
    } finally {
      if (functionThen === undefined) delete (Function.prototype as { then?: unknown }).then;
      else Object.defineProperty(Function.prototype, "then", functionThen);
      if (functionPrimitive === undefined) {
        delete (Function.prototype as { [Symbol.toPrimitive]?: unknown })[Symbol.toPrimitive];
      } else Object.defineProperty(Function.prototype, Symbol.toPrimitive, functionPrimitive);
    }
    expect(Object.getPrototypeOf(resolvedCallable)).toBeNull();
    expect(Object.isFrozen(resolvedCallable)).toBe(true);
    expect(callableCoercion).not.toBeNull();
    expect(functionThenRuns).toBe(0);
    expect(functionPrimitiveRuns).toBe(0);

    const inspectSymbol = Symbol.for("nodejs.util.inspect.custom");
    const inspectDescriptor = Object.getOwnPropertyDescriptor(Error.prototype, inspectSymbol);
    const inspectSecret = "inspect-secret";
    let inspectionError;
    try {
      Object.defineProperty(Error.prototype, inspectSymbol, {
        configurable: true,
        value: () => inspectSecret,
      });
      inspectionError = captureError(() => runDoctor({ sensitiveValues: ["true", inspectSecret] }));
    } finally {
      if (inspectDescriptor === undefined) {
        delete (Error.prototype as unknown as Record<PropertyKey, unknown>)[inspectSymbol];
      } else Object.defineProperty(Error.prototype, inspectSymbol, inspectDescriptor);
    }
    expect(inspect(inspectionError)).toBe("");
    expect(inspect(inspectionError)).not.toContain(inspectSecret);

    const objectInspectDescriptor = Object.getOwnPropertyDescriptor(
      Object.prototype,
      inspectSymbol,
    );
    const reportSecret = "report-inspect-secret";
    let reportInspectionError;
    try {
      Object.defineProperty(Object.prototype, inspectSymbol, {
        configurable: true,
        value: () => reportSecret,
      });
      reportInspectionError = captureError(() => runDoctor({ sensitiveValues: [reportSecret] }));
    } finally {
      if (objectInspectDescriptor === undefined) {
        delete (Object.prototype as unknown as Record<PropertyKey, unknown>)[inspectSymbol];
      } else Object.defineProperty(Object.prototype, inspectSymbol, objectInspectDescriptor);
    }
    expectOutputFreeRejection(reportInspectionError);
    expect(inspect(reportInspectionError)).not.toContain(reportSecret);

    const tagDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, Symbol.toStringTag);
    const tagSecret = "tag-secret";
    let tagError;
    try {
      Object.defineProperty(Object.prototype, Symbol.toStringTag, {
        configurable: true,
        get: () => tagSecret,
      });
      tagError = captureError(() => runDoctor({ sensitiveValues: [tagSecret] }));
    } finally {
      if (tagDescriptor === undefined) {
        delete (Object.prototype as unknown as Record<PropertyKey, unknown>)[Symbol.toStringTag];
      } else Object.defineProperty(Object.prototype, Symbol.toStringTag, tagDescriptor);
    }
    expectOutputFreeRejection(tagError);
    expect(inspect(tagError)).not.toContain(tagSecret);
  });

  test("rejects proxy-backed probe callbacks before execution", async () => {
    let invoked = false;
    const callback = new Proxy(
      () => synthetic("failed", true, "probe.proxy-callback"),
      {
        apply: (target, thisArgument, argumentsList) => {
          invoked = true;
          return Reflect.apply(target, thisArgument, argumentsList);
        },
      },
    );
    const report = await runDoctor({
      probes: [{
        id: "probe.proxy-callback",
        required: true,
        run: callback,
      }],
    });
    expect(invoked).toBe(false);
    expect(report.exitCode).toBe(4);
    assertDoctorReport(report);
  });

  test("commits synchronous probe results without thenable assimilation", async () => {
    const thenDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "then");
    let targetAssimilations = 0;
    let report;
    try {
      Object.defineProperty(Object.prototype, "then", {
        configurable: true,
        get(this: Record<string, unknown>) {
          if (this["id"] !== "probe.then-target") return undefined;
          targetAssimilations += 1;
          delete (Object.prototype as { then?: unknown }).then;
          return (resolve: (value: DoctorCheck) => void) => {
            resolve(synthetic("passed", true, "probe.then-target"));
          };
        },
      });
      report = await runDoctor({
        probes: [
          {
            id: "probe.then-install",
            required: false,
            run: () => synthetic("passed", false, "probe.then-install"),
          },
          {
            id: "probe.then-target",
            required: true,
            run: () => synthetic("failed", true, "probe.then-target"),
          },
          {
            id: "probe.then-cleanup",
            required: false,
            run: () => {
              delete (Object.prototype as { then?: unknown }).then;
              return synthetic("passed", false, "probe.then-cleanup");
            },
          },
        ],
      });
    } finally {
      if (thenDescriptor === undefined) delete (Object.prototype as { then?: unknown }).then;
      else Object.defineProperty(Object.prototype, "then", thenDescriptor);
    }
    expect(targetAssimilations).toBe(0);
    expect(report?.exitCode).toBe(3);
    expect(report?.checks.find((item) => item.id === "probe.then-target")?.status).toBe("failed");
    assertDoctorReport(report);

    const asynchronous = await runDoctor({
      probes: [{
        id: "probe.async-result",
        required: true,
        run: (() => Promise.resolve(synthetic("passed", true, "probe.async-result"))) as unknown as () => DoctorCheck,
      }],
    });
    expect(asynchronous.exitCode).toBe(4);
    assertDoctorReport(asynchronous);

    const originalMap = Array.prototype.map;
    let queuedMutationRan = false;
    try {
      const immediate = runDoctor({
        probes: [{
          id: "probe.queued-mutation",
          required: false,
          run: () => {
            queueMicrotask(() => {
              queuedMutationRan = true;
              Array.prototype.map = (() => []) as unknown as typeof Array.prototype.map;
            });
            return synthetic("passed", false, "probe.queued-mutation");
          },
        }],
      });
      expect(queuedMutationRan).toBe(false);
      expect(immediate.checks.at(-1)?.id).toBe("probe.queued-mutation");
      assertDoctorReport(immediate);
      await Promise.resolve();
    } finally {
      Array.prototype.map = originalMap;
    }
    expect(queuedMutationRan).toBe(true);
  });

  test("emits one ready fixture report from the repository-pinned external rig", async () => {
    const report = await runDoctor({
      now: () => "2026-07-20T10:30:00.000Z",
    });
    assertDoctorReport(report);
    expect(report).toMatchObject({
      schema: "dacs-doctor/v1",
      service: "dacs-forge",
      version: "0.1.1",
      generatedAt: "2026-07-20T10:30:00.000Z",
      evidenceMode: "fixture",
      ready: true,
      exitCode: 0,
    });
    expect(report.checks.find((item) => item.id === "execution.read-only")).toMatchObject({
      status: "passed",
      observed: { liveEffects: 0, registrationCommands: 0 },
    });
    expect(report.checks.find((item) => item.id === "binding.live-resolution")?.status)
      .toBe("not-applicable");
    expect(report.checks.find((item) => item.id === "conformance.external-rig")).toMatchObject({
      required: true,
      status: "passed",
      protocolDisposition: "pass",
      sourceRef: "release/release-manifest.json#pins.dacsStandard",
      observed: {
        acceptedRigPinned: true,
        profile: "v0.4",
        tag: "v0.4",
        commit: "4bb9e48a1095ab32c06c25b7c0b52018d3ce4091",
      },
    });
    expect(Buffer.byteLength(serializeDoctorReport(report), "utf8")).toBeLessThanOrEqual(16_384);
  });

  test("keeps local-chain and live blocked only on binding resolution", async () => {
    for (const evidenceMode of ["local-chain", "live"] as const) {
      const report = await runDoctor({ evidenceMode });
      expect(report.exitCode).toBe(5);
      expect(report.ready).toBe(false);
      expect(report.checks.filter((item) => item.required && item.status === "blocked")
        .map((item) => item.id)).toEqual(["binding.live-resolution"]);
      expect(report.checks.find((item) => item.id === "binding.live-resolution")).toMatchObject({
        evidenceMode,
        required: true,
        status: "blocked",
        protocolDisposition: "indeterminate",
        observed: { resolverConfigured: false },
      });
      expect(report.checks.find((item) => item.id === "conformance.external-rig")).toMatchObject({
        status: "passed",
        protocolDisposition: "pass",
        observed: { acceptedRigPinned: true },
      });
    }
  });

  test("applies required exit precedence 4 then 3 then 5 then 0", () => {
    expect(doctorExitCode([synthetic("blocked")])).toBe(5);
    expect(doctorExitCode([synthetic("blocked"), synthetic("failed")])).toBe(3);
    expect(doctorExitCode([synthetic("blocked"), synthetic("not-run")])).toBe(3);
    expect(doctorExitCode([
      synthetic("failed"),
      { ...synthetic("failed", true, "internal.tool"), protocolDisposition: "error" },
    ])).toBe(4);
    expect(doctorExitCode([synthetic("passed"), synthetic("not-applicable", false)])).toBe(0);
  });

  test("redacts sentinels from probe output and internal failures", async () => {
    const secret = [
      "fixture-user",
      "fixture-pass",
      "example.invalid/private",
      "fixture-token",
      "value",
    ].join("|");
    const report = await runDoctor({
      sensitiveValues: [secret, "fixture-token"],
      probes: [{
        id: "probe.secret",
        required: false,
        run: () => ({
          id: "probe.secret",
          required: false,
          status: "not-applicable",
          evidenceMode: "fixture",
          sourceRef: `https://${secret}`,
          observed: { detail: secret },
          reason: `unused ${secret}`,
        }),
      }],
    });
    const encoded = JSON.stringify(report);
    expect(encoded).not.toContain(secret);
    expect(encoded).not.toContain("fixture-token");
    expect(encoded).not.toContain(secret);

    const failed = await runDoctor({
      sensitiveValues: [secret],
      probes: [{
        id: "probe.failure",
        required: true,
        run: () => { throw new Error(`failed with ${secret}`); },
      }],
    });
    expect(failed.exitCode).toBe(4);
    expect(JSON.stringify(failed)).not.toContain(secret);

    const overlap = await runDoctor({
      sensitiveValues: ["fixture-token", "fixture-token-extended"],
      probes: [{
        id: "probe.overlap",
        required: false,
        run: () => ({
          id: "probe.overlap",
          required: false,
          status: "not-applicable",
          evidenceMode: "fixture",
          sourceRef: "fixture-token-extended",
          observed: { detail: "fixture-token-extended" },
          reason: "fixture-token-extended",
        }),
      }],
    });
    const overlapCheck = overlap.checks.at(-1);
    expect(JSON.stringify({
      sourceRef: overlapCheck?.sourceRef,
      observed: overlapCheck?.observed,
      reason: overlapCheck?.reason,
    })).not.toContain("fixture-token");
    expect(overlapCheck?.id).toBe("probe.overlap");
  });

  test("rejects mixed-mode, reserved, and non-finite probe evidence", async () => {
    for (const probe of [
      {
        id: "probe.mixed-mode",
        required: true,
        run: () => ({ ...synthetic("passed"), id: "probe.mixed-mode", evidenceMode: "fixture" as const }),
      },
      {
        id: "internal.tool",
        required: false,
        run: () => ({ ...synthetic("passed", false), id: "internal.tool" }),
      },
      {
        id: "probe.non-finite",
        required: false,
        run: () => ({
          ...synthetic("passed", false),
          id: "probe.non-finite",
          observed: { value: Number.POSITIVE_INFINITY },
        }),
      },
      {
        id: "probe.negative-zero",
        required: false,
        run: () => ({
          ...synthetic("passed", false),
          id: "probe.negative-zero",
          observed: { value: -0 },
        }),
      },
    ]) {
      const report = await runDoctor({ evidenceMode: "live", probes: [probe] });
      expect(report.exitCode).toBe(4);
      expect(report.checks).toHaveLength(1);
      expect(report.checks[0]?.id).toBe("internal.tool");
    }

    let invalidIdRan = false;
    const invalidId = await runDoctor({
      probes: [{
        id: "Invalid",
        required: true,
        run: () => {
          invalidIdRan = true;
          return synthetic("failed", true, "probe.invalid");
        },
      }],
    });
    expect(invalidIdRan).toBe(false);
    expect(invalidId.exitCode).toBe(4);
    assertDoctorReport(invalidId);
  });

  test("rejects unsupported report modes and malformed probe fields", async () => {
    const unsupported = await runDoctor({ evidenceMode: "remote" as "fixture" });
    expect(unsupported.exitCode).toBe(4);
    expect(unsupported.evidenceMode).toBe("fixture");
    const explicitNull = await runDoctor({ evidenceMode: null as unknown as "fixture" });
    expect(explicitNull.exitCode).toBe(4);

    for (const changed of [
      { sourceRef: 7 },
      { protocolDisposition: "bogus" },
      { reason: 9 },
      { reason: undefined },
      { required: "yes" },
      { extra: true },
      { status: "failed", protocolDisposition: "pass" },
      { protocolDisposition: undefined },
    ]) {
      const report = await runDoctor({
        probes: [{
          id: "probe.malformed",
          required: false,
          run: () => ({
            ...synthetic("not-applicable", false, "probe.malformed"),
            ...changed,
          }) as unknown as DoctorCheck,
        }],
      });
      expect(report.exitCode).toBe(4);
      expect(report.checks[0]?.id).toBe("internal.tool");
    }
  });

  test("normalizes long errors and redaction expansion into valid internal reports", async () => {
    const longFailure = await runDoctor({
      probes: [{
        id: "probe.long-error",
        required: true,
        run: () => { throw new Error(`bad\u0000${"x".repeat(2048)}`); },
      }],
    });
    expect(longFailure.exitCode).toBe(4);
    expect(longFailure.checks[0]?.reason?.length).toBeLessThanOrEqual(1024);
    expect(longFailure.checks[0]?.reason).not.toContain("\u0000");
    assertDoctorReport(longFailure);

    const oversizedFailure = await runDoctor({
      probes: [{
        id: "probe.oversized-error",
        required: true,
        run: () => { throw new Error("z".repeat(1_000_000)); },
      }],
    });
    expect(oversizedFailure.exitCode).toBe(4);
    expect(oversizedFailure.checks[0]?.reason).toBe("masked");
    assertDoctorReport(oversizedFailure);

    const c1Failure = await runDoctor({
      probes: [{
        id: "probe.c1-error",
        required: true,
        run: () => { throw new Error("bad\u009bcontrol\u0085line"); },
      }],
    });
    expect(c1Failure.exitCode).toBe(4);
    expect(c1Failure.checks[0]?.reason).toBe("bad control line");
    expect(serializeDoctorReport(c1Failure)).not.toMatch(/[\u0080-\u009f]/);
    assertDoctorReport(c1Failure);

    let aggregateProbeRuns = 0;
    const aggregateFailure = await runDoctor({
      probes: Array.from({ length: 32 }, (_, index) => ({
        id: `probe.aggregate-${index}`,
        required: false,
        run: () => {
          aggregateProbeRuns += 1;
          return {
            ...synthetic("passed", false, `probe.aggregate-${index}`),
            observed: { value: "x".repeat(2048) },
          };
        },
      })),
    });
    expect(aggregateFailure.exitCode).toBe(4);
    expect(aggregateFailure.checks[0]?.reason).toContain("16 KiB wire budget");
    expect(aggregateProbeRuns).toBeLessThan(32);
    assertDoctorReport(aggregateFailure);

    const numericObserved = Object.fromEntries(
      Array.from({ length: 256 }, (_, index) => [`value${index}`, Number.MAX_VALUE]),
    );
    let numericProbeRuns = 0;
    const numericAggregate = await runDoctor({
      probes: Array.from({ length: 3 }, (_, index) => ({
        id: `probe.numeric-budget-${index}`,
        required: false,
        run: () => {
          numericProbeRuns += 1;
          return {
            ...synthetic("passed", false, `probe.numeric-budget-${index}`),
            observed: numericObserved,
          };
        },
      })),
    });
    expect(numericAggregate.exitCode).toBe(4);
    expect(numericAggregate.checks[0]?.reason).toContain("16 KiB wire budget");
    expect(numericProbeRuns).toBeLessThan(3);
    assertDoctorReport(numericAggregate);

    const boundarySecret = "fixture-secret-spans-reason-boundary";
    const boundaryFailure = await runDoctor({
      sensitiveValues: [boundarySecret],
      probes: [{
        id: "probe.boundary-error",
        required: true,
        run: () => { throw new Error(`${"x".repeat(1010)}${boundarySecret}`); },
      }],
    });
    expect(boundaryFailure.exitCode).toBe(4);
    expect(JSON.stringify(boundaryFailure)).not.toContain(boundarySecret);
    assertDoctorReport(boundaryFailure);

    const expansionSecret = "fixture-secret-value";
    const expansion = await runDoctor({
      sensitiveValues: [expansionSecret],
      probes: [{
        id: "probe.expansion",
        required: false,
        run: () => ({
          id: "probe.expansion",
          required: false,
          status: "not-applicable",
          evidenceMode: "fixture",
          sourceRef: expansionSecret.repeat(20),
          observed: { value: expansionSecret.repeat(100) },
          reason: expansionSecret.repeat(50),
        }),
      }],
    });
    expect(expansion.exitCode).toBe(0);
    expect(expansion.checks.at(-1)?.sourceRef.length).toBeLessThanOrEqual(512);
    expect(String(expansion.checks.at(-1)?.observed["value"] ?? "").length)
      .toBeLessThanOrEqual(2048);
    assertDoctorReport(expansion);

    for (const thrown of [new Error(""), ""]) {
      const empty = await runDoctor({
        probes: [{
          id: "probe.empty-error",
          required: true,
          run: () => { throw thrown; },
        }],
      });
      expect(empty.exitCode).toBe(4);
      expect(empty.checks[0]?.reason).toBe("masked");
      assertDoctorReport(empty);
    }
  });

  test("rejects duplicate or reserved probes and malformed sensitive values", async () => {
    const passProbe = (id: string) => ({
      id,
      required: false,
      run: () => synthetic("passed", false, id),
    });
    for (const options of [
      { probes: [passProbe("runtime.bun")] },
      { probes: [passProbe("probe.duplicate"), passProbe("probe.duplicate")] },
      { probes: [passProbe("probe.fixture-token")], sensitiveValues: ["fixture-token"] },
    ]) {
      const report = await runDoctor(options);
      expect(report.exitCode).toBe(4);
      expect(report.checks[0]?.id).toBe("internal.tool");
      assertDoctorReport(report);
    }

    for (const options of [
      { sensitiveValues: null as unknown as readonly string[] },
      { sensitiveValues: [null] as unknown as readonly string[] },
      { sensitiveValues: [""] },
      { sensitiveValues: [null, "fixture"] as unknown as readonly string[] },
      { sensitiveValues: ["fixture"], extra: true } as unknown as DoctorOptions,
    ]) {
      const error = captureError(() => runDoctor(options));
      expectOutputFreeRejection(error);
      expect(String(error)).not.toContain("fixture");
    }

    for (const quoteSecret of ['"', 'secret",', '"schema']) {
      const error = captureError(() => runDoctor({ sensitiveValues: [quoteSecret] }));
      expectOutputFreeRejection(error);
      const message = error instanceof Error ? error.message : String(error);
      expect(message).not.toContain(quoteSecret);
      let serializationError: unknown;
      try {
        JSON.stringify(error);
      } catch (rejection) {
        serializationError = rejection;
      }
      expect(serializationError).toBe(error);
    }
  });

  test("snapshots mutable probe identity before execution", async () => {
    const mutable = {
      id: "probe.safe",
      required: false,
      run: () => {
        mutable.id = "probe.fixture-token";
        return synthetic("passed", false, mutable.id);
      },
    };
    const report = await runDoctor({
      sensitiveValues: ["fixture-token"],
      probes: [mutable],
    });
    expect(report.exitCode).toBe(4);
    expect(JSON.stringify(report)).not.toContain("fixture-token");
    assertDoctorReport(report);

    let secondRan = false;
    const probes = [
      {
        id: "probe.first",
        required: false,
        run: () => {
          probes.splice(1);
          return synthetic("passed", false, "probe.first");
        },
      },
      {
        id: "probe.second",
        required: false,
        run: () => {
          secondRan = true;
          return synthetic("passed", false, "probe.second");
        },
      },
    ];
    const snapshotReport = await runDoctor({
      probes,
      now: () => {
        probes.splice(0);
        return "2026-07-20T10:30:00.000Z";
      },
    });
    expect(secondRan).toBe(true);
    expect(snapshotReport.checks.some((item) => item.id === "probe.first")).toBe(true);
    expect(snapshotReport.checks.some((item) => item.id === "probe.second")).toBe(true);
    assertDoctorReport(snapshotReport);

    let arrayAccessorRan = false;
    const accessorManifest = [
      {
        id: "probe.accessor-first",
        required: false,
        run: () => synthetic("passed", false, "probe.accessor-first"),
      },
      {
        id: "probe.required-second",
        required: true,
        run: () => synthetic("failed", true, "probe.required-second"),
      },
    ];
    Object.defineProperty(accessorManifest, 0, {
      get: () => {
        arrayAccessorRan = true;
        accessorManifest[1] = {
          id: "probe.replacement",
          required: false,
          run: () => synthetic("passed", false, "probe.replacement"),
        };
        return {
          id: "probe.accessor-first",
          required: false,
          run: () => synthetic("passed", false, "probe.accessor-first"),
        };
      },
    });
    const accessorManifestReport = await runDoctor({ probes: accessorManifest });
    expect(arrayAccessorRan).toBe(false);
    expect(accessorManifestReport.exitCode).toBe(4);
    assertDoctorReport(accessorManifestReport);

    let descriptorAccessorRan = false;
    const descriptorProbe = {
      required: false,
      run: () => synthetic("passed", false, "probe.descriptor"),
    } as { id?: string; required: boolean; run: () => DoctorCheck };
    Object.defineProperty(descriptorProbe, "id", {
      get: () => {
        descriptorAccessorRan = true;
        return "probe.descriptor";
      },
    });
    const descriptorReport = await runDoctor({ probes: [descriptorProbe as never] });
    expect(descriptorAccessorRan).toBe(false);
    expect(descriptorReport.exitCode).toBe(4);
    assertDoctorReport(descriptorReport);

    let proxyTrapRan = false;
    const proxyProbe = new Proxy({
      id: "probe.proxy",
      required: true,
      run: () => synthetic("failed", true, "probe.proxy"),
    }, {
      getOwnPropertyDescriptor: (target, property) => {
        proxyTrapRan = true;
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });
    const proxyProbeReport = await runDoctor({ probes: [proxyProbe] });
    expect(proxyTrapRan).toBe(false);
    expect(proxyProbeReport.exitCode).toBe(4);
    assertDoctorReport(proxyProbeReport);

    let directProbeRan = false;
    const directProbe = () => {
      directProbeRan = true;
      return synthetic("failed", true, "probe.direct-call");
    };
    Object.defineProperty(directProbe, "call", {
      value: () => synthetic("passed", true, "probe.direct-call"),
    });
    const directCallReport = await runDoctor({
      probes: [{ id: "probe.direct-call", required: true, run: directProbe }],
    });
    expect(directProbeRan).toBe(true);
    expect(directCallReport.exitCode).toBe(3);
    assertDoctorReport(directCallReport);

    const originalApply = Reflect.apply;
    let intrinsicProbeRan = false;
    try {
      (Reflect as unknown as { apply: typeof Reflect.apply }).apply = (() =>
        synthetic("passed", true, "probe.intrinsic")) as typeof Reflect.apply;
      const intrinsicReport = await runDoctor({
        probes: [{
          id: "probe.intrinsic",
          required: true,
          run: () => {
            intrinsicProbeRan = true;
            return synthetic("failed", true, "probe.intrinsic");
          },
        }],
      });
      expect(intrinsicProbeRan).toBe(true);
      expect(intrinsicReport.exitCode).toBe(3);
      assertDoctorReport(intrinsicReport);
    } finally {
      (Reflect as unknown as { apply: typeof Reflect.apply }).apply = originalApply;
    }

    const originalIncludes = String.prototype.includes;
    const originalMap = Array.prototype.map;
    const originalStringify = JSON.stringify;
    let poisonedError;
    try {
      String.prototype.includes = (() => false) as typeof String.prototype.includes;
      Array.prototype.map = (function <T, U>(
        this: T[], callback: (value: T, index: number, array: T[]) => U,
      ): U[] {
        return originalMap.call(this.slice(0, 7), callback) as U[];
      }) as typeof Array.prototype.map;
      JSON.stringify = (() => '{"open":true}') as typeof JSON.stringify;
      poisonedError = captureError(() => runDoctor({
        sensitiveValues: ["api-key"],
        probes: [{
          id: "probe.poisoned-intrinsics",
          required: true,
          run: () => ({
            ...synthetic("failed", true, "probe.poisoned-intrinsics"),
            sourceRef: "test:api-key",
            reason: "failed with api-key",
          }),
        }],
      }));
    } finally {
      String.prototype.includes = originalIncludes;
      Array.prototype.map = originalMap;
      JSON.stringify = originalStringify;
    }
    expectOutputFreeRejection(poisonedError);
    expect(String(poisonedError)).not.toContain("api-key");

    const originalDescriptor = Object.getOwnPropertyDescriptor;
    const originalEntries = Object.entries;
    const originalFreeze = Object.freeze;
    const originalFinite = Number.isFinite;
    const originalPrototype = Object.getPrototypeOf;
    let reflectionError;
    let finiteError;
    try {
      Object.getOwnPropertyDescriptor = (() => undefined) as typeof Object.getOwnPropertyDescriptor;
      Object.entries = (() => []) as typeof Object.entries;
      Object.freeze = ((value: unknown) => {
        if (value !== null && typeof value === "object" && "status" in value) {
          (value as { status?: string }).status = "passed";
        }
        return value;
      }) as typeof Object.freeze;
      Number.isFinite = (() => true) as typeof Number.isFinite;
      Object.getPrototypeOf = (() => Object.prototype) as typeof Object.getPrototypeOf;

      reflectionError = captureError(() => runDoctor());

      finiteError = captureError(() => runDoctor({
        probes: [{
          id: "probe.non-finite-poison",
          required: true,
          run: () => ({
            ...synthetic("passed", true, "probe.non-finite-poison"),
            observed: { value: Number.NaN },
          }),
        }],
      }));
    } finally {
      Object.getOwnPropertyDescriptor = originalDescriptor;
      Object.entries = originalEntries;
      Object.freeze = originalFreeze;
      Number.isFinite = originalFinite;
      Object.getPrototypeOf = originalPrototype;
    }
    expect(String(reflectionError)).toContain("Doctor report prototype chain is unsafe");
    expect(String(finiteError)).toContain("Doctor report prototype chain is unsafe");

    const originalIsArray = Array.isArray;
    const originalRegexTest = RegExp.prototype.test;
    const originalReplace = String.prototype.replace;
    const originalToISOString = Date.prototype.toISOString;
    let recoveryError;
    let timestampError;
    let controlsError;
    try {
      recoveryError = captureError(() => runDoctor({
        probes: [{
          id: "probe.poison-array-classifier",
          required: true,
          run: () => {
            Array.isArray = (() => true) as unknown as typeof Array.isArray;
            throw new Error("probe failure");
          },
        }],
      }));
      Array.isArray = originalIsArray;

      timestampError = captureError(() => runDoctor({
        evidenceMode: "live",
        now: () => {
          RegExp.prototype.test = (() => true) as typeof RegExp.prototype.test;
          Date.prototype.toISOString = (() => "2026-99-99T99:99:99.999Z") as typeof Date.prototype.toISOString;
          return "2026-99-99T99:99:99.999Z";
        },
      }));
      RegExp.prototype.test = originalRegexTest;
      Date.prototype.toISOString = originalToISOString;

      controlsError = captureError(() => runDoctor({
        probes: [{
          id: "probe.poison-controls",
          required: true,
          run: () => {
            RegExp.prototype.test = (() => false) as typeof RegExp.prototype.test;
            String.prototype.replace = (function (this: string) { return String(this); }) as typeof String.prototype.replace;
            return {
              ...synthetic("passed", true, "probe.poison-controls"),
              sourceRef: "test:\u0000control",
            };
          },
        }],
      }));
    } finally {
      Array.isArray = originalIsArray;
      RegExp.prototype.test = originalRegexTest;
      String.prototype.replace = originalReplace;
      Date.prototype.toISOString = originalToISOString;
    }
    expect(String(recoveryError)).toContain("Doctor report prototype chain is unsafe");
    expect(String(timestampError)).toContain("Doctor report prototype chain is unsafe");
    expectDetachedDiagnostic(controlsError, "Doctor report prototype chain is unsafe");

    const liveManifestFailure = await runDoctor({
      evidenceMode: "live",
      probes: null as never,
    });
    expect(liveManifestFailure.exitCode).toBe(4);
    expect(liveManifestFailure.evidenceMode).toBe("live");
    assertDoctorReport(liveManifestFailure);

    let resultAccessorRan = false;
    const accessorResult = {
      id: "probe.result-accessor",
      required: false,
      status: "passed",
      evidenceMode: "fixture",
      sourceRef: "test:result-accessor",
      observed: { value: "ok" },
    } as Record<string, unknown>;
    Object.defineProperty(accessorResult, "protocolDisposition", {
      configurable: true,
      enumerable: true,
      get: () => {
        resultAccessorRan = true;
        Object.defineProperty(accessorResult, "protocolDisposition", {
          enumerable: true,
          value: "pass",
        });
        return "pass";
      },
    });
    const resultAccessorReport = await runDoctor({
      probes: [{
        id: "probe.result-accessor",
        required: false,
        run: () => accessorResult as unknown as DoctorCheck,
      }],
    });
    expect(resultAccessorRan).toBe(false);
    expect(resultAccessorReport.exitCode).toBe(4);
    assertDoctorReport(resultAccessorReport);
  });

  test("redacts marker-colliding strings and serialized primitive observations", async () => {
    const sensitive = ["redacted", "[redacted]", "1234"];
    const report = await runDoctor({
      sensitiveValues: sensitive,
      probes: [{
        id: "probe.primitive-redaction",
        required: false,
        run: () => ({
          id: "probe.primitive-redaction",
          required: false,
          status: "passed",
          protocolDisposition: "pass",
          evidenceMode: "fixture",
          sourceRef: "test:redacted:[redacted]",
          observed: { number: 1234, boolean: true, text: "redacted [redacted]" },
        }),
      }],
    });
    const observed = report.checks.at(-1)?.observed;
    const payload = JSON.stringify({
      sourceRef: report.checks.at(-1)?.sourceRef,
      observed,
      reason: report.checks.at(-1)?.reason,
    });
    for (const value of sensitive) expect(payload).not.toContain(value);
    expect(typeof observed?.["number"]).toBe("string");
    expect(typeof observed?.["boolean"]).toBe("string");
    assertDoctorReport(report);

    const primitiveBoundarySecret = "1234,";
    const primitiveBoundary = await runDoctor({
      sensitiveValues: [primitiveBoundarySecret],
      probes: [{
        id: "probe.primitive-boundary",
        required: false,
        run: () => ({
          ...synthetic("passed", false, "probe.primitive-boundary"),
          observed: { pin: 1234, next: true },
        }),
      }],
    });
    expect(JSON.stringify(primitiveBoundary)).not.toContain(primitiveBoundarySecret);
    expect(typeof primitiveBoundary.checks.at(-1)?.observed["pin"]).toBe("string");
    expect(typeof primitiveBoundary.checks.at(-1)?.observed["next"]).toBe("string");
    assertDoctorReport(primitiveBoundary);

    const reconstructed = `${String.fromCodePoint(0xe000)}b`;
    const boundary = await runDoctor({
      sensitiveValues: [reconstructed, "fixture-a"],
      probes: [{
        id: "probe.boundary",
        required: false,
        run: () => ({
          id: "probe.boundary",
          required: false,
          status: "passed",
          protocolDisposition: "pass",
          evidenceMode: "fixture",
          sourceRef: "fixture-ab",
          observed: { value: "fixture-ab" },
        }),
      }],
    });
    expect(JSON.stringify(boundary.checks.at(-1))).not.toContain(reconstructed);
    assertDoctorReport(boundary);

    const normalizedSecret = "a b";
    const controls = await runDoctor({
      sensitiveValues: [normalizedSecret],
      probes: [{
        id: "probe.controls",
        required: false,
        run: () => ({
          id: "probe.controls",
          required: false,
          status: "passed",
          protocolDisposition: "pass",
          evidenceMode: "fixture",
          sourceRef: "test:controls",
          observed: { detail: "a\u0000b" },
        }),
      }],
    });
    expect(JSON.stringify(controls.checks.at(-1))).not.toContain(normalizedSecret);
    assertDoctorReport(controls);

    const escapedSecret = "\\n";
    const escaped = await runDoctor({
      sensitiveValues: [escapedSecret],
      probes: [{
        id: "probe.serialization",
        required: false,
        run: () => ({
          id: "probe.serialization",
          required: false,
          status: "passed",
          protocolDisposition: "pass",
          evidenceMode: "fixture",
          sourceRef: "test:serialization",
          observed: { detail: "line\nbreak" },
        }),
      }],
    });
    expect(JSON.stringify(escaped.checks.at(-1))).not.toContain(escapedSecret);
    assertDoctorReport(escaped);
  });

  test("contains malformed error messages and top-level option access", async () => {
    const malformed = new Error("placeholder");
    Object.defineProperty(malformed, "message", { value: null });
    const malformedReport = await runDoctor({
      probes: [{
        id: "probe.malformed-error",
        required: true,
        run: () => { throw malformed; },
      }],
    });
    expect(malformedReport.exitCode).toBe(4);
    assertDoctorReport(malformedReport);

    let messageAccessorRan = false;
    const accessorMessage = Object.defineProperty(new Error(), "message", {
      get: () => {
        messageAccessorRan = true;
        throw new Error("message accessor ran");
      },
    });
    let coercionHookRan = false;
    const coercionThrowable = {
      [Symbol.toPrimitive]: () => {
        coercionHookRan = true;
        return "coercion hook ran";
      },
    };
    for (const thrown of [accessorMessage, coercionThrowable]) {
      const report = await runDoctor({
        probes: [{
          id: "probe.hostile-throwable",
          required: true,
          run: () => { throw thrown; },
        }],
      });
      expect(report.exitCode).toBe(4);
      expect(report.checks[0]?.reason).toBe("Unknown Doctor failure");
      assertDoctorReport(report);
    }
    expect(messageAccessorRan).toBe(false);
    expect(coercionHookRan).toBe(false);

    const hostile = Object.defineProperty({}, "sensitiveValues", {
      get: () => { throw new Error("getter failed"); },
    });
    const undefinedThrow = Object.defineProperty({}, "sensitiveValues", {
      get: () => { throw undefined; },
    });
    for (const options of [null, hostile, undefinedThrow]) {
      const error = captureError(() => runDoctor(options as unknown as DoctorOptions));
      expectOutputFreeRejection(error);
    }
    for (const options of [{ now: null }, { now: () => null }, { probes: null }]) {
      const report = await runDoctor(options as unknown as DoctorOptions);
      expect(report.exitCode).toBe(4);
      assertDoctorReport(report);
    }

    const accessorValues = ["api-key", "placeholder"];
    Object.defineProperty(accessorValues, 1, {
      get: () => { throw new Error("api-key"); },
    });
    const accessorError = captureError(() => runDoctor({ sensitiveValues: accessorValues }));
    expectOutputFreeRejection(accessorError);
    expect(String(accessorError)).not.toContain("api-key");
    expect(accessorError instanceof Error ? accessorError.stack : "").not.toContain("api-key");

    let sensitiveProxyTrapRan = false;
    const sensitiveProxy = new Proxy(["api-key", "second-secret"], {
      getOwnPropertyDescriptor: (target, property) => {
        sensitiveProxyTrapRan = true;
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    });
    const sensitiveProxyError = captureError(() => runDoctor({ sensitiveValues: sensitiveProxy }));
    expect(sensitiveProxyTrapRan).toBe(false);
    expectOutputFreeRejection(sensitiveProxyError);
    expect(String(sensitiveProxyError)).not.toContain("api-key");

    let topLevelGetterRan = false;
    const retainedProbe = {
      id: "probe.retained",
      required: true,
      run: () => synthetic("failed", true, "probe.retained"),
    };
    const topLevelOptions = Object.defineProperties({}, {
      probes: { enumerable: true, value: [retainedProbe] },
      sensitiveValues: {
        enumerable: true,
        get: () => {
          topLevelGetterRan = true;
          return [];
        },
      },
    });
    const topLevelError = captureError(() => runDoctor(topLevelOptions as DoctorOptions));
    expect(topLevelGetterRan).toBe(false);
    expectOutputFreeRejection(topLevelError);
    expect((topLevelOptions as { probes: unknown[] }).probes).toHaveLength(1);
  });

  test("preserves core ids and every prototype-named or colliding observation", async () => {
    const observed = JSON.parse(
      '{"__proto__":"keep","fixture-secret":"one","[redacted]":"two","redacted2":"three"}',
    ) as Record<string, string>;
    const report = await runDoctor({
      sensitiveValues: ["fixture-secret"],
      probes: [{
        id: "probe.observations",
        required: false,
        run: () => ({
          id: "probe.observations",
          required: false,
          status: "passed",
          protocolDisposition: "pass",
          evidenceMode: "fixture",
          sourceRef: "test:observations",
          observed,
        }),
      }],
    });
    expect(report.checks[0]?.id).toBe("runtime.bun");
    const result = report.checks.at(-1)?.observed;
    expect(result).toBeDefined();
    expect(Object.keys(result ?? {})).toHaveLength(4);
    expect(Object.hasOwn(result ?? {}, "__proto__")).toBe(true);
    expect(Object.getPrototypeOf(result)).toBe(Object.prototype);
    assertDoctorReport(report);
  });

  test("rejects sensitive values that collide with structural report fields", async () => {
    const timestamp = "2026-07-20T10:30:00.000Z";
    for (const options of [
      { sensitiveValues: ["true"] },
      { sensitiveValues: ["fixture"] },
      { now: () => timestamp, sensitiveValues: ["2026"] },
      {
        sensitiveValues: ["internal"],
        probes: [{
          id: "probe.failure",
          required: true,
          run: () => { throw new Error("internal tool failure"); },
        }],
      },
    ]) {
      const error = captureError(() => runDoctor(options));
      expectOutputFreeRejection(error);
      const surfaced = String(error);
      for (const sensitive of options.sensitiveValues) expect(surfaced).not.toContain(sensitive);
    }


    const diagnosticSecrets = ["true", "Doctor", "TypeError"];
    const diagnosticError = captureError(() => runDoctor({ sensitiveValues: diagnosticSecrets }));
    expectOutputFreeRejection(diagnosticError);
    const diagnosticMessage = String(diagnosticError);
    for (const sensitive of diagnosticSecrets) expect(diagnosticMessage).not.toContain(sensitive);
    const diagnosticStack = diagnosticError instanceof Error ? diagnosticError.stack ?? "" : "";
    for (const sensitive of [...diagnosticSecrets, "runDoctor"]) {
      expect(diagnosticStack).not.toContain(sensitive);
    }

    const errorName = Object.getOwnPropertyDescriptor(Error.prototype, "name");
    const injected = new Error("api-key");
    try {
      Object.defineProperty(Error.prototype, "name", {
        configurable: true,
        set: () => { throw injected; },
      });
      const setterError = captureError(() => runDoctor({ sensitiveValues: ["true", "api-key"] }));
      expect(setterError).not.toBe(injected);
      expect(String(setterError)).not.toContain("api-key");
    } finally {
      if (errorName === undefined) delete (Error.prototype as { name?: unknown }).name;
      else Object.defineProperty(Error.prototype, "name", errorName);
    }

    const provenanceCollision = captureError(() => runDoctor({ sensitiveValues: ["DACS"] }));
    expectOutputFreeRejection(provenanceCollision);
    expect(String(provenanceCollision)).not.toContain("DACS");
  });

  test("rejects open or malformed report/check shapes", async () => {
    const inheritedReport = Object.assign(
      Object.create({ attackerControlled: true }),
      JSON.parse(JSON.stringify(await runDoctor())),
    );
    expect(() => assertDoctorReport(inheritedReport)).toThrow("Doctor report must be an object");

    const canonical = JSON.parse(JSON.stringify(await runDoctor())) as {
      ready: boolean;
      exitCode: number;
      checks: Array<Record<string, unknown>>;
    };
    const fixed = canonical.checks.find((item) => item["id"] === "conformance.external-rig")!;
    fixed["status"] = "passed";
    fixed["protocolDisposition"] = "pass";
    fixed["observed"] = { arbitrary: true };
    delete fixed["reason"];
    canonical.ready = true;
    canonical.exitCode = 0;
    expect(() => assertDoctorReport(canonical)).toThrow(
      "Doctor check conformance.external-rig does not match canonical evidence",
    );

    const negativeZero = JSON.parse(JSON.stringify(await runDoctor())) as {
      checks: Array<Record<string, unknown>>;
    };
    const execution = negativeZero.checks.find((item) => item["id"] === "execution.read-only")!;
    (execution["observed"] as Record<string, unknown>)["liveEffects"] = -0;
    expect(() => assertDoctorReport(negativeZero)).toThrow(
      "Doctor check shape is invalid",
    );

    const reordered = JSON.parse(JSON.stringify(await runDoctor())) as {
      checks: Array<Record<string, unknown>>;
    };
    [reordered.checks[0], reordered.checks[1]] = [reordered.checks[1]!, reordered.checks[0]!];
    const speciesDescriptor = Object.getOwnPropertyDescriptor(Array, Symbol.species);
    try {
      Object.defineProperty(Array, Symbol.species, {
        configurable: true,
        value: class DoctorSpecies extends Array {},
      });
      expect(() => assertDoctorReport(reordered)).toThrow(
        "Doctor report prototype chain is unsafe",
      );
    } finally {
      if (speciesDescriptor === undefined) delete (Array as { [Symbol.species]?: unknown })[Symbol.species];
      else Object.defineProperty(Array, Symbol.species, speciesDescriptor);
    }

    const forgedVersion = JSON.parse(JSON.stringify(await runDoctor())) as Record<string, unknown>;
    forgedVersion["version"] = "attacker-version";
    expect(() => assertDoctorReport(forgedVersion)).toThrow("Doctor report shape is invalid");

    const controlObservation = JSON.parse(JSON.stringify(await runDoctor())) as {
      checks: Array<Record<string, unknown>>;
    };
    controlObservation.checks.push({
      id: "probe.control-observation",
      required: false,
      status: "passed",
      protocolDisposition: "pass",
      evidenceMode: "fixture",
      sourceRef: "test:control-observation",
      observed: { detail: "contains\u0000control" },
    });
    expect(() => assertDoctorReport(controlObservation)).toThrow("Doctor check shape is invalid");

    for (const control of ["\t", "\n", "\r", "\u0085", "\u009b"]) {
      const controlReason = JSON.parse(JSON.stringify(await runDoctor())) as {
        checks: Array<Record<string, unknown>>;
      };
      controlReason.checks.push({
        id: "probe.control-reason",
        required: false,
        status: "passed",
        protocolDisposition: "pass",
        evidenceMode: "fixture",
        sourceRef: "test:control-reason",
        observed: { completed: true },
        reason: `invalid${control}reason`,
      });
      expect(() => assertDoctorReport(controlReason)).toThrow("Doctor check shape is invalid");
    }

    const oversized = JSON.parse(JSON.stringify(await runDoctor())) as {
      checks: Array<Record<string, unknown>>;
    };
    for (let index = 0; index < 257; index += 1) {
      oversized.checks.push({
        id: `probe.cardinality-${index}`,
        required: false,
        status: "passed",
        protocolDisposition: "pass",
        evidenceMode: "fixture",
        sourceRef: "test:cardinality",
        observed: { index },
      });
    }
    expect(oversized.checks).toHaveLength(264);
    expect(() => assertDoctorReport(oversized)).toThrow("Doctor report shape is invalid");

    expect(() => assertDoctorReport({
      schema: "dacs-doctor/v1",
      service: "dacs-forge",
      version: "0.1.1",
      generatedAt: "2026-07-20T10:30:00.000Z",
      evidenceMode: "fixture",
      ready: true,
      exitCode: 0,
      checks: [],
    })).toThrow("Doctor report requires exactly one runtime.bun check");
    expect(() => assertDoctorReport({
      schema: "dacs-doctor/v1",
      service: "dacs-forge",
      version: "0.1.1",
      generatedAt: "2026-07-20T10:30:00.000Z",
      evidenceMode: "fixture",
      ready: false,
      exitCode: 4,
      checks: [
        {
          id: "internal.tool",
          required: true,
          status: "failed",
          protocolDisposition: "error",
          evidenceMode: "fixture",
          sourceRef: "doctor:internal",
          observed: { completed: false },
          reason: "failure",
        },
        synthetic("passed"),
      ],
    })).toThrow("internal.tool is valid only as the sole internal-error check");

    const inheritedSentinel = {
      schema: "dacs-doctor/v1",
      service: "dacs-forge",
      version: "0.1.1",
      generatedAt: "2026-07-20T10:30:00.000Z",
      evidenceMode: "fixture",
      ready: false,
      exitCode: 4,
      checks: [{
        id: "internal.tool",
        required: true,
        status: "failed",
        evidenceMode: "fixture",
        sourceRef: "doctor:internal",
        observed: { completed: false },
      }],
    };
    const protocolDescriptor = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "protocolDisposition",
    );
    const reasonDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "reason");
    let inheritedSentinelReads = 0;
    try {
      Object.defineProperty(Object.prototype, "protocolDisposition", {
        configurable: true,
        get: () => {
          inheritedSentinelReads += 1;
          return "error";
        },
      });
      Object.defineProperty(Object.prototype, "reason", {
        configurable: true,
        get: () => {
          inheritedSentinelReads += 1;
          return "forged reason";
        },
      });
      expect(() => assertDoctorReport(inheritedSentinel)).toThrow(
        "Doctor report prototype chain is unsafe",
      );
    } finally {
      if (protocolDescriptor === undefined) {
        delete (Object.prototype as { protocolDisposition?: unknown }).protocolDisposition;
      } else Object.defineProperty(Object.prototype, "protocolDisposition", protocolDescriptor);
      if (reasonDescriptor === undefined) delete (Object.prototype as { reason?: unknown }).reason;
      else Object.defineProperty(Object.prototype, "reason", reasonDescriptor);
    }
    expect(inheritedSentinelReads).toBe(0);
    expect(() => assertDoctorReport({
      schema: "dacs-doctor/v1",
      service: "dacs-forge",
      version: "0.1.1",
      generatedAt: "2026-07-20T10:30:00.000Z",
      evidenceMode: "fixture",
      ready: false,
      exitCode: 4,
      checks: [{
        id: "internal.tool",
        required: true,
        status: "failed",
        protocolDisposition: "error",
        evidenceMode: "fixture",
        sourceRef: "attacker:report",
        observed: { arbitrary: true },
        reason: "failure",
      }],
    })).toThrow("internal.tool is valid only as the sole internal-error check");
    expect(() => assertDoctorReport({
      schema: "dacs-doctor/v1",
      service: "dacs-forge",
      version: "0.1.1",
      generatedAt: "now",
      evidenceMode: "fixture",
      ready: true,
      exitCode: 0,
      checks: [],
      extra: true,
    })).toThrow("Doctor report shape is invalid");

    const hiddenReport = JSON.parse(JSON.stringify({
      schema: "dacs-doctor/v1",
      service: "dacs-forge",
      version: "0.1.1",
      generatedAt: "2026-07-20T10:30:00.000Z",
      evidenceMode: "fixture",
      ready: false,
      exitCode: 4,
      checks: [{
        id: "internal.tool",
        required: true,
        status: "failed",
        protocolDisposition: "error",
        evidenceMode: "fixture",
        sourceRef: "doctor:internal",
        observed: { completed: false },
        reason: "failure",
      }],
    })) as Record<string, unknown>;
    Object.defineProperty(hiddenReport, "toJSON", { value: () => ({ open: true }) });
    expect(() => assertDoctorReport(hiddenReport)).toThrow("Doctor report must be an object");

    let checksGetterRan = false;
    const accessorBackedReport = Object.defineProperties({
      schema: "dacs-doctor/v1",
      service: "dacs-forge",
      version: "0.1.1",
      generatedAt: "2026-07-20T10:30:00.000Z",
      evidenceMode: "fixture",
      ready: false,
      exitCode: 4,
    }, {
      checks: {
        enumerable: true,
        get: () => {
          checksGetterRan = true;
          return hiddenReport["checks"];
        },
      },
    });
    expect(() => assertDoctorReport(accessorBackedReport)).toThrow("Doctor report must be an object");
    expect(checksGetterRan).toBe(false);

    const hiddenCheckReport = JSON.parse(JSON.stringify({
      ...hiddenReport,
      checks: hiddenReport["checks"],
    })) as Record<string, unknown>;
    Object.defineProperty((hiddenCheckReport["checks"] as object[])[0]!, "toJSON", {
      value: () => ({ open: true }),
    });
    expect(() => assertDoctorReport(hiddenCheckReport)).toThrow("Doctor check shape is invalid");

    for (const version of ["", "bad\u0000version", "x".repeat(129)]) {
      const invalidVersionReport = JSON.parse(JSON.stringify({
        schema: "dacs-doctor/v1",
        service: "dacs-forge",
        version,
        generatedAt: "2026-07-20T10:30:00.000Z",
        evidenceMode: "fixture",
        ready: false,
        exitCode: 4,
        checks: [{
          id: "internal.tool",
          required: true,
          status: "failed",
          protocolDisposition: "error",
          evidenceMode: "fixture",
          sourceRef: "doctor:internal",
          observed: { completed: false },
          reason: "failure",
        }],
      }));
      expect(() => assertDoctorReport(invalidVersionReport)).toThrow("Doctor report shape is invalid");
    }

    const objectToJson = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
    const arrayToJson = Object.getOwnPropertyDescriptor(Array.prototype, "toJSON");
    try {
      Object.defineProperty(Object.prototype, "toJSON", {
        configurable: true,
        value: () => ({ open: true }),
      });
      expect(() => runDoctor()).toThrow();
    } finally {
      if (objectToJson === undefined) delete (Object.prototype as { toJSON?: unknown }).toJSON;
      else Object.defineProperty(Object.prototype, "toJSON", objectToJson);
    }
    try {
      Object.defineProperty(Array.prototype, "toJSON", {
        configurable: true,
        value: () => ({ open: true }),
      });
      expect(() => runDoctor()).toThrow();
    } finally {
      if (arrayToJson === undefined) delete (Array.prototype as { toJSON?: unknown }).toJSON;
      else Object.defineProperty(Array.prototype, "toJSON", arrayToJson);
    }

    const validCheck = synthetic("passed");
    for (const contradiction of [
      { ready: true, exitCode: "0" },
      { ready: true, exitCode: 3 },
      { ready: false, exitCode: 0 },
    ]) {
      expect(() => assertDoctorReport({
        schema: "dacs-doctor/v1",
        service: "dacs-forge",
        version: "0.1.1",
        generatedAt: "2026-07-20T10:30:00.000Z",
        evidenceMode: "fixture",
        checks: [validCheck],
        ...contradiction,
      })).toThrow();
    }

    for (const invalidCheck of [
      { ...validCheck, id: "Invalid" },
      { ...validCheck, status: "blocked", reason: undefined },
      { ...validCheck, status: "not-applicable", required: true, reason: "not applicable" },
      { ...validCheck, protocolDisposition: "error" },
      { ...validCheck, evidenceMode: "live" },
    ]) {
      expect(() => assertDoctorReport({
        schema: "dacs-doctor/v1",
        service: "dacs-forge",
        version: "0.1.1",
        generatedAt: "2026-07-20T10:30:00.000Z",
        evidenceMode: "fixture",
        ready: true,
        exitCode: 0,
        checks: [invalidCheck],
      })).toThrow();
    }
  });
});
