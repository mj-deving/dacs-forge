import { afterEach, describe, expect, test } from "bun:test";
import { createConnection } from "node:net";
import {
  createReadinessHttpHandler,
  requestMatchesReadinessBinding,
  startReadinessServer,
  type RunningReadinessServer,
} from "../../src/http/readiness-server.ts";
import { runDoctor } from "../../src/readiness/doctor.ts";

const servers: RunningReadinessServer[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.stop()));
});

async function body(response: Response): Promise<Record<string, unknown>> {
  return await response.json() as Record<string, unknown>;
}

function rawHttpRequest(port: number, request: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const socket = createConnection({ host: "127.0.0.1", port }, () => socket.write(request));
    socket.setTimeout(2_000);
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    socket.on("error", reject);
    socket.on("timeout", () => socket.destroy(new Error("raw HTTP request timed out")));
  });
}

async function ipv6LoopbackUnavailable(): Promise<boolean> {
  try {
    const control = Bun.serve({
      hostname: "::1",
      port: 0,
      fetch: () => new Response(null, { status: 204 }),
    });
    await control.stop(true);
    return false;
  } catch (error) {
    const code = error !== null && typeof error === "object" && "code" in error
      ? error.code : undefined;
    if (code === "EAFNOSUPPORT" || code === "EADDRNOTAVAIL") return true;
    throw error;
  }
}

describe("loopback HTTP readiness disclosure boundary", () => {
  test("serves exact closed anonymous health and readiness documents", async () => {
    const server = startReadinessServer();
    servers.push(server);

    const healthResponse = await fetch(`${server.url}/healthz`);
    expect(healthResponse.status).toBe(200);
    expect(healthResponse.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(healthResponse.headers.get("cache-control")).toBe("no-store");
    const health = await body(healthResponse);
    expect(Object.keys(health).sort()).toEqual([
      "schema", "service", "status", "timestamp", "version",
    ]);
    expect(health).toMatchObject({
      schema: "dacs-health/v1",
      service: "dacs-forge",
      status: "ok",
      version: "0.1.0-preview.1",
    });

    const readinessResponse = await fetch(`${server.url}/readyz`);
    expect(readinessResponse.status).toBe(503);
    const readiness = await body(readinessResponse);
    expect(Object.keys(readiness).sort()).toEqual([
      "blockerIds", "evidenceMode", "schema", "service", "status", "timestamp", "version",
    ]);
    expect(readiness).toMatchObject({
      schema: "dacs-readiness/v1",
      service: "dacs-forge",
      status: "not-ready",
      evidenceMode: "fixture",
      blockerIds: ["conformance.external-rig"],
    });
    expect(JSON.stringify(readiness)).not.toContain("sourceRef");
    expect(JSON.stringify(readiness)).not.toContain("observed");
    expect(JSON.stringify(readiness)).not.toContain("reason");
  });

  test("keeps detailed Doctor evidence behind an actual administrator authorizer", async () => {
    let doctorCalls = 0;
    const handler = createReadinessHttpHandler({
      authorizeAdministrator: ({ authorization }) => authorization === "Bearer fixture-admin-proof",
      doctor: () => {
        doctorCalls += 1;
        return runDoctor();
      },
    });

    const missing = handler(new Request("http://127.0.0.1/admin/readiness"));
    expect(missing.status).toBe(401);
    expect(await body(missing)).toEqual({
      schema: "dacs-http-error/v1",
      status: 401,
      code: "unauthorized",
    });
    expect(doctorCalls).toBe(0);

    const accepted = handler(new Request("http://127.0.0.1/admin/readiness", {
      headers: { authorization: "Bearer fixture-admin-proof" },
    }));
    expect(accepted.status).toBe(503);
    const report = await body(accepted);
    expect(report["schema"]).toBe("dacs-doctor/v1");
    expect(report["checks"]).toBeArray();
    expect(doctorCalls).toBe(1);
  });

  test("fails closed for missing, throwing, and asynchronous authorization", async () => {
    const absent = createReadinessHttpHandler();
    const absentResponse = absent(new Request("http://127.0.0.1/admin/readiness", {
      headers: { authorization: "Bearer never-reflect-this" },
    }));
    expect(absentResponse.status).toBe(404);
    expect(JSON.stringify(await body(absentResponse))).not.toContain("never-reflect-this");

    const thrown = createReadinessHttpHandler({
      authorizeAdministrator: () => { throw new Error("authorizer-secret"); },
    });
    const thrownResponse = thrown(new Request("http://127.0.0.1/admin/readiness"));
    expect(thrownResponse.status).toBe(500);
    expect(JSON.stringify(await body(thrownResponse))).not.toContain("authorizer-secret");

    const asynchronous = createReadinessHttpHandler({
      authorizeAdministrator: (() => Promise.resolve(true)) as unknown as () => boolean,
    });
    const asynchronousResponse = asynchronous(new Request("http://127.0.0.1/admin/readiness"));
    expect(asynchronousResponse.status).toBe(401);
  });

  test("does not replace a malformed injected Doctor result with default evidence", async () => {
    for (const value of [undefined, null]) {
      const handler = createReadinessHttpHandler({
        doctor: (() => value) as unknown as () => ReturnType<typeof runDoctor>,
      });
      const response = handler(new Request("http://127.0.0.1/readyz"));
      expect(response.status).toBe(500);
      expect(await body(response)).toEqual({
        schema: "dacs-http-error/v1",
        status: 500,
        code: "internal-error",
      });
    }
  });

  test("closes method, route, query, and error response surfaces", async () => {
    const handler = createReadinessHttpHandler();
    const post = handler(new Request("http://127.0.0.1/readyz", { method: "POST", body: "x" }));
    expect(post.status).toBe(405);
    expect(post.headers.get("x-content-type-options")).toBe("nosniff");
    expect(await body(post)).toEqual({
      schema: "dacs-http-error/v1",
      status: 405,
      code: "method-not-allowed",
    });
    expect(handler(new Request("http://127.0.0.1/readyz?detail=true")).status).toBe(404);
    expect(handler(new Request("http://127.0.0.1/readyz?")).status).toBe(404);
    expect(handler(new Request("http://127.0.0.1/unknown")).status).toBe(404);
  });

  test("rejects Host-controlled authority before routing", async () => {
    const standalone = createReadinessHttpHandler();
    expect(standalone(new Request("http://attacker.example/healthz")).status).toBe(421);

    const server = startReadinessServer();
    servers.push(server);
    const response = await fetch(`${server.url}/healthz`, {
      headers: { host: `attacker.example:${server.port}` },
    });
    expect(response.status).toBe(421);
    expect(await body(response)).toEqual({
      schema: "dacs-http-error/v1",
      status: 421,
      code: "misdirected-request",
    });
  });

  test("normalizes the default HTTP port without accepting another authority", () => {
    const defaultPort = new Request("http://127.0.0.1:80/healthz", {
      headers: { host: "127.0.0.1" },
    });
    expect(requestMatchesReadinessBinding(defaultPort, "127.0.0.1", 80)).toBe(true);
    expect(requestMatchesReadinessBinding(defaultPort, "127.0.0.1", 8080)).toBe(false);
    expect(requestMatchesReadinessBinding(new Request("http://127.0.0.1:8080/healthz", {
      headers: { host: "127.0.0.1:8080" },
    }), "127.0.0.1", 8080)).toBe(true);
    expect(requestMatchesReadinessBinding(new Request("http://127.0.0.1:8080/healthz", {
      headers: { host: "attacker.example:8080" },
    }), "127.0.0.1", 8080)).toBe(false);
    expect(requestMatchesReadinessBinding(new Request("http://127.0.0.1:8080/healthz", {
      headers: { host: "127.0.0.1:\t8080" },
    }), "127.0.0.1", 8080)).toBe(false);
    expect(requestMatchesReadinessBinding(new Request("http://127.0.0.1:8080/healthz", {
      headers: { host: "127.0.0.1:08080" },
    }), "127.0.0.1", 8080)).toBe(true);
    expect(requestMatchesReadinessBinding(new Request("http://[::1]:8080/healthz", {
      headers: { host: "[0:0:0:0:0:0:0:1]:08080" },
    }), "::1", 8080)).toBe(true);
    expect(requestMatchesReadinessBinding(new Request("http://[::1]:8080/healthz", {
      headers: { host: "[0:0:0:0:0:0:0:A]:8080" },
    }), "::1", 8080)).toBe(false);
  });

  test("rejects whitespace-obfuscated Host syntax on the bounded server", async () => {
    const server = startReadinessServer();
    servers.push(server);
    const response = await rawHttpRequest(server.port,
      `GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:\t${server.port}\r\nConnection: close\r\n\r\n`);
    expect(response).not.toContain(" 200 ");
    expect(response).not.toContain("dacs-health/v1");
  });

  test("serves and authority-binds a real IPv6 loopback server", async () => {
    let server: RunningReadinessServer;
    try {
      server = startReadinessServer({ hostname: "::1" });
    } catch (error) {
      const code = error !== null && typeof error === "object" && "code" in error
        ? error.code : undefined;
      if ((code === "EAFNOSUPPORT" || code === "EADDRNOTAVAIL")
        && await ipv6LoopbackUnavailable()) return;
      throw error;
    }
    servers.push(server);
    expect(server.url).toStartWith("http://[::1]:");
    expect((await fetch(`${server.url}/healthz`)).status).toBe(200);
    expect((await fetch(`${server.url}/healthz`, {
      headers: { host: `attacker.example:${server.port}` },
    })).status).toBe(421);
  });

  test("rejects every non-loopback bind before starting and stops idempotently", async () => {
    for (const hostname of ["0.0.0.0", "localhost", "127.0.0.2", "[::1]", "::1%lo"]) {
      expect(() => startReadinessServer({
        hostname: hostname as "127.0.0.1",
      })).toThrow(/explicit loopback/);
    }
    expect(() => startReadinessServer({ port: -1 })).toThrow(/port/);
    expect(() => startReadinessServer({ port: 65_536 })).toThrow(/port/);

    const server = startReadinessServer({ hostname: "127.0.0.1", port: 0 });
    servers.push(server);
    expect(server.hostname).toBe("127.0.0.1");
    expect(server.port).toBeGreaterThan(0);
    const firstStop = server.stop();
    const secondStop = server.stop();
    expect(secondStop).toBe(firstStop);
    await firstStop;
    await expect(fetch(`${server.url}/healthz`)).rejects.toThrow();
    servers.pop();
  });
});
