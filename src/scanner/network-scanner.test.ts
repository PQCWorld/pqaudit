import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:tls";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { execSync } from "node:child_process";
import { scanEndpoints } from "./network-scanner.js";

// Generate a self-signed cert for testing
let server: Server;
let port: number;
let certDir: string;

beforeAll(async () => {
  // Create temp certs
  certDir = execSync("mktemp -d").toString().trim();
  execSync(
    `openssl req -x509 -newkey rsa:2048 -keyout ${certDir}/key.pem -out ${certDir}/cert.pem -days 1 -nodes -subj "/CN=localhost" 2>/dev/null`,
  );

  const key = readFileSync(resolve(certDir, "key.pem"));
  const cert = readFileSync(resolve(certDir, "cert.pem"));

  server = createServer({ key, cert }, (socket) => {
    socket.end();
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      port = typeof addr === "object" && addr ? addr.port : 0;
      resolve();
    });
  });
});

afterAll(() => {
  server?.close();
  if (certDir) execSync(`rm -rf ${certDir}`);
});

describe("network scanner", () => {
  it("detects TLS protocol version", async () => {
    const findings = await scanEndpoints(
      [{ host: "127.0.0.1", port, protocol: "tls" }],
      5000,
    );

    const protocol = findings.find((f) => f.ruleId === "NET_TLS_PROTOCOL");
    expect(protocol).toBeDefined();
    expect(protocol!.detectionMethod).toBe("network");
    expect(protocol!.confidence).toBe(1.0);
    expect(protocol!.location.file).toBe(`tls://127.0.0.1:${port}`);
  });

  it("detects certificate key algorithm", async () => {
    const findings = await scanEndpoints(
      [{ host: "127.0.0.1", port, protocol: "tls" }],
      5000,
    );

    const certKey = findings.find((f) => f.ruleId === "NET_TLS_CERT_KEY");
    expect(certKey).toBeDefined();
    expect(certKey!.algorithm).toBe("RSA");
    expect(certKey!.severity).toBe("critical");
    expect(certKey!.confidence).toBe(1.0);
  });

  it("handles connection refused gracefully", async () => {
    const findings = await scanEndpoints(
      [{ host: "127.0.0.1", port: 1, protocol: "tls" }],
      2000,
    );

    expect(findings).toEqual([]);
  });

  it("handles timeout gracefully", async () => {
    const findings = await scanEndpoints(
      [{ host: "192.0.2.1", port: 443, protocol: "tls" }],
      1000,
    );

    expect(findings).toEqual([]);
  }, 10000);

  it("scans multiple endpoints in parallel", async () => {
    const findings = await scanEndpoints(
      [
        { host: "127.0.0.1", port, protocol: "tls" },
        { host: "127.0.0.1", port, protocol: "tls" },
      ],
      5000,
    );

    // Should get findings from both
    const protocols = findings.filter((f) => f.ruleId === "NET_TLS_PROTOCOL");
    expect(protocols.length).toBe(2);
  });
});
