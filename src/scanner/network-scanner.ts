import { connect as tlsConnect, type PeerCertificate } from "node:tls";
import { connect as netConnect } from "node:net";
import type { EndpointSpec, Finding } from "../types.js";

/** Scan multiple endpoints in parallel */
export async function scanEndpoints(
  endpoints: EndpointSpec[],
  timeout: number,
): Promise<Finding[]> {
  const results = await Promise.all(
    endpoints.map((ep) =>
      ep.protocol === "ssh"
        ? scanSSHEndpoint(ep.host, ep.port, timeout)
        : scanTLSEndpoint(ep.host, ep.port, timeout),
    ),
  );
  return results.flat();
}

/** Probe a TLS endpoint and inspect cipher suite, protocol, and certificate */
async function scanTLSEndpoint(
  host: string,
  port: number,
  timeout: number,
): Promise<Finding[]> {
  return new Promise((resolve) => {
    const endpoint = `tls://${host}:${port}`;
    const findings: Finding[] = [];

    const socket = tlsConnect(
      { host, port, rejectUnauthorized: false, timeout },
      () => {
        // Protocol version
        const protocol = socket.getProtocol() ?? "unknown";
        findings.push(makeProtocolFinding(endpoint, protocol, socket.getCipher()?.name));

        // Cipher suite
        const cipher = socket.getCipher();
        if (cipher) {
          findings.push(...makeCipherFindings(endpoint, cipher.name, protocol));
        }

        // Certificate
        const cert = socket.getPeerCertificate();
        if (cert && cert.subject) {
          findings.push(...makeCertFindings(endpoint, cert, protocol));
        }

        socket.end();
        resolve(findings);
      },
    );

    socket.on("error", () => resolve([]));
    socket.on("timeout", () => {
      socket.destroy();
      resolve([]);
    });

    // Safety timeout
    setTimeout(() => {
      socket.destroy();
      resolve(findings.length > 0 ? findings : []);
    }, timeout + 1000);
  });
}

/** Probe an SSH endpoint and read the banner */
async function scanSSHEndpoint(
  host: string,
  port: number,
  timeout: number,
): Promise<Finding[]> {
  return new Promise((resolve) => {
    const endpoint = `ssh://${host}:${port}`;
    let data = "";

    const socket = netConnect({ host, port, timeout }, () => {
      // SSH server sends banner first
    });

    socket.setEncoding("utf-8");
    socket.on("data", (chunk: string) => {
      data += chunk;
      // SSH banner is the first line
      if (data.includes("\n")) {
        const banner = data.split("\n")[0].trim();
        socket.destroy();
        resolve(makeBannerFindings(endpoint, banner));
      }
    });

    socket.on("error", () => resolve([]));
    socket.on("timeout", () => {
      socket.destroy();
      resolve([]);
    });

    setTimeout(() => {
      socket.destroy();
      resolve([]);
    }, timeout + 1000);
  });
}

/** Create a finding for the negotiated TLS protocol version */
function makeProtocolFinding(
  endpoint: string,
  protocol: string,
  cipherName?: string,
): Finding {
  const snippet = cipherName ? `${protocol} ${cipherName}` : protocol;
  const isVulnerable = protocol !== "TLSv1.3";

  return {
    ruleId: "NET_TLS_PROTOCOL",
    description: isVulnerable
      ? `${protocol} negotiated — key exchange is quantum-vulnerable`
      : `${protocol} negotiated — uses ephemeral key exchange`,
    severity: protocol === "TLSv1.3" ? "safe" : protocol === "TLSv1.2" ? "critical" : "critical",
    category: "protocol",
    algorithm: protocol,
    replacement: isVulnerable
      ? "TLS 1.3 with post-quantum hybrid key exchange (e.g. X25519Kyber768)"
      : null,
    effort: "moderate",
    location: { file: endpoint, snippet },
    detectionMethod: "network",
    confidence: 1.0,
  };
}

/** Create findings for the negotiated cipher suite */
function makeCipherFindings(
  endpoint: string,
  cipherName: string,
  protocol: string,
): Finding[] {
  const findings: Finding[] = [];
  const snippet = `${protocol} ${cipherName}`;

  // Check key exchange method
  if (cipherName.startsWith("TLS_RSA_") || /^AES\d+-SHA/.test(cipherName)) {
    findings.push({
      ruleId: "NET_TLS_KEX",
      description: "TLS RSA static key exchange — no forward secrecy, quantum-vulnerable",
      severity: "critical",
      category: "kem",
      algorithm: "RSA",
      replacement: "TLS 1.3 (ephemeral key exchange only)",
      effort: "moderate",
      location: { file: endpoint, snippet },
      detectionMethod: "network",
      confidence: 1.0,
    });
  } else if (/ECDHE|X25519/.test(cipherName) || /^TLS_.*_WITH_/.test(cipherName)) {
    findings.push({
      ruleId: "NET_TLS_KEX",
      description: "ECDHE/X25519 key exchange — quantum-vulnerable ephemeral keys",
      severity: "critical",
      category: "kem",
      algorithm: "ECDH",
      replacement: "Post-quantum hybrid key exchange (e.g. X25519Kyber768)",
      effort: "moderate",
      location: { file: endpoint, snippet },
      detectionMethod: "network",
      confidence: 1.0,
    });
  }

  return findings;
}

/** Create findings for the certificate key and signature algorithms */
function makeCertFindings(
  endpoint: string,
  cert: PeerCertificate,
  protocol: string,
): Finding[] {
  const findings: Finding[] = [];

  // Extract key algorithm from the public key info
  const pubkey = cert.pubkey;
  const keyInfo = detectCertKeyAlgorithm(cert);

  if (keyInfo) {
    const isVulnerable = keyInfo.algorithm !== "Ed448"; // all current cert key types are quantum-vulnerable
    findings.push({
      ruleId: "NET_TLS_CERT_KEY",
      description: `Certificate uses ${keyInfo.algorithm} ${keyInfo.bits ? keyInfo.bits + "-bit " : ""}key — ${isVulnerable ? "vulnerable to Shor's algorithm" : "quantum-resistant"}`,
      severity: isVulnerable ? "critical" : "safe",
      category: "signature",
      algorithm: keyInfo.algorithm,
      replacement: isVulnerable
        ? "Post-quantum certificate algorithms when available"
        : null,
      effort: "complex",
      location: {
        file: endpoint,
        snippet: `${keyInfo.algorithm}${keyInfo.bits ? ` ${keyInfo.bits}-bit` : ""} key, ${protocol}`,
      },
      detectionMethod: "network",
      confidence: 1.0,
    });
  }

  return findings;
}

/** Detect the certificate's public key algorithm and size */
function detectCertKeyAlgorithm(
  cert: PeerCertificate,
): { algorithm: string; bits?: number } | null {
  // Node's getPeerCertificate doesn't directly expose the key algorithm,
  // but we can infer from the public key buffer size and cert fields
  const pubkey = cert.pubkey;
  if (!pubkey) return null;

  // Check asn1Curve for EC keys
  const asn1Curve = (cert as unknown as Record<string, unknown>).asn1Curve as string | undefined;
  if (asn1Curve) {
    if (asn1Curve === "prime256v1" || asn1Curve === "P-256") return { algorithm: "ECDSA", bits: 256 };
    if (asn1Curve === "secp384r1" || asn1Curve === "P-384") return { algorithm: "ECDSA", bits: 384 };
    if (asn1Curve === "secp521r1" || asn1Curve === "P-521") return { algorithm: "ECDSA", bits: 521 };
    return { algorithm: "ECDSA" };
  }

  // Infer RSA from key size (RSA keys are typically 256+ bytes)
  if (pubkey.length >= 256) return { algorithm: "RSA", bits: pubkey.length * 8 };
  if (pubkey.length >= 128) return { algorithm: "RSA", bits: pubkey.length * 8 };

  // Small keys likely EC
  if (pubkey.length <= 65) return { algorithm: "ECDSA" };

  return { algorithm: "RSA", bits: pubkey.length * 8 };
}

/** Create findings for an SSH banner */
function makeBannerFindings(endpoint: string, banner: string): Finding[] {
  if (!banner.startsWith("SSH-")) return [];

  return [
    {
      ruleId: "NET_SSH_SERVER",
      description: "SSH server detected — uses DH/ECDH key exchange (quantum-vulnerable)",
      severity: "high",
      category: "protocol",
      algorithm: "SSH",
      replacement: "Enable post-quantum key exchange (e.g. sntrup761x25519-sha512@openssh.com)",
      effort: "moderate",
      location: { file: endpoint, snippet: banner },
      detectionMethod: "network",
      confidence: 0.85,
    },
  ];
}
