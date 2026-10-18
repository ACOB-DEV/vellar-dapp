import { describe, expect, it } from "vitest";
import { generateCsrfToken, verifyCsrfToken, createCsrfPreHandler } from "./csrf";
import { buildServer } from "./server";

const C1 = "CAFK7NMQOT7G2SKMREDUII3EOK4APIY54WIK6CVGY72XWFE76YFRDF67";

const spendingPolicy = {
  version: "1",
  type: "spending_limit",
  owners: [C1],
  spendingLimits: { dailyXlm: "100" },
};

describe("CSRF Protection Unit and Integration Tests (#526)", () => {
  const secret = "test-csrf-secret-key-32-chars-length";

  describe("verifyCsrfToken unit tests", () => {
    it("validates a freshly generated token (happy path)", () => {
      const token = generateCsrfToken(secret);
      const result = verifyCsrfToken(token, secret);
      expect(result.valid).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it("returns reason: missing when token is undefined or null", () => {
      expect(verifyCsrfToken(undefined, secret)).toEqual({
        valid: false,
        reason: "missing",
      });
      expect(verifyCsrfToken(null as any, secret)).toEqual({
        valid: false,
        reason: "missing",
      });
    });

    it("returns reason: malformed when token is empty or whitespace", () => {
      expect(verifyCsrfToken("", secret)).toEqual({
        valid: false,
        reason: "malformed",
      });
      expect(verifyCsrfToken("   ", secret)).toEqual({
        valid: false,
        reason: "malformed",
      });
    });

    it("returns reason: malformed when token structure is invalid", () => {
      expect(verifyCsrfToken("only-one-part", secret)).toEqual({
        valid: false,
        reason: "malformed",
      });
      expect(verifyCsrfToken("part1.part2", secret)).toEqual({
        valid: false,
        reason: "malformed",
      });
      expect(verifyCsrfToken("nonce.notanumber.sig", secret)).toEqual({
        valid: false,
        reason: "malformed",
      });
    });

    it("returns reason: expired when token timestamp exceeds TTL", () => {
      const nowMs = Date.now();
      const oldTimeMs = nowMs - 2 * 60 * 60 * 1000; // 2 hours ago
      const token = generateCsrfToken(secret, oldTimeMs);
      const result = verifyCsrfToken(token, secret, { nowMs, ttlMs: 3600_000 });
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("expired");
    });

    it("returns reason: invalid_signature when token signature is tampered", () => {
      const validToken = generateCsrfToken(secret);
      const [nonce, timestamp] = validToken.split(".");
      const badSig = "0".repeat(64);
      const tamperedToken = `${nonce}.${timestamp}.${badSig}`;

      const result = verifyCsrfToken(tamperedToken, secret);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe("invalid_signature");
    });
  });

  describe("HTTP endpoint header tests: missing vs malformed token (#526)", () => {
    it("rejects a request with the CSRF header completely absent", async () => {
      const app = buildServer({ csrfSecret: secret });

      const res = await app.inject({
        method: "POST",
        url: "/admin/policies/generate",
        payload: { definition: spendingPolicy, network: "testnet" },
        // No x-csrf-token header at all
      });

      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.error).toBe("csrf_token_missing");
      expect(body.message).toBe("CSRF token is required for state-changing admin routes");
      // Does not contain secret or valid token format
      expect(JSON.stringify(body)).not.toContain(secret);
      await app.close();
    });

    it("rejects a separate request with the header present but containing a malformed token", async () => {
      const app = buildServer({ csrfSecret: secret });

      const res = await app.inject({
        method: "POST",
        url: "/admin/policies/generate",
        headers: { "x-csrf-token": "completely-malformed-token" },
        payload: { definition: spendingPolicy, network: "testnet" },
      });

      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.error).toBe("csrf_token_invalid");
      expect(body.reason).toBe("malformed");
      expect(body.message).toBe("Invalid or tampered CSRF token");
      // Does not leak the secret or valid token format
      expect(JSON.stringify(body)).not.toContain(secret);
      await app.close();
    });

    it("rejects a request with an expired token and provides distinct error details", async () => {
      const app = buildServer({ csrfSecret: secret, csrfTtlMs: 1 });
      const tokenRes = await app.inject({ method: "GET", url: "/admin/csrf-token" });
      const { csrfToken } = tokenRes.json();

      // Wait 10ms for 1ms TTL token to expire
      await new Promise((r) => setTimeout(r, 10));

      const res = await app.inject({
        method: "POST",
        url: "/admin/policies/generate",
        headers: { "x-csrf-token": csrfToken },
        payload: { definition: spendingPolicy, network: "testnet" },
      });

      expect(res.statusCode).toBe(403);
      const body = res.json();
      expect(body.error).toBe("csrf_token_invalid");
      expect(body.reason).toBe("expired");
      expect(body.message).toBe("CSRF token has expired");
      await app.close();
    });

    it("confirms error details differ between missing header and malformed/expired token without leaking sensitive data", async () => {
      const app = buildServer({ csrfSecret: secret, csrfTtlMs: 1 });

      // Request 1: Missing header
      const missingRes = await app.inject({
        method: "POST",
        url: "/admin/policies/generate",
        payload: { definition: spendingPolicy, network: "testnet" },
      });

      // Request 2: Malformed header
      const malformedRes = await app.inject({
        method: "POST",
        url: "/admin/policies/generate",
        headers: { "x-csrf-token": "invalid.format" },
        payload: { definition: spendingPolicy, network: "testnet" },
      });

      // Both are rejected with 403
      expect(missingRes.statusCode).toBe(403);
      expect(malformedRes.statusCode).toBe(403);

      const missingBody = missingRes.json();
      const malformedBody = malformedRes.json();

      // Error detail clearly differs
      expect(missingBody.error).toBe("csrf_token_missing");
      expect(malformedBody.error).toBe("csrf_token_invalid");
      expect(missingBody.error).not.toEqual(malformedBody.error);
      expect(malformedBody.reason).toBe("malformed");
      expect(missingBody.reason).toBeUndefined();

      // Neither response leaks secret or valid format details
      expect(JSON.stringify(missingBody)).not.toContain(secret);
      expect(JSON.stringify(malformedBody)).not.toContain(secret);

      await app.close();
    });

    it("accepts a request with a valid CSRF token (happy path)", async () => {
      const app = buildServer({ csrfSecret: secret });
      const tokenRes = await app.inject({ method: "GET", url: "/admin/csrf-token" });
      const { csrfToken } = tokenRes.json();

      const res = await app.inject({
        method: "POST",
        url: "/admin/policies/generate",
        headers: { "x-csrf-token": csrfToken },
        payload: { definition: spendingPolicy, network: "testnet" },
      });

      expect(res.statusCode).toBe(201);
      expect(res.json().policy).toBeDefined();
      await app.close();
    });
  });
});
