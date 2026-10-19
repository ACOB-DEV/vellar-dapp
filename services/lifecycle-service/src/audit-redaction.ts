import crypto from "crypto";

/**
 * Audit log event before redaction.
 * Raw data from endpoints may contain PII.
 */
export interface AuditEvent {
  type: string;
  at: string;
  data: Record<string, unknown>;
}

/**
 * Generates a redaction salt for consistent hashing across the service lifetime.
 * The salt is deterministic per service instance and never changes for that instance,
 * ensuring that the same input always produces the same hash (enabling correlation).
 *
 * In production, the salt should be:
 * - Generated once at service startup
 * - Stored (e.g., in memory or a secure config store)
 * - Never logged or exported
 *
 * The salt is NOT cryptographically sensitive (it's not a secret key); it's used to
 * ensure deterministic hashing for correlation without exposing raw PII.
 */
export function generateRedactionSalt(): string {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Hashes a value deterministically for PII redaction.
 * Always produces the same output for the same input (within a service instance).
 *
 * @param value - The raw value to hash (e.g., Stellar account ID)
 * @param salt - The redaction salt (service-level, constant)
 * @returns SHA256 hash truncated to 12 hex characters (48 bits)
 */
export function hashForRedaction(value: string, salt: string): string {
  const combined = value + salt;
  const hash = crypto.createHash("sha256").update(combined).digest("hex");
  return hash.substring(0, 12);
}

/**
 * Extracts blocker types from a CleanupPlan's blockers array.
 * Used to preserve operational utility (what kinds of blockers exist)
 * while dropping descriptions that contain PII.
 *
 * @param blockers - Array of blocker objects with a 'type' field
 * @returns Array of unique blocker types
 */
function extractBlockerTypes(blockers: unknown[]): string[] {
  if (!Array.isArray(blockers)) return [];
  const types = new Set<string>();
  for (const blocker of blockers) {
    if (typeof blocker === "object" && blocker !== null && "type" in blocker) {
      const type = (blocker as Record<string, unknown>).type;
      if (typeof type === "string") types.add(type);
    }
  }
  return Array.from(types).sort();
}

const STELLAR_SECRET_REGEX = /\bS[A-Z0-9]{55}\b/g;

function isSensitiveKey(key: string): boolean {
  return /secret|private_?key|sponsor.*key|seed/i.test(key);
}

function redactString(str: string): string {
  return str.replace(STELLAR_SECRET_REGEX, "[REDACTED_SECRET_KEY]");
}

/**
 * Recursively walks nested structures, error cause chains, arrays, and objects,
 * redacting Stellar secret keys and sensitive field values.
 * Uses a WeakSet to detect and prevent infinite loops on circular references.
 */
export function redactNested(
  value: unknown,
  salt?: string,
  seen: WeakSet<object> = new WeakSet(),
): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === "string") {
    return redactString(value);
  }

  if (
    typeof value === "number" ||
    typeof value === "boolean" ||
    typeof value === "bigint"
  ) {
    return value;
  }

  if (typeof value === "symbol") {
    return value.toString();
  }

  if (typeof value === "function") {
    return "[Function]";
  }

  if (typeof value === "object") {
    if (seen.has(value)) {
      return "[Circular]";
    }
    seen.add(value);

    // Error handling (including cause chain)
    if (value instanceof Error || ("message" in value && "name" in value)) {
      const err = value as Error & { cause?: unknown; [key: string]: unknown };
      const result: Record<string, unknown> = {
        name: err.name,
        message: typeof err.message === "string" ? redactString(err.message) : err.message,
      };

      if (typeof err.stack === "string") {
        result.stack = redactString(err.stack);
      }

      if ("cause" in err && err.cause !== undefined) {
        result.cause = redactNested(err.cause, salt, seen);
      }

      for (const prop of Object.getOwnPropertyNames(err)) {
        if (["name", "message", "stack", "cause"].includes(prop)) continue;
        if (isSensitiveKey(prop)) {
          result[prop] = "[REDACTED_SECRET_KEY]";
        } else {
          result[prop] = redactNested(err[prop], salt, seen);
        }
      }

      return result;
    }

    if (Array.isArray(value)) {
      return value.map((item) => redactNested(item, salt, seen));
    }

    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (isSensitiveKey(k)) {
        result[k] = "[REDACTED_SECRET_KEY]";
      } else {
        result[k] = redactNested(v, salt, seen);
      }
    }
    return result;
  }

  return value;
}

/**
 * Redacts PII from a lifecycle-service audit event before persistence.
 *
 * Redaction strategy:
 * - DROP: Raw PII fields (account IDs, data keys, descriptions, XDR)
 * - HASH: Sensitive fields needed for correlation (accounts, destinations)
 * - KEEP: Operational non-PII fields (counts, types, hashes)
 *
 * The same input always produces the same redacted output (deterministic hashing),
 * enabling correlation across audit entries without exposing raw PII.
 *
 * @param event - The audit event before redaction
 * @param salt - The redaction salt (should be constant per service instance)
 * @returns Redacted audit event safe for persistence and external shipment
 */
export function redactAuditEvent(event: AuditEvent, salt: string): AuditEvent {
  const redacted: AuditEvent = {
    type: event.type,
    at: event.at,
    data: {},
  };

  // Helper to safely access and redact plan objects
  function redactPlan(plan: unknown): Record<string, unknown> {
    if (typeof plan !== "object" || plan === null) return {};

    const p = plan as Record<string, unknown>;
    const redactedPlan: Record<string, unknown> = {};

    // Hash account identifiers for correlation
    if (typeof p.accountId === "string") {
      redactedPlan.accountRef = hashForRedaction(p.accountId, salt);
    }
    if (typeof p.destination === "string") {
      redactedPlan.destinationRef = hashForRedaction(p.destination, salt);
    }

    // Preserve operational fields
    if (typeof p.estimatedTransactions === "number") {
      redactedPlan.estimatedTransactions = p.estimatedTransactions;
    }
    if (typeof p.mergeReady === "boolean") {
      redactedPlan.mergeReady = p.mergeReady;
    }

    // Extract blocker types (preserve operational value, drop descriptions)
    if (Array.isArray(p.blockers)) {
      const blockerTypes = extractBlockerTypes(p.blockers);
      redactedPlan.blockerTypes = blockerTypes;
      redactedPlan.blockerCount = p.blockers.length;
    }

    // DROP: account object (full HorizonAccount)
    // DROP: blockers[].description
    // DROP: blockers[].actionRequired
    // DROP: dataKeys array

    return redactedPlan;
  }

  // Helper to safely redact a single step (transaction)
  function redactStep(step: unknown): Record<string, unknown> {
    if (typeof step !== "object" || step === null) return {};

    const s = step as Record<string, unknown>;
    const redactedStep: Record<string, unknown> = {};

    // Preserve non-PII fields
    if (typeof s.title === "string") {
      redactedStep.title = s.title;
    }
    if (typeof s.hash === "string") {
      redactedStep.hash = s.hash;
    }

    // DROP: xdr (full transaction envelope with account IDs)
    // DROP: description (contains raw account IDs)

    return redactedStep;
  }

  // Redact based on endpoint type
  const eventType = event.type;
  const seen = new WeakSet<object>();

  if (eventType === "lifecycle.inspect_requested" || eventType === "lifecycle.account_inspected") {
    // POST /lifecycle/inspect returns { account: HorizonAccount }
    // DROP the entire account object
    // No fields to preserve
  } else if (
    eventType === "lifecycle.plan_requested" ||
    eventType === "lifecycle.cleanup_planned"
  ) {
    // POST /lifecycle/plan returns { plan: CleanupPlan }
    if (event.data.plan) {
      redacted.data.plan = redactPlan(event.data.plan);
    }
  } else if (
    eventType === "lifecycle.execute_requested" ||
    eventType === "lifecycle.cleanup_executed"
  ) {
    // POST /lifecycle/execute returns { steps: CleanupStep[], plan: CleanupPlan }
    if (event.data.plan) {
      redacted.data.plan = redactPlan(event.data.plan);
    }
    if (Array.isArray(event.data.steps)) {
      redacted.data.steps = (event.data.steps as unknown[]).map((step) => redactStep(step));
    }
  } else if (
    eventType === "lifecycle.merge_requested" ||
    eventType === "lifecycle.account_merged"
  ) {
    // POST /lifecycle/merge returns { step: CleanupStep }
    if (event.data.step) {
      redacted.data.step = redactStep(event.data.step);
    }
  } else {
    // Unknown event type: apply conservative redaction
    // Avoid common PII field names, but walk nested structures and scrub sensitive data
    for (const [key, value] of Object.entries(event.data)) {
      if (
        ["accountId", "destination", "account", "dataKeys", "offers", "description"].includes(
          key,
        )
      ) {
        continue;
      }
      if (isSensitiveKey(key)) {
        redacted.data[key] = "[REDACTED_SECRET_KEY]";
      } else {
        redacted.data[key] = redactNested(value, salt, seen);
      }
    }
  }

  // If an error is attached to any event data, ensure it is safely redacted and retained
  if (event.data.error !== undefined && redacted.data.error === undefined) {
    redacted.data.error = redactNested(event.data.error, salt, seen);
  }

  return redacted;
}
