import { createHash } from "node:crypto";
import { z } from "zod";
import type { PolicyDefinition } from "@vellar/types";
import { publisherIdFor } from "@vellar/service-kit";

// PolicyTemplateRegistry + PolicyValidator (idea.md §6.2; §19 D3: policies
// come from structured templates, never freeform). Each template declares how
// it is ENFORCED on-chain — honestly: our configurable spending-limit contract
// (cumulative allowance over a FIXED/tumbling window — resets on schedule, so up
// to 2x the cap can move across a boundary; NOT a sliding window) covers
// spending limits; allowlists and thresholds map to the smart wallet's native
// SignerLimits; timelock awaits a custom contract in contracts/policy-templates.

/**
 * VELA configurable spending-limit policy wasm (testnet). Built from
 * contracts/policy-templates/spending-limit and uploaded via stellar CLI; the
 * hash is verified against the local build (docs/decisions.md 2026-07-17).
 * Unlike the fixed-cap sample-policy, each instance takes the user's daily
 * limit + window as immutable constructor args, so the amount chosen in the
 * builder is the amount actually enforced on-chain.
 */
// Testnet wasm hash of the spending-limit policy contract. This is now the
// hash of the CANONICAL reproducible build — the bytes `stellar contract build`
// emits inside the verification toolchain image (infra/docker/…), uploaded to
// testnet 2026-07-20 (tx 6f83e098…, deployer vela-policy-deployer). So the
// deployed artifact == what the verification pipeline reproduces on any machine
// running the image (docs/decisions.md: container-as-source-of-truth). The prior
// hash (5d52e44c…) was a macOS-local build that a Linux container can't
// bit-reproduce — see the reproducibility finding in docs/decisions.md.
// Re-pinned 2026-09-25 (#399): the safety-rules build. Canonical image
// vela-verify:1.94.0 (rust 1.94.0, stellar-cli 26.1.0), self-verified by a
// clean rebuild producing byte-identical output; uploaded to testnet in tx
// d76a3743…. Instances deployed from the previous hash (0f6b858d…) keep their
// original semantics until detached and re-attached.
export const SPENDING_POLICY_WASM_HASH =
  "c42ab9b52c977a3ba29ca3e848dda499e91180e0c01de86a7e21e241989fcbdf";

/**
 * VELA verified-recipient policy wasm (testnet). Built through the SAME
 * canonical image (vela-verify:1.94.0), self-verified (clean rebuild
 * byte-identical), uploaded 2026-08-01 with --optimize=false (tx 4602d65e…).
 * `__constructor(wallet, registry)` binds each instance to one wallet and the
 * attestation registry; `policy__` rejects any auth whose contexts invoke a
 * contract without a live attestation (docs/design-provenance-gated-spending.md).
 */
// Re-pinned 2026-09-25 (#398): the provenance-modes build (strict /
// trusted-publishers, explicit auth_contexts parsing, bounded contexts). Same
// canonical image, self-verified, uploaded in tx 7a877049….
export const VERIFIED_RECIPIENT_WASM_HASH =
  "ef07b922670bab0f2c15c48bc96a3af0d858250c785536dde3e49d6ead690def";

/**
 * VELA token-scoped spending-limit policy wasm (testnet). Built through the
 * canonical image and uploaded 2026-07-26 (docs/decisions.md, #394). Each
 * instance binds ONE SEP-41 token: `__constructor(wallet, token, daily_limit,
 * window_seconds)`; transfers of any other token are rejected on-chain. This
 * is the policy an agent session key is minted against.
 */
export const TOKEN_SPENDING_POLICY_WASM_HASH =
  "7756ebbd6423a225692a529ca1294bc74e40bc7265184265dcd9bfc2e6a09c5e";

/** Bounds mirrored from the contracts (spending-limit `MAX_RULE_ENTRIES`,
 * verified-recipient `MAX_TRUSTED_PUBLISHERS`). Validated here so a bad
 * definition fails at authoring time, not at the constructor. */
export const MAX_RULE_ENTRIES = 8;
export const MAX_TRUSTED_PUBLISHERS = 16;

/**
 * The deployed AttestationRegistry instance (testnet, 2026-08-01), fed by the
 * verification pipeline's attestor (worker-service). Baked into generated
 * verified_only manifests the same way the wasm hashes are pinned: the
 * registry an instance trusts is part of what the policy IS.
 */
// Re-pinned 2026-09-25 (#398): the publisher-aware registry (wasm 1c243e00…,
// `upsert_with_publisher` / `publisher_of`), deployed with the SAME attestor
// address as the previous instance (CBZVS2ET…) so the verification worker
// keeps writing with its existing key once ATTESTATION_REGISTRY_ID is switched
// over in its config. The previous registry stays readable; policies pinned to
// it keep working in strict mode.
export const ATTESTATION_REGISTRY_ID = "CDYLXSYEE7CSPM3JTU52TODQWVUMDUZVFIDPEAVGDCBO7Q4YFKYHHR4W";

/** Stroops per XLM (7 decimals). */
const STROOPS_PER_XLM = 10_000_000n;
/** Default fixed (tumbling) window when a policy sets only a daily cap: 24h. */
export const DEFAULT_WINDOW_SECONDS = 60 * 60 * 24;

/** Parse a decimal XLM string (e.g. "12.5") to integer stroops. Assumes the
 * value already passed `positiveDecimal` validation (digits with one dot). */
export function xlmToStroops(xlm: string): bigint {
  const [whole = "0", frac = ""] = xlm.split(".");
  const fracPadded = (frac + "0000000").slice(0, 7);
  return BigInt(whole) * STROOPS_PER_XLM + BigInt(fracPadded);
}

const uniqueItems = (arr: string[]) => new Set(arr).size === arr.length;

const address = z.string().regex(/^[GC][A-Z2-7]{55}$/, "must be a Stellar address (G… or C…)");
const contractAddress = z.string().regex(/^C[A-Z2-7]{55}$/, "must be a contract address (C…)");

/** A positive integer amount in a token's BASE UNITS (stroops for XLM). Rules
 * and budgets are never fiat — there is no price oracle on Soroban. */
const baseUnits = z
  .string()
  .regex(/^\d+$/, "must be a whole number of base units")
  .refine((v) => !/^\d+$/.test(v) || BigInt(v) >= 1n, { message: "must be at least 1 base unit" })
  .refine((v) => !/^\d+$/.test(v) || BigInt(v) <= (1n << 127n) - 1n, {
    message: "exceeds the i128 range",
  });

const windowSeconds = z
  .number()
  .int("windowSeconds must be an integer")
  .min(1, "windowSeconds must be at least 1")
  .max(31_536_000, "windowSeconds cannot exceed 31,536,000 (365 days)");

/** On-chain safety rules for the spending-limit contract (#399). Both tables
 * are bounded by the contract; an empty allowlist would authorize nothing. */
const safetyRulesSchema = z
  .object({
    maxSingleTransfer: z
      .array(z.object({ token: contractAddress, amountBaseUnits: baseUnits }).strict())
      .max(MAX_RULE_ENTRIES, `at most ${MAX_RULE_ENTRIES} per-token caps`)
      .refine((rules) => uniqueItems(rules.map((r) => r.token)), {
        message: "duplicate tokens in maxSingleTransfer are not allowed",
      })
      .optional(),
    allowedTokens: z
      .array(contractAddress)
      .min(1, "allowedTokens must list at least one token")
      .max(MAX_RULE_ENTRIES, `at most ${MAX_RULE_ENTRIES} allowed tokens`)
      .refine(uniqueItems, { message: "duplicate allowed tokens are not allowed" })
      .optional(),
  })
  .strict();

/** Per-token budget for the token-scoped spending-limit contract (#394). */
const tokenBudgetSchema = z
  .object({
    token: contractAddress,
    amountBaseUnits: baseUnits,
    windowSeconds: windowSeconds.optional(),
  })
  .strict();

/** A publisher as the user names it ("github.com/owner" or a repo URL); it is
 * canonicalized + hashed at generate time. */
const publisher = z
  .string()
  .trim()
  .min(1)
  .max(200)
  .refine((v) => publisherIdFor(v) !== undefined, {
    message: "must identify a source host and owner (e.g. github.com/vellar-wallet)",
  });

/** Provenance mode for the verified-recipient contract (#398). */
const provenanceSchema = z.discriminatedUnion("mode", [
  z.object({ mode: z.literal("strict") }).strict(),
  z
    .object({
      mode: z.literal("trusted_publishers"),
      trustedPublishers: z
        .array(publisher)
        .min(1, "trusted_publishers mode needs at least one publisher")
        .max(MAX_TRUSTED_PUBLISHERS, `at most ${MAX_TRUSTED_PUBLISHERS} trusted publishers`),
    })
    .strict(),
]);

/**
 * Strict positive XLM decimal amount (idea.md §6.2).
 * Enforces Stellar stroop precision (max 7 decimal places) and positive value (>= 1 stroop = 0.0000001 XLM).
 */
const positiveXlmAmount = z
  .string()
  .regex(/^\d+(\.\d{1,7})?$/, "must be a valid decimal amount with at most 7 decimal places")
  .refine(
    (v) => {
      try {
        return xlmToStroops(v) > 0n;
      } catch {
        return false;
      }
    },
    { message: "amount must be at least 1 stroop (0.0000001 XLM)" },
  );

const base = z.object({
  version: z.literal("1"),
  schemaVersion: z.number().int().min(1).default(1).optional(),
  owners: z
    .array(address)
    .min(1, "must have at least one owner")
    .refine(uniqueItems, { message: "duplicate owners are not allowed" }),
});

export type Enforcement =
  | {
      kind: "policy-contract";
      wasmHash: string;
      /** Constructor args for the per-user instance, derived from the
       * definition/deployment. Present once a policy is generated. (Named
       * `constructorArgs`, not `constructor`, to avoid the reserved property.) */
      constructorArgs?:
        SpendingConstructor | TokenSpendingConstructor | VerifiedRecipientConstructor;
    }
  | { kind: "signer-limits" }
  | { kind: "none" }
  | { kind: "custom-contract-pending" };

/** Immutable args passed to the spending-limit contract's `__constructor`.
 * `wallet` is filled in at deploy time (the user's smart-account address); the
 * amount/window come from the policy definition. */
export interface SpendingConstructor {
  dailyLimitStroops: string;
  windowSeconds: number;
  /** Safety rules (#399). Absent = no rules (the original behavior); the
   * deployer encodes an empty rule set. */
  rules?: SafetyRulesConstructor;
}

/** The spending-limit contract's `SafetyRules` struct, in base units. */
export interface SafetyRulesConstructor {
  maxSingleTransfer: Array<{ token: string; amountBaseUnits: string }>;
  /** `null` = any token (contract `None`). */
  allowedTokens: string[] | null;
}

/** Immutable args for the token-scoped spending-limit contract's
 * `__constructor(wallet, token, daily_limit, window_seconds)`. */
export interface TokenSpendingConstructor {
  token: string;
  dailyLimitBaseUnits: string;
  windowSeconds: number;
}

/** Immutable args for the verified-recipient contract's `__constructor`.
 * `wallet` is filled in at deploy time; the registry is pinned at generate
 * time (ATTESTATION_REGISTRY_ID). `mode` selects strict (any live
 * attestation) or trusted-publishers (live attestation attributed to one of
 * `trustedPublisherIds`, 32-byte ids as hex). */
export interface VerifiedRecipientConstructor {
  registry: string;
  mode: "strict" | "trusted_publishers";
  trustedPublisherIds?: string[];
}

export interface PolicyTemplate {
  type: string;
  schemaVersion: number;
  title: string;
  description: string;
  schema: z.ZodType;
  enforcement: Enforcement;
}

/**
 * Schema validation rules for spending limits (idea.md §6.2):
 * - At least one of dailyXlm or perTxXlm must be provided
 * - Amounts must have <= 7 decimals and >= 1 stroop
 * - If both are set, perTxXlm must not exceed dailyXlm
 */
const spendingLimitsSchema = z
  .object({
    dailyXlm: positiveXlmAmount.optional(),
    perTxXlm: positiveXlmAmount.optional(),
  })
  .strict()
  .refine((v) => v.dailyXlm !== undefined || v.perTxXlm !== undefined, {
    message: "set dailyXlm and/or perTxXlm",
  })
  .refine(
    (v) => {
      if (v.dailyXlm !== undefined && v.perTxXlm !== undefined) {
        return xlmToStroops(v.perTxXlm) <= xlmToStroops(v.dailyXlm);
      }
      return true;
    },
    { message: "perTxXlm cannot exceed dailyXlm" },
  );

/**
 * Policy templates registry with strict field-level schema validation (idea.md §6.2).
 * Every template strictly validates input fields, range limits, unique arrays, and rejects unexpected properties.
 */
export const templates: PolicyTemplate[] = [
  {
    type: "single_owner",
    schemaVersion: 1,
    title: "Single owner",
    description: "One key controls the account (the default smart-wallet state).",
    schema: base
      .extend({
        type: z.literal("single_owner"),
        owners: z
          .array(address)
          .length(1, "single_owner policy requires exactly one owner")
          .refine(uniqueItems, { message: "duplicate owners are not allowed" }),
      })
      .strict(),
    enforcement: { kind: "none" },
  },
  {
    type: "multisig_threshold",
    schemaVersion: 1,
    title: "Multisig threshold",
    description: "Require N of M owners to approve sensitive actions.",
    schema: base
      .extend({
        type: z.literal("multisig_threshold"),
        owners: z
          .array(address)
          .min(2, "multisig_threshold policy requires at least two owners")
          .refine(uniqueItems, { message: "duplicate owners are not allowed" }),
        threshold: z
          .number()
          .int("threshold must be an integer")
          .min(2, "threshold must be at least 2"),
      })
      .strict()
      .refine((v) => v.threshold <= v.owners.length, {
        message: "threshold cannot exceed the number of owners",
      }),
    enforcement: { kind: "signer-limits" },
  },
  {
    type: "spending_limit",
    schemaVersion: 1,
    title: "Spending limit",
    description:
      "Cap total XLM a signer can move per fixed period, with optional on-chain safety rules (per-token single-transfer ceiling, token allowlist) for supported transfer patterns.",
    schema: base
      .extend({
        type: z.literal("spending_limit"),
        spendingLimits: spendingLimitsSchema,
        safetyRules: safetyRulesSchema.optional(),
      })
      .strict(),
    enforcement: { kind: "policy-contract", wasmHash: SPENDING_POLICY_WASM_HASH },
  },
  {
    type: "token_spending_limit",
    schemaVersion: 1,
    title: "Token budget (agent key)",
    description:
      "Cumulative allowance of ONE token per fixed period — the on-chain budget an agent session key is minted against. Transfers of any other token are rejected.",
    schema: base
      .extend({
        type: z.literal("token_spending_limit"),
        tokenBudget: tokenBudgetSchema,
      })
      .strict(),
    enforcement: { kind: "policy-contract", wasmHash: TOKEN_SPENDING_POLICY_WASM_HASH },
  },
  {
    type: "contract_allowlist",
    schemaVersion: 1,
    title: "Contract allowlist",
    description: "Restrict a signer to interacting only with approved contracts.",
    schema: base
      .extend({
        type: z.literal("contract_allowlist"),
        allowlistedContracts: z
          .array(contractAddress)
          .min(1, "must allowlist at least one contract")
          .refine(uniqueItems, { message: "duplicate allowlisted contracts are not allowed" }),
      })
      .strict(),
    enforcement: { kind: "signer-limits" },
  },
  {
    type: "verified_only",
    schemaVersion: 1,
    title: "Verified provenance only",
    description:
      "Restrict a signer to contracts with verified source provenance — strict (any live attestation) or trusted publishers only. Verified means reproducible, attributable source; not audited or safe.",
    schema: base
      .extend({
        type: z.literal("verified_only"),
        provenance: provenanceSchema.optional(),
      })
      .strict(),
    enforcement: { kind: "policy-contract", wasmHash: VERIFIED_RECIPIENT_WASM_HASH },
  },
  {
    type: "timelock",
    schemaVersion: 1,
    title: "Time-lock",
    description: "Delay sensitive admin actions by a configurable period.",
    schema: base
      .extend({
        type: z.literal("timelock"),
        timelocks: z
          .object({
            adminActionDelaySeconds: z
              .number()
              .int("delay must be an integer")
              .min(1, "delay must be at least 1 second")
              .max(31_536_000, "delay cannot exceed 31,536,000 seconds (365 days)"),
          })
          .strict(),
      })
      .strict(),
    enforcement: { kind: "custom-contract-pending" },
  },
];

export function getTemplate(type: string, schemaVersion?: number): PolicyTemplate | undefined {
  if (schemaVersion !== undefined) {
    return templates.find((t) => t.type === type && t.schemaVersion === schemaVersion);
  }
  const matching = templates.filter((t) => t.type === type);
  if (matching.length === 0) return undefined;
  return matching.slice().sort((a, b) => b.schemaVersion - a.schemaVersion)[0];
}

/**
 * Derive the on-chain constructor args for a spending-limit policy.
 *
 * The contract enforces a CUMULATIVE allowance over a FIXED (tumbling) window —
 * a per-transfer cap is not a real spending limit (policy signatures are
 * secretless; repeated capped transfers drain the wallet). So `dailyXlm` maps
 * directly to the window allowance over 24h (resets on a fixed schedule, so up
 * to 2x can move across a boundary). When only `perTxXlm` is set we still enforce it as
 * a cumulative daily cap (the safe interpretation), never as an unbounded
 * per-tx cap. When both are set, the daily cap is the enforced ceiling and the
 * per-tx value is authoring metadata only.
 */
export function deriveSpendingConstructor(definition: PolicyDefinition): SpendingConstructor {
  const limits = (definition as { spendingLimits?: { dailyXlm?: string; perTxXlm?: string } })
    .spendingLimits;
  const capXlm = limits?.dailyXlm ?? limits?.perTxXlm;
  if (!capXlm) {
    // Unreachable for a validated spending_limit definition (the schema
    // requires at least one), but fail loud rather than deploy an empty cap.
    throw new Error("spending_limit policy has no dailyXlm or perTxXlm");
  }
  const rules = deriveSafetyRules(definition);
  return {
    dailyLimitStroops: xlmToStroops(capXlm).toString(),
    windowSeconds: DEFAULT_WINDOW_SECONDS,
    ...(rules ? { rules } : {}),
  };
}

/** The spending-limit contract's `SafetyRules` for a definition, or undefined
 * when none were authored (the deployer then encodes the empty rule set). */
export function deriveSafetyRules(
  definition: PolicyDefinition,
): SafetyRulesConstructor | undefined {
  const rules = definition.safetyRules;
  if (!rules || (!rules.maxSingleTransfer?.length && !rules.allowedTokens)) return undefined;
  return {
    maxSingleTransfer: (rules.maxSingleTransfer ?? []).map(({ token, amountBaseUnits }) => ({
      token,
      amountBaseUnits,
    })),
    allowedTokens: rules.allowedTokens ? [...rules.allowedTokens] : null,
  };
}

/** Derive the token-scoped budget contract's constructor args. */
export function deriveTokenSpendingConstructor(
  definition: PolicyDefinition,
): TokenSpendingConstructor {
  const budget = definition.tokenBudget;
  if (!budget) {
    // Unreachable for a validated token_spending_limit definition.
    throw new Error("token_spending_limit policy has no tokenBudget");
  }
  return {
    token: budget.token,
    dailyLimitBaseUnits: budget.amountBaseUnits,
    windowSeconds: budget.windowSeconds ?? DEFAULT_WINDOW_SECONDS,
  };
}

/** Derive the verified-recipient constructor args: the pinned registry plus
 * the provenance mode. Publisher names are canonicalized + hashed here so the
 * on-chain set is exactly what the attestor writes (`publisherIdFor`). */
export function deriveVerifiedRecipientConstructor(
  definition: PolicyDefinition,
): VerifiedRecipientConstructor {
  const provenance = definition.provenance ?? { mode: "strict" as const };
  if (provenance.mode === "trusted_publishers") {
    const ids = (provenance.trustedPublishers ?? []).map((p) => {
      const id = publisherIdFor(p);
      if (!id) throw new Error(`unattributable publisher: ${p}`);
      return id;
    });
    return {
      registry: ATTESTATION_REGISTRY_ID,
      mode: "trusted_publishers",
      trustedPublisherIds: [...new Set(ids)],
    };
  }
  return { registry: ATTESTATION_REGISTRY_ID, mode: "strict" };
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

export function validateDefinition(
  definition: unknown,
  schemaVersionOverride?: number,
): ValidationResult {
  const typed = definition as { type?: unknown; schemaVersion?: unknown };
  if (!typed || typeof typed !== "object") {
    return { valid: false, errors: ["definition must be an object"] };
  }
  const typeStr = typeof typed.type === "string" ? typed.type : undefined;
  if (!typeStr) {
    return { valid: false, errors: [`unknown policy type: ${String(typed?.type)}`] };
  }

  const requestedVersion =
    schemaVersionOverride ??
    (typeof typed.schemaVersion === "number" ? typed.schemaVersion : undefined);

  if (requestedVersion !== undefined) {
    const template = getTemplate(typeStr, requestedVersion);
    if (!template) {
      return {
        valid: false,
        errors: [`schema version ${requestedVersion} does not exist for policy type: ${typeStr}`],
      };
    }
    const parsed = template.schema.safeParse(definition);
    if (parsed.success) return { valid: true, errors: [] };
    return {
      valid: false,
      errors: parsed.error.issues.map((i) => `${i.path.join(".") || "definition"}: ${i.message}`),
    };
  }

  const template = getTemplate(typeStr);
  if (!template) {
    return { valid: false, errors: [`unknown policy type: ${typeStr}`] };
  }
  const parsed = template.schema.safeParse(definition);
  if (parsed.success) return { valid: true, errors: [] };
  return {
    valid: false,
    errors: parsed.error.issues.map((i) => `${i.path.join(".") || "definition"}: ${i.message}`),
  };
}

export function validateDeployedPolicy(record: {
  definition: unknown;
  schemaVersion?: number;
}): ValidationResult {
  const version =
    record.schemaVersion ?? (record.definition as { schemaVersion?: number })?.schemaVersion;
  return validateDefinition(record.definition, version);
}

/** Recursive key-sorted serialization — a replacer array would silently drop
 * nested keys, making the hash blind to policy content. */
function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalize((value as Record<string, unknown>)[k])}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}

/** Deterministic content hash (idea.md §6.2 output artifacts: policy hash). */
export function policyHash(definition: PolicyDefinition): string {
  return createHash("sha256").update(canonicalize(definition)).digest("hex");
}

export interface GeneratedPolicy {
  definition: PolicyDefinition;
  policyHash: string;
  schemaVersion?: number;
  /** Deployment manifest (idea.md §6.2): how this policy gets enforced. */
  manifest: {
    template: string;
    schemaVersion?: number;
    enforcement: Enforcement;
    network: "testnet" | "mainnet";
  };
}

export function generatePolicy(
  definition: PolicyDefinition,
  network: "testnet" | "mainnet",
): GeneratedPolicy {
  const schemaVersion = definition.schemaVersion ?? 1;
  const template = getTemplate(definition.type, schemaVersion);
  if (!template) {
    throw new Error(
      `unknown policy type: ${definition.type}${
        definition.schemaVersion !== undefined ? ` (schemaVersion: ${definition.schemaVersion})` : ""
      }`,
    );
  }

  // Spending limits deploy a policy contract instance; bake the per-user
  // constructor args (derived from THIS definition) into the manifest so the
  // deploy step is a pure function of the generated policy.
  let enforcement = template.enforcement;
  if (definition.type === "spending_limit" && enforcement.kind === "policy-contract") {
    enforcement = { ...enforcement, constructorArgs: deriveSpendingConstructor(definition) };
  }
  if (definition.type === "token_spending_limit" && enforcement.kind === "policy-contract") {
    enforcement = { ...enforcement, constructorArgs: deriveTokenSpendingConstructor(definition) };
  }
  // Verified-only instances bind to the deployed attestation registry — pinned
  // at generate time so the manifest fully determines the deploy.
  if (definition.type === "verified_only" && enforcement.kind === "policy-contract") {
    enforcement = {
      ...enforcement,
      constructorArgs: deriveVerifiedRecipientConstructor(definition),
    };
  }

  const defWithVersion: PolicyDefinition = {
    ...definition,
    schemaVersion: template.schemaVersion,
  };

  return {
    definition: defWithVersion,
    policyHash: policyHash(defWithVersion),
    schemaVersion: template.schemaVersion,
    manifest: {
      template: template.type,
      schemaVersion: template.schemaVersion,
      enforcement,
      network,
    },
  };
}

