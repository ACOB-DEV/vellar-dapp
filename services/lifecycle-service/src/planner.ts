import { StrKey } from "@stellar/stellar-sdk";
import type { CleanupPlan } from "@vellar/types";
import type { HorizonAccount } from "./horizon";

// CleanupPlanner (idea.md §6.4): turns inspected account state into the
// doc's CleanupPlan — every blocker explicit, merge only when none remain.
// Destructive flows are guided planners with user review, never one-click.

// Full StrKey check (version byte + checksum), not just the shape: a
// well-shaped but invalid G… address would otherwise pass here and throw later
// inside the transaction builder as a 500.
export function isClassicAccountId(value: string): boolean {
  return StrKey.isValidEd25519PublicKey(value);
}

/** Operations fit ~100 to a transaction; the final merge is its own tx. */
const OPS_PER_TX = 100;

export const BASE_RESERVE_STROOPS = 5_000_000n; // 0.5 XLM per subentry
export const BASE_FEE_STROOPS = 100n; // 100 stroops per operation

export interface InsufficientSpendableBalanceResult {
  canSelfFund: false;
  error: "insufficient_spendable_balance";
  message: string;
  spendableBalanceXlm: string;
  requiredFeeXlm: string;
  spendableBalanceStroops: string;
  requiredFeeStroops: string;
  accountId: string;
  destination: string;
  blockers: CleanupPlan["blockers"];
  estimatedTransactions: number;
  mergeReady: false;
}

export type CleanupPlanResult = CleanupPlan | InsufficientSpendableBalanceResult;

export function calculateSpendableBalanceStroops(account: HorizonAccount): bigint {
  const native = account.balances.find((b) => b.assetType === "native");
  const nativeStroops = native ? BigInt(Math.round(Number(native.balance) * 10_000_000)) : 0n;
  const subentries =
    account.subentryCount !== undefined
      ? account.subentryCount
      : account.balances.filter((b) => b.assetType !== "native").length +
        account.openOffers +
        account.dataKeys.length;
  const reserveStroops = BigInt(2 + subentries) * BASE_RESERVE_STROOPS;
  return nativeStroops > reserveStroops ? nativeStroops - reserveStroops : 0n;
}

export function calculateRequiredFeeStroops(account: HorizonAccount): bigint {
  let cleanupOps = 0;
  for (const balance of account.balances) {
    if (balance.assetType === "native") continue;
    if (Number(balance.balance) > 0) cleanupOps++; // payment
    cleanupOps++; // trustline removal
  }
  cleanupOps += account.openOffers; // one manageSellOffer per open offer
  cleanupOps += account.dataKeys.length; // one manageData per entry
  const totalOps = Math.max(1, cleanupOps);
  return BigInt(totalOps) * BASE_FEE_STROOPS;
}

export function buildCleanupPlan(
  account: HorizonAccount,
  destination: string,
): CleanupPlanResult {
  // Safety check: refuse to build a plan if pagination was cut short (#531)
  if (account.paginationIncomplete) {
    throw new Error(
      "Cannot build cleanup plan: account trustline pagination is incomplete or was cut short by an error",
    );
  }

  // Preflight check: account must have sufficient spendable balance to self-fund (#529)
  const spendableStroops = calculateSpendableBalanceStroops(account);
  const requiredFeeStroops = calculateRequiredFeeStroops(account);

  if (spendableStroops < requiredFeeStroops) {
    const spendableXlm = (Number(spendableStroops) / 10_000_000).toFixed(7);
    const requiredXlm = (Number(requiredFeeStroops) / 10_000_000).toFixed(7);
    return {
      canSelfFund: false,
      error: "insufficient_spendable_balance",
      message: `Account cannot self-fund its own cleanup: spendable balance (${spendableXlm} XLM) is less than the required fee (${requiredXlm} XLM)`,
      spendableBalanceXlm: spendableXlm,
      requiredFeeXlm: requiredXlm,
      spendableBalanceStroops: spendableStroops.toString(),
      requiredFeeStroops: requiredFeeStroops.toString(),
      accountId: account.accountId,
      destination,
      blockers: [],
      estimatedTransactions: 0,
      mergeReady: false,
    };
  }

  const blockers: CleanupPlan["blockers"] = [];

  for (const balance of account.balances) {
    if (balance.assetType === "native") continue;
    const asset = `${balance.assetCode ?? "?"}:${balance.assetIssuer ?? "?"}`;
    if (Number(balance.balance) > 0) {
      blockers.push({
        type: "balance",
        description: `Holds ${balance.balance} ${balance.assetCode ?? asset}`,
        actionRequired: `Transfer or burn the ${balance.assetCode ?? asset} balance before removing its trustline`,
      });
    }
    blockers.push({
      type: "trustline",
      description: `Trustline to ${asset}`,
      actionRequired: `Remove the ${balance.assetCode ?? asset} trustline (requires zero balance)`,
    });
  }

  if (account.openOffers > 0) {
    blockers.push({
      type: "offer",
      description: `${account.openOffers} open DEX offer(s)`,
      actionRequired: "Cancel all open offers",
    });
  }

  for (const key of account.dataKeys) {
    blockers.push({
      type: "data",
      description: `Managed data entry "${key}"`,
      actionRequired: `Delete the "${key}" data entry`,
    });
  }

  // The estimate must track the ACTUAL operation count the builder emits, not
  // blocker count: a "N open offers" blocker is one row but N cancel ops, and a
  // non-zero balance is two ops (transfer + trustline removal). Undercounting
  // here would promise fewer transactions than the split builder produces.
  let cleanupOps = 0;
  for (const balance of account.balances) {
    if (balance.assetType === "native") continue;
    if (Number(balance.balance) > 0) cleanupOps++; // payment
    cleanupOps++; // trustline removal
  }
  cleanupOps += account.openOffers; // one manageSellOffer per open offer
  cleanupOps += account.dataKeys.length; // one manageData per entry
  const estimatedTransactions = Math.max(1, Math.ceil(cleanupOps / OPS_PER_TX) + 1);

  return {
    accountId: account.accountId,
    destination,
    blockers,
    estimatedTransactions: blockers.length === 0 ? 1 : estimatedTransactions,
    mergeReady: blockers.length === 0,
  };
}
