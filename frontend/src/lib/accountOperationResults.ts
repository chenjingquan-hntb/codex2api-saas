export interface AccountOperationEvent {
  type: "start" | "progress" | "complete";
  action: string;
  account_id?: number;
  account_name?: string;
  account_email?: string;
  status?: string;
  http_status?: number;
  message?: string;
  error?: string;
}

export interface AccountOperationResult {
  accountId: number;
  accountName?: string;
  accountEmail?: string;
  status: string;
  httpStatus?: number;
  message: string;
}

export interface AccountOperationSummary {
  total: number;
  success: number;
  failed: number;
  banned: number;
  rateLimited: number;
}

export interface AccountOperationResultsPage {
  results: AccountOperationResult[];
  page: number;
  totalPages: number;
}

export interface AccountOperationResultsState {
  action: "batch_test" | "batch_refresh";
  results: AccountOperationResult[];
}

export type AccountOperationChannel = "codex" | "grok" | "anthropic";
export type AccountOperationResultFilter =
  | "all"
  | "success"
  | "failed"
  | "banned"
  | "rate_limited";

type AccountOperationResultCategory = Exclude<
  AccountOperationResultFilter,
  "all"
>;

const RESULT_STATUS_PRIORITY: Record<string, number> = {
  failed: 0,
  banned: 1,
  rate_limited: 2,
  success: 3,
};

export function collectAccountOperationResult(
  results: Map<number, AccountOperationResult>,
  event: AccountOperationEvent,
): void {
  if (event.type === "start") {
    results.clear();
    return;
  }
  if (
    event.type !== "progress" ||
    (event.action !== "batch_test" && event.action !== "batch_refresh") ||
    !event.account_id
  ) {
    return;
  }

  const status =
    event.status?.trim() || (event.error?.trim() ? "failed" : "success");
  const accountName = event.account_name?.trim();
  const accountEmail = event.account_email?.trim();
  results.set(event.account_id, {
    accountId: event.account_id,
    ...(accountName ? { accountName } : {}),
    ...(accountEmail ? { accountEmail } : {}),
    status,
    httpStatus:
      event.http_status && event.http_status > 0
        ? event.http_status
        : undefined,
    message: event.error?.trim() || event.message?.trim() || "",
  });
}

export function snapshotAccountOperationResults(
  results: Map<number, AccountOperationResult>,
): AccountOperationResult[] {
  return Array.from(results.values()).sort((left, right) => {
    const statusDiff =
      (RESULT_STATUS_PRIORITY[left.status] ?? 99) -
      (RESULT_STATUS_PRIORITY[right.status] ?? 99);
    return statusDiff || left.accountId - right.accountId;
  });
}

export function summarizeAccountOperationResults(
  results: AccountOperationResult[],
): AccountOperationSummary {
  const summary: AccountOperationSummary = {
    total: results.length,
    success: 0,
    failed: 0,
    banned: 0,
    rateLimited: 0,
  };

  for (const result of results) {
    switch (getAccountOperationResultCategory(result.status)) {
      case "success":
        summary.success += 1;
        break;
      case "banned":
        summary.banned += 1;
        break;
      case "rate_limited":
        summary.rateLimited += 1;
        break;
      default:
        summary.failed += 1;
        break;
    }
  }

  return summary;
}

export function getAccountOperationResultCategory(
  status: string,
): AccountOperationResultCategory {
  switch (status) {
    case "success":
    case "banned":
    case "rate_limited":
      return status;
    default:
      return "failed";
  }
}

export function filterAccountOperationResults(
  results: AccountOperationResult[],
  filter: AccountOperationResultFilter,
): AccountOperationResult[] {
  if (filter === "all") return results;
  return results.filter(
    (result) => getAccountOperationResultCategory(result.status) === filter,
  );
}

export function paginateAccountOperationResults(
  results: AccountOperationResult[],
  page: number,
  pageSize: number,
): AccountOperationResultsPage {
  const normalizedPageSize = Math.max(1, Math.floor(pageSize));
  const totalPages = Math.max(
    1,
    Math.ceil(results.length / normalizedPageSize),
  );
  const normalizedPage = Math.min(
    Math.max(1, Math.floor(page)),
    totalPages,
  );
  const start = (normalizedPage - 1) * normalizedPageSize;

  return {
    results: results.slice(start, start + normalizedPageSize),
    page: normalizedPage,
    totalPages,
  };
}

export function resolveChannelBatchTestAccountIDs(
  accounts: Array<{ id: number; grok_api?: boolean; anthropic_api?: boolean }>,
  channel: AccountOperationChannel,
  requestedIDs?: number[],
): number[] {
  const allowedIDs = new Set(
    accounts
      .filter((account) =>
        channel === "grok"
          ? Boolean(account.grok_api)
          : channel === "anthropic"
            ? Boolean(account.anthropic_api)
            : !account.grok_api && !account.anthropic_api,
      )
      .map((account) => account.id),
  );
  const candidates = requestedIDs ?? Array.from(allowedIDs);
  const seen = new Set<number>();
  const scopedIDs: number[] = [];

  for (const id of candidates) {
    if (!allowedIDs.has(id) || seen.has(id)) continue;
    seen.add(id);
    scopedIDs.push(id);
  }
  return scopedIDs;
}
