import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { AccountRow } from "../types";
import {
  filterAccountOperationResults,
  paginateAccountOperationResults,
  summarizeAccountOperationResults,
  type AccountOperationResultFilter,
  type AccountOperationResultsState,
} from "../lib/accountOperationResults";
import ChannelLogo from "./ChannelLogo";
import Modal from "./Modal";
import Pagination from "./Pagination";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const RESULT_PAGE_SIZE_OPTIONS = [50, 100, 200];

function formatResultAccountName(account: AccountRow): string {
  if (account.openai_responses_api || account.grok_api) {
    return account.name?.trim() || `ID ${account.id}`;
  }
  return account.email || account.name || `ID ${account.id}`;
}

function resultAccountLines(result: {
  accountId: number;
  accountName?: string;
  accountEmail?: string;
}, account?: AccountRow): { primary: string; secondary?: string } {
  const email = (account?.email || result.accountEmail || "").trim();
  const name = (account?.name || result.accountName || "").trim();
  if (email) {
    return {
      primary: email,
      secondary: name && name !== email ? name : undefined,
    };
  }
  if (account) {
    return { primary: formatResultAccountName(account) };
  }
  return { primary: name || `#${result.accountId}` };
}

export default function OperationResultsModal({
  state,
  accounts,
  channel,
  onClose,
}: {
  state: AccountOperationResultsState | null;
  accounts: AccountRow[];
  channel: "codex" | "grok" | "anthropic";
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const [activeFilter, setActiveFilter] =
    useState<AccountOperationResultFilter>("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(RESULT_PAGE_SIZE_OPTIONS[0]);
  const tableScrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setActiveFilter("all");
    setPage(1);
    tableScrollRef.current?.scrollTo({ top: 0 });
  }, [state]);

  const accountsByID = new Map(accounts.map((account) => [account.id, account]));
  const summary = summarizeAccountOperationResults(state?.results ?? []);
  const summaryItems = [
    {
      filter: "all" as const,
      label: t("accounts.operationResultsTotal"),
      value: summary.total,
      tone: "border-border bg-muted/30 text-foreground",
    },
    {
      filter: "success" as const,
      label: t("accounts.operationProgressSuccess"),
      value: summary.success,
      tone:
        "border-emerald-200 bg-emerald-50/70 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/35 dark:text-emerald-300",
    },
    {
      filter: "failed" as const,
      label: t("accounts.operationProgressFailed"),
      value: summary.failed,
      tone:
        "border-red-200 bg-red-50/70 text-red-700 dark:border-red-900 dark:bg-red-950/35 dark:text-red-300",
    },
    ...(state?.action === "batch_test"
      ? [
          {
            filter: "banned" as const,
            label: t("accounts.operationProgressBanned"),
            value: summary.banned,
            tone:
              "border-rose-200 bg-rose-50/70 text-rose-700 dark:border-rose-900 dark:bg-rose-950/35 dark:text-rose-300",
          },
          {
            filter: "rate_limited" as const,
            label: t("accounts.operationProgressRateLimited"),
            value: summary.rateLimited,
            tone:
              "border-amber-200 bg-amber-50/70 text-amber-700 dark:border-amber-900 dark:bg-amber-950/35 dark:text-amber-300",
          },
        ]
      : []),
  ];
  const resolvedFilter = summaryItems.some(
    (item) => item.filter === activeFilter,
  )
    ? activeFilter
    : "all";
  const filteredResults = filterAccountOperationResults(
    state?.results ?? [],
    resolvedFilter,
  );
  const paginatedResults = paginateAccountOperationResults(
    filteredResults,
    page,
    pageSize,
  );
  const activeFilterLabel =
    summaryItems.find((item) => item.filter === resolvedFilter)?.label ??
    t("accounts.operationResultsTotal");

  const title =
    state?.action === "batch_refresh"
      ? t("accounts.operationRefreshResultsTitle")
      : t("accounts.operationTestResultsTitle");

  const statusLabel = (status: string) => {
    switch (status) {
      case "success":
        return t("accounts.operationProgressSuccess");
      case "banned":
        return t("accounts.operationProgressBanned");
      case "rate_limited":
        return t("accounts.operationProgressRateLimited");
      case "failed":
        return t("accounts.operationProgressFailed");
      default:
        return status || t("accounts.operationProgressFailed");
    }
  };

  const statusTone = (status: string) => {
    switch (status) {
      case "success":
        return "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-950/40 dark:text-emerald-300";
      case "rate_limited":
        return "bg-amber-50 text-amber-700 ring-amber-600/20 dark:bg-amber-950/40 dark:text-amber-300";
      case "banned":
      case "failed":
        return "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-950/40 dark:text-red-300";
      default:
        return "bg-muted text-muted-foreground ring-border";
    }
  };

  return (
    <Modal
      show={Boolean(state)}
      title={
        <span className="inline-flex items-center gap-2.5">
          <ChannelLogo
            channel={channel}
            size={26}
            title={channel === "grok" ? "Grok" : channel === "anthropic" ? "Anthropic" : "Codex"}
          />
          <span>{title}</span>
        </span>
      }
      contentClassName="sm:max-w-[900px]"
      onClose={onClose}
      footer={
        <Button type="button" variant="outline" onClick={onClose}>
          {t("common.close")}
        </Button>
      }
    >
      {state ? (
        <div className="space-y-3">
          <div
            className={`grid grid-cols-2 gap-2 ${
              state.action === "batch_test"
                ? "sm:grid-cols-5"
                : "sm:grid-cols-3"
            }`}
          >
            {summaryItems.map((item) => {
              const isActive = resolvedFilter === item.filter;
              return (
                <button
                  key={item.filter}
                  type="button"
                  aria-pressed={isActive}
                  aria-label={t("accounts.operationResultsFilterAria", {
                    filter: item.label,
                    count: item.value,
                  })}
                  className={`cursor-pointer rounded-lg border px-3 py-2.5 text-left transition-[box-shadow,transform] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 ${item.tone} ${
                    isActive
                      ? "ring-2 ring-primary/55 ring-offset-2"
                      : "hover:-translate-y-0.5 hover:shadow-sm"
                  }`}
                  onClick={() => {
                    setActiveFilter((current) =>
                      current === item.filter && item.filter !== "all"
                        ? "all"
                        : item.filter,
                    );
                    setPage(1);
                    tableScrollRef.current?.scrollTo({ top: 0 });
                  }}
                >
                  <div className="text-xs font-medium opacity-80">
                    {item.label}
                  </div>
                  <div className="mt-1 text-xl font-semibold tabular-nums">
                    {item.value}
                  </div>
                </button>
              );
            })}
          </div>
          <div
            ref={tableScrollRef}
            className="max-h-[58vh] overflow-auto rounded-lg border border-border"
          >
            <Table>
              <TableHeader className="sticky top-0 z-10 bg-card">
                <TableRow>
                  <TableHead>{t("accounts.operationResultsAccount")}</TableHead>
                  <TableHead>{t("accounts.operationResultsStatus")}</TableHead>
                  <TableHead>{t("accounts.operationResultsHTTP")}</TableHead>
                  <TableHead>{t("accounts.operationResultsMessage")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredResults.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={4}
                      className="py-8 text-center text-muted-foreground"
                    >
                      {state.results.length === 0
                        ? t("accounts.operationResultsEmpty")
                        : t("accounts.operationResultsFilterEmpty", {
                            filter: activeFilterLabel,
                          })}
                    </TableCell>
                  </TableRow>
                ) : (
                  paginatedResults.results.map((result) => {
                    const account = accountsByID.get(result.accountId);
                    const identity = resultAccountLines(result, account);
                    return (
                      <TableRow key={result.accountId}>
                        <TableCell className="min-w-48">
                          <div className="font-medium break-all">
                            {identity.primary}
                          </div>
                          {identity.secondary ? (
                            <div className="text-xs text-muted-foreground">
                              {identity.secondary}
                            </div>
                          ) : null}
                          <div className="text-xs text-muted-foreground">
                            ID {result.accountId}
                          </div>
                        </TableCell>
                        <TableCell>
                          <span
                            className={`inline-flex rounded-md px-2 py-1 text-xs font-semibold ring-1 ring-inset ${statusTone(result.status)}`}
                          >
                            {statusLabel(result.status)}
                          </span>
                        </TableCell>
                        <TableCell>
                          {result.httpStatus ? (
                            <span className="font-mono text-xs font-semibold">
                              {result.httpStatus}
                            </span>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell className="min-w-72 max-w-[32rem] whitespace-normal break-words text-xs">
                          {result.message || "—"}
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>
          {filteredResults.length > RESULT_PAGE_SIZE_OPTIONS[0] ? (
            <Pagination
              page={paginatedResults.page}
              totalPages={paginatedResults.totalPages}
              totalItems={filteredResults.length}
              pageSize={pageSize}
              pageSizeOptions={RESULT_PAGE_SIZE_OPTIONS}
              onPageChange={(nextPage) => {
                setPage(nextPage);
                tableScrollRef.current?.scrollTo({ top: 0 });
              }}
              onPageSizeChange={(nextPageSize) => {
                setPageSize(nextPageSize);
                setPage(1);
                tableScrollRef.current?.scrollTo({ top: 0 });
              }}
            />
          ) : null}
        </div>
      ) : null}
    </Modal>
  );
}
