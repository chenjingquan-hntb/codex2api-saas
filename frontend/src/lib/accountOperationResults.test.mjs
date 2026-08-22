import assert from "node:assert/strict";
import test from "node:test";

import {
  collectAccountOperationResult,
  filterAccountOperationResults,
  paginateAccountOperationResults,
  resolveChannelBatchTestAccountIDs,
  snapshotAccountOperationResults,
  summarizeAccountOperationResults,
} from "./accountOperationResults.ts";

test("collectAccountOperationResult preserves every account event before UI throttling", () => {
  const results = new Map();
  collectAccountOperationResult(results, {
    type: "start",
    action: "batch_test",
  });
  collectAccountOperationResult(results, {
    type: "progress",
    action: "batch_test",
    account_id: 3,
    status: "success",
    http_status: 200,
    message: "测试通过",
  });
  collectAccountOperationResult(results, {
    type: "progress",
    action: "batch_test",
    account_id: 7,
    status: "rate_limited",
    http_status: 429,
    message: "上游返回 429",
  });
  collectAccountOperationResult(results, {
    type: "progress",
    action: "batch_test",
    account_id: 5,
    status: "failed",
    http_status: 500,
    error: "上游返回 500",
  });

  assert.deepEqual(snapshotAccountOperationResults(results), [
    {
      accountId: 5,
      status: "failed",
      httpStatus: 500,
      message: "上游返回 500",
    },
    {
      accountId: 7,
      status: "rate_limited",
      httpStatus: 429,
      message: "上游返回 429",
    },
    {
      accountId: 3,
      status: "success",
      httpStatus: 200,
      message: "测试通过",
    },
  ]);
});

test("collectAccountOperationResult clears stale results and supports legacy events", () => {
  const results = new Map([
    [
      1,
      {
        accountId: 1,
        status: "failed",
        httpStatus: 500,
        message: "stale",
      },
    ],
  ]);

  collectAccountOperationResult(results, {
    type: "start",
    action: "batch_refresh",
  });
  collectAccountOperationResult(results, {
    type: "progress",
    action: "batch_refresh",
    account_id: 2,
    error: "refresh failed",
  });

  assert.deepEqual(snapshotAccountOperationResults(results), [
    {
      accountId: 2,
      status: "failed",
      httpStatus: undefined,
      message: "refresh failed",
    },
  ]);
});

test("summarizeAccountOperationResults groups every result for the modal header", () => {
  assert.deepEqual(
    summarizeAccountOperationResults([
      { accountId: 1, status: "success", httpStatus: 200, message: "" },
      { accountId: 2, status: "failed", httpStatus: 500, message: "" },
      { accountId: 3, status: "banned", httpStatus: 401, message: "" },
      {
        accountId: 4,
        status: "rate_limited",
        httpStatus: 429,
        message: "",
      },
      { accountId: 5, status: "unknown", message: "" },
    ]),
    {
      total: 5,
      success: 1,
      failed: 2,
      banned: 1,
      rateLimited: 1,
    },
  );
});

test("filterAccountOperationResults follows the same categories as the summary", () => {
  const results = [
    { accountId: 1, status: "success", httpStatus: 200, message: "" },
    { accountId: 2, status: "failed", httpStatus: 500, message: "" },
    { accountId: 3, status: "banned", httpStatus: 401, message: "" },
    {
      accountId: 4,
      status: "rate_limited",
      httpStatus: 429,
      message: "",
    },
    { accountId: 5, status: "unknown", message: "" },
  ];

  assert.equal(filterAccountOperationResults(results, "all"), results);
  assert.deepEqual(
    filterAccountOperationResults(results, "success").map(
      (result) => result.accountId,
    ),
    [1],
  );
  assert.deepEqual(
    filterAccountOperationResults(results, "failed").map(
      (result) => result.accountId,
    ),
    [2, 5],
  );
  assert.deepEqual(
    filterAccountOperationResults(results, "banned").map(
      (result) => result.accountId,
    ),
    [3],
  );
  assert.deepEqual(
    filterAccountOperationResults(results, "rate_limited").map(
      (result) => result.accountId,
    ),
    [4],
  );
});

test("paginateAccountOperationResults pages large result sets on the client", () => {
  const results = Array.from({ length: 1000 }, (_, index) => ({
    accountId: index + 1,
    status: "success",
    message: "",
  }));

  const firstPage = paginateAccountOperationResults(results, 1, 50);
  assert.equal(firstPage.page, 1);
  assert.equal(firstPage.totalPages, 20);
  assert.equal(firstPage.results.length, 50);
  assert.equal(firstPage.results[0].accountId, 1);
  assert.equal(firstPage.results[49].accountId, 50);

  const lastPage = paginateAccountOperationResults(results, 99, 50);
  assert.equal(lastPage.page, 20);
  assert.equal(lastPage.totalPages, 20);
  assert.equal(lastPage.results.length, 50);
  assert.equal(lastPage.results[0].accountId, 951);
  assert.equal(lastPage.results[49].accountId, 1000);
});

test("resolveChannelBatchTestAccountIDs keeps provider tests isolated", () => {
  const accounts = [
    { id: 1 },
    { id: 2, grok_api: false },
    { id: 3, grok_api: true },
    { id: 4, anthropic_api: true },
  ];

  assert.deepEqual(resolveChannelBatchTestAccountIDs(accounts, "codex"), [
    1, 2,
  ]);
  assert.deepEqual(resolveChannelBatchTestAccountIDs(accounts, "grok"), [3]);
  assert.deepEqual(resolveChannelBatchTestAccountIDs(accounts, "anthropic"), [4]);
  assert.deepEqual(
    resolveChannelBatchTestAccountIDs(accounts, "codex", [3, 4, 2, 2, 99, 1]),
    [2, 1],
  );
});
