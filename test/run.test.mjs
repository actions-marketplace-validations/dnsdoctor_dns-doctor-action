import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { parseBody, positiveNumber, propagationSummary, runScan, scanSummary, shouldFail, waitForPropagation, worstStatus } from "../run.mjs";

const report = {
  domain: "example.com",
  checks: [
    { check: "spf", status: "pass", title: "SPF record is valid" },
    { check: "dmarc", status: "fail", title: "No DMARC record found | none" },
    { check: "dkim", status: "temperror", title: "DKIM lookup timed out" },
  ],
  next_steps: { report_url: "https://dnsdoctor.dev/scan/example.com" },
};

function env(extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), "dnsd-action-"));
  return {
    DNSD_DOMAIN: "example.com",
    GITHUB_WORKSPACE: dir,
    GITHUB_OUTPUT: join(dir, "out"),
    GITHUB_STEP_SUMMARY: join(dir, "summary"),
    ...extra,
  };
}

test("worst status: fail beats warn, temperror and info never count", () => {
  assert.equal(worstStatus(report.checks), "fail");
  assert.equal(worstStatus([{ status: "warn" }, { status: "temperror" }]), "warn");
  assert.equal(worstStatus([{ status: "temperror" }, { status: "info" }]), "pass");
});

test("fail-on policy", () => {
  assert.equal(shouldFail("warn", "fail"), false);
  assert.equal(shouldFail("warn", "warn"), true);
  assert.equal(shouldFail("fail", "never"), false);
});

test("scan: writes the body verbatim, outputs, summary with the API's own URL; a fail fails the job", async () => {
  const e = env();
  process.exitCode = 0;
  await runScan(e, () => ({ code: 1, stdout: JSON.stringify(report), stderr: "" }));
  assert.equal(process.exitCode, 1);
  process.exitCode = 0;
  const out = readFileSync(e.GITHUB_OUTPUT, "utf8");
  assert.match(out, /status<<__dnsd__\nfail\n/);
  assert.match(out, /failing-checks<<__dnsd__\ndmarc\n/);
  assert.deepEqual(JSON.parse(readFileSync(join(e.GITHUB_WORKSPACE, "dns-doctor-report.json"), "utf8")), report);
  const summary = readFileSync(e.GITHUB_STEP_SUMMARY, "utf8");
  assert.match(summary, /\| dmarc \| fail \| No DMARC record found \\\| none \|/);
  assert.match(summary, /transient lookup failure/);
  assert.match(summary, /Full report: https:\/\/dnsdoctor\.dev\/scan\/example\.com/);
});

test("scan: a transient exit is not a verdict but still fails the job loudly", async () => {
  const e = env();
  process.exitCode = 0;
  await runScan(e, () => ({ code: 2, stdout: "", stderr: "rate limited" }));
  assert.equal(process.exitCode, 1);
  process.exitCode = 0;
});

test("scan: fail-on never passes a failing report", async () => {
  const e = env({ DNSD_FAIL_ON: "never" });
  process.exitCode = 0;
  await runScan(e, () => ({ code: 1, stdout: JSON.stringify(report), stderr: "" }));
  assert.equal(process.exitCode, 0);
});

test("propagation: polls through partial and a transient, stops at propagated (consistent counts too)", async () => {
  const answers = [
    { code: 1, stdout: JSON.stringify({ verdict: "partial", vantage_reached: 4, rows: [] }) },
    { code: 2, stdout: "" },
    { code: 0, stdout: JSON.stringify({ verdict: "propagated", vantage_reached: 6, vantages: [{ region: "eu-central-1", label: "EU Central", reached: true, cells: [{ resolver: "1.1.1.1", status: "match" }] }, { region: "sa-east-1", label: "South America", reached: false, detail: "deadline", cells: [] }] }) },
  ];
  let t = 0;
  const waits = [];
  const e = env({ DNSD_MODE: "propagation", DNSD_TIMEOUT_MINUTES: "10", DNSD_INTERVAL_SECONDS: "60", DNSD_EXPECTED: "1.2.3.4" });
  process.exitCode = 0;
  const verdict = await waitForPropagation(e, {
    cli: (args) => {
      assert.deepEqual(args, ["propagation", "example.com", "--type", "A", "--expect", "1.2.3.4"]);
      return { ...answers.shift(), stderr: "" };
    },
    now: () => t,
    wait: async (ms) => { waits.push(ms); t += ms; },
  });
  assert.equal(verdict, "propagated");
  assert.deepEqual(waits, [60_000, 60_000]);
  assert.equal(process.exitCode, 0);
  const summary = readFileSync(e.GITHUB_STEP_SUMMARY, "utf8");
  assert.match(summary, /Verdict: \*\*propagated\*\* \(6 locations answered\)/);
  assert.match(summary, /\| EU Central \| reached \| 1\.1\.1\.1: match \|/);
  assert.match(summary, /\| South America \| unreached \(deadline\) \|  \|/);
});

test("propagation: the deadline fails the job with the last verdict", async () => {
  let t = 0;
  const e = env({ DNSD_MODE: "propagation", DNSD_TIMEOUT_MINUTES: "2", DNSD_INTERVAL_SECONDS: "60" });
  process.exitCode = 0;
  const verdict = await waitForPropagation(e, {
    cli: () => ({ code: 1, stdout: JSON.stringify({ verdict: "not_propagated", vantage_reached: 6, rows: [] }), stderr: "" }),
    now: () => t,
    wait: async (ms) => { t += ms; },
  });
  assert.equal(verdict, "not_propagated");
  assert.equal(process.exitCode, 1);
  process.exitCode = 0;
});

test("parseBody tolerates a leading notice line and empty output", () => {
  assert.deepEqual(parseBody('npm notice\n{"a":1}'), { a: 1 });
  assert.equal(parseBody(""), null);
});

test("summaries escape pipes and never invent a URL", () => {
  const s = scanSummary("x.test", [{ check: "a", status: "pass", title: "p|q" }], undefined);
  assert.match(s, /\| a \| pass \|/);
  assert.match(s, /p\\\|q/);
  assert.doesNotMatch(s, /https?:\/\//);
  assert.match(propagationSummary("x.test", { verdict: "unknown", vantage_reached: 2, vantages: [] }), /\*\*unknown\*\* \(2 locations answered\)/);
});

test("propagation: malformed timing inputs fail before any poll", async () => {
  assert.equal(positiveNumber("", 30), 30);
  assert.equal(positiveNumber("2.5", 30), 2.5);
  assert.equal(positiveNumber("0", 30), null);
  assert.equal(positiveNumber("soon", 30), null);
  let calls = 0;
  process.exitCode = 0;
  const verdict = await waitForPropagation(env({ DNSD_TIMEOUT_MINUTES: "soon", DNSD_INTERVAL_SECONDS: "-5" }), {
    cli: () => { calls += 1; return { code: 0, stdout: "{}", stderr: "" }; },
  });
  assert.equal(verdict, "invalid-input");
  assert.equal(calls, 0);
  assert.equal(process.exitCode, 1);
  process.exitCode = 0;
});
