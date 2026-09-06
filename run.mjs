// The action's whole runtime: shells out to the `dns-doctor` npm CLI (`--json`),
// relays what it returns, and decides pass/fail. Zero dependencies, Node 20+.
//
// Two rules carried over from every other DNS Doctor client:
//   * relay, never compose - the report is written to disk verbatim and the
//     summary shows the API's own titles, statuses and URLs;
//   * a transport failure is never a verdict - the CLI's exit 2 fails the job
//     with a message that says so, and in propagation mode it is retried.

import { spawnSync } from "node:child_process";
import { appendFileSync, realpathSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const SEVERITY = { fail: 2, warn: 1, pass: 0, info: 0, temperror: 0 };
// `propagated` when an expected value was given, `consistent` when only agreement was asked for.
export const FINAL_VERDICTS = new Set(["propagated", "consistent"]);
export const TRANSIENT_EXIT = 2;

/** pass | warn | fail across the report's checks; temperror and info never count. */
export function worstStatus(checks) {
  let worst = "pass";
  for (const c of checks) {
    const s = String(c?.status ?? "");
    if ((SEVERITY[s] ?? 0) > SEVERITY[worst]) worst = s;
  }
  return worst;
}

export function shouldFail(status, failOn) {
  if (failOn === "never") return false;
  if (failOn === "warn") return status === "warn" || status === "fail";
  return status === "fail";
}

const cell = (v) => String(v ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");

export function scanSummary(domain, checks, nextSteps) {
  const rows = checks.map((c) => `| ${cell(c.check)} | ${cell(c.status)} | ${cell(c.title)} |`);
  const lines = [`### DNS Doctor: ${cell(domain)}`, "", "| Check | Status | Finding |", "| --- | --- | --- |", ...rows];
  if (checks.some((c) => c.status === "temperror")) {
    lines.push("", "A `temperror` row is a transient lookup failure, not a finding. Re-run to resolve it.");
  }
  if (nextSteps?.report_url) lines.push("", `Full report: ${nextSteps.report_url}`);
  return lines.join("\n") + "\n";
}

export function propagationSummary(name, result) {
  const rows = (result.vantages ?? []).map((r) => {
    const cells = (r.cells ?? []).map((c) => `${cell(c.resolver)}: ${cell(c.status)}`).join(", ");
    const row = r.reached === false ? `unreached${r.detail ? ` (${cell(r.detail)})` : ""}` : "reached";
    return `| ${cell(r.label ?? r.region)} | ${row} | ${cells} |`;
  });
  return [
    `### DNS Doctor propagation: ${cell(name)}`,
    "",
    `Verdict: **${cell(result.verdict)}** (${cell(result.vantage_reached)} locations answered)`,
    "",
    "| Location | Probe | Resolvers |",
    "| --- | --- | --- |",
    ...rows,
  ].join("\n") + "\n";
}

/** Parse the CLI's stdout: the JSON body, or null when it printed none. */
export function parseBody(stdout) {
  const text = String(stdout ?? "").trim();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    const start = text.indexOf("{");
    if (start < 0) return null;
    try {
      return JSON.parse(text.slice(start));
    } catch {
      return null;
    }
  }
}

function runCli(args, env) {
  const version = env.DNSD_CLI_VERSION || "0.2.1";
  const res = spawnSync("npx", ["-y", `dns-doctor@${version}`, ...args, "--json"], {
    encoding: "utf8",
    env: { ...env, NPM_CONFIG_UPDATE_NOTIFIER: "false" },
    maxBuffer: 16 * 1024 * 1024,
  });
  return { code: res.status ?? 1, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
}

function ghOutput(env, key, value) {
  if (!env.GITHUB_OUTPUT) return;
  appendFileSync(env.GITHUB_OUTPUT, `${key}<<__dnsd__\n${value}\n__dnsd__\n`);
}

function ghSummary(env, markdown) {
  if (env.GITHUB_SUMMARY_FILE_OVERRIDE) return; // tests
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, markdown);
}

function fail(message) {
  process.stdout.write(`::error::${message}\n`);
  process.exitCode = 1;
}

export async function runScan(env, cli = runCli) {
  const domain = env.DNSD_DOMAIN;
  const { code, stdout, stderr } = cli(["scan", domain], env);
  const body = parseBody(stdout);
  if (code === TRANSIENT_EXIT || body === null) {
    fail(`DNS Doctor could not scan ${domain} (transient: ${stderr.trim() || "no response"}). This is not a verdict about the domain; re-run.`);
    return;
  }
  const report = body.report ?? body;
  const checks = Array.isArray(report.checks) ? report.checks : [];
  const status = worstStatus(checks);
  const failing = checks.filter((c) => c.status === "fail").map((c) => c.check);
  const path = resolve(env.GITHUB_WORKSPACE || process.cwd(), "dns-doctor-report.json");
  writeFileSync(path, JSON.stringify(body, null, 2) + "\n");
  ghOutput(env, "status", status);
  ghOutput(env, "failing-checks", failing.join(","));
  ghOutput(env, "report-path", path);
  ghSummary(env, scanSummary(report.domain ?? domain, checks, body.next_steps));
  if (report.not_registered === true) {
    fail(`${domain} does not resolve (not registered, or a typo); no check ran.`);
    return;
  }
  if (shouldFail(status, env.DNSD_FAIL_ON || "fail")) {
    fail(`DNS Doctor: ${domain} is ${status} (${failing.join(", ") || "see the job summary"}).`);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A positive finite number from an input, its default when blank, null when malformed. */
export function positiveNumber(raw, fallback) {
  const text = String(raw ?? "").trim();
  if (text === "") return fallback;
  const n = Number(text);
  return Number.isFinite(n) && n > 0 ? n : null;
}

/**
 * Poll until the verdict is `propagated` or the deadline passes. `partial`,
 * `not_propagated`, `inconsistent` and `unknown` are all "not yet"; a transient
 * CLI failure is retried inside the same deadline.
 */
export async function waitForPropagation(env, { cli = runCli, now = Date.now, wait = sleep } = {}) {
  const name = env.DNSD_DOMAIN;
  const args = ["propagation", name, "--type", env.DNSD_RECORD_TYPE || "A"];
  if (env.DNSD_EXPECTED) args.push("--expect", env.DNSD_EXPECTED);
  const timeoutMinutes = positiveNumber(env.DNSD_TIMEOUT_MINUTES, 30);
  const intervalSeconds = positiveNumber(env.DNSD_INTERVAL_SECONDS, 60);
  if (timeoutMinutes === null || intervalSeconds === null) {
    fail("'timeout-minutes' and 'interval-seconds' must be positive numbers");
    return "invalid-input";
  }
  const deadline = now() + timeoutMinutes * 60_000;
  const interval = intervalSeconds * 1000;
  let last = null;
  for (;;) {
    const { code, stdout } = cli(args, env);
    const body = parseBody(stdout);
    if (code !== TRANSIENT_EXIT && body !== null) {
      last = body;
      if (FINAL_VERDICTS.has(String(body.verdict))) break;
    }
    if (now() + interval > deadline) break;
    await wait(interval);
  }
  const verdict = last ? String(last.verdict) : "unavailable";
  ghOutput(env, "status", verdict);
  ghOutput(env, "failing-checks", "");
  if (last) {
    const path = resolve(env.GITHUB_WORKSPACE || process.cwd(), "dns-doctor-propagation.json");
    writeFileSync(path, JSON.stringify(last, null, 2) + "\n");
    ghOutput(env, "report-path", path);
    ghSummary(env, propagationSummary(name, last));
  }
  if (!FINAL_VERDICTS.has(verdict)) {
    fail(
      last
        ? `${name} ${env.DNSD_RECORD_TYPE || "A"} is ${verdict} after ${timeoutMinutes} minutes.`
        : `DNS Doctor could not read ${name} from any location within the deadline (transient). This is not a verdict; re-run.`,
    );
  }
  return verdict;
}

export async function main(env = process.env) {
  if (!env.DNSD_DOMAIN) {
    fail("the 'domain' input is required");
    return;
  }
  if ((env.DNSD_MODE || "scan") === "propagation") await waitForPropagation(env);
  else await runScan(env);
}

export function isEntryPoint(argv1, moduleUrl) {
  if (typeof argv1 !== "string" || argv1 === "") return false;
  try {
    return realpathSync(argv1) === realpathSync(fileURLToPath(moduleUrl));
  } catch {
    return false;
  }
}

if (isEntryPoint(process.argv[1], import.meta.url)) await main();
