# DNS Doctor Check

A GitHub Action that runs [DNS Doctor](https://dnsdoctor.dev) in CI. Two modes:

- **scan**: the full report for a domain (SPF, DKIM, DMARC, MX, DNS health, blacklists, domain and TLS expiry). Fails the job on a chosen severity and writes a table to the job summary.
- **propagation**: after you change a DNS record, waits until six locations on four continents agree on it, or until a deadline passes.

Every verdict is deterministic. The action shells out to the [`dns-doctor` npm CLI](https://www.npmjs.com/package/dns-doctor), writes what the API returned to a file verbatim, and composes nothing itself. No API key is needed.

## Scan on every push

```yaml
- uses: dnsdoctor/dns-doctor-action@v0
  with:
    domain: example.com
    fail-on: warn        # fail | warn | never (default: fail)
```

The job summary shows one row per check. The full JSON is at the `report-path` output, and `status` is `pass`, `warn` or `fail`.

## Wait for a DNS change to propagate

```yaml
- name: Update the record
  run: ./deploy-dns.sh

- uses: dnsdoctor/dns-doctor-action@v0
  with:
    domain: app.example.com
    mode: propagation
    record-type: A
    expected: 203.0.113.10
    timeout-minutes: "20"
    interval-seconds: "60"
```

The step succeeds when every reachable location answers with the expected value. `partial`, `not_propagated`, `inconsistent` and `unknown` are polled again until the deadline, then fail the job with the last verdict. Omit `expected` to wait for consistency only.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `domain` | required | The domain (scan) or DNS name (propagation). |
| `mode` | `scan` | `scan` or `propagation`. |
| `fail-on` | `fail` | Scan: `fail`, `warn` or `never`. |
| `record-type` | `A` | Propagation: record type to read. |
| `expected` | empty | Propagation: the value every location must answer with. |
| `timeout-minutes` | `30` | Propagation: deadline. |
| `interval-seconds` | `60` | Propagation: poll interval. |
| `api-token` | empty | Optional DNS Doctor API token; raises the anonymous rate limit. |
| `cli-version` | `0.2.1` | The `dns-doctor` CLI version to run. |

## Outputs

| Output | Meaning |
| --- | --- |
| `status` | Scan: `pass`, `warn`, `fail`. Propagation: the final verdict. |
| `failing-checks` | Scan: comma-separated names of failing checks. |
| `report-path` | The JSON the CLI returned, relayed verbatim. |

## What is and is not a failure

- A `temperror` check is a transient lookup failure. It is shown in the summary and never counts as a finding.
- If the API cannot be reached or rate-limits the runner, the job fails with a message saying it is not a verdict about the domain. In propagation mode that case is retried within the deadline.
- A domain that does not resolve fails the scan with "does not resolve"; no check ran, so the report carries no findings.

## Rate limits

The anonymous allowance is per source IP, and GitHub-hosted runners share addresses. A scan every push on a busy repo can hit it; an `api-token` raises the limit.

Apache-2.0.
