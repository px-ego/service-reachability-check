# Architecture and behavior

## Execution paths

The production path is `hermes-plugin/service-reachability-dispatch/__init__.py` → `scripts.hermes_gateway_dispatch.register` → `pre_gateway_dispatch`. The loader obtains the Hermes home from `hermes_cli.config` and adds `skills/devops/service-reachability-check` to the Python import path. The installed Skill directory name therefore matters even if the GitHub checkout has a different name.

The hook accepts the Hermes event object, not a raw Feishu webhook. It leaves other platforms and other groups to normal Hermes routing. Within the configured alert group, it suppresses human messages, other bots, unrelated content, and recoveries. Accepted faults are scheduled with `asyncio.create_task`, executed through `asyncio.to_thread`, and serialized by a process-wide lock. The hook returns a skip action so Hermes does not generate an LLM reply for those messages.

The manual path is `scripts/service_reachability_check.py` → `run_manual_diagnosis`. It accepts normalized JSON and can stop after parsing, routing, or diagnosis. It does not replace the production hook's bot/group authorization checks.

## Intake and parsing

A normalized synthetic event is available in [examples/normalized_fault_event.json](../examples/normalized_fault_event.json). A parsed fault retains `source_bot`, `status`, `monitor_name`, `reason`, `alert_time`, and `raw_text`.

The upstream alert time is retained exactly when present; receipt time is never substituted. Title-only faults are accepted with empty reason/time fields. Cards identify missing upstream fields explicitly.

Production checks `source.is_bot`, the configured sender ID, and the configured chat ID. The standalone parser accepts an allowed display name **or** sender ID; it does not enforce chat membership or use `sender_type` as an authorization gate. Treat normalized CLI input as trusted local input.

The current title pattern finds a matching `监控告警:` line with a bracketed state. Recovery detection checks `正常` in that state or `[恢复正常]` in the text. Fault detection checks `故障` in the state or `[发生故障]` in the text. This describes the implementation's string matching; it is not a general Feishu message parser.

Deduplication claims the message ID before scheduling. If absent, the key is a SHA-256 hash of chat ID, text, and the supplied event timestamp. Claims expire after 24 hours, with a maximum of 1,024 entries. Failed scheduling/handling does not release the claim for automatic replay. All claims disappear on process restart.

## Routing and configuration

`load_config` loads a default configuration and a separate routes mapping, validates them, then resolves `feishu_user_id_env` references into internal `feishu_user_id` fields. The public templates use environment references; literal IDs are accepted by the compatibility parser but should not be placed in versioned configuration.

Routing evaluates exact `monitor_name` matches first. If any exist, regex routes are not considered. Otherwise `re.fullmatch` checks `monitor_name_regex`. Multiple matches within the selected tier return `route_conflict`; no match returns `route_not_found`. Both errors return fallback owners and prevent all probe execution. Targets are never inferred from alert text.

Each route must have a unique ID, one selector, a service name, a supported diagnosis type, valid target structure, and at least one owner. HTTP accepts a shared `url` or a `targets.internal/external.url` mapping. TCP accepts shared `host`/`port` or per-perspective targets. Shared and per-perspective fields cannot be mixed. Ports for TCP targets must be integers in `1..65535`; URLs must have an HTTP(S) scheme and network location. This is structural validation, not hostname allowlisting or full URL credential rejection. Keep credentials out of targets.

Concrete precedence is:

- `--config` selects the default YAML; otherwise the loader uses `config/default.yaml`.
- `--routes` overrides `runtime.alert_routes_path` from that YAML.
- Existing process environment values override project-local `.env` assignments.
- Environment values are used only by fields explicitly naming an environment variable, plus the gateway's fixed bot/chat/fallback variables. There is no generic environment override for every YAML field.

Relative config and routes paths are resolved against the Skill root. A routes path inside a custom YAML is not relative to that YAML's own directory.

## Probe execution

`CommandRunner` is the adapter boundary. Tests inject a fake runner; deployment uses `ParamikoSSHCommandRunner`. Both perspectives are attempted, in internal-then-external order. Runner errors become failure data, allowing the next perspective to run.

Commands are assembled from route fields and quoted with `shlex.quote`, then wrapped in Linux `timeout --signal=KILL`. Raw alert text is not inserted into a command.

```text
timeout --signal=KILL <effective>s tcping <host> <port>
timeout --signal=KILL <effective>s curl -sS -o /dev/null -w '%{http_code}' --max-time <http>s <url>
```

The supplied `tcping` is a Python TCP connect utility, not an ICMP probe. HTTP checks require a zero curl exit status and a returned status equal to `diagnosis.http_success_status`; other 2xx/3xx codes are not automatically accepted. Curl does not use `-L`, so redirects are not followed. It does not inspect a business response body or add application authentication.

| Setting | Meaning |
| --- | --- |
| `probes.retry_count` | Total attempts per perspective, including the first attempt |
| `probes.retry_interval_seconds` | Delay between failed attempts; no delay after final failure |
| `probes.ssh_timeout_seconds` | SSH connect/banner/auth timeout passed to Paramiko |
| `probes.command_timeout_seconds` | Upper bound for remote command execution |
| `diagnosis.tcp_timeout_seconds` / `http_timeout_seconds` | Probe-type execution budgets |
| Effective command timeout | Minimum of command timeout and the applicable diagnosis timeout |

Curl's `--max-time` receives the HTTP setting, while the wrapper uses the effective minimum. The SSH adapter also polls the channel against a local monotonic deadline and closes a hanging channel. These are execution budgets, not measured latency improvements or a single end-to-end SLA. There is no total queue/job deadline.

Results retain attempt count, elapsed time, configured timeout, exit status, truncated output, and structured adapter errors. Non-success HTTP status, command failure, missing tools, timeout, DNS/TLS/connect errors, and SSH failures all produce failed outcomes. Raw exception details may appear in internal probe evidence; gateway runtime fallback cards expose only a concise operational message.

## Diagnosis and notification

`diagnosis_engine.py` is pure: it compares two `ProbeOutcome` values and does not access networks. Both successful outcomes produce `normal`; the other three combinations produce cautious likely-path assessments. Missing or duplicate perspective results produce a structured error, not a guessed diagnosis. [The README decision table](../README.md#how-it-works) shows the four combinations.

Card building is separate from sending. `FeishuMessageBuildResult.payload` is always the group card with true `<at>` tags. `private_payload` is the separate card with owner names and no mention tags. Owner mentions and private recipients are deduplicated by ID.

The production gateway invokes `send_app_notification_fanout`:

1. Fetch one `tenant_access_token` for the fan-out.
2. Attempt a reply to the original alert, or a top-level group message if no original message ID exists.
3. If the reply returns an explicit unsuccessful API response, fall back to a top-level group message. An ambiguous transport failure returns a structured failure without sending a second group message.
4. Send the private card separately to each unique owner with `receive_id_type=open_id`, continuing after group or individual-recipient failure.
5. Return `sent`, `partial_failure`, `failed`, or missing-recipient status without including recipient IDs as result fields. Known credentials, token, and recipient values are redacted from returned response content.

There are no automatic send retries or cross-notification token cache. The configured API domain supports Feishu and Lark endpoints; live delivery to either service was not tested in this review.

Route errors use `fallback.owners`. Exceptions in the gateway job use the fixed `SERVICE_REACHABILITY_FEISHU_OWNER_OPEN_ID` environment reference and a built-in app configuration. Missing bot/group dispatch configuration instead suppresses a bot alert with a log message; scheduling failure also logs and suppresses it. These pre-job failure paths do not send a fallback card.

## Operational boundaries

`runtime.dry_run` is summary metadata, not an execution switch. Production application sending is separate from the legacy `feishu.enabled` webhook setting. The gateway exception fallback constructs an enabled application configuration independently of YAML; disabling `app_notify.enabled` alone is not a complete emergency stop. Disable the plugin for that purpose.

The SSH client currently uses `AutoAddPolicy` and does not load/pin a deployment known-hosts policy. Diagnostic JSON redacts configured owner IDs, but retains raw alert text, monitor names, target URLs/hosts, and command evidence. Restrict access to operational output and keep it out of the repository.

Scheduling persistence, multi-process deduplication, automatic repair, target-host login, business-body health checks, and generic conversation handling are outside the implementation.
