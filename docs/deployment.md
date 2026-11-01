# Configuration, deployment, and troubleshooting

## Local runtime files

Start with the [README local checks](../README.md#try-it-locally). Those commands pass committed templates explicitly and never probe or send messages. Real deployment uses ignored runtime files instead:

```powershell
Copy-Item config/default.example.yaml config/default.yaml
Copy-Item config/alert_routes.example.yaml config/alert_routes.yaml
Copy-Item config/alert_routes.test.example.yaml config/alert_routes.test.yaml
Copy-Item .env.example .env
```

Run these copy commands on a fresh checkout; back up existing deployment files before replacing them during an upgrade. Replace the example probe hosts, target URLs/ports, monitor names, and owner names in local YAML. Keep credentials, real Open IDs, and private-key paths in the deployment environment. The test routes template is for separately authorized acceptance testing and contains no live endpoint.

The CLI loads the project-root `.env`, using simple `KEY=VALUE` assignments and optional matching quotes. Existing process values take precedence. It does not implement shell expansion or the full dotenv syntax. Relative YAML and route paths resolve from the Skill root, not from the current shell or custom config file directory.

| Environment variable | Used by |
| --- | --- |
| `FEISHU_APP_ID` | Application-bot identity for production delivery |
| `FEISHU_APP_SECRET` | Application-bot credential |
| `FEISHU_DOMAIN` | `feishu` or `lark` API domain selection |
| `SERVICE_REACHABILITY_ALERT_BOT_ID` | Production sender ID restriction |
| `SERVICE_REACHABILITY_ALERT_CHAT_ID` | Production alert-group restriction |
| `SERVICE_REACHABILITY_FEISHU_OWNER_OPEN_ID` | Sample route/fallback owner and fixed gateway runtime-error recipient |
| `INTERNAL_PROBE_SSH_KEY_PATH` | Local private-key path used to SSH to internal-probe |
| `EXTERNAL_PROBE_SSH_KEY_PATH` | Local private-key path used to SSH to external-probe |
| `FEISHU_WEBHOOK_URL`, `FEISHU_SECRET` | Optional legacy custom-bot sender only |

Each additional owner can use a separate environment variable referenced by `feishu_user_id_env`. Owner references must be populated even for parse/route CLI commands because configuration validation resolves the whole routes file. Synthetic values suffice for the offline example; real app-scoped Open IDs are required for delivery.

`--config` chooses the main YAML; `--routes` overrides `runtime.alert_routes_path`. Environment variables supply only explicitly referenced fields and gateway settings; numeric retry/timeout fields come from YAML. See [architecture](architecture.md#routing-and-configuration) for the exact precedence.

## Routes

An HTTP route can share one URL:

```yaml
routes:
  - id: example-health
    match:
      monitor_name: "示例HTTP服务"
    service_name: "Example HTTP service"
    diagnosis:
      type: http
      url: "https://service.example.invalid/health"
    owners:
      - name: "Example owner"
        feishu_user_id_env: SERVICE_REACHABILITY_FEISHU_OWNER_OPEN_ID
fallback:
  owners:
    - name: "On-call owner"
      feishu_user_id_env: SERVICE_REACHABILITY_FEISHU_OWNER_OPEN_ID
```

The committed [routes template](../config/alert_routes.example.yaml) also shows separate internal/external HTTP targets and a shared TCP host/port. A per-perspective TCP diagnosis has this shape:

```yaml
type: tcp
targets:
  internal:
    host: "service-internal.example.invalid"
    port: 8000
  external:
    host: "service-public.example.invalid"
    port: 8000
```

Use exactly one of `match.monitor_name` and `match.monitor_name_regex`; regex matching is against the entire name. Do not derive a target from the title. Maintain `fallback.owners` as well as route owners.

## Linux probes

The probe images include OpenSSH, curl, Python, and the supplied `tcping` utility. On a host capable of building Linux containers, from the repository root:

```text
docker build -f probes/internal-probe/Dockerfile -t service-reachability-internal-probe:local probes
docker build -f probes/external-probe/Dockerfile -t service-reachability-external-probe:local probes
```

The build context must be `probes`, because each Dockerfile copies `common/*`. These are supplied deployment commands; image builds were not executed during publication preparation.

At container startup, provide public keys through `PROBE_AUTHORIZED_KEYS`, `PROBE_AUTHORIZED_KEYS_FILE`, or a mounted `authorized_keys` file for the `probe` user. The entrypoint refuses to start without authorized keys and generates SSH host keys. The server disables root and password login. Never copy client private keys into an image.

For existing Linux probe hosts, provide `curl`, `tcping`, and GNU-compatible `timeout` in the SSH user's PATH. The controller wraps TCP/HTTP commands in a timeout; the bundled TCP utility also has its own `TCPING_TIMEOUT_SECONDS` setting (default 5). The SSH client currently accepts unknown server host keys; host-key pinning requires further implementation.

Deploy the two probes where they have the intended network perspectives. Running both on the same network does not by itself demonstrate internal-versus-external isolation. Network routes, DNS, firewall rules, SSH exposure, and key permissions are deployment responsibilities.

## Hermes gateway installation

Prerequisites are a Hermes installation that exposes the `pre_gateway_dispatch` hook, the same Python environment able to import the requirements, reachable probe SSH hosts, and a configured Feishu application bot. This repository does not vendor Hermes or identify a verified gateway release.

Install these paths in the target Hermes home:

```text
<HERMES_HOME>/skills/devops/service-reachability-check/
<HERMES_HOME>/plugins/service-reachability-dispatch/
```

Copy the Skill files into the first directory. Copy the contents of `hermes-plugin/service-reachability-dispatch` into the second. A ZIP from [the allowlist builder](publishing.md#deployment-zip) already separates these directories. The checkout suffix `-github` must not be used for the installed Skill name, because the plugin loader imports from the fixed path above.

Install `requirements.txt` using the Python environment that runs the gateway. Create the ignored runtime YAML in the installed Skill. Merge the variables from `.env.example` into the gateway's environment or existing Hermes-home `.env`, preserving unrelated configuration. The hook reads the bot and chat IDs before `load_config` loads any Skill-local `.env`, so a Skill-local file alone does not enable production dispatch.

Add the plugin to the existing Hermes configuration without removing other enabled plugins:

```yaml
plugins:
  enabled:
    - service-reachability-dispatch
```

Restart the target gateway only as a separately approved deployment/acceptance action, using that installation's normal process. No gateway restart was performed in this review. For upgrade/rollback, preserve the prior code, plugin, `.env`, and runtime YAML. For a complete emergency stop, disable the plugin: a gateway runtime-error fallback uses an enabled built-in application configuration independently of `app_notify.enabled`.

## Feishu application and delivery

The existing monitoring bot sends the source alert; a different application bot sends diagnostic cards. The application must be in the alert group and permitted to send group replies and private messages. Owners must be within its available user scope, using Open IDs belonging to that application. `FEISHU_DOMAIN=lark` selects Lark API endpoints; this code path has no live delivery verification in the publication review.

The normal gateway path uses `feishu.app_notify.enabled`. `feishu.enabled` controls only the legacy webhook sender, not application fan-out. Runtime error notification also requires the fixed fallback owner variable and usable application credentials. If bot/chat IDs are missing, the pre-dispatch hook suppresses matching bot alerts and logs the configuration problem; it cannot run the normal notification job.

Group cards reply to the original alert and contain real owner mentions. Private cards contain names without mentions. A failed recipient does not prevent others from being attempted. Transport timeouts on a reply are treated as ambiguous and do not cause a second group message. Sends are not automatically retried.

## Manual CLI modes

These commands use configured local runtime files. The first three commands do not run SSH probes or call a sender:

```powershell
python scripts/service_reachability_check.py --summary-json
python scripts/service_reachability_check.py --event-json examples/normalized_fault_event.json
python scripts/service_reachability_check.py --resolve-event-json examples/normalized_fault_event.json
```

For separately authorized live SSH acceptance, this command probes both sides but does not send notifications:

```powershell
python scripts/service_reachability_check.py --config config/default.yaml --routes config/alert_routes.test.yaml --diagnose-event-json examples/normalized_fault_event.json
```

The notification-capable CLI modes differ from production:

| Mode | Behavior |
| --- | --- |
| `--diagnose-event-json` | SSH diagnosis; no sending unless `--send-feishu` is supplied |
| `--diagnose-event-json ... --send-feishu` | Legacy custom-bot webhook sending, subject to `feishu.enabled` |
| `--hermes-event-json` | Compatibility CLI that requests legacy webhook sending automatically; not production app fan-out |
| `--send-feishu-payload-json` | Sends a supplied payload via the legacy webhook; no diagnosis |
| Production gateway hook | Application bot with group reply and owner DMs |

`runtime.dry_run` is not consulted by these execution paths. Do not use it as a send/probe safeguard. CLI JSON is for operational diagnosis, includes target and alert data, and must not be posted back into the alert group or committed as public evidence.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No route | Exact monitor spelling, full-string regex, and the selected routes file |
| Configuration error | YAML shape, required owner environment variables, probe fields, retry/timeout types |
| SSH or command failure | Probe reachability, key path/permissions, SSH user/public-key authorization, and `curl`/`tcping`/`timeout` availability |
| Group succeeds but DM fails | App-scoped owner IDs, app user scope, and private-message capability |
| No notification | Both probes succeeded, source/recovery was filtered, credentials/settings are missing, or a duplicate was suppressed |
| Human mentions receive no response | The configured alert group intentionally suppresses non-target messages before LLM dispatch |

Inspect gateway status categories and private operational logs. The CLI's structured result status is the diagnostic outcome; a zero process exit code is not itself proof that the service is reachable. Configuration/input errors use exit code 2.
