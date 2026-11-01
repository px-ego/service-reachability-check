# Validation record

Publication review date: **2026-11-01** (Asia/Shanghai).

This record describes validation of the sanitized publication copy. It does not certify a production deployment. Runtime configuration and debug payloads from the source environment are excluded and are not used as public proof of live integration.

## Environment

- Windows, Python 3.11.15.
- Installed dependencies used for validation: PyYAML 6.0.3 and Paramiko 5.0.0.
- [requirements.txt](../requirements.txt) retains the supplied minimum-version constraints; there is no supplied lockfile. Other Python/OS combinations were not tested in this review.
- Tests use committed templates or temporary synthetic configuration. No local `.env` or runtime YAML is needed for the test suite.

## Validation scope

The full existing suite is run with:

```powershell
python -m unittest discover -s tests
```

**Final result: 127 passed, 0 failed, 0 skipped** (4.179 seconds in this local run; not a performance benchmark). SSH and Feishu request adapters are mocked. The TCP utility tests use a real temporary loopback listener and a closed local port; they do not access a deployment probe or monitored service.

The first publication-copy run reported 2 errors because legacy CLI tests still referred to excluded runtime routes. Those test fixtures now explicitly use committed example configuration and synthetic environment values; the complete rerun passed. No diagnostic application behavior was changed.

Additional checks:

- The `skill-creator` `quick_validate.py` validator returned `Skill is valid!`, run with Python UTF-8 mode for the Chinese Skill content on Windows. This checks Skill metadata/format, not live integration behavior.
- The README's offline route-resolution example returned `status: matched`, route `example-http-service`, and `[redacted]` in the owner field, without probing or sending.
- All 33 local Markdown links and heading references resolved. The 25 fenced code blocks were checked for closure; JSON/YAML examples parsed successfully. Python source syntax, four YAML files, and the synthetic event JSON parsed successfully. The Mermaid diagram was checked against the execution flow; it was not rendered in this review.
- A targeted scan of the 46 upload files found no known local credential/deployment values, real-looking Feishu IDs, private-key material, workstation paths, live webhook URLs, or non-loopback IPv4 literals. Synthetic IDs and loopback test addresses remain intentionally. The scan is not a universal secret detector.
- The allowlist builder produced a 49-file ZIP with template-derived runtime YAML and the two required top-level directories. All 33 archive-relative documentation links resolved, shell scripts had LF line endings, and the extracted CLI resolved the synthetic event using generated default configuration without SSH or messaging. Archives remain local and ignored.
- A whole-tree hash confirmed that the source directory's 98 files were unchanged. Copied core modules, plugin files, and probe assets preserve the supplied source content; `.gitattributes` normalizes text line endings for Git/Linux checkouts. Publication changes are limited to documentation, ignore/line-ending policy, test configuration isolation, and packaging metadata/allowlists.

| Area | Evidence exercised by the suite |
| --- | --- |
| Intake | Fault/recovery, human/other/self bot, unrelated messages, title-only input, upstream timestamps, UTF-8/BOM CLI input |
| Routing | Exact precedence, full regex matching, missing/conflicting routes, target/owner validation, owner environment resolution |
| Diagnosis | All four success/failure combinations and malformed/incomplete probe-result handling |
| Execution | Quoting, configured attempts/intervals, timeout budgets, mocked hanging SSH channel, one-side failure isolation |
| Notifications | Group mentions, private names without mentions, owner deduplication, one token, ambiguous reply timeout, partial/token/recipient failures |
| Silence | Normal/recovered/ignored results do not invoke a sender |
| Gateway | Hook registration, duplicate suppression, source/group filtering, error fallback with fixed owner |
| CLI and privacy | Synthetic credential/owner redaction and operational result shapes |
| Probe assets | Dockerfile/sshd/entrypoint content checks and local TCP utility execution |
| Packaging | Allowlisted ZIP, separate Skill/plugin roots, template-derived runtime YAML, excluded environment/cache/image artifacts |

## Outside this review

No paid models, remote SSH sessions, monitored targets, live Feishu/Lark requests, real gateway restart, or hardware were used. Dockerfiles were inspected and checked by existing file-content tests; Docker image builds, container boot, and deployment network topology were not exercised. No live-service reliability, latency, accuracy, or operational-impact metric is claimed.

The production integration and container assets exist in code. They are not merely design proposals, but their live operation is unverified by this review. A separate acceptance run should use a test group, test owners, and reversible deployment configuration.
