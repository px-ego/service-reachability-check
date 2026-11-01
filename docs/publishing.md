# Publishing this repository

Use the single line in [GITHUB_DESCRIPTION.txt](../GITHUB_DESCRIPTION.txt) for GitHub's Description field:

> Investigate Feishu reachability alerts with internal and external SSH probes, explicit routing, and failure-aware owner notifications before LLM dispatch.

## Repository review

The upload tree includes Python source, the Hermes plugin, Linux probe assets, dependency requirements, existing tests, synthetic event data, sanitized configuration templates, and maintained documentation. It excludes the source project's runtime YAML, `.env`, operational screenshot, debug payloads, logs, caches, and local state. The source project's `.git` directory was absent; no prior Git history is imported.

Inspect the staged paths before committing and verify your repository-local Git identity. Do not copy production configuration back into the staged tree. `.gitignore` only controls untracked files; it does not untrack files or purge historical commits.

```powershell
git status --short
git diff --cached --stat
git diff --cached --check
git config user.name
git config user.email
```

The publication preparation creates a local `main` commit using the existing account identity, without changing global Git configuration. A local commit and a configured remote do not upload files.

## GitHub upload

Recommended repository name: `service-reachability-check`, under `px-ego`. Prefer a **Private** repository for the first remote review, then deliberately change visibility when ready. If using an empty repository, do not initialize a separate README or license there.

From the prepared checkout, inspect the remote first:

```powershell
git remote -v
```

If no `origin` is configured, add it once:

```powershell
git remote add origin https://github.com/px-ego/service-reachability-check.git
```

After checking the target repository and its visibility, upload:

```powershell
git push -u origin main
```

Complete GitHub authentication if Git requests it. A successful push is the point at which the files have been uploaded. Do not force-push over unrelated existing history.

## Deployment ZIP

Use the existing allowlist builder instead of compressing the working directory:

```powershell
python tools/build_handoff_zip.py --output .local/service-reachability-check-handoff.zip
```

The ZIP contains a `service-reachability-check` Skill directory and a separate `service-reachability-dispatch` plugin directory. Runtime YAML inside the ZIP is generated from `config/*.example.yaml`, never copied from local runtime YAML. Referenced documentation is included. The builder scans staged text for private keys, real-looking Feishu IDs, workstation paths, and known local sensitive values. This is a targeted packaging check, not a guarantee that arbitrary added content is safe to publish.
