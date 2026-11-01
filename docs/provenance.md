# Provenance and contribution boundaries

This repository is a sanitized publication copy of an existing `service-reachability-check` project supplied for review. It was prepared for the GitHub account `px-ego`.

The supplied source directory had no `.git` metadata, branches, remotes, or commit history. No original-author declaration, license file, or separate contributor record was found in the supplied project. The publication copy therefore starts a new Git history; the original directory is retained separately. This initial commit records curation of a snapshot, not the project's original development date or individual contribution history.

The publication work retains the existing diagnostic modules, gateway hook and plugin, probe assets, and test cases. It replaces the main README with English documentation, adds behavior/deployment/validation notes, excludes deployment state, makes tests read committed templates, and extends the existing allowlisted packager to include the new documentation.

The code and tests alone do not establish sole authorship, independent implementation, employer ownership, production use, or measured operational impact. No such claims are made here. Any personal contribution statement should be supported by separate development records.

Hermes, Feishu/Lark, Python dependencies, Debian, OpenSSH, and curl are external systems or dependencies; they are not authored by this repository. Python dependencies are declared in [requirements.txt](../requirements.txt), and system packages in the [probe Dockerfiles](../probes). No dependency source is vendored. This publication review does not add a license or assign rights for the pre-existing code.
