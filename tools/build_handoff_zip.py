from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
import zipfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = (
    PROJECT_ROOT.parent / "service-reachability-check-handoff.zip"
)
SKILL_ARCHIVE_ROOT = Path("service-reachability-check")
PLUGIN_ARCHIVE_ROOT = Path("service-reachability-dispatch")

ROOT_FILES = (
    ".env.example",
    ".gitattributes",
    ".gitignore",
    "AGENTS.md",
    "GITHUB_DESCRIPTION.txt",
    "README.md",
    "requirements.txt",
    "SKILL.md",
)
PROBE_FILES = (
    "probes/common/entrypoint.sh",
    "probes/common/sshd_config",
    "probes/common/tcping.py",
    "probes/internal-probe/Dockerfile",
    "probes/external-probe/Dockerfile",
)
EXAMPLE_FILES = ("examples/normalized_fault_event.json",)
DOC_FILES = (
    "docs/architecture.md",
    "docs/deployment.md",
    "docs/validation.md",
    "docs/provenance.md",
    "docs/publishing.md",
)
CONFIG_MAPPINGS = {
    "config/default.example.yaml": "config/default.yaml",
    "config/alert_routes.example.yaml": "config/alert_routes.yaml",
    "config/alert_routes.test.example.yaml": "config/alert_routes.test.yaml",
}
PLUGIN_FILES = (
    "plugin.yaml",
    "__init__.py",
)
FORBIDDEN_PARTS = {
    ".env",
    ".tmp",
    ".pytest_cache",
    "__pycache__",
    ".venv",
    "venv",
    "reports",
}
TEXT_SUFFIXES = {
    "",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".txt",
    ".yaml",
    ".yml",
}
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
REAL_FEISHU_ID_PATTERN = re.compile(r"\b(?:ou|oc|om)_[0-9a-f]{24,}\b")
WINDOWS_USER_PATH_PATTERN = re.compile(r"\b[A-Za-z]:\\Users\\[^\\\r\n]+")
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SENSITIVE_ENV_NAME_PATTERN = re.compile(
    r"(?:SECRET|TOKEN|PASSWORD|WEBHOOK|API_KEY|PRIVATE_KEY|KEY_PATH|OPEN_ID|CHAT_ID|BOT_ID|APP_ID)",
    re.IGNORECASE,
)


class PackageBuildError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a sanitized service-reachability-check handoff ZIP."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"ZIP output path (default: {DEFAULT_OUTPUT})",
    )
    return parser.parse_args()


def _copy_file(source: Path, target: Path) -> None:
    if not source.is_file():
        raise PackageBuildError(f"required source file is missing: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def _copy_skill_tree(staging_root: Path) -> None:
    skill_root = staging_root / SKILL_ARCHIVE_ROOT
    for relative in ROOT_FILES:
        _copy_file(PROJECT_ROOT / relative, skill_root / relative)
    for relative in PROBE_FILES + EXAMPLE_FILES + DOC_FILES:
        _copy_file(PROJECT_ROOT / relative, skill_root / relative)
    for source_relative, target_relative in CONFIG_MAPPINGS.items():
        _copy_file(
            PROJECT_ROOT / source_relative,
            skill_root / source_relative,
        )
        _copy_file(
            PROJECT_ROOT / source_relative,
            skill_root / target_relative,
        )
    for directory in ("scripts", "tests", "tools"):
        for source in sorted((PROJECT_ROOT / directory).glob("*.py")):
            _copy_file(
                source,
                skill_root / directory / source.name,
            )


def _copy_plugin_tree(staging_root: Path) -> None:
    source_root = (
        PROJECT_ROOT
        / "hermes-plugin"
        / "service-reachability-dispatch"
    )
    if not source_root.is_dir():
        source_root = PROJECT_ROOT.parent / "service-reachability-dispatch"
    for relative in PLUGIN_FILES:
        _copy_file(
            source_root / relative,
            staging_root / PLUGIN_ARCHIVE_ROOT / relative,
        )


def _dotenv_values(path: Path) -> tuple[str, ...]:
    if not path.is_file():
        return ()
    values: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, raw_value = line.split("=", 1)
        if not SENSITIVE_ENV_NAME_PATTERN.search(name.strip()):
            continue
        value = raw_value.strip().strip("\"'")
        if len(value) >= 6 and not value.startswith("<"):
            values.append(value)
    return tuple(values)


def _live_ipv4_values() -> tuple[str, ...]:
    values: list[str] = []
    for name in (
        "default.yaml",
        "alert_routes.yaml",
        "alert_routes.test.yaml",
    ):
        path = PROJECT_ROOT / "config" / name
        if not path.is_file():
            continue
        for value in IPV4_PATTERN.findall(path.read_text(encoding="utf-8")):
            if value not in values:
                values.append(value)
    return tuple(values)


def _sensitive_values() -> tuple[str, ...]:
    candidates = list(_dotenv_values(PROJECT_ROOT / ".env"))
    try:
        hermes_home = PROJECT_ROOT.parents[2]
    except IndexError:
        hermes_home = None
    if hermes_home is not None:
        candidates.extend(_dotenv_values(hermes_home / ".env"))
    candidates.extend(_live_ipv4_values())
    return tuple(dict.fromkeys(value for value in candidates if value))


def _validate_staging(staging_root: Path) -> list[Path]:
    files = sorted(path for path in staging_root.rglob("*") if path.is_file())
    if not files:
        raise PackageBuildError("staging directory is empty")

    sensitive_values = _sensitive_values()
    violations: list[str] = []
    for path in files:
        relative = path.relative_to(staging_root)
        if any(
            part in FORBIDDEN_PARTS
            for part in relative.parts
            if part != ".env.example"
        ):
            violations.append(f"forbidden path: {relative.as_posix()}")
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8")
        if PRIVATE_KEY_PATTERN.search(text):
            violations.append(f"private key material: {relative.as_posix()}")
        if REAL_FEISHU_ID_PATTERN.search(text):
            violations.append(f"real-looking Feishu ID: {relative.as_posix()}")
        if WINDOWS_USER_PATH_PATTERN.search(text):
            violations.append(f"absolute user path: {relative.as_posix()}")
        for value in sensitive_values:
            if value in text:
                violations.append(
                    f"local sensitive value: {relative.as_posix()}"
                )
                break

    archive_roots = {path.relative_to(staging_root).parts[0] for path in files}
    if archive_roots != {
        SKILL_ARCHIVE_ROOT.as_posix(),
        PLUGIN_ARCHIVE_ROOT.as_posix(),
    }:
        violations.append(
            "archive must contain exactly the skill and plugin top-level directories"
        )
    if violations:
        raise PackageBuildError("; ".join(violations))
    return files


def _write_reproducible_zip(
    staging_root: Path,
    files: list[Path],
    output_path: Path,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()
    with zipfile.ZipFile(
        output_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path in files:
            relative = path.relative_to(staging_root).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(2026, 7, 27, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())


def build_handoff_zip(output_path: Path) -> dict[str, object]:
    resolved_output = output_path.expanduser().resolve()
    with tempfile.TemporaryDirectory(prefix="service-reachability-handoff-") as temp:
        staging_root = Path(temp)
        _copy_skill_tree(staging_root)
        _copy_plugin_tree(staging_root)
        files = _validate_staging(staging_root)
        _write_reproducible_zip(staging_root, files, resolved_output)

    digest = hashlib.sha256(resolved_output.read_bytes()).hexdigest()
    with zipfile.ZipFile(resolved_output) as archive:
        archive_files = sorted(
            info.filename for info in archive.infolist() if not info.is_dir()
        )
    return {
        "output_path": str(resolved_output),
        "file_count": len(archive_files),
        "size_bytes": resolved_output.stat().st_size,
        "sha256": digest,
    }


def main() -> int:
    args = parse_args()
    try:
        result = build_handoff_zip(args.output)
    except PackageBuildError as exc:
        print(json.dumps({"success": False, "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps({"success": True, **result}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
