from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROBES_ROOT = PROJECT_ROOT / "probes"
TCPING_SCRIPT = PROBES_ROOT / "common" / "tcping.py"
ENTRYPOINT = PROBES_ROOT / "common" / "entrypoint.sh"
SSHD_CONFIG = PROBES_ROOT / "common" / "sshd_config"


class ProbeContainerFileTests(unittest.TestCase):
    def test_probe_dockerfiles_exist_and_install_expected_tools(self) -> None:
        for probe_name in ("internal-probe", "external-probe"):
            with self.subTest(probe_name=probe_name):
                dockerfile = PROBES_ROOT / probe_name / "Dockerfile"
                content = dockerfile.read_text(encoding="utf-8")

                self.assertIn("FROM debian:bookworm-slim", content)
                self.assertIn("openssh-server", content)
                self.assertIn("curl", content)
                self.assertIn("python3", content)
                self.assertIn("ca-certificates", content)
                self.assertIn("useradd --create-home", content)
                self.assertIn("probe", content)
                self.assertIn("COPY common/tcping.py /usr/local/bin/tcping", content)
                self.assertIn(
                    "COPY common/entrypoint.sh /usr/local/bin/probe-entrypoint",
                    content,
                )
                self.assertIn("COPY common/sshd_config /etc/ssh/sshd_config", content)
                self.assertIn('ENTRYPOINT ["/usr/local/bin/probe-entrypoint"]', content)

    def test_sshd_config_disables_password_and_root_login(self) -> None:
        content = SSHD_CONFIG.read_text(encoding="utf-8")

        self.assertIn("PermitRootLogin no", content)
        self.assertIn("PasswordAuthentication no", content)
        self.assertIn("KbdInteractiveAuthentication no", content)
        self.assertIn("PubkeyAuthentication yes", content)
        self.assertIn("AuthenticationMethods publickey", content)
        self.assertIn("AllowUsers probe", content)

    def test_entrypoint_requires_authorized_keys_sources(self) -> None:
        content = ENTRYPOINT.read_text(encoding="utf-8")

        self.assertIn("PROBE_AUTHORIZED_KEYS", content)
        self.assertIn("PROBE_AUTHORIZED_KEYS_FILE", content)
        self.assertIn("authorized_keys", content)
        self.assertIn("ssh-keygen -A", content)
        self.assertIn("sshd -D -e", content)
        self.assertIn("exit 1", content)


class TcpingScriptTests(unittest.TestCase):
    def test_tcping_succeeds_against_local_tcp_server(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        accepted: list[bool] = []

        def accept_once() -> None:
            try:
                connection, _ = server.accept()
                with connection:
                    accepted.append(True)
            finally:
                server.close()

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        completed = _run_tcping("127.0.0.1", str(port))
        thread.join(timeout=2)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(f"tcping 127.0.0.1:{port} succeeded", completed.stdout)
        self.assertEqual(accepted, [True])

    def test_tcping_fails_against_closed_port(self) -> None:
        closed_port = _closed_local_port()
        completed = _run_tcping("127.0.0.1", str(closed_port))

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(f"tcping 127.0.0.1:{closed_port} failed", completed.stderr)

    def test_tcping_rejects_invalid_arguments(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(TCPING_SCRIPT), "127.0.0.1", "not-a-port"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            encoding="utf-8",
            text=True,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertIn("invalid port", completed.stderr)


def _run_tcping(host: str, port: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["TCPING_TIMEOUT_SECONDS"] = "1"
    return subprocess.run(
        [sys.executable, str(TCPING_SCRIPT), host, port],
        cwd=PROJECT_ROOT,
        capture_output=True,
        encoding="utf-8",
        text=True,
        env=env,
    )


def _closed_local_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


if __name__ == "__main__":
    unittest.main()
