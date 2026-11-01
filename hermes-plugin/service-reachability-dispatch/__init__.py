from __future__ import annotations

import sys

from hermes_cli.config import get_hermes_home


PROJECT_ROOT = (
    get_hermes_home()
    / "skills"
    / "devops"
    / "service-reachability-check"
)
project_root_text = str(PROJECT_ROOT)
if project_root_text not in sys.path:
    sys.path.insert(0, project_root_text)

from scripts.hermes_gateway_dispatch import register as _register  # noqa: E402


def register(ctx) -> None:
    _register(ctx)
