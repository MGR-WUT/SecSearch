"""Shared run-directory helpers for AttackGraph experiment scripts.

The convention mirrors WildGraphBench (`eval/WildGraphBench/runs_technology/<name>/`):
every run produces a self-describing folder under ``eval/AttackGraph/runs/<name>/``
containing the per-script JSON reports plus a single ``RUN.md`` card that records
every script invocation and its parameters in order.

A shared ``--run-dir`` argument is added to each CLI so users can group several
script invocations (load + link-prediction + community + cve_apt) into the same
run folder, or let each script default to its own auto-timestamped folder.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Resolve to ``DocsBasedSupport/eval/AttackGraph/runs`` regardless of cwd.
DEFAULT_RUNS_ROOT = Path(__file__).resolve().parent / "runs"


def resolve_run_dir(arg_value: str | Path | None, *, default_hint: str = "run") -> Path:
    """Return an existing run directory, creating it if necessary.

    * ``arg_value`` is the ``--run-dir`` CLI value. If absent, the run dir
      defaults to ``DEFAULT_RUNS_ROOT/<hint>-<UTC timestamp>``.
    * Relative paths are resolved against the current working directory so the
      caller can pass either ``eval/AttackGraph/runs/foo`` or an absolute path.
    """
    if arg_value is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
        run_dir = DEFAULT_RUNS_ROOT / f"{default_hint}-{timestamp}"
    else:
        run_dir = Path(arg_value).expanduser()
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def resolve_report_path(
    explicit_report_path: str | Path | None,
    run_dir: Path,
    default_filename: str,
) -> Path:
    """Pick the final report path: explicit override wins, otherwise default into run-dir."""
    if explicit_report_path is not None:
        path = Path(explicit_report_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    return run_dir / default_filename


def _format_config_lines(config: dict[str, Any]) -> str:
    lines: list[str] = []
    for key in sorted(config.keys()):
        value = config[key]
        rendered = _render_value(value)
        lines.append(f"- `{key}`: {rendered}")
    return "\n".join(lines)


def _render_value(value: Any) -> str:
    if value is None:
        return "`null`"
    if isinstance(value, bool):
        return f"`{str(value).lower()}`"
    if isinstance(value, (int, float)):
        return f"`{value}`"
    if isinstance(value, (list, tuple)):
        if not value:
            return "`[]`"
        return "`" + ", ".join(str(item) for item in value) + "`"
    return f"`{value}`"


def append_run_card(
    run_dir: Path,
    *,
    script: str,
    config: dict[str, Any],
    extra_md: str = "",
    output_files: list[Path] | None = None,
) -> Path:
    """Append a section to ``run_dir/RUN.md`` recording this script invocation."""
    card_path = run_dir / "RUN.md"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    if not card_path.exists():
        card_path.write_text(
            f"# AttackGraph run: `{run_dir.name}`\n\n"
            "This folder collects the outputs of one experiment over the MITRE ATT&CK\n"
            "knowledge graph. Each section below records a script that was run into\n"
            "this folder, including parameters and the files it produced. The folder\n"
            "is self-contained: copy / archive / commit it to keep the experiment\n"
            "reproducible.\n\n",
            encoding="utf-8",
        )
    section_lines = [
        f"## {script}",
        f"- `timestamp_utc`: `{now}`",
        _format_config_lines(config),
    ]
    if output_files:
        formatted = ", ".join(f"`{path.name}`" for path in output_files)
        section_lines.append(f"- `outputs`: {formatted}")
    section = "\n".join(section_lines)
    if extra_md:
        section += "\n\n" + extra_md.strip()
    with card_path.open("a", encoding="utf-8") as fh:
        fh.write("\n" + section + "\n")
    return card_path
