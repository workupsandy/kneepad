"""Configuration loading.

Two layers:

* User config at ``$KNEEPAD_HOME/config.toml`` (default ``~/.kneepad/config.toml``).
  This is trusted. It may relax or disable rules.
* Project config at ``.kneepad.toml`` found by walking up from the working
  directory. A repository is untrusted input, because an agent works inside
  repositories it did not write. Project config can therefore only make Kneepad
  *stricter*. Any attempt to relax it is ignored and reported as a warning.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .rules import ACTION_RANK, ACTIONS
from .util import kneepad_home

DEFAULT_IGNORE_DIRS = frozenset(
    {
        "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
        ".venv", "venv", "dist", "build", ".next", ".nuxt", ".cache", ".gradle", ".parcel-cache",
        ".turbo", ".terraform", "coverage", ".eggs", ".sass-cache", ".angular",
    }
)

DEFAULT_PROD_MARKERS = [r"(?i)(?<![a-z0-9])(?:prod|production|prd)(?![a-z0-9])"]

USER_KEYS = {
    "mode", "disable_rules", "action_overrides", "allow_patterns", "protected_paths",
    "allow_write_paths", "prod_markers", "snapshot_max_mb", "snapshot_max_files",
    "snapshot_total_mb", "ignore_dirs", "protected_branches",
}
PROJECT_KEYS = {"protected_paths", "prod_markers", "escalate", "snapshot_max_mb", "protected_branches"}


@dataclass
class Config:
    mode: str = "enforce"
    disable_rules: Set[str] = field(default_factory=set)
    action_overrides: Dict[str, str] = field(default_factory=dict)
    escalations: Dict[str, str] = field(default_factory=dict)
    allow_patterns: List[str] = field(default_factory=list)
    protected_paths: List[str] = field(default_factory=list)
    allow_write_paths: List[str] = field(default_factory=list)
    prod_markers: List[str] = field(default_factory=lambda: list(DEFAULT_PROD_MARKERS))
    snapshot_max_mb: int = 200
    snapshot_max_files: int = 50000
    snapshot_total_mb: int = 2048
    ignore_dirs: Set[str] = field(default_factory=lambda: set(DEFAULT_IGNORE_DIRS))
    protected_branches: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)


def _read_toml(path: str, warnings: List[str]) -> Optional[dict]:
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except FileNotFoundError:
        return None
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as exc:
        warnings.append(f"{path}: could not be read ({exc}); ignored")
        return None


def _str_list(val, key: str, warnings: List[str], src: str) -> List[str]:
    if isinstance(val, list) and all(isinstance(x, str) for x in val):
        return list(val)
    warnings.append(f"{src}: {key} must be a list of strings; ignored")
    return []


def _apply_user(cfg: Config, data: dict, src: str) -> None:
    for key in data:
        if key not in USER_KEYS:
            cfg.warnings.append(f"{src}: unknown key {key!r} ignored")
    mode = data.get("mode")
    if mode is not None:
        if mode in ("enforce", "monitor"):
            cfg.mode = mode
        else:
            cfg.warnings.append(f"{src}: mode must be 'enforce' or 'monitor'; ignored")
    if "disable_rules" in data:
        cfg.disable_rules |= set(_str_list(data["disable_rules"], "disable_rules", cfg.warnings, src))
    if "action_overrides" in data:
        ov = data["action_overrides"]
        if isinstance(ov, dict):
            for rid, act in ov.items():
                if act in ACTIONS:
                    cfg.action_overrides[rid] = act
                else:
                    cfg.warnings.append(f"{src}: action_overrides[{rid}] must be one of {ACTIONS}; ignored")
        else:
            cfg.warnings.append(f"{src}: action_overrides must be a table; ignored")
    for key in ("allow_patterns", "protected_paths", "allow_write_paths", "prod_markers", "protected_branches"):
        if key in data:
            vals = _str_list(data[key], key, cfg.warnings, src)
            if key == "prod_markers":
                cfg.prod_markers.extend(vals)
            else:
                getattr(cfg, key).extend(vals)
    for key in ("snapshot_max_mb", "snapshot_max_files", "snapshot_total_mb"):
        if key in data:
            v = data[key]
            if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
                setattr(cfg, key, v)
            else:
                cfg.warnings.append(f"{src}: {key} must be a non-negative integer; ignored")
    if "ignore_dirs" in data:
        cfg.ignore_dirs |= set(_str_list(data["ignore_dirs"], "ignore_dirs", cfg.warnings, src))


def _apply_project(cfg: Config, data: dict, src: str) -> None:
    for key in data:
        if key not in PROJECT_KEYS:
            if key in USER_KEYS:
                cfg.warnings.append(
                    f"{src}: {key!r} would relax protection and is ignored. "
                    "Project config can only make Kneepad stricter; put relaxations in your user config."
                )
            else:
                cfg.warnings.append(f"{src}: unknown key {key!r} ignored")
    if "protected_paths" in data:
        cfg.protected_paths.extend(_str_list(data["protected_paths"], "protected_paths", cfg.warnings, src))
    if "prod_markers" in data:
        cfg.prod_markers.extend(_str_list(data["prod_markers"], "prod_markers", cfg.warnings, src))
    if "protected_branches" in data:
        cfg.protected_branches.extend(_str_list(data["protected_branches"], "protected_branches", cfg.warnings, src))
    if "escalate" in data:
        esc = data["escalate"]
        if isinstance(esc, dict):
            for rid, act in esc.items():
                if act in ("ask", "deny"):
                    cfg.escalations[rid] = act
                else:
                    cfg.warnings.append(f"{src}: escalate[{rid}] must be 'ask' or 'deny'; ignored")
        else:
            cfg.warnings.append(f"{src}: escalate must be a table; ignored")
    if "snapshot_max_mb" in data:
        v = data["snapshot_max_mb"]
        if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= cfg.snapshot_max_mb:
            cfg.snapshot_max_mb = v
        else:
            cfg.warnings.append(f"{src}: snapshot_max_mb may only be lowered; ignored")


def find_project_config(cwd: str) -> Optional[str]:
    d = os.path.abspath(cwd)
    while True:
        cand = os.path.join(d, ".kneepad.toml")
        if os.path.isfile(cand):
            return cand
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def load_config(cwd: Optional[str] = None, home: Optional[str] = None) -> Config:
    cfg = Config()
    base = home or kneepad_home()
    user_path = os.path.join(base, "config.toml")
    data = _read_toml(user_path, cfg.warnings)
    if data is not None:
        _apply_user(cfg, data, user_path)
        cfg.sources.append(user_path)
    env_mode = os.environ.get("KNEEPAD_MODE")
    if env_mode in ("enforce", "monitor"):
        cfg.mode = env_mode
    proj = find_project_config(cwd or os.getcwd())
    if proj:
        pdata = _read_toml(proj, cfg.warnings)
        if pdata is not None:
            _apply_project(cfg, pdata, proj)
            cfg.sources.append(proj)
    return cfg


def stronger(a: str, b: str) -> str:
    return a if ACTION_RANK[a] >= ACTION_RANK[b] else b
