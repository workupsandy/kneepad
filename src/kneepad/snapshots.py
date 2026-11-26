"""Safety copies taken before a destructive command runs.

Two mechanisms:

* File snapshots copy the paths a command is about to delete into
  ``$KNEEPAD_HOME/snapshots/<id>/``.
* Git snapshots record the repository state in refs under ``refs/kneepad/<id>/``
  so uncommitted work and deleted branches stay reachable. They never touch the
  working tree.

Every git call disables ``core.fsmonitor``: a hostile repository could otherwise
use it to run a program of its choosing when Kneepad inspects the repo.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from .util import ensure_private_dir, now_iso, kneepad_home


class SnapshotError(Exception):
    """A snapshot could not be taken. The caller must not let the command run unattended."""


@dataclass
class SnapshotPlan:
    kind: str  # files | git-stash | git-branch | git-clean
    cwd: str
    paths: List[str] = field(default_factory=list)
    repo: str = ""
    branches: List[str] = field(default_factory=list)
    est_bytes: int = 0
    rule_id: str = ""


def git(cwd: str, *args: str, timeout: int = 10) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    return subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-C", cwd, *args],
        capture_output=True, text=True, timeout=timeout, env=env,
    )


def git_toplevel(cwd: str) -> Optional[str]:
    try:
        r = git(cwd, "rev-parse", "--show-toplevel")
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip() or None


def estimate_size(paths: List[str], max_bytes: int, max_files: int) -> Tuple[int, int, bool]:
    """Return (bytes, files, exceeded). Stops early once a limit is crossed."""
    total = files = 0
    stack = list(paths)
    while stack:
        p = stack.pop()
        try:
            st = os.lstat(p)
        except OSError:
            continue
        files += 1
        if stat.S_ISREG(st.st_mode):
            total += st.st_size
        if total > max_bytes or files > max_files:
            return total, files, True
        if stat.S_ISDIR(st.st_mode):
            try:
                with os.scandir(p) as it:
                    for e in it:
                        stack.append(e.path)
            except OSError:
                continue
    return total, files, False


def git_clean_dry_run_args(tokens: List[str]) -> List[str]:
    """Turn the arguments of ``git clean -fd...`` into those of a dry run."""
    out: List[str] = []
    for t in tokens:
        if t.startswith("--"):
            if t in ("--force", "--interactive", "--dry-run"):
                continue
            out.append(t)
        elif t.startswith("-") and len(t) > 1:
            kept = "".join(ch for ch in t[1:] if ch not in "fin")
            if kept:
                out.append("-" + kept)
        else:
            out.append(t)
    return ["clean", "-n", *out]


def list_git_clean_paths(cwd: str, tokens: List[str]) -> List[str]:
    """Absolute paths that ``git clean`` with these arguments would delete."""
    try:
        r = git(cwd, *git_clean_dry_run_args(tokens))
    except (OSError, subprocess.SubprocessError) as exc:
        raise SnapshotError(f"git clean dry run failed: {exc}")
    if r.returncode != 0:
        raise SnapshotError("git clean dry run failed: " + (r.stderr.strip() or "unknown error"))
    paths: List[str] = []
    for line in r.stdout.splitlines():
        if line.startswith("Would remove "):
            rel = line[len("Would remove "):]
            if rel.startswith('"'):
                raise SnapshotError("git clean lists a path with special characters that cannot be snapshotted safely")
            paths.append(os.path.normpath(os.path.join(cwd, rel)))
    return paths


class SnapshotStore:
    def __init__(self, home: Optional[str] = None) -> None:
        self.home = home or kneepad_home()
        self.root = os.path.join(self.home, "snapshots")

    # ---- creation ------------------------------------------------------
    def _new_id(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)

    def create(self, plan: SnapshotPlan) -> dict:
        ensure_private_dir(self.home)
        ensure_private_dir(self.root)
        sid = self._new_id()
        sdir = os.path.join(self.root, sid)
        os.makedirs(sdir, mode=0o700)
        manifest = {"id": sid, "created": now_iso(), "cwd": plan.cwd, "kind": plan.kind, "rule": plan.rule_id}
        try:
            if plan.kind in ("files", "git-clean"):
                manifest["items"] = self._copy_files(sdir, plan.paths)
            elif plan.kind == "git-stash":
                manifest.update(self._git_stash(sid, plan))
            elif plan.kind == "git-branch":
                manifest.update(self._git_branches(sid, plan))
            else:
                raise SnapshotError(f"unknown snapshot kind {plan.kind!r}")
            with open(os.path.join(sdir, "manifest.json"), "w", encoding="utf-8") as fh:
                json.dump(manifest, fh, indent=2, sort_keys=True)
        except Exception as exc:
            shutil.rmtree(sdir, ignore_errors=True)
            if isinstance(exc, SnapshotError):
                raise
            raise SnapshotError(f"snapshot failed: {exc}") from exc
        return manifest

    def _copy_files(self, sdir: str, paths: List[str]) -> List[dict]:
        items: List[dict] = []
        for idx, src in enumerate(paths):
            try:
                st = os.lstat(src)
            except FileNotFoundError:
                continue
            dest_rel = os.path.join("files", str(idx), os.path.basename(src.rstrip("/")) or "root")
            dest = os.path.join(sdir, dest_rel)
            os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
            if stat.S_ISLNK(st.st_mode):
                try:
                    os.symlink(os.readlink(src), dest)
                except OSError as exc:  # Windows needs a privilege to create symlinks
                    raise SnapshotError(f"cannot record symlink {src}: {exc}") from exc
                kind = "symlink"
            elif stat.S_ISDIR(st.st_mode):
                shutil.copytree(src, dest, symlinks=True, ignore_dangling_symlinks=True,
                                ignore=_skip_special, copy_function=shutil.copy2)
                kind = "dir"
            elif stat.S_ISREG(st.st_mode):
                shutil.copy2(src, dest)
                kind = "file"
            else:
                continue
            items.append({"orig": src, "stored": dest_rel, "type": kind})
        return items

    def _git_stash(self, sid: str, plan: SnapshotPlan) -> dict:
        top = plan.repo or git_toplevel(plan.cwd)
        if not top:
            raise SnapshotError("not inside a git repository")
        refs: List[str] = []
        head = git(top, "rev-parse", "--verify", "-q", "HEAD")
        head_sha = head.stdout.strip() if head.returncode == 0 else ""
        stash_sha = ""
        if head_sha:
            r = git(top, "stash", "create")
            if r.returncode != 0:
                raise SnapshotError("git stash create failed: " + r.stderr.strip())
            stash_sha = r.stdout.strip()
            u = git(top, "update-ref", f"refs/kneepad/{sid}/head", head_sha)
            if u.returncode != 0:
                raise SnapshotError("could not record HEAD: " + u.stderr.strip())
            refs.append(f"refs/kneepad/{sid}/head")
        if stash_sha:
            u = git(top, "update-ref", f"refs/kneepad/{sid}/stash", stash_sha)
            if u.returncode != 0:
                raise SnapshotError("could not record stash: " + u.stderr.strip())
            refs.append(f"refs/kneepad/{sid}/stash")
        return {"repo": top, "head": head_sha, "stash": stash_sha, "refs": refs}

    def _git_branches(self, sid: str, plan: SnapshotPlan) -> dict:
        top = plan.repo or git_toplevel(plan.cwd)
        if not top:
            raise SnapshotError("not inside a git repository")
        branches = []
        refs = []
        for name in plan.branches:
            r = git(top, "rev-parse", "--verify", "-q", f"refs/heads/{name}")
            if r.returncode != 0:
                continue  # branch does not exist: the delete will simply fail
            sha = r.stdout.strip()
            ref = f"refs/kneepad/{sid}/branch/{name}"
            u = git(top, "update-ref", ref, sha)
            if u.returncode != 0:
                raise SnapshotError(f"could not record branch {name}: {u.stderr.strip()}")
            branches.append({"name": name, "sha": sha})
            refs.append(ref)
        return {"repo": top, "branches": branches, "refs": refs}

    # ---- queries -------------------------------------------------------
    def list(self) -> List[dict]:
        out: List[dict] = []
        if not os.path.isdir(self.root):
            return out
        for name in sorted(os.listdir(self.root)):
            m = self.get(name)
            if m:
                out.append(m)
        return out

    def get(self, sid: str) -> Optional[dict]:
        if not sid or "/" in sid or sid.startswith("."):
            return None
        p = os.path.join(self.root, sid, "manifest.json")
        try:
            with open(p, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None

    # ---- restore -------------------------------------------------------
    def restore(self, sid: str, force: bool = False, to: Optional[str] = None, apply: bool = False) -> List[str]:
        m = self.get(sid)
        if not m:
            raise SnapshotError(f"no such snapshot: {sid}")
        msgs: List[str] = []
        kind = m["kind"]
        if kind in ("files", "git-clean"):
            sdir = os.path.join(self.root, sid)
            for it in m.get("items", []):
                src = os.path.join(sdir, it["stored"])
                dest = os.path.join(to, os.path.basename(it["orig"])) if to else it["orig"]
                if os.path.lexists(dest):
                    if not force:
                        msgs.append(f"skipped (exists, use --force): {dest}")
                        continue
                    aside = f"{dest}.kneepad-before-restore-{int(time.time())}"
                    os.rename(dest, aside)
                    msgs.append(f"moved existing to {aside}")
                os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
                if it["type"] == "symlink":
                    os.symlink(os.readlink(src), dest)
                elif it["type"] == "dir":
                    shutil.copytree(src, dest, symlinks=True, copy_function=shutil.copy2)
                else:
                    shutil.copy2(src, dest)
                msgs.append(f"restored: {dest}")
        elif kind == "git-branch":
            repo = m["repo"]
            for b in m.get("branches", []):
                exists = git(repo, "rev-parse", "--verify", "-q", f"refs/heads/{b['name']}").returncode == 0
                if exists:
                    msgs.append(f"branch {b['name']} already exists; skipped")
                    continue
                r = git(repo, "branch", b["name"], b["sha"])
                msgs.append(f"restored branch {b['name']} at {b['sha'][:10]}" if r.returncode == 0
                            else f"could not restore {b['name']}: {r.stderr.strip()}")
        elif kind == "git-stash":
            repo, head, stash = m["repo"], m.get("head", ""), m.get("stash", "")
            if stash:
                if apply:
                    r = git(repo, "stash", "apply", "--index", stash)
                    msgs.append("applied saved changes" if r.returncode == 0
                                else "could not apply cleanly: " + r.stderr.strip())
                else:
                    msgs.append(f"to restore the saved uncommitted changes: git -C {repo} stash apply --index {stash}")
            else:
                msgs.append("no uncommitted changes were present when this snapshot was taken")
            if head:
                msgs.append(f"HEAD was {head}; to return to it: git -C {repo} reset --hard {head}")
        return msgs

    # ---- pruning -------------------------------------------------------
    def delete(self, sid: str) -> None:
        m = self.get(sid)
        if m and m.get("repo"):
            for ref in m.get("refs", []):
                try:
                    git(m["repo"], "update-ref", "-d", ref)
                except (OSError, subprocess.SubprocessError):
                    pass
        shutil.rmtree(os.path.join(self.root, sid), ignore_errors=True)

    def prune(self, older_than_days: Optional[float] = None, max_total_mb: Optional[int] = None) -> List[str]:
        removed: List[str] = []
        snaps = self.list()
        now = time.time()
        if older_than_days is not None:
            for m in snaps:
                try:
                    created = datetime.strptime(m["created"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc).timestamp()
                except (KeyError, ValueError):
                    continue
                if now - created > older_than_days * 86400:
                    self.delete(m["id"])
                    removed.append(m["id"])
            snaps = [m for m in snaps if m["id"] not in removed]
        if max_total_mb is not None:
            def size(sid: str) -> int:
                tot = 0
                for dp, _dn, fn in os.walk(os.path.join(self.root, sid)):
                    for f in fn:
                        try:
                            tot += os.lstat(os.path.join(dp, f)).st_size
                        except OSError:
                            pass
                return tot
            sizes = {m["id"]: size(m["id"]) for m in snaps}
            total = sum(sizes.values())
            for m in snaps:  # oldest first (ids sort by time)
                if total <= max_total_mb * 1024 * 1024:
                    break
                total -= sizes[m["id"]]
                self.delete(m["id"])
                removed.append(m["id"])
        return removed


def _skip_special(directory: str, names: List[str]) -> List[str]:
    skipped = []
    for n in names:
        try:
            mode = os.lstat(os.path.join(directory, n)).st_mode
        except OSError:
            skipped.append(n)
            continue
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
            skipped.append(n)
    return skipped
