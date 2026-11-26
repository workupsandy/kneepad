"""Turn parsed shell words into a normalised, matchable argument view."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from .shellparse import RESERVED, Word, is_assignment

SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "csh", "tcsh"})
INTERPRETERS = frozenset({"python", "node", "ruby", "perl", "php", "deno", "bun"})

_SUDO_VAL = {
    "-u", "-g", "-h", "-p", "-C", "-D", "-R", "-r", "-t", "-T", "-U",
    "--user", "--group", "--host", "--prompt", "--close-from", "--chdir", "--chroot",
    "--role", "--type", "--command-timeout", "--other-user",
}
_XARGS_VAL = {
    "-n", "--max-args", "-L", "--max-lines", "-P", "--max-procs", "-I", "-s", "--max-chars",
    "-d", "--delimiter", "-E", "-a", "--arg-file", "--process-slot-var",
}
# name -> (options that take a value, number of leading positionals to skip)
_WRAPPERS: Dict[str, Tuple[Set[str], int]] = {
    "sudo": (_SUDO_VAL, 0),
    "doas": ({"-u", "-C"}, 0),
    "nice": ({"-n", "--adjustment"}, 0),
    "ionice": ({"-c", "-n", "-p", "-P", "-u", "--class", "--classdata"}, 0),
    "nohup": (set(), 0),
    "time": ({"-f", "--format", "-o", "--output"}, 0),
    "stdbuf": ({"-i", "-o", "-e", "--input", "--output", "--error"}, 0),
    "setsid": (set(), 0),
    "timeout": ({"-s", "--signal", "-k", "--kill-after"}, 1),
    "command": (set(), 0),
    "builtin": (set(), 0),
    "exec": ({"-a"}, 0),
    "xargs": (_XARGS_VAL, 0),
    "unbuffer": (set(), 0),
    "npx": ({"-p", "--package", "-c", "--call"}, 0),
    "pnpx": (set(), 0),
    "bunx": (set(), 0),
}

# Options that consume the next token, per command. Keeps values out of positionals.
VALUE_FLAGS: Dict[str, Set[str]] = {
    "git": {"-C", "-c", "-b", "-B", "-m", "-F", "--git-dir", "--work-tree", "--namespace",
            "--message", "--file", "--author", "--date", "-o", "--push-option", "--repo"},
    "kubectl": {"-n", "--namespace", "--context", "--kubeconfig", "-s", "--server", "--cluster",
                "--user", "--as", "--as-group", "--token", "-l", "--selector", "-f", "--filename",
                "-k", "--kustomize", "-o", "--output", "--field-selector", "--timeout",
                "--grace-period", "--request-timeout", "-c", "--container", "--cascade"},
    "helm": {"-n", "--namespace", "--kube-context", "--kubeconfig", "-f", "--values", "--set",
             "--version", "--timeout"},
    "terraform": {"-var", "-var-file", "-target", "-state", "-backend-config", "-lock-timeout",
                  "-parallelism", "-replace", "-out"},
    "tofu": {"-var", "-var-file", "-target", "-state", "-backend-config", "-lock-timeout",
             "-parallelism", "-replace", "-out"},
    "aws": {"--profile", "--region", "--endpoint-url", "--output", "--query", "--cli-input-json",
            "--ca-bundle", "--cli-read-timeout", "--cli-connect-timeout", "--color"},
    "gcloud": {"--project", "--account", "--format", "--configuration", "--impersonate-service-account"},
    "az": {"--subscription", "--output", "-o", "--query", "--resource-group", "-g", "--name", "-n"},
    # docker, podman and docker-compose reuse the same letters with different meanings per
    # subcommand (-f is a compose file option but also "force"), so they are scoped below.
    "docker": {"-H", "--host", "--context", "-c", "--config", "-l", "--log-level"},
    "podman": {"-H", "--host", "--context", "-c", "--config", "-l", "--log-level"},
    "docker-compose": {"-f", "--file", "-p", "--project-name", "--profile", "--env-file",
                       "--project-directory", "-H", "--host", "--context"},
    "curl": {"-X", "--request", "-H", "--header", "-d", "--data", "--data-raw", "--data-binary",
             "--data-urlencode", "-F", "--form", "-o", "--output", "-u", "--user", "-A",
             "--user-agent", "-e", "--referer", "-T", "--upload-file", "-w", "--write-out",
             "--connect-timeout", "-m", "--max-time", "-x", "--proxy", "--cacert", "--cert",
             "--key", "-b", "--cookie", "-c", "--cookie-jar", "-K", "--config", "--url"},
    "wget": {"-O", "-o", "-P", "-e", "--post-data", "--post-file", "--body-data", "--body-file",
             "--header", "--user", "--password", "-t", "-T", "-w", "-i", "-a"},
    "rsync": {"-e", "--rsh", "--exclude", "--include", "--exclude-from", "--include-from", "-f",
              "--filter", "--port", "--bwlimit", "--timeout", "--max-size", "--min-size"},
    "rclone": {"--config", "--transfers", "--checkers", "--exclude", "--include", "--filter",
               "--bwlimit", "--log-file", "--backup-dir"},
    "redis-cli": {"-h", "-p", "-a", "-n", "-u", "-s", "--user", "--pass"},
    "valkey-cli": {"-h", "-p", "-a", "-n", "-u", "-s", "--user", "--pass"},
    "gh": {"-R", "--repo"},
    "heroku": {"-a", "--app", "-r", "--remote", "--confirm"},
    "fly": {"-a", "--app", "-c", "--config", "-o", "--org"},
    "flyctl": {"-a", "--app", "-c", "--config", "-o", "--org"},
    "ssh": {"-i", "-l", "-p", "-o", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-e", "-m", "-O",
            "-Q", "-S", "-W", "-w", "-E", "-B"},
    "vercel": {"--token", "-t", "--scope", "-S", "-A"},
    "supabase": {"--workdir", "--project-ref"},
    "prisma": {"--schema", "--name", "--url"},
    "kill": {"-s", "-n"},
    "cp": {"-t", "--target-directory", "-S", "--suffix"},
    "mv": {"-t", "--target-directory", "-S", "--suffix"},
    "install": {"-t", "--target-directory", "-m", "--mode", "-o", "--owner", "-g", "--group"},
    "ln": {"-t", "--target-directory", "-S", "--suffix"},
    "psql": {"-c", "--command", "-f", "--file", "-d", "--dbname", "-h", "--host", "-p", "--port", "-U", "--username",
             "-v", "--set", "--variable", "-o", "--output", "-L", "--log-file", "-F", "-R", "-P", "-T", "-l"},
    "mysql": {"-e", "--execute", "-h", "--host", "-u", "--user", "-P", "--port", "-D", "--database", "-S", "--socket"},
    "mariadb": {"-e", "--execute", "-h", "--host", "-u", "--user", "-P", "--port", "-D", "--database", "-S", "--socket"},
    "mongosh": {"--eval", "--host", "--port", "-u", "--username", "-p", "--password", "--authenticationDatabase"},
    "find": set(),
}

# Commands whose value-taking options differ before/after the subcommand.
_SCOPED = frozenset({"docker", "podman", "docker-compose"})
_COMPOSE_VALS = {"-f", "--file", "-p", "--project-name", "--profile", "--env-file", "--project-directory"}
_SUB_VALUE_FLAGS: Dict[Tuple[str, str], Set[str]] = {
    ("docker", "compose"): _COMPOSE_VALS,
    ("podman", "compose"): _COMPOSE_VALS,
    ("docker", "exec"): {"-e", "--env", "-u", "--user", "-w", "--workdir", "--env-file", "--detach-keys"},
    ("podman", "exec"): {"-e", "--env", "-u", "--user", "-w", "--workdir", "--env-file", "--detach-keys"},
    ("docker", "run"): {"-e", "--env", "-u", "--user", "-w", "--workdir", "--env-file", "-v", "--volume", "-p", "--publish",
                        "--name", "--network", "--net", "-l", "--label", "--entrypoint", "-m", "--memory", "--restart",
                        "--mount", "-h", "--hostname", "--cpus", "--platform"},
    ("podman", "run"): {"-e", "--env", "-u", "--user", "-w", "--workdir", "--env-file", "-v", "--volume", "-p", "--publish",
                        "--name", "--network", "--net", "-l", "--label", "--entrypoint", "-m", "--memory", "--restart",
                        "--mount", "-h", "--hostname", "--cpus", "--platform"},
    ("docker", "build"): {"-t", "--tag", "-f", "--file", "--build-arg", "--target", "--platform"},
    ("docker", "logs"): {"--tail", "-n", "--since", "--until"},
}

_CLUSTER = re.compile(r"^[A-Za-z0-9]+$")


def cmd_name(text: str) -> str:
    """Canonical lowercase command name from argv[0]."""
    base = os.path.basename(text.rstrip("/")) or text
    base = base.lower()
    if base.endswith(".exe"):
        base = base[:-4]
    if re.fullmatch(r"python[0-9.]*", base):
        return "python"
    if base in ("nodejs",):
        return "node"
    return base


@dataclass
class ParsedArgv:
    name: str
    words: List[Word]
    tokens: List[str]
    flags: Set[str] = field(default_factory=set)
    flag_values: Dict[str, str] = field(default_factory=dict)
    pos: List[str] = field(default_factory=list)
    pos_words: List[Word] = field(default_factory=list)
    pos_idx: List[int] = field(default_factory=list)  # index into .words of each positional
    argstr: str = ""
    meta: dict = field(default_factory=dict)
    raw0: str = ""


def strip_wrappers(words: List[Word]) -> Tuple[List[Word], dict]:
    """Remove env assignments, reserved words and wrapper commands (sudo, env, ...)."""
    i, n = 0, len(words)
    meta = {"xargs": False, "sudo": False, "query": False}
    guard = 0
    while i < n and guard < 40:
        guard += 1
        t = words[i].text
        if t == "" or t in RESERVED:
            i += 1
            continue
        if is_assignment(t):
            i += 1
            continue
        name = cmd_name(t)
        if name == "env":
            i += 1
            while i < n:
                tt = words[i].text
                if tt == "--":
                    i += 1
                    break
                if is_assignment(tt):
                    i += 1
                    continue
                if tt.startswith("-") and len(tt) > 1:
                    i += 1
                    if tt in ("-u", "--unset", "-C", "--chdir", "-S", "--split-string") and i < n:
                        i += 1
                    continue
                break
            continue
        spec = _WRAPPERS.get(name)
        if spec is None:
            break
        val_opts, npos = spec
        i += 1
        if name == "command":
            while i < n and words[i].text.startswith("-") and words[i].text != "--":
                if words[i].text in ("-v", "-V"):
                    meta["query"] = True
                i += 1
            if i < n and words[i].text == "--":
                i += 1
            continue
        while i < n:
            tt = words[i].text
            if tt == "--":
                i += 1
                break
            if tt.startswith("-") and len(tt) > 1:
                i += 1
                if tt in val_opts and i < n:
                    i += 1
                continue
            break
        i += npos
        if name in ("sudo", "doas"):
            meta["sudo"] = True
        if name == "xargs":
            meta["xargs"] = True
    return words[i:], meta


def parse_argv(words: List[Word], meta: dict | None = None) -> ParsedArgv | None:
    if not words:
        return None
    name = cmd_name(words[0].text)
    tokens = [w.text for w in words[1:]]
    pa = ParsedArgv(name=name, words=words, tokens=tokens, meta=meta or {}, raw0=words[0].text)
    base_vals = VALUE_FLAGS.get(name, set())
    vals = base_vals
    i, after_dd = 0, False
    while i < len(tokens):
        t, w = tokens[i], words[i + 1]
        if after_dd:
            pa.pos.append(t)
            pa.pos_words.append(w)
            pa.pos_idx.append(i + 1)
            i += 1
            continue
        if t == "--":
            after_dd = True
            i += 1
            continue
        if t.startswith("--") and len(t) > 2:
            if "=" in t:
                nm, val = t.split("=", 1)
                pa.flags.add(nm)
                pa.flag_values[nm] = val
            else:
                pa.flags.add(t)
                if t in vals and i + 1 < len(tokens):
                    pa.flag_values[t] = tokens[i + 1]
                    i += 1
            i += 1
            continue
        if t.startswith("-") and len(t) > 1:
            body = t[1:]
            if _CLUSTER.match(body):
                for ch in body:
                    pa.flags.add("-" + ch)
                if len(body) > 1:
                    pa.flags.add(t)
                last = "-" + body[-1]
                if (t in vals or last in vals) and i + 1 < len(tokens):
                    pa.flag_values[t if t in vals else last] = tokens[i + 1]
                    i += 1
            else:
                nm = t.split("=", 1)[0]
                pa.flags.add(nm)
                if "=" in t:
                    pa.flag_values[nm] = t.split("=", 1)[1]
                elif t in vals and i + 1 < len(tokens):
                    pa.flag_values[t] = tokens[i + 1]
                    i += 1
            i += 1
            continue
        pa.pos.append(t)
        pa.pos_words.append(w)
        pa.pos_idx.append(i + 1)
        if name in _SCOPED:
            # Value-taking options change meaning per subcommand, so rescope as positionals appear:
            # global options -> subcommand options -> none (what follows belongs to the container command).
            n = len(pa.pos)
            if n == 1:
                vals = set() if name == "docker-compose" else _SUB_VALUE_FLAGS.get((name, t), set())
            elif n == 2:
                vals = set()
        i += 1
    pa.argstr = " ".join(tokens)
    return pa


def alt_match(token: str, alts: List[str], icase: bool = False) -> bool:
    for a in alts:
        if a.startswith("re:"):
            if re.search(a[3:], token, re.I if icase else 0):
                return True
        elif (a.lower() == token.lower()) if icase else (a == token):
            return True
    return False


def sub_matches(pa: ParsedArgv, sub: List[List[str]], icase: bool = False) -> bool:
    if len(pa.pos) < len(sub):
        return False
    return all(alt_match(p, alts, icase) for p, alts in zip(pa.pos, sub))
