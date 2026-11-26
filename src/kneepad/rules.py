"""Footgun database: loading, strict validation, and the matching DSL."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from typing import Dict, List

from .argvtools import ParsedArgv, sub_matches

SEVERITIES = ("low", "medium", "high", "critical")
ACTIONS = ("allow", "ask", "deny")
ACTION_RANK = {"allow": 0, "ask": 1, "deny": 2}
SNAPSHOT_KINDS = ("none", "files", "git-stash", "git-branch", "git-clean")
REVERSIBLE = ("yes", "partial", "no")

MATCH_KEYS = {
    "cmd", "cmd_re", "sub", "sub_icase", "pos_any", "pos_icase", "flags_any", "flags_all",
    "flags_none", "flag_values", "args_regex", "args_regex_none", "tokens_any", "raw_regex",
}
RULE_ID = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


@dataclass
class Rule:
    id: str
    title: str
    family: str
    severity: str
    action: str
    why: str
    safer: str
    recipe: str = ""
    reversible: str = "no"
    snapshot: str = "none"
    refs: List[str] = field(default_factory=list)
    match: dict = field(default_factory=dict)
    examples: Dict[str, List[str]] = field(default_factory=dict)
    virtual: bool = False
    no_override: bool = False


def _validate_regex(pattern: str, where: str, errors: List[str]) -> None:
    try:
        re.compile(pattern)
    except re.error as exc:
        errors.append(f"{where}: invalid regex {pattern!r}: {exc}")


def validate_rule_dict(d: dict, seen: set) -> List[str]:
    """Return a list of error strings for one raw rule table (empty when valid)."""
    errors: List[str] = []
    rid = d.get("id", "<missing id>")
    pre = f"rule {rid}"
    for key in ("id", "title", "family", "severity", "action", "why", "safer"):
        if not isinstance(d.get(key), str) or not d.get(key, "").strip():
            errors.append(f"{pre}: missing or empty string field {key!r}")
    if errors and "id" not in d:
        return errors
    if isinstance(d.get("id"), str):
        if not RULE_ID.match(d["id"]):
            errors.append(f"{pre}: id must be kebab-case")
        if d["id"] in seen:
            errors.append(f"{pre}: duplicate id")
        seen.add(d["id"])
    if d.get("severity") not in SEVERITIES:
        errors.append(f"{pre}: severity must be one of {SEVERITIES}")
    if d.get("action") not in ACTIONS:
        errors.append(f"{pre}: action must be one of {ACTIONS}")
    if d.get("snapshot", "none") not in SNAPSHOT_KINDS:
        errors.append(f"{pre}: snapshot must be one of {SNAPSHOT_KINDS}")
    if d.get("reversible", "no") not in REVERSIBLE:
        errors.append(f"{pre}: reversible must be one of {REVERSIBLE}")
    if d.get("action") == "allow" and d.get("snapshot", "none") == "none" and d.get("severity") in ("high", "critical"):
        errors.append(f"{pre}: a high or critical rule cannot simply allow without a snapshot")
    if d.get("severity") == "critical" and d.get("action") != "deny" and not d.get("virtual"):
        errors.append(f"{pre}: critical rules must deny")
    for url in d.get("refs", []):
        if not isinstance(url, str) or not url.startswith("https://"):
            errors.append(f"{pre}: refs must be https URLs")
    if d.get("virtual"):
        return errors
    m = d.get("match")
    if not isinstance(m, dict) or not m:
        errors.append(f"{pre}: needs a non-empty [rule.match] table (or virtual = true)")
        return errors
    unknown = set(m) - MATCH_KEYS
    if unknown:
        errors.append(f"{pre}: unknown match keys {sorted(unknown)}")
    if "raw_regex" not in m and not ({"cmd", "cmd_re"} & set(m)):
        errors.append(f"{pre}: match needs cmd, cmd_re or raw_regex so it cannot fire on every command")
    for key in ("args_regex", "args_regex_none", "raw_regex", "cmd_re"):
        if key in m:
            vals = m[key] if isinstance(m[key], list) else [m[key]]
            for v in vals:
                if not isinstance(v, str):
                    errors.append(f"{pre}: {key} must be a string")
                else:
                    _validate_regex(v, f"{pre}.{key}", errors)
    if "sub" in m:
        sub = m["sub"]
        if not isinstance(sub, list) or not all(isinstance(a, list) and a and all(isinstance(x, str) for x in a) for a in sub):
            errors.append(f"{pre}: sub must be a list of non-empty string lists")
        else:
            for alts in sub:
                for a in alts:
                    if a.startswith("re:"):
                        _validate_regex(a[3:], f"{pre}.sub", errors)
    for key in ("cmd", "pos_any", "flags_any", "flags_all", "flags_none", "tokens_any"):
        if key in m and not (isinstance(m[key], list) and all(isinstance(x, str) for x in m[key])):
            errors.append(f"{pre}: {key} must be a list of strings")
    if "flag_values" in m:
        fv = m["flag_values"]
        if not isinstance(fv, dict) or not all(isinstance(v, list) for v in fv.values()):
            errors.append(f"{pre}: flag_values must map flag -> list of values")
    ex = d.get("examples", {})
    if not (isinstance(ex.get("match"), list) and ex["match"]):
        errors.append(f"{pre}: examples.match needs at least one command")
    if not (isinstance(ex.get("no_match"), list) and ex["no_match"]):
        errors.append(f"{pre}: examples.no_match needs at least one command")
    return errors


def load_rules_text(text: str) -> List[Rule]:
    data = tomllib.loads(text)
    raw_rules = data.get("rule", [])
    seen: set = set()
    errors: List[str] = []
    for d in raw_rules:
        errors.extend(validate_rule_dict(d, seen))
    if errors:
        raise ValueError("invalid footgun database:\n  " + "\n  ".join(errors))
    rules: List[Rule] = []
    for d in raw_rules:
        rules.append(
            Rule(
                id=d["id"], title=d["title"], family=d["family"], severity=d["severity"],
                action=d["action"], why=d["why"].strip(), safer=d["safer"].strip(),
                recipe=d.get("recipe", "").strip(), reversible=d.get("reversible", "no"),
                snapshot=d.get("snapshot", "none"), refs=list(d.get("refs", [])),
                match=dict(d.get("match", {})), examples=dict(d.get("examples", {})),
                virtual=bool(d.get("virtual", False)), no_override=bool(d.get("no_override", False)),
            )
        )
    return rules


def load_default_rules() -> List[Rule]:
    base = resources.files("kneepad").joinpath("data")
    names = sorted(p.name for p in base.iterdir() if p.name.startswith("footguns") and p.name.endswith(".toml"))
    names.sort(key=lambda n: (n != "footguns.toml", n))  # core file first
    text = "\n\n".join(base.joinpath(n).read_text(encoding="utf-8") for n in names)
    return load_rules_text(text)


REGEX_INPUT_CAP = 16384


def bounded_args(argstr: str) -> str:
    """Bound the text regexes run on so a hostile or enormous command cannot stall the hook.

    Longer inputs keep their head and tail; the engine separately raises an "uninspectable" finding.
    """
    if len(argstr) <= REGEX_INPUT_CAP:
        return argstr
    half = REGEX_INPUT_CAP // 2
    return argstr[:half] + " " + argstr[-half:]


def match_argv(rule: Rule, pa: ParsedArgv) -> bool:
    """Evaluate the argv part of a rule's match table against one command."""
    m = rule.match
    if "cmd" in m and pa.name not in m["cmd"]:
        return False
    if "cmd_re" in m and not re.fullmatch(m["cmd_re"], pa.name):
        return False
    if "cmd" not in m and "cmd_re" not in m:
        return False
    if "sub" in m and not sub_matches(pa, m["sub"], bool(m.get("sub_icase"))):
        return False
    if "pos_any" in m:
        icase = bool(m.get("pos_icase"))
        want = [x.lower() for x in m["pos_any"]] if icase else m["pos_any"]
        have = [p.lower() for p in pa.pos] if icase else pa.pos
        if not any(p in want for p in have):
            return False
    if "flags_any" in m and not any(f in pa.flags for f in m["flags_any"]):
        return False
    if "flags_all" in m and not all(f in pa.flags for f in m["flags_all"]):
        return False
    if "flags_none" in m and any(f in pa.flags for f in m["flags_none"]):
        return False
    if "flag_values" in m:
        ok = False
        for flag, values in m["flag_values"].items():
            got = pa.flag_values.get(flag)
            if got is not None and got.lower() in [v.lower() for v in values]:
                ok = True
        if not ok:
            return False
    text = bounded_args(pa.argstr) if ("args_regex" in m or "args_regex_none" in m) else ""
    if "args_regex" in m and not re.search(m["args_regex"], text):
        return False
    if "args_regex_none" in m and re.search(m["args_regex_none"], text):
        return False
    if "tokens_any" in m and not any(t in pa.tokens for t in m["tokens_any"]):
        return False
    return True
