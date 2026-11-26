# Contributing

The most valuable contribution is a new footgun: a command that has hurt you, expressed as a rule with examples.

## Add a rule

Hand-written rules live in `src/kneepad/data/footguns.toml`. The files `footguns_ext.toml`, `footguns_windows.toml` and `footguns_macos.toml` are generated: edit `tools/gen_rules.py` or `tools/gen_platform_rules.py` and rerun them (CI fails if the output is out of sync). Windows rules use `family = "windows"`: they are evaluated by the Windows pass, where the command name is lower-cased, `.exe` is stripped and PowerShell switches are lower-cased, and their regexes should start with `(?i)`.

To add a hand-written rule, edit `src/kneepad/data/footguns.toml` and append:

```toml
[[rule]]
id = "tool-thing-destroy"
title = "short description of the danger"
family = "kubernetes"          # see docs/FOOTGUNS.md for existing families
severity = "high"              # low | medium | high | critical
action = "ask"                 # ask | deny (critical non-virtual rules must be deny)
why = "What goes wrong, in one or two sentences."
safer = "What to do instead."
reversible = "no"              # yes | partial | no
[rule.match]
cmd = ["thing"]
sub = [["destroy"]]
flags_any = ["--force"]
[rule.examples]
match = ["thing destroy --force prod"]
no_match = ["thing list", "echo thing destroy --force"]
```

Match keys: `cmd`, `cmd_re`, `sub`, `pos_any`, `flags_any`, `flags_all`, `flags_none`, `flag_values`, `args_regex`, `tokens_any`, `raw_regex`. All conditions AND together. Use TOML literal strings (single quotes) for regexes.

Every rule needs at least one `match` and one `no_match` example. The suite runs them inside a real git repo.

## Check your work

```
python3 -m unittest discover -s tests
kneepad rules validate src/kneepad/data/footguns.toml
```

If your rule flags something that people run daily, add that command to `tests/corpus_benign.txt`. If it should stop something dangerous, add it to `tests/corpus_malicious.txt`. Entries are separated by a line containing only `---`.

## Principles

- Never print `allow` from the hook. Silence keeps the user's normal permission flow.
- Prefer `ask` unless the action is catastrophic and has no plausible legitimate use.
- Avoid rules that fire on read-only commands.
- Failing safe means answering `ask`, not crashing and not allowing.
- Keep it dependency-free.
