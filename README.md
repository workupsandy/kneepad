# Kneepad

A local safety layer for AI coding agents. It sits in front of the commands your agent runs, stops the ones that cannot be undone, takes a safety copy of the ones that can, and keeps a tamper-evident record of what happened.

Zero dependencies. Python 3.11+. Linux, macOS and Windows. Runs entirely on your machine. MIT licensed.

## What it does

- **Footgun database.** 253 rules (220 pattern rules plus 33 emitted by engine code) for the commands that ruin days: `rm -rf` on the wrong path, `git push --force` to main, `terraform destroy`, `DROP TABLE`, `kubectl delete ns`, `aws s3 rb --force`, `prisma migrate reset`, `curl | sh`, writes to `~/.ssh` and `.bashrc`, and more. Rules are pattern families (one rule covers every `delete`/`destroy`/`terminate` subcommand of a cloud CLI, for example), across about 570 named tools, including Windows and macOS tools. Count of rules is not coverage: more rules also means more false positives, so every rule must pass the benign corpus. Every rule ships with examples that the test suite executes.
- **Understands shell, not just text.** Quotes, `$(...)`, backticks, heredocs, pipes, `bash -c`, `eval`, `ssh host '...'`, `docker exec`, `kubectl exec --`, `sudo`/`env`/`nice` wrappers, `npx`/`poetry run`/`bundle exec`, and shell scripts the agent is about to run. `echo "rm -rf /"` is not flagged. `DIR=; rm -rf $DIR/` is.
- **Snapshots before risky-but-allowed actions.** Deleting untracked files, `git reset --hard`, `git clean`, `git branch -D` each take a copy first. Restore with `kneepad snapshots restore <id>`.
- **Hash-chained audit log.** Every decision that has a finding (anything other than a plain allow), and every `kneepad run` decision, is appended to a JSONL log where each entry commits to the previous one and is signed with a local key. Editing, deleting, reordering or inserting entries is detected by `kneepad verify`.
- **"Protected by Kneepad" badge.** `kneepad badge` writes an SVG, and refuses to if the hook is not installed or the log does not verify.

Decision model: Kneepad never says "allow". Safe commands pass through silently and keep your normal permission flow. Risky ones get `ask`. Catastrophic ones get `deny`. If Kneepad itself errors, it answers `ask`.

## Works with

Claude Code, OpenAI Codex CLI, Cursor, Gemini CLI, GitHub Copilot CLI, Cline, any tool with a command hook (generic JSON), any agent that runs `$SHELL -c` (`kneepad-shell`), and your own Python agents (`kneepad.api`). The decision is made on the action, so it does not matter which LLM is driving. Each integration is tested against the vendor's documented hook contract; none has yet been verified inside the real vendor app. See [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) for the exact status and known vendor-side limits.

## Platforms

| | Linux | macOS | Windows |
|---|---|---|---|
| Command analysis | yes | yes: `diskutil`, `tmutil`, `csrutil`, `launchctl`, `security`, `dscl`, `osascript do shell script`, `/private` paths, case-insensitive volumes | yes: cmd.exe and PowerShell syntax, drive and UNC paths, `Remove-Item`/`del`/`rd`, registry, `-EncodedCommand` is decoded, `wsl`/`cmd /c`/`powershell -c` are unwrapped |
| Agent hook installers | all | all | all except Cline (its docs say macOS and Linux only) |
| Continuous integration | full suite and end-to-end QA | full suite and end-to-end QA | rule examples and platform tests gate the build; the full suite and the end-to-end QA run as informational steps and passed on real Windows runners for 0.3.1 |

Be clear about what this means. The Windows and macOS logic was written and unit-tested on Linux by simulating those platforms' paths and syntax, plus a mutation pass over the new code. The full suite passes on real macOS runners, and the Windows-specific tests pass on real Windows runners (Windows does not run the whole suite). Neither has been used by a person on a real machine with a real agent, so treat both as lightly proven. No agent integration has been run inside its real vendor app on any operating system. Known gaps are listed in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Install

```
pip install kneepad                        # Windows: py -m pip install kneepad
kneepad init --claude-code                 # Claude Code
kneepad init --target cursor --target gemini --target codex   # others (or --target all)
kneepad doctor
```

From a checkout instead:

```
pip install .
kneepad init --claude-code --scope project   # hook for this repo only
```

`init` backs up your settings file, preserves everything in it, and is safe to run twice. `kneepad uninstall` removes only its own entry.

## Try it without installing the hook

```
kneepad check 'rm -rf /'              # exit 20 (deny)
kneepad check 'terraform destroy'     # exit 10 (ask)
kneepad check 'ls -la'                # exit 0
kneepad run -- git push --force origin main
```

## Everyday commands

| command | purpose |
|---|---|
| `kneepad log` | recent decisions |
| `kneepad verify` | check the hash chain and signatures |
| `kneepad anchor` | print `SEQ:HASH` to store somewhere else (detects tail truncation) |
| `kneepad snapshots list/show/restore/prune` | safety copies |
| `kneepad rules list/show/validate` | browse and validate the footgun database |
| `kneepad badge` | write the badge SVG |

## Configuration

User config at `~/.kneepad/config.toml` is trusted and can relax rules (`disable_rules`, `allow_patterns`, `allow_write_paths`, `mode = "monitor"`). A project `.kneepad.toml` is untrusted, because a cloned repo could carry one, so it can only tighten: extra `protected_paths`, `prod_markers`, `protected_branches`, `escalate`, a lower snapshot size cap. Rules marked `no_override` (for example `rm -rf /`) cannot be disabled by any config.

A production marker (`prod`, `production`, `prd` as a whole word) in a destructive infrastructure or database command escalates `ask` to `deny`.

## What it is not

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before relying on it. In short: this catches accidents and common agent mistakes. It is not a sandbox, and it does not stop a determined adversary who can obfuscate commands.

## Development

```
python3 -m unittest discover -s tests
```

465 tests: parser, SQL scanner, every rule example, about 280 everyday commands that must pass silently, about 120 destructive commands that must be stopped, audit tamper fuzzing (every single byte flip is detected), concurrent writers, hostile-repo handling, random-input robustness, and Windows and macOS path and syntax simulation. `python tools/smoke_hook.py` installs the hooks into a throwaway home and runs the written hook command through your real OS shell.

Adding a rule: see [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md). The rule list is in [docs/FOOTGUNS.md](docs/FOOTGUNS.md).
