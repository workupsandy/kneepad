# Threat model and known limits

Kneepad is built for one failure: a well-meaning agent (or a tired human) running a destructive command by mistake. Bugs are possible in any software. This page lists what is covered, what is not, and what is known to be imperfect.

## In scope

- Destructive filesystem, git, cloud, database and infrastructure commands issued through Claude Code's Bash, Write/Edit and MCP tools.
- Commands hidden inside quotes, subshells, heredocs, `bash -c`, `eval`, `ssh`, `docker exec`, `kubectl exec`, wrappers, package runners, and scripts the command is about to execute.
- Unset or empty variables that turn `rm -rf $DIR/` into `rm -rf /`.
- Hostile repositories: all git calls run with `core.fsmonitor=false`, and a project `.kneepad.toml` can only tighten policy.
- Accidental or malicious edits to the audit log.

## Out of scope (not defended)

- **Deliberate obfuscation.** Base64-decoded commands, `printf` assembled strings, `$'\x72m'`, indirect execution through `python -c "exec(...)"`, or building a script on the fly with variables Kneepad cannot resolve. Dynamic targets in `rm -r` are flagged, but arbitrary code is not decidable.
- **A compromised user account.** Anything that can run as you can delete the audit key and log. Kneepad is not a sandbox, container or permission system.
- **Actions outside the hooked tools.** If the agent has a tool Kneepad does not see, it is not checked. The installer's matcher covers Bash, Write, Edit, MultiEdit, NotebookEdit and `mcp__*`.
- **Agents with no pre-execution hook and no `$SHELL -c` path.** Kneepad cannot see what they do. `kneepad run` and `kneepad check` can be wired in by hand.

## Known limits

1. **`cd` is modelled only when the target is a literal.** `cd /tmp && rm -rf *` resolves `*` against `/tmp`. `cd "$DIR"`, `cd -` and a `cd` hidden inside a script or function are not followed, and relative paths after them resolve against the hook's working directory. Absolute paths are always evaluated correctly.
2. **Followed scripts only count high and critical findings**, and only files up to 64 KB. Medium findings are reported as notes. This avoids blocking every build script.
3. **SQL inside `$$ ... $$` function bodies and stored procedures is opaque.**
4. **SQL detection is lexical.** It handles comments, quotes, dollar quoting and `WHERE 1=1` style tautologies, but cannot evaluate expressions.
5. **Audit log tail truncation is undetectable on its own.** Removing the newest entries leaves a valid chain. Use `kneepad anchor` and store the `SEQ:HASH` outside the machine (a commit, a ticket) to detect it. The HMAC key lives beside the log, so the log proves integrity against casual or accidental edits, not against an attacker who can read the key.
6. **Snapshots are bounded** (default size and file-count caps). Above the cap the command is escalated to `ask` instead of being copied. Files that git can already restore (tracked and clean) are not copied.
7. **Non-recursive `rm` of a file is allowed** after a snapshot. That is intentional. Kneepad is not trying to prevent routine work.
8. **Windows is a tokenizer plus patterns, not a PowerShell parser.** Script blocks are split into separate commands, variables assigned earlier (`$p = "C:\\"; rm -r $p`) are not tracked (they are treated as dynamic and asked about when they feed a recursive delete), user-defined aliases are not resolved, and `.ps1`, `.bat` and `.cmd` files are not followed the way shell scripts are.
9. **Windows path tricks that are not resolved:** junctions and symbolic links (`mklink /J`), 8.3 short names below the top level (a top-level short name such as `PROGRA~1` is treated as a system directory), and `\\?\GLOBALROOT\` device paths.
10. **macOS:** compiled AppleScript (`.scpt`) and scripts read from a file are not inspected, only `-e` text. APFS firmlinks other than `/private` are not resolved. Case-insensitive comparison assumes the default volume format; a case-sensitive APFS volume is treated as case-insensitive, which can only over-ask.
11. **Snapshots on Windows** copy files with the standard library, so they need to be able to read the files and cannot record symbolic links without the symlink privilege (the command asks instead).
12. **File permissions** of the audit key and state directory are enforced with POSIX modes on Linux and macOS. On Windows they are access-control lists: Kneepad reads the ACL with `icacls` when it creates the state directory or the key, in `kneepad init`, and in `kneepad doctor`, and removes access for anyone other than you, SYSTEM and Administrators if it finds any (a folder under your profile is already private; `KNEEPAD_HOME` elsewhere may inherit Users or Everyone). Administrators and SYSTEM can always read the key, as on any Windows machine. The check is not repeated on every hook call, so an ACL loosened later is noticed by `doctor` or the next `init`, not immediately. If `icacls` is unavailable or the ACL cannot be read, `doctor` says unknown and nothing is changed.
13. **Heuristic false positives exist.** If a rule gets in your way, `disable_rules` in your user config turns it off (except `no_override` rules), and an issue with the command that tripped it is a welcome contribution.
14. **Self-removal prompts cover the common spellings only.** Known misses: `python3 -Im kneepad uninstall`, `pip --python PATH uninstall kneepad`, `pip uninstall -r FILE`, names piped through `xargs`, and deleting the virtualenv (`rm -rf .venv`). A determined agent can always remove a tool it can run commands against; the prompt exists to make that a decision you see.

## Failure behaviour

| situation | result |
|---|---|
| malformed hook input | `ask` |
| oversized input or nesting deeper than the limit | `ask` (`analysis-limit-exceeded`) |
| internal exception | `ask` |
| snapshot could not be taken | `ask` (`snapshot-unavailable`) |
| audit log cannot be written | decision unchanged, logging skipped |
| invalid project config | ignored with a warning, protection stays on |

## "0 bugs"

No one can honestly promise that. What exists instead: 465 automated tests, an example-driven rule database that cannot drift from its documentation, byte-level tamper fuzzing, randomized input fuzzing for crashes and slowness, and the explicit limits above. During development the test suite found and fixed real defects, including an audit-rotation crash, a pipeline walk-back miss in `curl | tee | sh`, and several rule false positives. More will turn up in real use.
