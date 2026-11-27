# Changelog

## 0.3.1
Found by an end-to-end QA pass (`tools/qa_e2e.py`) against the installed package.
- Security: `kneepad shell` only recognised `-c`, `-lc`, `-ic` and `-cl`, so `kneepad shell -ec 'rm -rf ~'` (and `-xc`, `-euc`,
  `-l -c`, `-o pipefail -c`) skipped analysis and ran. All clustered and separated forms are now analysed.
- Fix: `kneepad shell` took no snapshot before an allowed risky command (for example `rm file`) even though `kneepad check`
  said one would be taken, and neither `shell` nor `run` logged refused commands. Both now share one code path that
  snapshots, logs every decision (allowed, asked, refused) and reports audit-log write failures on stderr instead of
  swallowing them.
- Fix: `kneepad uninstall` removed any hook whose command merely contained the words "kneepad" and "hook" (for example a
  user's `my-kneepad-notify hook start`). It now removes only entries that invoke the `kneepad` program or `python -m kneepad`.
- Fix: a `protected_paths` entry naming a directory (`secrets`) did not protect files inside it. Directory entries now cover
  their contents; `allow_write_paths` follows the same rule.
- Fix: `kneepad run` printed a traceback for a missing program or for `--help`. It now returns 127 (not found) or 126, and
  `kneepad run --help` prints usage.
- Fix: `kneepad log -n 0` printed every entry; negative values are rejected.
- Fix: `kneepad badge --out` into a missing directory, and `kneepad init` when the state path is a file, printed tracebacks.
  They now print a one-line error and exit 1.
- Fix: `kneepad.api.guard("cmd")` (string passed instead of decorating a function) silently did nothing; it now raises TypeError.
- Windows: the audit log's last-line reader used `os.pread`, which does not exist on Windows; replaced with seek and read.
- Security: `rm -rf ~/*`, `rm -rf $HOME/*`, `rm -rf /home/*` and `rm -rf ~/.[a-z]*` were only checked file by file, so in a
  small or empty home they were allowed. A recursive delete of a match-all glob directly under the home directory or a
  top-level directory is now denied no matter what it matches today.
- Security: `x=~; rm -rf $x` was allowed because an unquoted tilde in a variable assignment was not expanded (`x=/` was
  already denied). `busybox rm` and `toybox rm` are now unwrapped like `sudo` and `nice`, and `unlink` is treated like `rm`.
- Fix: MCP servers named `db` (`mcp__db__run`) were not recognised as databases, so SQL in their arguments was not scanned.
- Fix (race): when the audit log had a torn last line and several writers started together, a late writer could move the
  freshly started log aside, leaving some entries in a `.corrupt-*` file instead of the live log. Writers now confirm the
  file they locked is still the live log, and the log is set aside exactly once.
- Fix (race): `kneepad verify` could report "not valid JSON" for the last line when it read the log while another process was
  appending; it now waits for the append. Two parallel `kneepad init` calls could both write the first `init` entry; the
  first-entry write is now atomic.
- `kneepad rules validate` now says it checks structure only; each rule's examples are executed by the test suite.
- Help text for `init` and `uninstall` flags; README and threat model claims updated (test count, which decisions are logged,
  CI status per platform).
- `kneepad rules list | head -1` (any reader that closes early) no longer ends with "Exception ignored ... BrokenPipeError" and exit
  status 120: stdout and stderr are flushed inside `main`, and a broken pipe redirects the descriptor to the null device. Found by macOS CI
  (STB-007); it depends on timing, so it can also happen on Linux.
- Windows: the corrupt-tail rotation of the audit log failed with `WinError 32` because Windows cannot rename a file that is open. The
  corrupt log is now copied aside and the live file emptied in place, so the log recovers instead of staying corrupt.
- Windows: `protected_paths` and `allow_write_paths` were ignored for Windows paths. They now apply, case-insensitively.
- Windows: a path under the user's own profile spelled with an 8.3 short name (`C:\Users\RUNNER~1\...`, common in `%TEMP%`) was treated
  as a system directory, so every `rm` there asked. Short profile names now resolve to the home directory, and files inside the project
  directory are not system paths.
- Windows (Git Bash, which Claude Code uses): `/etc`, `/usr`, `/var`, `/sbin` and `/proc` style paths, `~/.bashrc` and the other shell
  startup files, `.git\hooks`, `.git\config`, `.github\workflows` and `.env` files are now protected, matching the POSIX behaviour.
- Windows: `kneepad run -- rm -rf C:\Users\me\proj` was allowed. `run` built the text it analyses with `subprocess.list2cmdline`,
  which leaves backslash paths unquoted; the shell parser read the backslashes as escapes, turned the path into a harmless-looking
  relative name and let the command through. `run` now quotes with POSIX rules on every platform.
- A leading `~` in a path given to the file-write check is expanded with the analyser's own home directory instead of the process
  environment, so the two can no longer disagree (they did on Windows when a caller passed `home` explicitly).
- Windows: two `kneepad init` runs at the same moment could fail with "Permission denied" because Windows will not read or replace a
  file another process has open. The settings writer now retries for about two seconds on Windows (not on POSIX), then gives up with the
  original error.
- Config path patterns (`protected_paths`, `allow_write_paths`) now match whether a tool names a file by its real path or through a symlinked
  alias. Found by macOS CI: the working directory is reported as `/private/var/...` while temp paths are spelled `/var/...`, so a
  relative `protected_paths` pattern missed writes made through the alias (a protection bypass).
- `tools/ci_run_tests.py` reports every failing unit test as a GitHub annotation (readable without downloading logs); the Windows
  job now also runs the whole suite as an informational step.
- New `tools/qa_e2e.py` (installs into a fresh virtualenv and exercises every command on Linux, macOS and Windows) and
  `tests/test_qa_regressions.py`.

## 0.3.0
- Renamed from Seatbelt to Kneepad (a kneepad is cheap gear that takes the hit so the joint does not). Package, CLI,
  environment variables (`KNEEPAD_*`) and state directory (`~/.kneepad`) changed. Nothing is migrated automatically.
- macOS fix found by the first real macOS CI run: paths under `/private` (where macOS temp dirs and some projects resolve)
  were compared against an un-normalised home and cwd, so `rm -rf ~` was allowed in that situation. Home, cwd and target
  are now normalised together. The simulated-macOS tests are skipped on real Windows, where POSIX paths cannot be modelled.
- Windows: cmd.exe and PowerShell tokenizer (`winshell.py`), Windows path classification (drive, UNC, case, 8.3 top-level
  names, registry providers), `Remove-Item`/`del`/`rd` handling with snapshots, `-EncodedCommand` decoding, unwrapping of
  `powershell -c`, `cmd /c`, `wsl`, `Start-Process`, `iex`, protected-path writes (profile, hosts, startup folder,
  `.ssh`), 38 Windows rules (format, shadow copies, registry, services, firewall, Defender, ACLs, robocopy /MIR,
  `wsl --unregister`, LOLBin downloads, PowerShell download-and-execute and more).
- macOS: system paths (`/System`, `/Library`, `/Applications`, `/private/...`), other users' home directories,
  case-insensitive comparison, Keychains and LaunchAgents protection, `osascript` shell-string analysis, 19 macOS rules.
- Git Bash, MSYS2 and WSL drive paths (`/c/Windows`, `/mnt/c`) are recognised.
- Portability: cross-platform file locking, binary-safe audit file descriptors, UTF-8 hook streams, Windows-safe hook
  command quoting, `kneepad shell` returns the child's exit code on Windows, Copilot `powershell` key on Windows, Cline
  refused on Windows.
- `tools/smoke_hook.py` runs the installed hook command through the real OS shell. CI now includes macOS and an
  experimental Windows job.
- Fix: `csrutil status` and other read-only `csrutil`/`kmutil` calls no longer ask.

## 0.2.0
- Integrations: Codex CLI, Cursor, Gemini CLI, GitHub Copilot CLI and Cline hooks, a generic JSON hook, a `$SHELL` wrapper
  (`kneepad-shell`) and a Python API (`kneepad.api`) for LangChain, OpenAI Agents SDK, CrewAI and custom agents.
  Each integration is labelled with how far it has been verified (docs/INTEGRATIONS.md).
- Rules: 46 additional pattern rules (cloud and PaaS CLIs, data stores, backups, disks, VMs, secrets, git hosts, package
  registries, network and boot changes), generated from tools/gen_rules.py. Total 192 (160 pattern, 32 engine-emitted).
- Safety: regex input is bounded, oversized commands ask instead of silently skipping inspection, NUL bytes no longer
  crash the analyzer, `tool --help` as the first argument is not flagged.
- Fix: `kneepad shell -c` and `kneepad run -- -x` no longer fail in argument parsing.
- Fix: audit key creation is atomic under concurrent first use.

## 0.1.0
- First release: footgun database, shell-aware analyzer, snapshots, hash-chained audit log, badge.
