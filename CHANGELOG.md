# Changelog

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
