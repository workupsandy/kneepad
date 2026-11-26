# Integrations

Kneepad judges the action (a shell command, a file write, an MCP tool call), not the model that proposed it. Claude, GPT, Gemini, Llama, Mistral, DeepSeek or a local model all get the same decision, because the decision is made by the agent application's hook, not by the LLM. "Supports all LLMs" therefore means "supports every agent application that exposes a pre-execution hook, or runs commands through a shell you can wrap".

Contracts below were read from each vendor's public documentation on 2026-11-26.

## Verification levels

| level | meaning |
|---|---|
| **Contract-tested** | Kneepad's adapter is tested against the payload and response shapes in the vendor docs, and the hook command the installer writes was executed end to end from a clean virtualenv install (`tools/smoke_hook.py`, on Linux here, and on macOS and Windows runners in CI). |
| **Run in the vendor app** | Someone ran the real vendor application with Kneepad installed and watched it block a command. **No integration has this level yet.** |

Until the second level is reached for an integration, treat it as unproven in production. If you run one, please open an issue with the result so the table can be updated.

## Support matrix

| Tool | Install | Hook | Ask supported by vendor | What Kneepad does on "ask" | Level |
|---|---|---|---|---|---|
| Claude Code | `kneepad init --claude-code` | `PreToolUse` | yes | asks | Contract-tested |
| OpenAI Codex CLI | `kneepad init --target codex` | `PreToolUse` | **no** (parsed, then the call continues) | denies | Contract-tested |
| Cursor | `kneepad init --target cursor` | `beforeShellExecution`, `beforeMCPExecution` (`failClosed`) | documented, but a forum report shows it ignored in sandbox mode | denies | Contract-tested |
| Gemini CLI | `kneepad init --target gemini` | `BeforeTool` | no | denies | Contract-tested |
| GitHub Copilot CLI | `kneepad init --target copilot` | `preToolUse` | not verified | denies | Contract-tested |
| Cline | `kneepad init --target cline` | `PreToolUse` script (macOS and Linux) | no | denies | Contract-tested |
| Anything else with a command hook | add `kneepad hook generic` | JSON `{"command","cwd"}` on stdin, exit 2 blocks | n/a | denies | Contract-tested |
| Any agent that runs `$SHELL -c` | `SHELL=$(which kneepad-shell)` or `kneepad shell -c ...` | shell wrapper, exit 126 | n/a | blocks | Tested with a stub shell, not with a vendor app |
| Your own agent (LangChain, OpenAI Agents SDK, CrewAI, custom loops) | `from kneepad.api import guard, check_command` | in-process | n/a | raises `KneepadBlocked` | Unit-tested |

Why "ask" becomes "deny" where the vendor has no ask: if a hook answers something the vendor does not understand, some tools continue the tool call (Codex does, per its docs). Failing open is worse than blocking, so Kneepad answers a hard deny and tells you in the message to run the command yourself if you meant it.

## Known vendor-side limits (not fixable by Kneepad)

- **Cursor** has forum reports of hooks failing open on some malformed responses and of `ask` not stopping a command in sandbox mode. Kneepad only emits well-formed responses and uses `deny`, and installs with `failClosed: true`.
- **Codex** runs non-managed hooks only after you review and trust them with `/hooks`. An untrusted hook does not run, so after install you must trust it.
- **Gemini CLI** fingerprints project-level hooks and treats a changed hook as new and untrusted, so a project-scope install needs approval.
- **Cline** hooks are macOS and Linux only.
- **Windows and macOS** are supported by Kneepad's analyzer and installers (see the README). The hook command is written with forward slashes and quotes so it works from cmd.exe, PowerShell and Git Bash. Whether each agent runs hook commands through a shell that accepts that form is not verified. Copilot CLI entries get both `bash` and `powershell` keys on Windows; that key is from Copilot's hooks reference and has not been run.
- Run `python tools/smoke_hook.py` on your own machine after installing. It executes the installed hook command through your real shell and prints failures.
- A hook only sees what the agent routes through that tool. Commands the agent runs in a separate sandbox, in an IDE terminal you typed into, or through a tool the hook does not cover are out of scope. See `THREAT_MODEL.md`.

## Vendor documentation used

- Claude Code hooks: https://code.claude.com/docs/en/hooks
- Cursor hooks: https://cursor.com/docs/hooks
- Gemini CLI hooks: https://geminicli.com/docs/hooks/reference/
- OpenAI Codex hooks: https://learn.chatgpt.com/docs/hooks (also at developers.openai.com/codex/hooks)
- GitHub Copilot hooks: https://docs.github.com/en/copilot/reference/hooks-reference
- Cline hooks: https://docs.cline.bot/customization/hooks

## Not supported yet

- **Windsurf, Aider, Continue, Amp, Roo Code, Zed, JetBrains Junie and others:** their hook contracts were not verified, so there is no adapter. The generic adapter and the shell wrapper may work. If you know the contract, an adapter is about 30 lines in `adapters.py` (see `CONTRIBUTING.md`).
- **MCP proxy:** Kneepad checks MCP tool calls when an agent's hook passes them in (Claude Code, Cursor), judging by tool name and input. It is not a standalone proxy between an agent and an MCP server.
