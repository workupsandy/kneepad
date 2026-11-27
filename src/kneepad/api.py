"""Use Kneepad from your own agent code (LangChain, OpenAI Agents SDK, CrewAI, custom loops).

    from kneepad.api import check_command, guard, KneepadBlocked

    d = check_command("terraform destroy")
    if d.action != "allow":
        print(d.reason())

    @guard                      # raises KneepadBlocked on deny or ask unless allow_ask=True
    def run_shell(command: str): ...

Nothing here depends on which LLM drives your agent; Kneepad looks at the action, not the model.
"""

from __future__ import annotations

import functools
import os
from typing import Any, Callable, Optional

from .config import load_config
from .engine import Analyzer, Decision


class KneepadBlocked(Exception):
    def __init__(self, decision: Decision):
        super().__init__(decision.reason())
        self.decision = decision


def check_command(command: str, cwd: Optional[str] = None) -> Decision:
    cwd = cwd or os.getcwd()
    return Analyzer(config=load_config(cwd), cwd=cwd).analyze_shell(command)


def check_write(path: str, cwd: Optional[str] = None) -> Decision:
    cwd = cwd or os.getcwd()
    return Analyzer(config=load_config(cwd), cwd=cwd).analyze_write_path(path)


def check_mcp(tool_name: str, tool_input: Any, cwd: Optional[str] = None) -> Decision:
    cwd = cwd or os.getcwd()
    return Analyzer(config=load_config(cwd), cwd=cwd).analyze_mcp(tool_name, tool_input)


def guard(func: Optional[Callable] = None, *, arg: str = "command", allow_ask: bool = False):
    """Decorator for a function that executes a shell command passed as its first argument or as ``arg``."""

    def wrap(f: Callable) -> Callable:
        @functools.wraps(f)
        def inner(*args, **kwargs):
            cmd = kwargs.get(arg) if arg in kwargs else (args[0] if args else None)
            if not isinstance(cmd, str):
                raise TypeError(f"guard expected a string command as the first argument or {arg}=")
            d = check_command(cmd)
            if d.action == "deny" or (d.action == "ask" and not allow_ask):
                raise KneepadBlocked(d)
            return f(*args, **kwargs)

        return inner

    if func is not None and not callable(func):
        raise TypeError("guard decorates a function: use @guard or @guard(allow_ask=True), not guard('command'). "
                        "To check a command string use check_command().")
    return wrap(func) if func is not None else wrap
