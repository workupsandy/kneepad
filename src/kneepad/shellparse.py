"""A small, dependency-free shell lexer and parser built for safety analysis.

It never executes anything. It splits a script into simple commands, understands
quoting, escapes, command substitution, process substitution, redirections,
heredocs, pipelines and comments, and exposes the nested scripts (for example the
body of ``$(...)``) so callers can analyse them recursively.

It is deliberately forgiving: unterminated quotes or substitutions never raise,
they consume to the end of input. Parsing is linear in the input size.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

MAX_SRC = 1_000_000
MAX_DEPTH = 6

RESERVED = frozenset(
    {
        "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "for",
        "in", "case", "esac", "select", "function", "{", "}", "!", "time", "coproc",
        "[[", "]]",
    }
)

_REDIR_OPS = ("&>>", "&>", "<<<", "<<-", "<<", "<&", ">&", ">>", ">|", "<>", ">", "<")
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")


@dataclass
class Word:
    """One shell word after quote removal. Variable expansions stay literal."""

    text: str
    raw: str = ""
    quoted: bool = False
    has_var: bool = False
    glob: bool = False
    subs: List[str] = field(default_factory=list)


@dataclass
class Cmd:
    """A simple command: words, redirections and heredoc bodies."""

    argv: List[Word]
    redirects: List[Tuple[str, Word]]
    heredocs: List[str]
    raw: str
    pipe_in: bool = False
    pipe_out: bool = False
    background: bool = False


class _Heredoc:
    __slots__ = ("delim", "strip_tabs", "body")

    def __init__(self, delim: str, strip_tabs: bool) -> None:
        self.delim = delim
        self.strip_tabs = strip_tabs
        self.body = ""


class _Lexer:
    def __init__(self, src: str) -> None:
        self.s = src
        self.n = len(src)
        self.i = 0
        self.tokens: List[tuple] = []
        self.pending: List[_Heredoc] = []

    # ---- helpers -------------------------------------------------------
    def _paren_body(self, start: int) -> Tuple[str, int]:
        """Return (body, index_after_closing_paren) for a ``$(`` already opened."""
        s, n = self.s, self.n
        depth = 1
        i = start
        while i < n:
            c = s[i]
            if c == "\\":
                i += 2
                continue
            if c == "'":
                j = s.find("'", i + 1)
                i = n if j == -1 else j + 1
                continue
            if c == '"':
                i += 1
                while i < n and s[i] != '"':
                    i += 2 if s[i] == "\\" else 1
                i += 1
                continue
            if c == "`":
                j = i + 1
                while j < n and s[j] != "`":
                    j += 2 if s[j] == "\\" else 1
                i = j + 1
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return s[start:i], i + 1
            i += 1
        return s[start:], n

    def _arith_end(self, start: int) -> int:
        s, n = self.s, self.n
        depth = 2
        i = start
        while i < n:
            c = s[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return n

    def _backtick_body(self, start: int) -> Tuple[str, int]:
        s, n = self.s, self.n
        i = start
        while i < n and s[i] != "`":
            i += 2 if s[i] == "\\" else 1
        end = min(i, n)
        return s[start:end].replace("\\`", "`"), min(i + 1, n)

    def _brace_end(self, start: int, w: Word) -> int:
        """Skip a ``${...}`` expansion, collecting nested command substitutions."""
        s, n = self.s, self.n
        depth = 1
        i = start
        while i < n:
            c = s[i]
            if c == "\\":
                i += 2
                continue
            if c == "'":
                j = s.find("'", i + 1)
                i = n if j == -1 else j + 1
                continue
            if c == '"':
                i += 1
                while i < n and s[i] != '"':
                    i += 2 if s[i] == "\\" else 1
                i += 1
                continue
            if c == "$" and i + 1 < n and s[i + 1] == "(" and not s.startswith("$((", i):
                body, end = self._paren_body(i + 2)
                w.subs.append(body)
                i = end
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return n

    def _read_dq(self, w: Word, buf: List[str]) -> None:
        s, n = self.s, self.n
        w.quoted = True
        self.i += 1  # opening quote
        while self.i < n:
            c = s[self.i]
            if c == '"':
                self.i += 1
                return
            if c == "\\" and self.i + 1 < n and s[self.i + 1] in '"\\$`\n':
                if s[self.i + 1] != "\n":
                    buf.append(s[self.i + 1])
                self.i += 2
                continue
            if c == "$" and self.i + 1 < n:
                nx = s[self.i + 1]
                if nx == "(":
                    if s.startswith("$((", self.i):
                        end = self._arith_end(self.i + 3)
                        buf.append(s[self.i:end])
                        w.has_var = True
                        self.i = end
                        continue
                    body, end = self._paren_body(self.i + 2)
                    w.subs.append(body)
                    buf.append(s[self.i:end])
                    w.has_var = True
                    self.i = end
                    continue
                if nx == "{":
                    end = self._brace_end(self.i + 2, w)
                    buf.append(s[self.i:end])
                    w.has_var = True
                    self.i = end
                    continue
                if nx.isalnum() or nx in "_@*#?!$-":
                    w.has_var = True
                buf.append("$")
                self.i += 1
                continue
            if c == "`":
                body, end = self._backtick_body(self.i + 1)
                w.subs.append(body)
                buf.append(s[self.i:end])
                w.has_var = True
                self.i = end
                continue
            buf.append(c)
            self.i += 1

    def _read_ansi_c(self, buf: List[str], w: Word) -> None:
        """Handle ``$'...'`` with the common escapes."""
        s, n = self.s, self.n
        w.quoted = True
        self.i += 2
        esc = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"', "a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "v": "\v"}
        while self.i < n:
            c = s[self.i]
            if c == "'":
                self.i += 1
                return
            if c == "\\" and self.i + 1 < n:
                nx = s[self.i + 1]
                if nx in esc:
                    buf.append(esc[nx])
                    self.i += 2
                    continue
                m = re.match(r"x([0-9A-Fa-f]{1,2})", s[self.i + 1:self.i + 4])
                if m:
                    buf.append(chr(int(m.group(1), 16)))
                    self.i += 1 + len(m.group(0))
                    continue
                m = re.match(r"([0-7]{1,3})", s[self.i + 1:self.i + 4])
                if m:
                    buf.append(chr(int(m.group(1), 8)))
                    self.i += 1 + len(m.group(0))
                    continue
                buf.append(nx)
                self.i += 2
                continue
            buf.append(c)
            self.i += 1

    def _read_word(self) -> Word:
        s, n = self.s, self.n
        buf: List[str] = []
        w = Word(text="")
        start = self.i
        while self.i < n:
            c = s[self.i]
            if c in " \t\n" or c in ";&|()":
                break
            if c in "<>":
                if not buf and self.i + 1 < n and s[self.i + 1] == "(":
                    body, end = self._paren_body(self.i + 2)
                    w.subs.append(body)
                    buf.append(s[self.i:end])
                    w.has_var = True
                    self.i = end
                    continue
                break
            if c == "\\":
                if self.i + 1 < n:
                    nx = s[self.i + 1]
                    if nx == "\n":
                        self.i += 2
                        continue
                    buf.append(nx)
                    w.quoted = True
                    self.i += 2
                    continue
                self.i += 1
                continue
            if c == "'":
                end = s.find("'", self.i + 1)
                if end == -1:
                    end = n
                buf.append(s[self.i + 1:end])
                w.quoted = True
                self.i = min(end + 1, n)
                continue
            if c == '"':
                self._read_dq(w, buf)
                continue
            if c == "$":
                nx = s[self.i + 1] if self.i + 1 < n else ""
                if nx == "'":
                    self._read_ansi_c(buf, w)
                    continue
                if nx == '"':
                    self.i += 1
                    continue
                if nx == "(":
                    if s.startswith("$((", self.i):
                        end = self._arith_end(self.i + 3)
                        buf.append(s[self.i:end])
                        w.has_var = True
                        self.i = end
                        continue
                    body, end = self._paren_body(self.i + 2)
                    w.subs.append(body)
                    buf.append(s[self.i:end])
                    w.has_var = True
                    self.i = end
                    continue
                if nx == "{":
                    end = self._brace_end(self.i + 2, w)
                    buf.append(s[self.i:end])
                    w.has_var = True
                    self.i = end
                    continue
                if nx and (nx.isalnum() or nx in "_@*#?!$-"):
                    w.has_var = True
                buf.append("$")
                self.i += 1
                continue
            if c == "`":
                body, end = self._backtick_body(self.i + 1)
                w.subs.append(body)
                buf.append(s[self.i:end])
                w.has_var = True
                self.i = end
                continue
            if c in "*?[":
                w.glob = True
            buf.append(c)
            self.i += 1
        w.text = "".join(buf)
        w.raw = s[start:self.i]
        return w

    def _read_heredocs(self) -> None:
        s, n = self.s, self.n
        for hd in self.pending:
            lines: List[str] = []
            while self.i < n:
                j = s.find("\n", self.i)
                line = s[self.i:] if j == -1 else s[self.i:j]
                self.i = n if j == -1 else j + 1
                cmp = line.lstrip("\t") if hd.strip_tabs else line
                if cmp == hd.delim:
                    break
                lines.append(line)
            hd.body = "\n".join(lines)
        self.pending = []

    # ---- main loop -----------------------------------------------------
    def run(self) -> List[tuple]:
        s, n = self.s, self.n
        while self.i < n:
            c = s[self.i]
            if c in " \t":
                self.i += 1
                continue
            if c == "\\" and self.i + 1 < n and s[self.i + 1] == "\n":
                self.i += 2
                continue
            if c == "\n":
                self.tokens.append(("op", "\n"))
                self.i += 1
                if self.pending:
                    self._read_heredocs()
                continue
            if c == "#":
                j = s.find("\n", self.i)
                self.i = n if j == -1 else j
                continue
            if c in ";&|()":
                self._read_operator()
                continue
            fd_match = None
            if c.isdigit():
                m = re.match(r"\d+(?=[<>])", s[self.i:self.i + 12])
                if m:
                    fd_match = m
            if c in "<>" or fd_match or (c == "&" and s.startswith("&>", self.i)):
                if c in "<>" and self.i + 1 < n and s[self.i + 1] == "(":
                    self.tokens.append(("word", self._read_word()))
                    continue
                if fd_match:
                    self.i += len(fd_match.group(0))
                self._read_redirect()
                continue
            self.tokens.append(("word", self._read_word()))
        return self.tokens

    def _read_operator(self) -> None:
        s = self.s
        c = s[self.i]
        if c == "&" and s.startswith("&>", self.i):
            self._read_redirect()
            return
        two = s[self.i:self.i + 2]
        three = s[self.i:self.i + 3]
        if three in (";;&",):
            op = three
        elif two in ("&&", "||", "|&", ";;", ";&"):
            op = two
        else:
            op = c
        self.i += len(op)
        self.tokens.append(("op", op))

    def _read_redirect(self) -> None:
        s = self.s
        op = ""
        for cand in _REDIR_OPS:
            if s.startswith(cand, self.i):
                op = cand
                break
        if not op:  # defensive: should be unreachable
            self.i += 1
            return
        self.i += len(op)
        if op in ("<<", "<<-"):
            while self.i < self.n and s[self.i] in " \t":
                self.i += 1
            delim_word = self._read_word()
            hd = _Heredoc(delim_word.text, op == "<<-")
            self.pending.append(hd)
            self.tokens.append(("heredoc", hd))
            return
        self.tokens.append(("redir", op))


def parse(src: str) -> List[Cmd]:
    """Parse ``src`` into simple commands. Never raises on malformed input."""
    src = src[:MAX_SRC]
    toks = _Lexer(src).run()
    cmds: List[Cmd] = []
    words: List[Word] = []
    redirs: List[Tuple[str, Word]] = []
    heredocs: List[_Heredoc] = []
    pending_redir: Optional[str] = None
    pipe_in = False

    def flush(pipe_out: bool = False, bg: bool = False) -> None:
        nonlocal words, redirs, heredocs, pipe_in, pending_redir
        if words or redirs or heredocs:
            raw = " ".join(w.raw for w in words)
            cmds.append(Cmd(words, redirs, [h.body for h in heredocs], raw, pipe_in, pipe_out, bg))
        words, redirs, heredocs = [], [], []
        pending_redir = None
        pipe_in = pipe_out

    for tok in toks:
        kind = tok[0]
        if kind == "word":
            if pending_redir is not None:
                redirs.append((pending_redir, tok[1]))
                pending_redir = None
            else:
                words.append(tok[1])
        elif kind == "redir":
            pending_redir = tok[1]
        elif kind == "heredoc":
            heredocs.append(tok[1])
        else:  # op
            op = tok[1]
            if op in ("|", "|&"):
                flush(pipe_out=True)
            elif op == "&":
                flush(bg=True)
            else:
                flush()
    flush()
    return cmds


def is_assignment(text: str) -> bool:
    return bool(_ASSIGN_RE.match(text))


def iter_nested(cmds: List[Cmd]):
    """Yield every command-substitution body found in ``cmds``."""
    for c in cmds:
        for w in c.argv:
            for sub in w.subs:
                yield sub
        for _op, w in c.redirects:
            for sub in w.subs:
                yield sub
