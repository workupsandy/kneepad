"""Conservative scanners for destructive SQL, Mongo shell and Redis text.

Everything here works on text and never connects to a database. The SQL scanner
tokenises just enough (comments, quotes, dollar quoting, parentheses) to avoid
the classic mistakes: a ``;`` inside a string, a ``WHERE`` inside a subquery,
or a keyword inside a comment.
"""

from __future__ import annotations

import re
from typing import List, Tuple

MAX_TEXT = 2_000_000

SQL_DROP_DATABASE = "drop-database"
SQL_DROP_TABLE = "drop-table"
SQL_TRUNCATE = "truncate"
SQL_DELETE_NO_WHERE = "delete-no-where"
SQL_UPDATE_NO_WHERE = "update-no-where"
SQL_DROP_COLUMN = "drop-column"
SQL_DROP_ROLE = "drop-role"

_DOLLAR_TAG = re.compile(r"\$[A-Za-z_]*\$")
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*|\d+(?:\.\d+)?|[()]|[^\sA-Za-z0-9_()]")


def _strip_and_split(sql: str) -> List[List[Tuple[str, int]]]:
    """Split into statements. Each statement is a list of (TOKEN, paren_depth).

    Comments are removed; quoted strings and identifiers become a single
    placeholder token ``'`` so their contents can never be mistaken for keywords.
    """
    sql = sql[:MAX_TEXT]
    n = len(sql)
    i = 0
    statements: List[List[Tuple[str, int]]] = []
    cur: List[Tuple[str, int]] = []
    depth = 0
    while i < n:
        c = sql[i]
        if c.isspace():
            i += 1
            continue
        if c == "-" and sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j == -1 else j + 1
            continue
        if c == "#" :  # MySQL comment
            j = sql.find("\n", i)
            i = n if j == -1 else j + 1
            continue
        if c == "/" and sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        if c == "'" or c == '"' or c == "`":
            q = c
            i += 1
            while i < n:
                if sql[i] == "\\" and q != "`":
                    i += 2
                    continue
                if sql[i] == q:
                    if i + 1 < n and sql[i + 1] == q:  # doubled quote escape
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            cur.append(("'", depth))
            continue
        if c == "$":
            m = _DOLLAR_TAG.match(sql, i)
            if m:
                tag = m.group(0)
                j = sql.find(tag, m.end())
                i = n if j == -1 else j + len(tag)
                cur.append(("'", depth))
                continue
        if c == ";":
            if cur:
                statements.append(cur)
            cur = []
            depth = 0
            i += 1
            continue
        m = _WORD.match(sql, i)
        if not m:  # defensive
            i += 1
            continue
        tok = m.group(0)
        i = m.end()
        if tok == "(":
            depth += 1
            cur.append((tok, depth))
        elif tok == ")":
            cur.append((tok, depth))
            depth = max(0, depth - 1)
        else:
            cur.append((tok.upper(), depth))
    if cur:
        statements.append(cur)
    return statements


_CLAUSE_END = {"ORDER", "LIMIT", "RETURNING", "OFFSET", "GROUP", "HAVING"}


def _is_tautology_term(factors: List[List[str]]) -> bool:
    """True if every AND-factor is trivially true (TRUE, 1, 1 = 1, 'a' = 'a')."""
    trivially_true = {("TRUE",), ("1",), ("1", "=", "1"), ("'", "=", "'"), ("(", "TRUE", ")"), ("(", "1", "=", "1", ")")}
    return bool(factors) and all(tuple(f) in trivially_true for f in factors)


def _has_effective_where(tokens: List[Tuple[str, int]]) -> bool:
    """True if there is a top-level WHERE that is not an obvious tautology."""
    for idx, (tok, depth) in enumerate(tokens):
        if tok != "WHERE" or depth != 0:
            continue
        clause: List[str] = []
        for t, d in tokens[idx + 1:]:
            if d == 0 and t in _CLAUSE_END:
                break
            clause.append(t)
        if not clause:
            return False
        # Split on top-level OR, then AND. Parenthesised groups are kept whole
        # by tracking depth through the raw clause tokens.
        or_terms: List[List[str]] = [[]]
        depth = 0
        for t in clause:
            if t == "(":
                depth += 1
            elif t == ")":
                depth = max(0, depth - 1)
            if depth == 0 and t == "OR":
                or_terms.append([])
            else:
                or_terms[-1].append(t)
        for term in or_terms:
            factors: List[List[str]] = [[]]
            depth = 0
            for t in term:
                if t == "(":
                    depth += 1
                elif t == ")":
                    depth = max(0, depth - 1)
                if depth == 0 and t == "AND":
                    factors.append([])
                else:
                    factors[-1].append(t)
            if _is_tautology_term(factors):
                return False
        return True
    return False


def scan_sql(sql: str) -> List[Tuple[str, str]]:
    """Return a list of (kind, snippet) for destructive statements found."""
    found: List[Tuple[str, str]] = []
    for tokens in _strip_and_split(sql):
        words = [t for t, _d in tokens]
        if not words:
            continue
        snippet = " ".join(words)[:160]
        head = words[0]
        # Unwrap "WITH ... DELETE/UPDATE" and EXPLAIN ANALYZE prefixes.
        if head == "WITH":
            for k, (t, d) in enumerate(tokens):
                if d == 0 and t in ("DELETE", "UPDATE", "INSERT", "SELECT"):
                    tokens = tokens[k:]
                    words = [t2 for t2, _ in tokens]
                    head = words[0]
                    break
        if head == "DROP":
            second = words[1] if len(words) > 1 else ""
            if second in ("DATABASE", "SCHEMA", "KEYSPACE"):
                found.append((SQL_DROP_DATABASE, snippet))
            elif second == "TABLE":
                found.append((SQL_DROP_TABLE, snippet))
            elif second in ("USER", "ROLE"):
                found.append((SQL_DROP_ROLE, snippet))
        elif head == "TRUNCATE":
            found.append((SQL_TRUNCATE, snippet))
        elif head == "DELETE" and len(words) > 1 and words[1] == "FROM":
            if not _has_effective_where(tokens):
                found.append((SQL_DELETE_NO_WHERE, snippet))
        elif head == "UPDATE":
            if "SET" in words and not _has_effective_where(tokens):
                found.append((SQL_UPDATE_NO_WHERE, snippet))
        elif head == "ALTER" and len(words) > 2 and words[1] == "TABLE":
            for k in range(len(words) - 1):
                if words[k] == "DROP" and words[k + 1] == "COLUMN":
                    found.append((SQL_DROP_COLUMN, snippet))
                    break
    return found


# ---- Mongo shell / drivers -------------------------------------------------

MONGO_DROP_DATABASE = "mongo-drop-database"
MONGO_DROP_COLLECTION = "mongo-drop-collection"
MONGO_DELETE_ALL = "mongo-delete-all"
MONGO_UPDATE_ALL = "mongo-update-all"

_JS_COMMENTS = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
_MONGO_RULES = [
    (MONGO_DROP_DATABASE, re.compile(r"\.\s*dropDatabase\s*\(|\bdrop_database\s*\(", re.I)),
    (
        MONGO_DROP_COLLECTION,
        re.compile(
            r"\bdb\s*(?:\.\s*[A-Za-z_$][\w$]*|\.\s*getCollection\s*\([^)]*\)|\[[^\]]+\])\s*\.\s*drop\s*\(|\bdrop_collection\s*\(",
        ),
    ),
    (
        MONGO_DELETE_ALL,
        re.compile(
            r"\.\s*(?:deleteMany|remove|delete_many)\s*\(\s*(?:\{\s*\}\s*)?(?:,[^)]*)?\)",
        ),
    ),
    (MONGO_UPDATE_ALL, re.compile(r"\.\s*(?:updateMany|update_many)\s*\(\s*\{\s*\}\s*,")),
]


def scan_mongo(text: str) -> List[Tuple[str, str]]:
    text = _JS_COMMENTS.sub(" ", text[:MAX_TEXT])
    found: List[Tuple[str, str]] = []
    for kind, pat in _MONGO_RULES:
        m = pat.search(text)
        if m:
            start = max(0, m.start() - 20)
            found.append((kind, text[start:m.end() + 20].strip()[:160]))
    return found


# ---- Redis -----------------------------------------------------------------

REDIS_FLUSH = "redis-flush"
_REDIS_FLUSH = re.compile(r"(?i)(?:^|[\s\"';|])flush(?:all|db)\b")


def scan_redis(text: str) -> List[Tuple[str, str]]:
    m = _REDIS_FLUSH.search(text[:MAX_TEXT])
    if m:
        return [(REDIS_FLUSH, text[max(0, m.start() - 10):m.end() + 10].strip()[:160])]
    return []
