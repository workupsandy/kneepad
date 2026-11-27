"""Tamper-evident audit log.

Each line is one JSON object. Every entry contains the SHA-256 of the previous
entry, so editing, deleting or reordering any line breaks the chain from that
point on. Each entry is also signed with HMAC-SHA256 using a key stored next to
the log, so someone who can edit the file but cannot read the key cannot forge a
valid replacement chain.

What this does NOT protect against, stated plainly:

* Deleting entries from the END of the log leaves a valid chain. Record an
  anchor (``kneepad anchor``) somewhere the agent cannot write to, and verify
  against it with ``kneepad verify --anchor SEQ:HASH``.
* Anyone who can read the key AND write the log can forge a new chain.
* It is local. It proves integrity of a file on this machine, not that the
  machine itself was not compromised.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .util import ensure_private_dir, now_iso, kneepad_home

GENESIS = "0" * 64
_BIN = getattr(os, "O_BINARY", 0)  # Windows translates newlines unless the descriptor is binary
VERSION = 1
_COPY_ROTATION = os.name == "nt"  # Windows cannot rename a file that is open; see AuditLog._set_aside

try:  # POSIX
    import fcntl

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

    def _lock_shared(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_SH)
except ImportError:  # Windows
    import msvcrt

    def _lock(fd: int) -> None:
        # LK_LOCK gives up after about 10 seconds with OSError; keep trying for up to a minute.
        deadline = time.monotonic() + 60
        while True:
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                return
            except OSError:
                if time.monotonic() > deadline:
                    raise

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

    _lock_shared = _lock  # Windows has no shared byte-range lock here; an exclusive one is brief


def canonical(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def entry_hash(entry_without_hashes: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical(entry_without_hashes).encode("ascii")).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    count: int = 0
    head_seq: int = 0
    head_hash: str = GENESIS
    error: str = ""
    hmac_verified: bool = False
    warnings: List[str] = field(default_factory=list)


class _Rotated(Exception):
    pass


class _Stale(Exception):
    """The file we locked is no longer the live log (another writer rotated it while we waited)."""


class AuditLog:
    def __init__(self, home: Optional[str] = None) -> None:
        self.home = home or kneepad_home()
        self.path = os.path.join(self.home, "audit.jsonl")
        self.key_path = os.path.join(self.home, "key")
        self.anchor_path = os.path.join(self.home, "anchors.txt")

    # ---- key -----------------------------------------------------------
    def ensure_key(self) -> bytes:
        ensure_private_dir(self.home)
        key = self._read_key()
        if key is None:
            # Write the key to a private temp file, then publish it atomically with link(), which
            # fails if another process got there first. Readers never see a half-written key.
            tmp = os.path.join(self.home, f".key.{os.getpid()}.{secrets.token_hex(4)}")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BIN, 0o600)
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write(secrets.token_hex(32))
                    fh.flush()
                    os.fsync(fh.fileno())
                try:
                    os.link(tmp, self.key_path)
                except FileExistsError:
                    pass
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            key = self._read_key()
        if key is None:
            raise OSError("could not read the audit key")
        return key

    def _read_key(self) -> Optional[bytes]:
        try:
            with open(self.key_path, "r", encoding="ascii") as fh:
                hexkey = fh.read().strip()
            return bytes.fromhex(hexkey) if hexkey else None
        except (OSError, ValueError):
            return None

    # ---- append --------------------------------------------------------
    def _last_line(self, fd: int) -> Optional[bytes]:
        size = os.fstat(fd).st_size
        if size == 0:
            return None
        chunk = 65536
        data = b""
        pos = size
        while pos > 0:
            read = min(chunk, pos)
            pos -= read
            os.lseek(fd, pos, os.SEEK_SET)  # portable: os.pread does not exist on Windows
            data = os.read(fd, read) + data
            body = data.rstrip(b"\n")
            if b"\n" in body or pos == 0:
                break
        body = data.rstrip(b"\n")
        return body.rsplit(b"\n", 1)[-1] if body else None

    def append_if_empty(self, event: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Append only when the log has no entries yet, atomically (parallel `init` calls write one init event)."""
        return self.append(event, data, only_if_empty=True)

    def append(self, event: str, data: Dict[str, Any], only_if_empty: bool = False) -> Optional[Dict[str, Any]]:
        note = False
        for _attempt in range(50):
            try:
                return self._append(event, {**data, "note": "previous log was corrupt and was set aside"} if note else data,
                                    only_if_empty)
            except _Rotated:
                note = True
            except _Stale:
                continue
        raise OSError("audit log kept changing underneath this writer; giving up")

    def _is_live(self, fd: int) -> bool:
        """True when ``fd`` still refers to the file currently at self.path (not one a peer rotated away)."""
        try:
            a, b = os.stat(self.path), os.fstat(fd)
        except OSError:
            return False
        if not a.st_ino or not b.st_ino:  # some Windows filesystems report no inode: assume live
            return True
        return (a.st_ino, a.st_dev) == (b.st_ino, b.st_dev)

    def _set_aside(self, fd: int, dest: str) -> None:
        """Move the corrupt log out of the way while this writer still holds it open and locked.

        POSIX renames the file. Windows refuses to rename a file that any handle has open (WinError 32), including ours, so
        there the evidence is copied to ``dest`` and the live file is emptied in place; peers waiting on the lock then see
        an empty log and start a fresh chain, exactly as they do after a rename."""
        if not _COPY_ROTATION:
            os.replace(self.path, dest)
            return
        size = os.fstat(fd).st_size
        out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BIN, 0o600)
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            left = size
            while left > 0:
                chunk = os.read(fd, min(left, 1 << 20))
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    view = view[os.write(out, view):]
                left -= len(chunk)
            os.fsync(out)
        finally:
            os.close(out)
        os.ftruncate(fd, 0)

    def _append(self, event: str, data: Dict[str, Any], only_if_empty: bool = False) -> Optional[Dict[str, Any]]:
        key = self.ensure_key()
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND | _BIN, 0o600)
        try:
            _lock(fd)
            try:
                if not self._is_live(fd):
                    raise _Stale()
                last_raw = self._last_line(fd)
                if only_if_empty and last_raw is not None:
                    return None
                last: Optional[Dict[str, Any]] = None
                if last_raw is not None:
                    try:
                        last = json.loads(last_raw)
                        if not isinstance(last, dict) or "hash" not in last or "seq" not in last:
                            raise ValueError("not an entry")
                    except ValueError:
                        # Corrupt tail (for example a crash mid-write): keep the evidence
                        # and start a fresh chain.
                        # Rotate while still holding the lock, then retry on a fresh file.
                        dest = f"{self.path}.corrupt-{int(time.time())}"
                        n = 0
                        while os.path.exists(dest):
                            n += 1
                            dest = f"{self.path}.corrupt-{int(time.time())}-{n}"
                        self._set_aside(fd, dest)
                        raise _Rotated()
                seq = (last["seq"] + 1) if last else 1
                prev = last["hash"] if last else GENESIS
                body = {"v": VERSION, "seq": seq, "ts": now_iso(), "event": event, "data": data, "prev": prev}
                h = entry_hash(body)
                entry = dict(body)
                entry["hash"] = h
                entry["hmac"] = hmac.new(key, h.encode("ascii"), hashlib.sha256).hexdigest()
                os.write(fd, (canonical(entry) + "\n").encode("ascii"))
                os.fsync(fd)
                return entry
            finally:
                _unlock(fd)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    # ---- read / verify -------------------------------------------------
    def read_all(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            with open(self.path, "rb") as fh:
                for raw in fh:
                    raw = raw.rstrip(b"\n")
                    if raw:
                        try:
                            out.append(json.loads(raw))
                        except ValueError:
                            continue
        except FileNotFoundError:
            pass
        return out

    def tail(self, n: int = 20) -> List[Dict[str, Any]]:
        return self.read_all()[-n:] if n > 0 else []

    def verify(self, anchor: Optional[str] = None) -> VerifyResult:
        res = VerifyResult(ok=True)
        key = self._read_key()
        saw_hmac = False
        expected_prev = GENESIS
        expected_seq = 1
        anchor_seq: Optional[int] = None
        anchor_hash: Optional[str] = None
        if anchor:
            try:
                s, h = anchor.split(":", 1)
                anchor_seq, anchor_hash = int(s), h.strip().lower()
            except ValueError:
                return VerifyResult(ok=False, error="anchor must look like SEQ:HASH")
        anchor_found = False
        try:
            fh = open(self.path, "rb")
        except FileNotFoundError:
            if anchor:
                return VerifyResult(ok=False, error="no audit log exists but an anchor was supplied")
            return res
        with fh:
            try:
                # Wait for any append in progress, so a half-written last line is never mistaken for tampering.
                # Closing the file at the end of this block releases the lock.
                _lock_shared(fh.fileno())
            except (OSError, ValueError):
                pass
            for lineno, raw in enumerate(fh, 1):
                raw = raw.rstrip(b"\n")
                if not raw:
                    return self._fail(res, f"line {lineno}: blank line inside the log")
                try:
                    text = raw.decode("ascii")
                except UnicodeDecodeError:
                    return self._fail(res, f"line {lineno}: non-ASCII bytes (entries are ASCII-only)")
                try:
                    e = json.loads(text)
                except ValueError:
                    return self._fail(res, f"line {lineno}: not valid JSON")
                if not isinstance(e, dict):
                    return self._fail(res, f"line {lineno}: not an object")
                for k in ("v", "seq", "ts", "event", "data", "prev", "hash"):
                    if k not in e:
                        return self._fail(res, f"line {lineno}: missing field {k!r}")
                if canonical(e) != text:
                    return self._fail(res, f"line {lineno}: not in canonical form (edited or re-serialised)")
                if e["seq"] != expected_seq:
                    return self._fail(res, f"line {lineno}: sequence is {e['seq']}, expected {expected_seq} (entry removed, inserted or reordered)")
                if e["prev"] != expected_prev:
                    return self._fail(res, f"line {lineno}: previous-hash does not match the entry before it (chain broken)")
                body = {k: v for k, v in e.items() if k not in ("hash", "hmac")}
                if entry_hash(body) != e["hash"]:
                    return self._fail(res, f"line {lineno}: contents do not match their hash (entry was modified)")
                if "hmac" in e:
                    saw_hmac = True
                    if key is not None:
                        want = hmac.new(key, e["hash"].encode("ascii"), hashlib.sha256).hexdigest()
                        if not hmac.compare_digest(want, str(e["hmac"])):
                            return self._fail(res, f"line {lineno}: signature does not verify (forged or key changed)")
                elif key is not None:
                    return self._fail(res, f"line {lineno}: entry is unsigned although a key exists")
                if anchor_seq is not None and e["seq"] == anchor_seq:
                    if e["hash"] != anchor_hash:
                        return self._fail(res, f"anchor mismatch at seq {anchor_seq}: the log was rewritten")
                    anchor_found = True
                expected_prev = e["hash"]
                expected_seq += 1
                res.count += 1
                res.head_seq = e["seq"]
                res.head_hash = e["hash"]
        if anchor and not anchor_found:
            return self._fail(res, f"anchor seq {anchor_seq} not found: the log was truncated")
        if saw_hmac and key is None:
            res.warnings.append("entries are signed but the key file is missing, so signatures were not verified")
        res.hmac_verified = bool(saw_hmac and key is not None)
        return res

    @staticmethod
    def _fail(res: VerifyResult, msg: str) -> VerifyResult:
        res.ok = False
        res.error = msg
        return res

    # ---- anchors -------------------------------------------------------
    def anchor(self) -> Optional[str]:
        """Record the current head as SEQ:HASH, to be stored somewhere the agent cannot write."""
        res = self.verify()
        if not res.ok or res.head_seq == 0:
            return None
        line = f"{res.head_seq}:{res.head_hash}"
        ensure_private_dir(self.home)
        with open(self.anchor_path, "a", encoding="ascii") as fh:
            fh.write(f"{now_iso()} {line}\n")
        return line
