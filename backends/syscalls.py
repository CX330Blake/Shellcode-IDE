from __future__ import annotations

import json
import time
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


# Data directory for baked-in syscall tables
DATA_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "syscalls"))

# Conservative in-memory cache; optionally persisted via settings.json by caller if desired
_CACHE: Dict[Tuple[str], Tuple[float, List[Dict[str, Any]]]] = {}
_TTL_SECONDS = 24 * 3600  # 24h


@dataclass
class Syscall:
    nr: int
    name: str
    args: List[str]
    ret: Optional[str] = None
    notes: Optional[str] = None


def _now() -> float:
    return time.time()


SUPPORTED_ARCHES = {"x86", "x64", "arm", "arm64"}


def canonical_arch(arch_name: str) -> Optional[str]:
    """Map a variety of IDE/BN arch names onto syscall.sh's supported set.

    Returns one of: x86, x64, arm, arm64; or None if unsupported.
    """
    a = (arch_name or "").lower()
    if a in ("x64", "x86_64", "amd64"):
        return "x64"
    if a in ("x86", "i386", "i686", "ia32", "x86_32"):
        return "x86"
    if a in ("aarch64", "arm64"):
        return "arm64"
    if a in ("arm", "armv7", "armv7l"):
        return "arm"
    return None


def map_arch_for_api(arch_name: str) -> List[str]:
    # For local tables we only use the canonical single token
    a = (arch_name or "").lower()
    can = canonical_arch(a)
    return [can] if can else []


def _data_path_for_arch(can_arch: str) -> str:
    return os.path.join(DATA_DIR, f"{can_arch}.json")


def _load_local_rows(can_arch: str) -> List[Dict[str, Any]]:
    p = _data_path_for_arch(can_arch)
    if not os.path.exists(p):
        raise RuntimeError(f"Local syscall table not found for arch {can_arch}: {p}")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def load_syscall_table(arch: str) -> Tuple[List[str], List[List[str]]]:
    """Load rich syscall table (headers + rows) for the given arch.

    Expects files at data/syscalls/{x86,x64,arm,arm64}_table.json.
    Returns (headers, rows) as strings.
    """
    can = canonical_arch(arch)
    if not can:
        supp = ", ".join(sorted(SUPPORTED_ARCHES))
        raise RuntimeError(f"Unsupported architecture for syscalls: {arch}. Supported: {supp}")
    p = os.path.join(DATA_DIR, f"{can}_table.json")
    if not os.path.exists(p):
        raise RuntimeError(f"Local syscall table file not found: {p}")
    with open(p, "r", encoding="utf-8") as f:
        obj = json.load(f)
    headers = obj.get("headers") or []
    rows = obj.get("rows") or []
    if not isinstance(headers, list) or not isinstance(rows, list):
        raise RuntimeError(f"Invalid syscall table format in {p}")
    return headers, rows


def _normalize_rows(payload: Any) -> List[Dict[str, Any]]:
    # Local files are a flat list of rows already
    if isinstance(payload, list):
        return payload
    return []


def _coerce_syscall(row: Dict[str, Any]) -> Optional[Syscall]:
    try:
        nr = row.get("nr") if "nr" in row else row.get("id")
        if nr is None:
            # some APIs use string numbers
            nr = int(row.get("number")) if row.get("number") is not None else None
        nr = int(nr)  # type: ignore
        name = str(row.get("name") or row.get("syscall") or row.get("call") or "")
        if not name:
            return None
        args = row.get("args") or row.get("arguments") or []
        if not isinstance(args, list):
            # sometimes provided as comma-separated string
            args = [a.strip() for a in str(args).split(",") if a.strip()]
        ret = row.get("ret") or row.get("return")
        notes = row.get("notes") or row.get("comment")
        return Syscall(nr=nr, name=name, args=args, ret=ret, notes=notes)
    except Exception:
        return None


def fetch_syscalls(
    arch: str,
    os_name: Optional[str] = None,
    abi: Optional[str] = None,
    use_cache: bool = True,
) -> List[Syscall]:
    """Load syscalls for an architecture from local data files.

    Only supports: x86, x64, arm, arm64.
    """
    can = canonical_arch(arch)
    if not can:
        supp = ", ".join(sorted(SUPPORTED_ARCHES))
        raise RuntimeError(f"Unsupported architecture for syscalls: {arch}. Supported: {supp}")

    key = (can,)
    if use_cache and key in _CACHE:
        ts, rows = _CACHE[key]
        if _now() - ts < _TTL_SECONDS:
            return [_s for _s in (_coerce_syscall(r) for r in rows) if _s is not None]

    rows = _load_local_rows(can)
    _CACHE[key] = (_now(), rows)
    out = [_s for _s in (_coerce_syscall(r) for r in rows) if _s is not None]
    return sorted(out, key=lambda s: s.nr)


def format_asm_snippet(sys: Syscall, arch: str, commented: bool = True) -> str:
    """Return a small assembly snippet to invoke the syscall for the given arch.

    This is best-effort and intended for Dev mode convenience.
    """
    a = arch.lower()
    if a in ("x86_64", "amd64", "x64"):
        # Linux x86_64: rax = nr; rdi,rsi,rdx,r10,r8,r9; syscall
        regs = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
        if not commented:
            return f"mov rax, {sys.nr}\nsyscall\n"
        moves = [f"mov rax, {sys.nr}"]
        for i, arg in enumerate(sys.args[:6]):
            target = regs[i]
            if arg.lower() != target:
                moves.append(f"; {arg}")
            moves.append(f"; mov {target}, <{arg or 'arg'+str(i)}>")
        return "\n".join(moves + ["syscall"]) + "\n"
    if a in ("x86", "i386", "ia32", "x86_32"):
        # Linux i386: eax = nr; ebx,ecx,edx,esi,edi,ebp; int 0x80
        regs = ["ebx", "ecx", "edx", "esi", "edi", "ebp"]
        if not commented:
            return f"mov eax, {sys.nr}\nint 0x80\n"
        moves = [f"mov eax, {sys.nr}"]
        for i, arg in enumerate(sys.args[:6]):
            target = regs[i]
            if arg.lower() != target:
                moves.append(f"; {arg}")
            moves.append(f"; mov {target}, <{arg or 'arg'+str(i)}>")
        return "\n".join(moves + ["int 0x80"]) + "\n"
    if a in ("aarch64", "arm64"):
        # Linux aarch64: x8 = nr; x0-x5 args; svc #0
        regs = ["x0", "x1", "x2", "x3", "x4", "x5"]
        if not commented:
            return f"mov x8, #{sys.nr}\nsvc #0\n"
        moves = [f"mov x8, #{sys.nr}"]
        for i, arg in enumerate(sys.args[:6]):
            target = regs[i]
            if arg.lower() != target:
                moves.append(f"; {arg}")
            moves.append(f"; mov {target}, <{arg or 'arg'+str(i)}>")
        return "\n".join(moves + ["svc #0"]) + "\n"
    if a in ("arm", "armv7", "armv7l"):
        # Linux ARM EABI: r7 = nr; r0-r6 args; svc #0
        regs = ["r0", "r1", "r2", "r3", "r4", "r5"]
        if not commented:
            return f"mov r7, #{sys.nr}\nsvc #0\n"
        moves = [f"mov r7, #{sys.nr}"]
        for i, arg in enumerate(sys.args[:6]):
            target = regs[i]
            if arg.lower() != target:
                moves.append(f"; {arg}")
            moves.append(f"; mov {target}, <{arg or 'arg'+str(i)}>")
        return "\n".join(moves + ["svc #0"]) + "\n"
    # Generic fallback
    return f"; syscall {sys.name} ({', '.join(sys.args)}) nr={sys.nr}\n"
