from __future__ import annotations

from typing import Iterable


def _byte_iter(data: bytes) -> Iterable[str]:
    for b in data:
        yield f"{b:02x}"


def bytes_to_inline(data: bytes) -> str:
    """Inline escaped string: "\x90\x90\x48...""" 
    return "".join(f"\\x{h}" for h in _byte_iter(data))


def bytes_to_hex(data: bytes, sep: str = " ", prefix: bool = False) -> str:
    if prefix:
        return sep.join(f"0x{h}" for h in _byte_iter(data))
    return sep.join(_byte_iter(data))


def bytes_to_c_array(data: bytes, var_name: str = "shellcode", include_len: bool = True) -> str:
    elems = ", ".join(f"0x{h}" for h in _byte_iter(data))
    arr = f"unsigned char {var_name}[] = {{{elems}}};"
    if include_len:
        arr += f"\nsize_t {var_name}_len = sizeof({var_name});"
    return arr


def bytes_to_python_bytes(data: bytes, style: str = "literal") -> str:
    if style == "list":
        elems = ", ".join(f"0x{h}" for h in _byte_iter(data))
        return f"shellcode = bytes([{elems}])"
    # default literal
    return f"shellcode = b\"{bytes_to_inline(data)}\""


def bytes_to_zig_array(data: bytes, var_name: str = "shellcode") -> str:
    elems = ", ".join(f"0x{h}" for h in _byte_iter(data))
    return f"const {var_name}: [_]u8 = .{{{elems}}};"


def bytes_to_rust_array(data: bytes, var_name: str = "SHELLCODE") -> str:
    """Rust constant byte array: const SHELLCODE: [u8; N] = [0x.., ...];"""
    elems = ", ".join(f"0x{h}" for h in _byte_iter(data))
    n = len(data)
    return f"const {var_name}: [u8; {n}] = [{elems}];"


def bytes_to_go_slice(data: bytes, var_name: str = "shellcode") -> str:
    """Go byte slice: var shellcode = []byte{0x.., ...}"""
    elems = ", ".join(f"0x{h}" for h in _byte_iter(data))
    return f"var {var_name} = []byte{{{elems}}}"
