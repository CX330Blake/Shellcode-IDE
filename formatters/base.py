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

def bytes_to_c_stub(data: bytes, var_name: str = "shellcode", bytes_per_line: int = 16) -> str:
    r"""Produce a minimal C test stub that executes the shellcode.

    Pattern:
    // gcc -z execstack shellcode.c -o shellcode
    int main(){ unsigned char shellcode[] = "\x.."; (*(void(*)())shellcode)(); }
    """
    # Break the inline string into multiple quoted lines for readability
    hex_list = [f"\\x{h}" for h in _byte_iter(data)]
    lines = []
    for i in range(0, len(hex_list), max(1, int(bytes_per_line))):
        chunk = "".join(hex_list[i:i+bytes_per_line])
        lines.append(f'      "{chunk}"')
    body = ("\n".join(lines)) if lines else '      ""'
    stub = (
        "// gcc -z execstack shellcode.c -o shellcode\n\n"
        "#include <stdio.h>\n"
        "#include <string.h>\n\n"
        "int main() {\n"
        f"  unsigned char {var_name}[] =\n"
        f"{body};\n"
        f"  (*(void (*)()){var_name})();\n"
        "  return 0;\n"
        "}\n"
    )
    return stub


def bytes_to_python_bytes(data: bytes, style: str = "literal") -> str:
    if style == "list":
        elems = ", ".join(f"0x{h}" for h in _byte_iter(data))
        return f"shellcode = bytes([{elems}])"
    # default literal
    return f"shellcode = b\"{bytes_to_inline(data)}\""


def bytes_to_python_stub(data: bytes, var_name: str = "shellcode") -> str:
    """Emit a very compact Python stub (fewest lines) to execute the bytes.

    Note: Uses POSIX mmap with RWX; may need adaptation on Windows.
    """
    inline = bytes_to_inline(data)
    return (
        "import ctypes, mmap\n"
        f"{var_name} = b\"{inline}\"\n"
        f"m = mmap.mmap(-1, len({var_name}), prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC); "
        f"m.write({var_name}); ctypes.CFUNCTYPE(None)(ctypes.addressof(ctypes.c_char.from_buffer(m)))()\n"
    )


def bytes_to_zig_array(data: bytes, var_name: str = "shellcode") -> str:
    elems = ", ".join(f"0x{h}" for h in _byte_iter(data))
    return f"const {var_name}: [_]u8 = .{{{elems}}};"


def bytes_to_zig_stub(data: bytes, var_name: str = "shellcode", bytes_per_line: int = 16) -> str:
    """Zig stub that places bytes in .text and calls them via function pointer.

    Matches the requested template for the Shellcode tab.
    """
    elems = ", ".join(f"0x{h}" for h in _byte_iter(data))
    return (
        "// zig run shellcode.zig -O ReleaseFast\n\n"
        "const std = @import(\"std\");\n\n"
        f"const {var_name} linksection(\".text\") = [_]u8{{ {elems} }};\n\n"
        "pub fn main() !void {\n"
        f"    const ptr: *const anyopaque = &{var_name};\n"
        f"    const fn_{var_name}: *const fn () callconv(.c) void = @ptrCast(@alignCast(ptr));\n"
        f"    fn_{var_name}();\n"
        "}\n"
    )


def bytes_to_rust_array(data: bytes, var_name: str = "SHELLCODE") -> str:
    """Rust constant byte array: const SHELLCODE: [u8; N] = [0x.., ...];"""
    elems = ", ".join(f"0x{h}" for h in _byte_iter(data))
    n = len(data)
    return f"const {var_name}: [u8; {n}] = [{elems}];"


def bytes_to_go_slice(data: bytes, var_name: str = "shellcode") -> str:
    """Go byte slice: var shellcode = []byte{0x.., ...}"""
    elems = ", ".join(f"0x{h}" for h in _byte_iter(data))
    return f"var {var_name} = []byte{{{elems}}}"


def bytes_to_rust_stub(data: bytes, var_name: str = "SHELLCODE", bytes_per_line: int = 16) -> str:
    """Produce a minimal Rust stub (POSIX) using RW mmap + mprotect to RX.

    Matches the requested pattern: mmap RW -> copy -> mprotect RX -> call.
    """
    # Build wrapped array body
    hex_list = [f"0x{h}" for h in _byte_iter(data)]
    step = max(1, int(bytes_per_line))
    lines = []
    for i in range(0, len(hex_list), step):
        chunk = ", ".join(hex_list[i:i + step])
        lines.append(f"    {chunk},")
    body = "\n".join(lines) if lines else ""
    n = len(data)
    return (
        "// rustc -C opt-level=3 shellcode.rs -o shellcode\n\n"
        "use std::{mem, ptr};\n"
        "extern \"C\" {\n"
        "    fn mmap(a: *mut core::ffi::c_void, l: usize, p: i32, f: i32, fd: i32, o: isize) -> *mut core::ffi::c_void;\n"
        "    fn mprotect(a: *mut core::ffi::c_void, l: usize, p: i32) -> i32;\n"
        "}\n\n"
        "const RW: i32 = 1 | 2;\n"
        "const RX: i32 = 1 | 4;\n"
        "const MAP: i32 = 2 | 0x20;\n\n"
        f"static {var_name}: [u8; {n}] = [\n{body}\n];\n\n"
        "fn main() { unsafe {\n"
        "    let p = mmap(ptr::null_mut(), 4096, RW, MAP, -1, 0);\n"
        f"    ptr::copy_nonoverlapping({var_name}.as_ptr(), p as *mut u8, {var_name}.len());\n"
        "    mprotect(p, 4096, RX);\n"
        "    mem::transmute::<*mut core::ffi::c_void, extern \"C\" fn() -> !>(p)();\n"
        "}}\n"
    )


def bytes_to_go_stub(data: bytes, var_name: str = "shellcode", bytes_per_line: int = 16) -> str:
    """Produce a minimal, runnable Go stub that executes the shellcode (POSIX via cgo mmap).

    Notes:
    - Requires cgo and a POSIX-like OS for mmap.
    - Allocates RWX memory, copies bytes, casts to function pointer in C, and calls it.
    """
    hex_list = [f"0x{h}" for h in _byte_iter(data)]
    step = max(1, int(bytes_per_line))
    total = len(hex_list)
    lines = []
    for i in range(0, total, step):
        chunk = ", ".join(hex_list[i:i+step])
        # In multi-line Go composite literals, a trailing comma is required even on the last element
        lines.append(f"    {chunk},")
    body = ("\n".join(lines)) if lines else ""
    return (
        "package main\n\n"
        "import \"C\"\n"
        "import \"unsafe\"\n\n"
        f"var {var_name} = []byte{{\n{body}\n}}\n\n"
        "func main() {\n"
        f"    p := C.alloc_exec(C.size_t(len({var_name})))\n"
        f"    C.memcpy(p, unsafe.Pointer(&{var_name}[0]), C.size_t(len({var_name})))\n"
        "    C.run(p)\n"
        "}\n"
    )
