from __future__ import annotations

from typing import Iterable, List, Optional
import os
import re


class BNAdapter:
    """Thin wrapper around Binary Ninja APIs for assemble/disassemble.

    If `bn_api` is None or BN is not available, assemble/disassemble will raise.
    """

    def __init__(self, bn_api=None):
        self.bn = bn_api

    # Discovery
    def list_architectures(self) -> List[str]:
        # Try BN registry, fallback to common set
        if self.bn is not None:
            try:
                # BN may provide Architecture.list or .registered
                arch_names = []
                try:
                    # Newer APIs
                    arch_names = [a.name for a in self.bn.Architecture]
                except Exception:
                    pass
                if not arch_names:
                    # Conservative defaults if enumeration fails
                    arch_names = [
                        "x86",
                        "x86_64",
                        "aarch64",
                        "armv7",
                        "mips32",
                        "ppc",
                    ]
                # Filter to only those accessible
                available = []
                for n in arch_names:
                    try:
                        _ = self.bn.Architecture[n]
                        available.append(n)
                    except Exception:
                        continue
                if available:
                    return sorted(set(available))
            except Exception:
                pass
        # Fallback outside BN
        return ["x86_64", "x86", "aarch64"]

    def list_platforms(self) -> List[str]:
        if self.bn is not None:
            # Try a handful of common platforms; full enumeration isn't stable across versions
            candidates = [
                "linux-x86_64",
                "linux-x86",
                "linux-aarch64",
                "windows-x86_64",
                "windows-x86",
                "mac-x86_64",
                "mac-arm64",
            ]
            available = []
            for n in candidates:
                try:
                    _ = self.bn.Platform[n]
                    available.append(n)
                except Exception:
                    continue
            if available:
                return available
        return []

    # Core functionality
    def assemble(
        self,
        asm_text: str,
        arch_name: str,
        platform_name: Optional[str] = None,
        addr: int = 0,
        allow_labels: bool = False,
    ) -> bytes:
        """Assemble assembly text into bytes.

        - When `allow_labels` is False (default), aggressively sanitize by
          removing labels/directives for shellcode-friendly, line-oriented
          diagnostics.
        - When `allow_labels` is True, perform block assembly: preserve labels
          and forward references (only strip comments/blank lines). Also tries
          to inline simple NASM/YASM `%include` directives relative to CWD.
        """
        # Optionally expand simple include directives in block mode
        src_text = asm_text
        if allow_labels:
            try:
                src_text = self._preprocess_includes(src_text, base_dirs=[os.getcwd()])
            except Exception as inc_err:
                raise RuntimeError(f"Preprocessor error: {inc_err}")
        # Sanitize assembly per mode
        sanitized, line_map = self._sanitize_asm(src_text, keep_labels=bool(allow_labels))

        # Try Keystone assembler first (default)
        ks_err = None
        try:
            data = self._assemble_with_keystone(sanitized, arch_name, addr)
            if data:
                return data
        except Exception as e:
            ks_err = str(e)

        # Fallback to Binary Ninja assembler if available
        if self.bn is not None:
            try:
                arch = self._get_arch(arch_name)
                data = arch.assemble(sanitized, addr)
                if data:
                    return data
            except Exception as e:
                # Try BN-friendly rewrites
                try:
                    rewritten = self._bn_rewrite_movabs_imm64(sanitized)
                    if rewritten != sanitized:
                        data = arch.assemble(rewritten, addr)
                        if data:
                            return data
                except Exception:
                    pass
                # Augment BN error with original line mapping
                bn_err = self._augment_bn_error(e, sanitized, line_map)
            else:
                bn_err = None
        else:
            bn_err = "Binary Ninja API is not available"

        # Both assemblers failed
        msg = f"Assembly failed"
        if ks_err:
            msg += f": {ks_err}"
        if bn_err and ks_err:
            msg += f"\nBinary Ninja fallback also failed: {bn_err}"
        elif bn_err:
            msg += f": {bn_err}"
        msg += ".\nTried Keystone assembler"
        if self.bn is not None:
            msg += " and Binary Ninja fallback"
        msg += ".\nTips: use 'movabs' for 64-bit immediates, "
        msg += ("avoid unsupported directives if using labels." if allow_labels else "remove directives/labels or enable 'Allow labels'.")
        raise RuntimeError(msg)

    def _bn_rewrite_movabs_imm64(self, asm: str) -> str:
        """Rewrite 'mov reg, imm64' into 'movabs reg, imm64' for BN compatibility.

        BN sometimes prefers 'movabs' for 64-bit immediates into 64-bit regs.
        This preserves semantics and helps common shellcode snippets assemble.
        """
        out_lines: list[str] = []
        # Support optional leading label: 'label: mov rax, IMM'
        pat = re.compile(
            r"^\s*(?:(?P<label>[A-Za-z_.$][\w.$@]*):\s*)?mov\s+"
            r"(?P<reg>r(?:[0-9]+|[abcd]x|[sb]p|[sd]i)),\s*(?P<imm>0x[0-9a-fA-F]+|\d+)\s*$",
            re.IGNORECASE,
        )
        for line in asm.splitlines():
            m = pat.match(line)
            if not m:
                out_lines.append(line)
                continue
            reg, imm = m.group("reg"), m.group("imm")
            label = m.group("label")
            is_hex = imm.lower().startswith('0x')
            try:
                val = int(imm, 16 if is_hex else 10)
            except Exception:
                val = None
            # Only rewrite when value requires 64-bit immediate
            if val is None or val <= 0xFFFFFFFF:
                out_lines.append(line)
                continue
            prefix = f"{label}: " if label else ""
            new_line = f"{prefix}movabs {reg}, {imm}"
            out_lines.append(new_line)
        return "\n".join(out_lines)

    def disassemble(self, data: bytes, arch_name: str, addr: int = 0) -> List[str]:
        if self.bn is None:
            raise RuntimeError("Binary Ninja API is not available for disassembly.")
        arch = self._get_arch(arch_name)
        pos = 0
        lines: List[str] = []
        view_addr = addr
        b = bytes(data)
        # Heuristic: Use get_instruction_text in a loop
        while pos < len(b):
            try:
                tokens, length = arch.get_instruction_text(b[pos:], view_addr + pos)
            except Exception as e:
                # Emit undecoded remainder and break
                lines.append(f"db {b[pos:].hex()}")
                break
            if not length or length < 0:
                # Avoid infinite loop on bad length
                lines.append(f"db {b[pos:].hex()}")
                break
            txt = "".join([t.text for t in tokens]) if tokens else "(bad)"
            bytes_hex = b[pos : pos + length].hex()
            lines.append(f"{txt}")
            pos += length
        return lines

    def disassemble_detailed(self, data: bytes, arch_name: str, addr: int = 0) -> List[str]:
        """Objdump-like lines: address: bytes  mnemonic operands"""
        if self.bn is None:
            raise RuntimeError("Binary Ninja API is not available for disassembly.")
        arch = self._get_arch(arch_name)
        pos = 0
        lines: List[str] = []
        base = addr
        b = bytes(data)
        while pos < len(b):
            try:
                tokens, length = arch.get_instruction_text(b[pos:], base + pos)
            except Exception:
                rem = b[pos:]
                lines.append(f"{base+pos:08x}:  {rem.hex(' ')}\t.db")
                break
            if not length or length < 0:
                rem = b[pos:]
                lines.append(f"{base+pos:08x}:  {rem.hex(' ')}\t.db")
                break
            txt = "".join([t.text for t in tokens]) if tokens else "(bad)"
            bytes_hex = b[pos : pos + length].hex(" ")
            lines.append(f"{base+pos:08x}:  {bytes_hex:<20}\t{txt}")
            pos += length
        return lines

    def disassemble_spans(self, data: bytes, arch_name: str, addr: int = 0):
        """Return list of (start_offset, length) for each instruction line."""
        if self.bn is None:
            raise RuntimeError("Binary Ninja API is not available for disassembly.")
        arch = self._get_arch(arch_name)
        pos = 0
        b = bytes(data)
        spans = []
        while pos < len(b):
            try:
                _tokens, length = arch.get_instruction_text(b[pos:], addr + pos)
            except Exception:
                spans.append((pos, len(b) - pos))
                break
            if not length or length < 0:
                spans.append((pos, len(b) - pos))
                break
            spans.append((pos, length))
            pos += length
        return spans

    # Internals
    def _get_arch(self, name: str):
        try:
            return self.bn.Architecture[name]
        except Exception:
            raise RuntimeError(f"Architecture not found: {name}")

    # --- helpers ---
    def _sanitize_asm(self, text: str, keep_labels: bool = False) -> tuple[str, List[int]]:
        """Return (sanitized_text, line_map) where line_map[i] = original line number (1-based)
        for sanitized line i.

        If keep_labels is True, retain label definitions and label+instruction
        lines, only stripping comments and blanks. Otherwise, drop labels and
        assembler directives to minimize surprises during shellcode assembly.
        """
        lines: List[str] = []
        mapping: List[int] = []
        for idx, raw in enumerate(text.splitlines(), start=1):
            s = raw
            # strip comments (simple)
            s = re.split(r"[;#]", s, maxsplit=1)[0]
            s = s.strip()
            if not s:
                continue
            if not keep_labels:
                # strip label-only lines: label:
                if re.match(r"^[A-Za-z_.$][\w.$@]*:\s*$", s):
                    continue
                # strip leading label when followed by instruction on same line: label: instr ...
                m = re.match(r"^([A-Za-z_.$][\w.$@]*):\s*(.+)$", s)
                if m:
                    s = m.group(2).strip()
                    if not s:
                        continue
                # drop assembler directives starting with '.'
                if re.match(r"^\s*\.", s):
                    continue
                # drop NASM/YASM preprocessor lines beginning with '%'
                if s.startswith('%'):
                    continue
            else:
                # In block mode, surface unsupported preprocessor directives (includes are expanded earlier)
                if s.startswith('%'):
                    raise RuntimeError(f"Unsupported NASM/YASM directive: '{s}'. Inline or remove macros/defines.")
                # Drop common assembler declarations and section directives
                if re.match(r"^\s*\.", s):
                    # e.g., .intel_syntax, .text, .globl
                    continue
                if re.match(r"^(?i)(global|extern|extrn)\b", s):
                    continue
            lines.append(s)
            mapping.append(idx)
        return "\n".join(lines), mapping

    def _preprocess_includes(self, text: str, base_dirs: Optional[List[str]] = None) -> str:
        """Inline simple NASM/YASM `%include` directives.

        Supports: %include "file", %include 'file', %include file
        Returns expanded text or raises with a helpful message if missing.
        """
        base_dirs = list(base_dirs or [])
        seen: set[str] = set()

        def _resolve(path: str) -> Optional[str]:
            if os.path.isabs(path):
                return path if os.path.isfile(path) else None
            for d in base_dirs:
                cand = os.path.join(d, path)
                if os.path.isfile(cand):
                    return cand
            return None

        def _expand(buf: str) -> str:
            out: List[str] = []
            for raw in buf.splitlines():
                line = raw.strip()
                m = re.match(r"^%?include\s+(?:'([^']+)'|\"([^\"]+)\"|([^'\"\s]+))\s*$", line, re.IGNORECASE)
                if m:
                    inc_path = m.group(1) or m.group(2) or m.group(3)
                    full = _resolve(inc_path)
                    if not full:
                        where = ", ".join(base_dirs) if base_dirs else os.getcwd()
                        raise RuntimeError(f"include not found: {inc_path} (searched: {where})")
                    if full in seen:
                        # prevent recursive loops
                        continue
                    seen.add(full)
                    try:
                        with open(full, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                    except Exception as e:
                        raise RuntimeError(f"unable to read include '{inc_path}': {e}")
                    out.append(_expand(content))
                else:
                    out.append(raw)
            return "\n".join(out)

        return _expand(text)

    def _augment_bn_error(self, err: Exception, sanitized: str, line_map: List[int]) -> Exception:
        """Try to remap BN error line numbers to the user's original input and add context."""
        try:
            msg = str(err)
        except Exception:
            return err
        # Look for patterns like 'input:1:' or 'line 1'
        m = re.search(r"input:(\d+)", msg)
        line_no = None
        if m:
            try:
                line_no = int(m.group(1))
            except Exception:
                line_no = None
        else:
            m = re.search(r"line\s+(\d+)", msg, flags=re.IGNORECASE)
            if m:
                try:
                    line_no = int(m.group(1))
                except Exception:
                    line_no = None
        if line_no is None:
            return err
        # Map to original line number if available
        orig_line = None
        if 1 <= line_no <= len(line_map):
            orig_line = line_map[line_no - 1]
        # Extract the sanitized line content for quick hint
        try:
            san_lines = sanitized.splitlines()
            bad_src = san_lines[line_no - 1] if 1 <= line_no <= len(san_lines) else ""
        except Exception:
            bad_src = ""
        hint = []
        if bad_src:
            hint.append(f"at '{bad_src}'")
            # Heuristic: detect possible AT&T syntax which BN doesn't accept
            if any(ch in bad_src for ch in ('%', '$')):
                hint.append("looks like AT&T syntax; use Intel or install Keystone (ATT)")
            # Heuristic: invalid operand count often due to extra commas
            if bad_src.count(',') >= 2:
                hint.append("too many operands (extra comma?)")
        loc = f"original line {orig_line}" if orig_line is not None else f"sanitized line {line_no}"
        augmented = f"{msg} [{loc}{('; ' + '; '.join(hint)) if hint else ''}]"
        try:
            return RuntimeError(augmented)
        except Exception:
            return err

    def _assemble_with_keystone(self, asm: str, arch_name: str, addr: int) -> bytes:
        try:
            import keystone as ks  # type: ignore
        except Exception as exc:
            raise RuntimeError("Keystone not available") from exc

        arch_l = (arch_name or "").lower()
        if arch_l in ("x86_64", "amd64", "x64"):
            ks_arch, ks_mode = ks.KS_ARCH_X86, ks.KS_MODE_64
        elif arch_l in ("x86", "i386", "i686"):
            ks_arch, ks_mode = ks.KS_ARCH_X86, ks.KS_MODE_32
        elif arch_l in ("aarch64", "arm64"):
            ks_arch, ks_mode = ks.KS_ARCH_ARM64, ks.KS_MODE_LITTLE_ENDIAN
        elif arch_l in ("armv7", "armv7l", "arm"):
            ks_arch, ks_mode = ks.KS_ARCH_ARM, ks.KS_MODE_ARM
        elif arch_l.startswith("mips"):
            ks_arch, ks_mode = ks.KS_ARCH_MIPS, ks.KS_MODE_MIPS32
            ks_mode |= ks.KS_MODE_LITTLE_ENDIAN
        else:
            raise RuntimeError(f"Keystone fallback unsupported for arch: {arch_name}")

        try:
            engine = ks.Ks(ks_arch, ks_mode)
            # Detect AT&T syntax for x86 when '%' or '$' appear
            try:
                if ks_arch == ks.KS_ARCH_X86 and any(ch in asm for ch in ('%', '$')):
                    engine.syntax = ks.KS_OPT_SYNTAX_ATT  # type: ignore[attr-defined]
            except Exception:
                # Older bindings may require option API
                try:
                    if ks_arch == ks.KS_ARCH_X86 and any(ch in asm for ch in ('%', '$')):
                        engine.option(ks.KS_OPT_SYNTAX, ks.KS_OPT_SYNTAX_ATT)
                except Exception:
                    pass
            encoding, _ = engine.asm(asm, addr)
            return bytes(encoding)
        except Exception as e:
            raise RuntimeError(f"Keystone assembly failed: {e}")

    # Optional: decompile to C-like text when decompiler is available
    def decompile(self, data: bytes, arch_name: str, addr: int = 0) -> str:
        if self.bn is None:
            raise RuntimeError("Binary Ninja API is not available for decompilation.")
        arch = self._get_arch(arch_name)
        bv = None
        try:
            # Create an ephemeral BinaryView backed by bytes
            bv = self.bn.BinaryView.new(bytearray(data))
        except Exception:
            try:
                # Fallback to Raw view type if available
                raw = self.bn.BinaryViewType["Raw"]
                bv = raw.create(bytearray(data))
            except Exception as e:
                raise RuntimeError(f"Unable to create BinaryView for decompilation: {e}")
        try:
            bv.arch = arch
        except Exception:
            pass
        try:
            # Basic setup: add function at entry and run analysis
            bv.add_function(addr)
        except Exception:
            pass
        try:
            bv.update_analysis_and_wait()
        except Exception:
            pass
        func = None
        try:
            func = bv.get_function_at(addr)
        except Exception:
            func = None
        if func is None:
            try:
                func = next(iter(bv.functions))
            except Exception:
                func = None
        if func is None:
            raise RuntimeError("No function to decompile.")

        # Try official decompiler if available
        try:
            decomp_mod = getattr(self.bn, "decompiler", None)
            if decomp_mod is not None:
                dc = decomp_mod.get_default_decompiler(bv)
                if dc is not None:
                    res = dc.decompile_function(func)
                    # BN API typically exposes .text on result
                    text = getattr(res, "text", None)
                    if text:
                        return text
        except Exception:
            pass

        # Fallback: dump HLIL if present
        try:
            hlil = func.hlil
            # Simple textual representation of HLIL
            lines: List[str] = []
            for block in hlil:
                for ins in block:
                    lines.append(str(ins))
            if lines:
                return "\n".join(lines)
        except Exception:
            pass

        # Last resort
        raise RuntimeError("Decompiler not available or failed to produce output.")
