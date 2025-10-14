from __future__ import annotations

from typing import Iterable, List, Optional
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
    ) -> bytes:
        if self.bn is None:
            raise RuntimeError("Binary Ninja API is not available for assembling.")
        arch = self._get_arch(arch_name)

        # Sanitize assembly: strip comments, labels, and directives that BN may not accept
        sanitized = self._sanitize_asm(asm_text)

        # Try BN assembler first
        try:
            data = arch.assemble(sanitized, addr)
            if data:
                return data
        except Exception as e:
            bn_err = e
        else:
            bn_err = None

        # Optional fallback: keystone, if installed
        try:
            data = self._assemble_with_keystone(sanitized, arch_name, addr)
            if data:
                return data
        except Exception:
            pass

        msg = f"Assembly failed"
        if bn_err is not None:
            msg += f": {bn_err}"
        msg += ".\nTried Binary Ninja assembler"
        try:
            import keystone  # type: ignore  # noqa: F401
            msg += " and Keystone fallback"
        except Exception:
            msg += " (Keystone not installed)"
        msg += ".\nTips: remove directives/labels, or install keystone-engine."
        raise RuntimeError(msg)

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
    def _sanitize_asm(self, text: str) -> str:
        lines: List[str] = []
        for raw in text.splitlines():
            s = raw
            # strip comments (simple)
            s = re.split(r"[;#]", s, maxsplit=1)[0]
            s = s.strip()
            if not s:
                continue
            # strip label-only lines: label:
            if re.match(r"^[A-Za-z_.$][\w.$@]*:\s*$", s):
                continue
            # drop assembler directives starting with '.'
            if re.match(r"^\s*\.", s):
                continue
            lines.append(s)
        return "\n".join(lines)

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
