from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Pattern, Set, Dict


@dataclass
class TransformRule:
    name: str
    description: str
    archs: List[str]
    enabled: bool
    apply: Callable[[str], str]


@dataclass
class Proposal:
    rule: TransformRule
    before: str
    after: str


def _normalize_asm(asm: str) -> List[str]:
    return [ln.rstrip() for ln in asm.splitlines()]


def _join(lines: List[str]) -> str:
    return "\n".join(lines)


def _normalize_reg_to_64(reg: str) -> Optional[str]:
    r = reg.lower()
    base_map: Dict[str, str] = {
        # classic
        'al': 'rax', 'ax': 'rax', 'eax': 'rax', 'rax': 'rax',
        'bl': 'rbx', 'bx': 'rbx', 'ebx': 'rbx', 'rbx': 'rbx',
        'cl': 'rcx', 'cx': 'rcx', 'ecx': 'rcx', 'rcx': 'rcx',
        'dl': 'rdx', 'dx': 'rdx', 'edx': 'rdx', 'rdx': 'rdx',
        'sil': 'rsi', 'si': 'rsi', 'esi': 'rsi', 'rsi': 'rsi',
        'dil': 'rdi', 'di': 'rdi', 'edi': 'rdi', 'rdi': 'rdi',
        'bpl': 'rbp', 'bp': 'rbp', 'ebp': 'rbp', 'rbp': 'rbp',
        'spl': 'rsp', 'sp': 'rsp', 'esp': 'rsp', 'rsp': 'rsp',
    }
    if r in base_map:
        return base_map[r]
    if r.startswith('r') and r.endswith('b') and r[1:-1].isdigit():
        n = int(r[1:-1])
        if 8 <= n <= 15:
            return f"r{n}"
    if r.startswith('r') and r.endswith('w') and r[1:-1].isdigit():
        n = int(r[1:-1])
        if 8 <= n <= 15:
            return f"r{n}"
    if r.startswith('r') and r.endswith('d') and r[1:-1].isdigit():
        n = int(r[1:-1])
        if 8 <= n <= 15:
            return f"r{n}"
    if r.startswith('r') and r[1:].isdigit():
        n = int(r[1:])
        if 8 <= n <= 15:
            return f"r{n}"
    return None


def _collect_used_gprs(lines: List[str]) -> Set[str]:
    used: Set[str] = set()
    # rough tokenization for registers; include various sizes
    reg_re = re.compile(r"\b(r1?[0-5]|r[0-9]|e?[abcd]x|[abcd]l|[re]?(si|di|bp|sp)|r[8-9]|r1[0-5]|[abcd]x|[abcd]h)\b", re.I)
    for ln in lines:
        for m in reg_re.finditer(ln):
            base = _normalize_reg_to_64(m.group(0))
            if base:
                used.add(base)
    return used


def _choose_zero_reg(arch: str, used: Set[str]) -> str:
    a = (arch or '').lower()
    if 'x86_64' in a or a == 'x64' or 'x86' in a:
        # prefer a single reusable volatile register; favor r11 when available
        candidates64 = ['r11', 'r10', 'r9', 'r8', 'rcx', 'rdx', 'rax']
        for r in candidates64:
            if r not in used:
                return r
        return 'rax'
    else:
        # 32-bit preference: ecx, edx, ebx, eax
        candidates32 = ['ecx', 'edx', 'ebx', 'eax']
        for r in candidates32:
            # normalize check
            base = _normalize_reg_to_64(r)
            if base not in used:
                return r
        return 'eax'


def _x86_push_zero(lines: List[str], arch: str = "x86_64") -> List[str]:
    out: List[str] = []
    # Capture indentation, optional size token, and any immediate that equals zero
    # Matches variants like:
    #   push 0
    #   push    0x0
    #   push 0x00000000
    #   push dword 0
    #   push qword 000h
    push0 = re.compile(
        r"^(?P<indent>\s*)push(?P<sep>\s+)"  # mnemonic + spaces
        r"(?:(?:byte|word|dword|qword)\s+)?"   # optional size
        r"(?P<imm>(?:0[xX]0+|0+|0)(?:h)?)"     # zero immediate in common forms
        r"\s*(?P<cmt>;.*)?$",
        re.I,
    )
    used = _collect_used_gprs(lines)

    def _reg_aliases(base64: str) -> List[str]:
        b = (base64 or '').lower()
        fam: List[str] = []
        if b in ('rax','rbx','rcx','rdx'):
            fam = [b, 'e'+b[1:], b[2:]+'x', b[2:]+'l']
        elif b in ('rsi','rdi','rbp','rsp'):
            # 8-bit low forms for SI/DI/BP/SP on x86_64 are sil/dil/bpl/spl
            low8 = {'rsi':'sil','rdi':'dil','rbp':'bpl','rsp':'spl'}[b]
            fam = [b, 'e'+b[1:], b[1:], low8]
        elif b.startswith('r') and b[1:].isdigit():
            # r8..r15 family
            fam = [b, b+'d', b+'w', b+'b']
        elif b in ('eax','ebx','ecx','edx'):
            fam = [b, b[1:]+'x', b[1:]+'l']
        elif b in ('esi','edi','ebp','esp'):
            fam = [b, b[1:], {'esi':'sil','edi':'dil','ebp':'bpl','esp':'spl'}[b]]
        else:
            # fallback: just itself
            fam = [b]
        return fam

    def _find_reusable_zero_reg(start_idx: int) -> Optional[str]:
        """Scan backward for a prior 'xor R,R' and ensure R is not overwritten before start_idx.

        Returns a base 64-bit register name suitable for reuse (e.g., 'r11'), or None.
        """
        zero_re = re.compile(r"^\s*xor\s+([A-Za-z0-9]+)\s*,\s*([A-Za-z0-9]+)\s*(?:;.*)?$", re.I)
        write_mnems = (
            'mov','lea','xor','or','and','add','sub','adc','sbb','imul','idiv','mul','div','not','neg',
            'inc','dec','shl','shr','sal','sar','rol','ror','bswap','xchg','pop','set','cmov'
        )
        for k in range(start_idx - 1, -1, -1):
            ln = lines[k]
            m = zero_re.match(ln)
            if not m:
                continue
            r1, r2 = m.group(1), m.group(2)
            b1 = _normalize_reg_to_64(r1) or r1.lower()
            b2 = _normalize_reg_to_64(r2) or r2.lower()
            if b1 != b2:
                continue
            # ensure no overwrite of this register family between k+1 and start_idx-1
            aliases = _reg_aliases(b1)
            alias_re = re.compile(r"^\s*([A-Za-z.]+)\s+([^,;]+)", re.I)
            overwritten = False
            for t in range(k + 1, start_idx):
                mt = alias_re.match(lines[t])
                if not mt:
                    continue
                mnem = mt.group(1).lower()
                op1 = (mt.group(2) or '').strip()
                # Clean addressing like 'qword ptr [rax]' or memory; only consider bare registers
                op1_token = op1.split()[0]
                op1_token = op1_token.strip(',').lower()
                if mnem in write_mnems and op1_token in aliases:
                    overwritten = True
                    break
            if not overwritten:
                return b1
        return None
    i = 0
    n = len(lines)
    while i < n:
        m = push0.match(lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue
        # Start of a consecutive push-0 block
        indent = m.group('indent') or ""
        sep = m.group('sep') or " "
        # Collect comments per line to preserve them
        comments: List[str] = [m.group('cmt') or ""]
        j = i + 1
        while j < n:
            mj = push0.match(lines[j])
            if not mj:
                break
            comments.append(mj.group('cmt') or "")
            j += 1
        # Choose a reusable zero register once for the block; prefer an existing zeroed reg
        zreg = _find_reusable_zero_reg(i)
        if zreg is None:
            zreg = _choose_zero_reg(arch, used)
            used.add(_normalize_reg_to_64(zreg) or zreg)
            # Emit a single xor to zero the register, then push it repeatedly
            out.append(f"{indent}xor{sep}{zreg}, {zreg}")
        # Attach the original first-line comment to the first push to keep context
        for k in range(i, j):
            cmt = comments[k - i]
            out.append(f"{indent}push{sep}{zreg}{cmt}")
        i = j
    return out


def _x86_mov_reg_imm8(lines: List[str]) -> List[str]:
    out: List[str] = []
    # Capture indentation, spacing, register and immediate
    mov_re = re.compile(
        r"^(?P<indent>\s*)mov(?P<sep>\s+)(?P<reg>r(?:[0-9]{1,2}|[abcd]x|[sb]p|si|di)|e[abcd]x|e[sb]p|e[sd]i)\s*,\s*(?P<imm>0x[0-9a-fA-F]+|\d+)\s*(?P<cmt>;.*)?$",
        re.I,
    )
    for ln in lines:
        m = mov_re.match(ln)
        if not m:
            out.append(ln)
            continue
        imm_s = m.group('imm')
        indent = m.group('indent') or ""
        sep = m.group('sep') or " "
        cmt = m.group('cmt') or ""
        reg = m.group('reg').lower()
        try:
            imm = int(imm_s, 16) if imm_s.lower().startswith("0x") else int(imm_s, 10)
        except Exception:
            out.append(ln)
            continue
        if 0 <= imm <= 0xFF:
            # Map 64-bit regs to 8-bit low regs (x86_64)
            reg8_map = {
                'rax': 'al', 'rbx': 'bl', 'rcx': 'cl', 'rdx': 'dl',
                'rsi': 'sil', 'rdi': 'dil', 'rbp': 'bpl', 'rsp': 'spl',
                'eax': 'al', 'ebx': 'bl', 'ecx': 'cl', 'edx': 'dl',
                'esi': 'sil', 'edi': 'dil', 'ebp': 'bpl', 'esp': 'spl',
            }
            reg8 = None
            if reg in reg8_map:
                reg8 = reg8_map[reg]
            elif reg.startswith('r') and reg[1:].isdigit():
                # r8-r15 family
                try:
                    num = int(reg[1:])
                    if 8 <= num <= 15:
                        reg8 = f"r{num}b"
                except Exception:
                    reg8 = None
            # If we found a valid 8-bit register, emit replacement
            if reg8:
                out.append(f"{indent}mov{sep}{reg8}, {imm_s}{cmt}")
            else:
                out.append(ln)
        else:
            out.append(ln)
    return out


def default_rules_for_arch(arch: str) -> List[TransformRule]:
    a = (arch or "").lower()
    rules: List[TransformRule] = []
    if "x86" in a:
        rules.append(
            TransformRule(
                name="push-zero-to-xor-push",
                description="Replace push 0 with xor rax,rax; push rax",
                archs=["x86", "x86_64"],
                enabled=True,
                apply=lambda asm, arch=a: _join(_x86_push_zero(_normalize_asm(asm), arch)),
            )
        )
        rules.append(
            TransformRule(
                name="mov-reg-imm8-to-mov-reg8",
                description="Use mov reg8, imm8 when immediate fits in 8 bits (risky)",
                archs=["x86_64"],
                enabled=False,
                apply=lambda asm: _join(_x86_mov_reg_imm8(_normalize_asm(asm))),
            )
        )
    return rules


def propose(asm_text: str, arch: str, rules: Optional[List[TransformRule]] = None) -> List[Proposal]:
    """Return proposals by applying each enabled rule virtually and diffing."""
    rules = rules or default_rules_for_arch(arch)
    proposals: List[Proposal] = []
    for r in rules:
        if not r.enabled:
            continue
        after = r.apply(asm_text)
        if after != asm_text:
            proposals.append(Proposal(rule=r, before=asm_text, after=after))
    return proposals


def apply_all(asm_text: str, arch: str, rules: Optional[List[TransformRule]] = None) -> str:
    rules = rules or default_rules_for_arch(arch)
    out = asm_text
    for r in rules:
        if r.enabled:
            out = r.apply(out)
    return out


# --- Formatting helpers -----------------------------------------------------

def align_assembly(asm_text: str) -> str:
    """Align mnemonics and operands for readability while preserving indent and comments.

    - Keeps original leading indentation per line
    - Pads mnemonic to a common width across instruction lines
    - Preserves labels and assembler directives as-is
    - Preserves comments, placing at least two spaces before a trailing comment
    """
    lines = asm_text.splitlines()
    parsed = []  # (indent, mnemonic, operands, comment, original)
    mnemonic_width = 0

    label_re = re.compile(r"^\s*[A-Za-z_.$][\w.$@]*:\s*$")
    dir_re = re.compile(r"^\s*\.")
    for ln in lines:
        if not ln.strip() or ln.lstrip().startswith(';') or label_re.match(ln) or dir_re.match(ln):
            parsed.append((None, None, None, None, ln))
            continue
        # Split trailing comment
        code, sep, cmt = ln.partition(';')
        comment = (sep + cmt) if sep else ''
        m = re.match(r"^(?P<indent>\s*)(?P<mnem>[A-Za-z.][\w.]*)\s*(?P<ops>.*)$", code)
        if not m:
            parsed.append((None, None, None, None, ln))
            continue
        indent = m.group('indent') or ''
        mnem = m.group('mnem') or ''
        ops = (m.group('ops') or '').rstrip()
        mnemonic_width = max(mnemonic_width, len(mnem))
        parsed.append((indent, mnem, ops, comment, ln))

    out_lines: List[str] = []
    for indent, mnem, ops, comment, original in parsed:
        if indent is None:
            out_lines.append(original)
            continue
        # Build aligned line
        pad = ' ' * (mnemonic_width - len(mnem) + 1)  # at least one space after mnemonic
        base = f"{indent}{mnem}{pad}{ops}" if ops else f"{indent}{mnem}"
        if comment:
            # ensure at least two spaces before a trailing comment
            if not base.endswith(' '):
                base += ' '
            base += ' '  # two spaces
            base += comment.lstrip()
        out_lines.append(base)
    return "\n".join(out_lines)
