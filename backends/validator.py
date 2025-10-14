from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any


@dataclass
class ValidationIssue:
    kind: str
    message: str
    severity: str = "error"  # or "warn", "info"
    line: Optional[int] = None
    offset: Optional[int] = None
    suggestion: Optional[str] = None


@dataclass
class Pattern:
    type: str  # 'hex' | 'sequence' | 'regex'
    value: str
    name: str = ""
    enabled: bool = True


@dataclass
class PatternMatch:
    pattern: Pattern
    offsets: List[int] = field(default_factory=list)


DEFAULT_PATTERNS: List[Pattern] = [
    Pattern(type="hex", value="00", name="NULL byte", enabled=True),
    Pattern(type="hex", value="0a", name="LF byte", enabled=False),
    Pattern(type="hex", value="ff", name="0xFF byte", enabled=False),
]


class BadPatternManager:
    def __init__(self, patterns: Optional[List[Pattern]] = None):
        self.patterns: List[Pattern] = patterns[:] if patterns is not None else DEFAULT_PATTERNS[:]

    def serialize(self) -> List[Dict[str, Any]]:
        return [p.__dict__ for p in self.patterns]

    @staticmethod
    def deserialize(data: List[Dict[str, Any]]) -> "BadPatternManager":
        pats: List[Pattern] = []
        for row in data:
            try:
                pats.append(Pattern(
                    type=row.get("type", "hex"),
                    value=row.get("value", ""),
                    name=row.get("name", ""),
                    enabled=bool(row.get("enabled", True)),
                ))
            except Exception:
                continue
        return BadPatternManager(pats)

    def _parse_hex_byte(self, s: str) -> Optional[int]:
        s = s.strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        if len(s) != 2:
            return None
        try:
            return int(s, 16)
        except Exception:
            return None

    def _parse_sequence(self, s: str) -> Optional[bytes]:
        parts = [p for p in re.split(r"[\s,]+", s.strip()) if p]
        if not parts:
            return None
        out: List[int] = []
        for p in parts:
            b = self._parse_hex_byte(p)
            if b is None:
                return None
            out.append(b)
        return bytes(out)

    def match_patterns(self, data: bytes) -> List[PatternMatch]:
        matches: List[PatternMatch] = []
        hexstr = data.hex()
        for p in self.patterns:
            if not p.enabled:
                continue
            if p.type == "hex":
                b = self._parse_hex_byte(p.value)
                if b is None:
                    continue
                offs = [i for i, v in enumerate(data) if v == b]
                if offs:
                    matches.append(PatternMatch(pattern=p, offsets=offs))
            elif p.type == "sequence":
                seq = self._parse_sequence(p.value)
                if not seq:
                    continue
                offs: List[int] = []
                i = 0
                mv = memoryview(data)
                while True:
                    j = data.find(seq, i)
                    if j == -1:
                        break
                    offs.append(j)
                    i = j + 1
                if offs:
                    matches.append(PatternMatch(pattern=p, offsets=offs))
            elif p.type == "regex":
                try:
                    rx = re.compile(p.value)
                except Exception:
                    continue
                offs = []
                for m in rx.finditer(hexstr):
                    # Map hex index to byte offset: every 2 hex chars per byte
                    start = m.start() // 2
                    offs.append(start)
                if offs:
                    matches.append(PatternMatch(pattern=p, offsets=offs))
        return matches


LABEL_RE = re.compile(r"^\s*[@.$A-Za-z_][\w@.$]*:\s*$")
DIRECTIVE_RE = re.compile(r"^\s*\.(globl|global|data|text|bss|section|byte|word|dword|qword)\b", re.I)
ABS_IMM_RE = re.compile(r"\b(0x[0-9a-f]{5,}|[0-9]{6,})\b", re.I)
ABS_MEM_RE = re.compile(r"\[[^\]]*0x[0-9a-f]+[^\]]*\]", re.I)


def validate_assembly(asm_text: str, arch_name: str) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []
    if not asm_text:
        return issues
    for idx, line in enumerate(asm_text.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith(";") or s.startswith("#"):
            continue
        if LABEL_RE.match(s):
            issues.append(ValidationIssue(
                kind="label",
                message="Labels/variables are not allowed in shellcode",
                line=idx,
                severity="error",
            ))
            continue
        if DIRECTIVE_RE.match(s):
            issues.append(ValidationIssue(
                kind="directive",
                message="Assembler directives are not supported",
                line=idx,
                severity="warn",
            ))
        # Absolute immediates that look like addresses
        if ABS_IMM_RE.search(s):
            issues.append(ValidationIssue(
                kind="absolute-address",
                message="Potential absolute address immediate detected",
                line=idx,
                severity="warn",
            ))
        if ABS_MEM_RE.search(s):
            issues.append(ValidationIssue(
                kind="absolute-memory",
                message="Absolute memory operand detected",
                line=idx,
                severity="error",
            ))
    return issues


def validate_bytes(data: bytes, bpm: BadPatternManager) -> Tuple[List[ValidationIssue], List[PatternMatch]]:
    issues: List[ValidationIssue] = []
    # Always report nulls explicitly
    null_offs = [i for i, b in enumerate(data) if b == 0]
    for off in null_offs:
        issues.append(ValidationIssue(
            kind="null-byte",
            message=f"Null byte at offset {off}",
            offset=off,
            severity="warn",
        ))
    # Pattern matches
    pmatches = bpm.match_patterns(data)
    return issues, pmatches


def validate_all(asm_text: str, data: bytes, arch_name: str, bpm: BadPatternManager) -> Tuple[List[ValidationIssue], List[PatternMatch]]:
    issues = validate_assembly(asm_text, arch_name)
    b_issues, pmatches = validate_bytes(data, bpm)
    issues.extend(b_issues)
    return issues, pmatches

