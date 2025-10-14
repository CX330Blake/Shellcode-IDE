from __future__ import annotations

import re


_HEX_RE = re.compile(r"[0-9a-fA-F]")


def parse_hex_input(s: str) -> bytes:
    """Parse a variety of common hex/byte literal formats into raw bytes.

    Accepts:
    - Inline escaped: \x90\x90\x48...
    - C-style: 0x90,0x90,0x48 or 0x90 0x90 0x48
    - Raw hex: 909048...
    - With whitespace, commas, newlines
    """
    if not s:
        return b""
    s = s.strip()
    # Inline \x.. sequences
    if "\\x" in s:
        pairs = re.findall(r"\\x([0-9a-fA-F]{2})", s)
        if not pairs:
            raise ValueError("No valid \\xHH sequences found")
        return bytes(int(p, 16) for p in pairs)

    # Remove 0x prefixes and non-hex separators
    cleaned = re.sub(r"0x", "", s, flags=re.IGNORECASE)
    cleaned = re.sub(r"[^0-9a-fA-F]", "", cleaned)
    if not cleaned:
        return b""
    if len(cleaned) % 2 != 0:
        raise ValueError("Odd-length hex string after cleaning")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"Invalid hex input: {e}")


def count_nulls(b: bytes) -> int:
    return sum(1 for x in b if x == 0)

