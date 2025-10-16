from __future__ import annotations

import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import List, Optional, Tuple
import ssl


# Use a common browser-like user agent to avoid being blocked by some endpoints
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/119.0.0.0 Safari/537.36"
)


@dataclass
class ShellstormEntry:
    sid: str
    title: str
    arch: str = ""
    platform: str = ""
    author: str = ""
    url: str = ""


def _http_get(url: str, timeout: float = 8.0, verify_ssl: bool = True) -> Tuple[int, str]:
    print(f"[Shellcode-IDE] _http_get: url={url} verify_ssl={verify_ssl} timeout={timeout}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    context = None
    if url.lower().startswith("https:"):
        if verify_ssl:
            context = None
        else:
            try:
                context = ssl._create_unverified_context()  # type: ignore[attr-defined]
            except Exception:
                context = None
    # Use an opener with HTTPSHandler so redirects preserve the SSL context
    opener = None
    try:
        if context is not None:
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        else:
            opener = urllib.request.build_opener()
    except Exception:
        opener = None
    open_fn = (opener.open if opener is not None else urllib.request.urlopen)
    with open_fn(req, timeout=timeout) as resp:  # type: ignore[arg-type]
        code = getattr(resp, "status", resp.getcode())
        data = resp.read()
        print(f"[Shellcode-IDE] _http_get: status={code} bytes={len(data)}")
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = data.decode("latin-1", errors="replace")
        return code, text


def _http_fallback(url: str) -> str:
    if url.lower().startswith("https://"):
        return "http://" + url[8:]
    return url


def search(query: str, arch: Optional[str] = None, timeout: float = 8.0, verify_ssl: bool = True, allow_http_fallback: bool = True) -> List[ShellstormEntry]:
    """Search Shell-Storm database.

    The Shell-Storm API has historically supported multiple query shapes. We try a
    few common endpoints and parse semi-structured responses.
    """
    q = urllib.parse.quote_plus(query.strip())
    print(f"[Shellcode-IDE] Shellstorm.search: q='{query}' arch='{arch}' verify_ssl={verify_ssl} allow_http_fallback={allow_http_fallback}")
    candidates = [
        f"https://shell-storm.org/api/?s={q}",
        f"https://shell-storm.org/api/?op=search&shellcode={q}",
    ]
    # Optional arch filter – best effort; some deployments support it
    if arch:
        aq = urllib.parse.quote_plus(arch)
        candidates.append(f"https://shell-storm.org/api/?op=search&arch={aq}&shellcode={q}")

    last_err: Optional[Exception] = None
    text = ""
    for u in candidates:
        try:
            print(f"[Shellcode-IDE] Shellstorm.search: trying {u}")
            code, text = _http_get(u, timeout=timeout, verify_ssl=verify_ssl)
            if 200 <= code < 300 and text:
                break
        except Exception as e:
            last_err = e
            print(f"[Shellcode-IDE] Shellstorm.search: error {type(e).__name__}: {e}")
            # Optional: try HTTP fallback when SSL fails
            if allow_http_fallback:
                try:
                    u2 = _http_fallback(u)
                    if u2 != u:
                        print(f"[Shellcode-IDE] Shellstorm.search: retry fallback {u2}")
                        code, text = _http_get(u2, timeout=timeout, verify_ssl=False)
                        if 200 <= code < 300 and text:
                            break
                except Exception as e2:
                    last_err = e2
                    print(f"[Shellcode-IDE] Shellstorm.search: fallback error {type(e2).__name__}: {e2}")
            continue
    if not text:
        # Propagate last error context if any
        if last_err:
            raise last_err
        return []

    entries: List[ShellstormEntry] = []
    url_re = re.compile(r"^https?://", re.I)
    id_from_url_re = re.compile(r"shellcode[-_/](\d+)", re.I)
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        # Common formats seen historically:
        # id;title;platform;author;arch;url
        # id|title|platform|author|arch|url
        # id::::title::::platform::::author::::arch::::url
        if "::::" in s:
            parts = [p.strip() for p in s.split("::::")]
        elif "|" in s:
            parts = [p.strip() for p in s.split("|")]
        else:
            parts = [p.strip() for p in s.split(";")]
        # Identify url/id robustly (heuristic, do not assume fixed column order)
        found_url = ""
        found_id = ""
        cand_title = ""
        platform = ""
        author = ""
        arch_f = ""
        # First, pick URL if any part looks like one
        for p in parts:
            if url_re.match(p):
                found_url = p
                break
        # Pick numeric id if present among parts
        for p in parts:
            if p.isdigit():
                found_id = p
                break
        # Try to extract id from URL if needed
        if not found_id and found_url:
            m = id_from_url_re.search(found_url)
            if m:
                found_id = m.group(1)
        # Build candidate pool excluding id/url and empties
        pool = [p for p in parts if p and not url_re.match(p) and not p.isdigit()]
        # Simple classifiers
        def looks_platform(x: str) -> bool:
            xl = x.lower()
            return ('/' in xl) or any(t in xl for t in (
                'linux', 'win', 'osx', 'freebsd', 'openbsd', 'netbsd', 'solaris', 'ios', 'android'
            ))
        def looks_arch(x: str) -> bool:
            xl = x.lower()
            return xl in ('x86', 'x86_64', 'amd64', 'i386', 'arm', 'armv7', 'arm64', 'aarch64', 'mips', 'ppc', 'sparc')
        def looks_author(x: str) -> bool:
            # Prefer short tokens with few spaces and no slashes
            return ('/' not in x) and (len(x) <= 40) and (len(x.split()) <= 3)
        # Pick platform if present
        for p in pool:
            if looks_platform(p):
                platform = p
                break
        # Pick arch if present (and distinct from platform)
        for p in pool:
            if p != platform and looks_arch(p):
                arch_f = p
                break
        # Title: choose the longest remaining descriptive string
        # Exclude chosen platform/arch
        title_candidates = [p for p in pool if p not in (platform, arch_f)]
        if title_candidates:
            cand_title = max(title_candidates, key=lambda s: (len(s), s.count(' ')))
        # Author: choose a reasonable short leftover token not equal to title/platform/arch
        for p in pool:
            if p not in (cand_title, platform, arch_f) and looks_author(p):
                author = p
                break
        entries.append(ShellstormEntry(
            sid=str(found_id or cand_title or ""),
            title=cand_title or (found_url or found_id),
            platform=platform,
            author=author,
            arch=arch_f,
            url=found_url,
        ))
    print(f"[Shellcode-IDE] Shellstorm.search: parsed entries={len(entries)}")
    return entries


def fetch_code(entry: ShellstormEntry, timeout: float = 8.0, verify_ssl: bool = True, allow_http_fallback: bool = True) -> str:
    """Fetch the shellcode source/code body for an entry.

    Prefer the provided URL if present; otherwise try id-based endpoint.
    """
    # Prefer direct URL if provided
    urls: List[str] = []
    if entry.url:
        urls.append(entry.url)
    # Fallback to id-based detail API
    if entry.sid:
        urls.append(f"https://shell-storm.org/shellcode/files/shellcode-{entry.sid}.php")
    last_err: Optional[Exception] = None
    print(f"[Shellcode-IDE] Shellstorm.fetch_code: id={entry.sid} url={entry.url} verify_ssl={verify_ssl} allow_http_fallback={allow_http_fallback}")
    for u in urls:
        try:
            print(f"[Shellcode-IDE] Shellstorm.fetch_code: trying {u}")
            code, text = _http_get(u, timeout=timeout, verify_ssl=verify_ssl)
            if 200 <= code < 300 and text:
                return text
        except Exception as e:
            last_err = e
            print(f"[Shellcode-IDE] Shellstorm.fetch_code: error {type(e).__name__}: {e}")
            if allow_http_fallback:
                try:
                    u2 = _http_fallback(u)
                    if u2 != u:
                        print(f"[Shellcode-IDE] Shellstorm.fetch_code: retry fallback {u2}")
                        code, text = _http_get(u2, timeout=timeout, verify_ssl=False)
                        if 200 <= code < 300 and text:
                            return text
                except Exception as e2:
                    last_err = e2
                    print(f"[Shellcode-IDE] Shellstorm.fetch_code: fallback error {type(e2).__name__}: {e2}")
            continue
    if last_err:
        raise last_err
    return ""


_HEX_PAIR_RE = re.compile(r"\\x([0-9a-fA-F]{2})")


def extract_hex_bytes(blob: str) -> Optional[bytes]:
    r"""Best-effort to extract raw bytes from common code blobs.

    - Finds C/Python-style "\xHH" string sequences and converts them.
    - As a fallback, finds contiguous hex pairs (with optional separators).
    """
    pairs = _HEX_PAIR_RE.findall(blob)
    if pairs:
        try:
            return bytes(int(p, 16) for p in pairs)
        except Exception:
            pass
    # Fallback: extract any run of hex and try to parse as bytes
    cleaned = re.sub(r"[^0-9a-fA-F]", "", blob)
    if len(cleaned) >= 2 and len(cleaned) % 2 == 0:
        try:
            return bytes.fromhex(cleaned)
        except Exception:
            pass
    return None


def seems_assembly(text: str) -> bool:
    """Heuristic to decide if the fetched text is assembly source."""
    s = text.lower()
    # Common asm mnemonics across x86/arm/mips/aarch64
    mnems = [
        "mov", "jmp", "call", "push", "pop", "xor", "add", "sub", "cmp", "lea",
        "ldr", "str", "bl", "b ", "adrp", "adr", "svc", "int ",
        "lw", "sw", "li", "la", "syscall",
    ]
    return any(m in s for m in mnems)
