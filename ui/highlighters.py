from __future__ import annotations

try:
    from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QPalette
    QT6 = True
except Exception:
    from PySide2.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont  # type: ignore
    from PySide2.QtWidgets import QApplication  # type: ignore
    from PySide2.QtGui import QPalette  # type: ignore
    QT6 = False


def _qcolor_from_css(css: str) -> QColor:
    try:
        return QColor(css)
    except Exception:
        return QColor("#cccccc")


def _theme_palette():
    try:
        app = QApplication.instance()
        return app.palette() if app else None
    except Exception:
        return None


def _theme_text_color() -> QColor:
    pal = _theme_palette()
    try:
        return pal.color(QPalette.Text) if pal else QColor('#dddddd')
    except Exception:
        return QColor('#dddddd')


def _theme_muted_color() -> QColor:
    pal = _theme_palette()
    try:
        c = pal.color(QPalette.Disabled, QPalette.Text)
        return c if c.isValid() else pal.color(QPalette.Mid)
    except Exception:
        return QColor('#6A737D')


def _theme_accent_color() -> QColor:
    pal = _theme_palette()
    try:
        # Prefer Link color used by BN themes; fallback to Highlight
        c = pal.color(QPalette.Link)
        if not c.isValid():
            c = pal.color(QPalette.Highlight)
        return c if c.isValid() else QColor('#007ACC')
    except Exception:
        return QColor('#007ACC')


def _palette_role_color(role_name: str) -> QColor | None:
    """Return a QColor for a given Qt palette role name (e.g., 'Base').

    The mapping follows QPalette roles commonly exposed in BN theme files under
    the "palette" section (Window, WindowText, Base, AlternateBase, Text, Link, ...).
    """
    pal = _theme_palette()
    if not pal:
        return None
    name = (role_name or '').strip().lower()
    try:
        role_map = {
            'window': QPalette.Window,
            'windowtext': QPalette.WindowText,
            'base': QPalette.Base,
            'alternatebase': QPalette.AlternateBase,
            'tooltipbase': QPalette.ToolTipBase,
            'tooltiptext': QPalette.ToolTipText,
            'text': QPalette.Text,
            'button': QPalette.Button,
            'buttontext': QPalette.ButtonText,
            'brighttext': QPalette.BrightText,
            'link': QPalette.Link,
            'linkvisited': QPalette.LinkVisited,
            'highlight': QPalette.Highlight,
            'highlightedtext': QPalette.HighlightedText,
            'light': QPalette.Light,
            'mid': QPalette.Mid if hasattr(QPalette, 'Mid') else QPalette.Dark,
        }
        role = role_map.get(name)
        if role is None:
            return None
        return pal.color(role)
    except Exception:
        return None


def _rotate_hue(col: QColor, delta: int) -> QColor:
    try:
        h, s, v, a = col.getHsv()
    except Exception:
        return col
    if h is None or h < 0:
        h = 200
    nh = (int(h) + int(delta)) % 360
    ns = max(100, min(255, s if isinstance(s, int) else 180))
    nv = max(140, min(255, v if isinstance(v, int) else 200))
    out = QColor()
    out.setHsv(nh, ns, nv, a if isinstance(a, int) else 255)
    return out


def _good_bad_colors() -> tuple[QColor, QColor]:
    """Return (good_green, bad_red) using Binary Ninja theme when available.

    Priority:
    1) binaryninjaui ThemeColor roles for green/red standards
    2) App stylesheet tokens ("success"/"error" or similar keywords)
    3) QPalette-derived fallbacks
    """
    # 1) Binary Ninja ThemeColor (if available) and named theme variables
    try:
        from binaryninjaui import ThemeColor, getThemeColor  # type: ignore

        def _try_named(var_name: str):
            # Try to resolve via optional helpers, if present
            try:
                from binaryninjaui import getThemeColorByName  # type: ignore
                c = getThemeColorByName(var_name)
                if c is not None and c.isValid():
                    return c
            except Exception:
                pass
            try:
                from binaryninjaui import getColorByName  # type: ignore
                c = getColorByName(var_name)
                if c is not None and c.isValid():
                    return c
            except Exception:
                pass
            # Some builds may accept string to getThemeColor directly
            try:
                c = getThemeColor(var_name)  # type: ignore[arg-type]
                if c is not None and c.isValid():
                    return c
            except Exception:
                pass
            return None

        # Prefer theme file variables if available
        g = _try_named('green') or _try_named('success')
        r = _try_named('red') or _try_named('error')

        # Otherwise, probe ThemeColor enums for reasonable standard highlight colors
        if g is None or r is None:
            green_attr_candidates = [
                'GreenStandardHighlightColor', 'GreenStandardColor', 'GreenStandard', 'Green',
            ]
            red_attr_candidates = [
                'RedStandardHighlightColor', 'RedStandardColor', 'RedStandard', 'Red',
            ]
            if g is None:
                for name in green_attr_candidates:
                    if hasattr(ThemeColor, name):
                        g = getThemeColor(getattr(ThemeColor, name))
                        if g is not None and g.isValid():
                            break
            if r is None:
                for name in red_attr_candidates:
                    if hasattr(ThemeColor, name):
                        r = getThemeColor(getattr(ThemeColor, name))
                        if r is not None and r.isValid():
                            break
        if g is not None and r is not None and g.isValid() and r.isValid():
            return g, r
    except Exception:
        pass
    # 2) Stylesheet keywords
    try:
        g = _stylesheet_color_for('success') or _stylesheet_color_for('green')
        r = _stylesheet_color_for('error') or _stylesheet_color_for('red')
        if g and r and g.isValid() and r.isValid():
            return g, r
    except Exception:
        pass
    # 3) QPalette fallbacks
    pal = _theme_palette()
    if pal:
        try:
            # Use Highlight for good; derive red from BrightText or a darker Link
            good = pal.color(QPalette.Highlight)
            bad = pal.color(QPalette.BrightText)
            if not bad.isValid() or bad == good:
                bad = QColor(pal.color(QPalette.Link)).darker(150)
            return good, bad
        except Exception:
            pass
    # Final fallback
    return QColor('#2ecc71'), QColor('#e74c3c')


def _tint(bg: QColor, alpha: int = 32) -> QColor:
    # Return a translucent version of bg for background highlighting
    c = QColor(bg)
    c.setAlpha(max(16, min(96, int(alpha))))
    return c


def _stylesheet_color_for(*keywords: str) -> QColor | None:
    """Try to extract a color used in the active Qt stylesheet for selectors
    containing all given keywords (case-insensitive). Returns the first matching
    'color:' value as a QColor, or None if not found.

    This helps align with Binary Ninja themes that style disassembly tokens via QSS.
    """
    try:
        app = QApplication.instance()
        if not app:
            return None
        qss = app.styleSheet() or ""
        if not qss:
            return None
        # Simple block-wise scan: split by '}' and search each block header and body
        for block in qss.split('}'):
            if '{' not in block:
                continue
            header, body = block.split('{', 1)
            hdr = header.lower()
            if all(k.lower() in hdr for k in keywords):
                import re as _re
                m = _re.search(r"color\s*:\s*([^;]+);", body, flags=_re.IGNORECASE)
                if m:
                    val = m.group(1).strip()
                    # palette(...) or hex/name
                    if val.lower().startswith('palette('):
                        # Extract role inside palette(role)
                        role = val[val.find('(')+1: val.rfind(')')].strip()
                        try:
                            # Map a few common roles
                            role_map = {
                                'text': QPalette.Text,
                                'windowtext': QPalette.WindowText,
                                'highlight': QPalette.Highlight,
                                'link': QPalette.Link,
                                'brighttext': QPalette.BrightText,
                            }
                            pal = _theme_palette()
                            if pal and role.lower() in role_map:
                                return pal.color(role_map[role.lower()])
                        except Exception:
                            pass
                    c = QColor(val)
                    if c.isValid():
                        return c
        return None
    except Exception:
        return None


def _theme_token_color(role: str) -> QColor | None:
    """Return QColor for a Binary Ninja theme token (per docs: themes.html#tokens).

    Priority:
    1) binaryninjaui ThemeColor via getThemeColor(ThemeColor.*)
    2) App stylesheet selectors approximating token names
    3) QPalette heuristics for reasonable defaults
    """
    role_l = (role or '').lower().strip()

    # 1) Binary Ninja UI theme tokens
    try:
        from binaryninjaui import ThemeColor, getThemeColor  # type: ignore
        # Map lower-case BN token name to ThemeColor enum attribute
        bn_map = {
            'addresscolor': 'AddressColor',
            'registercolor': 'RegisterColor',
            'numbercolor': 'NumberColor',
            'opcodecolor': 'OpcodeColor',
            'codesymbolcolor': 'CodeSymbolColor',
            'datasymbolcolor': 'DataSymbolColor',
            'stackvariablecolor': 'StackVariableColor',
            'importcolor': 'ImportColor',
            'annotationcolor': 'AnnotationColor',
            'commentcolor': 'CommentColor',
            'stringcolor': 'StringColor',
            'typenamecolor': 'TypeNameColor',
            'fieldnamecolor': 'FieldNameColor',
            'keywordcolor': 'KeywordColor',
            'uncertaincolor': 'UncertainColor',
            'operationcolor': 'OperationColor',
            'gotolabelcolor': 'GotoLabelColor',
        }
        enum_name = bn_map.get(role_l)
        if enum_name and hasattr(ThemeColor, enum_name):
            c = getThemeColor(getattr(ThemeColor, enum_name))
            if c and c.isValid():
                return c
    except Exception:
        pass

    # 2) Approximate via stylesheet selectors
    selector_map = {
        'addresscolor': ('address',),
        'registercolor': ('register',),
        'numbercolor': ('number', 'immediate', 'const'),
        'opcodecolor': ('opcode', 'mnemonic', 'instruction'),
        'codesymbolcolor': ('codesymbol', 'function', 'symbol', 'procname'),
        'datasymbolcolor': ('datasymbol', 'datasym', 'symbol-data'),
        'stackvariablecolor': ('stackvar', 'stack', 'var'),
        'importcolor': ('import',),
        'annotationcolor': ('annotation', 'hint'),
        'commentcolor': ('comment',),
        'stringcolor': ('string',),
        'typenamecolor': ('typename', 'type'),
        'fieldnamecolor': ('fieldname', 'member', 'field'),
        'keywordcolor': ('keyword',),
        'uncertaincolor': ('uncertain', 'lowconfidence'),
        'operationcolor': ('operation', 'operator', 'punct'),
        'gotolabelcolor': ('goto', 'label'),
    }
    kw = selector_map.get(role_l)
    if kw:
        c = _stylesheet_color_for(*kw)
        if c and c.isValid():
            return c

    # 3) Palette heuristics
    pal = _theme_palette()
    if not pal:
        return None
    try:
        if role_l in ('registercolor', 'opcodecolor', 'keywordcolor'):
            return pal.color(QPalette.Link)
        if role_l in ('numbercolor',):
            return pal.color(QPalette.Text)
        if role_l in ('commentcolor', 'annotationcolor'):
            return pal.color(QPalette.Disabled, QPalette.Text)
        if role_l in ('operationcolor', 'addresscolor'):
            return pal.color(QPalette.Mid)
        if role_l in ('stringcolor',):
            t = pal.color(QPalette.Text)
            return QColor(t).darker(115)
        if role_l in ('typenamecolor', 'fieldnamecolor', 'codesymbolcolor', 'datasymbolcolor'):
            return QColor(pal.color(QPalette.Link)).darker(110)
    except Exception:
        return None
    return None


class PygmentsHighlighter(QSyntaxHighlighter):
    """QSyntaxHighlighter adapter that uses Pygments for tokenization + styling.

    If Pygments is unavailable or a lexer cannot be created, initialization
    raises ImportError so callers can fallback to a simpler highlighter.
    """

    def __init__(self, parent_document, lexer_name: str = "asm", style_name: str = "native"):
        # Initialize without a document first to avoid early highlightBlock calls
        QSyntaxHighlighter.__init__(self)
        print(f"[Shellcode IDE] PygmentsHighlighter: lexer_name={lexer_name}, style_name={style_name}")

        self.lexer = None
        self.formats = {}
        self.default_format = QTextCharFormat()
        try:
            import pygments  # noqa: F401
            from pygments.lexers import get_lexer_by_name
            from pygments.styles import get_style_by_name
            from pygments.token import Token
        except Exception as exc:
            print(f"[Shellcode IDE] Pygments not available: {exc}")
            raise ImportError("pygments is not available") from exc

        try:
            self.lexer = get_lexer_by_name(lexer_name)
        except Exception as exc:
            print(f"[Shellcode IDE] Failed to get lexer for {lexer_name}: {exc}")
            # fallback to text lexer
            self.lexer = get_lexer_by_name("text")

        try:
            self.style = get_style_by_name(style_name)
        except Exception:
            print(f"[Shellcode IDE] Style '{style_name}' not found, falling back to 'default'")
            self.style = get_style_by_name("default")

        # Build QTextCharFormat map for pygments style entries
        self.formats = {}
        # self.style.styles is a dict {TokenType: 'style spec string'}
        try:
            style_map = getattr(self.style, 'styles', {})
        except Exception:
            style_map = {}

        def parse_spec(spec: str) -> QTextCharFormat:
            fmt = QTextCharFormat()
            if not spec:
                return fmt
            for part in spec.split():
                p = part.lower()
                if p == 'bold':
                    fmt.setFontWeight(QFont.Bold)
                elif p == 'italic':
                    fmt.setFontItalic(True)
                elif p == 'underline':
                    fmt.setFontUnderline(True)
                elif p.startswith('bg:'):
                    col = p[3:]
                    fmt.setBackground(_qcolor_from_css(col))
                else:
                    # assume foreground color token (e.g., #rrggbb or named)
                    fmt.setForeground(_qcolor_from_css(p))
            return fmt

        for token, spec in style_map.items():
            fmt = parse_spec(spec)
            self.formats[token] = fmt

        # Cache for token parent lookup
        self.token_cache = {}

        # Base format for Token.Text and style background
        base_spec = ""
        try:
            base_spec = style_map.get(Token.Text, "") or style_map.get(Token, "") or ""
        except Exception:
            base_spec = ""
        self.base_format = parse_spec(base_spec)
        try:
            bg = getattr(self.style, 'background_color', None)
            if bg:
                self.base_format.setBackground(_qcolor_from_css(bg))
        except Exception:
            pass

        # Finally, attach to the document
        try:
            self.setDocument(parent_document)
        except Exception:
            pass
        # Mnemonic format: use theme palette WindowText color for opcode per request
        self.mnemonic_format = QTextCharFormat()
        wtxt_col = _palette_role_color('WindowText')
        self.mnemonic_format.setForeground(wtxt_col if wtxt_col and wtxt_col.isValid() else _theme_accent_color())

    def _format_for(self, token):
        if token in self.formats:
            return self.formats[token]
        # walk up parent chain
        cur = token
        while getattr(cur, 'parent', None) is not None:
            cur = cur.parent
            if cur in self.formats:
                self.formats[token] = self.formats[cur]
                return self.formats[cur]
        return self.default_format

    def highlightBlock(self, text: str) -> None:  # type: ignore
        try:
            from pygments import lex
        except Exception:
            return
        if getattr(self, 'lexer', None) is None:
            return
        # Apply base format to entire line first
        try:
            if hasattr(self, 'base_format') and self.base_format is not None:
                self.setFormat(0, len(text), self.base_format)
        except Exception:
            pass
        pos = 0
        for ttype, value in lex(text, self.lexer):
            length = len(value)
            if length:
                fmt = self._format_for(ttype)
                self.setFormat(pos, length, fmt)
                pos += length
        # Ensure the mnemonic at line start is colored (helps when styles are subtle)
        try:
            stripped = text.lstrip()
            if stripped:
                start = len(text) - len(stripped)
                # mnemonic is first contiguous word
                end = start
                n = len(text)
                while end < n and not text[end].isspace() and text[end] not in ',;#':
                    end += 1
                if end > start:
                    self.setFormat(start, end - start, self.mnemonic_format)
        except Exception:
            pass


class SimpleAsmHighlighter(QSyntaxHighlighter):
    """Small, dependency-free assembly highlighter.

    This is a fallback used when Pygments is unavailable. It provides
    lightweight highlighting for mnemonics, registers, immediates, and
    comments so users still get visual structure.
    """

    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)

        # Theme-aware colors, prefer Binary Ninja stylesheet token colors / roles
        accent = _theme_accent_color()
        muted = _theme_muted_color()
        # Mnemonics (e.g., 'push', 'mov') should use palette WindowText color
        c_mnemonic = _palette_role_color('WindowText') or _theme_token_color('opcodeColor') or _stylesheet_color_for('mnemonic', 'instruction') or accent
        c_register = _theme_token_color('registerColor') or _stylesheet_color_for('register') or QColor(accent).darker(115)
        c_number   = _theme_token_color('numberColor') or _stylesheet_color_for('number', 'immediate') or QColor(accent).lighter(115)
        c_comment  = _theme_token_color('commentColor') or _stylesheet_color_for('comment') or muted
        c_label    = _theme_token_color('gotoLabelColor') or _stylesheet_color_for('label') or QColor(accent).darker(115)
        c_operator = _theme_token_color('operationColor') or _stylesheet_color_for('operator', 'punct') or _theme_muted_color()

        self.fmt_mnemonic = QTextCharFormat(); self.fmt_mnemonic.setForeground(c_mnemonic)
        self.fmt_register = QTextCharFormat(); self.fmt_register.setForeground(c_register); self.fmt_register.setFontWeight(QFont.Bold)
        self.fmt_number = QTextCharFormat(); self.fmt_number.setForeground(c_number)
        self.fmt_comment = QTextCharFormat(); self.fmt_comment.setForeground(c_comment); self.fmt_comment.setFontItalic(True)
        self.fmt_label = QTextCharFormat(); self.fmt_label.setForeground(c_label)
        self.fmt_operator = QTextCharFormat(); self.fmt_operator.setForeground(c_operator)

        # Very loose regex patterns handled manually in highlightBlock for Qt5/6 compat
        # Common register names across x86/x64; extend as needed
        self._reg_words = set(
            [
                # x86_64
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                # x86
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
                "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
                # ip
                "eip", "rip",
                # SIMD
                *[f"xmm{i}" for i in range(32)], *[f"ymm{i}" for i in range(32)], *[f"zmm{i}" for i in range(32)],
            ]
        )

    def _is_hex_prefix(self, s: str, i: int) -> bool:
        return i + 2 <= len(s) and s[i] == '0' and (i + 1 < len(s) and (s[i + 1] in 'xX'))

    def _is_digit(self, ch: str) -> bool:
        return '0' <= ch <= '9'

    def _is_ident_start(self, ch: str) -> bool:
        return ch == '_' or ch.isalpha()

    def _is_ident_part(self, ch: str) -> bool:
        return ch == '_' or ch.isalnum()

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not text:
            return
        n = len(text)

        # 0) Address at line start (objdump-like): hex or 0x... followed by ':'
        try:
            addr_end = -1
            # allow leading spaces
            ls = len(text) - len(text.lstrip())
            j = ls
            # accept 0x... or hex digits
            if j < len(text) and text[j] == '0' and j + 1 < len(text) and text[j+1] in 'xX':
                j += 2
            k = j
            while k < len(text) and (text[k].isdigit() or ('a' <= text[k].lower() <= 'f')):
                k += 1
            if k > j and k < len(text) and text[k] == ':':
                addr_end = k
                fmt_addr = QTextCharFormat(); fmt_addr.setForeground(_theme_token_color('addressColor') or _theme_muted_color())
                self.setFormat(ls, addr_end - ls, fmt_addr)
        except Exception:
            pass

        # 1) Comments: ';' or '#' until EOL (not inside strings; strings uncommon in asm here)
        for mark in (';', '#'):
            pos = text.find(mark)
            if pos != -1:
                self.setFormat(pos, n - pos, self.fmt_comment)
                n = pos  # treat remainder as code
                text = text[:pos]
                break

        # 2) Labels: leading identifier ending with ':'
        # e.g., "loop:", possibly with indentation
        stripped = text.lstrip()
        if stripped:
            start = len(text) - len(stripped)
            i = start
            # scan first token
            if i < len(text) and self._is_ident_start(text[i]):
                j = i + 1
                while j < len(text) and self._is_ident_part(text[j]):
                    j += 1
                if j < len(text) and text[j] == ':':
                    self.setFormat(i, j - i + 1, self.fmt_label)
                    # nothing else on label-only lines typically
                    return

        # 3) Mnemonic: first non-whitespace word until whitespace or delimiter
        stripped = text.lstrip()
        if stripped:
            start = len(text) - len(stripped)
            end = start
            while end < len(text) and not text[end].isspace() and text[end] not in ',;#':
                end += 1
            if end > start:
                self.setFormat(start, end - start, self.fmt_mnemonic)

        # 4) Registers and numbers across the rest of the line
        i = 0
        while i < len(text):
            ch = text[i]
            if ch.isspace():
                i += 1
                continue
            if ch in ',:+-*/()[]{}<>|&^~':
                self.setFormat(i, 1, self.fmt_operator)
                i += 1
                continue
            # hex immediates: 0x....
            if self._is_hex_prefix(text, i):
                j = i + 2
                while j < len(text) and (text[j].isdigit() or ('a' <= text[j].lower() <= 'f')):
                    j += 1
                if j > i + 2:
                    self.setFormat(i, j - i, self.fmt_number)
                i = j
                continue
            # decimal numbers
            if self._is_digit(ch):
                j = i + 1
                while j < len(text) and self._is_digit(text[j]):
                    j += 1
                self.setFormat(i, j - i, self.fmt_number)
                i = j
                continue
            # string literals (quotes)
            if ch in ('"', "'"):
                q = ch; j = i + 1
                while j < len(text):
                    if text[j] == '\\':
                        j += 2; continue
                    if text[j] == q:
                        j += 1; break
                    j += 1
                fmt_str = QTextCharFormat(); fmt_str.setForeground(_theme_token_color('stringColor') or QColor(accent).darker(115))
                self.setFormat(i, j - i, fmt_str)
                i = j
                continue
            # identifiers (possible registers)
            if self._is_ident_start(ch):
                j = i + 1
                while j < len(text) and self._is_ident_part(text[j]):
                    j += 1
                word = text[i:j].lower()
                if word in self._reg_words:
                    self.setFormat(i, j - i, self.fmt_register)
                i = j
                continue
            i += 1

class HexBadByteHighlighter(QSyntaxHighlighter):
    """Highlights only specific byte positions in a hex dump string.

    Expects content like "aa bb cc ..."; set bad byte indices via
    `set_bad_offsets({0,3,5})` and it will color just those bytes.
    """

    def __init__(self, document, color: str = ""):
        QSyntaxHighlighter.__init__(self, document)
        self.bad_offsets = set()  # set[int]
        self.bad_fmt = QTextCharFormat()
        if color:
            self.bad_fmt.setForeground(_qcolor_from_css(color))
        else:
            _, bad = _good_bad_colors()
            self.bad_fmt.setForeground(bad)

    def set_bad_offsets(self, offs):
        try:
            self.bad_offsets = set(int(x) for x in offs)
        except Exception:
            self.bad_offsets = set()
        self.rehighlight()

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not self.bad_offsets:
            return
        # Compute mapping from byte index -> char position within the line
        idx = 0
        pos = 0
        n = len(text)
        while pos < n:
            # skip spaces
            while pos < n and text[pos].isspace():
                pos += 1
            if pos + 1 >= n:
                break
            # assume two hex chars
            if idx in self.bad_offsets:
                self.setFormat(pos, 2, self.bad_fmt)
            pos += 2
            idx += 1


class InlineBadByteHighlighter(QSyntaxHighlighter):
    """Highlights bad bytes in an inline escaped string (e.g., "\\x90\\x00\\xff").

    Indexing is by byte position: set with `set_bad_offsets({0, 3, ...})`.
    """

    def __init__(self, document, color: str = ""):
        QSyntaxHighlighter.__init__(self, document)
        self.bad_offsets = set()  # set[int]
        self.bad_fmt = QTextCharFormat()
        if color:
            self.bad_fmt.setForeground(_qcolor_from_css(color))
        else:
            _, bad = _good_bad_colors()
            self.bad_fmt.setForeground(bad)

    def set_bad_offsets(self, offs):
        try:
            self.bad_offsets = set(int(x) for x in offs)
        except Exception:
            self.bad_offsets = set()
        self.rehighlight()

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not self.bad_offsets or not text:
            return
        i = 0
        n = len(text)
        idx = 0  # byte index
        while i < n:
            # Look for \xHH pattern
            if i + 3 < n and text[i] == '\\' and text[i+1].lower() == 'x':
                # Next two must be hex digits
                h1 = text[i+2].lower()
                h2 = text[i+3].lower()
                if (('0' <= h1 <= '9' or 'a' <= h1 <= 'f') and
                    ('0' <= h2 <= '9' or 'a' <= h2 <= 'f')):
                    # Highlight the HH portion for the bad byte index
                    if idx in self.bad_offsets:
                        self.setFormat(i + 2, 2, self.bad_fmt)
                    idx += 1
                    i += 4
                    continue
            # Not a byte escape; skip one char
            i += 1

class AsmObjdumpBadByteHighlighter(QSyntaxHighlighter):
    """Highlights bad byte hex pairs in an objdump-like assembly listing.

    Expects lines formatted like: "00000000:  aa bb cc   \t mnemonic ...".
    Provide per-line (start_offset, length) mapping via set_mapping, and
    the set of bad byte offsets via set_bad_offsets.
    """

    def __init__(self, document, color: str = ""):
        QSyntaxHighlighter.__init__(self, document)
        self.bad_offsets = set()
        self.line_spans = []  # list[(start, length)]
        self.bad_fmt = QTextCharFormat()
        if color:
            self.bad_fmt.setForeground(_qcolor_from_css(color))
        else:
            _, bad = _good_bad_colors()
            self.bad_fmt.setForeground(bad)

    def set_mapping(self, spans):
        try:
            self.line_spans = [(int(a), int(b)) for a, b in spans]
        except Exception:
            self.line_spans = []
        self.rehighlight()

    def set_bad_offsets(self, offs):
        try:
            self.bad_offsets = set(int(x) for x in offs)
        except Exception:
            self.bad_offsets = set()
        self.rehighlight()

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not self.bad_offsets or not self.line_spans:
            return
        try:
            line_no = self.currentBlock().blockNumber()
            if line_no < 0 or line_no >= len(self.line_spans):
                return
            start_off, length = self.line_spans[line_no]
            # Find bytes segment positions: after ':  ' and before '\t'
            colon = text.find(":  ")
            if colon == -1:
                return
            bytes_start = colon + 3
            tabpos = text.find("\t", bytes_start)
            if tabpos == -1:
                tabpos = len(text)
            # For each bad offset in this line, color its two hex chars
            for off in sorted(self.bad_offsets):
                if off < start_off or off >= start_off + length:
                    continue
                idx = off - start_off
                char_pos = bytes_start + (idx * 3)  # 2 hex + 1 space
                if char_pos + 2 <= len(text):
                    self.setFormat(char_pos, 2, self.bad_fmt)
        except Exception:
            return

class UnifiedDiffHighlighter(QSyntaxHighlighter):
    """Highlights lines in a unified diff: additions green, deletions red, headers dim.

    Intended for use with a QPlainTextEdit containing the text produced by
    difflib.unified_diff (or similar). Lines beginning with '+', excluding
    '+++', are highlighted green; lines beginning with '-', excluding '---',
    are highlighted red; and hunk/file headers are dimmed.
    """

    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)
        good, bad = _good_bad_colors()
        self.fmt_add = QTextCharFormat(); self.fmt_add.setBackground(_tint(good)); self.fmt_add.setForeground(good)
        self.fmt_del = QTextCharFormat(); self.fmt_del.setBackground(_tint(bad));  self.fmt_del.setForeground(bad)
        self.fmt_hdr = QTextCharFormat(); self.fmt_hdr.setForeground(_theme_muted_color())

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not text:
            return
        try:
            if text.startswith('+++') or text.startswith('---') or text.startswith('@@'):
                self.setFormat(0, len(text), self.fmt_hdr)
            elif text.startswith('+'):
                self.setFormat(0, len(text), self.fmt_add)
            elif text.startswith('-'):
                self.setFormat(0, len(text), self.fmt_del)
        except Exception:
            return


def _first_available_style(names):
    try:
        from pygments.styles import get_style_by_name
    except Exception:
        return None
    for nm in names:
        try:
            if nm:
                get_style_by_name(nm)
                return nm
        except Exception:
            continue
    return None


def create_disassembly_highlighter(document, arch_name: str = "x86_64", style_name: str | None = None):
    """Create a syntax highlighter for disassembly text using Qt only."""
    return SimpleAsmHighlighter(document)


def create_code_highlighter(document, lexer_name: str = "text", style_name: str | None = None):
    """Create a Qt-only code highlighter for a given language name.

    Supported: 'c', 'cpp', 'c++', 'python', 'py', 'zig', 'rust', 'go'. Others return None.
    """
    try:
        lang = (lexer_name or "").lower()
        if lang in ("c", "cpp", "c++"):
            return SimpleCHighlighter(document)
        if lang in ("python", "py"):
            return SimplePythonHighlighter(document)
        if lang == "zig":
            return SimpleZigHighlighter(document)
        if lang == "rust":
            return SimpleRustHighlighter(document)
        if lang == "go":
            return SimpleGoHighlighter(document)
    except Exception:
        pass
    return None


class SimplePythonHighlighter(QSyntaxHighlighter):
    """Minimal Python highlighter using Qt only."""

    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)
        self.kw = set(
            "and as assert break class continue def del elif else except False finally for from global if import in is lambda None nonlocal not or pass raise return True try while with yield"
            .split()
        )
        self.fmt_kw = QTextCharFormat(); self.fmt_kw.setForeground(_theme_token_color('keywordColor') or _palette_role_color('Link') or _theme_accent_color()); self.fmt_kw.setFontWeight(QFont.Bold)
        self.fmt_num = QTextCharFormat(); self.fmt_num.setForeground(_theme_token_color('numberColor') or _theme_accent_color())
        self.fmt_str = QTextCharFormat(); self.fmt_str.setForeground(_theme_token_color('stringColor') or _theme_accent_color())
        self.fmt_comm = QTextCharFormat(); self.fmt_comm.setForeground(_theme_token_color('commentColor') or _theme_muted_color()); self.fmt_comm.setFontItalic(True)

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not text:
            return
        n = len(text)
        # Comments (# ...)
        cpos = text.find('#')
        code = text
        if cpos != -1:
            self.setFormat(cpos, n - cpos, self.fmt_comm)
            code = text[:cpos]
        # Strings '...' or "..." (no multiline support here)
        i = 0
        masked = list(code)
        while i < len(code):
            ch = code[i]
            if ch in ('"', "'"):
                q = ch; j = i + 1
                while j < len(code):
                    if code[j] == '\\':
                        j += 2; continue
                    if code[j] == q:
                        j += 1; break
                    j += 1
                self.setFormat(i, j - i, self.fmt_str)
                for k in range(i, min(j, len(masked))): masked[k] = ' '
                i = j
            else:
                i += 1
        code = ''.join(masked)
        # Numbers
        i = 0
        while i < len(code):
            ch = code[i]
            if ch.isdigit():
                j = i + 1
                while j < len(code) and (code[j].isdigit() or code[j] in 'xX._'):
                    j += 1
                self.setFormat(i, j - i, self.fmt_num)
                i = j
            else:
                i += 1
        # Keywords
        i = 0
        while i < len(code):
            ch = code[i]
            if ch == '_' or ch.isalpha():
                j = i + 1
                while j < len(code) and (code[j] == '_' or code[j].isalnum()):
                    j += 1
                word = code[i:j]
                if word in self.kw:
                    self.setFormat(i, j - i, self.fmt_kw)
                i = j
            else:
                i += 1


class SimpleZigHighlighter(QSyntaxHighlighter):
    """Minimal Zig highlighter using Qt only."""

    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)
        self.kw = set(
            "const var fn pub usingnamespace comptime if else switch while for defer errdefer try catch return break continue struct enum union opaque anytype error or and not true false null"
            .split()
        )
        self.fmt_kw = QTextCharFormat(); self.fmt_kw.setForeground(_theme_token_color('keywordColor') or _palette_role_color('Link') or _theme_accent_color()); self.fmt_kw.setFontWeight(QFont.Bold)
        self.fmt_num = QTextCharFormat(); self.fmt_num.setForeground(_theme_token_color('numberColor') or _theme_accent_color())
        self.fmt_str = QTextCharFormat(); self.fmt_str.setForeground(_theme_token_color('stringColor') or _theme_accent_color())
        self.fmt_comm = QTextCharFormat(); self.fmt_comm.setForeground(_theme_token_color('commentColor') or _theme_muted_color()); self.fmt_comm.setFontItalic(True)

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not text:
            return
        n = len(text)
        # // comments
        cpos = text.find('//')
        code = text
        if cpos != -1:
            self.setFormat(cpos, n - cpos, self.fmt_comm)
            code = text[:cpos]
        # /* */ block comments are not tracked across lines here; color inline occurrences
        startc = code.find('/*')
        if startc != -1:
            endc = code.find('*/', startc + 2)
            if endc == -1: endc = len(code)
            self.setFormat(startc, endc - startc + (2 if endc < len(code) else 0), self.fmt_comm)
            code = code[:startc]
        # Strings
        i = 0
        while i < len(code):
            ch = code[i]
            if ch in ('"', "'"):
                q = ch; j = i + 1
                while j < len(code):
                    if code[j] == '\\': j += 2; continue
                    if code[j] == q: j += 1; break
                    j += 1
                self.setFormat(i, j - i, self.fmt_str)
                i = j
            else:
                i += 1
        # Numbers
        i = 0
        while i < len(code):
            ch = code[i]
            if ch.isdigit():
                j = i + 1
                while j < len(code) and (code[j].isdigit() or code[j] in 'xX._'):
                    j += 1
                self.setFormat(i, j - i, self.fmt_num)
                i = j
            else:
                i += 1
        # Keywords
        i = 0
        while i < len(code):
            ch = code[i]
            if ch == '_' or ch.isalpha():
                j = i + 1
                while j < len(code) and (code[j] == '_' or code[j].isalnum()):
                    j += 1
                word = code[i:j]
                if word in self.kw:
                    self.setFormat(i, j - i, self.fmt_kw)
                i = j
            else:
                i += 1


class SimpleRustHighlighter(QSyntaxHighlighter):
    """Minimal Rust highlighter using Qt only."""

    IN_BLOCK_COMMENT = 1

    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)
        self.kw = set(
            "as break const continue crate else enum extern false fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait true type unsafe use where while dyn async await"
            .split()
        )
        self.fmt_kw = QTextCharFormat(); self.fmt_kw.setForeground(_theme_token_color('keywordColor') or _palette_role_color('Link') or _theme_accent_color()); self.fmt_kw.setFontWeight(QFont.Bold)
        self.fmt_num = QTextCharFormat(); self.fmt_num.setForeground(_theme_token_color('numberColor') or _theme_accent_color())
        self.fmt_str = QTextCharFormat(); self.fmt_str.setForeground(_theme_token_color('stringColor') or _theme_accent_color())
        self.fmt_comm = QTextCharFormat(); self.fmt_comm.setForeground(_theme_token_color('commentColor') or _theme_muted_color()); self.fmt_comm.setFontItalic(True)
        self.fmt_char = QTextCharFormat(); self.fmt_char.setForeground(_theme_token_color('stringColor') or _theme_accent_color())

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not text:
            return
        n = len(text)
        line = text

        # Block comments /* */ across blocks
        self.setCurrentBlockState(0)
        start = 0
        if self.previousBlockState() == self.IN_BLOCK_COMMENT:
            endc = line.find('*/', start)
            if endc == -1:
                self.setFormat(0, n, self.fmt_comm)
                self.setCurrentBlockState(self.IN_BLOCK_COMMENT)
                return
            else:
                self.setFormat(0, endc + 2, self.fmt_comm)
                start = endc + 2
        while True:
            startc = line.find('/*', start)
            if startc == -1:
                break
            endc = line.find('*/', startc + 2)
            if endc == -1:
                self.setFormat(startc, n - startc, self.fmt_comm)
                self.setCurrentBlockState(self.IN_BLOCK_COMMENT)
                return
            else:
                self.setFormat(startc, endc - startc + 2, self.fmt_comm)
                start = endc + 2

        # Line comments // ...
        cpos = line.find('//')
        code = line
        if cpos != -1:
            self.setFormat(cpos, n - cpos, self.fmt_comm)
            code = line[:cpos]

        # Strings "..." and chars 'c' (no raw strings support here)
        i = 0
        masked = list(code)
        while i < len(code):
            ch = code[i]
            if ch in ('"', "'"):
                q = ch; j = i + 1
                while j < len(code):
                    if code[j] == '\\': j += 2; continue
                    if code[j] == q: j += 1; break
                    j += 1
                self.setFormat(i, j - i, self.fmt_str if q == '"' else self.fmt_char)
                for k in range(i, min(j, len(masked))): masked[k] = ' '
                i = j
            else:
                i += 1
        code = ''.join(masked)

        # Numbers
        i = 0
        while i < len(code):
            ch = code[i]
            if ch.isdigit():
                j = i + 1
                while j < len(code) and (code[j].isdigit() or code[j] in 'xX._'):
                    j += 1
                self.setFormat(i, j - i, self.fmt_num)
                i = j
            else:
                i += 1

        # Keywords
        i = 0
        while i < len(code):
            ch = code[i]
            if ch == '_' or ch.isalpha():
                j = i + 1
                while j < len(code) and (code[j] == '_' or code[j].isalnum()):
                    j += 1
                word = code[i:j]
                if word in self.kw:
                    self.setFormat(i, j - i, self.fmt_kw)
                i = j
            else:
                i += 1


class SimpleGoHighlighter(QSyntaxHighlighter):
    """Minimal Go highlighter using Qt only."""

    IN_BLOCK_COMMENT = 1

    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)
        self.kw = set(
            "break default func interface select case defer go map struct chan else goto package switch const fallthrough if range type continue for import return var true false nil"
            .split()
        )
        self.fmt_kw = QTextCharFormat(); self.fmt_kw.setForeground(_theme_token_color('keywordColor') or _palette_role_color('Link') or _theme_accent_color()); self.fmt_kw.setFontWeight(QFont.Bold)
        self.fmt_num = QTextCharFormat(); self.fmt_num.setForeground(_theme_token_color('numberColor') or _theme_accent_color())
        self.fmt_str = QTextCharFormat(); self.fmt_str.setForeground(_theme_token_color('stringColor') or _theme_accent_color())
        self.fmt_comm = QTextCharFormat(); self.fmt_comm.setForeground(_theme_token_color('commentColor') or _theme_muted_color()); self.fmt_comm.setFontItalic(True)

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not text:
            return
        n = len(text)
        line = text

        # Block comments /* */ across blocks
        self.setCurrentBlockState(0)
        start = 0
        if self.previousBlockState() == self.IN_BLOCK_COMMENT:
            endc = line.find('*/', start)
            if endc == -1:
                self.setFormat(0, n, self.fmt_comm)
                self.setCurrentBlockState(self.IN_BLOCK_COMMENT)
                return
            else:
                self.setFormat(0, endc + 2, self.fmt_comm)
                start = endc + 2
        while True:
            startc = line.find('/*', start)
            if startc == -1:
                break
            endc = line.find('*/', startc + 2)
            if endc == -1:
                self.setFormat(startc, n - startc, self.fmt_comm)
                self.setCurrentBlockState(self.IN_BLOCK_COMMENT)
                return
            else:
                self.setFormat(startc, endc - startc + 2, self.fmt_comm)
                start = endc + 2

        # Line comments // ...
        cpos = line.find('//')
        code = line
        if cpos != -1:
            self.setFormat(cpos, n - cpos, self.fmt_comm)
            code = line[:cpos]

        # Strings "..." and raw `...`
        i = 0
        masked = list(code)
        while i < len(code):
            ch = code[i]
            if ch in ('"', '`'):
                q = ch; j = i + 1
                while j < len(code):
                    if q == '"' and code[j] == '\\': j += 2; continue
                    if code[j] == q: j += 1; break
                    j += 1
                self.setFormat(i, j - i, self.fmt_str)
                for k in range(i, min(j, len(masked))): masked[k] = ' '
                i = j
            else:
                i += 1
        code = ''.join(masked)

        # Numbers
        i = 0
        while i < len(code):
            ch = code[i]
            if ch.isdigit():
                j = i + 1
                while j < len(code) and (code[j].isdigit() or code[j] in 'xX._'):
                    j += 1
                self.setFormat(i, j - i, self.fmt_num)
                i = j
            else:
                i += 1

        # Keywords
        i = 0
        while i < len(code):
            ch = code[i]
            if ch == '_' or ch.isalpha():
                j = i + 1
                while j < len(code) and (code[j] == '_' or code[j].isalnum()):
                    j += 1
                word = code[i:j]
                if word in self.kw:
                    self.setFormat(i, j - i, self.fmt_kw)
                i = j
            else:
                i += 1


class SimpleCHighlighter(QSyntaxHighlighter):
    """Lightweight C/C-like syntax highlighter using Qt only.

    Handles keywords, types, numbers, strings/chars, comments, and preprocessor lines.
    Colors are chosen to be readable on both dark and light themes.
    """

    IN_BLOCK_COMMENT = 1

    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)

        # Formats (use multiple BN token colors when available)
        self.fmt_keyword = QTextCharFormat(); self.fmt_keyword.setForeground(_theme_token_color('keywordColor') or _palette_role_color('Link') or _theme_accent_color()); self.fmt_keyword.setFontWeight(QFont.Bold)
        self.fmt_type    = QTextCharFormat(); self.fmt_type.setForeground(_theme_token_color('typeNameColor') or _palette_role_color('LinkVisited') or _theme_accent_color())
        self.fmt_number  = QTextCharFormat(); self.fmt_number.setForeground(_theme_token_color('numberColor') or _theme_accent_color())
        self.fmt_string  = QTextCharFormat(); self.fmt_string.setForeground(_theme_token_color('stringColor') or _theme_accent_color())
        self.fmt_char    = QTextCharFormat(); self.fmt_char.setForeground(_theme_token_color('stringColor') or _theme_accent_color())
        self.fmt_comment = QTextCharFormat(); self.fmt_comment.setForeground(_theme_token_color('commentColor') or _theme_muted_color()); self.fmt_comment.setFontItalic(True)
        self.fmt_pp      = QTextCharFormat(); self.fmt_pp.setForeground(_theme_token_color('annotationColor') or _palette_role_color('BrightText') or _theme_muted_color())

        # Word sets
        self._keywords = set(
            "auto break case const continue default do else enum extern for goto if register return sizeof static struct switch typedef union volatile while"
            .split()
        )
        self._types = set(
            "void char short int long float double signed unsigned bool _Bool size_t ssize_t intptr_t uintptr_t uint8_t uint16_t uint32_t uint64_t int8_t int16_t int32_t int64_t wchar_t DWORD WORD BYTE QWORD"
            .split()
        )

    def _is_ident_start(self, ch: str) -> bool:
        return ch == '_' or ch.isalpha()

    def _is_ident_part(self, ch: str) -> bool:
        return ch == '_' or ch.isalnum()

    def _apply_words(self, text: str) -> None:
        i = 0
        n = len(text)
        while i < n:
            ch = text[i]
            if not self._is_ident_start(ch):
                i += 1
                continue
            j = i + 1
            while j < n and self._is_ident_part(text[j]):
                j += 1
            word = text[i:j]
            lw = word
            if lw in self._keywords:
                self.setFormat(i, j - i, self.fmt_keyword)
            elif lw in self._types:
                self.setFormat(i, j - i, self.fmt_type)
            i = j

    def _apply_numbers(self, text: str) -> None:
        i = 0
        n = len(text)
        while i < n:
            ch = text[i]
            if ch == '0' and i + 1 < n and text[i+1] in 'xX':
                j = i + 2
                while j < n and (text[j].isdigit() or ('a' <= text[j].lower() <= 'f')):
                    j += 1
                if j > i + 2:
                    self.setFormat(i, j - i, self.fmt_number)
                i = j
            elif ch.isdigit():
                j = i + 1
                while j < n and text[j].isdigit():
                    j += 1
                self.setFormat(i, j - i, self.fmt_number)
                i = j
            else:
                i += 1

    def _apply_strings_and_chars(self, text: str) -> str:
        # We return a copy with strings masked to avoid double-highlighting words inside strings
        out = list(text)
        i = 0
        n = len(text)
        while i < n:
            ch = text[i]
            if ch in ('"', "'"):
                quote = ch
                j = i + 1
                while j < n:
                    if text[j] == '\\':
                        j += 2
                        continue
                    if text[j] == quote:
                        j += 1
                        break
                    j += 1
                length = j - i
                fmt = self.fmt_string if quote == '"' else self.fmt_char
                self.setFormat(i, length, fmt)
                # mask for subsequent passes
                for k in range(i, min(j, n)):
                    out[k] = ' '
                i = j
            else:
                i += 1
        return ''.join(out)

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not text:
            return
        n = len(text)

        # Preprocessor (line starting with # ignoring spaces)
        stripped = text.lstrip()
        if stripped.startswith('#'):
            self.setFormat(0, n, self.fmt_pp)
            return

        # Line comments // ... applied after strings to avoid masking
        line = text

        # Multi-line comments /* ... */ across blocks
        self.setCurrentBlockState(0)
        start = 0
        if self.previousBlockState() == self.IN_BLOCK_COMMENT:
            endc = line.find('*/', start)
            if endc == -1:
                self.setFormat(0, n, self.fmt_comment)
                self.setCurrentBlockState(self.IN_BLOCK_COMMENT)
                return
            else:
                self.setFormat(0, endc + 2, self.fmt_comment)
                start = endc + 2
        while True:
            startc = line.find('/*', start)
            if startc == -1:
                break
            endc = line.find('*/', startc + 2)
            if endc == -1:
                self.setFormat(startc, n - startc, self.fmt_comment)
                self.setCurrentBlockState(self.IN_BLOCK_COMMENT)
                return
            else:
                self.setFormat(startc, endc - startc + 2, self.fmt_comment)
                start = endc + 2

        # Strings/chars first to mask content
        masked = self._apply_strings_and_chars(line)

        # Single-line // comments (apply to original line)
        cpos = masked.find('//')
        if cpos != -1:
            self.setFormat(cpos, n - cpos, self.fmt_comment)
            # Trim masked for further passes
            masked = masked[:cpos]

        # Keywords/types and numbers on masked content only
        self._apply_words(masked)
        self._apply_numbers(masked)


def create_qt_c_highlighter(document):
    """Factory for lightweight C highlighter using Qt only."""
    return SimpleCHighlighter(document)
