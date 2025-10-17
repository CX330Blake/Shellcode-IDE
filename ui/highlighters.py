from __future__ import annotations

"""
Optimized Qt-only syntax highlighters for Assembly, C, Python, Zig, Rust, and Go.

Key improvements vs. the previous version:
- Faster hot paths: fewer temporary QTextCharFormat creations during highlightBlock,
  cached formats, fewer attribute lookups in loops, and reduced string copying.
- Better language coverage: multi-line Python triple-quoted strings, Zig block
  comments across lines, richer number literals (0b/0o/0x, underscores, suffixes),
  asm register sets per arch (x86/x64, arm64, arm, mips, risc-v), and raw strings
  in Rust/Go.
- Theme fidelity: reuses Binary Ninja theme tokens when available; otherwise uses
  QPalette/stylesheet fallbacks. "Good/Bad" colors are derived once and reused.
- Safer fallbacks: robust to PySide2/PySide6, missing app palette, no-Pygments envs.

Factory helpers:
- create_disassembly_highlighter(document, arch_name="x86_64") -> SimpleAsmHighlighter
- create_code_highlighter(document, lexer_name, style_name=None) -> Simple*Highlighter | None
- create_best_highlighter(document, language, prefer_pygments=True) -> QSyntaxHighlighter

This file has no external runtime deps beyond PySide2/6. Pygments is optional.
"""

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

# --------------------------
# Theme / color helpers
# --------------------------

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
        c = pal.color(QPalette.Link)
        if not c.isValid():
            c = pal.color(QPalette.Highlight)
        return c if c.isValid() else QColor('#007ACC')
    except Exception:
        return QColor('#007ACC')


def _palette_role_color(role_name: str) -> QColor | None:
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


def _good_bad_colors() -> tuple[QColor, QColor]:
    """(good_green, bad_red) from BN theme/palette when available."""
    try:
        from binaryninjaui import ThemeColor, getThemeColor  # type: ignore

        def _try_named(var_name: str):
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
            try:
                c = getThemeColor(var_name)  # type: ignore[arg-type]
                if c is not None and c.isValid():
                    return c
            except Exception:
                pass
            return None

        g = _try_named('green') or _try_named('success')
        r = _try_named('red') or _try_named('error')
        if g is None:
            for name in ('GreenStandardHighlightColor','GreenStandardColor','GreenStandard','Green'):
                if hasattr(ThemeColor, name):
                    c = getThemeColor(getattr(ThemeColor, name))
                    if c and c.isValid():
                        g = c; break
        if r is None:
            for name in ('RedStandardHighlightColor','RedStandardColor','RedStandard','Red'):
                if hasattr(ThemeColor, name):
                    c = getThemeColor(getattr(ThemeColor, name))
                    if c and c.isValid():
                        r = c; break
        if g and r and g.isValid() and r.isValid():
            return g, r
    except Exception:
        pass
    pal = _theme_palette()
    if pal:
        try:
            good = pal.color(QPalette.Highlight)
            bad = pal.color(QPalette.BrightText)
            if not bad.isValid() or bad == good:
                bad = QColor(pal.color(QPalette.Link)).darker(150)
            return good, bad
        except Exception:
            pass
    return QColor('#2ecc71'), QColor('#e74c3c')


def _stylesheet_color_for(*keywords: str) -> QColor | None:
    try:
        app = QApplication.instance()
        if not app:
            return None
        qss = app.styleSheet() or ""
        if not qss:
            return None
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
                    if val.lower().startswith('palette('):
                        role = val[val.find('(')+1: val.rfind(')')].strip().lower()
                        try:
                            role_map = {
                                'text': QPalette.Text,
                                'windowtext': QPalette.WindowText,
                                'highlight': QPalette.Highlight,
                                'link': QPalette.Link,
                                'brighttext': QPalette.BrightText,
                            }
                            pal = _theme_palette()
                            if pal and role in role_map:
                                return pal.color(role_map[role])
                        except Exception:
                            pass
                    c = QColor(val)
                    if c.isValid():
                        return c
        return None
    except Exception:
        return None


def _theme_token_color(role: str) -> QColor | None:
    role_l = (role or '').lower().strip()
    try:
        from binaryninjaui import ThemeColor, getThemeColor  # type: ignore
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


def _tint(bg: QColor, alpha: int = 32) -> QColor:
    c = QColor(bg)
    c.setAlpha(max(16, min(96, int(alpha))))
    return c

# --------------------------
# Optional Pygments adapter
# --------------------------

class PygmentsHighlighter(QSyntaxHighlighter):
    """QSyntaxHighlighter adapter that uses Pygments for tokenization + styling.

    If Pygments is unavailable or a lexer cannot be created, initialization
    raises ImportError so callers can fallback to a simpler highlighter.
    """

    def __init__(
        self,
        parent_document,
        lexer_name: str = "asm",
        style_name: str | None = None,
        debug: bool = False,
    ):
        QSyntaxHighlighter.__init__(self)
        self._debug = bool(debug)
        if self._debug:
            print(f"[Highlighter] Pygments: lexer={lexer_name} style={style_name or 'auto'}")

        self.lexer = None
        self.formats: dict = {}
        self.default_format = QTextCharFormat()
        try:
            import pygments  # noqa: F401
            from pygments.lexers import get_lexer_by_name
            from pygments.styles import get_style_by_name
            from pygments.token import Token
        except Exception as exc:
            if self._debug:
                print(f"[Highlighter] Pygments not available: {exc}")
            raise ImportError("pygments is not available") from exc

        try:
            self.lexer = get_lexer_by_name(lexer_name)
        except Exception as exc:
            if self._debug:
                print(f"[Highlighter] Failed lexer {lexer_name}: {exc}; using text")
            self.lexer = get_lexer_by_name("text")

        if style_name is None:
            # try to pick something close to current theme
            style_name = _first_available_style(("native","monokai","friendly","default")) or "default"
        try:
            self.style = get_style_by_name(style_name)
        except Exception:
            self.style = get_style_by_name("default")

        self.formats = {}
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
                    # Respect app preference: do not bold code
                    pass
                elif p == 'italic':
                    fmt.setFontItalic(True)
                elif p == 'underline':
                    fmt.setFontUnderline(True)
                elif p.startswith('bg:'):
                    col = p[3:]
                    fmt.setBackground(_qcolor_from_css(col))
                else:
                    fmt.setForeground(_qcolor_from_css(p))
            return fmt

        for token, spec in style_map.items():
            fmt = parse_spec(spec)
            self.formats[token] = fmt

        self.token_cache: dict = {}
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

        try:
            self.setDocument(parent_document)
        except Exception:
            pass
        self.mnemonic_format = QTextCharFormat()
        wtxt_col = _palette_role_color('WindowText')
        self.mnemonic_format.setForeground(
            wtxt_col if wtxt_col and wtxt_col.isValid() else _theme_accent_color()
        )

    def _format_for(self, token):
        if token in self.formats:
            return self.formats[token]
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
        try:
            stripped = text.lstrip()
            if stripped:
                start = len(text) - len(stripped)
                end = start
                n = len(text)
                while end < n and not text[end].isspace() and text[end] not in ',;#':
                    end += 1
                if end > start:
                    self.setFormat(start, end - start, self.mnemonic_format)
        except Exception:
            pass

# --------------------------
# Utility predicates
# --------------------------

def _is_hex_digit(ch: str) -> bool:
    cl = ch.lower()
    return ('0' <= cl <= '9') or ('a' <= cl <= 'f')

# --------------------------
# Assembly (multi-arch)
# --------------------------

class SimpleAsmHighlighter(QSyntaxHighlighter):
    """Lightweight assembly/disassembly highlighter.

    - Highlights address field, labels, mnemonics, registers, immediates, comments.
    - Supports comments starting with ';', '#', or '//' and basic strings.
    - Register set adapts to arch_name in {x86, x86_64, amd64, arm64, aarch64, arm,
      mips, mips64, riscv, riscv64}.
    """

    def __init__(self, document, arch_name: str = "x86_64"):
        QSyntaxHighlighter.__init__(self, document)

        accent = _theme_accent_color()
        muted = _theme_muted_color()

        # Prefer Binary Ninja theme token roles first; only fall back to palette/stylesheet if unavailable
        c_mnemonic = _palette_role_color('Text') or accent
        c_register = _theme_token_color('registerColor') or _stylesheet_color_for('register') or QColor(accent).darker(115)
        c_number   = _theme_token_color('numberColor')   or _stylesheet_color_for('number','immediate') or QColor(accent).lighter(115)
        c_comment  = _theme_token_color('commentColor')  or _stylesheet_color_for('comment') or muted
        c_label    = _theme_token_color('gotoLabelColor') or _stylesheet_color_for('label') or QColor(accent).darker(115)
        c_operator = _theme_token_color('operationColor') or _stylesheet_color_for('operator','punct') or _theme_muted_color()
        c_address  = _theme_token_color('addressColor') or muted

        self.fmt_mnemonic = QTextCharFormat(); self.fmt_mnemonic.setForeground(c_mnemonic)
        self.fmt_register = QTextCharFormat(); self.fmt_register.setForeground(c_register)
        self.fmt_number   = QTextCharFormat(); self.fmt_number.setForeground(c_number)
        self.fmt_comment  = QTextCharFormat(); self.fmt_comment.setForeground(c_comment); self.fmt_comment.setFontItalic(True)
        self.fmt_label    = QTextCharFormat(); self.fmt_label.setForeground(c_label)
        self.fmt_operator = QTextCharFormat(); self.fmt_operator.setForeground(c_operator)
        self.fmt_address  = QTextCharFormat(); self.fmt_address.setForeground(c_address)

        self._arch = (arch_name or "x86_64").lower()
        self._reg_words = self._build_regset(self._arch)

    def _build_regset(self, arch: str) -> set[str]:
        x86_regs = {
            # x86_64
            "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
            "r8","r9","r10","r11","r12","r13","r14","r15",
            # x86
            "eax","ebx","ecx","edx","esi","edi","ebp","esp",
            "ax","bx","cx","dx","si","di","bp","sp",
            "al","bl","cl","dl","ah","bh","ch","dh",
            # ip
            "eip","rip",
        }
        simd = {*(f"xmm{i}" for i in range(32)), *(f"ymm{i}" for i in range(32)), *(f"zmm{i}" for i in range(32))}
        arm64_regs = {*(f"x{i}" for i in range(31)), *(f"w{i}" for i in range(31)), "sp","zr","lr"}
        arm_regs = {*(f"r{i}" for i in range(16)), "sp","ip","lr","pc","cpsr"}
        mips_regs = {"zero","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4","t5","t6","t7","s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1","gp","sp","fp","ra"}
        riscv_regs = {*(f"x{i}" for i in range(32)), "sp","gp","tp","ra","fp","s0","s1","a0","a1","a2","a3","a4","a5","a6","a7","t0","t1","t2","t3","t4","t5","t6"}
        if arch in ("x86","i386"):
            return x86_regs | simd
        if arch in ("x86_64","amd64"):
            return x86_regs | simd
        if arch in ("arm64","aarch64"):
            return arm64_regs
        if arch in ("arm","armv7"):
            return arm_regs
        if arch.startswith("mips"):
            return mips_regs
        if arch.startswith("riscv"):
            return riscv_regs
        return x86_regs | simd

    def _is_hex_prefix(self, s: str, i: int) -> bool:
        return i + 2 <= len(s) and s[i] == '0' and (i + 1 < len(s) and (s[i + 1] in 'xX'))

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not text:
            return
        setFormat = self.setFormat
        fmt_comment = self.fmt_comment
        fmt_operator = self.fmt_operator
        fmt_number = self.fmt_number
        fmt_register = self.fmt_register
        fmt_mnemonic = self.fmt_mnemonic
        fmt_label = self.fmt_label
        fmt_address = self.fmt_address

        n = len(text)

        # Address field like "00401000:" (supports 0x... too)
        try:
            ls = len(text) - len(text.lstrip())
            j = ls
            if j < n and text[j] == '0' and j + 1 < n and text[j+1] in 'xX':
                j += 2
            k = j
            while k < n and (text[k].isdigit() or ('a' <= text[k].lower() <= 'f')):
                k += 1
            if k > j and k < n and text[k] == ':':
                setFormat(ls, k - ls, fmt_address)
        except Exception:
            pass

        # Comments
        cpos = text.find('//')
        cmark = None
        if cpos != -1:
            cmark = ('//', cpos)
        else:
            for mark in (';', '#'):
                pos = text.find(mark)
                if pos != -1:
                    cmark = (mark, pos)
                    break
        code = text
        if cmark is not None:
            pos = cmark[1]
            setFormat(pos, n - pos, fmt_comment)
            code = text[:pos]
            n = len(code)

        # Labels at line start
        stripped = code.lstrip()
        if stripped:
            start = len(code) - len(stripped)
            i = start
            ch0 = code[i] if i < n else ''
            if ch0 == '_' or ch0.isalpha():
                j = i + 1
                while j < n and (code[j] == '_' or code[j].isalnum()):
                    j += 1
                if j < n and code[j] == ':':
                    setFormat(i, j - i + 1, fmt_label)
                    return

        # Mnemonic (first token)
        if stripped:
            start = len(code) - len(stripped)
            end = start
            while end < n and not code[end].isspace() and code[end] not in ',;#':
                end += 1
            if end > start:
                setFormat(start, end - start, fmt_mnemonic)

        # Remainder: registers, numbers, operators, strings
        i = 0
        regs = self._reg_words
        while i < n:
            ch = code[i]
            if ch.isspace():
                i += 1; continue
            if ch in ',:+-*/()[]{}<>|&^~%':
                setFormat(i, 1, fmt_operator)
                i += 1; continue
            if self._is_hex_prefix(code, i):
                j = i + 2
                while j < n and _is_hex_digit(code[j]):
                    j += 1
                if j > i + 2:
                    setFormat(i, j - i, fmt_number)
                i = j; continue
            # 0b/0o binary/octal
            if i + 2 <= n and code[i] == '0' and i + 1 < n and code[i+1] in 'bBoO':
                j = i + 2
                valid = '01' if code[i+1] in 'bB' else '01234567'
                while j < n and code[j] in valid:
                    j += 1
                if j > i + 2:
                    setFormat(i, j - i, fmt_number)
                i = j; continue
            if ch.isdigit():
                j = i + 1
                while j < n and code[j].isdigit():
                    j += 1
                setFormat(i, j - i, fmt_number)
                i = j; continue
            if ch in ('"', "'"):
                q = ch; j = i + 1
                while j < n:
                    if code[j] == '\\':
                        j += 2; continue
                    if code[j] == q:
                        j += 1; break
                    j += 1
                # reuse number color for strings to keep palette simple
                setFormat(i, j - i, fmt_number)
                i = j; continue
            if ch == '_' or ch.isalpha():
                j = i + 1
                while j < n and (code[j] == '_' or code[j].isalnum()):
                    j += 1
                word = code[i:j].lower()
                if word in regs:
                    setFormat(i, j - i, fmt_register)
                i = j; continue
            i += 1

# --------------------------
# C and C-like
# --------------------------

class SimpleCHighlighter(QSyntaxHighlighter):
    """Lightweight C/C-like syntax highlighter using Qt only."""

    IN_BLOCK_COMMENT = 1

    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)

        self.fmt_keyword = QTextCharFormat(); self.fmt_keyword.setForeground(_theme_token_color('keywordColor') or _palette_role_color('Link') or _theme_accent_color())
        self.fmt_type    = QTextCharFormat(); self.fmt_type.setForeground(_theme_token_color('typeNameColor') or _palette_role_color('LinkVisited') or _theme_accent_color())
        self.fmt_number  = QTextCharFormat(); self.fmt_number.setForeground(_theme_token_color('numberColor') or _theme_accent_color())
        self.fmt_string  = QTextCharFormat(); self.fmt_string.setForeground(_theme_token_color('stringColor') or _theme_accent_color())
        self.fmt_char    = QTextCharFormat(); self.fmt_char.setForeground(_theme_token_color('stringColor') or _theme_accent_color())
        self.fmt_comment = QTextCharFormat(); self.fmt_comment.setForeground(_theme_token_color('commentColor') or _theme_muted_color()); self.fmt_comment.setFontItalic(True)
        self.fmt_pp      = QTextCharFormat(); self.fmt_pp.setForeground(_theme_token_color('annotationColor') or _palette_role_color('BrightText') or _theme_muted_color())

        self._keywords = set(
            "auto break case const continue default do else enum extern for goto if register return sizeof static struct switch typedef union volatile while inline _Atomic _Alignas _Alignof _Thread_local"
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
        i = 0; n = len(text); setFormat = self.setFormat
        fmt_kw = self.fmt_keyword; fmt_ty = self.fmt_type
        while i < n:
            ch = text[i]
            if not self._is_ident_start(ch):
                i += 1; continue
            j = i + 1
            while j < n and self._is_ident_part(text[j]):
                j += 1
            word = text[i:j]
            if word in self._keywords:
                setFormat(i, j - i, fmt_kw)
            elif word in self._types:
                setFormat(i, j - i, fmt_ty)
            i = j

    def _apply_numbers(self, text: str) -> None:
        i = 0; n = len(text); setFormat = self.setFormat; fmt_num = self.fmt_number
        while i < n:
            ch = text[i]
            if ch == '0' and i + 1 < n and text[i+1] in 'xX':
                j = i + 2
                while j < n and _is_hex_digit(text[j]):
                    j += 1
                # integer suffixes U/L combinations
                while j < n and text[j] in 'uUlL':
                    j += 1
                if j > i + 2:
                    setFormat(i, j - i, fmt_num)
                i = j
            elif ch.isdigit():
                j = i + 1
                while j < n and (text[j].isdigit() or text[j] in '._'):
                    j += 1
                # optional float suffixes fFlL
                if j < n and text[j] in 'fFlL':
                    j += 1
                setFormat(i, j - i, fmt_num)
                i = j
            else:
                i += 1

    def _apply_strings_and_chars(self, text: str) -> str:
        out = list(text); setFormat = self.setFormat
        i = 0; n = len(text)
        fmt_str = self.fmt_string; fmt_char = self.fmt_char
        while i < n:
            ch = text[i]
            if ch in ('"', "'"):
                quote = ch; j = i + 1
                while j < n:
                    if text[j] == '\\':
                        j += 2; continue
                    if text[j] == quote:
                        j += 1; break
                    j += 1
                fmt = fmt_str if quote == '"' else fmt_char
                setFormat(i, j - i, fmt)
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

        stripped = text.lstrip()
        if stripped.startswith('#'):
            self.setFormat(0, n, self.fmt_pp)
            return

        line = text
        self.setCurrentBlockState(0)
        start = 0
        # Collect comment spans on this line so later passes don't recolor inside them
        comment_spans: list[tuple[int, int]] = []
        if self.previousBlockState() == self.IN_BLOCK_COMMENT:
            endc = line.find('*/', start)
            if endc == -1:
                self.setFormat(0, n, self.fmt_comment)
                self.setCurrentBlockState(self.IN_BLOCK_COMMENT)
                return
            else:
                self.setFormat(0, endc + 2, self.fmt_comment)
                comment_spans.append((0, endc + 2))
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
                comment_spans.append((startc, endc + 2))
                start = endc + 2

        masked = self._apply_strings_and_chars(line)
        # Line comments (//) — add to comment spans and mask, rather than slicing only
        cpos = line.find('//')
        if cpos != -1:
            self.setFormat(cpos, n - cpos, self.fmt_comment)
            comment_spans.append((cpos, n))

        # Mask all comment spans to prevent subsequent passes from recoloring within them
        if comment_spans:
            ml = list(masked)
            for a, b in comment_spans:
                a0 = max(0, min(len(ml), a))
                b0 = max(a0, min(len(ml), b))
                for k in range(a0, b0):
                    ml[k] = ' '
            masked = ''.join(ml)

        self._apply_words(masked)
        self._apply_numbers(masked)
        # Function calls: identifier followed by '(' outside strings/comments
        try:
            i = 0; n = len(masked); setFormat = self.setFormat
            while i < n:
                if (masked[i] == '_' or masked[i].isalpha()):
                    j = i + 1
                    while j < n and (masked[j] == '_' or masked[j].isalnum()): j += 1
                    k = j
                    while k < n and masked[k].isspace(): k += 1
                    if k < n and masked[k] == '(':
                        # Use number color for subtle calls, or a code symbol color if available
                        fmt = QTextCharFormat(self.fmt_number)
                        cs = _theme_token_color('codeSymbolColor')
                        if cs and cs.isValid():
                            fmt.setForeground(cs)
                        setFormat(i, j - i, fmt)
                        i = j; continue
                    i = j
                else:
                    i += 1
        except Exception:
            pass

# --------------------------
# Python
# --------------------------

class SimplePythonHighlighter(QSyntaxHighlighter):
    """Minimal Python highlighter with triple-quote support across blocks."""

    IN_TRIPLE_SINGLE = 1
    IN_TRIPLE_DOUBLE = 2

    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)
        self.kw = set(
            "and as assert break class continue def del elif else except False finally for from global if import in is lambda None nonlocal not or pass raise return True try while with yield async await"
            .split()
        )
        self.fmt_kw = QTextCharFormat(); self.fmt_kw.setForeground(_theme_token_color('keywordColor') or _palette_role_color('Link') or _theme_accent_color())
        self.fmt_num = QTextCharFormat(); self.fmt_num.setForeground(_theme_token_color('numberColor') or _theme_accent_color())
        self.fmt_str = QTextCharFormat(); self.fmt_str.setForeground(_theme_token_color('stringColor') or _theme_accent_color())
        self.fmt_comm = QTextCharFormat(); self.fmt_comm.setForeground(_theme_token_color('commentColor') or _theme_muted_color()); self.fmt_comm.setFontItalic(True)
        # Extras: functions, builtins, decorators
        self.builtins = set(
            "abs all any ascii bin bool bytearray bytes callable chr classmethod compile complex delattr dict dir divmod enumerate eval exec filter float format getattr globals hasattr hash hex id input int isinstance issubclass iter len list locals map max min next object oct open ord pow print property range repr reversed round set setattr slice sorted staticmethod str sum super tuple type vars zip".split()
        )
        self.fmt_func = QTextCharFormat(); self.fmt_func.setForeground(_theme_token_color('codeSymbolColor') or _palette_role_color('LinkVisited') or _theme_accent_color())
        self.fmt_def  = QTextCharFormat(); self.fmt_def.setForeground(_theme_token_color('codeSymbolColor') or _theme_accent_color())
        self.fmt_builtin = QTextCharFormat(); self.fmt_builtin.setForeground(_theme_token_color('annotationColor') or _palette_role_color('BrightText') or _theme_muted_color())
        self.fmt_deco = QTextCharFormat(); self.fmt_deco.setForeground(_theme_token_color('annotationColor') or _theme_muted_color()); self.fmt_deco.setFontItalic(True)

    def _mask_strings_numbers_keywords(self, code: str) -> None:
        # Numbers
        i = 0; n = len(code); setFormat = self.setFormat; fmt_num = self.fmt_num
        # hex/bin/oct/decimal with underscores
        while i < n:
            ch = code[i]
            if ch == '0' and i + 1 < n and code[i+1] in 'xXbBoO':
                j = i + 2
                valid = '01' if code[i+1] in 'bB' else ('01234567' if code[i+1] in 'oO' else None)
                if valid is None:
                    while j < n and _is_hex_digit(code[j]): j += 1
                else:
                    while j < n and code[j] in valid: j += 1
                if j > i + 2:
                    setFormat(i, j - i, fmt_num)
                i = j
            elif ch.isdigit():
                j = i + 1
                while j < n and (code[j].isdigit() or code[j] in '._'):
                    j += 1
                setFormat(i, j - i, fmt_num)
                i = j
            else:
                i += 1

        # Operators and punctuation colored with operationColor
        try:
            s = code; L = len(s); i = 0; setFormat = self.setFormat; fmt_op = self.fmt_op
            ops = set(',:+-*/()[]{}<>|&^~%!=?:.;')
            while i < L:
                ch = s[i]
                if ch in ops:
                    setFormat(i, 1, fmt_op)
                i += 1
        except Exception:
            pass
        # Keywords
        i = 0; n = len(code); fmt_kw = self.fmt_kw
        def is_start(c: str) -> bool: return c == '_' or c.isalpha()
        def is_part(c: str) -> bool: return c == '_' or c.isalnum()
        while i < n:
            ch = code[i]
            if is_start(ch):
                j = i + 1
                while j < n and is_part(code[j]): j += 1
                word = code[i:j]
                if word in self.kw:
                    setFormat(i, j - i, fmt_kw)
                i = j
            else:
                i += 1

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not text:
            return
        n = len(text)
        line = text
        setFormat = self.setFormat
        fmt_str = self.fmt_str
        fmt_comm = self.fmt_comm

        # Handle triple-quoted strings across blocks
        self.setCurrentBlockState(0)
        start = 0
        prev = self.previousBlockState()
        if prev in (self.IN_TRIPLE_SINGLE, self.IN_TRIPLE_DOUBLE):
            delim = "'''" if prev == self.IN_TRIPLE_SINGLE else '"""'
            endc = line.find(delim, start)
            if endc == -1:
                setFormat(0, n, fmt_str)
                self.setCurrentBlockState(prev)
                return
            else:
                setFormat(0, endc + 3, fmt_str)
                start = endc + 3

        # Single-line comments
        cpos = line.find('#', start)
        code = line
        if cpos != -1:
            setFormat(cpos, n - cpos, fmt_comm)
            code = line[:cpos]

        # Strings (single/double and triple-quote openers)
        i = start; masked = list(code)
        while i < len(code):
            ch = code[i]
            if ch in ('"', "'"):
                # triple or single
                is_triple = (i + 2 < len(code) and code[i+1] == ch and code[i+2] == ch)
                if is_triple:
                    delim = ch * 3
                    j = i + 3
                    endc = code.find(delim, j)
                    if endc == -1:
                        setFormat(i, len(code) - i, fmt_str)
                        self.setCurrentBlockState(self.IN_TRIPLE_SINGLE if ch == "'" else self.IN_TRIPLE_DOUBLE)
                        code = code[:i]  # mask rest
                        break
                    else:
                        setFormat(i, endc - i + 3, fmt_str)
                        for k in range(i, min(endc + 3, len(masked))): masked[k] = ' '
                        i = endc + 3
                        continue
                # single/double quoted
                j = i + 1
                while j < len(code):
                    if code[j] == '\\': j += 2; continue
                    if code[j] == ch: j += 1; break
                    j += 1
                setFormat(i, j - i, fmt_str)
                for k in range(i, min(j, len(masked))): masked[k] = ' '
                i = j
            else:
                i += 1
        code_masked = ''.join(masked)

        # Numbers and keywords on masked code
        self._mask_strings_numbers_keywords(code_masked)

        # Decorators at line start: @name
        try:
            stripped = line.lstrip()
            if stripped.startswith('@'):
                start = len(line) - len(stripped)
                j = start + 1
                while j < len(line) and (line[j] == '_' or line[j].isalnum()):
                    j += 1
                setFormat(start, j - start, self.fmt_deco)
        except Exception:
            pass

        # Function definitions: def name(
        try:
            def_kw = 'def '
            pos = code_masked.find(def_kw)
            if pos != -1:
                k = pos + len(def_kw)
                while k < len(code_masked) and code_masked[k].isspace():
                    k += 1
                j = k
                while j < len(code_masked) and (code_masked[j] == '_' or code_masked[j].isalnum()):
                    j += 1
                if j > k:
                    setFormat(k, j - k, self.fmt_def)
        except Exception:
            pass

        # Builtins and function calls: name(...)
        try:
            i = 0; s = code_masked; L = len(s)
            while i < L:
                ch = s[i]
                if ch == '_' or ch.isalpha():
                    j = i + 1
                    while j < L and (s[j] == '_' or s[j].isalnum()): j += 1
                    name = s[i:j]
                    # Builtins
                    if name in self.builtins:
                        setFormat(i, j - i, self.fmt_builtin)
                    # Calls
                    k = j
                    while k < L and s[k].isspace(): k += 1
                    if k < L and s[k] == '(' and name not in self.kw:
                        setFormat(i, j - i, self.fmt_func)
                        i = j; continue
                    i = j
                else:
                    i += 1
        except Exception:
            pass

# --------------------------
# Zig
# --------------------------

class SimpleZigHighlighter(QSyntaxHighlighter):
    """Minimal Zig highlighter with block comment state."""

    IN_BLOCK_COMMENT = 1

    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)
        self.kw = set(
            "const var fn pub usingnamespace comptime if else switch while for defer errdefer try catch return break continue struct enum union opaque anytype error or and not true false null asm volatile align addressspace linksection packed export extern inline noinline callconv suspend resume await"
            .split()
        )
        self.types = set("u8 u16 u32 u64 usize i8 i16 i32 i64 isize f16 f32 f64 bool void noreturn anyerror type comptime_int comptime_float".split())
        self.fmt_kw = QTextCharFormat(); self.fmt_kw.setForeground(_theme_token_color('keywordColor') or _palette_role_color('Link') or _theme_accent_color())
        self.fmt_num = QTextCharFormat(); self.fmt_num.setForeground(_theme_token_color('numberColor') or _theme_accent_color())
        self.fmt_str = QTextCharFormat(); self.fmt_str.setForeground(_theme_token_color('stringColor') or _theme_accent_color())
        self.fmt_comm = QTextCharFormat(); self.fmt_comm.setForeground(_theme_token_color('commentColor') or _theme_muted_color()); self.fmt_comm.setFontItalic(True)
        self.fmt_type = QTextCharFormat(); self.fmt_type.setForeground(_theme_token_color('typeNameColor') or _palette_role_color('LinkVisited') or _theme_accent_color())
        self.fmt_func = QTextCharFormat(); self.fmt_func.setForeground(_theme_token_color('codeSymbolColor') or _palette_role_color('Link') or _theme_accent_color())
        self.fmt_builtin = QTextCharFormat(); self.fmt_builtin.setForeground(_theme_token_color('addressColor') or _theme_muted_color())

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not text:
            return
        setFormat = self.setFormat
        fmt_comm = self.fmt_comm
        fmt_str = self.fmt_str
        fmt_num = self.fmt_num
        fmt_kw = self.fmt_kw

        line = text
        n = len(line)
        self.setCurrentBlockState(0)
        start = 0
        if self.previousBlockState() == self.IN_BLOCK_COMMENT:
            endc = line.find('*/', start)
            if endc == -1:
                setFormat(0, n, fmt_comm)
                self.setCurrentBlockState(self.IN_BLOCK_COMMENT)
                return
            else:
                setFormat(0, endc + 2, fmt_comm)
                start = endc + 2
        while True:
            startc = line.find('/*', start)
            if startc == -1:
                break
            endc = line.find('*/', startc + 2)
            if endc == -1:
                setFormat(startc, n - startc, fmt_comm)
                self.setCurrentBlockState(self.IN_BLOCK_COMMENT)
                return
            else:
                setFormat(startc, endc - startc + 2, fmt_comm)
                start = endc + 2

        # // comments
        cpos = line.find('//')
        code = line
        if cpos != -1:
            setFormat(cpos, n - cpos, fmt_comm)
            code = line[:cpos]

        # Strings
        i = 0; masked = list(code)
        while i < len(code):
            ch = code[i]
            if ch in ('"', "'"):
                q = ch; j = i + 1
                while j < len(code):
                    if code[j] == '\\': j += 2; continue
                    if code[j] == q: j += 1; break
                    j += 1
                setFormat(i, j - i, fmt_str)
                for k in range(i, min(j, len(masked))): masked[k] = ' '
                i = j
            else:
                i += 1
        code = ''.join(masked)

        # Numbers (0x/0b/0o and decimal with underscores)
        i = 0; n = len(code)
        while i < n:
            ch = code[i]
            if ch == '0' and i + 1 < n and code[i+1] in 'xXbBoO':
                j = i + 2
                if code[i+1] in 'xX':
                    while j < n and (_is_hex_digit(code[j]) or code[j] == '_'): j += 1
                elif code[i+1] in 'bB':
                    while j < n and (code[j] in '01' or code[j] == '_'): j += 1
                else:
                    while j < n and (code[j] in '01234567' or code[j] == '_'): j += 1
                if j > i + 2:
                    setFormat(i, j - i, fmt_num)
                i = j
            elif ch.isdigit():
                j = i + 1
                while j < n and (code[j].isdigit() or code[j] in '._'): j += 1
                setFormat(i, j - i, fmt_num)
                i = j
            else:
                i += 1

        # Keywords / types / builtins (Zig builtins start with '@')
        i = 0; n = len(code)
        def is_start(c: str) -> bool: return c == '_' or c.isalpha()
        def is_part(c: str) -> bool: return c == '_' or c.isalnum()
        while i < n:
            ch = code[i]
            # Builtin: @name
            if ch == '@':
                j = i + 1
                while j < n and is_part(code[j]): j += 1
                setFormat(i, j - i, self.fmt_builtin)
                i = j; continue
            if is_start(ch):
                j = i + 1
                while j < n and is_part(code[j]): j += 1
                word = code[i:j]
                if word in self.kw:
                    setFormat(i, j - i, fmt_kw)
                elif word in self.types:
                    setFormat(i, j - i, self.fmt_type)
                i = j
            else:
                i += 1

        # Function defs: fn name(
        try:
            fn_pos = code.find('fn ')
            if fn_pos != -1:
                k = fn_pos + 3
                while k < len(code) and code[k].isspace(): k += 1
                j = k
                while j < len(code) and (code[j] == '_' or code[j].isalnum()): j += 1
                if j > k:
                    setFormat(k, j - k, self.fmt_func)
        except Exception:
            pass

        # Calls: name( — only start at identifier boundaries and skip builtins (preceded by '@')
        try:
            i = 0
            while i < len(code):
                prev = code[i-1] if i > 0 else ' '
                if (code[i] == '_' or code[i].isalpha()) and (i == 0 or (prev != '@' and not (prev == '_' or prev.isalnum()))):
                    j = i + 1
                    while j < len(code) and (code[j] == '_' or code[j].isalnum()): j += 1
                    name = code[i:j]
                    k = j
                    while k < len(code) and code[k].isspace(): k += 1
                    if k < len(code) and code[k] == '(' and name not in self.kw and name not in self.types and not name.startswith('@'):
                        setFormat(i, j - i, self.fmt_func)
                        i = j; continue
                    i = j
                else:
                    i += 1
        except Exception:
            pass

# --------------------------
# Rust
# --------------------------

class SimpleRustHighlighter(QSyntaxHighlighter):
    """Minimal Rust highlighter (line/block comments, raw strings, numbers, keywords)."""

    IN_BLOCK_COMMENT = 1

    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)
        self.kw = set(
            "as break const continue crate else enum extern false fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait true type unsafe use where while dyn async await"
            .split()
        )
        self.types = set("u8 u16 u32 u64 usize i8 i16 i32 i64 isize f32 f64 bool char str String Option Result Box Vec".split())
        self.fmt_kw = QTextCharFormat();   
        self.fmt_kw.setForeground(_theme_token_color('keywordColor')    or _palette_role_color('Link')        or _theme_accent_color()); 
        # No bold styling

        self.fmt_num = QTextCharFormat();  
        self.fmt_num.setForeground(_theme_token_color('numberColor')     or _theme_accent_color())

        self.fmt_str = QTextCharFormat();  self.fmt_str.setForeground(_theme_token_color('stringColor')     or _theme_accent_color())
        self.fmt_comm = QTextCharFormat(); self.fmt_comm.setForeground(_theme_token_color('commentColor')    or _theme_muted_color()); self.fmt_comm.setFontItalic(True)
        self.fmt_char = QTextCharFormat(); self.fmt_char.setForeground(_theme_token_color('stringColor')     or _theme_accent_color())
        self.fmt_type = QTextCharFormat(); self.fmt_type.setForeground(_theme_token_color('typeNameColor')   or _palette_role_color('LinkVisited') or _theme_accent_color())
        self.fmt_func = QTextCharFormat(); self.fmt_func.setForeground(_theme_token_color('codeSymbolColor') or _theme_accent_color())
        self.fmt_macro = QTextCharFormat();self.fmt_macro.setForeground(_theme_token_color('annotationColor') or _theme_muted_color())
        self.fmt_op   = QTextCharFormat(); self.fmt_op.setForeground(_theme_token_color('operationColor') or _theme_muted_color())

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not text:
            return
        setFormat = self.setFormat
        fmt_comm = self.fmt_comm
        fmt_str = self.fmt_str
        fmt_char = self.fmt_char
        fmt_num = self.fmt_num
        fmt_kw = self.fmt_kw

        line = text
        n = len(line)
        self.setCurrentBlockState(0)
        start = 0
        if self.previousBlockState() == self.IN_BLOCK_COMMENT:
            endc = line.find('*/', start)
            if endc == -1:
                setFormat(0, n, fmt_comm)
                self.setCurrentBlockState(self.IN_BLOCK_COMMENT)
                return
            else:
                setFormat(0, endc + 2, fmt_comm)
                start = endc + 2
        while True:
            startc = line.find('/*', start)
            if startc == -1:
                break
            endc = line.find('*/', startc + 2)
            if endc == -1:
                setFormat(startc, n - startc, fmt_comm)
                self.setCurrentBlockState(self.IN_BLOCK_COMMENT)
                return
            else:
                setFormat(startc, endc - startc + 2, fmt_comm)
                start = endc + 2

        # Line comments
        cpos = line.find('//')
        code = line
        if cpos != -1:
            setFormat(cpos, n - cpos, fmt_comm)
            code = line[:cpos]

        # Strings / chars / raw strings r"..." r#"..."# (single-line only here)
        i = 0; masked = list(code)
        while i < len(code):
            ch = code[i]
            if ch in ('"', "'"):
                q = ch; j = i + 1
                while j < len(code):
                    if code[j] == '\\': j += 2; continue
                    if code[j] == q: j += 1; break
                    j += 1
                setFormat(i, j - i, fmt_str if q == '"' else fmt_char)
                for k in range(i, min(j, len(masked))): masked[k] = ' '
                i = j; continue
            if ch == 'r' and i + 1 < len(code) and code[i+1] in ('"', '#'):
                # r"..." or r#"..."#
                j = i + 1
                hashes = 0
                while j < len(code) and code[j] == '#':
                    hashes += 1; j += 1
                if j < len(code) and code[j] == '"':
                    j += 1
                    closing = '"' + ('#' * hashes)
                    endc = code.find(closing, j)
                    if endc == -1:
                        endc = len(code)
                    else:
                        endc += len(closing)
                    setFormat(i, endc - i, fmt_str)
                    for k in range(i, min(endc, len(masked))): masked[k] = ' '
                    i = endc; continue
            i += 1
        code = ''.join(masked)

        # Numbers: 0x/0o/0b, decimal, underscores, suffixes
        i = 0; n = len(code)
        while i < n:
            ch = code[i]
            if ch == '0' and i + 1 < n and code[i+1] in 'xXbBoO':
                j = i + 2
                if code[i+1] in 'xX':
                    while j < n and (_is_hex_digit(code[j]) or code[j] == '_'): j += 1
                elif code[i+1] in 'bB':
                    while j < n and (code[j] in '01' or code[j] == '_'): j += 1
                else:
                    while j < n and (code[j] in '01234567' or code[j] == '_'): j += 1
                # optional type suffix like u8, i32
                k = j
                if k + 1 < n and code[k] in 'iu' and code[k+1].isdigit():
                    k += 1
                    while k < n and code[k].isdigit(): k += 1
                    j = k
                setFormat(i, j - i, fmt_num)
                i = j
            elif ch.isdigit():
                j = i + 1
                while j < n and (code[j].isdigit() or code[j] in '._'): j += 1
                # optional suffix
                k = j
                if k + 1 < n and code[k] in 'iu' and code[k+1].isdigit():
                    k += 1
                    while k < n and code[k].isdigit(): k += 1
                    j = k
                setFormat(i, j - i, fmt_num)
                i = j
            else:
                i += 1

        # Keywords / Types
        i = 0; n = len(code)
        def is_start(c: str) -> bool: return c == '_' or c.isalpha()
        def is_part(c: str) -> bool: return c == '_' or c.isalnum()
        while i < n:
            ch = code[i]
            if is_start(ch):
                j = i + 1
                while j < n and is_part(code[j]): j += 1
                word = code[i:j]
                if word in self.kw:
                    setFormat(i, j - i, fmt_kw)
                elif word in self.types or (word and word[0].isupper()):
                    setFormat(i, j - i, self.fmt_type)
                i = j
            else:
                i += 1

        # Macros name!
        try:
            i = 0; s = code; L = len(s)
            while i < L:
                if s[i] == '_' or s[i].isalpha():
                    j = i + 1
                    while j < L and (s[j] == '_' or s[j].isalnum()): j += 1
                    if j < L and s[j] == '!':
                        setFormat(i, j - i + 1, self.fmt_macro)
                        i = j + 1; continue
                    # calls
                    k = j
                    while k < L and s[k].isspace(): k += 1
                    if k < L and s[k] == '(':
                        setFormat(i, j - i, self.fmt_func)
                        i = j; continue
                    i = j
                else:
                    i += 1
        except Exception:
            pass

# --------------------------
# Go
# --------------------------

class SimpleGoHighlighter(QSyntaxHighlighter):
    """Minimal Go highlighter with raw strings and block comment state."""

    IN_BLOCK_COMMENT = 1

    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)
        self.kw = set(
            "break default func interface select case defer go map struct chan else goto package switch const fallthrough if range type continue for import return var true false nil"
            .split()
        )
        self.types = set("bool byte rune string error int int8 int16 int32 int64 uint uint8 uint16 uint32 uint64 uintptr float32 float64 complex64 complex128".split())
        self.fmt_kw = QTextCharFormat(); self.fmt_kw.setForeground(_theme_token_color('keywordColor') or _palette_role_color('Link') or _theme_accent_color())
        self.fmt_num = QTextCharFormat(); self.fmt_num.setForeground(_theme_token_color('numberColor') or _theme_accent_color())
        self.fmt_str = QTextCharFormat(); self.fmt_str.setForeground(_theme_token_color('stringColor') or _theme_accent_color())
        self.fmt_comm = QTextCharFormat(); self.fmt_comm.setForeground(_theme_token_color('commentColor') or _theme_muted_color()); self.fmt_comm.setFontItalic(True)
        self.fmt_type = QTextCharFormat(); self.fmt_type.setForeground(_theme_token_color('typeNameColor') or _palette_role_color('LinkVisited') or _theme_accent_color())
        self.fmt_func = QTextCharFormat(); self.fmt_func.setForeground(_theme_token_color('codeSymbolColor') or _theme_accent_color())

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not text:
            return
        setFormat = self.setFormat
        fmt_comm = self.fmt_comm
        fmt_str = self.fmt_str
        fmt_num = self.fmt_num
        fmt_kw = self.fmt_kw

        line = text
        n = len(line)
        self.setCurrentBlockState(0)
        start = 0
        # Track inline block comment spans so later token passes don't override comment formatting
        comment_spans: list[tuple[int,int]] = []
        if self.previousBlockState() == self.IN_BLOCK_COMMENT:
            endc = line.find('*/', start)
            if endc == -1:
                setFormat(0, n, fmt_comm)
                self.setCurrentBlockState(self.IN_BLOCK_COMMENT)
                return
            else:
                setFormat(0, endc + 2, fmt_comm)
                comment_spans.append((0, endc + 2))
                start = endc + 2
        while True:
            startc = line.find('/*', start)
            if startc == -1:
                break
            endc = line.find('*/', startc + 2)
            if endc == -1:
                setFormat(startc, n - startc, fmt_comm)
                self.setCurrentBlockState(self.IN_BLOCK_COMMENT)
                return
            else:
                setFormat(startc, endc - startc + 2, fmt_comm)
                comment_spans.append((startc, endc + 2))
                start = endc + 2

        # // comments
        cpos = line.find('//')
        code = line
        if cpos != -1:
            setFormat(cpos, n - cpos, fmt_comm)
            comment_spans.append((cpos, n))

        # Mask all comment spans to prevent subsequent passes from recoloring within them
        if comment_spans:
            masked_line = list(code)
            for a, b in comment_spans:
                a0 = max(0, min(len(masked_line), a))
                b0 = max(a0, min(len(masked_line), b))
                for k in range(a0, b0):
                    masked_line[k] = ' '
            code = ''.join(masked_line)

        # Strings "..." and raw `...`
        i = 0; masked = list(code)
        def _apply_str_format_range(a: int, b: int) -> None:
            # Color [a,b) as string, excluding any comment spans
            if a >= b:
                return
            if not comment_spans:
                setFormat(a, b - a, fmt_str); return
            cur = a
            for (ca, cb) in sorted(comment_spans):
                if cb <= cur:
                    continue
                if ca >= b:
                    break
                if cur < ca:
                    setFormat(cur, min(ca, b) - cur, fmt_str)
                cur = max(cur, cb)
                if cur >= b:
                    break
            if cur < b:
                setFormat(cur, b - cur, fmt_str)
        while i < len(code):
            ch = code[i]
            if ch == '`':
                j = i + 1
                endc = code.find('`', j)
                if endc == -1: endc = len(code)
                else: endc += 1
                _apply_str_format_range(i, endc)
                for k in range(i, min(endc, len(masked))): masked[k] = ' '
                i = endc; continue
            if ch == '"':
                j = i + 1
                while j < len(code):
                    if code[j] == '\\': j += 2; continue
                    if code[j] == '"': j += 1; break
                    j += 1
                _apply_str_format_range(i, j)
                for k in range(i, min(j, len(masked))): masked[k] = ' '
                i = j; continue
            i += 1
        code = ''.join(masked)

        # Numbers
        i = 0; n = len(code)
        while i < n:
            ch = code[i]
            if ch == '0' and i + 1 < n and code[i+1] in 'xXbBoO':
                j = i + 2
                if code[i+1] in 'xX':
                    while j < n and (_is_hex_digit(code[j]) or code[j] == '_'): j += 1
                elif code[i+1] in 'bB':
                    while j < n and (code[j] in '01' or code[j] == '_'): j += 1
                else:
                    while j < n and (code[j] in '01234567' or code[j] == '_'): j += 1
                setFormat(i, j - i, fmt_num)
                i = j
            elif ch.isdigit():
                j = i + 1
                while j < n and (code[j].isdigit() or code[j] in '._'): j += 1
                setFormat(i, j - i, fmt_num)
                i = j
            else:
                i += 1

        # Keywords / Types
        i = 0; n = len(code)
        def is_start(c: str) -> bool: return c == '_' or c.isalpha()
        def is_part(c: str) -> bool: return c == '_' or c.isalnum()
        while i < n:
            ch = code[i]
            if is_start(ch):
                j = i + 1
                while j < n and is_part(code[j]): j += 1
                word = code[i:j]
                if word in self.kw:
                    setFormat(i, j - i, fmt_kw)
                elif word in self.types:
                    setFormat(i, j - i, self.fmt_type)
                i = j
            else:
                i += 1

        # Function defs: func name(
        try:
            func_pos = code.find('func ')
            if func_pos != -1:
                k = func_pos + 5
                while k < len(code) and code[k].isspace(): k += 1
                # receiver (T)
                if k < len(code) and code[k] == '(':
                    while k < len(code) and code[k] != ')': k += 1
                    k += 1
                    while k < len(code) and code[k].isspace(): k += 1
                j = k
                while j < len(code) and (code[j] == '_' or code[j].isalnum()): j += 1
                if j > k:
                    setFormat(k, j - k, self.fmt_func)
        except Exception:
            pass

        # Calls: name(
        try:
            i = 0
            while i < len(code):
                if code[i] == '_' or code[i].isalpha():
                    j = i + 1
                    while j < len(code) and (code[j] == '_' or code[j].isalnum()): j += 1
                    k = j
                    while k < len(code) and code[k].isspace(): k += 1
                    if k < len(code) and code[k] == '(':
                        setFormat(i, j - i, self.fmt_func)
                        i = j; continue
                    i = j
                else:
                    i += 1
        except Exception:
            pass

# --------------------------
# Minimal bad-byte and diff helpers (unchanged, minor perf cleanup)
# --------------------------

class HexBadByteHighlighter(QSyntaxHighlighter):
    """Highlights specific byte positions in a hex dump string."""

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
        idx = 0; pos = 0; n = len(text); setFormat = self.setFormat; fmt = self.bad_fmt
        while pos < n:
            while pos < n and text[pos].isspace():
                pos += 1
            if pos + 1 >= n:
                break
            if idx in self.bad_offsets:
                setFormat(pos, 2, fmt)
            pos += 2
            idx += 1


class InlineBadByteHighlighter(QSyntaxHighlighter):
    """Highlights bad bytes in inline escaped string ("\\xHH")."""

    def __init__(self, document, color: str = ""):
        QSyntaxHighlighter.__init__(self, document)
        self.bad_offsets = set()
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
        i = 0; n = len(text); idx = 0; setFormat = self.setFormat; fmt = self.bad_fmt
        while i < n:
            if i + 3 < n and text[i] == '\\' and text[i+1].lower() == 'x':
                h1 = text[i+2].lower(); h2 = text[i+3].lower()
                if ((_is_hex_digit(h1)) and (_is_hex_digit(h2))):
                    if idx in self.bad_offsets:
                        setFormat(i + 2, 2, fmt)
                    idx += 1; i += 4; continue
            i += 1


class AsmObjdumpBadByteHighlighter(QSyntaxHighlighter):
    """Highlights bad hex pairs in objdump-like listing."""

    def __init__(self, document, color: str = ""):
        QSyntaxHighlighter.__init__(self, document)
        self.bad_offsets = set()
        self.line_spans: list[tuple[int,int]] = []
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
            colon = text.find(":  ")
            if colon == -1:
                return
            bytes_start = colon + 3
            tabpos = text.find("\t", bytes_start)
            if tabpos == -1:
                tabpos = len(text)
            setFormat = self.setFormat; fmt = self.bad_fmt
            for off in sorted(self.bad_offsets):
                if off < start_off or off >= start_off + length:
                    continue
                idx = off - start_off
                char_pos = bytes_start + (idx * 3)
                if char_pos + 2 <= len(text):
                    setFormat(char_pos, 2, fmt)
        except Exception:
            return


class UnifiedDiffHighlighter(QSyntaxHighlighter):
    """Highlights unified diff additions/deletions/headers."""

    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)
        good, bad = _good_bad_colors()
        self.fmt_add = QTextCharFormat(); self.fmt_add.setBackground(_tint(good)); self.fmt_add.setForeground(good)
        self.fmt_del = QTextCharFormat(); self.fmt_del.setBackground(_tint(bad));  self.fmt_del.setForeground(bad)
        self.fmt_hdr = QTextCharFormat(); self.fmt_hdr.setForeground(_theme_muted_color())

    def highlightBlock(self, text: str) -> None:  # type: ignore
        if not text:
            return
        if text.startswith('+++') or text.startswith('---') or text.startswith('@@'):
            self.setFormat(0, len(text), self.fmt_hdr)
        elif text.startswith('+'):
            self.setFormat(0, len(text), self.fmt_add)
        elif text.startswith('-'):
            self.setFormat(0, len(text), self.fmt_del)

# --------------------------
# Factories
# --------------------------

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


def create_disassembly_highlighter(
    document,
    arch_name: str = "x86_64",
    style_name: str | None = None,  # kept for API compat (unused)
):
    """Create a syntax highlighter for disassembly text using Qt only."""
    return SimpleAsmHighlighter(document, arch_name=arch_name)


def create_code_highlighter(
    document,
    lexer_name: str = "text",
    style_name: str | None = None,
):
    """Create a Qt-only code highlighter for a given language name.

    Supported: 'c', 'cpp', 'c++', 'python', 'py', 'zig', 'rust', 'go'.
    Others return None.
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


def create_best_highlighter(
    document,
    language: str,
    prefer_pygments: bool = True,
    style_name: str | None = None,
):
    """Best-effort factory: use Pygments if available (and requested), else Qt-only.

    language: e.g., 'asm', 'c', 'python', 'zig', 'rust', 'go', ...
    """
    lang = (language or '').lower()
    if prefer_pygments:
        try:
            return PygmentsHighlighter(document, lexer_name=lang, style_name=style_name or None)
        except Exception:
            pass
    # Disassembly special-case
    if lang in ("asm","assembly","disasm","disassembly","x86","x86_64","arm","arm64","aarch64","mips","riscv"):
        return create_disassembly_highlighter(document, arch_name=lang)
    return create_code_highlighter(document, lexer_name=lang, style_name=style_name)


def create_qt_c_highlighter(document):
    """Factory for lightweight C highlighter using Qt only (compat)."""
    return SimpleCHighlighter(document)
