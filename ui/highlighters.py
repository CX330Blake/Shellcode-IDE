from __future__ import annotations

try:
    from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
    QT6 = True
except Exception:
    from PySide2.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont  # type: ignore
    QT6 = False


def _qcolor_from_css(css: str) -> QColor:
    try:
        return QColor(css)
    except Exception:
        return QColor("#cccccc")


class PygmentsHighlighter(QSyntaxHighlighter):
    """QSyntaxHighlighter adapter that uses Pygments for tokenization + styling.

    If Pygments is unavailable or a lexer cannot be created, initialization
    raises ImportError so callers can fallback to a simpler highlighter.
    """

    def __init__(self, parent_document, lexer_name: str = "asm", style_name: str = "native"):
        # Initialize without a document first to avoid early highlightBlock calls
        QSyntaxHighlighter.__init__(self)
        self.lexer = None
        self.formats = {}
        self.default_format = QTextCharFormat()
        try:
            import pygments  # noqa: F401
            from pygments.lexers import get_lexer_by_name
            from pygments.styles import get_style_by_name
            from pygments.token import Token
        except Exception as exc:
            raise ImportError("pygments is not available") from exc

        try:
            self.lexer = get_lexer_by_name(lexer_name)
        except Exception as exc:
            # fallback to text lexer
            self.lexer = get_lexer_by_name("text")

        try:
            self.style = get_style_by_name(style_name)
        except Exception:
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
        # Fallback mnemonic format to ensure visible difference
        self.mnemonic_format = QTextCharFormat()
        self.mnemonic_format.setForeground(_qcolor_from_css("#bd93f9"))  # dracula purple as a safe default

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


class HexBadByteHighlighter(QSyntaxHighlighter):
    """Highlights only specific byte positions in a hex dump string.

    Expects content like "aa bb cc ..."; set bad byte indices via
    `set_bad_offsets({0,3,5})` and it will color just those bytes.
    """

    def __init__(self, document, color: str = "#ff5555"):
        QSyntaxHighlighter.__init__(self, document)
        self.bad_offsets = set()  # set[int]
        self.bad_fmt = QTextCharFormat()
        self.bad_fmt.setForeground(_qcolor_from_css(color))

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


class AsmObjdumpBadByteHighlighter(QSyntaxHighlighter):
    """Highlights bad byte hex pairs in an objdump-like assembly listing.

    Expects lines formatted like: "00000000:  aa bb cc   \t mnemonic ...".
    Provide per-line (start_offset, length) mapping via set_mapping, and
    the set of bad byte offsets via set_bad_offsets.
    """

    def __init__(self, document, color: str = "#ff5555"):
        QSyntaxHighlighter.__init__(self, document)
        self.bad_offsets = set()
        self.line_spans = []  # list[(start, length)]
        self.bad_fmt = QTextCharFormat()
        self.bad_fmt.setForeground(_qcolor_from_css(color))

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


def create_disassembly_highlighter(document, arch_name: str = "x86_64", style_name: str | None = None):
    """Create a Pygments-based highlighter for disassembly using NASM syntax.

    Forces the lexer to 'nasm' for consistency; falls back to 'asm' if needed.
    """
    # Use requested style first, then fall back
    style_candidates = []
    if style_name:
        style_candidates.append(style_name)
    style_candidates.extend(["monokai", "native", "default"])
    last_exc = None
    for lexname in ("nasm", "asm"):
        for sty in style_candidates:
            try:
                return PygmentsHighlighter(document, lexer_name=lexname, style_name=sty)
            except Exception as exc:
                last_exc = exc
                continue
    if last_exc:
        raise last_exc
    raise ImportError("No suitable pygments lexer/style found")
