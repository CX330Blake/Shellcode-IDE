from __future__ import annotations

from typing import Callable, List, Optional
import re as _re
import html as _html

try:
    from PySide6.QtCore import Qt, QTimer  # type: ignore
    from PySide6.QtGui import QPalette  # type: ignore
    from PySide6.QtWidgets import (  # type: ignore
        QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QLabel,
        QTableWidget, QTableWidgetItem, QMessageBox, QPlainTextEdit, QComboBox, QStackedLayout, QHeaderView, QApplication
    )
    _QT = "PySide6"
except Exception:
    try:
        from PySide2.QtCore import Qt, QTimer  # type: ignore
        from PySide2.QtGui import QPalette  # type: ignore
        from PySide2.QtWidgets import (  # type: ignore
            QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QLabel,
            QTableWidget, QTableWidgetItem, QMessageBox, QPlainTextEdit, QComboBox, QStackedLayout, QHeaderView, QApplication
        )
        _QT = "PySide2"
    except Exception as exc:  # pragma: no cover
        raise ImportError("Qt (PySide6/PySide2) is required for ShellstormPanel") from exc

from ..backends import shellstorm as ss
from ..utils.hexbytes import parse_hex_input
from .highlighters import create_qt_c_highlighter, create_code_highlighter, create_disassembly_highlighter


class ShellstormPanel(QWidget):
    """Search and import shellcodes from Shell-Storm."""

    def __init__(
        self,
        get_arch_cb: Callable[[], str],
        insert_hex_cb: Callable[[bytes], None],
        insert_asm_cb: Callable[[str], None],
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._get_arch = get_arch_cb
        self._insert_hex = insert_hex_cb
        self._insert_asm = insert_asm_cb
        self._rows: List[ss.ShellstormEntry] = []

        layout = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("Search:"))
        self.q = QLineEdit(); self.q.setPlaceholderText("keyword, syscall, technique…")
        row.addWidget(self.q, 1)
        row.addWidget(QLabel("Arch:"))
        self.arch = QComboBox()
        try:
            # Keep concise list; first item is 'All' (no filter)
            self.arch.addItems(["All", "x86", "x86_64", "arm", "aarch64", "mips", "ppc", "sparc"])
        except Exception:
            pass
        row.addWidget(self.arch)
        self.btn_search = QPushButton("Search")
        row.addWidget(self.btn_search)
        layout.addLayout(row)

        # Removed insecure toggle; operate insecure by default

        # Results area: table + empty state with "justify-between"-like layout
        self.results_container = QWidget()
        self.results_stack = QStackedLayout(self.results_container)
        self.table = QTableWidget(0, 4)
        try:
            # Columns: ID, Title, Platform, Author (correct alignment)
            self.table.setHorizontalHeaderLabels(["ID", "Title", "Platform", "Author"])
            self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            self.table.verticalHeader().setVisible(False)
            self.table.setAlternatingRowColors(True)
            # Do not elide any text; use horizontal scrollbar when needed
            try:
                self.table.setTextElideMode(Qt.ElideNone)  # type: ignore[attr-defined]
            except Exception:
                pass
            try:
                self.table.setWordWrap(False)
            except Exception:
                pass
            try:
                self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            except Exception:
                pass
        except Exception:
            pass
        self.results_stack.addWidget(self.table)
        # Empty state page with top/bottom labels and space-between behavior
        self.empty_state = QWidget()
        _es_lay = QVBoxLayout(self.empty_state)
        _es_lay.setContentsMargins(12, 12, 12, 12)
        self.empty_top = QLabel("No results")
        try:
            self.empty_top.setStyleSheet("color: palette(mid); font-weight: 600;")
        except Exception:
            pass
        self.empty_top.setWordWrap(True)
        self.empty_bottom = QLabel("Tip: Try different keywords or set Arch to 'All'.")
        self.empty_bottom.setWordWrap(True)
        _es_lay.addWidget(self.empty_top)
        _es_lay.addStretch(1)  # justify-between spacing
        _es_lay.addWidget(self.empty_bottom)
        self.results_stack.addWidget(self.empty_state)
        # Default to table view on startup (show column headers with no rows)
        try:
            self.results_stack.setCurrentIndex(0)
        except Exception:
            pass
        layout.addWidget(self.results_container, 1)
        # Auto-size columns at startup: fill table width (no rows yet)
        try:
            hh = self.table.horizontalHeader()
            hh.setSectionResizeMode(0, QHeaderView.Stretch)  # ID
            hh.setSectionResizeMode(1, QHeaderView.Stretch)  # Title
            hh.setSectionResizeMode(2, QHeaderView.Stretch)  # Platform
            hh.setSectionResizeMode(3, QHeaderView.Stretch)  # Author
            try:
                hh.setStretchLastSection(True)
            except Exception:
                pass
        except Exception:
            pass

        # Preview and actions
        prow = QHBoxLayout()
        self.btn_fetch = QPushButton("Preview")
        self.btn_insert_hex = QPushButton("Insert Hex")
        self.btn_insert_asm = QPushButton("Insert Asm")
        self.btn_copy = QPushButton("Copy")
        try:
            self.btn_copy.setToolTip("Copy preview to clipboard")
        except Exception:
            pass
        prow.addWidget(self.btn_fetch)
        prow.addStretch(1)
        # Syntax language selector (manual)
        try:
            prow.addWidget(QLabel("Syntax:"))
            self.lang_combo = QComboBox()
            # Default to C
            self.lang_combo.addItems(["C", "Assembly", "Python", "Zig", "Rust", "Go", "Text"])
            prow.addWidget(self.lang_combo)
        except Exception:
            self.lang_combo = None
        prow.addWidget(self.btn_insert_hex)
        prow.addWidget(self.btn_insert_asm)
        prow.addWidget(self.btn_copy)
        layout.addLayout(prow)

        self.preview = QPlainTextEdit(); self.preview.setReadOnly(True)
        layout.addWidget(self.preview, 1)
        # Syntax highlighting for preview (user-selectable; default C)
        self.preview_code_hl = None
        try:
            self._apply_preview_highlighter()
        except Exception:
            pass

        # Wire
        try:
            self.btn_search.clicked.connect(self._on_search)
            self.btn_fetch.clicked.connect(self._on_preview)
            self.table.cellDoubleClicked.connect(lambda r, c: self._on_preview())
            self.btn_insert_hex.clicked.connect(self._on_insert_hex)
            self.btn_insert_asm.clicked.connect(self._on_insert_asm)
            self.btn_copy.clicked.connect(self._on_copy_preview)
            if self.lang_combo is not None:
                self.lang_combo.currentTextChanged.connect(lambda _t: self._apply_preview_highlighter())
            pass
        except Exception:
            pass

    def _current_entry(self) -> Optional[ss.ShellstormEntry]:
        try:
            r = self.table.currentRow()
            if r < 0 or r >= len(self._rows):
                return None
            return self._rows[r]
        except Exception:
            return None

    def _on_search(self) -> None:
        q = (self.q.text() or "").strip()
        try:
            print(f"[Shellcode-IDE] UI: Shell-Storm search q='{q}' arch='{self.arch.currentText()}' insecure=True")
        except Exception:
            pass
        if not q:
            QMessageBox.information(self, "Shell-Storm", "Enter a search term.")
            return
        sel = (self.arch.currentText() or "").strip()
        arch = None if sel.lower() in ("", "all") else sel
        try:
            rows = ss.search(q, arch=arch, verify_ssl=False, allow_http_fallback=True)
        except Exception as e:
            msg = str(e)
            # Already using insecure; just report the failure
            try:
                print(f"[Shellcode-IDE] UI: search failed: {e}")
            except Exception:
                pass
            QMessageBox.warning(self, "Shell-Storm", f"Search failed: {e}")
            return
        self._rows = rows
        self._populate(rows)

    def _populate(self, rows: List[ss.ShellstormEntry]) -> None:
        try:
            self.table.setRowCount(0)
            for it in rows:
                r = self.table.rowCount()
                self.table.insertRow(r)
                self.table.setItem(r, 0, QTableWidgetItem(str(it.sid)))
                # Correct mapping: col1=Title, col3=Author
                self.table.setItem(r, 1, QTableWidgetItem(it.title or ""))
                self.table.setItem(r, 2, QTableWidgetItem(it.platform or ""))
                self.table.setItem(r, 3, QTableWidgetItem(it.author or ""))
            # Do not auto-fit to contents; header uses Stretch to fill width
            # Toggle empty state vs table and adjust column sizing policy
            try:
                if len(rows) == 0:
                    self.results_stack.setCurrentIndex(1)
                    # With no rows, fill available width with stretched columns
                    hh = self.table.horizontalHeader()
                    hh.setSectionResizeMode(0, QHeaderView.Stretch)
                    hh.setSectionResizeMode(1, QHeaderView.Stretch)
                    hh.setSectionResizeMode(2, QHeaderView.Stretch)
                    hh.setSectionResizeMode(3, QHeaderView.Stretch)
                    try:
                        hh.setStretchLastSection(True)
                    except Exception:
                        pass
                else:
                    self.results_stack.setCurrentIndex(0)
                    # With results, size each column to its contents; rely on horizontal scrollbar
                    hh = self.table.horizontalHeader()
                    hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # ID
                    hh.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Title
                    hh.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Platform
                    hh.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Author
                    try:
                        # Do not stretch last section; allow scrollbar if width exceeds viewport
                        hh.setStretchLastSection(False)
                    except Exception:
                        pass
                    # Do an initial fit pass so non-stretch columns size to content immediately
                    try:
                        # Temporarily set non-title to ResizeToContents and call resize
                        self.table.resizeColumnToContents(0)
                        self.table.resizeColumnToContents(1)
                        self.table.resizeColumnToContents(2)
                        self.table.resizeColumnToContents(3)
                    except Exception:
                        pass
                    # After sizing, decide whether to stretch Title to fill extra space
                    try:
                        self._adjust_column_modes()
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass

    def _on_preview(self) -> None:
        it = self._current_entry()
        if not it:
            return
        try:
            try:
                print(f"[Shellcode-IDE] UI: Shell-Storm preview id='{getattr(it, 'sid', '')}' insecure=True")
            except Exception:
                pass
            text = ss.fetch_code(it, verify_ssl=False, allow_http_fallback=True)
        except Exception as e:
            msg = str(e)
            try:
                print(f"[Shellcode-IDE] UI: preview failed: {e}")
            except Exception:
                pass
            QMessageBox.warning(self, "Shell-Storm", f"Fetch failed: {e}")
            return
        # Clean up HTML responses to show only code/pre content
        text = self._clean_preview_text(text)
        self.preview.setPlainText(text)

    def _on_copy_preview(self) -> None:
        try:
            content = self.preview.toPlainText()
            QApplication.clipboard().setText(content)
        except Exception:
            pass
        # Visual feedback: show temporary green OK on the Copy button using theme palette
        try:
            prev_text = self.btn_copy.text()
            try:
                prev_style = self.btn_copy.styleSheet()
            except Exception:
                prev_style = ""
            # Change label to OK and set text color to green
            try:
                self.btn_copy.setText("OK")
            except Exception:
                pass
            # Prefer theme-aware green
            ok_color = None
            try:
                from .highlighters import _good_bad_colors  # type: ignore
                g, _r = _good_bad_colors()
                if g and g.isValid():
                    ok_color = g.name()
            except Exception:
                ok_color = None
            if not ok_color:
                try:
                    pal = self.palette()
                    ok_color = pal.color(QPalette.Highlight).name()
                except Exception:
                    ok_color = None
            if ok_color:
                self.btn_copy.setStyleSheet(f"QPushButton {{ color: {ok_color}; }}")
            # Keep enabled to avoid background color changes in some themes
            QTimer.singleShot(1200, lambda: self._restore_copy_btn(prev_text, prev_style))
        except Exception:
            pass

    def _restore_copy_btn(self, prev_text: str = "Copy", prev_style: str = "") -> None:
        try:
            self.btn_copy.setText(prev_text)
            self.btn_copy.setStyleSheet(prev_style or "")
            self.btn_copy.setEnabled(True)
        except Exception:
            pass

    def _apply_preview_highlighter(self) -> None:
        # Detach previous highlighter if any
        try:
            if getattr(self, 'preview_code_hl', None):
                try:
                    self.preview_code_hl.setDocument(None)
                except Exception:
                    pass
        except Exception:
            pass
        lang = None
        try:
            lang = (self.lang_combo.currentText() if self.lang_combo is not None else 'C') or 'C'
        except Exception:
            lang = 'C'
        lang = lang.strip().lower()
        try:
            if lang == 'c':
                self.preview_code_hl = create_code_highlighter(self.preview.document(), lexer_name='c') or create_qt_c_highlighter(self.preview.document())
            elif lang == 'assembly':
                arch = None
                try:
                    arch = self._get_arch() or 'x86_64'
                except Exception:
                    arch = 'x86_64'
                self.preview_code_hl = create_disassembly_highlighter(self.preview.document(), arch_name=arch)
            elif lang == 'python':
                self.preview_code_hl = create_code_highlighter(self.preview.document(), lexer_name='python')
            elif lang == 'zig':
                self.preview_code_hl = create_code_highlighter(self.preview.document(), lexer_name='zig')
            elif lang == 'rust':
                self.preview_code_hl = create_code_highlighter(self.preview.document(), lexer_name='rust')
            elif lang == 'go':
                self.preview_code_hl = create_code_highlighter(self.preview.document(), lexer_name='go')
            else:  # Text
                self.preview_code_hl = None
        except Exception:
            self.preview_code_hl = None

    def _on_insert_hex(self) -> None:
        blob = self.preview.toPlainText()
        if not blob:
            self._on_preview()
            blob = self.preview.toPlainText()
        if not blob:
            return
        # Try explicit \xHH first, then generic hex run
        data = ss.extract_hex_bytes(blob)
        if data is None:
            # As a last resort, allow pasting any hex-like content
            try:
                data = parse_hex_input(blob)
            except Exception:
                data = None
        if data is None:
            QMessageBox.information(self, "Shell-Storm", "Could not extract raw bytes from preview.")
            return
        try:
            self._insert_hex(data)
        except Exception:
            pass

    def _on_insert_asm(self) -> None:
        blob = self.preview.toPlainText()
        if not blob:
            self._on_preview()
            blob = self.preview.toPlainText()
        if not blob:
            return
        text = blob
        # The preview is already cleaned; if not, sanitize again
        text = self._clean_preview_text(text)
        if not ss.seems_assembly(text):
            QMessageBox.information(self, "Shell-Storm", "Fetched content does not look like assembly.")
            return
        try:
            self._insert_asm(text)
        except Exception:
            pass

    # No insecure toggle; insecure mode is always enabled by default

    # No Pygments style selection needed for Qt-only highlighter

    def _clean_preview_text(self, text: str) -> str:
        """Extract useful code content from Shell-Storm HTML pages.

        - Prefer <pre> blocks; join multiple with spacing.
        - Otherwise, strip tags and decode HTML entities.
        """
        try:
            s = text or ""
            low = s.lower()
            # Grab <pre> content first
            blocks = []
            if "<pre" in low:
                blocks = _re.findall(r"(?is)<pre[^>]*>(.*?)</pre>", s)
            if blocks:
                joined = "\n\n".join(_html.unescape(b) for b in blocks)
                return joined.strip()
            # Otherwise, remove common noisy sections and tags
            s = _re.sub(r"(?is)<script[^>]*>.*?</script>", "\n", s)
            s = _re.sub(r"(?is)<style[^>]*>.*?</style>", "\n", s)
            s = _re.sub(r"(?is)<[^>]+>", "\n", s)
            s = _html.unescape(s)
            s = _re.sub(r"\n\s*\n\s*\n+", "\n\n", s).strip()
            return s
        except Exception:
            return text

    # Dynamically adjust column sizing so:
    # - When content width is smaller than viewport, Title column stretches to fill.
    # - When content exceeds viewport, all columns are sized to contents and a horizontal scrollbar appears.
    def _adjust_column_modes(self) -> None:
        try:
            hh = self.table.horizontalHeader()
            vp = self.table.viewport()
            vpw = vp.width() if vp is not None else self.table.width()
            cols = self.table.columnCount()
            # Prefer sizeHintForColumn if available; fallback to current width
            total = 0
            for i in range(cols):
                try:
                    w = self.table.sizeHintForColumn(i)
                except Exception:
                    w = -1
                if not isinstance(w, int) or w <= 0:
                    w = self.table.columnWidth(i)
                total += max(0, int(w))
            # Account for vertical header width and frame
            try:
                total += self.table.verticalHeader().width()
            except Exception:
                pass
            # Decide mode
            if total < vpw:
                # There is extra space: Title stretches; others keep content-based size
                for i in range(cols):
                    if i == 1:  # Title
                        hh.setSectionResizeMode(i, QHeaderView.Stretch)
                    else:
                        hh.setSectionResizeMode(i, QHeaderView.ResizeToContents)
                try:
                    hh.setStretchLastSection(False)
                except Exception:
                    pass
            else:
                # Content wider than viewport: no stretching; allow horizontal scrolling
                for i in range(cols):
                    hh.setSectionResizeMode(i, QHeaderView.ResizeToContents)
                try:
                    hh.setStretchLastSection(False)
                except Exception:
                    pass
        except Exception:
            pass

    # Keep columns behaving on window resize
    def resizeEvent(self, ev):  # type: ignore[override]
        try:
            super().resizeEvent(ev)
        except Exception:
            pass
        try:
            self._adjust_column_modes()
        except Exception:
            pass
