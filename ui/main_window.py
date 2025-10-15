from __future__ import annotations

import traceback
from typing import Optional, Tuple

# Qt compatibility: prefer PySide6 (Qt6), fallback to PySide2 (Qt5)
_QT_LIB = None
try:
    from PySide6.QtCore import Qt  # type: ignore
    from PySide6.QtGui import QFont, QAction, QPalette  # type: ignore  # QAction is in QtGui on Qt6
    from PySide6.QtWidgets import (  # type: ignore
        QApplication,
        QCheckBox,
        QComboBox,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QPlainTextEdit,
        QSizePolicy,
        QSplitter,
        QStatusBar,
        QTabWidget,
        QToolBar,
        QVBoxLayout,
        QWidget,
    )
    _QT_LIB = "PySide6"
except Exception:
    try:
        from PySide2.QtCore import Qt  # type: ignore
        from PySide2.QtGui import QFont, QPalette  # type: ignore
        from PySide2.QtWidgets import (  # type: ignore
            QAction,  # QAction is in QtWidgets on Qt5
            QApplication,
            QCheckBox,
            QComboBox,
            QGridLayout,
            QGroupBox,
            QHBoxLayout,
            QLabel,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QPlainTextEdit,
            QSizePolicy,
            QSplitter,
            QStatusBar,
            QTabWidget,
            QToolBar,
            QVBoxLayout,
            QWidget,
        )
        _QT_LIB = "PySide2"
    except Exception as exc:  # pragma: no cover
        raise ImportError("Qt (PySide6/PySide2) is required to run Shellcode IDE") from exc

from ..backends.bn_adapter import BNAdapter
from ..backends.validator import BadPatternManager, validate_all
from ..utils.config import load_config, save_config
from .patterns_dialog import PatternsDialog
from .patterns_panel import PatternsPanel
from .highlighters import (
    create_disassembly_highlighter,
    create_code_highlighter,
    HexBadByteHighlighter,
    AsmObjdumpBadByteHighlighter,
)
from .optimize_panel import OptimizePanel
from .syscalls_panel import SyscallsPanel
from ..backends.syscalls import canonical_arch
from ..formatters.base import (
    bytes_to_c_array,
    bytes_to_hex,
    bytes_to_inline,
    bytes_to_python_bytes,
    bytes_to_zig_array,
)
from ..utils.hexbytes import parse_hex_input, count_nulls


MONO_FONT = "Menlo, Consolas, monospace"


class ShellcodeIDEWindow(QMainWindow):
    def __init__(self, parent: Optional[QWidget] = None, bn_api=None):
        super().__init__(parent)
        self.setWindowTitle("Shellcode IDE")
        self.resize(1100, 700)

        self.adapter = BNAdapter(bn_api=bn_api)
        # Load config and patterns
        cfg = load_config()
        if isinstance(cfg.get("bad_patterns"), list):
            self.bpm = BadPatternManager.deserialize(cfg.get("bad_patterns") or [])
        else:
            self.bpm = BadPatternManager()

        # Toolbar
        tb = QToolBar("Main")
        tb.setMovable(False)
        self.addToolBar(tb)

        # Mode switcher (Dev/Analysis)
        self.mode_combo = QComboBox()
        try:
            self.mode_combo.addItems(["Dev", "Analysis"])  # Dev = assemble, Analysis = disassemble
        except Exception:
            pass

        self.arch_combo = QComboBox()
        self._populate_arch_platform()

        self.act_assemble = QAction("Assemble", self)
        self.act_disassemble = QAction("Disassemble", self)

        tb.addWidget(QLabel("Mode:"))
        tb.addWidget(self.mode_combo)
        tb.addSeparator()
        tb.addWidget(QLabel("Arch:"))
        tb.addWidget(self.arch_combo)
        tb.addSeparator()
        tb.addAction(self.act_assemble)
        tb.addAction(self.act_disassemble)

        # Central layout
        splitter = QSplitter()
        splitter.setOrientation(Qt.Horizontal)
        self.setCentralWidget(splitter)

        # Left side - Input tabs
        left = QWidget()
        left_layout = QVBoxLayout(left)
        self.input_tabs = QTabWidget()
        self.hex_edit = QPlainTextEdit()
        self.asm_edit = QPlainTextEdit()
        self._apply_mono(self.hex_edit)
        self._apply_mono(self.asm_edit)
        self.input_tabs.addTab(self.hex_edit, "Hex/Bytes")
        self.input_tabs.addTab(self.asm_edit, "Assembly")
        # Fill space so editor borders align top and bottom with right
        left_layout.addWidget(self.input_tabs, 1)
        splitter.addWidget(left)

        # Right side - Output tabs and bad-chars controls
        right = QWidget()
        right_layout = QVBoxLayout(right)
        # keep a handle to right layout for later visibility toggles
        self._right_layout = right_layout
        # Bad-chars controls will be placed into the tab bar corner below
        # load setting
        self._last_bytes = b""
        self.output_tabs = QTabWidget()

        # Disassembly view (used in analysis mode)
        self.output_text = QPlainTextEdit()
        self._apply_mono(self.output_text)
        self.output_text.setReadOnly(True)
        self.disasm_highlighter = None
        self._refresh_disasm_highlighter()
        self.output_tabs.addTab(self.output_text, "Disassembly")

        # Debug tab for assemble mode: Opcode + Assembly (objdump-like)
        self.debug_widget = QWidget()
        dbg_layout = QVBoxLayout(self.debug_widget)
        # Opcode block
        self.opcode_text = QPlainTextEdit()
        self._apply_mono(self.opcode_text)
        self.opcode_text.setReadOnly(True)
        dbg_layout.addWidget(self._labeled_box("Opcode", target=self.opcode_text))
        dbg_layout.addWidget(self.opcode_text)
        try:
            self.op_hl = HexBadByteHighlighter(self.opcode_text.document())
        except Exception:
            self.op_hl = None
        # Assembly block
        self.debug_asm_text = QPlainTextEdit()
        self._apply_mono(self.debug_asm_text)
        self.debug_asm_text.setReadOnly(True)
        dbg_layout.addWidget(self._labeled_box("Assembly", target=self.debug_asm_text))
        dbg_layout.addWidget(self.debug_asm_text)
        try:
            self.debug_asm_bad_hl = AsmObjdumpBadByteHighlighter(self.debug_asm_text.document())
        except Exception:
            self.debug_asm_bad_hl = None
        # Token highlighter for debug assembly (Pygments)
        try:
            self.debug_asm_token_hl = create_disassembly_highlighter(
                self.debug_asm_text.document(), arch_name=self.arch_combo.currentText() or "x86_64", style_name=self._preferred_style()
            )
        except Exception:
            self.debug_asm_token_hl = None
        self.output_tabs.addTab(self.debug_widget, "Debug")

        # Optimize panel (Dev mode)
        self.optimize_widget = OptimizePanel(
            get_asm=lambda: self.asm_edit.toPlainText(),
            set_asm=lambda s: self.asm_edit.setPlainText(s),
            get_arch=lambda: (self.arch_combo.currentText() or "x86_64"),
            parent=self,
        )
        self.output_tabs.addTab(self.optimize_widget, "Optimize")

        # Formats view
        fmt_widget = QWidget()
        fmt_layout = QGridLayout(fmt_widget)

        self.inline_text = QPlainTextEdit(); self._setup_output_box(self.inline_text)
        self.hex_text = QPlainTextEdit(); self._setup_output_box(self.hex_text)
        self.c_text = QPlainTextEdit(); self._setup_output_box(self.c_text)
        self.py_text = QPlainTextEdit(); self._setup_output_box(self.py_text)
        self.zig_text = QPlainTextEdit(); self._setup_output_box(self.zig_text)

        fmt_layout.addWidget(self._labeled_box("Inline"), 0, 0)
        fmt_layout.addWidget(self.inline_text, 1, 0)
        fmt_layout.addWidget(self._labeled_box("Hex"), 0, 1)
        fmt_layout.addWidget(self.hex_text, 1, 1)
        fmt_layout.addWidget(self._labeled_box("C"), 2, 0)
        fmt_layout.addWidget(self.c_text, 3, 0)
        fmt_layout.addWidget(self._labeled_box("Python"), 2, 1)
        fmt_layout.addWidget(self.py_text, 3, 1)
        fmt_layout.addWidget(self._labeled_box("Zig"), 4, 0, 1, 2)
        fmt_layout.addWidget(self.zig_text, 5, 0, 1, 2)
        # Keep formats packed to top
        # No extra stretch; the tab widget fills the height

        self.output_tabs.addTab(fmt_widget, "Shellcode")
        self.formats_widget = fmt_widget
        # Tabs fill space so borders align
        right_layout.addWidget(self.output_tabs, 1)

        # Syntax highlighting for Output tab code blocks (with fallback)
        try:
            sty = self._preferred_style()
            self.inline_code_hl = create_code_highlighter(self.inline_text.document(), lexer_name="python", style_name=sty)
        except Exception:
            self.inline_code_hl = None
        try:
            sty = self._preferred_style()
            self.c_code_hl = create_code_highlighter(self.c_text.document(), lexer_name="c", style_name=sty)
        except Exception:
            self.c_code_hl = None
        try:
            sty = self._preferred_style()
            self.py_code_hl = create_code_highlighter(self.py_text.document(), lexer_name="python", style_name=sty)
        except Exception:
            self.py_code_hl = None
        try:
            sty = self._preferred_style()
            # Pygments supports 'zig' in newer versions; fallback kicks in otherwise
            self.zig_code_hl = create_code_highlighter(self.zig_text.document(), lexer_name="zig", style_name=sty)
        except Exception:
            self.zig_code_hl = None

        # Bad-chars editor as its own tab (Dev mode)
        self.patterns_widget = PatternsPanel(self.bpm, self)
        self.output_tabs.addTab(self.patterns_widget, "Bad Chars")

        # Syscalls tab (visible in both modes)
        def _insert_snippet(snippet: str) -> None:
            try:
                cursor = self.asm_edit.textCursor()  # type: ignore[attr-defined]
                try:
                    cursor.insertText(snippet)
                except Exception:
                    # Fallback: append
                    self.asm_edit.appendPlainText(snippet)
            except Exception:
                # final fallback
                self.asm_edit.appendPlainText(snippet)

        self.syscalls_widget = SyscallsPanel(
            get_arch_cb=lambda: (self.arch_combo.currentText() or "x86_64"),
            insert_asm_cb=_insert_snippet,
            parent=self,
        )
        self.output_tabs.addTab(self.syscalls_widget, "Syscalls")

        # Validation tab (container with a button bar and text)
        val_container = QWidget()
        val_layout = QVBoxLayout(val_container)
        self.btn_patterns = QPushButton("Patterns…")
        self.btn_patterns.setFixedWidth(100)
        bar = QHBoxLayout()
        bar.addWidget(self.btn_patterns)
        bar.addStretch(1)
        val_layout.addLayout(bar)
        self.validation_text = QPlainTextEdit()
        self._apply_mono(self.validation_text)
        self.validation_text.setReadOnly(True)
        val_layout.addWidget(self.validation_text)
        self.output_tabs.addTab(val_container, "Validation")
        self.validation_container = val_container
        # output_tabs already added with stretch above
        splitter.addWidget(right)

        # Status bar
        sb = QStatusBar()
        self.setStatusBar(sb)
        self.status_arch = QLabel("arch: -")
        self.status_len = QLabel("len: 0")
        self.status_nulls = QLabel("nulls: 0")
        self.status_bad = QLabel("bad: 0")
        sb.addPermanentWidget(self.status_arch)
        sb.addPermanentWidget(self.status_len)
        sb.addPermanentWidget(self.status_nulls)
        sb.addPermanentWidget(self.status_bad)

        # Wire actions
        self.act_assemble.triggered.connect(self.on_assemble)
        self.act_disassemble.triggered.connect(self.on_disassemble)
        self.btn_patterns.clicked.connect(self.on_patterns)
        # No "New" toolbar action per request

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        # Initialize toolbar mode based on current tab
        try:
            self.input_tabs.currentChanged.connect(self.on_input_tab_changed)
        except Exception:
            pass
        # Mode switcher handler
        try:
            self.mode_combo.currentIndexChanged.connect(self.on_mode_changed)
        except Exception:
            pass
        # Default to Dev (assemble) mode regardless of initial tab
        try:
            self._update_toolbar_for_mode("assemble")
            try:
                self.mode_combo.blockSignals(True)
                self.mode_combo.setCurrentIndex(0)  # Dev
                self.mode_combo.blockSignals(False)
            except Exception:
                pass
            # Enforce initial tab visibility based on current mode
            try:
                self.on_mode_changed(0)
            except Exception:
                pass
        except Exception:
            self._update_toolbar_for_mode("assemble")
            try:
                self.mode_combo.setCurrentIndex(0)
            except Exception:
                pass
        # Update highlighter when arch changes
        try:
            self.arch_combo.currentTextChanged.connect(lambda _t: self._refresh_disasm_highlighter())
        except Exception:
            pass
        # Also refresh/hide syscalls tab on arch change
        try:
            self.arch_combo.currentTextChanged.connect(lambda _t: self._refresh_syscalls_tab())
        except Exception:
            pass
        # Add Pygments to Assembly editor as well
        try:
            self.asm_highlighter = create_disassembly_highlighter(
                self.asm_edit.document(), arch_name=self.arch_combo.currentText() or "x86_64", style_name=self._preferred_style()
            )
        except Exception:
            self.asm_highlighter = None
        # Keep Optimize preview live on arch/asm changes
        try:
            self.arch_combo.currentTextChanged.connect(lambda _t: self.optimize_widget.on_preview())
        except Exception:
            pass
        try:
            self.asm_edit.textChanged.connect(self.optimize_widget.on_preview)
        except Exception:
            pass
        # Patterns panel change hook (refresh highlighting and persist)
        try:
            self.patterns_widget.on_changed = lambda: self.on_badchars_toggled(self.patterns_widget.is_highlight_enabled())
        except Exception:
            pass
        # Patterns panel change hook (refresh highlights + persist)
        try:
            self.patterns_widget.on_changed = lambda: self.on_badchars_toggled(self.patterns_widget.is_highlight_enabled())
        except Exception:
            pass

    def _set_tab_visible(self, tabs: QTabWidget, widget: QWidget, visible: bool):
        try:
            idx = tabs.indexOf(widget)
            if idx >= 0:
                tabs.setTabVisible(idx, visible)  # Qt 5.15+/Qt6
        except Exception:
            # Fallback: disable when we cannot hide
            try:
                idx = tabs.indexOf(widget)
                if idx >= 0:
                    tabs.setTabEnabled(idx, visible)
            except Exception:
                pass

    def _update_toolbar_for_mode(self, mode: str):
        # assemble mode: show Assemble; analysis mode: show Disassemble
        if mode == "assemble":
            try:
                self.act_assemble.setVisible(True)
                self.act_disassemble.setVisible(False)
            except Exception:
                pass
        elif mode == "disassemble":
            try:
                self.act_assemble.setVisible(False)
                self.act_disassemble.setVisible(True)
            except Exception:
                pass
        else:
            try:
                self.act_assemble.setVisible(True)
                self.act_disassemble.setVisible(True)
            except Exception:
                pass

    def _set_mode(self, mode: str):
        # Input side: navigate to relevant tab, but keep both visible for easy switching
        idx_hex = self.input_tabs.indexOf(self.hex_edit)
        idx_asm = self.input_tabs.indexOf(self.asm_edit)
        if mode == "assemble":
            try:
                self.input_tabs.setCurrentIndex(idx_asm)
            except Exception:
                pass
            # Hide Hex tab, show only Assembly editor in Dev mode
            try:
                self.input_tabs.setTabVisible(idx_hex, False)  # Qt 5.15+/6
                self.input_tabs.setTabVisible(idx_asm, True)
            except Exception:
                try:
                    self.input_tabs.setTabEnabled(idx_hex, False)
                    self.input_tabs.setTabEnabled(idx_asm, True)
                except Exception:
                    pass
            # Output: show Output (formats), Debug, and Optimize
            self._set_tab_visible(self.output_tabs, self.output_text, False)
            self._set_tab_visible(self.output_tabs, self.validation_container, False)
            self._set_tab_visible(self.output_tabs, self.debug_widget, True)
            self._set_tab_visible(self.output_tabs, self.optimize_widget, True)
            self._set_tab_visible(self.output_tabs, self.formats_widget, True)
            # Syscalls visible in Dev mode
            # Syscalls visible only when supported for current arch
            try:
                sys_ok = canonical_arch(self.arch_combo.currentText() or "") is not None
            except Exception:
                sys_ok = False
            self._set_tab_visible(self.output_tabs, self.syscalls_widget, bool(sys_ok))
            try:
                self.output_tabs.setCurrentWidget(self.debug_widget)
            except Exception:
                pass
            # Show patterns tab in dev mode
            self._set_tab_visible(self.output_tabs, self.patterns_widget, True)
        elif mode == "disassemble":
            try:
                self.input_tabs.setCurrentIndex(idx_hex)
            except Exception:
                pass
            # Hide Assembly tab, show only Hex editor in Analysis mode
            try:
                self.input_tabs.setTabVisible(idx_hex, True)
                self.input_tabs.setTabVisible(idx_asm, False)
            except Exception:
                try:
                    self.input_tabs.setTabEnabled(idx_hex, True)
                    self.input_tabs.setTabEnabled(idx_asm, False)
                except Exception:
                    pass
            # Output: only textual disassembly
            self._set_tab_visible(self.output_tabs, self.formats_widget, False)
            self._set_tab_visible(self.output_tabs, self.validation_container, False)
            self._set_tab_visible(self.output_tabs, self.output_text, True)
            self._set_tab_visible(self.output_tabs, self.debug_widget, False)
            self._set_tab_visible(self.output_tabs, self.optimize_widget, False)
            # Syscalls visible in Analysis mode only when supported
            try:
                sys_ok = canonical_arch(self.arch_combo.currentText() or "") is not None
            except Exception:
                sys_ok = False
            self._set_tab_visible(self.output_tabs, self.syscalls_widget, bool(sys_ok))
            try:
                self.output_tabs.setCurrentWidget(self.output_text)
            except Exception:
                pass
            # Hide patterns tab in analysis mode
            self._set_tab_visible(self.output_tabs, self.patterns_widget, False)
        else:
            # Show everything
            self._set_tab_visible(self.output_tabs, self.formats_widget, True)
            self._set_tab_visible(self.output_tabs, self.validation_container, True)
            self._set_tab_visible(self.output_tabs, self.output_text, True)
            self._set_tab_visible(self.output_tabs, self.debug_widget, True)
            self._set_tab_visible(self.output_tabs, self.optimize_widget, True)
            # Show both input tabs (fallback state)
            try:
                self.input_tabs.setTabVisible(idx_hex, True)
                self.input_tabs.setTabVisible(idx_asm, True)
            except Exception:
                try:
                    self.input_tabs.setTabEnabled(idx_hex, True)
                    self.input_tabs.setTabEnabled(idx_asm, True)
                except Exception:
                    pass
            self._set_tab_visible(self.output_tabs, self.patterns_widget, True)
        self._update_toolbar_for_mode(mode)

    def on_input_tab_changed(self, idx: int):
        # Switch toolbar mode based on active input tab
        if self.input_tabs.widget(idx) is self.asm_edit:
            self._update_toolbar_for_mode("assemble")
            self._set_tab_visible(self.output_tabs, self.patterns_widget, True)
            try:
                self.mode_combo.blockSignals(True)
                self.mode_combo.setCurrentIndex(0)
                self.mode_combo.blockSignals(False)
            except Exception:
                pass
        else:
            self._update_toolbar_for_mode("disassemble")
            self._set_tab_visible(self.output_tabs, self.patterns_widget, False)
            try:
                self.mode_combo.blockSignals(True)
                self.mode_combo.setCurrentIndex(1)
                self.mode_combo.blockSignals(False)
            except Exception:
                pass

    # Helpers
    def _apply_mono(self, widget: QPlainTextEdit):
        f = QFont()
        # Qt5 vs Qt6: StyleHint enum location varies
        try:
            style_hint = QFont.Monospace  # PySide2
        except Exception:
            try:
                style_hint = QFont.StyleHint.Monospace  # PySide6
            except Exception:
                style_hint = None
        if style_hint is not None:
            try:
                f.setStyleHint(style_hint)
            except Exception:
                pass
        f.setFamily(MONO_FONT)
        widget.setFont(f)
        try:
            widget.setLineWrapMode(QPlainTextEdit.NoWrap)  # Qt5 style
        except Exception:
            try:
                widget.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)  # Qt6 style
            except Exception:
                pass

    def _setup_output_box(self, box: QPlainTextEdit):
        self._apply_mono(box)
        box.setReadOnly(True)
        box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

    def _labeled_box(self, text: str, target: Optional[QPlainTextEdit] = None) -> QWidget:
        w = QWidget()
        l = QHBoxLayout(w)
        l.setContentsMargins(0, 4, 0, 0)
        lbl = QLabel(text)
        copy_btn = QPushButton("Copy")
        copy_btn.setFixedWidth(60)
        l.addWidget(lbl)
        # Extra controls per block
        if text == "Hex":
            try:
                self.hex_no_space_chk = QCheckBox("No space")
                self.hex_no_space_chk.setToolTip("Remove spaces between hex bytes in output")
                # Default: spaces (unchecked)
                self.hex_no_space_chk.setChecked(False)
                # Update live when toggled
                def _on_hex_space_toggle(_state: int):
                    try:
                        self._refresh_hex_output()
                    except Exception:
                        pass
                self.hex_no_space_chk.stateChanged.connect(_on_hex_space_toggle)
                l.addSpacing(8)
                l.addWidget(self.hex_no_space_chk)
            except Exception:
                pass
        l.addStretch(1)
        l.addWidget(copy_btn)
        # Bind copy for the next widget added after label in layout usage
        def do_copy():
            if target is not None:
                content = target.toPlainText()
            else:
                # Map copy button to appropriate text box by label
                if text == "Inline":
                    content = self.inline_text.toPlainText()
                elif text == "Hex":
                    content = self.hex_text.toPlainText()
                elif text == "C":
                    content = self.c_text.toPlainText()
                elif text == "Python":
                    content = self.py_text.toPlainText()
                elif text == "Zig":
                    content = self.zig_text.toPlainText()
                else:
                    # Fallback: copy empty string
                    content = ""
            QApplication.clipboard().setText(content)
        copy_btn.clicked.connect(do_copy)
        return w

    def _populate_arch_platform(self):
        archs = self.adapter.list_architectures()
        self.arch_combo.clear()
        for a in archs:
            self.arch_combo.addItem(a)
        if self.arch_combo.count() == 0:
            self.arch_combo.addItem("x86_64")
        # Default-select x86_64 when available
        try:
            idx = self.arch_combo.findText("x86_64")
            if idx >= 0:
                self.arch_combo.setCurrentIndex(idx)
        except Exception:
            pass

    def _update_stats(self, raw: bytes):
        arch = self.arch_combo.currentText()
        self.status_arch.setText(f"Arch: {arch}")
        self.status_len.setText(f"Len: {len(raw)}")
        self.status_nulls.setText(f"Nulls: {count_nulls(raw)}")
        # bad pattern count excluding null-byte pattern (tracked separately)
        pmatches = [m for m in self.bpm.match_patterns(raw) if not (m.pattern.type == 'hex' and m.pattern.value.strip().lower() in ('00', '0x00'))]
        bad_count = sum(len(m.offsets) for m in pmatches)
        self.status_bad.setText(f"Bad: {bad_count}")

    # Actions
    def on_clear(self):
        self.hex_edit.clear()
        self.asm_edit.clear()
        self.output_text.clear()
        self.inline_text.clear()
        self.hex_text.clear()
        self.c_text.clear()
        self.py_text.clear()
        self.zig_text.clear()
        self.status_len.setText("len: 0")
        self.status_nulls.setText("nulls: 0")

    def on_disassemble(self):
        data_str = self.hex_edit.toPlainText()
        try:
            data = parse_hex_input(data_str)
        except ValueError as e:
            QMessageBox.critical(self, "Hex Parse Error", str(e))
            return

        arch = self.arch_combo.currentText() or "x86_64"
        try:
            lines = self.adapter.disassemble(data, arch_name=arch, addr=0)
        except Exception as e:
            QMessageBox.critical(self, "Disassembly Error", f"{e}\n\n{traceback.format_exc()}")
            return

        self.output_text.setPlainText("\n".join(lines))
        try:
            if self.disasm_highlighter:
                self.disasm_highlighter.rehighlight()
        except Exception:
            pass
        # Update formatter views
        self._update_formats(data)
        self._update_stats(data)
        self._last_bytes = data
        # Validation is only auto-run on assemble per requirements
        # Show only hex editor + disassembly output
        self._set_mode("disassemble")
        # Decompile tab removed

    def on_assemble(self):
        asm = self.asm_edit.toPlainText()
        if not asm.strip():
            QMessageBox.information(self, "Assemble", "Assembly input is empty.")
            return
        arch = self.arch_combo.currentText() or "x86_64"
        try:
            data = self.adapter.assemble(asm, arch_name=arch, platform_name=None, addr=0)
        except Exception as e:
            QMessageBox.critical(self, "Assemble Error", f"{e}\n\n{traceback.format_exc()}")
            return

        # Show disassembly of the assembled bytes for context
        try:
            lines = self.adapter.disassemble(data, arch_name=arch, addr=0)
        except Exception:
            lines = []
        if lines:
            self.output_text.setPlainText("\n".join(lines))
            try:
                if self.disasm_highlighter:
                    self.disasm_highlighter.rehighlight()
            except Exception:
                pass
        else:
            self.output_text.setPlainText("(no disassembly)")

        self.hex_edit.setPlainText(bytes_to_hex(data, sep=" "))
        self._update_formats(data)
        self._update_stats(data)
        # Update Debug pane (opcode + objdump-like assembly)
        self._update_debug(data, arch)
        # Auto-run validation on assemble
        self._update_validation_view(data)
        # Show only asm editor + Output/Debug
        self._set_mode("assemble")
        self._last_bytes = data

    def _update_formats(self, data: bytes):
        self.inline_text.setPlainText(bytes_to_inline(data))
        # Respect the Hex "No space" option
        try:
            self._refresh_hex_output(data)
        except Exception:
            self.hex_text.setPlainText(bytes_to_hex(data, sep=" "))
        self.c_text.setPlainText(bytes_to_c_array(data, var_name="shellcode", include_len=True))
        self.py_text.setPlainText(bytes_to_python_bytes(data, style="literal"))
        self.zig_text.setPlainText(bytes_to_zig_array(data, var_name="shellcode"))

    def _refresh_hex_output(self, data: Optional[bytes] = None):
        """Refresh the Hex output area honoring the no-space checkbox."""
        try:
            ns = bool(getattr(self, 'hex_no_space_chk', None) and self.hex_no_space_chk.isChecked())
        except Exception:
            ns = False
        sep = "" if ns else " "
        buf = data if data is not None else getattr(self, '_last_bytes', b"")
        if not isinstance(buf, (bytes, bytearray)):
            buf = b""
        self.hex_text.setPlainText(bytes_to_hex(buf, sep=sep))

    def _update_opcode(self, data: bytes):
        # Update opcode pane with hex bytes
        hex_str = bytes_to_hex(data, sep=" ")
        self.opcode_text.setPlainText(hex_str)
        # Compute exact bad byte offsets and highlight only those bytes
        bad = self._compute_bad_offsets(data)
        try:
            if hasattr(self, 'op_hl') and self.op_hl:
                self.op_hl.set_bad_offsets(bad)
        except Exception:
            pass

    def _compute_bad_offsets(self, data: bytes):
        try:
            if hasattr(self, 'patterns_widget') and (not self.patterns_widget.is_highlight_enabled()):
                return set()
        except Exception:
            pass
        offs = set()
        try:
            pmatches = self.bpm.match_patterns(data)
        except Exception:
            pmatches = []
        for m in pmatches:
            if m.pattern.type == 'hex':
                for o in m.offsets:
                    offs.add(int(o))
            elif m.pattern.type == 'sequence':
                # Highlight the entire sequence length
                try:
                    seq = self.bpm._parse_sequence(m.pattern.value)  # type: ignore
                except Exception:
                    seq = None
                length = len(seq) if seq else 1
                for o in m.offsets:
                    for k in range(length):
                        offs.add(int(o) + k)
            else:
                # regex: we only mark the starting byte
                for o in m.offsets:
                    offs.add(int(o))
        return offs

    def _update_debug(self, data: bytes, arch: str):
        # Opcode + objdump-like assembly
        self._update_opcode(data)
        try:
            lines = self.adapter.disassemble_detailed(data, arch_name=arch, addr=0)
        except Exception:
            lines = []
        self.debug_asm_text.setPlainText("\n".join(lines))
        # Update bad byte highlighting in assembly bytes column
        try:
            spans = self.adapter.disassemble_spans(data, arch_name=arch, addr=0)
        except Exception:
            spans = []
        bad = self._compute_bad_offsets(data)
        try:
            if hasattr(self, 'debug_asm_bad_hl') and self.debug_asm_bad_hl:
                self.debug_asm_bad_hl.set_mapping(spans)
                self.debug_asm_bad_hl.set_bad_offsets(bad)
        except Exception:
            pass

    def on_badchars_toggled(self, checked: bool):
        # Persist setting and refresh current highlights
        cfg = load_config()
        cfg["bad_highlight_enabled"] = bool(checked)
        save_config(cfg)
        data = getattr(self, '_last_bytes', b"") or b""
        if data:
            arch = self.arch_combo.currentText() or "x86_64"
            # Refresh opcode/debug highlights
            self._update_debug(data, arch)

    def _is_dark_mode(self) -> bool:
        try:
            pal = QApplication.instance().palette()
            col = pal.color(QPalette.Window)
            # Use perceived brightness to decide dark/light
            r, g, b = col.red(), col.green(), col.blue()
            brightness = (0.299 * r + 0.587 * g + 0.114 * b)
            return brightness < 128
        except Exception:
            return True

    def _preferred_style(self) -> str:
        # Dracula for dark, Rainbow Dash for light, with safe fallbacks
        return "dracula" if self._is_dark_mode() else "rainbow_dash"

    def _refresh_disasm_highlighter(self):
        # Recreate token highlighters for current architecture/style
        arch = self.arch_combo.currentText() or "x86_64"
        style = self._preferred_style()
        # Output disassembly
        try:
            if self.disasm_highlighter:
                try:
                    self.disasm_highlighter.setDocument(None)
                except Exception:
                    pass
            self.disasm_highlighter = create_disassembly_highlighter(self.output_text.document(), arch_name=arch, style_name=style)
            try:
                self.disasm_highlighter.rehighlight()
            except Exception:
                pass
        except Exception:
            self.disasm_highlighter = None
        # Debug assembly token highlighter
        try:
            if hasattr(self, 'debug_asm_token_hl') and self.debug_asm_token_hl:
                try:
                    self.debug_asm_token_hl.setDocument(None)
                except Exception:
                    pass
            self.debug_asm_token_hl = create_disassembly_highlighter(self.debug_asm_text.document(), arch_name=arch, style_name=style)
            try:
                self.debug_asm_token_hl.rehighlight()
            except Exception:
                pass
        except Exception:
            self.debug_asm_token_hl = None
        # Assembly editor token highlighter
        try:
            if hasattr(self, 'asm_highlighter') and self.asm_highlighter:
                try:
                    self.asm_highlighter.setDocument(None)
                except Exception:
                    pass
            self.asm_highlighter = create_disassembly_highlighter(self.asm_edit.document(), arch_name=arch, style_name=style)
            try:
                self.asm_highlighter.rehighlight()
            except Exception:
                pass
        except Exception:
            self.asm_highlighter = None
        # Initialize Syscalls tab state
        try:
            self._refresh_syscalls_tab()
        except Exception:
            pass
        # Output tab code highlighters (refresh for style changes)
        try:
            if hasattr(self, 'inline_code_hl') and self.inline_code_hl:
                try:
                    self.inline_code_hl.setDocument(None)
                except Exception:
                    pass
            self.inline_code_hl = create_code_highlighter(self.inline_text.document(), lexer_name="python", style_name=style)
        except Exception:
            self.inline_code_hl = None
        try:
            if hasattr(self, 'c_code_hl') and self.c_code_hl:
                try:
                    self.c_code_hl.setDocument(None)
                except Exception:
                    pass
            self.c_code_hl = create_code_highlighter(self.c_text.document(), lexer_name="c", style_name=style)
        except Exception:
            self.c_code_hl = None
        try:
            if hasattr(self, 'py_code_hl') and self.py_code_hl:
                try:
                    self.py_code_hl.setDocument(None)
                except Exception:
                    pass
            self.py_code_hl = create_code_highlighter(self.py_text.document(), lexer_name="python", style_name=style)
        except Exception:
            self.py_code_hl = None
        try:
            if hasattr(self, 'zig_code_hl') and self.zig_code_hl:
                try:
                    self.zig_code_hl.setDocument(None)
                except Exception:
                    pass
            self.zig_code_hl = create_code_highlighter(self.zig_text.document(), lexer_name="zig", style_name=style)
        except Exception:
            self.zig_code_hl = None

    def _show_badchars_controls(self, show: bool):
        """Show/hide the bad-chars controls (checkbox + Edit…) in Dev mode only."""
        try:
            if getattr(self, '_bc_in_corner', False):
                # Corner widget mode: add/remove entirely
                if show:
                    self.chk_badchars.setVisible(True)
                    self.btn_edit_patterns_mid.setVisible(True)
                    self.output_tabs.setCornerWidget(self.bc_container, Qt.TopRightCorner)
                else:
                    # Remove corner widget when hidden
                    self.output_tabs.setCornerWidget(None, Qt.TopRightCorner)
            else:
                # Fallback: container in layout; toggle visibility
                self.chk_badchars.setVisible(bool(show))
                self.btn_edit_patterns_mid.setVisible(bool(show))
                self.bc_container.setVisible(bool(show))
        except Exception:
            pass

    def on_mode_changed(self, idx: int):
        # 0 = Dev (assemble), 1 = Analysis (disassemble)
        mode = "assemble" if idx == 0 else "disassemble"
        self._set_mode(mode)
        # Ensure input tab follows the mode
        try:
            if mode == "assemble":
                self.input_tabs.setCurrentWidget(self.asm_edit)
            else:
                self.input_tabs.setCurrentWidget(self.hex_edit)
        except Exception:
            pass

    def _refresh_syscalls_tab(self):
        """Show/hide Syscalls tab based on current arch and refresh when shown."""
        try:
            arch = self.arch_combo.currentText() or ""
        except Exception:
            arch = ""
        try:
            supported = canonical_arch(arch) is not None
        except Exception:
            supported = False
        # Toggle visibility
        try:
            self._set_tab_visible(self.output_tabs, self.syscalls_widget, bool(supported))
        except Exception:
            pass
        if supported:
            try:
                self.syscalls_widget.reload()
            except Exception:
                pass
        else:
            # If currently selected, nudge to a safe tab
            try:
                if self.output_tabs.currentWidget() is self.syscalls_widget:
                    self.output_tabs.setCurrentWidget(self.output_text)
            except Exception:
                pass

    def on_validate(self):
        arch = self.arch_combo.currentText() or "x86_64"
        asm = self.asm_edit.toPlainText()
        data: bytes = b""
        hex_str = self.hex_edit.toPlainText().strip()
        if hex_str:
            try:
                data = parse_hex_input(hex_str)
            except ValueError as e:
                QMessageBox.critical(self, "Hex Parse Error", str(e))
                return
        elif asm.strip():
            try:
                data = self.adapter.assemble(asm, arch_name=arch, platform_name=None, addr=0)
            except Exception:
                data = b""
        self._update_validation_view(data)
        # Ensure the Validation tab is visible and active
        self._set_tab_visible(self.output_tabs, self.validation_container, True)
        try:
            self.output_tabs.setCurrentWidget(self.validation_container)
        except Exception:
            pass

    def _update_validation_view(self, data: bytes):
        arch = self.arch_combo.currentText() or "x86_64"
        asm = self.asm_edit.toPlainText()
        issues, pmatches = validate_all(asm, data, arch, self.bpm)
        lines = []
        if not issues and (sum(len(m.offsets) for m in pmatches) == 0):
            lines.append("No issues found.")
        else:
            for iss in issues:
                loc = f" line {iss.line}" if getattr(iss, 'line', None) else (f" offset {iss.offset}" if getattr(iss, 'offset', None) is not None else "")
                lines.append(f"[{iss.severity}] {iss.kind}:{loc} - {iss.message}")
            for m in pmatches:
                if m.pattern.type == 'hex' and m.pattern.value.lower().strip() in ('00', '0x00'):
                    continue
                offlist = ", ".join(str(o) for o in m.offsets[:10])
                more = "" if len(m.offsets) <= 10 else f" (+{len(m.offsets)-10} more)"
                nm = m.pattern.name or m.pattern.value
                lines.append(f"[warn] pattern:{nm} at offsets {offlist}{more}")
        self.validation_text.setPlainText("\n".join(lines))
        # also update status bar
        self._update_stats(data)

    # Decompile tab removed

    def on_patterns(self):
        dlg = PatternsDialog(self.bpm, self)
        try:
            res = dlg.exec()
        except Exception:
            res = dlg.exec_()
        if res:
            self.bpm.patterns = dlg.result_patterns()
            # persist immediately
            cfg = load_config()
            cfg["bad_patterns"] = self.bpm.serialize()
            save_config(cfg)
            # refresh validation view based on current bytes
            try:
                data = parse_hex_input(self.hex_edit.toPlainText())
            except Exception:
                data = b""
            self._update_validation_view(data)

    def closeEvent(self, event):
        # persist patterns on close as well
        cfg = load_config()
        cfg["bad_patterns"] = self.bpm.serialize()
        save_config(cfg)
        super().closeEvent(event)
