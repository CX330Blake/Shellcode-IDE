from __future__ import annotations

import traceback
from typing import Optional, Tuple

# Qt compatibility: prefer PySide6 (Qt6), fallback to PySide2 (Qt5)
_QT_LIB = None
try:
    from PySide6.QtCore import Qt, QTimer, QEvent, QSize  # type: ignore
    from PySide6.QtGui import QFont, QAction, QPalette, QColor, QIcon, QPixmap, QPainter  # type: ignore  # QAction is in QtGui on Qt6
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
        QFrame,
        QTabWidget,
        QToolBar,
        QVBoxLayout,
        QWidget,
    )
    _QT_LIB = "PySide6"
except Exception:
    try:
        from PySide2.QtCore import Qt, QTimer, QEvent, QSize  # type: ignore
        from PySide2.QtGui import QFont, QPalette, QColor, QIcon, QPixmap, QPainter  # type: ignore
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
            QFrame,
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
    create_inline_highlighter,
    HexBadByteHighlighter,
    AsmObjdumpBadByteHighlighter,
    InlineBadByteHighlighter,
    _good_bad_colors,
)
from .optimize_panel import OptimizePanel
from .file_tab import FileDropTab
from .syscalls_panel import SyscallsPanel
from .shellstorm_panel import ShellstormPanel
from ..backends.syscalls import canonical_arch
from ..formatters.base import (
    bytes_to_c_array,
    bytes_to_c_stub,
    bytes_to_hex,
    bytes_to_inline,
    bytes_to_python_bytes,
    bytes_to_python_stub,
    bytes_to_zig_array,
    bytes_to_zig_stub,
    bytes_to_rust_array,
    bytes_to_rust_stub,
    bytes_to_go_slice,
    bytes_to_go_stub,
)
from ..utils.hexbytes import parse_hex_input, count_nulls


MONO_FONT = "Menlo, Consolas, monospace"


class ShellcodeIDEWindow(QMainWindow):
    def __init__(self, parent: Optional[QWidget] = None, bn_api=None):
        super().__init__(parent)
        self.setWindowTitle("Shellcode IDE")
        # Slightly narrower default width for better fit on smaller screens
        self.resize(900, 700)
        # Compute centered geometry before the window is shown (best-effort),
        # and then finalize exact centering synchronously in showEvent using
        # frameGeometry so decorations are accounted for without a visible move.
        self._did_center_after_show = True  # disable any delayed re-centering
        self._did_first_show_center = False  # will center once in showEvent
        try:
            self._set_initial_center_geometry()
        except Exception:
            pass

        self.adapter = BNAdapter(bn_api=bn_api)
        # Load config and patterns
        cfg = load_config()
        if isinstance(cfg.get("bad_patterns"), list):
            self.bpm = BadPatternManager.deserialize(cfg.get("bad_patterns") or [])
        else:
            self.bpm = BadPatternManager()
        # One-time migration: ensure 0x00 is enabled by default.
        # If user previously disabled it, they can disable again; we only flip once.
        try:
            if not bool(cfg.get("migrated_00_default", False)):
                pats = list(getattr(self.bpm, 'patterns', []) or [])
                def _is_null_pat(p) -> bool:
                    try:
                        v = (p.value or "").strip().lower()
                        if v.startswith('0x'):
                            v = v[2:]
                        return p.type == 'hex' and v == '00'
                    except Exception:
                        return False
                found = False
                for p in pats:
                    if _is_null_pat(p):
                        found = True
                        p.enabled = True
                        break
                if not found:
                    from ..backends.validator import Pattern as _Pat
                    pats.insert(0, _Pat(type='hex', value='00', name='NULL byte', enabled=True))
                self.bpm.patterns = pats
                cfg["bad_patterns"] = self.bpm.serialize()
                cfg["migrated_00_default"] = True
                save_config(cfg)
        except Exception:
            pass

        # Toolbar
        tb = QToolBar("Main")
        tb.setMovable(False)
        self.addToolBar(tb)
        # Keep a handle for later padding sync with editors
        self._toolbar = tb
        # Left spacer to align toolbar content (Mode, Arch) with the Assembly editor text
        # Width is updated later once we compute editor padding from the Syscalls tab.
        try:
            self._toolbar_left_spacer = QWidget()
            # Default to 0; will be set in _sync_shellcode_padding_to_syscalls
            self._toolbar_left_spacer.setFixedWidth(0)
            tb.addWidget(self._toolbar_left_spacer)
        except Exception:
            self._toolbar_left_spacer = None

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
        # Apply borderless style to both editors; padding will be synced to Syscalls
        # Add comfortable inner padding to the Assembly editor so it matches
        # the feel of the right-side output panes.
        # Padding set later to match Syscalls panel once it's created
        # Ensure the Assembly editor aligns flush with the tab pane edges (no extra inner frame),
        # while keeping internal padding via document margins above.
        try:
            self.hex_edit.setContentsMargins(0, 0, 0, 0)
        except Exception:
            pass
        try:
            self.asm_edit.setContentsMargins(0, 0, 0, 0)
        except Exception:
            pass
        try:
            self.hex_edit.setFrameShape(QFrame.NoFrame)
        except Exception:
            pass
        try:
            self.asm_edit.setFrameShape(QFrame.NoFrame)
        except Exception:
            pass
        self.input_tabs.addTab(self.hex_edit, "Hex/Bytes")
        self.input_tabs.addTab(self.asm_edit, "Assembly")
        # Drag & Drop File tab: lets user drop or open a file, routing
        # assembly-like files to the Assembly editor and others to Hex.
        def _filetab_insert_hex(b: bytes) -> None:
            try:
                self.hex_edit.setPlainText(bytes_to_hex(b, sep=" "))
                self._update_formats(b)
                self._update_stats(b)
                self._last_bytes = b
                # Take user to the Hex editor for immediate editing
                try:
                    self.input_tabs.setCurrentWidget(self.hex_edit)
                    self.hex_edit.setFocus()
                except Exception:
                    pass
            except Exception:
                pass
        def _filetab_insert_asm_text(s: str) -> None:
            try:
                self.asm_edit.setPlainText(s)
                # Take user to the Assembly editor for immediate editing
                try:
                    self.input_tabs.setCurrentWidget(self.asm_edit)
                    self.asm_edit.setFocus()
                except Exception:
                    pass
            except Exception:
                pass
        # Provide a mode provider so the File tab can enforce Analysis-only-bytes
        def _mode_provider() -> str:
            try:
                return (self.mode_combo.currentText() or "").strip()
            except Exception:
                return "Dev"
        self.file_tab = FileDropTab(on_hex=_filetab_insert_hex, on_asm=_filetab_insert_asm_text, parent=self, mode_provider=_mode_provider)
        self.input_tabs.addTab(self.file_tab, "File")
        # Fill space so editor borders align top and bottom with right
        left_layout.addWidget(self.input_tabs, 1)
        splitter.addWidget(left)
        # Install event filters to auto-trim trailing blank lines on focus loss
        try:
            self.hex_edit.installEventFilter(self)
            self.asm_edit.installEventFilter(self)
        except Exception:
            pass

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
        # Apply comfortable inner padding similar to Syscalls tab visuals
        try:
            self._apply_inner_padding(self.output_text, margin_px=10, viewport_pad=(6, 6, 6, 6))
        except Exception:
            pass
        # Header row with "Send to Dev mode" action
        self.disasm_header = QWidget()
        _dh_lay = QHBoxLayout(self.disasm_header)
        try:
            _def_h = QHBoxLayout()
            _m = _def_h.contentsMargins()
            _dh_lay.setContentsMargins(_m.left(), _m.top(), _m.right(), _m.bottom())
            _dh_lay.setSpacing(_def_h.spacing())
        except Exception:
            pass
        _dh_lay.addWidget(QLabel("Disassembly"))
        _dh_lay.addStretch(1)
        # Copy button for disassembly view
        self.btn_disasm_copy = QPushButton("Copy")
        try:
            self.btn_disasm_copy.setFixedWidth(60)
        except Exception:
            pass
        try:
            def _copy_disasm():
                try:
                    QApplication.clipboard().setText(self.output_text.toPlainText())
                except Exception:
                    return
                try:
                    self._flash_copied(self.btn_disasm_copy)
                except Exception:
                    pass
            self.btn_disasm_copy.clicked.connect(_copy_disasm)
        except Exception:
            pass
        _dh_lay.addWidget(self.btn_disasm_copy)
        # Send-to-dev action
        self.btn_send_to_dev = QPushButton("Send to Dev mode")
        try:
            self.btn_send_to_dev.setToolTip("Copy disassembly to Assembly editor and switch to Dev mode")
        except Exception:
            pass
        _dh_lay.addWidget(self.btn_send_to_dev)
        try:
            self.btn_send_to_dev.clicked.connect(self._send_disassembly_to_dev)
        except Exception:
            pass
        # Wrap header + view in a container for the Disassembly tab
        self.disasm_container = QWidget()
        _dv = QVBoxLayout(self.disasm_container)
        try:
            _m = _dv.contentsMargins()
            _dv.setContentsMargins(_m.left(), _m.top(), _m.right(), _m.bottom())
        except Exception:
            pass
        _dv.addWidget(self.disasm_header)
        _dv.addWidget(self.output_text)
        self.disasm_highlighter = None
        self._refresh_disasm_highlighter()
        self.output_tabs.addTab(self.disasm_container, "Disassembly")

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
            assemble_cb=self.on_assemble,
            parent=self,
        )
        self.output_tabs.addTab(self.optimize_widget, "Optimize")

        # Formats view (Shellcode output pane)
        fmt_widget = QWidget()
        fmt_layout = QGridLayout(fmt_widget)
        # Keep a handle for later syncing with Syscalls padding style
        self.formats_layout = fmt_layout
        # Match default padding style (like Syscalls tab)
        try:
            _def_v = QVBoxLayout()
            _m = _def_v.contentsMargins()
            fmt_layout.setContentsMargins(_m.left(), _m.top(), _m.right(), _m.bottom())
        except Exception:
            pass
        try:
            _def_v = QVBoxLayout()
            _sp = _def_v.spacing()
            fmt_layout.setHorizontalSpacing(_sp)
            fmt_layout.setVerticalSpacing(_sp)
        except Exception:
            pass
        # Ensure header rows stay compact and do not expand vertically
        try:
            fmt_layout.setRowStretch(0, 0)
            fmt_layout.setRowStretch(2, 0)
            fmt_layout.setRowStretch(1, 1)  # let text areas take extra space
            fmt_layout.setRowStretch(3, 2)
        except Exception:
            pass

        self.inline_text = QPlainTextEdit(); self._setup_output_box(self.inline_text)
        self.hex_text = QPlainTextEdit(); self._setup_output_box(self.hex_text)
        # Copy As Code pane (single area with language selector)
        self.hll_text = QPlainTextEdit(); self._setup_output_box(self.hll_text)
        self.hll_lang_combo = QComboBox()
        try:
            # supported generators (label C emits the runnable C stub)
            self.hll_lang_combo.addItems(["C", "Python", "Zig", "Rust", "Go"])  # supported generators
        except Exception:
            pass
        try:
            # Prevent Enter/Return from leaking to the Assembly editor when changing selection
            self.hll_lang_combo.installEventFilter(self)
            # After a selection, move focus to the read-only output box to avoid editing ASM
            self.hll_lang_combo.activated.connect(lambda *_: self.hll_text.setFocus())
        except Exception:
            pass

        self.inline_header = self._labeled_box("Inline")
        fmt_layout.addWidget(self.inline_header, 0, 0)
        fmt_layout.addWidget(self.inline_text, 1, 0)
        self.hex_header = self._labeled_box("Hex")
        fmt_layout.addWidget(self.hex_header, 0, 1)
        fmt_layout.addWidget(self.hex_text, 1, 1)
        # Copy As Code row with selector and copy button (compact)
        hll_row = QWidget(); hll_row_layout = QHBoxLayout(hll_row)
        try:
            # Use default margins/spacing to mirror Syscalls panel
            _def_h = QHBoxLayout()
            _m = _def_h.contentsMargins()
            hll_row_layout.setContentsMargins(_m.left(), _m.top(), _m.right(), _m.bottom())
            hll_row_layout.setSpacing(_def_h.spacing())
        except Exception:
            pass
        lbl_hll = QLabel("Copy As Code")
        try:
            lbl_hll.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            lbl_hll.setMargin(0)
        except Exception:
            pass
        hll_row_layout.addWidget(lbl_hll)
        # Push language selector + copy to the right
        hll_row_layout.addStretch(1)
        hll_row_layout.addWidget(QLabel("Language:"))
        # Use default widget height for combo to match Optimize tab
        hll_row_layout.addWidget(self.hll_lang_combo)
        hll_copy = QPushButton("Copy");
        try:
            hll_copy.setFixedWidth(60)
        except Exception:
            pass
        hll_row_layout.addWidget(hll_copy)
        # Default height mirrors standard toolbar-like rows
        def _copy_hll():
            try:
                QApplication.clipboard().setText(self.hll_text.toPlainText())
                try:
                    self._flash_copied(hll_copy)
                except Exception:
                    pass
            except Exception:
                pass
        try:
            hll_copy.clicked.connect(_copy_hll)
        except Exception:
            pass
        fmt_layout.addWidget(hll_row, 2, 0, 1, 2)
        self.hll_header_row = hll_row
        fmt_layout.addWidget(self.hll_text, 3, 0, 1, 2)
        # Keep formats packed to top
        # No extra stretch; the tab widget fills the height

        self.output_tabs.addTab(fmt_widget, "Shellcode")
        self.formats_widget = fmt_widget
        # Tabs fill space so borders align
        right_layout.addWidget(self.output_tabs, 1)

        # Syntax highlighting for Output tab code blocks using Qt-only highlighters
        try:
            # Inline: custom highlighter that colors only [0-9a-f]
            self.inline_code_hl = create_inline_highlighter(self.inline_text.document())
        except Exception:
            self.inline_code_hl = None
        # High-level language code highlighter; depends on selected language
        self.hll_code_hl = None
        try:
            self._apply_hll_highlighter()
        except Exception:
            self.hll_code_hl = None
        try:
            self.hll_lang_combo.currentTextChanged.connect(lambda _t: self._on_hll_lang_changed())
        except Exception:
            pass
        # Bad-byte highlighters for Inline and Hex panes (attached in analysis mode)
        self.hex_bad_hl = None
        self.inline_bad_hl = None

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
        # Now that Syscalls tab exists, sync Shellcode pane and editors padding to match it
        try:
            self._sync_shellcode_padding_to_syscalls()
        except Exception:
            pass
        # Also align the toolbar's left padding with the editors once paddings are known
        try:
            self._sync_toolbar_padding_to_editors()
        except Exception:
            pass
        # Preload Syscalls table once after UI is shown so users don't need to Refresh
        try:
            QTimer.singleShot(0, self._refresh_syscalls_tab)
        except Exception:
            try:
                # Fallback: attempt immediately
                self._refresh_syscalls_tab()
            except Exception:
                pass

        # Shell-Storm tab (search/import online shellcodes)
        def _insert_hex_bytes(b: bytes) -> None:
            try:
                # Insert into Hex editor and switch to Analysis mode to show disassembly
                self.hex_edit.setPlainText(bytes_to_hex(b, sep=" "))
                self._update_formats(b)
                self._update_stats(b)
                self._last_bytes = b
                self._set_mode("disassemble")
            except Exception:
                pass
        def _insert_asm_text(s: str) -> None:
            try:
                self.asm_edit.setPlainText(s)
                self._set_mode("assemble")
            except Exception:
                pass
        self.shellstorm_widget = ShellstormPanel(
            get_arch_cb=lambda: (self.arch_combo.currentText() or "x86_64"),
            insert_hex_cb=_insert_hex_bytes,
            insert_asm_cb=_insert_asm_text,
            parent=self,
        )
        self.output_tabs.addTab(self.shellstorm_widget, "Shell-Storm")

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
        # Ensure Shellcode tab appears before Debug tab
        try:
            dbg_idx = self.output_tabs.indexOf(self.debug_widget)
            sh_idx = self.output_tabs.indexOf(self.formats_widget)
            if dbg_idx != -1 and sh_idx != -1 and sh_idx > dbg_idx:
                dbg_text = self.output_tabs.tabText(dbg_idx)
                sh_text = self.output_tabs.tabText(sh_idx)
                # Remove in descending order to avoid index shifts
                self.output_tabs.removeTab(sh_idx)
                self.output_tabs.removeTab(dbg_idx)
                # Insert swapped
                self.output_tabs.insertTab(dbg_idx, self.formats_widget, sh_text)
                self.output_tabs.insertTab(sh_idx, self.debug_widget, dbg_text)
        except Exception:
            pass
        # output_tabs already added with stretch above
        splitter.addWidget(right)

        # Status bar
        sb = QStatusBar()
        self.setStatusBar(sb)
        self.status_arch = QLabel("arch: -")
        self.status_len = QLabel("len: 0")
        self.status_bad = QLabel("bad: 0")
        sb.addPermanentWidget(self.status_arch)
        sb.addPermanentWidget(self._status_separator())
        sb.addPermanentWidget(self.status_len)
        sb.addPermanentWidget(self._status_separator())
        sb.addPermanentWidget(self.status_bad)

        # Keep grip visible for resizing
        try:
            sb.setSizeGripEnabled(True)
        except Exception:
            pass

        # Wire actions
        self.act_assemble.triggered.connect(self.on_assemble)
        self.act_disassemble.triggered.connect(self.on_disassemble)
        # No Disassembly control bar; keep simple padded text view
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
        # Also nudge File tab to re-apply restrictions when mode changes
        try:
            self.mode_combo.currentIndexChanged.connect(lambda _i: getattr(self.file_tab, '_enforce_analysis_restrictions', lambda: None)())
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
        # Add Qt-only highlighter to Assembly editor
        try:
            self.asm_highlighter = create_disassembly_highlighter(
                self.asm_edit.document(), arch_name=self.arch_combo.currentText() or "x86_64"
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

        # Final centering happens once after the window is shown.

    def showEvent(self, event):  # type: ignore[override]
        # Center synchronously before the first paint using frameGeometry
        # so the window appears already centered without a post-show jump.
        try:
            if not getattr(self, '_did_first_show_center', False):
                center_point = None
                # Prefer parent window center when available
                try:
                    p = self.parentWidget()
                    if p and p.isWindow():
                        center_point = p.frameGeometry().center()
                except Exception:
                    center_point = None
                if center_point is None:
                    try:
                        # Use the screen that will show this window
                        from PySide6.QtGui import QGuiApplication  # type: ignore
                        scr = getattr(self, 'screen', lambda: None)() or QGuiApplication.primaryScreen()
                        ag = scr.availableGeometry() if scr else None
                        center_point = ag.center() if ag else None
                    except Exception:
                        center_point = None
                if center_point is None:
                    try:
                        # Qt5 fallback
                        desk = QApplication.desktop()  # type: ignore[attr-defined]
                        ag = desk.availableGeometry(self)
                        center_point = ag.center()
                    except Exception:
                        center_point = None
                if center_point is not None:
                    try:
                        fg = self.frameGeometry()
                        fg.moveCenter(center_point)
                        self.move(fg.topLeft())
                    except Exception:
                        pass
                self._did_first_show_center = True
        except Exception:
            pass
        try:
            super().showEvent(event)
        except Exception:
            pass

    def _center_after_show(self) -> None:
        if getattr(self, '_did_center_after_show', False):
            return
        ag = None
        # If we have a top-level parent window, center relative to it
        try:
            p = self.parentWidget()
            if p and p.isWindow():
                pg = p.frameGeometry()
                fg = self.frameGeometry()
                fg.moveCenter(pg.center())
                self.move(fg.topLeft())
                self._did_center_after_show = True
                return
        except Exception:
            pass
        # Prefer the screen where the window resides (Qt6)
        try:
            from PySide6.QtGui import QGuiApplication  # type: ignore
            scr = getattr(self, 'screen', lambda: None)() or QGuiApplication.primaryScreen()
            ag = scr.availableGeometry() if scr else None
        except Exception:
            ag = None
        if ag is None:
            # Qt5 fallback: use the screen for this window if possible
            try:
                desk = QApplication.desktop()  # type: ignore[attr-defined]
                idx = desk.screenNumber(self) if hasattr(desk, 'screenNumber') else -1
                if isinstance(idx, int) and idx >= 0:
                    ag = desk.availableGeometry(idx)
                else:
                    ag = desk.availableGeometry(self)
            except Exception:
                ag = None
        if ag is None:
            return
        try:
            fg = self.frameGeometry()
            fg.moveCenter(ag.center())
            self.move(fg.topLeft())
            self._did_center_after_show = True
        except Exception:
            # As a last resort, setGeometry using current size
            try:
                w, h = self.width(), self.height()
                x = ag.x() + max(0, (ag.width() - w) // 2)
                y = ag.y() + max(0, (ag.height() - h) // 2)
                self.setGeometry(x, y, w, h)
                self._did_center_after_show = True
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

    def _status_separator(self) -> QFrame:
        frm = QFrame()
        try:
            frm.setFrameShape(QFrame.VLine)
            frm.setFrameShadow(QFrame.Sunken)
            try:
                frm.setLineWidth(1)
                frm.setMidLineWidth(0)
            except Exception:
                pass
            # Give the separator breathing room
            try:
                frm.setFixedWidth(10)
            except Exception:
                pass
        except Exception:
            # Fallback to a simple label if QFrame isn't available
            try:
                lb = QLabel("|")
                return lb  # type: ignore[return-value]
            except Exception:
                pass
        return frm

    def eventFilter(self, obj, event):  # type: ignore[override]
        try:
            # Swallow Enter/Return keys on the Copy As Code language combo to avoid inserting\n
            # unintended newlines in the Assembly editor when users confirm selection.
            if obj is getattr(self, 'hll_lang_combo', None):
                if event and hasattr(event, 'type'):
                    t = event.type()
                    try:
                        key = event.key() if hasattr(event, 'key') else None
                    except Exception:
                        key = None
                    if t in (QEvent.KeyPress, QEvent.KeyRelease) and key in (Qt.Key_Return, Qt.Key_Enter):
                        try:
                            event.accept()
                        except Exception:
                            pass
                        return True
        except Exception:
            pass
        try:
            if event and hasattr(event, 'type') and event.type() == QEvent.FocusOut:
                if obj is self.asm_edit or obj is self.hex_edit:
                    try:
                        self._strip_editor_blank_lines(obj)
                    except Exception:
                        pass
        except Exception:
            pass
        try:
            return super().eventFilter(obj, event)
        except Exception:
            return False

    def _strip_editor_blank_lines(self, edit: QPlainTextEdit) -> None:
        """Remove trailing blank lines and whitespace from the end of the editor text."""
        try:
            text = edit.toPlainText()
        except Exception:
            return
        try:
            stripped = text.rstrip()
        except Exception:
            stripped = text
        if stripped != text:
            try:
                edit.blockSignals(True)
            except Exception:
                pass
            try:
                edit.setPlainText(stripped)
                # Move cursor to end
                cur = edit.textCursor()  # type: ignore[attr-defined]
                cur.movePosition(cur.End)
                edit.setTextCursor(cur)
            except Exception:
                pass
            try:
                edit.blockSignals(False)
            except Exception:
                pass

    def _set_initial_center_geometry(self) -> None:
        """Compute and set a centered geometry prior to show()."""
        # Prefer centering relative to a parent window if available (e.g., BN main window)
        try:
            p = self.parentWidget()
            if p and p.isWindow():
                w, h = self.width(), self.height()
                try:
                    pg = p.frameGeometry()
                    cx, cy = pg.center().x(), pg.center().y()
                except Exception:
                    pg = p.geometry()
                    cx = pg.x() + pg.width() // 2
                    cy = pg.y() + pg.height() // 2
                x = int(cx - w // 2)
                y = int(cy - h // 2)
                self.setGeometry(x, y, w, h)
                return
        except Exception:
            pass
        # Determine available geometry (primary screen)
        ag = None
        try:
            from PySide6.QtGui import QGuiApplication  # type: ignore
            scr = QGuiApplication.primaryScreen()
            ag = scr.availableGeometry() if scr else None
        except Exception:
            ag = None
        if ag is None:
            try:
                # Qt5 fallback
                desk = QApplication.desktop()  # type: ignore[attr-defined]
                ag = desk.availableGeometry(self)
            except Exception:
                ag = None
        if ag is None:
            return
        w, h = self.width(), self.height()
        x = ag.x() + max(0, (ag.width() - w) // 2)
        y = ag.y() + max(0, (ag.height() - h) // 2)
        try:
            self.setGeometry(x, y, w, h)
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
            self._set_tab_visible(self.output_tabs, self.disasm_container, False)
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
                self.output_tabs.setCurrentWidget(self.formats_widget)
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
            # Output: only textual disassembly (hide Shellcode tab in Analysis mode)
            self._set_tab_visible(self.output_tabs, self.formats_widget, False)
            self._set_tab_visible(self.output_tabs, self.validation_container, False)
            self._set_tab_visible(self.output_tabs, self.disasm_container, True)
            self._set_tab_visible(self.output_tabs, self.debug_widget, False)
            self._set_tab_visible(self.output_tabs, self.optimize_widget, False)
            # Keep Shell-Storm and Syscalls visible for reference
            # Syscalls visible in Analysis mode only when supported
            try:
                sys_ok = canonical_arch(self.arch_combo.currentText() or "") is not None
            except Exception:
                sys_ok = False
            self._set_tab_visible(self.output_tabs, self.syscalls_widget, bool(sys_ok))
            self._set_tab_visible(self.output_tabs, self.shellstorm_widget, True)
            try:
                self.output_tabs.setCurrentWidget(self.disasm_container)
            except Exception:
                pass
            # Hide patterns tab in analysis mode
            self._set_tab_visible(self.output_tabs, self.patterns_widget, False)
            # No Shellcode tab or its highlighters in Analysis mode
        else:
            # Show everything
            self._set_tab_visible(self.output_tabs, self.formats_widget, True)
            self._set_tab_visible(self.output_tabs, self.validation_container, True)
            self._set_tab_visible(self.output_tabs, self.disasm_container, True)
            self._set_tab_visible(self.output_tabs, self.debug_widget, True)
            self._set_tab_visible(self.output_tabs, self.optimize_widget, True)
            self._set_tab_visible(self.output_tabs, self.shellstorm_widget, True)
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
        # In Dev mode, detach any analysis-only highlighters
        if mode == "assemble":
            try:
                self._apply_shellcode_highlighters(analysis_mode=False)
            except Exception:
                pass

    def on_input_tab_changed(self, idx: int):
        # Switch toolbar mode only when Hex or Assembly tab is explicitly selected.
        # Keep current mode when the File tab is selected so it's usable in both modes.
        w = self.input_tabs.widget(idx)
        if w is self.asm_edit:
            self._update_toolbar_for_mode("assemble")
            self._set_tab_visible(self.output_tabs, self.patterns_widget, True)
            try:
                self.mode_combo.blockSignals(True)
                self.mode_combo.setCurrentIndex(0)
                self.mode_combo.blockSignals(False)
            except Exception:
                pass
        elif w is self.hex_edit:
            self._update_toolbar_for_mode("disassemble")
            self._set_tab_visible(self.output_tabs, self.patterns_widget, False)
            try:
                self.mode_combo.blockSignals(True)
                self.mode_combo.setCurrentIndex(1)
                self.mode_combo.blockSignals(False)
            except Exception:
                pass
        else:
            # File tab or other auxiliary tabs: do not change mode.
            return

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
        # Use default document margin to match Optimize panel appearance

    def _apply_inner_padding(self, edit: QPlainTextEdit, margin_px: int = 8, viewport_pad: Optional[Tuple[int, int, int, int]] = None) -> None:
        """Apply inner padding to a plain text editor using only document margin.

        Optionally adds small viewport margins to match the visual rhythm of
        the right-side panes. Keep values modest to avoid inner-border effects
        some styles render around the viewport.
        """
        try:
            if viewport_pad and len(viewport_pad) == 4:
                l, t, r, b = [max(0, int(x)) for x in viewport_pad]
                edit.setViewportMargins(l, t, r, b)
            else:
                # Default: no viewport padding
                edit.setViewportMargins(0, 0, 0, 0)
        except Exception:
            pass
        try:
            # Increase document margin slightly so text doesn't hug the frame
            doc = edit.document()
            doc.setDocumentMargin(float(max(0, margin_px)))
        except Exception:
            pass

    def _apply_hll_highlighter(self) -> None:
        # Choose lexer based on current HLL language
        try:
            lang = (self.hll_lang_combo.currentText() or "C").strip().lower()
        except Exception:
            lang = "c"
        lexer = {
            'c': 'c',
            'c stub': 'c',
            'python': 'python',
            'python stub': 'python',  # legacy label support
            'zig': 'zig',
            'rust': 'rust',
            'go': 'go',
        }.get(lang, 'text')
        try:
            if self.hll_code_hl:
                try:
                    self.hll_code_hl.setDocument(None)
                except Exception:
                    pass
            self.hll_code_hl = create_code_highlighter(self.hll_text.document(), lexer_name=lexer)
        except Exception:
            self.hll_code_hl = None

    def _on_hll_lang_changed(self) -> None:
        try:
            self._apply_hll_highlighter()
        except Exception:
            pass
        try:
            # Refresh content for the selected language
            self._update_formats(getattr(self, '_last_bytes', b"") or b"")
        except Exception:
            pass
    def _apply_shellcode_highlighters(self, analysis_mode: bool) -> None:
        """Attach/detach Qt syntax highlighters for the Shellcode output pane.

        In analysis mode, enable:
        - Inline: Python-style string highlighting (already attached at init)
        - C: C highlighter (already attached at init)
        - Python: Python highlighter (already attached at init)
        - Zig: Zig highlighter (already attached at init)
        - Hex: Bad-byte hex highlighter to emphasize problematic bytes
        Outside analysis mode, detach only the analysis-specific Hex highlighter.
        """
        # Manage bad-byte highlighters for Inline and Hex
        try:
            if analysis_mode:
                # Hex
                if self.hex_bad_hl:
                    try:
                        self.hex_bad_hl.setDocument(self.hex_text.document())
                    except Exception:
                        pass
                else:
                    try:
                        self.hex_bad_hl = HexBadByteHighlighter(self.hex_text.document())
                    except Exception:
                        self.hex_bad_hl = None
                # Inline
                if self.inline_bad_hl:
                    try:
                        self.inline_bad_hl.setDocument(self.inline_text.document())
                    except Exception:
                        pass
                else:
                    try:
                        self.inline_bad_hl = InlineBadByteHighlighter(self.inline_text.document())
                    except Exception:
                        self.inline_bad_hl = None
            else:
                if self.hex_bad_hl:
                    try:
                        self.hex_bad_hl.setDocument(None)
                    except Exception:
                        pass
                if self.inline_bad_hl:
                    try:
                        self.inline_bad_hl.setDocument(None)
                    except Exception:
                        pass
        except Exception:
            pass

    # Disassembly control helpers removed per user request; keep simple padded view

    def _sync_shellcode_padding_to_syscalls(self) -> None:
        """Match the Shellcode pane paddings (margins/spacing) to the Syscalls tab.

        Copies the first controls-row layout margins/spacing from the Syscalls panel
        when available; otherwise falls back to the Syscalls panel's main layout
        defaults. Applies to:
        - Formats grid layout (overall margins/spacing)
        - Inline/Hex header rows
        - Copy As Code header row
        """
        sys_lay = getattr(self.syscalls_widget, 'layout', lambda: None)()
        if not sys_lay:
            return
        # Prefer the first row (controls row) margins/spacing if present
        try:
            item0 = sys_lay.itemAt(0)
            row_lay = item0.layout() if item0 and item0.layout() else None
        except Exception:
            row_lay = None
        # Collect outer (panel) and inner (row) metrics
        try:
            outer_margins = sys_lay.contentsMargins()
            outer_spacing = sys_lay.spacing()
        except Exception:
            outer_margins, outer_spacing = None, None
        try:
            row_margins = row_lay.contentsMargins() if row_lay else outer_margins
            row_spacing = row_lay.spacing() if row_lay else outer_spacing
        except Exception:
            row_margins, row_spacing = outer_margins, outer_spacing
        # Apply to Formats grid
        try:
            if hasattr(self, 'formats_layout') and self.formats_layout:
                if outer_margins:
                    self.formats_layout.setContentsMargins(outer_margins.left(), outer_margins.top(), outer_margins.right(), outer_margins.bottom())
                if outer_spacing is not None:
                    self.formats_layout.setHorizontalSpacing(outer_spacing)
                    self.formats_layout.setVerticalSpacing(outer_spacing)
        except Exception:
            pass
        # Helper to apply to a header QWidget containing an HBox layout
        def _apply_header(w: QWidget) -> None:
            try:
                lay = w.layout()
                if lay is None:
                    return
                # Match Syscalls' header row margins (inner row margins)
                if row_margins:
                    lay.setContentsMargins(row_margins.left(), row_margins.top(), row_margins.right(), row_margins.bottom())
                if row_spacing is not None:
                    lay.setSpacing(row_spacing)
                # Ensure labels don't add extra padding beyond layout margins
                for i in range(lay.count()):
                    try:
                        it = lay.itemAt(i)
                        wid = it.widget()
                        if hasattr(wid, 'setMargin') and isinstance(wid, QLabel):
                            wid.setMargin(0)
                    except Exception:
                        continue
            except Exception:
                pass
        for hdr in (getattr(self, 'inline_header', None), getattr(self, 'hex_header', None), getattr(self, 'hll_header_row', None)):
            if hdr:
                _apply_header(hdr)

        # Also apply the same inner padding to editors and text areas, with an
        # additional inner text margin to create two-layer padding.
        try:
            self._sync_editors_padding_to_syscalls(row_margins or outer_margins, spacing=row_spacing or outer_spacing)
        except Exception:
            pass
        # After syncing editors, make toolbar left indent match editor text start
        try:
            self._sync_toolbar_padding_to_editors(row_margins or outer_margins)
        except Exception:
            pass

    def _sync_editors_padding_to_syscalls(self, margins, spacing: Optional[int] = None) -> None:
        """Apply two layers of padding to editors and outputs:

        - Outer: viewport margins equal to Syscalls row margins (matches pane inset)
        - Inner: document margin as a second, inner padding for the text body
        """
        try:
            if margins is None:
                # Fallback to a reasonable uniform padding
                l = t = r = b = 8
            else:
                l, t, r, b = margins.left(), margins.top(), margins.right(), margins.bottom()
            pads = (max(0, int(l)), max(0, int(t)), max(0, int(r)), max(0, int(b)))
        except Exception:
            pads = (8, 8, 8, 8)
        # Inner text padding: use row spacing if available, else a small default
        try:
            doc_pad = int(spacing) if isinstance(spacing, int) and spacing is not None else 6
            doc_pad = max(2, min(16, doc_pad))
        except Exception:
            doc_pad = 6
        for edit in (
            getattr(self, 'asm_edit', None),
            getattr(self, 'hex_edit', None),
            getattr(self, 'output_text', None),
            getattr(self, 'inline_text', None),
            getattr(self, 'hex_text', None),
            getattr(self, 'hll_text', None),
            getattr(self, 'opcode_text', None),
            getattr(self, 'debug_asm_text', None),
            getattr(self, 'validation_text', None),
        ):
            if edit is None:
                continue
            try:
                # Apply both visible outer padding and an inner document margin
                self._apply_inner_padding(edit, margin_px=doc_pad, viewport_pad=pads)
            except Exception:
                continue

    def _sync_toolbar_padding_to_editors(self, margins=None) -> None:
        """Align the toolbar's content (Mode, Arch) with the Assembly editor text.

        Achieved by adjusting a left spacer in the QToolBar to match the
        editors' left viewport margin derived from the Syscalls panel row margins.
        """
        try:
            spacer = getattr(self, '_toolbar_left_spacer', None)
            if spacer is None:
                return
            # Determine left padding from provided margins or infer a sensible default
            if margins is not None:
                try:
                    left_px = int(max(0, margins.left()))
                except Exception:
                    left_px = 8
            else:
                left_px = 8
            spacer.setFixedWidth(left_px)
        except Exception:
            pass

    def _update_shellcode_bad_highlights(self, data: bytes) -> None:
        """Update bad-byte positions for Inline and Hex highlighters from current data."""
        try:
            offs = self._compute_bad_offsets(data)
        except Exception:
            offs = set()
        # Hex
        try:
            if self.hex_bad_hl:
                self.hex_bad_hl.set_bad_offsets(offs)
        except Exception:
            pass
        # Inline
        try:
            if self.inline_bad_hl:
                self.inline_bad_hl.set_bad_offsets(offs)
        except Exception:
            pass

    def _labeled_box(self, text: str, target: Optional[QPlainTextEdit] = None) -> QWidget:
        w = QWidget()
        l = QHBoxLayout(w)
        # Use default margins/spacing to match Syscalls panel feel
        try:
            _def_h = QHBoxLayout()
            _m = _def_h.contentsMargins()
            l.setContentsMargins(_m.left(), _m.top(), _m.right(), _m.bottom())
            l.setSpacing(_def_h.spacing())
        except Exception:
            pass
        lbl = QLabel(text)
        # Label styling consistent with defaults
        try:
            if text in ("Inline", "Hex", "Copy As Code"):
                lbl.setMargin(0)
                lbl.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        except Exception:
            pass
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
        # Let the header row use default height for consistency with Optimize tab
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
            try:
                self._flash_copied(copy_btn)
            except Exception:
                pass
        copy_btn.clicked.connect(do_copy)
        return w

    def _flash_copied(self, btn: QPushButton, timeout_ms: int = 1200) -> None:
        """Temporarily show green "OK" on a copy button to indicate success."""
        try:
            prev_text = btn.text()
        except Exception:
            prev_text = "Copy"
        try:
            prev_style = btn.styleSheet()
        except Exception:
            prev_style = ""
        try:
            # Use theme-derived green like Optimize tab
            try:
                good_col, _bad = self._theme_accent_colors()
                ok_color = good_col.name() if hasattr(good_col, 'name') else None
            except Exception:
                ok_color = None
            # Change label to OK and set text color to green
            try:
                btn.setText("OK")
            except Exception:
                pass
            if ok_color:
                btn.setStyleSheet(f"QPushButton {{ color: {ok_color}; }}")
            else:
                # Fallback to palette(Link) if no accent
                try:
                    pal = QApplication.instance().palette()
                    ok_color = pal.color(QPalette.Highlight).name()
                    btn.setStyleSheet(f"QPushButton {{ color: {ok_color}; }}")
                except Exception:
                    pass
            # Do not disable to avoid theme changing button background
        except Exception:
            pass
        try:
            QTimer.singleShot(max(200, int(timeout_ms)), lambda: self._restore_copy_btn(btn, prev_text, prev_style))
        except Exception:
            # Immediate restore if timer fails
            self._restore_copy_btn(btn, prev_text, prev_style)

    def _restore_copy_btn(self, btn: QPushButton, text: str = "Copy", style: str = "") -> None:
        try:
            btn.setText(text)
            btn.setStyleSheet(style or "")
            btn.setEnabled(True)
        except Exception:
            pass

    def _send_disassembly_to_dev(self) -> None:
        """Send current Disassembly view text to the Assembly editor and switch to Dev mode."""
        try:
            asm_text = (self.output_text.toPlainText() or "").strip()
        except Exception:
            asm_text = ""
        try:
            if asm_text:
                self.asm_edit.setPlainText(asm_text)
        except Exception:
            pass
        # Switch mode combo to Dev (index 0) and focus Assembly editor
        try:
            self.mode_combo.setCurrentIndex(0)
        except Exception:
            pass
        try:
            self.input_tabs.setCurrentWidget(self.asm_edit)
            self.asm_edit.setFocus()
        except Exception:
            pass

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
        null_cnt = count_nulls(raw)
        # Match Debug tab highlights exactly (enabled patterns + toggle)
        try:
            bad_offs = self._compute_bad_offsets(raw)
        except Exception:
            bad_offs = set()
        bad_count = len(bad_offs)
        self.status_bad.setText(f"Bad Chars: {bad_count}")
        # Colorize status based on presence of bad chars/nulls using shared theme colors.
        try:
            good_col, bad_col = _good_bad_colors()
            def set_label_color(lbl, good: bool):
                col = good_col if good else bad_col
                # stylesheet is simplest and works across Qt5/Qt6
                try:
                    lbl.setStyleSheet(f"QLabel {{ color: {col.name()}; }}")
                except Exception:
                    # Fallback: palette
                    pal = lbl.palette()
                    pal.setColor(QPalette.WindowText, col)
                    lbl.setPalette(pal)
            # Green when zero, red when non-zero
            set_label_color(self.status_bad, bad_count == 0)
        except Exception:
            pass

    def _status_palette_colors(self) -> tuple:
        """Return (good_color, bad_color) from the active Qt palette only.

        - good_color: prefer `QPalette.Highlight`, fallback `QPalette.Link`.
        - bad_color: prefer `QPalette.BrightText`. If it matches `QPalette.Text`,
          derive a darker variant from `QPalette.Link` to stay within palette.
        """
        try:
            pal = QApplication.instance().palette()
        except Exception:
            pal = None
        good = QColor()
        bad = QColor()
        if pal is not None:
            try:
                good = pal.color(QPalette.Highlight)
                if not good.isValid():
                    good = pal.color(QPalette.Link)
            except Exception:
                pass
            try:
                bad = pal.color(QPalette.BrightText)
                # If BrightText is not distinct or invalid, derive from Link
                if (not bad.isValid()) or (bad == pal.color(QPalette.Text)):
                    alt = pal.color(QPalette.Link)
                    bad = QColor(alt).darker(150) if alt.isValid() else pal.color(QPalette.Text)
            except Exception:
                pass
        # Final fallbacks if palette is unavailable
        if not good.isValid():
            good = QColor(Qt.green) if 'Qt' in globals() else QColor('#00aa00')
        if not bad.isValid():
            bad = QColor(Qt.red) if 'Qt' in globals() else QColor('#cc3333')
        return (good, bad)

    def _bad_byte_offsets_for_status(self, data: bytes) -> set:
        """Compute a set of byte offsets that are considered 'bad' for status purposes.

        - Excludes null bytes patterns (counted separately).
        - For sequence patterns, counts every byte of each match span.
        - For regex patterns, counts the start byte of each match (length unknown).
        """
        offs = set()
        try:
            pmatches = self.bpm.match_patterns(data)
        except Exception:
            pmatches = []
        for m in pmatches:
            # Skip explicit null-byte single hex pattern
            if m.pattern.type == 'hex' and m.pattern.value.strip().lower() in ('00', '0x00'):
                continue
            if m.pattern.type == 'hex':
                for o in m.offsets:
                    offs.add(int(o))
            elif m.pattern.type == 'sequence':
                try:
                    seq = self.bpm._parse_sequence(m.pattern.value)  # type: ignore[attr-defined]
                except Exception:
                    seq = None
                seqlen = len(seq) if seq else 0
                for o in m.offsets:
                    if seqlen > 0:
                        for k in range(seqlen):
                            offs.add(int(o) + k)
                    else:
                        offs.add(int(o))
            else:  # regex
                for o in m.offsets:
                    offs.add(int(o))
        return offs

    def _set_optimize_bad_indicator(self, has_bad: bool, bad_color: QColor | None = None) -> None:
        """Color the Debug tab text using the theme's bad color when bad bytes exist.

        Removes any previously-set icon/bullet and updates only the Debug tab label color.
        """
        try:
            idx = self.output_tabs.indexOf(self.debug_widget)
        except Exception:
            idx = -1
        if idx < 0:
            return
        # Clear any previous icon or legacy bullet prefix
        try:
            self.output_tabs.setTabIcon(idx, QIcon())
        except Exception:
            pass
        try:
            txt = self.output_tabs.tabText(idx)
            if txt.startswith('• '):
                self.output_tabs.setTabText(idx, txt[2:])
        except Exception:
            pass

        # Determine colors
        try:
            if bad_color is None:
                _g, bad_color = _good_bad_colors()
        except Exception:
            bad_color = QColor(200, 60, 60)
        try:
            tb = self.output_tabs.tabBar()
            pal = tb.palette() if hasattr(tb, 'palette') else None
            # Default tab text color from palette
            default_col = QColor()
            if pal is not None:
                try:
                    # Prefer ButtonText/Text as common roles for tab text
                    default_col = pal.color(QPalette.ButtonText)
                    if not default_col.isValid():
                        default_col = pal.color(QPalette.Text)
                except Exception:
                    pass
            if not default_col.isValid():
                default_col = QColor(0, 0, 0)

            # Apply per-tab text color if available
            if hasattr(tb, 'setTabTextColor'):
                try:
                    tb.setTabTextColor(idx, bad_color if has_bad else default_col)
                except Exception:
                    pass
        except Exception:
            pass

    # Actions
    def on_clear(self):
        self.hex_edit.clear()
        self.asm_edit.clear()
        self.output_text.clear()
        self.inline_text.clear()
        self.hex_text.clear()
        try:
            self.hll_text.clear()
        except Exception:
            pass
        self.status_len.setText("len: 0")
        # Reset status colors to default palette
        try:
            for lbl in (self.status_bad,):
                lbl.setStyleSheet("")
        except Exception:
            pass

    def on_disassemble(self):
        # Auto-strip trailing blank lines from Hex editor before parsing
        try:
            self._strip_editor_blank_lines(self.hex_edit)
        except Exception:
            pass
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
        # No control bar: nothing to reset
        # Show only hex editor + disassembly output
        self._set_mode("disassemble")
        # Decompile tab removed

    def on_assemble(self):
        # Auto-strip trailing blank lines from Assembly editor before assembling
        try:
            self._strip_editor_blank_lines(self.asm_edit)
        except Exception:
            pass
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
        # High-level language output based on selection
        try:
            lang = (self.hll_lang_combo.currentText() or "C").strip().lower()
        except Exception:
            lang = "c"
        if lang == 'c' or lang == 'c stub':  # accept legacy label
            self.hll_text.setPlainText(bytes_to_c_stub(data, var_name="shellcode"))
        elif lang == 'python':
            self.hll_text.setPlainText(bytes_to_python_stub(data, var_name="shellcode"))
        elif lang == 'zig':
            self.hll_text.setPlainText(bytes_to_zig_stub(data, var_name="shellcode"))
        elif lang == 'rust':
            # Prefer the concise RW->RX mmap+mprotect Rust stub with static array name 'S'
            self.hll_text.setPlainText(bytes_to_rust_stub(data, var_name="S"))
        elif lang == 'go':
            self.hll_text.setPlainText(bytes_to_go_stub(data, var_name="shellcode"))
        else:
            self.hll_text.setPlainText("")
        try:
            self._apply_hll_highlighter()
        except Exception:
            pass
        # Refresh bad-byte highlights for Inline/Hex when available
        try:
            self._update_shellcode_bad_highlights(data)
        except Exception:
            pass

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

    def _null_pattern_enabled(self) -> bool:
        try:
            for p in getattr(self.bpm, 'patterns', []) or []:
                try:
                    v = (p.value or "").strip().lower()
                    if v.startswith('0x'):
                        v = v[2:]
                    if p.type == 'hex' and v == '00' and bool(getattr(p, 'enabled', True)):
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        return False

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
        # Update Debug tab label color live based on highlight presence
        try:
            _g, bad_col = _good_bad_colors()
        except Exception:
            bad_col = QColor(200, 60, 60)
        try:
            self._set_optimize_bad_indicator(bool(bad), bad_col)
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
            # Keep status bar indicator in sync with Debug highlights
            self._update_stats(data)

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
        # Recreate token highlighters for current architecture
        arch = self.arch_combo.currentText() or "x86_64"
        # Output disassembly
        try:
            if self.disasm_highlighter:
                try:
                    self.disasm_highlighter.setDocument(None)
                except Exception:
                    pass
            self.disasm_highlighter = create_disassembly_highlighter(self.output_text.document(), arch_name=arch)
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
            self.debug_asm_token_hl = create_disassembly_highlighter(self.debug_asm_text.document(), arch_name=arch)
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
            self.asm_highlighter = create_disassembly_highlighter(self.asm_edit.document(), arch_name=arch)
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
        # Output tab code highlighters (Qt-only, no style changes needed)
        try:
            if hasattr(self, 'inline_code_hl') and self.inline_code_hl:
                try:
                    self.inline_code_hl.setDocument(None)
                except Exception:
                    pass
            self.inline_code_hl = create_code_highlighter(self.inline_text.document(), lexer_name="python")
        except Exception:
            self.inline_code_hl = None
        try:
            if hasattr(self, 'hll_code_hl') and self.hll_code_hl:
                try:
                    self.hll_code_hl.setDocument(None)
                except Exception:
                    pass
            self._apply_hll_highlighter()
        except Exception:
            self.hll_code_hl = None

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
        # Clear File tab data when switching modes (do not carry over files)
        try:
            if hasattr(self, 'file_tab') and self.file_tab:
                self.file_tab.clear_for_mode()
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
                    self.output_tabs.setCurrentWidget(self.disasm_container)
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
