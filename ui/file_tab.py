from __future__ import annotations

from typing import Callable, Optional, Tuple
import os
import sys

# Qt compatibility: prefer PySide6, fallback to PySide2
try:
    from PySide6.QtCore import Qt, QSize  # type: ignore
    from PySide6.QtGui import (
        QDragEnterEvent,
        QDropEvent,
        QPalette,
        QPainter,
        QPen,
        QColor,
        QKeySequence,
        QShortcut,
    )  # type: ignore
    from PySide6.QtWidgets import (  # type: ignore
        QWidget,
        QVBoxLayout,
        QLabel,
        QPushButton,
        QFileDialog,
        QHBoxLayout,
        QFrame,
        QSizePolicy,
        QApplication,
        QScrollArea,
        QFormLayout,
        QTableWidget,
        QTableWidgetItem,
    )
except Exception:
    from PySide2.QtCore import Qt, QSize  # type: ignore
    from PySide2.QtGui import (
        QDragEnterEvent,
        QDropEvent,
        QPalette,
        QPainter,
        QPen,
        QColor,
        QKeySequence,
    )  # type: ignore
    from PySide2.QtWidgets import (  # type: ignore
        QWidget,
        QVBoxLayout,
        QLabel,
        QPushButton,
        QFileDialog,
        QHBoxLayout,
        QFrame,
        QApplication,
        QScrollArea,
        QShortcut,
        QFormLayout,
        QTableWidget,
        QTableWidgetItem,
    )


class FileDropTab(QWidget):
    """A simple drag-and-drop tab to load files into the IDE.

    Behavior:
    - If dropped/opened file looks like assembly text (by extension or heuristic),
      calls `on_asm(str)` callback with its contents and focuses Assembly mode.
    - Otherwise treats it as raw bytes and calls `on_hex(bytes)`.
    """

    def __init__(
        self,
        on_hex: Callable[[bytes], None],
        on_asm: Callable[[str], None],
        parent: Optional[QWidget] = None,
        mode_provider: Optional[Callable[[], str]] = None,
    ) -> None:
        super().__init__(parent)
        self._on_hex = on_hex
        self._on_asm = on_asm
        # Optional callback to query IDE mode (e.g., 'dev' or 'analysis')
        self._get_mode = mode_provider

        self.setAcceptDrops(True)
        try:
            self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        except Exception:
            pass
        self._last_path: Optional[str] = None
        self._last_bytes: Optional[bytes] = None
        self._last_text: Optional[str] = None

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(8)

        # Header removed; the drop zone is now also clickable to open files

        # Top controls row (Clear only - moved Copy to Info section)
        mode_row = QHBoxLayout()
        mode_row.addStretch(1)
        self.btn_clear = QPushButton("Clear")
        self.btn_clear.clicked.connect(self._clear_preview)
        mode_row.addWidget(self.btn_clear)
        root.addLayout(mode_row)
        # Apply mode restrictions (no controls shown here)
        try:
            self._enforce_analysis_restrictions()
        except Exception:
            pass

        # Keyboard shortcuts
        try:
            _sc_copy = QShortcut(QKeySequence("Ctrl+Shift+C" if os.name == 'nt' else "Meta+Shift+C"), self)
            _sc_copy.activated.connect(self._copy_info)
        except Exception:
            pass

        # Drop zone with clean rounded border and subtle background
        self.drop_zone = DropZoneFrame(self, on_click=self._open_dialog)
        try:
            self.drop_zone.setMinimumHeight(120)
        except Exception:
            pass
        # Apply initial non-hover style
        try:
            self._apply_dropzone_style(hover=False)
        except Exception:
            # Fallback constant styling
            self.drop_zone.setStyleSheet(
                "QFrame { border: 2px dashed #888; border-radius: 8px; background: rgba(136,136,136,20); }"
            )

        dz_layout = QVBoxLayout(self.drop_zone)
        dz_layout.setContentsMargins(24, 24, 24, 24)
        dz_layout.setSpacing(6)
        self.drop_text = QLabel("📁 Drop file or click to browse")
        try:
            self.drop_text.setAlignment(Qt.AlignCenter)
            self.drop_text.setWordWrap(True)
            self.drop_text.setStyleSheet("border: none; background: transparent;")
        except Exception:
            pass
        dz_layout.addWidget(self.drop_text)
        # self.hint_text = QLabel("Auto-detect assembly vs bytes; override with Import as.")
        # try:
        #     self.hint_text.setAlignment(Qt.AlignCenter)
        #     self.hint_text.setStyleSheet("color: palette(mid);")
        #     self.hint_text.setWordWrap(True)
        # except Exception:
        #     pass
        # dz_layout.addWidget(self.hint_text)
        root.addWidget(self.drop_zone, 0)

        # (Removed top summary row in favor of unified Details below)
        self.info_name = ElideLabel("—")
        self.info_size = QLabel("—")
        self.info_detect = QLabel("—")

        # Header for Info list
        info_header = QHBoxLayout()
        info_title = QLabel("File Information")
        try:
            info_title.setStyleSheet("font-weight: bold;")
        except Exception:
            pass
        info_header.addWidget(info_title)
        info_header.addStretch(1)
        self.btn_copy_info = QPushButton("Copy All")
        try:
            self.btn_copy_info.setStyleSheet("padding: 4px 8px;")
        except Exception:
            pass
        # Access main window flash helper if available for consistent OK color
        try:
            from .main_window import ShellcodeIDEWindow  # type: ignore
            _flash_ok_colored = lambda: getattr(self.parent(), '_flash_copied', None) and self.parent()._flash_copied(self.btn_copy_info, 800)
        except Exception:
            _flash_ok_colored = None
        self.btn_copy_info.clicked.connect(self._copy_info)
        # Flash OK feedback on copy
        def _flash_ok(btn: QPushButton):
            try:
                old = btn.text()
                btn.setText("OK")
                from PySide6.QtCore import QTimer as _T
                _T.singleShot(600, lambda: btn.setText(old))
            except Exception:
                try:
                    from PySide2.QtCore import QTimer as _T
                    _T.singleShot(600, lambda: btn.setText(old))
                except Exception:
                    pass
        try:
            if _flash_ok_colored:
                self.btn_copy_info.clicked.connect(lambda: _flash_ok_colored())
            else:
                self.btn_copy_info.clicked.connect(lambda: _flash_ok(self.btn_copy_info))
        except Exception:
            pass

        info_header.addWidget(self.btn_copy_info)
        root.addLayout(info_header)

        # Info displayed as a table (like Syscall tab)
        self.info_table = QTableWidget(0, 2)
        try:
            self.info_table.setHorizontalHeaderLabels(["Field", "Value"])
            self.info_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            self.info_table.setAlternatingRowColors(True)
            self.info_table.setWordWrap(False)
            self.info_table.verticalHeader().setVisible(False)
            self.info_table.setContextMenuPolicy(Qt.CustomContextMenu)
            self.info_table.customContextMenuRequested.connect(self._on_info_context_menu)
        except Exception:
            pass
        # Map attribute name -> row index
        # Match Syscall table behavior: select whole rows and auto-size columns
        try:
            self.info_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        except Exception:
            pass
        # Header resize like Syscall tab
        try:
            from PySide6.QtWidgets import QHeaderView as _HV  # type: ignore
        except Exception:
            try:
                from PySide2.QtWidgets import QHeaderView as _HV  # type: ignore
            except Exception:
                _HV = None  # type: ignore
        if _HV:
            try:
                hh = self.info_table.horizontalHeader()
                try:
                    hh.setSectionResizeMode(0, _HV.ResizeToContents)  # type: ignore
                    hh.setSectionResizeMode(1, _HV.Stretch)  # type: ignore
                except Exception:
                    # Fallback: stretch last section
                    try:
                        hh.setStretchLastSection(True)
                    except Exception:
                        pass
                else:
                    try:
                        hh.setStretchLastSection(True)
                    except Exception:
                        pass
            except Exception:
                pass

        self._info_row_index = {}

        def _add_row(title: str, attr: str) -> None:
            r = self.info_table.rowCount()
            self.info_table.insertRow(r)
            self.info_table.setItem(r, 0, QTableWidgetItem(title.rstrip(':')))
            self.info_table.setItem(r, 1, QTableWidgetItem("—"))
            self._info_row_index[attr] = r

        # Define rows
        _add_row("File:", "file")
        _add_row("Size:", "size")
        _add_row("MD5:", "md5")
        _add_row("SHA-256:", "sha256")
        _add_row("Encoding:", "encoding")
        _add_row("Lines:", "lines")
        _add_row("Created:", "created")
        _add_row("Modified:", "mtime")

        # Create lightweight proxies so existing code (lbl_*) keeps working
        class _TableValueProxy:
            def __init__(self, table: QTableWidget, row: int) -> None:
                self._t = table
                self._r = row
            def setText(self, text: str) -> None:
                it = self._t.item(self._r, 1)
                if it is None:
                    it = QTableWidgetItem()
                    self._t.setItem(self._r, 1, it)
                it.setText(text)
            def setToolTip(self, tip: str) -> None:
                it = self._t.item(self._r, 1)
                if it:
                    it.setToolTip(tip)

        self.lbl_file = _TableValueProxy(self.info_table, self._info_row_index["file"])  # type: ignore[attr-defined]
        self.lbl_size = _TableValueProxy(self.info_table, self._info_row_index["size"])  # type: ignore[attr-defined]
        self.lbl_encoding = _TableValueProxy(self.info_table, self._info_row_index["encoding"])  # type: ignore[attr-defined]
        self.lbl_lines = _TableValueProxy(self.info_table, self._info_row_index["lines"])  # type: ignore[attr-defined]
        self.lbl_md5 = _TableValueProxy(self.info_table, self._info_row_index["md5"])  # type: ignore[attr-defined]
        self.lbl_sha256 = _TableValueProxy(self.info_table, self._info_row_index["sha256"])  # type: ignore[attr-defined]
        self.lbl_created = _TableValueProxy(self.info_table, self._info_row_index["created"])  # type: ignore[attr-defined]
        self.lbl_mtime = _TableValueProxy(self.info_table, self._info_row_index["mtime"])  # type: ignore[attr-defined]

        # Click-to-copy behavior
        try:
            self.info_table.cellClicked.connect(self._on_info_cell_clicked)
        except Exception:
            pass

        # modest height; matches recent box style
        info_scroll = QScrollArea()
        try:
            info_scroll.setWidgetResizable(True)
            info_scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        except Exception:
            pass
        info_scroll.setFrameShape(QFrame.NoFrame)
        info_scroll.setWidget(self.info_table)
        try:
            info_scroll.setMaximumHeight(200)
            info_scroll.setMinimumHeight(180)
        except Exception:
            pass
        root.addWidget(info_scroll)

        # Recent files table header
        recent_header = QHBoxLayout()
        recent_title = QLabel("Recent Files")
        try:
            recent_title.setStyleSheet("font-weight: bold; margin-top: 4px;")
        except Exception:
            pass
        recent_header.addWidget(recent_title)
        recent_header.addStretch(1)
        root.addLayout(recent_header)

        # Recent files table (like Syscall tab)
        self.recent_table = QTableWidget(0, 1)
        try:
            # Hide header labels for a clean list look
            self.recent_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            self.recent_table.setAlternatingRowColors(True)
            self.recent_table.setWordWrap(False)
            self.recent_table.verticalHeader().setVisible(False)
            self.recent_table.horizontalHeader().setVisible(False)
            self.recent_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        except Exception:
            pass
        # Header: stretch the single column to fill width
        try:
            from PySide6.QtWidgets import QHeaderView as _HV2  # type: ignore
        except Exception:
            try:
                from PySide2.QtWidgets import QHeaderView as _HV2  # type: ignore
            except Exception:
                _HV2 = None  # type: ignore
        if _HV2:
            try:
                hh2 = self.recent_table.horizontalHeader()
                hh2.setSectionResizeMode(0, _HV2.Stretch)  # type: ignore
            except Exception:
                try:
                    self.recent_table.horizontalHeader().setStretchLastSection(True)
                except Exception:
                    pass
        # Interactions: double-click open, context menu
        try:
            self.recent_table.cellDoubleClicked.connect(lambda r, _c: self._open_recent_row(r))
            self.recent_table.setContextMenuPolicy(Qt.CustomContextMenu)
            self.recent_table.customContextMenuRequested.connect(self._on_recent_context_menu)
        except Exception:
            pass
        try:
            self.recent_table.setMaximumHeight(200)
        except Exception:
            pass
        root.addWidget(self.recent_table, 1)

        # Load recents from config
        try:
            self._recents = self._load_recents()
            self._refresh_recent_ui()
        except Exception:
            self._recents = []

    def sizeHint(self):  # type: ignore[override]
        try:
            return QSize(520, 420)
        except Exception:
            return super().sizeHint()

    def minimumSizeHint(self):  # type: ignore[override]
        try:
            return QSize(360, 300)
        except Exception:
            return super().minimumSizeHint()

    # Drag and drop events
    def dragEnterEvent(self, e: QDragEnterEvent) -> None:  # noqa: N802
        if e.mimeData() and e.mimeData().hasUrls():
            e.acceptProposedAction()
            try:
                self._apply_dropzone_style(hover=True)
            except Exception:
                pass
        else:
            e.ignore()

    def dragLeaveEvent(self, _e) -> None:  # noqa: N802
        self._reset_border()

    def dropEvent(self, e: QDropEvent) -> None:  # noqa: N802
        self._reset_border()
        urls = e.mimeData().urls() if e.mimeData() else []
        if not urls:
            return
        # Use the first file only
        local = urls[0].toLocalFile()
        if not local:
            return
        self._load_path(local, trigger_import=True)

    def _reset_border(self) -> None:
        try:
            # Re-apply the default non-hover style
            self._apply_dropzone_style(hover=False)
        except Exception:
            self.drop_zone.setStyleSheet("QFrame { border: 2px dashed #888; border-radius: 8px; background: rgba(136,136,136,20); }")

    # Open file dialog
    def _open_dialog(self) -> None:
        # Restrict file types by mode: Analysis=bytes only, Dev=assembly only
        if self._in_analysis_mode():
            filters = "Binary (*.bin *.raw);;All Files (*)"
        else:
            filters = "Assembly (*.s *.S *.asm *.txt);;All Files (*)"
        start_dir = self._last_dir_from_config()
        path, _ = QFileDialog.getOpenFileName(self, "Open File", start_dir, filters)
        if path:
            self._save_last_dir_to_config(path)
            self._load_path(path, trigger_import=True)

    # Load and route file content
    def _load_path(self, path: str, trigger_import: bool = False) -> None:
        # Heuristic: treat as assembly if extension looks like asm or decoded text looks assembly-like
        lower = path.lower()
        as_asm_ext = lower.endswith((".s", ".asm", ".S", ".txt"))
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:  # pragma: no cover - UI error path
            self._show_error(f"Failed to read file: {e}")
            return

        self._last_path = path
        self._last_bytes = bytes(data)
        self._last_text = None

        text: Optional[str] = None
        try:
            text_try = data.decode("utf-8", errors="strict")
        except Exception:
            text_try = None
        # Detect text that is either assembly or hex-like
        detected_kind = "bytes"
        if text_try:
            text = text_try
            if self._looks_like_assembly(text_try):
                detected_kind = "assembly"
            else:
                # Try hex parsing
                parsed = self._try_parse_hex(text_try)
                if parsed is not None and len(parsed) > 0:
                    self._last_bytes = parsed
                    detected_kind = "bytes"
        elif as_asm_ext:
            # No strict decode but extension hints assembly; best-effort decode
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = None
            detected_kind = "assembly"  # hint

        # Persist last decoded text for auto-import decision
        self._last_text = text
        # If analysis mode forbids assembly, keep detected type but UI will block on import
        self._update_info(path, len(self._last_bytes or b""), detected_kind)
        self._update_details(path, text, self._last_bytes)

        if trigger_import:
            self._import_current()
        # Update recents
        try:
            self._add_recent(path)
        except Exception:
            pass

    def _looks_like_assembly(self, s: str) -> bool:
        # Simple heuristic: contains common mnemonics and line breaks and no long NUL runs
        lowered = s.lower()
        has_lines = ("\n" in s) or ("\r" in s)
        mnemonic_hits = 0
        for kw in (
            "mov", "push", "pop", "xor", "add", "sub", "call", "jmp", "int", "syscall",
            "ldr", "str", "stp", "ldp", "bl", "b ",
        ):
            if kw in lowered:
                mnemonic_hits += 1
                if mnemonic_hits >= 2:
                    break
        return has_lines and mnemonic_hits >= 2

    def _try_parse_hex(self, s: str) -> Optional[bytes]:
        try:
            from ..utils.hexbytes import parse_hex_input  # type: ignore
        except Exception:
            return None
        try:
            return parse_hex_input(s)
        except Exception:
            return None

    def _current_mode(self) -> str:
        # Radio controls removed; always auto-detect
        return "auto"

    def _import_current(self) -> None:
        if not (self._last_bytes or self._last_text or self._last_path):
            return
        mode = self._current_mode()
        # Compute final decision
        final_kind = "bytes"
        text = self._last_text
        data = self._last_bytes or b""
        if mode == "assembly":
            # decode best-effort
            if text is None:
                try:
                    text = data.decode("utf-8", errors="replace")
                except Exception:
                    text = ""
            final_kind = "assembly"
        elif mode == "bytes":
            final_kind = "bytes"
        else:
            # auto
            if text is not None and self._looks_like_assembly(text):
                final_kind = "assembly"
            else:
                # try hex text to bytes conversion
                if text is not None:
                    parsed = self._try_parse_hex(text)
                    if parsed is not None and len(parsed) > 0:
                        data = parsed
                final_kind = "bytes"

        # Enforce mode restrictions:
        # - Analysis mode: only bytes allowed
        # - Dev mode: only assembly allowed
        if self._in_analysis_mode() and final_kind == "assembly":
            self._show_error("Analysis mode accepts bytes only. Switch to Dev for assembly.")
            # Also ensure UI selection reflects restriction
            try:
                self._enforce_analysis_restrictions()
            except Exception:
                pass
            return
        if not self._in_analysis_mode() and final_kind != "assembly":
            self._show_error("Dev mode accepts assembly only. Switch to Analysis for bytes.")
            try:
                self._enforce_analysis_restrictions()
            except Exception:
                pass
            return

        if final_kind == "assembly":
            self._on_asm(text or "")
            try:
                # Show filename only, not full path
                full = self._last_path or "(clipboard)"
                name = os.path.basename(full)
                self._show_status_message(f"{name} is opened in Assembly view")
            except Exception:
                pass
        else:
            self._on_hex(data)
            try:
                full = self._last_path or "(clipboard)"
                name = os.path.basename(full)
                self._show_status_message(f"{name} is opened in Analysis view")
            except Exception:
                pass

    def _in_analysis_mode(self) -> bool:
        try:
            mode = (self._get_mode() if callable(self._get_mode) else "").strip().lower()
        except Exception:
            mode = ""
        return mode.startswith("analysis") or mode.startswith("disassemble")

    def _enforce_analysis_restrictions(self) -> None:
        """Enforce allowed import kinds based on IDE mode.

        - Analysis mode: bytes only (disable Asm)
        - Dev mode: assembly only (disable Bytes)
        """
        # No UI controls to toggle; this method remains for future extension
        return

    def reload_for_mode(self) -> None:
        """Re-apply mode restrictions and re-import the currently loaded file, if any."""
        try:
            self._enforce_analysis_restrictions()
        except Exception:
            pass
        # Re-import current content to route to the correct destination for this mode
        try:
            if self._last_bytes is not None or self._last_text is not None or self._last_path is not None:
                self._import_current()
        except Exception:
            pass

    def clear_for_mode(self) -> None:
        """Clear any loaded file preview/data when the host mode changes."""
        try:
            self._enforce_analysis_restrictions()
        except Exception:
            pass
        try:
            self._clear_preview()
        except Exception:
            pass
        # Reset drop zone message/style if it showed an Analysis-only warning
        try:
            self._reset_drop_message()
        except Exception:
            pass

    def _clear_preview(self) -> None:
        self._last_path = None
        self._last_bytes = None
        self._last_text = None
        self.info_name.setText("File: —")
        self.info_size.setText("Size: —")
        self.info_detect.setText("—")
        try:
            # Reset all table values to "—"
            for row in range(self.info_table.rowCount()):
                val_item = self.info_table.item(row, 1)
                if val_item:
                    val_item.setText("—")
        except Exception:
            pass
        # Restore original drop message and style
        try:
            self._reset_drop_message()
        except Exception:
            pass


    def _update_info(self, path: str, size: int, detected: str) -> None:
        try:
            self.info_name.set_full_text(path)
            self.info_name.setToolTip(path)
        except Exception:
            self.info_name.setText(path)
        self.info_size.setText(f"{size} B")
        self.info_detect.setText("assembly" if detected == "assembly" else "bytes")

    def _update_details(self, path: Optional[str], text: Optional[str], data: Optional[bytes]) -> None:
        # File path (shown from home with ~ when applicable) and size
        try:
            disp = self._display_path(path) if path else "(clipboard)"
            self.lbl_file.setText(disp)
            if path:
                self.lbl_file.setToolTip(path)
        except Exception:
            pass
        buf = data or b""
        try:
            self.lbl_size.setText(f"{len(buf)} B")
        except Exception:
            self.lbl_size.setText("—")
        # Encoding and lines
        if text is not None:
            enc = "utf-8"
            try:
                text.encode("utf-8")
            except Exception:
                enc = "text"
            self.lbl_encoding.setText(enc)
            try:
                self.lbl_lines.setText(str(len(text.splitlines())))
            except Exception:
                self.lbl_lines.setText("—")
        else:
            self.lbl_encoding.setText("—")
            self.lbl_lines.setText("—")
        # Hashes
        try:
            import hashlib as _hl
            self.lbl_md5.setText(_hl.md5(buf).hexdigest())
            self.lbl_sha256.setText(_hl.sha256(buf).hexdigest())
        except Exception:
            self.lbl_md5.setText("—")
            self.lbl_sha256.setText("—")
        # Created / Modified time
        try:
            if path:
                st = os.stat(path)
                from datetime import datetime as _dt
                # Modified time
                self.lbl_mtime.setText(_dt.fromtimestamp(getattr(st, 'st_mtime', 0)).strftime("%Y-%m-%d %H:%M:%S"))
                # Created time: prefer st_birthtime when available (macOS); on Windows fall back to getctime
                created_ts = getattr(st, 'st_birthtime', None)
                if created_ts is None:
                    if sys.platform.startswith('win'):
                        try:
                            created_ts = os.path.getctime(path)
                        except Exception:
                            created_ts = None
                if created_ts:
                    self.lbl_created.setText(_dt.fromtimestamp(created_ts).strftime("%Y-%m-%d %H:%M:%S"))
                else:
                    self.lbl_created.setText("—")
            else:
                self.lbl_mtime.setText("—")
                self.lbl_created.setText("—")
        except Exception:
            self.lbl_mtime.setText("—")
            try:
                self.lbl_created.setText("—")
            except Exception:
                pass

    def _on_info_cell_clicked(self, row: int, col: int) -> None:
        """Copy the value (column 1) of the clicked row to clipboard."""
        try:
            # Always copy from the value column (column 1)
            val_item = self.info_table.item(row, 1)
            if val_item:
                txt = val_item.text()
                if txt and txt != "—":
                    QApplication.clipboard().setText(txt)
                    # Visual feedback
                    try:
                        from PySide6.QtCore import QTimer
                        orig_bg = val_item.background()
                        val_item.setBackground(self.palette().color(QPalette.Highlight))
                        QTimer.singleShot(200, lambda: val_item.setBackground(orig_bg))
                    except Exception:
                        try:
                            from PySide2.QtCore import QTimer
                            orig_bg = val_item.background()
                            val_item.setBackground(self.palette().color(QPalette.Highlight))
                            QTimer.singleShot(200, lambda: val_item.setBackground(orig_bg))
                        except Exception:
                            pass
        except Exception:
            pass

    def _show_status_message(self, msg: str) -> None:
        try:
            self.drop_text.setText(msg)
            self.drop_text.setStyleSheet("border: none; background: transparent; color: palette(windowText);")
            try:
                self._apply_dropzone_style(hover=True)
            except Exception:
                pass
        except Exception:
            pass




    def _display_path(self, path: Optional[str]) -> str:
        """Return a display path starting from the user's home directory.
    def _show_status_message(self, msg: str) -> None:
        try:
            self.drop_text.setText(msg)
            self.drop_text.setStyleSheet("border: none; background: transparent; color: palette(windowText);")
            # Light hover background to draw attention
            try:
                self._apply_dropzone_style(hover=True)
            except Exception:
                pass
        except Exception:
            pass


        If the path is under the home directory, replace that prefix with '~'.
        Otherwise, return the original path.
        """
        try:
            if not path:
                return ""
            home = os.path.expanduser("~")
            # Normalize for comparison
            p_norm = os.path.realpath(path)
            h_norm = os.path.realpath(home)
            if p_norm.startswith(h_norm + os.sep) or p_norm == h_norm:
                rel = os.path.relpath(p_norm, h_norm)
                return f"~/{rel}" if rel != "." else "~"
            return path
        except Exception:
            return path or ""

    def _is_printable_text(self, s: str) -> bool:
        # Heuristic: most chars printable and contains newlines
        if not s:
            return False
        printable = sum(1 for ch in s if (" " <= ch <= "~") or ch in "\n\r\t")
        return (printable / max(1, len(s))) > 0.9 and ("\n" in s or "\r" in s)

    def _on_info_context_menu(self, pos) -> None:
        try:
            idx = self.info_table.indexAt(pos)
            if not idx.isValid():
                return
            row = idx.row()
            val_item = self.info_table.item(row, 1)
            key_item = self.info_table.item(row, 0)
            if not val_item:
                return
            val = val_item.text() or ""
            key = key_item.text() if key_item else ""
            # Build menu
            try:
                from PySide6.QtWidgets import QMenu as _Menu  # type: ignore
            except Exception:
                try:
                    from PySide2.QtWidgets import QMenu as _Menu  # type: ignore
                except Exception:
                    _Menu = None
            if not _Menu:
                return
            menu = _Menu(self)
            act_copy_val = menu.addAction("Copy Value")
            act_copy_key = menu.addAction("Copy Field Name")
            act_copy_both = menu.addAction("Copy 'Field: Value'")
            act = menu.exec(self.info_table.viewport().mapToGlobal(pos))
            if not act:
                return
            if act == act_copy_val:
                QApplication.clipboard().setText(val)
            elif act == act_copy_key:
                QApplication.clipboard().setText(key)
            elif act == act_copy_both:
                QApplication.clipboard().setText(f"{key}: {val}")
        except Exception:
            pass

    # Preview removed: no hex/text rendering here

    def _show_error(self, msg: str) -> None:
        # Lightweight inline error: show message using the drop text (no border)
        try:
            self.drop_text.setText(msg)
            self.drop_text.setStyleSheet("border: none; background: transparent; color: #c00;")
        except Exception:
            pass

    def _reset_drop_message(self) -> None:
        """Restore the default non-error drop text and styling."""
        try:
            self.drop_text.setText("📁 Drop file or click to browse")
            self.drop_text.setStyleSheet("border: none; background: transparent;")
            self._apply_dropzone_style(hover=False)
        except Exception:
            pass

    # Clipboard and info helpers
    def _paste_clipboard(self) -> None:
        try:
            cb = QApplication.clipboard()
            text = cb.text() if cb else ""
        except Exception:
            text = ""
        if not text:
            self._show_error("Clipboard is empty")
            return
        # Try parse as hex; if not, treat as text/asm
        data = self._try_parse_hex(text or "")
        self._last_path = None
        if data:
            self._last_bytes = data
            self._last_text = text
            self._update_info("(clipboard)", len(data), "bytes")
            self._update_details(None, text, data)
        else:
            self._last_text = text
            self._last_bytes = (data or b"")
            self._update_info("(clipboard)", len(self._last_bytes), "assembly" if self._looks_like_assembly(text) else "bytes")
            self._update_details(None, text, self._last_bytes)
        self._import_current()

    def _copy_info(self) -> None:
        try:
            QApplication.clipboard().setText(self._details_text())
        except Exception:
            return

    def _details_text(self) -> str:
        # Build a multi-line summary of current details from table
        lines = []
        try:
            for row in range(self.info_table.rowCount()):
                key_item = self.info_table.item(row, 0)
                val_item = self.info_table.item(row, 1)
                if key_item and val_item:
                    key = key_item.text()
                    val = val_item.text()
                    lines.append(f"{key}: {val}")
        except Exception:
            pass
        return "\n".join(lines) if lines else ""

    # Recent files persistence/UI
    def _load_recents(self):
        try:
            from ..utils.config import load_config  # type: ignore
        except Exception:
            return []
        cfg = load_config() or {}
        lst = cfg.get("recent_files", [])
        if isinstance(lst, list):
            return [p for p in lst if isinstance(p, str)]
        return []

    def _save_recents(self) -> None:
        try:
            from ..utils.config import load_config, save_config  # type: ignore
        except Exception:
            return
        cfg = load_config() or {}
        cfg["recent_files"] = self._recents[:10]
        save_config(cfg)

    def _add_recent(self, path: str) -> None:
        if not path:
            return
        # De-duplicate and move to front
        try:
            self._recents = [p for p in self._recents if p != path]
        except Exception:
            self._recents = []
        self._recents.insert(0, path)
        # Cap length
        self._recents = self._recents[:10]
        self._save_recents()
        self._refresh_recent_ui()

    def _refresh_recent_ui(self) -> None:
        # Rebuild recent table rows
        try:
            self.recent_table.setRowCount(0)
        except Exception:
            return
        for p in (self._recents if hasattr(self, "_recents") else []):
            r = self.recent_table.rowCount()
            self.recent_table.insertRow(r)
            # Display shortened path but keep tooltip with full path
            disp = self._display_path(p)
            it = QTableWidgetItem(disp)
            it.setToolTip(p)
            try:
                it.setData(Qt.UserRole, p)
            except Exception:
                pass
            self.recent_table.setItem(r, 0, it)

    def _last_dir_from_config(self) -> str:
        try:
            from ..utils.config import load_config  # type: ignore
            cfg = load_config() or {}
            last = cfg.get("last_open_dir")
            return last if isinstance(last, str) else ""
        except Exception:
            return ""

    def _save_last_dir_to_config(self, path: str) -> None:
        try:
            import os
            from ..utils.config import load_config, save_config  # type: ignore
            cfg = load_config() or {}
            cfg["last_open_dir"] = os.path.dirname(path)
            save_config(cfg)
        except Exception:
            pass

    def _attach_hover_events(self, w: QWidget) -> None:
        """Attach hover events to a widget for visual feedback."""
        try:
            w.setMouseTracking(True)
            w.installEventFilter(self)
            # Store original style to restore on leave
            w.setProperty("_original_style", w.styleSheet())
            # Mark which container this is from (only recent now uses hover)
            if w.parent() == self._recent_container:
                w.setProperty("_container_type", "recent")
        except Exception:
            pass

    def eventFilter(self, obj: QWidget, event) -> bool:  # type: ignore
        """Handle hover events for recent rows."""
        try:
            # Check if this is a recent row container
            container_type = obj.property("_container_type")
            if container_type == "recent":
                from PySide6.QtCore import QEvent
                if event.type() == QEvent.Enter:
                    obj.setStyleSheet("QWidget { background: palette(highlight); opacity: 0.1; border-radius: 4px; }")
                    return False
                elif event.type() == QEvent.Leave:
                    obj.setStyleSheet("QWidget { border-radius: 4px; padding: 0px; }")
                    return False
        except Exception:
            pass
    def _open_recent_row(self, row: int) -> None:
        try:
            it = self.recent_table.item(row, 0)
            if not it:
                return
            path = it.data(Qt.UserRole) or it.text()
            if isinstance(path, str) and path:
                self._load_path(path, trigger_import=True)
        except Exception:
            pass

    def _on_recent_context_menu(self, pos) -> None:
        try:
            idx = self.recent_table.indexAt(pos)
            if not idx.isValid():
                return
            row = idx.row()
            it = self.recent_table.item(row, 0)
            if not it:
                return
            path = it.data(Qt.UserRole) or it.text()
            from PySide6.QtWidgets import QMenu as _Menu  # type: ignore
        except Exception:
            try:
                from PySide2.QtWidgets import QMenu as _Menu  # type: ignore
            except Exception:
                _Menu = None
        try:
            menu = _Menu(self) if _Menu else None
            if not menu:
                return
            act_open = menu.addAction("Open")
            act_copy = menu.addAction("Copy Path")
            act_remove = menu.addAction("Remove")
            act = menu.exec(self.recent_table.viewport().mapToGlobal(pos))
            if not act:
                return
            if act == act_open:
                self._load_path(path, trigger_import=True)  # type: ignore[arg-type]
            elif act == act_copy:
                QApplication.clipboard().setText(str(path))
            elif act == act_remove:
                try:
                    self._recents = [q for q in self._recents if q != path]
                    self._save_recents()
                    self._refresh_recent_ui()
                except Exception:
                    pass
        except Exception:
            pass

    def _spacer_label(self) -> QLabel:
        lbl = QLabel("•")
        try:
            lbl.setStyleSheet("color: palette(mid);")
        except Exception:
            pass
        return lbl

    def _apply_dropzone_style(self, hover: bool) -> None:
        """Apply style or state to the drop zone; prefers custom painter for better dash control."""
        dz = self.drop_zone
        # If we have our custom frame, just toggle hover state and repaint
        if isinstance(dz, DropZoneFrame):
            dz.setHover(hover)
            return
        # Fallback to stylesheet (cannot control dash gaps precisely)
        pal = dz.palette()
        try:
            border_col = pal.color(QPalette.Highlight if hover else QPalette.Mid)
        except Exception:
            border_col = None
        try:
            base_col = pal.color(QPalette.Base)
        except Exception:
            base_col = None
        def rgba(c, a: int) -> str:
            if c is None:
                return f"rgba(136,136,136,{a})"
            try:
                return f"rgba({c.red()},{c.green()},{c.blue()},{a})"
            except Exception:
                return f"rgba(136,136,136,{a})"
        border = border_col.name() if hasattr(border_col, 'name') else rgba(border_col, 255)
        bg = rgba(border_col, 22 if hover else 12) if hover else rgba(base_col, 10)
        width = 3 if hover else 2
        dz.setStyleSheet(f"QFrame {{ border: {width}px dashed {border}; border-radius: 8px; background: {bg}; }}")


class DropZoneFrame(QFrame):
    """Custom frame that paints a dashed rounded border with adjustable dash/gap."""
    def __init__(self, parent=None, on_click: Optional[Callable[[], None]] = None):
        super().__init__(parent)
        self._hover = False
        self._on_click = on_click
        # Improve appearance with full update on style changes
        try:
            self.setAttribute(getattr(self, 'WA_StyledBackground'))
        except Exception:
            pass
        try:
            # Indicate clickability
            self.setCursor(Qt.PointingHandCursor)
        except Exception:
            pass

    def setHover(self, h: bool) -> None:
        self._hover = bool(h)
        try:
            self.update()
        except Exception:
            pass

    def paintEvent(self, event) -> None:  # type: ignore
        try:
            super().paintEvent(event)
        except Exception:
            pass
        try:
            p = QPainter(self)
            p.setRenderHint(QPainter.Antialiasing, True)
            pal = self.palette()
            try:
                border_col = pal.color(QPalette.Highlight if self._hover else QPalette.Mid)
            except Exception:
                try:
                    border_col = pal.color(QPalette.WindowText)
                except Exception:
                    border_col = QColor(136, 136, 136)
            try:
                base_col = pal.color(QPalette.Base)
            except Exception:
                base_col = QColor(0, 0, 0, 0)
            # Background fill (subtle)
            bg = QColor(base_col)
            try:
                bg.setAlpha(30 if self._hover else 20)
            except Exception:
                pass
            p.fillRect(self.rect().adjusted(2, 2, -2, -2), bg)
            # Dashed border with larger dash/gap
            pen = QPen(border_col)
            pen.setWidth(3 if self._hover else 2)
            try:
                # Longer dashes and gaps to reduce dot density
                pen.setStyle(Qt.CustomDashLine)
                pen.setDashPattern([12.0, 10.0] if self._hover else [10.0, 8.0])
            except Exception:
                pen.setStyle(Qt.DashLine)
            p.setPen(pen)
            radius = 8
            r = self.rect().adjusted(2, 2, -2, -2)
            try:
                p.drawRoundedRect(r, radius, radius)
            except Exception:
                # Fallback to normal rect
                p.drawRect(r)
            p.end()
        except Exception:
            pass

    def mouseReleaseEvent(self, e) -> None:  # type: ignore
        try:
            if hasattr(e, 'button') and e.button() == Qt.LeftButton and callable(self._on_click):
                # Treat as click-to-open when not in a drag operation
                self._on_click()
                e.accept()
                return
        except Exception:
            pass
        try:
            super().mouseReleaseEvent(e)
        except Exception:
            pass


class ElideLabel(QLabel):
    """Label that elides long text in the middle to avoid enforcing large widths."""
    def __init__(self, text: str = "", parent: Optional[QWidget] = None, mode=Qt.ElideMiddle):
        super().__init__(text, parent)
        self._full_text = text
        self._mode = mode
        try:
            self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        except Exception:
            pass

    def set_full_text(self, text: str) -> None:
        self._full_text = text
        self._update_elide()

    def resizeEvent(self, e):  # type: ignore
        try:
            super().resizeEvent(e)
        except Exception:
            pass
        self._update_elide()

    def _update_elide(self) -> None:
        try:
            fm = self.fontMetrics()
            w = max(0, self.width())
            el = fm.elidedText(self._full_text or "", self._mode, w)
            super().setText(el)
        except Exception:
            try:
                super().setText(self._full_text)
            except Exception:
                pass
