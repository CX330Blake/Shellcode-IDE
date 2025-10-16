from __future__ import annotations

from typing import Callable, Optional, Tuple

# Qt compatibility: prefer PySide6, fallback to PySide2
try:
    from PySide6.QtCore import Qt, QSize  # type: ignore
    from PySide6.QtGui import QDragEnterEvent, QDropEvent, QPalette, QPainter, QPen, QColor  # type: ignore
    from PySide6.QtWidgets import (  # type: ignore
        QWidget,
        QVBoxLayout,
        QLabel,
        QPushButton,
        QFileDialog,
        QHBoxLayout,
        QFrame,
        QRadioButton,
        QButtonGroup,
        QPlainTextEdit,
        QSizePolicy,
    )
except Exception:
    from PySide2.QtCore import Qt, QSize  # type: ignore
    from PySide2.QtGui import QDragEnterEvent, QDropEvent, QPalette, QPainter, QPen, QColor  # type: ignore
    from PySide2.QtWidgets import (  # type: ignore
        QWidget,
        QVBoxLayout,
        QLabel,
        QPushButton,
        QFileDialog,
        QHBoxLayout,
        QFrame,
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

        # Import mode controls
        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("Type:"))
        self.rb_auto = QRadioButton("Auto")
        self.rb_asm = QRadioButton("Asm")
        self.rb_bytes = QRadioButton("Bytes")
        self.rb_auto.setChecked(True)
        self._mode_group = QButtonGroup(self)
        self._mode_group.addButton(self.rb_auto)
        self._mode_group.addButton(self.rb_asm)
        self._mode_group.addButton(self.rb_bytes)
        mode_row.addWidget(self.rb_auto)
        mode_row.addWidget(self.rb_asm)
        mode_row.addWidget(self.rb_bytes)
        mode_row.addStretch(1)
        self.btn_clear = QPushButton("Clear")
        self.btn_clear.clicked.connect(self._clear_preview)
        mode_row.addWidget(self.btn_clear)
        root.addLayout(mode_row)
        # Respect Analysis mode: only Bytes allowed (disable Asm and prefer Auto/Bytes)
        try:
            self._enforce_analysis_restrictions()
        except Exception:
            pass
        # Re-import automatically when the user changes the mode, if a file is loaded
        try:
            def _auto_reimport(checked: bool) -> None:
                if checked and (self._last_bytes is not None or self._last_text is not None or self._last_path is not None):
                    self._import_current()
            self.rb_auto.toggled.connect(_auto_reimport)
            self.rb_asm.toggled.connect(_auto_reimport)
            self.rb_bytes.toggled.connect(_auto_reimport)
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
        self.drop_text = QLabel("Drop / Click")
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

        # File info + preview
        info_row = QHBoxLayout()
        self.info_name = ElideLabel("—")
        # Make labels shrinkable so they don't enforce a wide minimum
        try:
            self.info_name.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        except Exception:
            pass
        self.info_size = QLabel("—")
        self.info_detect = QLabel("—")
        info_row.addWidget(QLabel("File:"))
        info_row.addWidget(self.info_name, 1)
        info_row.addWidget(self._spacer_label())
        info_row.addWidget(QLabel("Size:"))
        info_row.addWidget(self.info_size)
        info_row.addWidget(self._spacer_label())
        info_row.addWidget(QLabel("Type:"))
        info_row.addWidget(self.info_detect)
        info_row.addStretch(1)
        root.addLayout(info_row)

        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        # Wrap to widget width to avoid wide minimums
        try:
            self.preview.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        except Exception:
            try:
                self.preview.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
            except Exception:
                pass
        try:
            self.preview.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        except Exception:
            pass
        # Apply a monospace font without importing main_window to avoid cycles
        try:
            from PySide6.QtGui import QFont as _QF  # type: ignore
        except Exception:
            try:
                from PySide2.QtGui import QFont as _QF  # type: ignore
            except Exception:
                _QF = None
        try:
            if _QF:
                f = _QF()
                try:
                    f.setStyleHint(getattr(_QF, 'Monospace', getattr(_QF, 'StyleHint', None)))
                except Exception:
                    pass
                try:
                    f.setFamily("Menlo, Consolas, monospace")
                except Exception:
                    pass
                self.preview.setFont(f)
        except Exception:
            pass
        root.addWidget(self.preview, 1)

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
        # In analysis mode, restrict dialog to bytes files
        if self._in_analysis_mode():
            filters = "Binary (*.bin *.raw);;All Files (*)"
        else:
            filters = "All Files (*);;Assembly (*.s *.S *.asm *.txt);;Binary (*.bin *.raw)"
        path, _ = QFileDialog.getOpenFileName(self, "Open File", "", filters)
        if path:
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
        self._update_preview(text, self._last_bytes)

        if trigger_import:
            self._import_current()

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
        if self.rb_asm.isChecked():
            return "assembly"
        if self.rb_bytes.isChecked():
            return "bytes"
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

        # Enforce Analysis mode restriction: only bytes may be imported
        if self._in_analysis_mode() and final_kind == "assembly":
            self._show_error("Analysis mode accepts bytes only. Switch to Dev for assembly.")
            # Also ensure UI selection reflects restriction
            try:
                self._enforce_analysis_restrictions()
            except Exception:
                pass
            return

        if final_kind == "assembly":
            self._on_asm(text or "")
        else:
            self._on_hex(data)

    def _in_analysis_mode(self) -> bool:
        try:
            mode = (self._get_mode() if callable(self._get_mode) else "").strip().lower()
        except Exception:
            mode = ""
        return mode.startswith("analysis") or mode.startswith("disassemble")

    def _enforce_analysis_restrictions(self) -> None:
        if not self._in_analysis_mode():
            # Re-enable in other modes
            try:
                self.rb_asm.setEnabled(True)
                self.rb_auto.setEnabled(True)
                self.rb_bytes.setEnabled(True)
            except Exception:
                pass
            return
        # Disable Asm radio and prefer Bytes in Analysis
        try:
            self.rb_asm.setEnabled(False)
            # If Asm was selected, switch to Bytes
            if getattr(self.rb_asm, 'isChecked', lambda: False)():
                self.rb_bytes.setChecked(True)
        except Exception:
            pass

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
        self.preview.setPlainText("")
        self.info_name.setText("File: —")
        self.info_size.setText("Size: —")
        self.info_detect.setText("Detected: —")

    def _update_info(self, path: str, size: int, detected: str) -> None:
        try:
            self.info_name.set_full_text(path)
            self.info_name.setToolTip(path)
        except Exception:
            self.info_name.setText(path)
        self.info_size.setText(f"{size} B")
        self.info_detect.setText("assembly" if detected == "assembly" else "bytes")

    def _update_preview(self, text: Optional[str], data: Optional[bytes]) -> None:
        # Prefer text preview when looks like assembly or human-readable
        if text is not None and (self._looks_like_assembly(text) or self._is_printable_text(text)):
            snippet = "\n".join(text.splitlines()[:200])
            self.preview.setPlainText(snippet)
        else:
            buf = data or b""
            # hex preview limited
            hex_lines = self._hex_preview(buf, max_bytes=4096)
            self.preview.setPlainText(hex_lines)

    def _is_printable_text(self, s: str) -> bool:
        # Heuristic: most chars printable and contains newlines
        if not s:
            return False
        printable = sum(1 for ch in s if (" " <= ch <= "~") or ch in "\n\r\t")
        return (printable / max(1, len(s))) > 0.9 and ("\n" in s or "\r" in s)

    def _hex_preview(self, data: bytes, max_bytes: int = 4096) -> str:
        if not data:
            return ""
        view = data[:max_bytes]
        # simple 16-byte rows
        out_lines = []
        for i in range(0, len(view), 16):
            chunk = view[i:i+16]
            hex_bytes = " ".join(f"{b:02x}" for b in chunk)
            out_lines.append(f"{i:08x}: {hex_bytes}")
        if len(data) > max_bytes:
            out_lines.append(f"… ({len(data) - max_bytes} more bytes)")
        return "\n".join(out_lines)

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
            self.drop_text.setText("Drop / Click")
            self.drop_text.setStyleSheet("border: none; background: transparent;")
            self._apply_dropzone_style(hover=False)
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
