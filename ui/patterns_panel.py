from __future__ import annotations

from typing import Callable, Optional

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QCheckBox,
        QScrollArea, QLineEdit, QComboBox
    )
except Exception:
    from PySide2.QtCore import Qt  # type: ignore
    from PySide2.QtWidgets import (  # type: ignore
        QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QCheckBox,
        QScrollArea, QLineEdit, QComboBox
    )

from ..backends.validator import BadPatternManager, Pattern
from .patterns_dialog import PatternRow  # reuse row widget
from ..utils.config import load_config, save_config


class PatternsPanel(QWidget):
    def __init__(self, bpm: BadPatternManager, parent=None):
        super().__init__(parent)
        self.bpm = bpm
        self.on_changed: Optional[Callable[[], None]] = None

        layout = QVBoxLayout(self)
        # Top controls: enable checkbox + quick-adds
        top = QHBoxLayout()
        self.chk_enabled = QCheckBox("Highlight in Debug")
        cfg = load_config()
        try:
            self.chk_enabled.setChecked(bool(cfg.get("bad_highlight_enabled", True)))
        except Exception:
            self.chk_enabled.setChecked(True)
        self.btn_add = QPushButton("Add")
        self.btn_00 = QPushButton("Add 00")
        self.btn_0A = QPushButton("Add 0A")
        self.btn_FF = QPushButton("Add FF")
        self.btn_reset = QPushButton("Reset Defaults")
        for b in (self.btn_add, self.btn_00, self.btn_0A, self.btn_FF):
            try:
                b.setFixedWidth(88)
            except Exception:
                pass
        try:
            self.btn_reset.setFixedWidth(130)
        except Exception:
            pass
        top.addWidget(self.chk_enabled)
        top.addSpacing(10)
        top.addWidget(self.btn_add)
        top.addWidget(self.btn_00)
        top.addWidget(self.btn_0A)
        top.addWidget(self.btn_FF)
        top.addSpacing(12)
        top.addWidget(self.btn_reset)
        top.addStretch(1)
        layout.addLayout(top)

        # Scrollable rows
        self.scroll = QScrollArea(); self.scroll.setWidgetResizable(True)
        self.rows_host = QWidget()
        self.rows_layout = QVBoxLayout(self.rows_host)
        try:
            self.rows_layout.setContentsMargins(6, 6, 6, 6)
            self.rows_layout.setSpacing(6)
        except Exception:
            pass
        self.rows_layout.addStretch(1)
        self.scroll.setWidget(self.rows_host)
        layout.addWidget(self.scroll)

        # Populate from bpm
        self._rebuild_rows()

        # Wire events
        self.chk_enabled.toggled.connect(self._persist_enabled)
        self.btn_add.clicked.connect(self._add_row)
        self.btn_00.clicked.connect(lambda: self._add_quick("00", "NULL byte"))
        self.btn_0A.clicked.connect(lambda: self._add_quick("0a", "LF byte"))
        self.btn_FF.clicked.connect(lambda: self._add_quick("ff", "0xFF byte"))
        self.btn_reset.clicked.connect(self._reset_defaults)

    # API
    def is_highlight_enabled(self) -> bool:
        try:
            return bool(self.chk_enabled.isChecked())
        except Exception:
            return True

    # Internals
    def _persist_enabled(self):
        cfg = load_config()
        cfg["bad_highlight_enabled"] = self.is_highlight_enabled()
        save_config(cfg)
        self._notify_changed()

    def _notify_changed(self):
        if self.on_changed:
            try:
                self.on_changed()
            except Exception:
                pass

    def _rebuild_rows(self):
        # Remove old
        while self.rows_layout.count() > 1:
            item = self.rows_layout.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)
        # Add from bpm
        for p in self.bpm.patterns:
            self._append_row(p)

    def _append_row(self, p: Pattern):
        row = PatternRow(p, self)
        self.rows_layout.insertWidget(self.rows_layout.count() - 1, row)
        # wire
        try:
            row.val.textChanged.connect(self._rows_changed)
            row.typ.currentIndexChanged.connect(self._rows_changed)
            row.chk.toggled.connect(self._rows_changed)
            row.rm.clicked.connect(lambda _=None, w=row: self._remove_row(w))
        except Exception:
            pass

    def _add_row(self):
        self._append_row(Pattern(type="hex", value="", name="", enabled=True))
        self._rows_changed()

    def _add_quick(self, val: str, name: str):
        self._append_row(Pattern(type="hex", value=val, name=name, enabled=True))
        self._rows_changed()

    def _remove_row(self, row: PatternRow):
        try:
            row.setParent(None)
        except Exception:
            pass
        self._rows_changed()

    def _rows_changed(self):
        # Collect patterns from rows
        pats = []
        for i in range(self.rows_layout.count() - 1):
            w = self.rows_layout.itemAt(i).widget()
            if isinstance(w, PatternRow):
                pats.append(w.to_pattern())
        self.bpm.patterns = pats
        # persist
        cfg = load_config()
        cfg["bad_patterns"] = self.bpm.serialize()
        save_config(cfg)
        self._notify_changed()

    def _reset_defaults(self):
        # Reset to default patterns via a fresh BPM and rebuild UI
        try:
            self.bpm = BadPatternManager()
        except Exception:
            return
        self._rebuild_rows()
        # persist
        cfg = load_config()
        cfg["bad_patterns"] = self.bpm.serialize()
        save_config(cfg)
        self._notify_changed()
