from __future__ import annotations

from typing import List

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QDialog,
        QDialogButtonBox,
        QVBoxLayout,
        QHBoxLayout,
        QWidget,
        QPushButton,
        QComboBox,
        QCheckBox,
        QLineEdit,
        QLabel,
        QScrollArea,
        QFrame,
    )
except Exception:  # fallback to PySide2
    from PySide2.QtCore import Qt  # type: ignore
    from PySide2.QtWidgets import (  # type: ignore
        QDialog,
        QDialogButtonBox,
        QVBoxLayout,
        QHBoxLayout,
        QWidget,
        QPushButton,
        QComboBox,
        QCheckBox,
        QLineEdit,
        QLabel,
        QScrollArea,
        QFrame,
    )

from ..backends.validator import BadPatternManager, Pattern


class PatternRow(QWidget):
    def __init__(self, pattern: Pattern | None = None, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        try:
            lay.setContentsMargins(8, 4, 8, 4)
            lay.setSpacing(8)
        except Exception:
            pass
        # Enabled (centered)
        self.chk = QCheckBox()
        try:
            wrap = QWidget(); hl = QHBoxLayout(wrap); hl.setContentsMargins(0,0,0,0)
            hl.addStretch(1); hl.addWidget(self.chk); hl.addStretch(1)
            lay.addWidget(wrap, 0)
        except Exception:
            lay.addWidget(self.chk, 0)
        # Type, Value, Name, Remove
        self.typ = QComboBox(); self.typ.addItems(["hex","sequence","regex"]) ; self.typ.setToolTip("Pattern type")
        self.val = QLineEdit(); self.val.setPlaceholderText("e.g. 00  |  00 0a ff  |  (00){2,}")
        self.name = QLineEdit(); self.name.setPlaceholderText("Optional description")
        self.rm = QPushButton("Remove")
        try:
            self.rm.setFixedWidth(80)
        except Exception:
            pass
        lay.addWidget(self.typ, 0)
        lay.addWidget(self.val, 3)
        lay.addWidget(self.name, 2)
        lay.addWidget(self.rm, 0)

        p = pattern or Pattern(type="hex", value="", name="", enabled=True)
        try:
            self.typ.setCurrentIndex(max(0, ["hex","sequence","regex"].index(p.type) if p.type in ["hex","sequence","regex"] else 0))
        except Exception:
            pass
        self.val.setText(p.value or "")
        self.name.setText(p.name or "")
        self.chk.setChecked(bool(p.enabled))

    def to_pattern(self) -> Pattern:
        return Pattern(
            type=self.typ.currentText(),
            value=self.val.text(),
            name=self.name.text(),
            enabled=self.chk.isChecked(),
        )


class PatternsDialog(QDialog):
    def __init__(self, bpm: BadPatternManager, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Bad Patterns")
        self.resize(720, 420)
        self.bpm = bpm

        layout = QVBoxLayout(self)

        # Top toolbar
        hl = QHBoxLayout()
        self.add_btn = QPushButton("Add")
        self.add_null_btn = QPushButton("Add 00")
        self.add_lf_btn = QPushButton("Add 0A")
        self.add_ff_btn = QPushButton("Add FF")
        self.reset_btn = QPushButton("Reset Defaults")
        for b in (self.add_btn, self.add_null_btn, self.add_lf_btn, self.add_ff_btn):
            b.setFixedWidth(88)
        self.reset_btn.setFixedWidth(130)
        hl.addWidget(self.add_btn)
        hl.addWidget(self.add_null_btn)
        hl.addWidget(self.add_lf_btn)
        hl.addWidget(self.add_ff_btn)
        hl.addSpacing(12)
        hl.addWidget(self.reset_btn)
        hl.addStretch(1)
        layout.addLayout(hl)

        # List container inside a scroll area
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

        self._populate()

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        layout.addWidget(self.buttons)

        self.add_btn.clicked.connect(self._add_row)
        self.add_null_btn.clicked.connect(lambda: self._append_pattern(Pattern(type="hex", value="00", name="NULL byte", enabled=True)))
        self.add_lf_btn.clicked.connect(lambda: self._append_pattern(Pattern(type="hex", value="0a", name="LF byte", enabled=True)))
        self.add_ff_btn.clicked.connect(lambda: self._append_pattern(Pattern(type="hex", value="ff", name="0xFF byte", enabled=True)))
        self.reset_btn.clicked.connect(self._reset_defaults)
        self.buttons.accepted.connect(self._try_accept)
        self.buttons.rejected.connect(self.reject)

    def _populate(self):
        # Clear and rebuild list
        while self.rows_layout.count() > 1:
            item = self.rows_layout.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)
        for p in self.bpm.patterns:
            self._append_pattern(p)

    def _append_pattern(self, p: Pattern):
        roww = PatternRow(p, self)
        self.rows_layout.insertWidget(self.rows_layout.count() - 1, roww)
        try:
            roww.val.textChanged.connect(self._validate_all)
            roww.typ.currentIndexChanged.connect(self._validate_all)
            roww.rm.clicked.connect(lambda _=None, w=roww: self._remove_row(w))
        except Exception:
            pass
        self._validate_all()

    def _add_row(self):
        self._append_pattern(Pattern(type="hex", value="", name="", enabled=True))
        # focus last row's value
        try:
            idx = self.rows_layout.count() - 2
            w = self.rows_layout.itemAt(idx).widget()
            if isinstance(w, PatternRow):
                w.val.setFocus()
        except Exception:
            pass

    def _del_selected(self):
        # Not applicable in list mode; no-op
        self._validate_all()

    def _remove_row_clicked(self):
        # Deprecated in list mode
        self._validate_all()

    def _remove_row(self, roww: PatternRow):
        try:
            roww.setParent(None)
        except Exception:
            pass
        self._validate_all()

    def result_patterns(self) -> List[Pattern]:
        out: List[Pattern] = []
        for i in range(self.rows_layout.count() - 1):
            w = self.rows_layout.itemAt(i).widget()
            if isinstance(w, PatternRow):
                out.append(w.to_pattern())
        return out

    # UX helpers
    def _reset_defaults(self):
        self.bpm = BadPatternManager()  # reload defaults
        self._populate()
        self._validate_all()

    def _validate_all(self):
        ok = True
        for i in range(self.rows_layout.count() - 1):
            w = self.rows_layout.itemAt(i).widget()
            if not isinstance(w, PatternRow):
                continue
            typ = w.typ.currentText()
            val = w.val.text()
            valid = True
            if typ == "hex":
                valid = len(val.strip()) in (0, 2) and all(c in "0123456789abcdefABCDEF" for c in val.strip())
            elif typ == "sequence":
                parts = [p for p in val.replace(',', ' ').split() if p]
                valid = len(parts) > 0 and all(len(p) == 2 and all(c in "0123456789abcdefABCDEF" for c in p) for p in parts)
            elif typ == "regex":
                try:
                    import re
                    re.compile(val)
                    valid = True
                except Exception:
                    valid = False
            try:
                if not valid:
                    w.val.setStyleSheet("QLineEdit { background: #ffeded; }")
                else:
                    w.val.setStyleSheet("")
            except Exception:
                pass
            ok = ok and valid
        try:
            self.buttons.button(QDialogButtonBox.Ok).setEnabled(ok)
        except Exception:
            pass

    def _try_accept(self):
        self._validate_all()
        try:
            if not self.buttons.button(QDialogButtonBox.Ok).isEnabled():
                return
        except Exception:
            pass
        self.accept()
