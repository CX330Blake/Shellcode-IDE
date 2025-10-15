from __future__ import annotations

from typing import List, Optional, Callable

try:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QTextCharFormat, QColor, QTextCursor, QTextFormat
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QCheckBox, QListWidget, QListWidgetItem, QPlainTextEdit, QTextEdit
    )
except Exception:
    from PySide2.QtCore import Qt  # type: ignore
    from PySide2.QtGui import QTextCharFormat, QColor, QTextCursor, QTextFormat  # type: ignore
    from PySide2.QtWidgets import (  # type: ignore
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QCheckBox, QListWidget, QListWidgetItem, QPlainTextEdit, QTextEdit
    )

from ..backends.optimize import default_rules_for_arch, propose, apply_all, TransformRule, Proposal


class OptimizePanel(QWidget):
    def __init__(self, get_asm: Callable[[], str], set_asm: Callable[[str], None], get_arch: Callable[[], str], parent=None):
        super().__init__(parent)
        self.get_asm = get_asm
        self.set_asm = set_asm
        self.get_arch = get_arch

        layout = QVBoxLayout(self)
        # Header controls
        top = QHBoxLayout()
        self.chk_rule1 = QCheckBox("Push 0 -> xor; push reg")
        self.chk_rule2 = QCheckBox("mov reg, imm8 -> mov reg8, imm8 (risky)")
        self.btn_apply = QPushButton("Apply All")
        top.addWidget(self.chk_rule1)
        top.addWidget(self.chk_rule2)
        top.addStretch(1)
        top.addWidget(self.btn_apply)
        layout.addLayout(top)

        # Before/After panes
        panes = QHBoxLayout()
        # Left: Before
        self.before_edit = QPlainTextEdit()
        self.before_edit.setPlaceholderText("Before (original assembly)")
        # Right: After
        self.after_edit = QPlainTextEdit()
        self.after_edit.setPlaceholderText("After (with selected optimizations)")
        try:
            for ed in (self.before_edit, self.after_edit):
                ed.setReadOnly(True)
                ed.setLineWrapMode(QPlainTextEdit.NoWrap)  # type: ignore
        except Exception:
            pass
        panes.addWidget(self.before_edit, 1)
        panes.addWidget(self.after_edit, 1)
        layout.addLayout(panes)

        # Note: unified diff view removed per UX request (two panes only)

        # Defaults
        self.chk_rule1.setChecked(True)
        self.chk_rule2.setChecked(True)

        # Wire (live preview)
        try:
            self.chk_rule1.toggled.connect(self.on_preview)
            self.chk_rule2.toggled.connect(self.on_preview)
        except Exception:
            pass
        self.btn_apply.clicked.connect(self.on_apply)
        # Initial preview
        self.on_preview()
        
    def _set_line_highlights(self, edit: QPlainTextEdit, add_lines: set, del_lines: set) -> None:
        """Apply GitHub-like line background highlights to a QPlainTextEdit.

        - add_lines: indices to highlight green
        - del_lines: indices to highlight red
        """
        sels = []
        try:
            doc = edit.document()
            # Formats
            f_add = QTextCharFormat(); f_add.setBackground(QColor('#dafbe1'))  # addition bg (light/dark friendly)
            f_add.setForeground(QColor('#1a7f37'))  # addition fg
            f_add.setProperty(QTextFormat.FullWidthSelection, True)
            f_del = QTextCharFormat(); f_del.setBackground(QColor('#ffebe9'))  # deletion bg
            f_del.setForeground(QColor('#d1242f'))  # deletion fg
            f_del.setProperty(QTextFormat.FullWidthSelection, True)
            max_lines = doc.blockCount()
            for i in range(max_lines):
                block = doc.findBlockByNumber(i)
                if not block.isValid():
                    continue
                fmt = f_add if i in add_lines else (f_del if i in del_lines else None)
                if fmt is None:
                    continue
                es = QTextEdit.ExtraSelection()
                # Select the entire block so the full-width selection background applies
                cur = QTextCursor(block)
                cur.setPosition(block.position())
                cur.movePosition(QTextCursor.EndOfBlock, QTextCursor.KeepAnchor)
                es.cursor = cur
                es.format = fmt
                sels.append(es)
            edit.setExtraSelections(sels)
        except Exception:
            try:
                edit.setExtraSelections([])
            except Exception:
                pass

    def _set_intraline_highlights(self, edit: QPlainTextEdit, spans_by_line: dict, kind: str) -> None:
        """Highlight only differing parts within lines.

        spans_by_line: { line_index: [(start_col, length), ...], ... }
        kind: 'add' or 'del' to choose colors.
        """
        sels = []
        try:
            doc = edit.document()
            fmt = QTextCharFormat()
            if kind == 'add':
                fmt.setBackground(QColor('#dafbe1'))
                fmt.setForeground(QColor('#1a7f37'))
            else:
                fmt.setBackground(QColor('#ffebe9'))
                fmt.setForeground(QColor('#d1242f'))
            for line_no, spans in spans_by_line.items():
                block = doc.findBlockByNumber(int(line_no))
                if not block.isValid():
                    continue
                base = block.position()
                # block.length includes newline; clamp within visible text
                max_len = max(0, block.length() - 1)
                for (start, length) in spans:
                    if length <= 0:
                        continue
                    s = max(0, min(int(start), max_len))
                    e = max(0, min(int(start + length), max_len))
                    if e <= s:
                        continue
                    cur = QTextCursor(block)
                    cur.setPosition(base + s)
                    cur.setPosition(base + e, QTextCursor.KeepAnchor)
                    es = QTextEdit.ExtraSelection()
                    es.cursor = cur
                    es.format = fmt
                    sels.append(es)
            edit.setExtraSelections(sels)
        except Exception:
            try:
                edit.setExtraSelections([])
            except Exception:
                pass

    def _rules(self) -> List[TransformRule]:
        arch = self.get_arch()
        rules = default_rules_for_arch(arch)
        # Map to checkboxes by name
        for r in rules:
            if r.name == "push-zero-to-xor-push":
                r.enabled = self.chk_rule1.isChecked()
            elif r.name == "mov-reg-imm8-to-mov-reg8":
                r.enabled = self.chk_rule2.isChecked()
        return rules

    def on_preview(self):
        asm = self.get_asm()
        arch = self.get_arch()
        rules = self._rules()
        props = propose(asm, arch, rules)
        # Populate before/after boxes
        self.before_edit.setPlainText(asm)
        from ..backends.optimize import align_assembly
        after = apply_all(asm, arch, rules)
        after = align_assembly(after)
        self.after_edit.setPlainText(after if after != asm else "; No change with current rules\n" + asm)
        # Compute line-level diff highlights (line is the minimum unit)
        try:
            import difflib
            import re
            a = (asm or "").splitlines()
            b = (after or "").splitlines()
            # Normalize whitespace for diffing so formatting-only changes are ignored
            def _norm(s: str) -> str:
                return re.sub(r"\s+", " ", s).strip()
            a_norm = [_norm(x) for x in a]
            b_norm = [_norm(x) for x in b]
            sm = difflib.SequenceMatcher(None, a_norm, b_norm)
            add_after = set()
            del_before = set()
            for tag, i1, i2, j1, j2 in sm.get_opcodes():
                if tag == 'equal':
                    continue
                if tag in ('replace', 'delete'):
                    del_before.update(range(i1, i2))
                if tag in ('replace', 'insert'):
                    add_after.update(range(j1, j2))
            self._set_line_highlights(self.before_edit, add_lines=set(), del_lines=del_before)
            self._set_line_highlights(self.after_edit, add_lines=add_after, del_lines=set())
        except Exception:
            # Clear highlights on error
            self._set_line_highlights(self.before_edit, set(), set())
            self._set_line_highlights(self.after_edit, set(), set())

        # No unified diff box; rely on line highlights in Before/After panes

    def on_apply(self):
        asm = self.get_asm()
        arch = self.get_arch()
        rules = self._rules()
        from ..backends.optimize import align_assembly
        new_asm = apply_all(asm, arch, rules)
        new_asm = align_assembly(new_asm)
        if new_asm != asm:
            self.set_asm(new_asm)
        # Refresh comparison against current editor contents
        self.on_preview()
