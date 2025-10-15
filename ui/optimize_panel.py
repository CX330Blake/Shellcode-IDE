from __future__ import annotations

from typing import List, Optional, Callable

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QCheckBox, QListWidget, QListWidgetItem, QPlainTextEdit
    )
except Exception:
    from PySide2.QtCore import Qt  # type: ignore
    from PySide2.QtWidgets import (  # type: ignore
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QCheckBox, QListWidget, QListWidgetItem, QPlainTextEdit
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
