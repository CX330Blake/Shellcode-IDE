from __future__ import annotations

from typing import Optional

try:
    from PySide6.QtCore import Qt  # type: ignore
    from PySide6.QtWidgets import (  # type: ignore
        QDialog, QDialogButtonBox, QVBoxLayout, QHBoxLayout, QWidget,
        QLabel, QCheckBox, QPushButton, QComboBox, QTabWidget
    )
except Exception:
    from PySide2.QtCore import Qt  # type: ignore
    from PySide2.QtWidgets import (  # type: ignore
        QDialog, QDialogButtonBox, QVBoxLayout, QHBoxLayout, QWidget,
        QLabel, QCheckBox, QPushButton, QComboBox, QTabWidget
    )

from ..utils.config import load_config, save_config
# Patterns management is no longer exposed in Settings


class SettingsDialog(QDialog):
    """Aggregated Settings dialog for Shellcode IDE.

    Tabs include per-feature preferences mirrored from the main UI:
    - Bad Chars (highlight toggle + manage patterns)
    - Optimize (rule toggles)
    - Formats (default language)
    - Syscalls (snippet style)
    - Shell-Storm (preview syntax)
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.resize(520, 360)

        cfg = load_config()

        lay = QVBoxLayout(self)
        self.tabs = QTabWidget()
        lay.addWidget(self.tabs)

        # Optimize tab
        opt = QWidget(); opt_l = QVBoxLayout(opt)
        self.chk_opt_rule1 = QCheckBox("Push 0 -> xor; push reg")
        self.chk_opt_rule2 = QCheckBox("mov reg, imm -> mov reg8/16/32, imm (risky)")
        self.chk_opt_rule1.setChecked(bool(cfg.get("opt_rule_push_zero", True)))
        self.chk_opt_rule2.setChecked(bool(cfg.get("opt_rule_mov_imm8", True)))
        opt_l.addWidget(self.chk_opt_rule1)
        opt_l.addWidget(self.chk_opt_rule2)
        opt_l.addStretch(1)
        self.tabs.addTab(opt, "Optimize")

        # Syscalls tab
        sc = QWidget(); sc_l = QVBoxLayout(sc)
        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Default snippet style:"))
        self.combo_sys_style = QComboBox(); self.combo_sys_style.addItems(["Commented", "Minimal"])
        try:
            def_style = (cfg.get("syscalls_style_default") or "Commented")
            idx = max(0, self.combo_sys_style.findText(def_style))
            self.combo_sys_style.setCurrentIndex(idx)
        except Exception:
            pass
        r2.addWidget(self.combo_sys_style)
        r2.addStretch(1)
        sc_l.addLayout(r2)
        sc_l.addStretch(1)
        self.tabs.addTab(sc, "Syscalls")

        # Buttons
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        lay.addWidget(self.buttons)

        # Events
        self.buttons.accepted.connect(self._on_accept)
        self.buttons.rejected.connect(self.reject)

    # Expose results to caller
    def values(self) -> dict:
        return {
            "opt_rule_push_zero": bool(self.chk_opt_rule1.isChecked()),
            "opt_rule_mov_imm8": bool(self.chk_opt_rule2.isChecked()),
            "syscalls_style_default": self.combo_sys_style.currentText() or "Commented",
        }

    # Hooks
    def _on_accept(self):
        # Persist to config; the main window will apply live
        cfg = load_config()
        vals = self.values()
        cfg.update(vals)
        save_config(cfg)
        self.accept()
