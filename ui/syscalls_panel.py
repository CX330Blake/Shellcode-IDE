from __future__ import annotations

from typing import Callable, List, Optional, Dict, Set

try:
    from PySide6.QtCore import Qt  # type: ignore
    from PySide6.QtWidgets import (  # type: ignore
        QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
        QLineEdit, QLabel, QTableWidget, QTableWidgetItem, QMessageBox,
        QCheckBox, QComboBox, QMenu
        )
    _QT = "PySide6"
except Exception:
    try:
        from PySide2.QtCore import Qt  # type: ignore
        from PySide2.QtWidgets import (  # type: ignore
        QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
        QLineEdit, QLabel, QTableWidget, QTableWidgetItem, QMessageBox,
        QCheckBox, QComboBox, QMenu
        )
        _QT = "PySide2"
    except Exception as exc:  # pragma: no cover
        raise ImportError("Qt (PySide6/PySide2) is required for SyscallsPanel") from exc

from ..backends.syscalls import fetch_syscalls, Syscall, format_asm_snippet, canonical_arch, load_syscall_table
from ..utils.config import load_config, save_config


class SyscallsPanel(QWidget):
    """Displays a syscall table for the selected architecture/OS.

    - Visible in both Dev and Analysis modes.
    - In Dev mode, double-click inserts an assembly snippet via `insert_asm_cb`.
    """

    def __init__(
        self,
        get_arch_cb: Callable[[], str],
        insert_asm_cb: Optional[Callable[[str], None]] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._get_arch = get_arch_cb
        self._insert_asm = insert_asm_cb
        self._rows: List[Syscall] = []
        self._filtered_rows: List[Syscall] = []
        self._favorites: Dict[str, Set[int]] = self._load_favorites()

        layout = QVBoxLayout(self)

        # Numeric-sorting item for the NR column
        class _IntItem(QTableWidgetItem):
            def __lt__(self, other):  # type: ignore[override]
                try:
                    return int(self.text()) < int(other.text())
                except Exception:
                    return super().__lt__(other)
        self._IntItem = _IntItem

        # Controls row
        row = QHBoxLayout()
        # Snippet style selector
        row.addWidget(QLabel("Snippet:"))
        self.style_combo = QComboBox()
        try:
            self.style_combo.addItems(["Commented", "Minimal"])
        except Exception:
            pass
        row.addWidget(self.style_combo)
        # Favorites filter removed to match strict table layout
        self.btn_refresh = QPushButton("Refresh")
        row.addWidget(self.btn_refresh)
        row.addStretch(1)
        row.addWidget(QLabel("Search:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("name, num, arg")
        row.addWidget(self.search_edit)
        # Status label
        self.status_lbl = QLabel("")
        row.addWidget(self.status_lbl)
        layout.addLayout(row)

        # Table (headers will be set dynamically per-arch)
        self.table = QTableWidget(0, 0)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        try:
            self.table.setAlternatingRowColors(True)
        except Exception:
            pass
        try:
            self.table.setWordWrap(False)
        except Exception:
            pass
        # Sorting will be enabled after headers are set
        # Hide sequential row numbers; keep only syscall number column
        try:
            self.table.verticalHeader().setVisible(False)
        except Exception:
            pass
        # Header resize helper will be applied after headers are known
        self._QHeaderView = None
        try:
            from PySide6.QtWidgets import QHeaderView as _HV  # type: ignore
            self._QHeaderView = _HV
        except Exception:
            try:
                from PySide2.QtWidgets import QHeaderView as _HV  # type: ignore
                self._QHeaderView = _HV
            except Exception:
                self._QHeaderView = None
        layout.addWidget(self.table, 1)

        # Events
        try:
            self.btn_refresh.clicked.connect(self.reload)
            self.search_edit.textChanged.connect(self._apply_filter)
            self.table.cellDoubleClicked.connect(self._on_double_click)
            self.table.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table.customContextMenuRequested.connect(self._on_context_menu)
        except Exception:
            pass

        # Initial load is managed by main window to avoid errors on unsupported arch

    def reload(self) -> None:
        arch = self._get_arch() or "x86_64"
        try:
            headers, table_rows = load_syscall_table(arch)
        except Exception as e:
            QMessageBox.warning(self, "Syscalls", f"Failed to load syscalls for {arch}:\n{e}")
            headers, table_rows = [], []
        # Remove 'references' column and simplify header 'SYSCALL NAME' -> 'Name'
        ref_idx = None
        for i, h in enumerate(headers):
            if isinstance(h, str) and h.strip().lower() == 'references':
                ref_idx = i
                break
        hdrs = []
        for i, h in enumerate(headers):
            if ref_idx is not None and i == ref_idx:
                continue
            if isinstance(h, str) and h.strip().lower() == 'syscall name':
                hdrs.append('Name')
            else:
                hdrs.append(h)
        # Filter table rows to drop the references column
        filtered_rows: List[List[str]] = []
        for r in table_rows:
            if len(r) < len(headers):
                r = r + [''] * (len(headers) - len(r))
            filtered_rows.append([c for j, c in enumerate(r[:len(headers)]) if j != ref_idx])
        # Configure headers and resizing
        try:
            self.table.setColumnCount(len(hdrs))
            if hdrs:
                self.table.setHorizontalHeaderLabels(hdrs)
            # Enable sorting now that headers exist
            self.table.setSortingEnabled(True)
            if self._QHeaderView:
                hh = self.table.horizontalHeader()
                # Fit all columns to the longest cell (no stretching)
                for i in range(len(hdrs)):
                    hh.setSectionResizeMode(i, self._QHeaderView.ResizeToContents)  # type: ignore
                try:
                    hh.setStretchLastSection(False)
                except Exception:
                    pass
        except Exception:
            pass
        # Store full table and a simplified model for snippet generation
        self._headers = hdrs
        self._table_rows = filtered_rows
        try:
            # After removing 'references', args are columns 3..8 (NR=0, Name=1, Reg=2)
            self._rows = [
                Syscall(nr=int(r[0]), name=r[1], args=[c for c in r[3:9] if c and c not in ('-', '–')])
                for r in filtered_rows if len(r) >= 2 and r[0].strip().isdigit()
            ]
        except Exception:
            self._rows = []
        # Populate and apply current filter
        self._populate_table(filtered_rows)
        self._apply_filter(self.search_edit.text())

    def _populate_table(self, rows: List[List[str]]) -> None:
        # Populate raw list-of-lists into the table widget
        try:
            prev_sort = self.table.isSortingEnabled()
            if prev_sort:
                self.table.setSortingEnabled(False)
        except Exception:
            prev_sort = False
        self.table.setRowCount(0)
        for rdata in rows:
            r = self.table.rowCount()
            self.table.insertRow(r)
            for c, val in enumerate(rdata):
                if c == 0:
                    # Ensure NR column sorts numerically
                    self.table.setItem(r, c, self._IntItem(val))
                else:
                    self.table.setItem(r, c, QTableWidgetItem(val))
        # Auto-size pass
        try:
            self.table.resizeColumnsToContents()
        except Exception:
            pass
        # Restore sorting
        try:
            if prev_sort:
                self.table.setSortingEnabled(True)
        except Exception:
            pass

    def _populate(self, rows: List[Syscall]) -> None:
        # Temporarily disable sorting during population for performance/consistency
        try:
            prev_sort = self.table.isSortingEnabled()
            if prev_sort:
                self.table.setSortingEnabled(False)
        except Exception:
            prev_sort = False
        self.table.setRowCount(0)
        arch_key = canonical_arch(self._get_arch() or "") or ""
        favs = self._favorites.get(arch_key, set())
        for sys in rows:
            r = self.table.rowCount()
            self.table.insertRow(r)
            fav_cell = QTableWidgetItem("★" if sys.nr in favs else "")
            try:
                fav_cell.setTextAlignment(Qt.AlignCenter)
            except Exception:
                pass
            self.table.setItem(r, 0, fav_cell)
            self.table.setItem(r, 1, QTableWidgetItem(str(sys.nr)))
            self.table.setItem(r, 2, QTableWidgetItem(sys.name))
            self.table.setItem(r, 3, QTableWidgetItem(", ".join(sys.args)))
            self.table.setItem(r, 4, QTableWidgetItem(sys.ret or ""))
            self.table.setItem(r, 5, QTableWidgetItem(sys.notes or ""))
        # Auto-size pass
        try:
            self.table.resizeColumnsToContents()
        except Exception:
            pass
        # Restore sorting and keep current sort order
        try:
            if prev_sort:
                self.table.setSortingEnabled(True)
        except Exception:
            pass
        # Update status label
        try:
            self.status_lbl.setText(f"{len(rows)} / {len(self._rows)}")
        except Exception:
            pass

    def _apply_filter(self, text: str) -> None:
        q = (text or "").strip().lower()
        rows = list(self._table_rows) if hasattr(self, '_table_rows') else []
        if q:
            rows = [r for r in rows if q in (" | ".join(r).lower())]
        self._populate_table(rows)
        # Update status
        try:
            total = len(self._table_rows)
            self.status_lbl.setText(f"{len(rows)} / {total}")
        except Exception:
            pass

    def _on_double_click(self, row: int, col: int) -> None:
        if not self._insert_asm:
            return
        try:
            nr_item = self.table.item(row, 0)
            name_item = self.table.item(row, 1)
            if not nr_item or not name_item:
                return
            nr = int(nr_item.text())
            name = name_item.text()
        except Exception:
            return
        # Build Syscall from row
        try:
            vals = [self.table.item(row, c).text() if self.table.item(row, c) else '' for c in range(self.table.columnCount())]
        except Exception:
            vals = []
        # After removing 'references', args are indices 3..8
        args = [c for c in (vals[3:9] if len(vals) >= 9 else []) if c and c not in ('-', '–')]
        sys_e = Syscall(nr=nr, name=name, args=args)
        arch = self._get_arch() or "x86_64"
        commented = (self.style_combo.currentText() != "Minimal")
        snippet = format_asm_snippet(sys_e, arch, commented=commented)
        try:
            self._insert_asm(snippet)
        except Exception:
            pass

    def _on_context_menu(self, pos):
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return
        row = idx.row()
        try:
            nr_item = self.table.item(row, 0)
            name_item = self.table.item(row, 1)
            if not nr_item or not name_item:
                return
            nr = int(nr_item.text())
            name = name_item.text()
        except Exception:
            return
        arch = self._get_arch() or "x86_64"
        # Build Syscall object from current table row (for snippet generation)
        try:
            vals = [self.table.item(row, c).text() if self.table.item(row, c) else '' for c in range(self.table.columnCount())]
        except Exception:
            vals = []
        # After removing 'references', args are indices 3..8
        args = [c for c in (vals[3:9] if len(vals) >= 9 else []) if c and c not in ('-', '–')]
        sys_e = Syscall(nr=nr, name=name, args=args)
        menu = QMenu(self)
        act_copy_name = menu.addAction("Copy name")
        act_copy_nr = menu.addAction("Copy number")
        act_copy_snip = menu.addAction("Copy snippet")
        # No favorites toggling in strict table mode
        act = menu.exec(self.table.viewport().mapToGlobal(pos))
        if not act:
            return
        try:
            import pyperclip  # type: ignore
            clipboard_set = lambda s: pyperclip.copy(s)
        except Exception:
            # Fallback to Qt clipboard when available
            try:
                from PySide6.QtWidgets import QApplication as _App  # type: ignore
            except Exception:
                try:
                    from PySide2.QtWidgets import QApplication as _App  # type: ignore
                except Exception:
                    _App = None
            def clipboard_set(s: str):
                if _App:
                    _App.clipboard().setText(s)  # type: ignore
        if act == act_copy_name:
            clipboard_set(name)
        elif act == act_copy_nr:
            clipboard_set(str(nr))
        elif act == act_copy_snip:
            commented = (self.style_combo.currentText() != "Minimal")
            clipboard_set(format_asm_snippet(sys_e, arch, commented=commented))
        # no-op for removed favorite action

    def _fav_key(self) -> str:
        return canonical_arch(self._get_arch() or "") or ""

    def _load_favorites(self) -> Dict[str, Set[int]]:
        cfg = load_config()
        fav_map = cfg.get("syscall_favorites") or {}
        out: Dict[str, Set[int]] = {}
        if isinstance(fav_map, dict):
            for k, v in fav_map.items():
                try:
                    out[str(k)] = set(int(x) for x in v)
                except Exception:
                    continue
        return out

    def _save_favorites(self) -> None:
        cfg = load_config()
        ser = {k: sorted(list(v)) for k, v in self._favorites.items()}
        cfg["syscall_favorites"] = ser
        save_config(cfg)

    def _toggle_favorite(self, nr: int) -> None:
        key = self._fav_key()
        if not key:
            return
        s = self._favorites.setdefault(key, set())
        if nr in s:
            s.remove(nr)
        else:
            s.add(nr)
        self._save_favorites()
        # Refresh current view
        self._apply_filter(self.search_edit.text())
