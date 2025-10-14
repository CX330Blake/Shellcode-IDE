"""
Shellcode IDE plugin entrypoint for Binary Ninja.

Registers a UI action and opens a PySide2 window that provides:
- Hex/bytes and Assembly editors
- Assemble/Disassemble actions via BN API (when available)
- Basic byte statistics and multi-format export preview

Note: This plugin is designed to run inside Binary Ninja where the Python
environment includes PySide2 and the `binaryninja` API. When imported outside
BN, the module will not auto-run; you can still import and instantiate the
window for UI development if PySide2 is available.
"""

from __future__ import annotations

import sys
from typing import Optional


def _in_binary_ninja() -> bool:
    try:
        import binaryninja  # noqa: F401
        return True
    except Exception:
        return False


def _register_bn_actions():
    """Register UI actions and a Tools menu entry in Binary Ninja.

    This avoids hard dependency at import-time when developing outside BN.
    """
    try:
        import binaryninja as bn
        from binaryninja import PluginCommand
        from binaryninjaui import UIAction, Menu, UIActionHandler
    except Exception:
        # Not running in BN UI, nothing to register
        return

    def open_window(_context):
        from .ui.main_window import ShellcodeIDEWindow

        # Create and show a top-level window. BN bundles the Qt app instance.
        win = ShellcodeIDEWindow(parent=None, bn_api=bn)
        win.show()

    action_name = "Shellcode IDE"
    UIAction.registerAction(action_name)
    # Bind using a UIAction wrapper; BN expects a UIAction instance, not a raw function
    UIActionHandler.globalActions().bindAction(action_name, UIAction(open_window))

    # Register a Plugins menu entry: Plugins -> Shellcode IDE -> Open
    # Using PluginCommand with a namespaced label creates the submenu structure.
    PluginCommand.register(action_name, "Open the Shellcode IDE window", lambda bv: open_window(None))


def launch_standalone():
    """Launch the Shellcode IDE in standalone mode if PySide2 is available.

    This is primarily for UI development outside of Binary Ninja.
    """
    # Try PySide2 then PySide6 for standalone
    app_mod = None
    try:
        from PySide2.QtWidgets import QApplication  # type: ignore
        app_mod = "PySide2"
    except Exception:
        try:
            from PySide6.QtWidgets import QApplication  # type: ignore
            app_mod = "PySide6"
        except Exception as exc:
            print("PySide2/PySide6 is required for standalone launch:", exc)
            sys.exit(1)

    from .ui.main_window import ShellcodeIDEWindow

    app = QApplication.instance() or QApplication(sys.argv)
    win = ShellcodeIDEWindow(parent=None, bn_api=None)
    win.show()
    try:
        rc = app.exec()
    except Exception:
        rc = app.exec_()
    sys.exit(rc)


# Register with BN when imported inside its runtime
if _in_binary_ninja():
    _register_bn_actions()
