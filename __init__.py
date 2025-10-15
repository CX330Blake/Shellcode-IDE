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
        # PluginCommand is no longer used for opening the window to avoid a disabled Plugins item
        from binaryninjaui import UIAction, Menu, UIActionHandler
    except Exception:
        # Not running in BN UI, nothing to register
        return

    def open_window(_context):
        from .ui.main_window import ShellcodeIDEWindow

        # Create and show a top-level window. BN bundles the Qt app instance.
        win = ShellcodeIDEWindow(parent=None, bn_api=bn)
        win.show()

    # Validator to keep the action always enabled regardless of context
    def always_enabled(_context) -> bool:
        return True

    # Register a global UI action so it appears in the Command Palette
    action_name = "Shellcode IDE"
    UIAction.registerAction(action_name)
    # Bind using a UIAction wrapper; BN expects a UIAction instance, not a raw function
    UIActionHandler.globalActions().bindAction(action_name, UIAction(open_window, always_enabled))

    # Add the action to the Plugins menu so it is always clickable
    try:
        # Preferred: add under Plugins -> Shellcode IDE
        Menu.mainMenu("Plugins").addAction(action_name, action_name)
    except Exception:
        try:
            # Fallback signatures for older BN builds
            Menu.mainMenu("Plugins").addAction(action_name)
        except Exception:
            try:
                # Last-resort path notation
                Menu().addAction(f"Plugins\\{action_name}", action_name)
            except Exception:
                pass

    # Do not add under Tools per user request; Plugins menu entry above is sufficient


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
            print("[Shellcode IDE] PySide2/PySide6 is required for standalone launch:", exc)
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
