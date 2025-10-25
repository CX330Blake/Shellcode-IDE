# Shellcode-IDE (v0.1.9)
Author: **CX330Blake**

_This is a short description meant to fit on one line._

## Description:

# Shellcode IDE

A Qt-based Binary Ninja plugin that helps you compose, analyze, optimize, validate, and export shellcode across architectures that Binary Ninja supports. It combines Binary Ninja’s assembler/disassembler with a user-friendly GUI for rapid iteration and safe validation of shellcode for reverse engineering, CTFs, and security research.

- Audience: reverse engineers, CTF players, exploit developers, security researchers
- Status: early development; core assemble/disassemble and UI scaffolding targeted first

---

## Highlights

- Two-way conversion: raw bytes/hex ⇆ assembly text
- Assemble for any Binary Ninja architecture/platform
- Multiple output formats: inline `\x..`, raw hex, C stub, Python stub, Zig stub, Rust stub, Go stub
- Live metadata: byte length, instruction count, null count, endianness, arch
- Configurable bad-pattern detection (e.g., `00`, `0a`, `ff`, sequences, regex)
- Peephole optimizations with preview/confirm (e.g., `push 0` → `xor reg, reg; push reg`, `mov rax, imm8` when safe)
- Validation rules: no variables/labels, no absolute addresses/relocations, no nulls (unless allowed)
- Binary Ninja integration: menu + toolbar + dockable/floating Qt window with shortcuts

---

## Screenshots

(Coming soon)
- Main window with Input/Output panes and live stats
- Validation tab with clickable issues and fix suggestions

---

## Requirements

- Binary Ninja (licensed), with Python API available
- Python 3.8+ (match your Binary Ninja build)
- Qt via PySide2 (Binary Ninja typically bundles PySide2; no manual install required)
- Optional: Capstone/Keystone for fallback dis/assembly (used only if configured)

---

## Installation

You can install as a user plugin. Typical plugin directories:

- macOS: `~/Library/Application Support/Binary Ninja/plugins`
- Linux: `~/.binaryninja/plugins`
- Windows: `%APPDATA%\Binary Ninja\plugins`

Manual install:

1. Close Binary Ninja.
2. Copy or clone this repository into your plugins directory as `Shellcode-IDE`.
   - Example (macOS/Linux):
     - `cd "~/Library/Application Support/Binary Ninja/plugins"` (macOS) or `cd ~/.binaryninja/plugins` (Linux)
     - `git clone https://github.com/<you>/Shellcode-IDE.git Shellcode-IDE`
3. Start Binary Ninja. The plugin registers a Tools menu entry and a toolbar icon.

If you’re reading this inside `.../Binary Ninja/plugins/Shellcode-IDE`, you’re set. Restart Binary Ninja to load the plugin, or use “Reload Plugins” if available.

---

## Launching

- Menu: `Tools → Shellcode IDE`
- Toolbar: Shellcode IDE icon
- Docking: Opens as a dockable/floating Qt window

---

## Quick Start

- Disassemble bytes/hex → assembly
  1. Open Shellcode IDE.
  2. Select target `Architecture`/`Platform` (defaults to active view when available).
  3. Paste hex/bytes into the “Hex/Bytes” tab (supports whitespace, `0x` prefixes, and `\x..` forms).
  4. Click “Disassemble”. View assembly in the output panel and stats in the status bar.
  5. Export via the “Formats” tab (copy or save to file).

- Assemble assembly → shellcode
  1. Switch to the “Assembly” tab and enter one instruction per line.
  2. Click “Assemble”. Errors (if any) show inline with line/column info.
  3. Review live stats, run “Optimize” (optional), “Validate”, and export in your preferred format.

---

## Features

- Input/Output
  - Input tabs: “Hex/Bytes”, “Assembly”, with syntax highlighting and paste detection
  - Output tabs: “Disassembly / Assembly Output”, “Formats”, “Validation”, “History”
  - Status bar: arch/platform, length, null count, bad-pattern count, optimization status

- Assemblers & Disassemblers
  - Uses Binary Ninja API: `Architecture.assemble()` and instruction text utilities
  - Disassembly can work in-memory from raw bytes; follows branches best-effort
  - Architecture and platform are user-selectable and default to the active view

- Export Formats
  - Inline: `"\x90\x90\x48..."`
  - Hex: `90 90 48 ...` or `0x90,0x90,...` (selectable)
  - C: minimal runnable C stub (mmap + function pointer)
  - Python: minimal runnable Python stub (mmap + ctypes)
  - Zig: minimal runnable Zig stub (page-alloc + mprotect + function pointer)
  - Rust: minimal runnable Rust stub (mmap + function pointer)
  - Go: minimal runnable Go stub (cgo + mmap + function pointer)
  - Configurable templates: variable names, include length, trailing comma, line wrapping

- Bad-Pattern Detection
  - Patterns as hex bytes (`00`, `0a`, `ff`), byte sequences (`00 00 00`), or regex over hex text
  - Matches list with offsets; click to highlight bytes/assembly
  - Status badge for match count

- Validation Rules
  - No variables/labels or assembler directives that produce relocations
  - No absolute addresses (e.g., `mov rax, 0x7fff...`, `[0xADDR]`)
  - No relocations/unresolved symbols from the assembler
  - No null bytes by default; user can allow via patterns

- Peephole Optimizations (opt-in)
  - `push 0` → `xor reg, reg; push reg` (arch-aware)
  - `mov rax, IMM` → `mov al, IMM` when `IMM` fits and safe
  - Preview changes; accept/reject per transform
  - Safety checks ensure no forbidden bytes/semantics changes; warn on uncertainty

- History & Snippets
  - Save/load named snippets per architecture
  - Persist settings and patterns per user

---

## UI Overview

- Top toolbar: New, Open, Save, Copy, Assemble, Disassemble, Optimize (toggle), Validate
- Left pane: Input tabs (Hex/Bytes, Assembly)
- Right pane: Output (Disassembly/Assembly), Formats, Validation, History
- Bottom status bar: arch/platform, length, nulls, bad-patterns, optimization state

---

## Keyboard Shortcuts (default)

- `Ctrl/Cmd + Enter`: Assemble current Assembly tab
- `Shift + Enter`: Disassemble Hex/Bytes input
- `Ctrl/Cmd + B`: Toggle Optimize preview
- `Ctrl/Cmd + E`: Validate
- `Ctrl/Cmd + C`: Copy current format block

(Shortcuts are subject to change; configurable in a later milestone.)

---

## Safety & Ethics

- The plugin never executes shellcode. It assembles/disassembles and analyzes bytes only.
- Use shellcode exclusively on systems you own or have explicit permission to test.

---

## Configuration & Storage

- Bad patterns, export templates, and user snippets are stored in a plugin-specific config under Binary Ninja’s user data directory (platform-specific).
- A future update will add UI to import/export settings and custom transforms.

---

## Development

- Tech stack: Python 3.8+, Binary Ninja Python API, PySide2
- Recommended workspace layout:

```
Shellcode-IDE/
  shellcode_ide/
    __init__.py              # plugin entrypoint (BN actions, dock widget)
    ui/                      # Qt .ui files and wrappers
    backends/
      bn_adapter.py          # BN assembly/disassembly wrappers
      optimize.py            # peephole passes
      validator.py           # validation checks
    formatters/              # export formatters
  tests/                     # unit tests and sample shellcodes
  README.md                  # this file
  LICENSE                    # MIT recommended
```

### Running & Reloading

- Start Binary Ninja; the plugin registers automatically.
- To iterate on UI/logic: edit files, then restart BN or use “Reload Plugins”.
- Logs and errors: open Binary Ninja’s Log and Python Console to view tracebacks and debug prints.

### Testing

- Tests cover assemble/disassemble round-trips, optimization rules, and validators.
- From the repo root (with BN’s Python available on PATH or `PYTHONPATH`), run:
  - `python -m pytest -q`
- Some tests may require the Binary Ninja API; those will be skipped if the API is unavailable in the current interpreter.

### Coding Style

- Prefer small, composable modules with clear responsibilities
- Keep GUI code thin; push logic to backends
- Add docstrings where behavior isn’t obvious; avoid over-commenting obvious code

---

## Roadmap

- M1 — Core assemble/disassemble: basic GUI, assemble/disassemble, formats, length
- M2 — Validation & bad-patterns: validation pipeline, pattern editor UI
- M3 — Optimize passes: two sample peepholes, preview+apply UX
- M4 — Extensibility: snippets, custom transforms, export templates
- M5 — Polish & tests: full unit tests, docs, sample snippets, CI

---

## Troubleshooting

- “Assemble” fails or produces errors
  - Confirm the selected Architecture/Platform matches your intent
  - Check Binary Ninja version and that its Python environment is used
  - Inspect the Log/Python Console for detailed assembler diagnostics

- Disassembly stops mid-stream
  - The bytes may not decode fully for the selected architecture; verify input and arch mode (e.g., 32-bit vs 64-bit)

- UI issues (blank window or missing Qt)
  - Binary Ninja bundles Qt/PySide2; ensure you’re not shadowing it with another Qt install
  - Restart Binary Ninja and check the Log for exceptions

- Validation flags “relocations”
  - Remove labels/symbols/absolute addresses from assembly; ensure position-independent constructs

---

## FAQ

- Does the plugin execute shellcode?
  - No. It never runs user-provided bytes; it only assembles/disassembles and analyzes.

- Can I add my own optimizations?
  - Planned: a small JSON/DSL for custom peepholes with safety checks.

- Which architectures are supported?
  - Any architecture that Binary Ninja supports and exposes via its Python API on your installation.

---

## Contributing

Contributions are welcome! Please open issues for bugs/ideas and submit focused PRs.

- Keep changes minimal and scoped to the task
- Match the existing code style and structure
- Include tests for new logic where practical

---

## License

MIT (recommended). See `LICENSE` once added to the repository.

---

## Acknowledgments

- Binary Ninja team and community for the APIs and plugin ecosystem
- Inspiration from common shellcode workflows and CTF tooling



## Installation Instructions

### Darwin

macOS:
cd "~/Library/Application Support/Binary Ninja/plugins"
git clone https://github.com/CX330Blake/Shellcode-IDE Shellcode-IDE
Restart Binary Ninja or use "Reload Plugins".

### Linux

Linux:
cd ~/.binaryninja/plugins
git clone https://github.com/CX330Blake/Shellcode-IDE Shellcode-IDE
Restart Binary Ninja or use "Reload Plugins".

### Windows

Windows (PowerShell or CMD):
cd "%APPDATA%\Binary Ninja\plugins"
git clone https://github.com/CX330Blake/Shellcode-IDE Shellcode-IDE
Restart Binary Ninja or use "Reload Plugins".

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

* 3164



## Required Dependencies

The following dependencies are required for this plugin:

 * pip - pygments>=2.12, keystone-engine>=0.9.2
 * apt - 
 * installers - 
 * other - Requires Binary Ninja with Python API (licensed)., PySide2 is bundled with Binary Ninja; no extra install typically required.


## License

This plugin is released under a MIT license.
## Metadata Version

2
