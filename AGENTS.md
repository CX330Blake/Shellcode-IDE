# Shellcode IDE — agent.md

## Project overview

**Name:** Shellcode IDE

**Purpose:** A Binary Ninja plugin with a Qt GUI that helps users compose, analyze, optimize, and export shellcode across all architectures and platforms Binary Ninja supports. It combines Binary Ninja's binary/assembly APIs with a user-friendly GUI for rapid iteration and safe validation of shellcode suitable for exploitation and CTF use.

**Audience:** Reverse engineers, CTF players, exploit developers, and security researchers.

---

## Goals and scope

1. Provide two-way conversion between raw shellcode (hex / bytes) and assembly text.
2. Enable editing assembly and producing shellcode for any architecture supported by Binary Ninja.
3. Support multiple output formats for generated shellcode (inline asm, hex string, C array, Python bytes literal, Zig `[]u8`).
4. Show shellcode metadata (byte length, null-byte count, architecture, endianness).
5. Provide configurable bad-pattern detection (e.g. `\x00`, `\x0a`, `\xff`, sequences) and present results live.
6. Provide automatic peephole optimizations (user-toggleable) including the example transforms:

    - replace `push 0` → `xor reg, reg; push reg` (or `push 0x0` -> optimized sequence depending on arch)
    - replace `mov rax, 60` → `mov al, 60` when safe

7. Validate shellcode against constraints:

    - no variable references (no symbolic/local variables in assembly)
    - no direct absolute memory addresses or relocations
    - no null bytes unless allowed by user

8. Expose the plugin as a Binary Ninja toolbar/menu item and a floating Qt window with keyboard shortcuts.

---

## High-level architecture

1. **Frontend (Qt GUI):** Built with PySide2 or PyQt5 (choose one; PySide2 recommended because Binary Ninja typically bundles PySide2). GUI provides:

    - Input panel: paste raw hex or type assembly.
    - Output panel: shows generated shellcode in chosen format with copy buttons.
    - Live stats bar: architecture, length, null-count, bad-pattern count.
    - Bad-patterns config dialog: add/remove patterns (regex or hex bytes).
    - Optimization toggles and a "Run optimizer" button.
    - Validation / lint tab: shows violations with clickable items to jump to assembly line.
    - History / snippets manager: save named snippets per architecture.

2. **Backend (Binary Ninja plugin logic):** Uses Binary Ninja Python API for assemble/disassemble/architecture/platform discovery and for integration into the BN UI. Responsibilities:

    - Parse input (hex → bytes, assembly → tokens).
    - Call `Architecture.assemble()` for requested architecture and platform to get bytes from assembly.
    - Disassemble bytes into assembly text using Binary Ninja's `Architecture.get_instruction_text` or `BinaryView.get_disassembly` utilities.
    - Check produced bytes and assembly for rules (no addresses, no variables, no nulls).
    - Perform peephole optimizations on assembly text using pattern-match and rewrite passes (architecture-aware).

3. **Exporter module:** Formats bytes into: inline (escaped `\x..`), raw hex, C-style `unsigned char shellcode[] = {0x..}`, python-style `b"\x.."` or `bytes([...])`, and Zig-style `[]u8{0x..}`. Provide copy-to-clipboard and a save-to-file feature.

---

## Binary Ninja integration details

- **Plugin registration:** register plugin as a `UIAction` and a `DockWidget` / `Window` so it can open independently of a BinaryView. Provide menu entry under `Tools -> Shellcode IDE` and a toolbar icon.

- **Architecture / Platform selection:** Query `binaryninja.Architecture` and `binaryninja.Platform` registry: list all registered architectures and platforms. Default to the active BinaryView architecture/platform but allow the user to override.

- **Assemble flow:**

    1. User selects architecture+platform.
    2. `Architecture.assemble(asm_text, addr=0)` → returns bytes or raises `AssemblyError` with diagnostics.
    3. Show bytes, length, and formatted outputs.

- **Disassemble flow (hex -> asm):**

    1. Parse hex input into `bytes`.
    2. Create a temporary `BinaryView` backed by the bytes (in-memory) or use `Architecture.get_instruction_text` repeatedly with a cursor to decode instructions until the bytes are consumed.
    3. Render the disassembly in the output panel.

- **Error handling:** Show assembly errors with line/column if available. For disassembly, show where decoding failed.

---

## GUI details (UX)

### Main window layout

- **Top toolbar:** New, Open, Save, Copy, Assemble, Disassemble, Optimize (toggle), Validate.
- **Left pane (Input):** Tabs: "Hex/Bytes" and "Assembly". Each tab supports syntax highlighting (assembly using BN language or a simple highlighter). Paste detectors will auto-detect hex or base64.
- **Right pane (Output & Reports):** Tabs: "Disassembly / Assembly Output", "Formats", "Validation", "History".
- **Bottom status bar:** Selected architecture / platform, shellcode length, null byte count, bad pattern count, optimization status.

### Format output buttons

Each format output block includes: formatted text area, a Copy button, Save button, and a small preview showing the first N bytes.

### Validation tab

List of checks with pass/fail icons. Clicking an issue highlights the relevant line in the assembly editor and offers a fix-suggestion (e.g., replace `push 0` suggestion).

---

## Features in detail

### 1. Generate assembly from raw shellcodes (hex)

- Input: hex string, with optional whitespace, `0x` prefixes allowed; also accept `\x..` input.
- Output: architecture-aware assembly listing. Optionally try to follow relative branches when possible (best effort).
- Provide a toggle: "disassemble as 32-bit vs 64-bit" — select architecture explicitly.

### 2. Generate shellcodes from assembly language

- Accept BN-style assembly text with one instruction per line.
- Use `Architecture.assemble()` and show errors inline.
- Support pseudoinstructions or directives only if architecture supports them.

### 3. Support all platforms Binary Ninja supports

- Dynamically enumerate `Architecture` and `Platform` registries in Binary Ninja and expose to the user.
- Respect calling conventions / endianness where relevant. For example, when optimizing operands assume endianness and operand sizes from the selected architecture.

### 4. Output formats

- **Inline:** `"\x90\x90\x48..."` – a single escaped string.
- **Hex:** `90 90 48 ...` or `0x90,0x90,...` selectable.
- **C-style:** `unsigned char shellcode[] = {0x90, 0x90, 0x48, ...}; size_t shellcode_len = sizeof(shellcode);`
- **Python-style:** `shellcode = b"\x90\x90\x48..."` or `shellcode = bytes([0x90, 0x90, 0x48])`.
- **Zig-style:** `const shellcode: [ ]u8 = .{0x90, 0x90, 0x48, ...};` (use Zig literal appropriate syntax).

Allow user to customize small template (variable names, whether to include length var, tail comma, line width wrapping).

### 5. Show shellcode length

Always display total bytes and instruction count. Show null byte count and locations (byte offsets) if any.

### 6. Bad-pattern detection (configurable)

- Allow user to add patterns as:

  - Raw hex bytes (eg. `00`, `0a`, `ff`) -- pattern matches any occurrence of those bytes.
  - Regular expressions over the hex string.
  - Byte sequences (eg. `00 00 00`).

- The UI lists matches with offsets; clicking a match highlights the corresponding bytes/assembly instruction.
- Badge indicator in status bar for number of pattern matches.

### 7. Auto-optimize (peephole) feature

- **Design:** apply architecture-aware peephole transforms to assembly before assembling. Transform rules are simple rewrite patterns with validation.

- **Provided transforms (initial):**

    1. `push 0` → `xor reg, reg; push reg` (choose appropriate register size for architecture; if `push 0` intends pushing immediate 0, prefer `push 0`→ `xor rax, rax; push rax` for 64-bit? The plugin will choose smallest register that is legal for the target and that doesn't break calling convention in a trivial shellcode context.)
    2. `mov rax, IMM` where `IMM fits in 8-bit` → `mov al, IMM` (detect when no higher bits are needed and when using the smaller encoding reduces null bytes)

- **User control:** toggles for each transform, preview of changes, ability to accept/reject changes.

- **Safety checks:** each transform must confirm it does not introduce forbidden bytes or invalid semantics (e.g., changing operand size that affects higher bytes might change behavior if code later depends on full register value). Plugin will warn when transformation may be unsafe and require user confirmation.

---

## Shellcode validation rules

The plugin will enforce and/or report violations for:

1. **No variables:** Assembly must be position-independent and must not use assembler-level variables/labels that expand to addresses or memory offsets. The plugin will scan for assembler directives, symbolic constants, or local variables and either reject or ask user to rewrite.

2. **No direct absolute addresses:** Detect `mov rax, 0x7ff...` or `mov [0xADDR], ...` patterns and mark them as violations. Relative addressing (`call rel32`, `jmp rel32`, rip-relative loads) is allowed but the UI will warn if absolute addresses appear.

3. **No NULL bytes (\x00):** Flag occurrences by default. User can add exceptions in the bad-pattern list (e.g., allow `\x00` if they explicitly permit).

4. **No relocations / no external symbols:** When assembling with Binary Ninja's assembler, detect if the assembler emitted relocation records or unresolved symbols and reject until resolved.

---

## Security and safety

- Do not execute assembled shellcode locally. The plugin only assembles/disassembles and analyzes — it must never run the produced shellcode.
- Make clear in the UI the legal/ethical warning about using shellcode only on systems you own or authorized testing environments.

---

## Extensibility & configuration

- **Custom transforms:** allow users to add their own peephole rules in a DSL or JSON format: pattern -> replacement with optional safety checks (e.g., "requires register RAX unused").
- **Export templates:** users can define custom export templates for different languages.
- **Snippets library:** save/load snippets per architecture to the plugin's config directory.

---

## Testing

- Provide a test suite (pytest or unittest) for assembler/disassembler round-trips and for each optimization rule. Include a list of canonical sample shellcodes (x86, x64, arm, aarch64, mips if supported) and expected outputs.
- Add unit tests for bad-pattern detection and validation rules.

---

## Implementation roadmap & milestones

1. **M1 — Core assemble/disassemble:** Basic GUI and ability to assemble and disassemble bytes for the active architecture. Expose formats and length display.
2. **M2 — Validation & bad-patterns:** Implement the validation pipeline and configurable bad-pattern lists. Add UI for pattern editing.
3. **M3 — Optimize passes:** Implement the two sample peephole optimizations and the transform framework. Add preview+apply UX.
4. **M4 — Extensibility:** Snippets, custom transforms, export templates.
5. **M5 — Polish & tests:** Add full unit tests, docs, sample snippets, and CI integration.

---

## Dependencies

- Binary Ninja (user must have a licensed copy and the Binary Ninja Python API available).
- Python 3.8+ (match Binary Ninja environment).
- PySide2 or PyQt5 (prefer PySide2 for compatibility with BN UI).
- Optional: `capstone`/`keystone` for fallbacks if BN assembler/disassembler fails (use only as optional enhancements).

---

## Deliverables

- `shellcode_ide/` plugin package with:

  - `__init__.py` plugin entrypoint (register BN actions, create dock widget)
  - `ui/` Qt UI files (+ Python wrappers)
  - `backends/bn_adapter.py` (Binary Ninja assembly/disassembly wrappers)
  - `backends/optimize.py` (peephole passes)
  - `backends/validator.py` (checks)
  - `formatters/` (export formatters)
  - `tests/` (automated tests and sample shellcodes)
  - README with install, usage, and contribution guide
  - LICENSE (MIT recommended)

---

## Example user workflows

1. **Quick disassemble:** Paste `\x48\x31\xff\x57` into "Inline" tab → choose `x86_64` → "Disassemble" → view assembly, length, and formats → copy C-style for payload embedding.

2. **Write & export:** Type assembly in "Assembly" tab → "Assemble" → see bytes and stats → run optimizer → validate (no `00`) → export as Python-style.

3. **Fix a bad byte:** Validator reports `00` at offset 4 → click the issue → editor highlights instruction → plugin suggests a transform or manual rewrite.

---

## Notes & assumptions

- The plugin relies primarily on Binary Ninja's assembly/disassembly; where BN cannot assemble or disassemble certain constructs, the plugin should show helpful diagnostics and optionally fall back to Keystone/Capstone when available.
- Because peephole optimizations can change semantics, every optimization is behind a preview/confirm step and annotated with a safety note.

---

## Appendix: Example peephole rule format (JSON)

```json
{
    "name": "push-zero-to-xor-push",
    "arch": ["x86", "x86_64", "armv7", "armv8"],
    "match": "push 0",
    "replacement": "xor {reg}, {reg}; push {reg}",
    "description": "Replace pushing immediate zero with a zeroed register push to avoid encoding nulls",
    "safety_checks": ["replacement_bytes_contains_no_forbidden_patterns"],
    "weight": 10
}
```

---
