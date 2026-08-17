# Ponytail Audit — firewall-tui

Whole-repo scan for over-engineering, dead code, and shrink opportunities.
Complexity only; correctness, security, and performance are out of scope.

## Findings (ranked, biggest cut first)

1. **delete: `generate_preview()` — dead code, never called.** The actual
   preview (`p`) runs the `__firewall` type manifest directly via
   `_preview_worker()`. This function (and its `rules_in_section` import
   from parser) is leftover from before the manifest-based preview landed.
   [fwtui/expand.py:579-632]

2. **delete: `rules_sections()` — dead code, never called.** Defined in
   parser.py at line 178; no caller anywhere in the codebase. [fwtui/parser.py:178-182]

3. **delete: `FW_DIR_DEFAULT` — unused constant.** Defined at app.py:56 but
   never referenced; the actual default lives in config.py's `DEFAULTS`.
   [fwtui/app.py:56]

4. **delete: unused `Screen` import.** `from textual.screen import ModalScreen, Screen`
   — only `ModalScreen` is used; `Screen` is imported but never referenced
   (the single occurrence in the file is inside a docstring comment).
   [fwtui/app.py:43]

5. **shrink: `rules_in_section` import in expand.py becomes dead after #1.**
   After removing `generate_preview()`, the import `rules_in_section` on
   line 15 of expand.py is no longer needed (it was only used by
   `generate_preview`). The import becomes: `from .parser import global_dict`.
   [fwtui/expand.py:15]

## Net

**net: −42 lines, −0 deps possible.**
