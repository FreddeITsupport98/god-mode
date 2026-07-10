# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added
- `God_mode.bat` — Batch launcher that automatically bypasses Execution Policy for this run only. Recommended way to start the suite when scripts are blocked.
- `Launch-SystemShell.bat` — Batch launcher for the SYSTEM shell tool with automatic Execution Policy bypass.
- `Launch-SystemShell.ps1` — Explicit, non-persistent SYSTEM shell launcher for security testing. Uses a temporary scheduled task. No auto-elevation, no silent UAC bypass, no persistence.
- `tests/Test-Suite.ps1` — Comprehensive regression test suite for `God_mode.ps1` and `Launch-SystemShell.ps1`. Validates syntax, script structure, installer/uninstaller logic, and menu integrity without making system changes.
- `changelog.md` — Project changelog initialized.
- Registry ACL hardening helpers: `Harden-RegistryKey` and `Restore-RegistryKey` — apply multi-layer `Deny` ACLs (`SetValue`, `CreateSubkey`, `Delete`, `WriteKey`) to `Administrators`, `Everyone`, and `Authenticated Users` on all DNS, DoH, and God Mode registry keys, plus disable inheritance and strip old deny rules before re-applying.

### Improved
- Project structure reorganized with `tests/` folder for regression scripts.

---

## 2026-07-09 19:00:00 UTC — Initial review

### Notes
- Reviewed `God_mode.ps1` (Enterprise DNS Hijack Protection & Installer Suite).
- Identified existing features: IPv4/IPv6 registry ACL locks, browser DoH GPO restrictions, NTFS self-defense, scheduled task persistence, WMI subscription persistence, integrity checking, interactive menu.
- Identified missing: regression test suite, explicit SYSTEM shell tool, consolidated changelog.

---
