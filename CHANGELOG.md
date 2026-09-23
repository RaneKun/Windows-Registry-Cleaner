# 📋 Changelog

All notable changes to Windows Registry Cleaner will be documented in this file.

---

## [v1.0.0] - 2026-09-24

### 🎉 Initial Release

The first public version of Windows Registry Cleaner, built around a single principle: **never change anything you can't prove, preview, and undo**.

---

### ✨ Features

#### 🧹 Clean Tab — Find and Remove Broken Registry Entries

Nine independent scan categories, each opt-in:

- **Leftover uninstall entries** — apps whose uninstaller, install folder AND icon are all provably gone. MSI products, updates, system components and hidden entries are never flagged.
- **Stale shared-DLL counts** — SharedDLLs reference counts for files that no longer exist.
- **Broken application paths** — App Paths entries whose program no longer exists.
- **Broken startup entries** — Run / RunOnce entries pointing at missing programs. Items you disabled in Task Manager / Settings are skipped via StartupApproved.
- **Stale program-name cache** — MUI cache entries for programs that no longer exist.
- **Missing font files** — Font entries pointing at full paths outside Windows that no longer exist.
- **Orphaned file associations** — Extensions pointing to a dead ProgID, or ProgIDs whose `open` commands all point to missing programs.
- **Dead right-click menu entries** — Shell-extension handlers whose COM server DLL is provably missing, and static verbs whose program is gone.
- **⚠ Stale network history** — Remembered network locations in Explorer's TypedPaths, Map Network Drive MRU and MountPoints2. **Listed unticked** because this is history you may have created on purpose. Explorer can freeze for many seconds when one of these servers is unreachable, so cleaning them is useful — but only you can decide.

#### 🛡️ Safety Model

Every write operation follows the same strict order:

1. **Re-validate** every entry against its original findings (drives may have been plugged in, apps installed)
2. **Snapshot** exactly what's about to change into an in-memory plan
3. **Write an undo `.reg` file** to `<backup>\Undo\`
4. **Read it back** and compare entry by entry against what was meant to be written
5. **Abort with nothing changed** if the read-back check fails
6. Only then apply the changes

Repeated undo-check failures on the same entries (three times in a session) unlock a **"Continue anyway (risky!)"** option — the unverified undo file is kept, and the deletion proceeds. Every attempt is logged.

#### 💾 Backup Tab

One-click full-registry backup:

- Exports HKEY_LOCAL_MACHINE and HKEY_USERS as plain-text `.reg` files into a time-stamped folder
- Skips `HARDWARE` (volatile), `SAM` and `SECURITY` (protected) — documented in `backup-info.txt` alongside the exports
- Uses Windows' own `reg export` first; falls back to a built-in streaming exporter (skipping unreadable keys) if `reg.exe` fails
- Requires at least 3 GB free space, and cleans up the partial folder if cancelled mid-way
- Memory-efficient: streams the output, never holds the whole registry in RAM

#### 🛠️ Restore Defaults Tab

Curated repairs of well-known Windows defaults, never a blanket reset:

- **Policy locks** — `DisableTaskMgr`, `DisableRegistryTools`, `DisableCMD`, `NoControlPanel`. Default state is "not configured", so the repair is to remove the value. Detects domain-joined / Entra-joined / MDM-enrolled PCs and warns before touching these.
- **Critical file associations** — `.exe`, `.lnk`, `.bat`, `.cmd`, `.reg`, `Directory\shell`, `Drive\shell`, `Folder\shell`. A wrong HKCU override is removed; a wrong or missing HKLM value is set back. Deliberate alternatives (e.g. a file-manager replacement) start unticked.
- **Shell folder paths** — Desktop / Documents / Downloads / etc. Only entries that are **provably missing or invalid** are proposed. Working custom paths, network paths, and unresolved variables are never touched.

Every repair is shown as `old value → new value`, and each gets its own undo file before anything changes.

#### 📥 Import .reg Tab

Merge `.reg` files safely:

- **Preview first** — every file is analyzed for what it would create, overwrite or delete, with a preview of the first 400 rows
- **Blocks critical-key deletions** — a hard-coded set of hive roots, top-level containers and well-known critical keys can never be deleted by an import, no matter what the file says
- **Undo file per file** — same write-and-verify safety model as the other tabs. The streamed undo file is verified **entry by entry** via a fingerprint of every entry written, not just by counting entries
- **Uses Windows' own `reg import`** — no custom merge logic to get wrong

#### 🔄 Restart Advice

Rather than always or never asking for a restart, each finished operation produces a **weighted score** based on which kinds of change were made:

- `0` — takes effect at once (broken-entry cleanup, MUI cache, shared-DLL counts)
- `1` — programs already running may keep the old value (file associations, context menus)
- `3` — read at sign-in (shell folders, policies, sign-in settings)
- `7` — only read while Windows boots (services, drivers, `HKLM\SYSTEM`)

Scores are added up across the distinct kinds of change. Below the threshold: "No restart is needed". Above it: "recommended", then "strongly recommended". If Windows **already** has a restart pending (from updates or other software), a restart is at least "recommended". When a restart is advised, the finished box offers **Restart Now** (with a 30-second countdown so you can cancel with `shutdown /a`) or **Restart Later**.

#### 🎨 Interface

- Four tabs, one shared progress bar, one shared status line
- Comic Sans MS UI matching the other RaneKun tools
- Windows accent colour integration
- Non-blocking UI — every operation runs in a background thread
- Drag-and-drop `.reg` files anywhere on the window
- **Restart as Administrator** button when launched without elevation
- Per-run log file in `%TEMP%`, plus an `error-log 📃.txt` next to the executable
- Log and undo-folder shortcuts in the footer

---

### 🔒 Safety & Compatibility

- **64-bit Python required** on 64-bit Windows — a 32-bit Python would see a redirected filesystem (`System32` → `SysWOW64`) and could report working files as missing. The program refuses to start in that case.
- **Every registry key is opened in the native 64-bit view** (`KEY_WOW64_64KEY`), so WOW6432Node paths are listed explicitly and both bitnesses are covered exactly once.
- **Windows-owned folders are never touched** — paths under `%SystemRoot%`, WindowsApps, Defender, Windows Media Player, Internet Explorer, WindowsPowerShell, etc. are treated as protected, and a missing file there means a damaged Windows component, not something to "fix".
- **Offline / removable / network drives are never treated as broken** — if a drive isn't currently mounted, no entry pointing to it is flagged.
- **UNC paths are never contacted** — the scanner is fully static. A dead network share can never stall the app.

---

### 📦 Build System

- **`build_exe.bat`** — hardened Windows batch script. Enforces Python 3.11+, checks pip availability, uses `python -m pip` (not bare `pip`), checks network only when PyInstaller actually needs installing, moves the finished `.exe` next to the build script, and cleans up `build\`, `dist\` and the `.spec` file automatically.
- **`BUILD_INSTRUCTIONS.md`** — plain-English guide covering prerequisites, the one-step build, testing, sharing, and the common hiccups.
- **No `.py` build method** — the batch script is the only supported build path, to keep the instructions short.

---

### ⚠️ Limitations

Being honest about what this tool does **not** do:

- **It doesn't scan everything.** Categories are deliberately narrow — one for each of the nine areas above. A registry cleaner that walks the whole hive and flags anything it doesn't recognise is exactly the kind of tool that breaks Windows.
- **It won't find much on a healthy PC.** If your scan comes back empty, that's the tool working as designed, not a bug.
- **`SAM` and `SECURITY` can't be backed up as `.reg` files** — those hives are protected by design and would need a different mechanism (like `reg save`) that produces binary files, which can't be merged back with `reg import`.
- **`.reg` files don't store key permissions.** Importing a backup restores the data, not the ACLs.
- **Import never removes keys added after a backup.** `reg import` merges — it doesn't roll back additions.

---

<p align="center">
  <strong>Version 1.0.0 — a registry cleaner that would rather find nothing than break something</strong>
</p>
