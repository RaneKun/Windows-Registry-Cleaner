# 🧹 Windows Registry Cleaner

<p align="center">
  <img src="windows_registry_cleaner.ico" alt="Windows Registry Cleaner Icon" width="128" height="128">
</p>

<p align="center">
  <strong>Find and repair the registry carefully — with previews, undo files, and a strict allow-list that never touches anything you didn't explicitly approve.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%2010%2F11-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Language-Python%203.11-yellow?style=for-the-badge">
  <img src="https://img.shields.io/badge/GUI-PyQt6-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-Free%20for%20Personal%20Use-orange?style=for-the-badge">
  <img src="https://img.shields.io/badge/Safe-Analyze%20before%20cleaning-brightgreen?style=for-the-badge">
</p>

---

<p align="center">
<img width="1004" height="739" alt="Screenshot 2026-09-23 205953" src="https://github.com/user-attachments/assets/2a984853-12f4-420e-a194-3b74303b7abc" />
</p>

<p align="center"><em>Analyze → review → confirm. Every change gets its own undo file.</em></p>

---

## 💡 Why This Exists

Most registry cleaners are either **afraid of their own shadow** (they list hundreds of "problems" but never fix anything) or **recklessly confident** (they delete things that break Windows).

This one takes a third path: it **only ever flags an entry when the target file is provably missing**, shows you exactly what it will do, writes an undo file of exactly what it's about to change, and refuses to touch anything outside a strict allow-list.

- ✅ **Analyze first** — nothing changes until you review the list and click Clean
- ✅ **Undo file written first** — read back and verified before any change happens; abort if it can't be proven correct
- ✅ **Strict allow-list** — a bug in the scanner still can't delete anything outside the approved locations
- ✅ **No blanket resets** — the Restore tab repairs a curated set of critical defaults, never "reset everything"
- ✅ **Open source** — every line of code is right here in the repo

---

## 🚀 Get Started

### Download & Run (Recommended)

1. Grab the latest **`Windows Registry Cleaner.exe`** from the [Releases](https://github.com/RaneKun/Windows-Registry-Cleaner/releases) page
2. **Right-click → Run as administrator** *(required — writing to the registry needs elevation)*
3. Choose what to scan on the **Clean** tab and click **Analyze 🔍**
4. Review the list, tick what you want removed, and click **Clean Selected 🧹**

That's it. The first run typically finds a handful of genuinely-broken entries — usually fewer than you'd expect, because it's deliberately conservative.

---

## 🎯 What It Does

Four tabs, four jobs:

### 🧹 Clean — find and remove broken registry entries

Everything below is only flagged when the target is **provably** missing on a currently-mounted local drive.

| Category | What it finds |
|----------|--------------|
| **Leftover uninstall entries** | Apps in "Installed apps" whose uninstaller, folder AND icon are all gone |
| **Stale shared-DLL counts** | SharedDLLs reference counts for files that no longer exist |
| **Broken application paths** | App Paths entries whose program is gone |
| **Broken startup entries** | Run / RunOnce entries pointing at missing programs (skips ones you disabled) |
| **Stale program-name cache** | MUI cache entries for programs that no longer exist |
| **Missing font files** | Font entries pointing at font files that aren't there |
| **Orphaned file associations** | Extensions pointing to a dead program type, or program types whose programs are all gone |
| **Dead right-click menu entries** | Context-menu handlers whose DLL is missing |
| **⚠ Stale network history** | Remembered network locations in Explorer that can stall it — *listed unticked, your call* |

### 💾 Backup — save the whole registry

One-click export of HKEY_LOCAL_MACHINE and HKEY_USERS as plain-text `.reg` files in a time-stamped folder. Skipped on purpose: `HARDWARE` (volatile), `SAM` and `SECURITY` (protected hives).

### 🛠️ Restore Defaults — repair a curated set of critical settings

Never a "reset everything" button. Each repair is shown as `old value → new value` and only proposed when the registry currently differs from the known default:

| Area | What it repairs |
|------|-----------------|
| **Policy locks** | Task Manager / Registry Editor / Command Prompt / Control Panel locks left behind by malware or old tweak tools |
| **Critical file associations** | Only `.exe`, `.lnk`, `.bat`, `.cmd`, `.reg`, folders and drives — your other default apps are never touched |
| **Shell folder paths** | Desktop / Documents / Downloads / etc. when they're missing or invalid (working custom paths are left alone) |

### 📥 Import .reg — merge registry files safely

Drag-and-drop or browse. Every import is **previewed first** and gets its own undo file before Windows' own `reg import` runs. Critical-key deletions in the file are blocked outright.

---

## 🛡️ Is It Safe?

**Yes — and here's what keeps it that way:**

- 🎯 **"Provably missing" is the bar** — an entry only counts as broken when a path check comes back `MISSING` on a mounted local fixed drive. Access-denied, network paths, offline drives and unresolved variables all count as `UNKNOWN` and are skipped
- 🔍 **Analyze first** — you see the full list before anything changes
- ↩️ **Undo files, verified** — before any change, an undo `.reg` file containing exactly what's about to be modified is written, read back, and compared against what was meant to be written. If the check fails, the operation **aborts with nothing changed**
- 🛡️ **Strict allow-list** — every delete is re-checked against a hard-coded list of exactly which key patterns are allowed per category. Even a bug in the scanner can't reach outside those locations
- 🔄 **Re-validated at delete time** — every entry is checked one more time right before deletion, in case a drive was plugged in or an app installed since the scan
- 🚫 **Never touches** Windows-owned folders, MSI products, protected extensions, COM/ActiveX/TypeLib data, or your chosen default apps
- 🧠 **Deliberate-history options start unticked** — network history and file-manager style associations need your explicit per-row tick

### A Note About Antivirus

Some antivirus software may flag the `.exe` as suspicious. **This is a false positive** — it happens with any executable that bundles a Python runtime and requires admin rights. Since the full source is public, you can verify exactly what the tool does, or build the `.exe` yourself in a few minutes.

---

## ✨ Features at a Glance

- **Non-blocking UI** — everything runs in a background thread; the window never freezes
- **Restart advice** — after each operation, you're told whether a restart is actually needed, with an optional "Restart Now" countdown
- **Live operation log** — every action is timestamped and written to a per-run log file
- **Managed-PC warnings** — if the PC looks domain-joined or Intune-managed, policy-lock repairs get an extra confirmation
- **Restart as Administrator** — one click to relaunch elevated if you started without it
- **Colour-matched to Windows** — uses your system accent colour for the UI
- **Fully [open source](LICENSE.md)**

---

## 🔧 Build It Yourself

Prefer to compile from source rather than trust a downloaded `.exe`? It takes a couple of minutes.

### What you need
- **Python 3.11 or newer** (64-bit — 32-bit Python on 64-bit Windows is refused, because filesystem redirection would produce false "missing file" results)
- These files in the same folder:
  - `windows_registry_cleaner.py`
  - `windows_registry_cleaner.ico` (optional but recommended)
  - `build_exe.bat`

### Steps
1. **Double-click `build_exe.bat`**
2. Wait 2-5 minutes while it builds
3. Your **`Windows Registry Cleaner.exe`** appears in the same folder

The build script handles everything — checking Python version, installing PyInstaller if needed, building, moving the finished `.exe` into place, and cleaning up all temporary build files.

📖 **Full details:** see [`BUILD_INSTRUCTIONS.md`](BUILD_INSTRUCTIONS.md)

---

## 🐛 Troubleshooting

| Problem | Fix |
|---------|-----|
| **"Limited mode" shown at the top** | The program isn't elevated. Click **Restart as Administrator** to enable write buttons. |
| **Analyze finds nothing** | That's expected on a healthy PC. The scanner is deliberately strict about what counts as "broken". |
| **Some entries get skipped during cleaning** | Normal — files can be locked, or a path became reachable again between scan and clean. The log explains each skip. |
| **WinSxS-style operations take a long time** | Backups of the whole registry take a few minutes. Let them run; Cancel is available if you need it. |
| **Antivirus blocked the .exe** | False positive — see the "[Note About Antivirus](https://github.com/RaneKun/Windows-Registry-Cleaner/edit/main/README.md#a-note-about-antivirus)" section above. |
| **Windows Defender "unknown publisher" warning** | Click "More info" → "Run anyway". The tool isn't code-signed (that costs money), but the source is public. |

---

## 💬 Feedback & Support

- 🐛 **Found a bug?** [Open an issue](https://github.com/RaneKun/Windows-Registry-Cleaner/issues)
- 💡 **Have a suggestion?** [Start a discussion](https://github.com/RaneKun/Windows-Registry-Cleaner/discussions)
- ⭐ **Find it useful?** Star the repo — it helps others find it too

---

## 📜 License

**Free for personal use. No selling. Keep it credited.**

**You can:** use it, read the source, modify it, share it, learn from it  
**You can't:** sell it, use it commercially without permission, claim it as your own  
**You must:** credit RaneKun and keep modifications open source

Full license text is in the [`LICENSE`](LICENSE.md) file.

---

## 🙏 Credits

**Built with** [Python](https://www.python.org/) · [PyQt6](https://www.riverbankcomputing.com/software/pyqt/) · [PyInstaller](https://pyinstaller.org/)

**Inspired by** the many registry cleaners that either delete too much or too little — and the many that don't tell you what they're about to do.

Sources for every hard-coded default (exefile command, policy value names, shell folder paths, restart indicators, MultiSZ parsing) are listed in the module docstring at the top of `windows_registry_cleaner.py`.

---

## ⚠️ Disclaimer

Provided as-is, without warranty. Registry editing is inherently sensitive — while every safeguard in this tool exists to keep changes small, verified and reversible, always keep a backup of anything important. The author isn't responsible for data loss or system issues arising from use.

---

<p align="center">
  <strong>Made with ❤️ by RaneKun</strong>
</p>

<p align="center">
  <sub>Analyze. Review. Confirm. Undo if needed. 🧹✨</sub>
</p>
