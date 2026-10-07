# 📋 Changelog

All notable changes to Windows Registry Cleaner will be documented in this file.

---

## [v2.0.0] - 2026-10-07

### 🎉 Major Release - Safety You Can See

Nothing about the core principle changed — **analyze first, verify the undo file, change only after that** — but now the program *proves* that principle to you instead of asking you to take it on faith, gives you a way to keep the results list under your own control, and stops nagging you about restarts.

This release adds a **start-up safety self-check**, **user exclusions** that only ever hide findings, a **review panel** that explains every finding before you tick it, a **three-tier restart classification** whose default is *silence*, and a substantial UI redesign built around cards, a statistics bar and a resizable window.

---

### ✨ New Features

#### 🛡️ Start-up Safety Self-Check (New!)
- **The safety machinery is now *run* at start-up on made-up data**, instead of being trusted because it is loaded
- **Six independent checks:**
  - **Allowlist** — one made-up finding per category must be accepted, and forbidden ones (hive roots, system keys, protected types/verbs, the `(Default)` value) must be refused
  - **Delete guards** — hive roots and system key paths must stay protected
  - **Protected paths** — Windows and Program Files folders must be recognised as protected
  - **Undo backup** — made-up values (including quoted text, backslashes, binary, multi-string and `REG_EXPAND_SZ`) round-trip through the real writer, reader and verifier in a throw-away temp folder
  - **Backup folder** — non-critical: verified when a clean actually starts, so a dead network share cannot freeze the window at start-up
  - **Exclusions** — non-critical: a damaged exclusions file is ignored, not fatal
- **Fail-closed by design:** if a **critical** check (allow-list, guards, protected paths, undo system) fails, **cleaning is disabled** — Analyze, the review panel, Backup, Restore and Import preview all keep working
- **The in-memory checks run again right before every clean**, so a problem introduced since start-up stops the clean before anything changes
- **Every check is documented in the log** with `[SAFETY] Self-check: …` and its pass/fail state
- **Implemented by `run_safety_self_check()`**, `SafetyCheck`, `SafetyReport` and one `check_*()` function per check

#### 🔬 Safety Banner
- **A slim banner under the header** shows three live ticks: *Allowlist Protected*, *Undo Backup Created Before Cleanup*, *Review Before Deletion*
- **Each tick is switched off when its self-check could not prove it** — a failed allow-list check turns its chip red, a backup folder that is not writable turns the undo chip amber, and a red banner plus the words "Cleaning disabled" appear when a critical check failed
- **The System Status card carries the full picture** with a row per check (Safety Status, Admin, Exclusions, Restart, Backup folder), each with its own tooltip explaining what it proved
- **`Safety Status` values:** *Healthy*, *Attention needed*, *Cleaning disabled*

#### 🚫 User Exclusions (New!)
- **Highlight any finding and click "Add to Exclusions 🚫"** — it stops appearing in future scan results
- **The Excluded Items section at the bottom of the Clean tab** lists everything you excluded, when you excluded it and the reason the scanner gave at the time; remove rows one by one or clear the whole list
- **Exclusions only ever hide.** They are applied *after* the scan, to the finished list, and only remove rows from what you see:
  - the scanner still checks every finding
  - the allow-list, the delete guards, the re-validation and the clean engine behave exactly as if the feature did not exist
  - a finding whose exclusion was removed comes back **unticked** and has to be ticked deliberately
- **Stored in `windows_registry_cleaner_exclusions.json` next to the program** — human-readable, versioned, checksummed
- **Fails safe:** if the file cannot be loaded safely it is **ignored** (nothing is hidden) and you are warned; a damaged file is moved aside under a new name before a new list is written, so nothing recoverable is ever destroyed
- **Identity is `(category, key path, is-a-value, value name, fingerprint)`**, where the fingerprint is a hash of the evidence the scanner recorded (reason text, re-check paths, re-check ProgID). A different finding that later lands on the same path is *not* silently hidden
- **Implemented by `ExclusionStore`**, `ExclusionRecord`, `exclusion_identity_of()`, `finding_fingerprint()` and `parse_exclusions_document()`

#### 👁️ Review Panel + Confidence (New!)
- **Click any finding to see it explained in a two-column review panel** below the results list
- **Left column:** the full registry path, the value name, the detected issue, a plain-language explanation of **why it counts as orphaned**, a plain-language explanation of **what cleaning would remove**, a per-category **risk level**, and the scanner's **confidence**
- **Right column:** a live before/after view of the registry entry, read directly from the registry — the current values and subkeys, and exactly what would be deleted (with a proper "no longer exists" message if the entry has been removed since the scan)
- **Confidence levels** are derived only from facts the scanner itself produced:
  - **Very Safe** — everything the entry points to was checked and is missing, and removing it only discards bookkeeping or cache data that nothing needs any more
  - **Safe** — the program/file/folder the entry points to was checked on a local drive and is missing
  - **Review Recommended** — this may be something you set up on purpose, *or* the scanner recorded no proof to re-check
- **Colour-coded confidence column** in the results list; the full meaning is in the tooltip
- **The panel has a draggable divider** and can be collapsed to give the list the full height
- **Reviewing never writes to the registry**
- **Implemented by `render_finding_html()`, `build_registry_preview()`, `assess_confidence()`, `explain_why_orphaned()`, `explain_what_is_removed()`**

#### 📊 Cleanup Summary + Impact (New!)
- **A live statistics bar** in the Scan Results card shows Findings, Selected, Cleanup Categories and Exclusions, updated as you tick rows
- **The Cleanup Summary card** shows the selected count, the number of categories affected, how many undo entries will be created and verified, and the outcome of the last scan and the last clean (with its undo file path)
- **The confirmation dialog now says exactly what a clean would modify:**
  - Items selected
  - Categories affected
  - Undo entries created
  - **"Will modify: N keys and M values"** — counted live with a hard time budget so the window never freezes; when a tree was too large to count fully the numbers say **"at least …"**
- **The workflow accent colour marks the next step:** Analyze is the primary (accent-filled) button until you have a selection; as soon as you tick something, Clean Selected becomes the primary button
- **Implemented by `summarize_clean_impact()`, `CleanImpact`, `count_key_tree()`**

#### 🔄 Three-Tier Restart Advice (Rewritten)
- **Tier 0 — No restart needed:** **nothing is shown at all.** No popup, no dialog, no banner, no notification. This is where routine orphan cleanup stays, even after removing dozens of entries
- **Tier 1 — Restart recommended:** one optional, **non-modal** note with a single OK button. It never blocks the window and it never schedules anything. The wording is fixed on purpose: *"A system restart is recommended to ensure all Windows components observe the changes. The restart is optional and can be performed later."*
- **Tier 2 — Restart strongly recommended:** the **Restart Now / Restart Later** box, with a 30-second countdown so you can cancel with `shutdown /a`
- **Every kind of change carries a weight** (0 = bookkeeping nobody reads while it runs, 1 = a running program may have loaded it, 2 = right-click handlers), and every deleted entry adds the weight of its kind. The points add up and the total decides the tier
- **Restore and Import count each kind once** and use higher thresholds, sized so that **a single sign-in-read setting reaches Tier 1 on its own** and **a setting that is only read while Windows boots reaches Tier 2 on its own**
- **A pending Windows restart raises the tier by one — but only for a change big enough to matter.** On its own, "Windows is waiting for a restart" no longer produces any prompt (this was the cause of the nagging)
- **Problems are always reported**, whatever the tier: skipped entries, failed entries and accepted undo-file problems get their own box regardless
- **Implemented by `RestartTier` (IntEnum), `RestartImpact`, `RestartAdvice`, `assess_clean_restart()`, `assess_restore_restart()`, `assess_import_restart()`**

#### 🎨 UI Redesign
- **Card-based Clean tab:** Scan Categories, Scan Results, Cleanup Summary and System Status are separate bordered cards, with the collapsible Excluded Items section below them
- **Resizable, scroll-friendly window** — long pages scroll inside a `ContentScrollArea` instead of forcing the window taller than the screen, so no button is ever out of reach on a laptop or high-DPI display
- **The window opens sized to its content, capped to 94% of the usable screen**, then centres itself; it can be resized freely afterwards
- **Empty-state pages** that explain what to do next instead of showing a blank area — "Click Analyze to begin a scan", "No findings detected", "Everything found is on your exclusion list"
- **System Status card** with Safety Status, Admin, Exclusions, Restart, Backup folder — every row has a tooltip that spells out the current state
- **Non-modal notices** (`show_notice()`) for start-up warnings, Tier 1 restart advice and unsaved exclusions — they never block the window
- **Cleaner styling:** rounded cards, a rounded tab pane, tab hover states, a one-pixel stat divider, style properties (`primary`, `danger`, `workflow`, `state`) instead of separate object names where that made the stylesheet cleaner
- **Safety banner and System Status share one `set_state_property()` helper** so the "good / warn / bad" tint is consistent everywhere

---

### 🐛 Bug Fixes

#### Correctness
- **Fixed: Clean and Restore undo files now pass an additional final gate.** After the strict value-by-value read-back, `validate_undo_file()` checks once more that the file exists, is non-empty, parses completely and matches the writer's per-entry fingerprints (content, not just counts). The gate can only turn a pass into a failure — it never weakens the value-by-value check
- **Fixed: a pending Windows restart no longer nags on its own.** The old advice treated a pending restart as "recommended" by itself, which could produce a dialog after a Tier 0 cleanup. A pending restart now raises the tier by at most one, and only for a change big enough to matter
- **Fixed: the risky "Continue anyway (risky!)" button could be offered for an entry that had not actually failed enough times.** It is now offered only when **every** entry that failed this run has reached the threshold, because the repeated run only accepts problems for those entries
- **Fixed: a failed undo check now untickes exactly the responsible rows** and leaves every other tick the user set untouched — the whole tree is no longer rebuilt after a failure
- **Fixed: the "Check All" button no longer silently re-ticks rows whose undo check already failed.** Such rows stay unticked and have to be ticked deliberately
- **Fixed: the `(Default)` value is never deleted by the cleaner**, no matter which category produced the finding (`is_delete_allowed()` refuses it explicitly and the self-check proves the refusal)

#### UI / Behaviour
- **Fixed: the results list no longer resets every tick after a clean.** The user's tick map is captured before the list is rebuilt and reapplied to the surviving rows
- **Fixed: group check state stays correct after partial ticks** by marking parent rows as auto-tristate, and by spanning their text across all columns
- **Fixed: sorting by category groups no longer breaks** when a group holds thousands of rows — checkbox changes are coalesced through `schedule_selection_refresh()` so one tick on a group does not trigger one refresh per row
- **Fixed: pressing Enter or Esc can never pick the risky choice** in the failed-undo-check box, because OK is the default button and also the escape button
- **Fixed: pressing Enter or Esc can never restart the computer** in the Restart Now / Restart Later box, because Restart Later is the default button and also the escape button
- **Fixed: the clean engine now consults the exclusion list one last time** right before a clean, so a finding the user chose to keep cannot reach the engine whatever state the list is in

---

### 🔒 User-Facing Improvements

#### ✅ Cleanup Confirmation Dialog Tells You What Would Change
- **The confirm box shows items, categories, undo entries and a live key/value count** — computed with the same bounded walker the rest of the app uses, so the number is honest about being a lower bound when the tree was too large to count in full
- **A note explains that nothing changes until you confirm**, and that the undo backup is read back and verified first

#### 📊 Diagnostics Written to the Log, Numbers Only
- **New `log_telemetry()` helper** writes one line per finished operation such as `[TELEMETRY] scan seconds=2.314 findings=24` or `[TELEMETRY] clean seconds=3.118 deleted=4 skipped=0 failed=0 restart_tier=0`
- **Text is dropped on purpose:** only numbers and yes/no values are accepted, so a telemetry line cannot carry a path, a name or any personal data
- **Nothing leaves the PC** — the lines go to the same per-run log file as everything else

#### 🛡️ The Self-Check Runs Again Before Every Clean
- **`confirm_safety_before_clean()`** runs the instant, in-memory parts (allow-list, delete guards, protected paths) before the engine is even asked to do anything
- **A critical failure stops the clean, disables the button and explains what failed** — Analyze and the review panel keep working

#### 🏷️ Start-up Notices Are Non-Modal
- **A failed safety self-check, a damaged exclusions file and a warning about a network backup folder** are now shown in a non-modal notice with a single OK button — they never block the window, ask nothing and schedule nothing

#### 🕒 Last Scan and Last Clean Are Remembered On Screen
- **The Cleanup Summary card shows** how long the last scan took, how many findings it returned, how long the last clean took and where its undo file is

---

### ⚙️ Internal Improvements

- **`hashlib` and `html` imports added** — the former for exclusion fingerprints and file checksums, the latter to escape every piece of registry text that is put into the review panel's HTML
- **New Qt imports** — `QSize`, `QBrush`, `QColor`, `QFrame`, `QScrollArea`, `QSplitter`, `QStackedWidget`, `QTextBrowser`, `QToolButton`, and `IntEnum` alongside the existing `Enum`
- **`PreferredSizeSplitter`** — asks for a sensible height so the review panel and the results list start with useful proportions instead of the cramped Qt default
- **`PreferredHeightPage`** — a small helper so the empty state page is exactly as tall as the results view it replaces (otherwise the card would shrink before the first scan and grow after it)
- **`ContentScrollArea`** — a frameless scroll area that reports the *content's* size hint, so the window opens big enough to show the whole page but can also be shrunk down to a scrolling laptop size
- **`make_card()`, `make_stat_block()`, `make_status_pair()`** — three new small builders, so the Clean tab's layout reads as a few lines of structure per card instead of one large block of widget wiring
- **`mark_workflow_button()` and `set_state_property()`** — small helpers that set a style property and repolish the widget if it changed, so the primary/next-step styling is one call instead of a dozen lines each
- **Constants extended** for the exclusions file (name, format, version, note, maximum size), the preview panel (max value lines, max subkey lines, tree key limit), the impact summary (key limit, time budget), the exclusions list height, the new UI font sizes and card paddings, the new colour, and every restart weight and threshold
- **`log_telemetry()` accepts only `int`, `float` and `bool`** — anything else is silently dropped, which keeps the "numbers only" promise honest even if a caller passes a string by mistake
- **All existing docstrings preserved and extended** where a new function's *why* was not obvious (exclusion identity, fail-closed self-check, gate ordering, tier thresholds)
- **App version bumped** from `1.0.0` to `2.0.0`

---

### ⚙️ Changes from v1.0.0

- **Cleanup categories: 9 (unchanged)** — every scan rule is exactly as strict as before
- **No cleanup behaviour was broadened.** Every change either *adds a check* (self-check, extra undo gate, pre-clean re-check), *hides a row* (exclusions) or *describes a row* (review panel, confidence)
- **Restart advice default flipped to silence.** Tier 0 is now the norm for routine cleanup; Tier 1 is a single non-modal sentence; Tier 2 is the only tier with Restart Now / Restart Later
- **A pending Windows restart no longer produces a prompt on its own**
- **Config file format unchanged.** The new exclusions file is separate and optional; if it is missing the program behaves exactly as before
- **No migration needed** — v2.0 reads the v1.0 settings file as-is

---

### 📊 Statistics

**Code Changes:**
- **Lines of source:** ~5,500 → ~7,500
- **New features added:** 7 major (self-check, banner, exclusions, review panel, confidence, impact summary, tiered restart) plus the UI redesign
- **New functions/methods added:** 40+
- **New constants added:** 30+
- **New classes added:** 8 (`ExclusionStore`, `ExclusionRecord`, `SafetyCheck`, `SafetyReport`, `RegistryPreview`, `CleanImpact`, `ScanOutcome`, `PreferredSizeSplitter`, `PreferredHeightPage`, `ContentScrollArea`)
- **Docstrings expanded:** every new function, plus the module docstring's safety-model section

**User Impact:**
- **Visibility of the safety model:** "trust the description" → "the program proved it at start-up and shows the result"
- **Control over the results list:** no way to stop a finding reappearing → exclusions that only ever hide, with a fail-safe file
- **Explanation per finding:** a one-line reason → key, confidence, why it is orphaned, risk, and a live before/after
- **Restart noise:** "always tells you" → "silent unless a restart really helps"
- **Window behaviour:** fixed size → resizable with scrolling pages, cards and a draggable review divider

---

### 🎯 Migration from v1.0.0

**Good news:** No migration needed!

- **Settings file compatible** — v2.0 reads the v1.0 settings file as-is, including your chosen backup folder
- **Same scan rules** — every category finds exactly the same set of findings it did before
- **Exclusions start empty** — the new file is created the first time you exclude something; before that the program behaves exactly as v1.0 did
- **Old undo files stay valid** — the format is unchanged and they can still be imported from the Import tab
- **Logs continue to be written** to the same folder under `%TEMP%`

**To upgrade:**
1. Download v2.0
2. Extract and run (right-click → Run as administrator)
3. Your backup folder is remembered
4. Watch the Safety banner on first run — a red banner means cleaning is disabled on purpose, and the tooltip explains which check failed

---

### 🙏 Acknowledgments

This release was driven by:
- The realisation that a safety model which is only described in prose is hard to trust, and that a program which can *run* its own guards is worth a lot more than one that claims them
- Repeated user feedback that the restart advice was too eager — sometimes just a pending Windows Update was enough to prompt
- The wish to make the results list easier to live with, without ever giving the cleaner a way to decide less carefully
- The same "prove it, don't promise it" approach already used by the other RaneKun tools

---

## [v1.0.0] - 2026-09-24

### 🚀 Initial Release

The first public version of Windows Registry Cleaner, built around a single principle: **never change anything you can't prove, preview, and undo**.

---

### ✨ Features

#### 🧹 Clean Tab — Find and Remove Broken Registry Entries

Nine independent scan categories, each opt-in:

- **Leftover uninstall entries** — apps whose uninstaller, install folder AND icon are all provably gone. MSI products, updates, system components and hidden entries are never flagged
- **Stale shared-DLL counts** — SharedDLLs reference counts for files that no longer exist
- **Broken application paths** — App Paths entries whose program no longer exists
- **Broken startup entries** — Run / RunOnce entries pointing at missing programs. Items you disabled in Task Manager / Settings are skipped via StartupApproved
- **Stale program-name cache** — MUI cache entries for programs that no longer exist
- **Missing font files** — Font entries pointing at full paths outside Windows that no longer exist
- **Orphaned file associations** — Extensions pointing to a dead ProgID, or ProgIDs whose `open` commands all point to missing programs
- **Dead right-click menu entries** — Shell-extension handlers whose COM server DLL is provably missing, and static verbs whose program is gone
- **⚠ Stale network history** — Remembered network locations in Explorer's TypedPaths, Map Network Drive MRU and MountPoints2. Listed **unticked**, because this is history you may have created on purpose

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

- **Policy locks** — `DisableTaskMgr`, `DisableRegistryTools`, `DisableCMD`, `NoControlPanel`. Default state is "not configured", so the repair is to remove the value. Detects domain-joined / Entra-joined / MDM-enrolled PCs and warns before touching these
- **Critical file associations** — `.exe`, `.lnk`, `.bat`, `.cmd`, `.reg`, `Directory\shell`, `Drive\shell`, `Folder\shell`. A wrong HKCU override is removed; a wrong or missing HKLM value is set back. Deliberate alternatives (e.g. a file-manager replacement) start unticked
- **Shell folder paths** — Desktop / Documents / Downloads / etc. Only entries that are **provably missing or invalid** are proposed. Working custom paths, network paths, and unresolved variables are never touched

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

- **64-bit Python required** on 64-bit Windows — a 32-bit Python would see a redirected filesystem (`System32` → `SysWOW64`) and could report working files as missing. The program refuses to start in that case
- **Every registry key is opened in the native 64-bit view** (`KEY_WOW64_64KEY`), so WOW6432Node paths are listed explicitly and both bitnesses are covered exactly once
- **Windows-owned folders are never touched** — paths under `%SystemRoot%`, WindowsApps, Defender, Windows Media Player, Internet Explorer, WindowsPowerShell, etc. are treated as protected, and a missing file there means a damaged Windows component, not something to "fix"
- **Offline / removable / network drives are never treated as broken** — if a drive isn't currently mounted, no entry pointing to it is flagged
- **UNC paths are never contacted** — the scanner is fully static. A dead network share can never stall the app

---

### 📦 Build System

- **`build_exe.bat`** — hardened Windows batch script. Enforces Python 3.11+, checks pip availability, uses `python -m pip` (not bare `pip`), checks network only when PyInstaller actually needs installing, moves the finished `.exe` next to the build script, and cleans up `build\`, `dist\` and the `.spec` file automatically
- **`BUILD_INSTRUCTIONS.md`** — plain-English guide covering prerequisites, the one-step build, testing, sharing, and the common hiccups
- **No `.py` build method** — the batch script is the only supported build path, to keep the instructions short

---

### ⚠️ Limitations

Being honest about what this tool does **not** do:

- **It doesn't scan everything.** Categories are deliberately narrow — one for each of the nine areas above. A registry cleaner that walks the whole hive and flags anything it doesn't recognise is exactly the kind of tool that breaks Windows
- **It won't find much on a healthy PC.** If your scan comes back empty, that's the tool working as designed, not a bug
- **`SAM` and `SECURITY` can't be backed up as `.reg` files** — those hives are protected by design and would need a different mechanism (like `reg save`) that produces binary files, which can't be merged back with `reg import`
- **`.reg` files don't store key permissions.** Importing a backup restores the data, not the ACLs
- **Import never removes keys added after a backup.** `reg import` merges — it doesn't roll back additions

---

<p align="center">
  <strong>Version 2.0.0 proves its own safety model instead of describing it</strong><br>
  <sub>Analyze. Review. Confirm. Exclude. Undo if needed. 🧹✨</sub>
</p>
