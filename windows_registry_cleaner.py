"""
Windows Registry Cleaner by Rane
================================

A small, single-purpose Windows tool that does four things and nothing else:

  1. CLEAN   - finds and removes *broken* registry entries (entries whose target
               file/folder no longer exists). It never touches deliberate user
               choices (default-app selections, disabled startup items, policies).
               Remembered network locations in Explorer's history (which can freeze Explorer when
               a server is unreachable) are listed too, but start UNTICKED so you decide.
  2. BACKUP  - one-click backup of the whole registry to a folder of your choice
               (plain-text .reg files).
  3. RESTORE - restores a curated set of critical Windows defaults (policy locks,
               critical file associations, shell-folder paths) - never blanket resets.
  4. IMPORT  - merges .reg files into the registry, with a preview first.

SAFETY MODEL (every write operation follows these rules)
--------------------------------------------------------
  * Analyze first - nothing is changed until you review the list and confirm.
  * Before ANY change an "undo" .reg file containing exactly what is about to be
    changed is written, verified by reading it back, and the operation is aborted
    if that fails. Undo files live in "<backup folder>\\Undo" and can be re-imported
    with the Import tab.
    If that read-back check fails while cleaning, the entries that caused it are
    unticked (marked with a stop sign) and nothing is deleted. Only after the SAME
    entry has failed 3 times does the error box offer "Continue anyway (risky!)":
    an explicit choice that keeps the unverified undo file and deletes anyway.
    The Import tab's streamed undo file is verified entry by entry (a fingerprint of every
    entry written is compared with what is read back), not merely by counting entries.
  * Every deletion is re-validated immediately before it happens and is checked
    against a strict allow-list of registry locations (the scanner also drops any
    finding the allow-list would refuse, so such entries are never even listed).
  * After a change, the finished box says whether a restart is advised (a heuristic
    score per kind of change): routine cleaning of broken entries stays at "no restart
    needed"; "Restart Now / Restart Later" appear only when a restart really helps.
  * Anything that cannot be verified (offline/removable/network drives, protected
    Windows folders, unresolved environment variables, unreadable paths) is skipped,
    never treated as "broken".
  * Windows-owned entries, COM/ActiveX/TypeLib data and Windows Installer data are
    never scanned.
  * Entries that may be deliberate user history (remembered network locations) start
    unticked and need an explicit tick. Scanning is static: no server is ever contacted.

REQUIREMENTS
------------
  * Windows 10/11, 64-bit Python 3.11+ (32-bit Python on 64-bit Windows is refused
    because file-system redirection would produce false "missing file" results).
  * PyQt6  (pip install PyQt6). Everything else is the standard library.
  * Administrator rights for anything that writes to HKLM (the app offers to
    relaunch itself elevated).

SOURCES USED FOR THE HARD-CODED DEFAULTS (links re-checked on 2026-09-20)
------------------------------------------------------------------------
  * reg export syntax "reg export <keyname> <filename> [/y]" (there is no /reg switch, so none is used):
      https://learn.microsoft.com/windows-server/administration/windows-commands/reg-export
    (Microsoft Learn: "reg import" - same section - documents the "reg import <filename>" syntax used here.)
  * exefile\\shell\\open\\command = "%1" %*  (Microsoft Learn, "Can't open EXE files"):
      https://learn.microsoft.com/en-us/troubleshoot/windows-server/setup-upgrade-and-drivers/cant-open-exe-files
  * Directory\\shell / Drive\\shell default = none:
      https://www.winhelponline.com/blog/cmd-default-for-folders-right-click/
  * Folder\\shell must have NO default value:
      https://www.winhelponline.com/blog/fix-folders-open-new-window/
  * The UserChoice key should not exist for .exe:
      https://www.winhelponline.com/blog/exe-files-open-notepad-fix-association/
  * Default User Shell Folders (Windows 10/11):
      https://www.winhelponline.com/blog/windows-10-shell-folders-paths-defaults-restore/
  * Policy value names and locations (DisableTaskMgr / DisableRegistryTools / NoControlPanel; "Not configured"
    means the value is absent):
      https://support.eset.com/en/kb721-an-infiltration-is-blocking-access-to-the-control-panel-task-manager-registry-editor-and-command-promptwhat-should-i-do
  * DisableCMD lives in ...\\Policies\\Microsoft\\Windows\\System (Microsoft Group Policy reference, "Prevent access
    to the command prompt").
  * StartupApproved: first byte 02 = enabled, 03 = disabled (community documentation, PowerShell forums thread
    "Enable/Disable startup programs in Windows 10"). This tool is stricter: anything except 02/06 counts as disabled.
  * Pending-restart indicators used by the restart advice (Component Based Servicing "RebootPending", Windows Update
    "RebootRequired", Session Manager "PendingFileRenameOperations"; link checked 2026-09-21):
      https://devblogs.microsoft.com/scripting/determine-pending-reboot-statuspowershell-style-part-2/
  * REG_MULTI_SZ data is split exactly like Python's own winreg module does it (countStrings/fixupMultiSZ in CPython's
    PC/winreg.c; the reading code is identical in Python 3.11, 3.12, 3.13 and main; link checked 2026-09-21):
      https://github.com/python/cpython/blob/main/PC/winreg.c

Created by RaneKun. Licensed under the RaneKun Open-Use License (non-commercial,
attribution required).
"""

from __future__ import annotations

# --- Standard library imports ---
import ctypes
import datetime
import getpass
import io
import json
import logging
import ntpath
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import winreg
from array import array
from dataclasses import dataclass, field
from enum import Enum
from logging.handlers import RotatingFileHandler
from typing import Any, Callable, Iterator

# --- Third-party imports (GUI) ---
from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QDragEnterEvent, QDragMoveEvent, QDropEvent, QCloseEvent, QFont, QIcon
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QFileDialog, QGridLayout, QGroupBox, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QTabWidget, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)


# =============================================================================
# CONSTANTS - identity, file names, folders
# =============================================================================

APP_NAME = "Windows Registry Cleaner"
APP_WINDOW_TITLE = "Windows Registry Cleaner by Rane"
APP_VERSION = "1.0.0"
APP_AUTHOR = "RaneKun"

ICON_FILE_NAME = "windows_registry_cleaner.ico"            # optional, placed next to this script
SETTINGS_FILE_NAME = "windows_registry_cleaner_settings.json"
ERROR_LOG_FILE_NAME = "error-log 📃.txt"                    # same name the other tools use
LOG_FOLDER_NAME = "Windows Registry Cleaner by Rane Logs"   # created under the OS temp folder
DEFAULT_BACKUP_FOLDER_NAME = "Registry Backups"
UNDO_SUBFOLDER_NAME = "Undo"
FULL_BACKUP_FOLDER_PREFIX = "Full Backup"
BACKUP_INFO_FILE_NAME = "backup-info.txt"

# =============================================================================
# CONSTANTS - limits and tuning values
# =============================================================================

MAX_SAFE_PATH_LENGTH = 240            # longer paths may fail on systems without long-path support -> "unknown"
MAX_TREE_KEYS_FOR_DELETE = 2000       # refuse to auto-delete unusually large key trees
MAX_PREVIEW_ROWS = 400                # rows shown in the .reg import preview
LARGE_REG_FILE_BYTES = 64 * 1024 * 1024   # above this the import preview shows totals only
MIN_FREE_SPACE_BYTES = 3 * 1024 ** 3      # full backups are large; require this much free space
REG_LINE_WIDTH = 80                   # regedit wraps long hex values at this width
DRIVE_FIXED = 3                       # GetDriveTypeW() result for a normal local disk
NET_SETUP_DOMAIN_NAME = 3             # NetGetJoinInformation() result for "joined to a domain"
SUBPROCESS_POLL_SECONDS = 0.2         # how often a running reg.exe is checked for cancel requests
REPORT_MIN_INTERVAL_SECONDS = 0.1     # routine progress updates are limited to ~10 per second (huge jobs would flood the UI and log)
UNDO_FAILURES_BEFORE_OVERRIDE = 3     # the SAME entry must fail the undo safety check this many times before "Continue anyway (risky!)" is offered
MAX_LOGGED_UNDO_PROBLEMS = 100        # individual undo-check problems written to the log per run (the rest are only counted)
# Restart advice: how much each kind of change needs a restart. These are HEURISTIC scores - tune them here.
RESTART_SCORE_NONE = 0                # takes effect at once, or only matters the next time something is launched
RESTART_SCORE_PROGRAMS = 1            # a program that is already running (e.g. Explorer) may keep the old value until restarted
RESTART_SCORE_SHELL = 3               # read once at sign-in: restart (or sign out and back in) recommended
RESTART_SCORE_BOOT = 7                # only read while Windows starts (services, drivers, boot/session settings)
RESTART_RECOMMENDED_AT = 3            # total score from which a restart is "recommended"
RESTART_STRONG_AT = 7                 # total score from which it is "strongly recommended"
RESTART_DELAY_SECONDS = 30            # "Restart Now" restarts after this countdown, so it can still be cancelled with "shutdown /a"
RESTART_COMMENT = "Restart requested by Windows Registry Cleaner by Rane to finish applying registry changes."
CREATE_NO_WINDOW_FLAG = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # hides the console window on Windows

# =============================================================================
# CONSTANTS - user interface (all colors, fonts and sizes live here)
# =============================================================================

UI_FONT_FAMILY = "Comic Sans MS"      # same font as the other Rane tools
UI_FONT_POINT_SIZE = 9
UI_MONO_FONT_FAMILY = "Consolas"
UI_WINDOW_MARGIN = 12
UI_LAYOUT_SPACING = 8
UI_RESULTS_MIN_WIDTH = 900
UI_RESULTS_MIN_HEIGHT = 280
UI_PREVIEW_MIN_HEIGHT = 200
UI_FILE_LIST_MIN_HEIGHT = 110
UI_CATEGORY_COLUMNS = 3             # columns of scan-category checkboxes (3 keeps the window short on laptop screens)
# Result-column widths are given in "average characters" and converted with the actual font at start-up, so the
# layout adapts to Comic Sans MS (which is wider than most fonts) instead of clipping text.
UI_COLUMN_PROBLEM_CHARS = 56        # 'Problem' column of the Clean results
UI_COLUMN_REPAIR_CHARS = 44         # 'Repair' column of the Restore results
UI_COLUMN_CURRENT_CHARS = 24        # 'Current value' column of the Restore results
UI_COLUMN_RESTORED_CHARS = 34       # 'Restored value' column (the longest texts live here)
UI_STRETCH_COLUMN_MIN_CHARS = 30    # smallest width of the flexible 'Entry' / 'Location' column
UI_SCROLLBAR_ALLOWANCE = 24         # pixels reserved for the vertical scroll bar of a result list
UI_STATUS_MIN_WIDTH = 300           # the status line is shortened (elided) to fit its width
UI_CONTINUE_ANYWAY_TEXT = "Continue anyway (risky!)"   # extra button of the error box once an entry failed the undo check often enough
UI_UNDO_FAILED_MARKER = "⛔"          # prefix of result rows whose undo backup failed the safety check (such rows start unticked)
UI_UNDO_FAILED_LIST_LIMIT = 5       # entries named in that error box before it says "... and N more"

COLOR_ERROR = "#c0392b"
COLOR_WARNING = "#b9770e"
COLOR_SUCCESS = "#1e8449"
COLOR_MUTED = "#6b6b6b"

STYLESHEET = f"""
QPushButton {{
    padding: 5px 12px;
    border: 1px solid palette(mid);
    border-radius: 4px;
    background-color: palette(button);
}}
QPushButton:hover {{ border-color: palette(highlight); }}
QPushButton:disabled {{ color: palette(mid); }}
QPushButton#primaryButton {{
    background-color: palette(highlight);
    color: palette(highlighted-text);
    border: 1px solid palette(highlight);
    font-weight: bold;
}}
QPushButton#primaryButton:disabled {{
    background-color: palette(button);
    color: palette(mid);
    border: 1px solid palette(mid);
}}
QPushButton#dangerButton {{ border: 1px solid {COLOR_ERROR}; color: {COLOR_ERROR}; font-weight: bold; }}
QPushButton#dangerButton:disabled {{ border: 1px solid palette(mid); color: palette(mid); }}
QGroupBox {{
    font-weight: bold;
    margin-top: 10px;
    border: 1px solid palette(mid);
    border-radius: 4px;
    padding: 8px;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; }}
QTabWidget::pane {{ border: 1px solid palette(mid); border-radius: 4px; }}
QProgressBar {{ border: 1px solid palette(mid); border-radius: 4px; text-align: center; }}
QProgressBar::chunk {{ background-color: palette(highlight); }}
QLabel#mutedLabel {{ color: {COLOR_MUTED}; }}
QLabel#warningLabel {{ color: {COLOR_WARNING}; font-weight: bold; }}
QLabel#successLabel {{ color: {COLOR_SUCCESS}; font-weight: bold; }}
QPlainTextEdit {{ font-family: "{UI_MONO_FONT_FAMILY}"; }}
"""

# =============================================================================
# CONSTANTS - registry hives and locations
# =============================================================================

HKLM = "HKEY_LOCAL_MACHINE"
HKCU = "HKEY_CURRENT_USER"
HKCR = "HKEY_CLASSES_ROOT"
HKU = "HKEY_USERS"
HKCC = "HKEY_CURRENT_CONFIG"

HIVE_HANDLES: dict[str, Any] = {
    HKLM: winreg.HKEY_LOCAL_MACHINE,
    HKCU: winreg.HKEY_CURRENT_USER,
    HKCR: winreg.HKEY_CLASSES_ROOT,
    HKU: winreg.HKEY_USERS,
    HKCC: winreg.HKEY_CURRENT_CONFIG,
}
HIVE_ALIASES: dict[str, str] = {
    "HKLM": HKLM, "HKCU": HKCU, "HKCR": HKCR, "HKU": HKU, "HKCC": HKCC,
}

# (hive, key path) pairs the scanner walks. WOW6432Node paths are listed explicitly because every
# key is opened in the native 64-bit view (KEY_WOW64_64KEY), so both bitnesses are covered exactly once.
RegLocation = tuple[str, str]

UNINSTALL_ROOTS: tuple[RegLocation, ...] = (
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (HKLM, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (HKCU, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    (HKCU, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
)
SHARED_DLL_ROOTS: tuple[RegLocation, ...] = (
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs"),
    (HKLM, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs"),
)
APP_PATHS_ROOTS: tuple[RegLocation, ...] = (
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"),
    (HKLM, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths"),
    (HKCU, r"Software\Microsoft\Windows\CurrentVersion\App Paths"),
)
RUN_ROOTS: tuple[RegLocation, ...] = (
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (HKLM, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    (HKLM, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    (HKCU, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (HKCU, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
)
# Task Manager / Settings record "this startup item was switched off" here instead of deleting the Run value.
STARTUP_APPROVED_ROOTS: tuple[RegLocation, ...] = (
    (HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
    (HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"),
)
STARTUP_APPROVED_ENABLED_BYTES = (0x02, 0x06)   # first byte values that mean "enabled"
MUI_CACHE_ROOT: RegLocation = (
    HKCU, r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache")
FONT_ROOTS: tuple[RegLocation, ...] = (
    (HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"),
    (HKCU, r"Software\Microsoft\Windows NT\CurrentVersion\Fonts"),
)
CLASSES_HKLM: RegLocation = (HKLM, r"SOFTWARE\Classes")
CLASSES_HKCU: RegLocation = (HKCU, r"Software\Classes")
CLASSES_WOW_HKLM: RegLocation = (HKLM, r"SOFTWARE\WOW6432Node\Classes")
CLASSES_WOW_HKCU: RegLocation = (HKCU, r"Software\Classes\WOW6432Node")
CLASSES_ROOTS: tuple[RegLocation, ...] = (CLASSES_HKLM, CLASSES_HKCU)
FILE_EXTS_HKCU: RegLocation = (HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts")
PACKAGED_COM_INDEX: RegLocation = (HKLM, r"SOFTWARE\Classes\PackagedCom\ClassIndex")

# Explorer history that remembers network locations (the "Stale network history" category). All under HKCU.
EXPLORER_HKCU_ROOT = r"Software\Microsoft\Windows\CurrentVersion\Explorer"
NET_HISTORY_TYPED_PATHS: RegLocation = (HKCU, EXPLORER_HKCU_ROOT + r"\TypedPaths")
NET_HISTORY_MAP_DRIVE_MRU: RegLocation = (HKCU, EXPLORER_HKCU_ROOT + r"\Map Network Drive MRU")
NET_HISTORY_MOUNT_POINTS: RegLocation = (HKCU, EXPLORER_HKCU_ROOT + r"\MountPoints2")
LOCAL_HOST_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})   # \\localhost\... never leaves this PC, so it cannot stall

# Well-known top-level places where "Open with" style context-menu entries live.
CONTEXT_MENU_TARGET_KEYS: tuple[str, ...] = (
    "*", "AllFilesystemObjects", "Directory", r"Directory\Background", "Folder", "Drive",
)

# =============================================================================
# CONSTANTS - protection lists (things the cleaner must never flag)
# =============================================================================

# Paths under these folders are Windows-owned; a missing file there means a damaged or optional Windows
# component, which is not something to "fix" by deleting registry references.
PROTECTED_PATH_TEMPLATES: tuple[str, ...] = (
    "%SystemRoot%",
    r"%ProgramFiles%\WindowsApps",
    r"%ProgramFiles%\Windows Defender",
    r"%ProgramFiles(x86)%\Windows Defender",
    r"%ProgramFiles%\Windows Defender Advanced Threat Protection",
    r"%ProgramData%\Microsoft\Windows Defender",
    r"%ProgramFiles%\Windows Media Player",
    r"%ProgramFiles(x86)%\Windows Media Player",
    r"%ProgramFiles%\Windows NT",
    r"%ProgramFiles(x86)%\Windows NT",
    r"%ProgramFiles%\Windows Mail",
    r"%ProgramFiles(x86)%\Windows Mail",
    r"%ProgramFiles%\Windows Photo Viewer",
    r"%ProgramFiles(x86)%\Windows Photo Viewer",
    r"%ProgramFiles%\Windows Sidebar",
    r"%ProgramFiles%\Internet Explorer",
    r"%ProgramFiles(x86)%\Internet Explorer",
    r"%ProgramFiles%\WindowsPowerShell",
    r"%ProgramFiles(x86)%\WindowsPowerShell",
)

# Extensions the cleaner never touches (the Restore tab handles the critical ones explicitly).
PROTECTED_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys", ".com", ".bat", ".cmd", ".lnk", ".reg", ".msi", ".msc", ".cpl", ".scr",
    ".ini", ".inf", ".txt", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1", ".url", ".zip", ".cab",
    ".mui", ".ocx", ".drv", ".theme", ".nls", ".log", ".dat", ".tmp", ".cat", ".manifest", ".pif",
})

# ProgIDs / class keys that are never treated as "orphaned" (system associations and special keys).
PROTECTED_CLASS_KEYS = frozenset({
    "*", "allfilesystemobjects", "directory", "folder", "drive", "clsid", "interface", "typelib", "appid",
    "installer", "licenses", "mime", "packagedcom", "local settings", "wow6432node", "systemfileassociations",
    "unknown", "desktopbackground", "exefile", "batfile", "cmdfile", "comfile", "regfile", "lnkfile",
    "piffile", "scrfile", "txtfile", "inifile", "inffile", "vbsfile", "vbefile", "jsfile", "jsefile",
    "wsffile", "wshfile", "mscfile", "cplfile", "dllfile", "sysfile", "htmlfile", "cabfolder",
    "compressedfolder", "themefile", "http", "https", "ftp", "file", "ms-settings", "shell", "applications",
})

# The static-menu verbs Windows or well-known tools ship; never flagged even if their exe looks missing.
PROTECTED_VERB_NAMES = frozenset({"open", "opennewwindow", "explore", "find", "cmd", "powershell", "runas"})

# Registry-key protection for .reg imports that contain "[-KEY]" delete lines: these keys (relative to the
# hive, lower-case) are never allowed to be deleted by an import, no matter who wrote the file.
CRITICAL_MACHINE_KEYS = frozenset({
    "software", "system", "hardware", "sam", "security", "software\\microsoft", "software\\microsoft\\windows",
    "software\\microsoft\\windows nt", "software\\microsoft\\windows nt\\currentversion",
    "software\\microsoft\\windows nt\\currentversion\\winlogon", "software\\microsoft\\windows\\currentversion",
    "software\\microsoft\\windows\\currentversion\\explorer", "software\\classes", "software\\wow6432node",
    "software\\policies", "system\\currentcontrolset", "system\\currentcontrolset\\services",
    "system\\currentcontrolset\\control", "system\\controlset001", "system\\controlset001\\services",
    "system\\controlset001\\control",
})
CRITICAL_USER_KEYS = frozenset({
    "software", "software\\microsoft", "software\\microsoft\\windows", "software\\microsoft\\windows nt",
    "software\\microsoft\\windows\\currentversion", "software\\microsoft\\windows\\currentversion\\explorer",
    "software\\classes", "software\\policies",
})
CRITICAL_CLASSES_KEYS = frozenset({
    "clsid", "interface", "typelib", "appid", "*", "allfilesystemobjects", "directory", "folder", "drive",
    "installer", "local settings", "wow6432node", "systemfileassociations", "exefile", "lnkfile", "batfile",
    "cmdfile", "regfile", "comfile", "txtfile", "htmlfile", "http", "https", "file", "ms-settings", "shell",
    ".exe", ".lnk", ".bat", ".cmd", ".reg", ".dll",
})

# =============================================================================
# CONSTANTS - registry value types
# =============================================================================

REG_TYPE_NAMES: dict[int, str] = {
    winreg.REG_NONE: "REG_NONE", winreg.REG_SZ: "REG_SZ", winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
    winreg.REG_BINARY: "REG_BINARY", winreg.REG_DWORD: "REG_DWORD", winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
    winreg.REG_QWORD: "REG_QWORD",
}
REG_HEADER_V5 = "Windows Registry Editor Version 5.00"
REG_HEADER_V4 = "REGEDIT4"


# =============================================================================
# LOGGING SETUP
# =============================================================================
# One structured, timestamped log file per run (kept in the OS temp folder, like the other Rane tools),
# plus a separate "error-log 📃.txt" next to the app that only collects errors.

def resolve_log_directory() -> str:
    """
    Work out where the per-run log files live and make sure the folder exists.

    Returns:
        str: Absolute path of the log folder (falls back to the system temp folder if the
             preferred location cannot be created).
    """
    preferred_base = os.environ.get("TEMP") or tempfile.gettempdir()
    for base_folder in (preferred_base, tempfile.gettempdir()):
        candidate = os.path.join(base_folder, LOG_FOLDER_NAME)
        try:
            os.makedirs(candidate, exist_ok=True)
            return candidate
        except OSError:
            continue  # try the next candidate; logging must never stop the app from starting
    return tempfile.gettempdir()


LOG_DIR = resolve_log_directory()
_log_timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")   # one log file per run
LOG_FILE_PATH = os.path.join(LOG_DIR, f"Windows_Registry_Cleaner_{_log_timestamp}.log")

_logger = logging.getLogger("WindowsRegistryCleanerByRane")
_logger.setLevel(logging.DEBUG)
try:
    _file_handler = RotatingFileHandler(LOG_FILE_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    _file_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    _logger.addHandler(_file_handler)
except OSError:
    _logger.addHandler(logging.NullHandler())   # no writable log location -> keep running without a file


def log(message: object) -> None:
    """
    Drop-in replacement for print() that ALSO writes a timestamped line to the log file.

    The log level is detected from the "[TAG]" style used throughout this file: messages containing
    "[ERROR]" are logged as errors, "[WARNING]" as warnings, everything else as info.

    Args:
        message (object): Anything printable; it is converted with str().

    Returns:
        None
    """
    text = str(message)
    try:
        print(text)  # console echo (useful when running the .py version); a no-op in a windowed .exe
    except UnicodeEncodeError:
        # Old Windows consoles cannot print emoji; the log FILE is UTF-8 so nothing is lost there.
        print(text.encode("ascii", errors="replace").decode("ascii"))
    if "[ERROR]" in text or text.upper().startswith("ERROR"):
        _logger.error(text)
    elif "[WARNING]" in text:
        _logger.warning(text)
    else:
        _logger.info(text)


def log_exception(context: str) -> None:
    """
    Log the exception currently being handled, including its full traceback.

    Args:
        context (str): Short description of what was being attempted (shown before the traceback).

    Returns:
        None
    """
    log(f"[ERROR] {context}\n{traceback.format_exc()}")


# =============================================================================
# EXCEPTIONS AND SMALL SHARED TYPES
# =============================================================================

class OperationCancelled(Exception):
    """Raised inside a running task when the user pressed Cancel."""


class RegistryOperationError(Exception):
    """Raised when a registry operation cannot be completed safely (message is shown to the user)."""


@dataclass(frozen=True)
class UndoProblem:
    """
    One difference found when an undo file is read back and compared with what it was supposed to contain.

    Besides the readable sentence it records WHERE the difference is (which key and value). That is what lets the
    Clean tab work out which findings made the safety check fail, so it can untick exactly those.
    """

    message: str                    # readable text for the error box and the logs
    key_path: str = ""              # lower-case full key path; "" = the problem concerns the file as a whole
    value_name: str | None = None   # lower-case value name; None = the problem concerns the key itself


class UndoVerificationError(RegistryOperationError):
    """
    The undo file was written but did not read back exactly as planned, so the operation stopped before changing anything.

    It IS a RegistryOperationError (everything that already handles that keeps working unchanged), but it also
    carries the individual problems and - for a Clean run - the findings they belong to. The window uses that to
    untick those findings and, after repeated failures, to offer "Continue anyway (risky!)".
    """

    def __init__(self, message: str, problems: list[UndoProblem]) -> None:
        """
        Args:
            message (str): Text for the user ("The undo backup failed its safety check (...). Nothing was changed.").
            problems (list[UndoProblem]): Every problem that was NOT accepted by the caller.
        """
        super().__init__(message)
        self.problems = problems
        self.failed_entries: list[BrokenEntry] = []   # filled in by clean_entries(); stays empty for other operations


class RegParseError(Exception):
    """Raised when a .reg file is not a valid registry script."""


class ProgressReporter:
    """
    Carries progress, status text and the cancel flag between a background task and the UI.

    Engine code only ever talks to this small class, so it never needs to import or know about Qt.
    """

    def __init__(
        self,
        progress_callback: Callable[[int], None] | None = None,
        status_callback: Callable[[str], None] | None = None,
        cancel_check: Callable[[], bool] | None = None,
        critical_callback: Callable[[bool], None] | None = None,
    ) -> None:
        """
        Args:
            progress_callback: Called with 0-100 whenever progress changes.
            status_callback: Called with a human-readable status line.
            cancel_check: Returns True once the user asked to cancel.
            critical_callback: Called with True/False when the task enters/leaves a stage that must not be interrupted.
        """
        self._progress_callback = progress_callback
        self._status_callback = status_callback
        self._cancel_check = cancel_check
        self._critical_callback = critical_callback
        self._last_report_time = 0.0

    def report(self, percent: int, message: str | None = None, force: bool = False) -> None:
        """
        Report progress (clamped to 0-100) and optionally a status line.

        Routine updates that arrive faster than REPORT_MIN_INTERVAL_SECONDS are dropped, so a job with tens of
        thousands of items cannot flood the window or the log. 0%, 100% and calls with force=True (used for stage
        changes such as "Writing the undo backup...") are never dropped.

        Args:
            percent (int): Progress from 0 to 100.
            message (str | None): Optional status line.
            force (bool): Deliver this update even if the previous one was very recent.
        """
        clamped = max(0, min(100, int(percent)))
        now = time.monotonic()
        if not force and clamped not in (0, 100) and now - self._last_report_time < REPORT_MIN_INTERVAL_SECONDS:
            return
        self._last_report_time = now
        if self._progress_callback is not None:
            self._progress_callback(clamped)
        if message is not None:
            self.status(message)

    def status(self, message: str) -> None:
        """Publish a status line (also written to the log)."""
        log(f"[STATUS] {message}")
        if self._status_callback is not None:
            self._status_callback(message)

    def is_cancelled(self) -> bool:
        """Return True if the user pressed Cancel."""
        return bool(self._cancel_check and self._cancel_check())

    def raise_if_cancelled(self) -> None:
        """Raise OperationCancelled if the user pressed Cancel (call between safe steps only)."""
        if self.is_cancelled():
            raise OperationCancelled()

    def set_critical(self, is_critical: bool) -> None:
        """Mark the start/end of a stage that cannot be cancelled or interrupted (e.g. applying changes)."""
        if self._critical_callback is not None:
            self._critical_callback(is_critical)


# =============================================================================
# ENVIRONMENT HELPERS (paths, admin rights, bitness, managed-PC detection)
# =============================================================================

def get_app_dir() -> str:
    """
    Return the folder that contains this script (or the built .exe).

    Files that should persist (settings, backups, error log) live here instead of the current working
    directory because a UAC relaunch starts processes in System32, which would scatter files there.

    Returns:
        str: Absolute folder path.
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def resource_path(relative_path: str) -> str:
    """
    Resolve a bundled resource (like the icon), for both normal runs and PyInstaller builds.

    Args:
        relative_path (str): File name relative to the app folder / PyInstaller bundle.

    Returns:
        str: Absolute path to the resource.
    """
    base_path = getattr(sys, "_MEIPASS", None) or get_app_dir()
    return os.path.join(base_path, relative_path)


def is_running_as_admin() -> bool:
    """
    Check whether the current process has administrator rights (is elevated).

    Returns:
        bool: True if elevated, False otherwise (or if the check is unavailable).
    """
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False


def relaunch_as_admin() -> bool:
    """
    Ask Windows (UAC) to start a new, elevated copy of this program.

    Returns:
        bool: True if Windows accepted the request (the caller should then exit this instance),
              False if it was declined or failed.
    """
    try:
        if getattr(sys, "frozen", False):
            parameters = subprocess.list2cmdline(sys.argv[1:])
        else:
            parameters = subprocess.list2cmdline([os.path.abspath(sys.argv[0]), *sys.argv[1:]])
        shell_execute = ctypes.windll.shell32.ShellExecuteW  # type: ignore[attr-defined]
        shell_execute.restype = ctypes.c_void_p  # the HINSTANCE result is pointer-sized
        result = shell_execute(None, "runas", sys.executable, parameters, get_app_dir(), 1)
        succeeded = bool(result) and int(result) > 32   # values <= 32 are ShellExecute error codes
        log(f"[ADMIN] Elevation request {'accepted' if succeeded else 'declined or failed'} (code {result})")
        return succeeded
    except (AttributeError, OSError) as error:
        log(f"[ERROR] Could not request elevation: {error}")
        return False


def is_32bit_python_on_64bit_windows() -> bool:
    """
    Detect a 32-bit Python running on 64-bit Windows.

    Such a process would see redirected folders (System32 -> SysWOW64) and could report files as
    missing when they exist, so the app refuses to scan in that situation.

    Returns:
        bool: True if the process is running under WOW64.
    """
    return bool(os.environ.get("PROCESSOR_ARCHITEW6432"))   # only set for 32-bit processes on 64-bit Windows


def describe_current_user() -> str:
    """Return the account name this process runs as (HKCU refers to this account's registry hive)."""
    try:
        domain = os.environ.get("USERDOMAIN", "")
        user = getpass.getuser()
        return f"{domain}\\{user}" if domain else user
    except (OSError, KeyError):
        return "unknown user"


def _is_domain_joined() -> bool:
    """Return True if Windows reports this PC as joined to an Active Directory domain."""
    try:
        name_buffer = ctypes.c_wchar_p()
        join_status = ctypes.c_int()
        netapi32 = ctypes.windll.netapi32  # type: ignore[attr-defined]
        if netapi32.NetGetJoinInformation(None, ctypes.byref(name_buffer), ctypes.byref(join_status)) != 0:
            return False
        try:
            return join_status.value == NET_SETUP_DOMAIN_NAME
        finally:
            netapi32.NetApiBufferFree(name_buffer)  # the API allocates the name buffer for us
    except (AttributeError, OSError):
        return False


def detect_managed_environment() -> list[str]:
    """
    Best-effort check whether this PC is managed by an organisation (domain, Entra ID or MDM).

    On managed PCs, Group Policy / Intune can silently re-apply policy values that this tool removes,
    and removing them may go against the organisation's rules. This is a heuristic used only to show a warning.

    Returns:
        list[str]: Human-readable reasons; empty if the PC does not look managed.
    """
    reasons: list[str] = []
    if _is_domain_joined():
        reasons.append("the PC is joined to an Active Directory domain")
    if list_subkey_names(HKLM, r"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"):
        reasons.append("the PC is joined to Microsoft Entra ID (Azure AD)")
    if list_subkey_names(HKLM, r"SOFTWARE\Microsoft\Provisioning\OMADM\Accounts"):
        reasons.append("the PC is enrolled in a device-management (MDM/Intune) service")
    return reasons


# =============================================================================
# REGISTRY PRIMITIVES - every key is opened in the native 64-bit view
# =============================================================================

@dataclass
class RegValue:
    """One registry value: its name ("" is the (Default) value), type and data."""

    name: str
    value_type: int
    data: Any


@dataclass
class RegKeySnapshot:
    """A key with all of its values and (recursively) all of its subkeys, captured for an undo file."""

    hive_name: str
    subkey: str
    values: list[RegValue] = field(default_factory=list)
    children: list["RegKeySnapshot"] = field(default_factory=list)

    @property
    def full_path(self) -> str:
        """Return the key path in .reg style, e.g. HKEY_LOCAL_MACHINE\\SOFTWARE\\Foo."""
        return f"{self.hive_name}\\{self.subkey}" if self.subkey else self.hive_name


def split_full_key_path(full_path: str) -> tuple[str, str]:
    """
    Split "HKEY_LOCAL_MACHINE\\SOFTWARE\\Foo" into ("HKEY_LOCAL_MACHINE", "SOFTWARE\\Foo").

    Args:
        full_path (str): Path starting with a hive name (long names or HKLM/HKCU style short names).

    Returns:
        tuple[str, str]: Canonical long hive name and the sub-path ("" for the hive itself).

    Raises:
        ValueError: If the path does not start with a known registry hive.
    """
    hive_text, _, subkey = full_path.strip().partition("\\")
    hive_upper = hive_text.upper()
    hive_name = HIVE_ALIASES.get(hive_upper, hive_upper)
    if hive_name not in HIVE_HANDLES:
        raise ValueError(f"Unknown registry hive: {hive_text!r}")
    return hive_name, subkey.strip("\\")


def open_registry_key(hive_name: str, subkey: str, access: int = winreg.KEY_READ) -> Any:
    """
    Open a registry key in the native 64-bit view.

    Args:
        hive_name (str): Long hive name (HKEY_LOCAL_MACHINE, ...).
        subkey (str): Path below the hive ("" opens the hive itself).
        access (int): winreg access rights (KEY_READ by default).

    Returns:
        A winreg key handle (use it as a context manager so it is always closed).

    Raises:
        FileNotFoundError: The key does not exist.
        PermissionError: The key exists but cannot be opened with this access.
    """
    return winreg.OpenKey(HIVE_HANDLES[hive_name], subkey, 0, access | winreg.KEY_WOW64_64KEY)


def registry_key_exists(hive_name: str, subkey: str) -> bool:
    """
    Check whether a key exists.

    A key that exists but cannot be opened (access denied) counts as existing - being conservative
    here prevents anything protected from ever being treated as "missing".

    Args:
        hive_name (str): Long hive name.
        subkey (str): Path below the hive.

    Returns:
        bool: True if the key exists (or exists but is unreadable).
    """
    try:
        with open_registry_key(hive_name, subkey):
            return True
    except FileNotFoundError:
        return False
    except OSError:
        return True


def list_subkey_names(hive_name: str, subkey: str) -> list[str]:
    """
    List the names of a key's direct subkeys.

    Args:
        hive_name (str): Long hive name.
        subkey (str): Path below the hive.

    Returns:
        list[str]: Subkey names; empty if the key is missing or unreadable (a warning is logged for the latter).
    """
    try:
        key = open_registry_key(hive_name, subkey)
    except FileNotFoundError:
        return []
    except OSError as error:
        log(f"[WARNING] Cannot read subkeys of {hive_name}\\{subkey}: {error}")
        return []
    names: list[str] = []
    with key:
        subkey_count = winreg.QueryInfoKey(key)[0]
        for index in range(subkey_count):
            try:
                names.append(winreg.EnumKey(key, index))
            except OSError:
                break  # the key changed while we were reading it; what we have so far is enough
    return names


def read_registry_values(hive_name: str, subkey: str) -> list[RegValue]:
    """
    Read every value stored directly in a key.

    Args:
        hive_name (str): Long hive name.
        subkey (str): Path below the hive.

    Returns:
        list[RegValue]: All values; empty if the key is missing or unreadable (a warning is logged for the latter).
    """
    try:
        key = open_registry_key(hive_name, subkey)
    except FileNotFoundError:
        return []
    except OSError as error:
        log(f"[WARNING] Cannot read values of {hive_name}\\{subkey}: {error}")
        return []
    values: list[RegValue] = []
    with key:
        value_count = winreg.QueryInfoKey(key)[1]
        for index in range(value_count):
            try:
                name, data, value_type = winreg.EnumValue(key, index)
            except OSError:
                break
            values.append(RegValue(name, value_type, data))
    return values


def read_registry_value(hive_name: str, subkey: str, value_name: str) -> RegValue | None:
    """
    Read one value.

    Args:
        hive_name (str): Long hive name.
        subkey (str): Path below the hive.
        value_name (str): Value name ("" for the (Default) value).

    Returns:
        RegValue | None: The value, or None if the key or value does not exist / cannot be read.
    """
    try:
        with open_registry_key(hive_name, subkey) as key:
            data, value_type = winreg.QueryValueEx(key, value_name)
            return RegValue(value_name, value_type, data)
    except FileNotFoundError:
        return None
    except OSError as error:
        log(f"[WARNING] Cannot read {hive_name}\\{subkey} [{value_name or '(Default)'}]: {error}")
        return None


def set_registry_value(hive_name: str, subkey: str, value: RegValue) -> None:
    """
    Create or overwrite one value (creating the key path if needed).

    Args:
        hive_name (str): Long hive name.
        subkey (str): Path below the hive.
        value (RegValue): The value to write.

    Returns:
        None
    """
    access = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
    with winreg.CreateKeyEx(HIVE_HANDLES[hive_name], subkey, 0, access) as key:
        winreg.SetValueEx(key, value.name, 0, value.value_type, value.data)
    log(f"[WRITE] Set {hive_name}\\{subkey} [{value.name or '(Default)'}]")


def delete_registry_value(hive_name: str, subkey: str, value_name: str) -> None:
    """
    Delete one value from a key.

    Args:
        hive_name (str): Long hive name.
        subkey (str): Path below the hive.
        value_name (str): Value name ("" for the (Default) value).

    Returns:
        None
    """
    with open_registry_key(hive_name, subkey, winreg.KEY_SET_VALUE) as key:
        winreg.DeleteValue(key, value_name)
    log(f"[DELETE] Value {hive_name}\\{subkey} [{value_name or '(Default)'}]")


def _delete_single_key(hive_name: str, subkey: str) -> None:
    """Delete one key that has no subkeys left (winreg cannot delete a key that still has children)."""
    parent_path, _, child_name = subkey.rpartition("\\")
    try:
        parent = open_registry_key(hive_name, parent_path, winreg.KEY_WRITE)
    except PermissionError:
        parent = open_registry_key(hive_name, parent_path, winreg.KEY_READ)  # the parent's rights don't matter for deletes
    with parent:
        try:
            winreg.DeleteKeyEx(parent, child_name, winreg.KEY_WOW64_64KEY, 0)
        except NotImplementedError:
            winreg.DeleteKey(parent, child_name)  # 32-bit Windows has only one registry view


def delete_registry_tree(hive_name: str, subkey: str, max_keys: int = MAX_TREE_KEYS_FOR_DELETE) -> int:
    """
    Delete a key together with all of its subkeys (children first, since winreg cannot delete a non-empty key).

    Args:
        hive_name (str): Long hive name.
        subkey (str): Path below the hive (must not be empty - hives themselves are never deleted).
        max_keys (int): Refuse to delete trees with more keys than this.

    Returns:
        int: Number of keys deleted.

    Raises:
        RegistryOperationError: If the path is empty or the tree is unexpectedly large.
    """
    if not subkey.strip("\\"):
        raise RegistryOperationError("Refusing to delete a registry hive root.")
    key_paths = _collect_tree_paths(hive_name, subkey, max_keys)
    for key_path in reversed(key_paths):   # deepest keys first
        _delete_single_key(hive_name, key_path)
    log(f"[DELETE] Key tree {hive_name}\\{subkey} ({len(key_paths)} key(s))")
    return len(key_paths)


def _collect_tree_paths(hive_name: str, subkey: str, max_keys: int) -> list[str]:
    """Return subkey and all descendants (parents before children); raise if there are more than max_keys."""
    collected: list[str] = []
    pending = [subkey]
    while pending:
        current = pending.pop()
        collected.append(current)
        if len(collected) > max_keys:
            raise RegistryOperationError(
                f"{hive_name}\\{subkey} contains more than {max_keys} keys; refusing to process it automatically.")
        pending.extend(f"{current}\\{child}" for child in list_subkey_names(hive_name, current))
    return collected


def snapshot_key_tree(hive_name: str, subkey: str, max_keys: int = MAX_TREE_KEYS_FOR_DELETE) -> RegKeySnapshot:
    """
    Capture a key, all of its values and all of its descendants so they can be written to an undo file.

    Args:
        hive_name (str): Long hive name.
        subkey (str): Path below the hive.
        max_keys (int): Refuse to snapshot trees with more keys than this.

    Returns:
        RegKeySnapshot: The captured tree.

    Raises:
        RegistryOperationError: If the key does not exist or the tree is unexpectedly large.
    """
    if not registry_key_exists(hive_name, subkey):
        raise RegistryOperationError(f"{hive_name}\\{subkey} does not exist.")
    counter = [0]

    def capture(current_path: str) -> RegKeySnapshot:
        """Snapshot one key (its values and, recursively, its subkeys); refuses trees larger than max_keys."""
        counter[0] += 1
        if counter[0] > max_keys:
            raise RegistryOperationError(
                f"{hive_name}\\{subkey} contains more than {max_keys} keys; refusing to process it automatically.")
        snapshot = RegKeySnapshot(hive_name, current_path, read_registry_values(hive_name, current_path))
        for child_name in list_subkey_names(hive_name, current_path):
            snapshot.children.append(capture(f"{current_path}\\{child_name}"))
        return snapshot

    return capture(subkey)


def find_topmost_missing_ancestor(hive_name: str, subkey: str) -> str | None:
    """
    Find the highest key on a path that does not exist yet.

    Creating a deep key also creates every missing parent, so an undo for that creation must delete the
    *topmost* newly created key, not just the deepest one.

    Args:
        hive_name (str): Long hive name.
        subkey (str): Path below the hive.

    Returns:
        str | None: Path of the topmost missing key, or None if the whole path already exists.
    """
    candidate = ""
    for part in (piece for piece in subkey.split("\\") if piece):
        candidate = f"{candidate}\\{part}" if candidate else part
        if not registry_key_exists(hive_name, candidate):
            return candidate
    return None


def is_critical_key_path(full_path: str) -> bool:
    """
    Decide whether deleting this key would endanger the system (used to block "[-KEY]" lines in imports).

    Args:
        full_path (str): Key path beginning with a hive name.

    Returns:
        bool: True if the key is a hive root, a top-level container or a well-known critical key.
    """
    try:
        hive_name, subkey = split_full_key_path(full_path)
    except ValueError:
        return True   # an unparseable target is never safe to delete
    relative = subkey.lower().strip("\\")
    if not relative:
        return True   # hive roots
    if hive_name == HKLM:
        return relative in CRITICAL_MACHINE_KEYS
    if hive_name == HKCU:
        return relative in CRITICAL_USER_KEYS
    if hive_name == HKU:
        parts = relative.split("\\", 1)
        # HKU\<SID> itself is critical, and HKU\<SID>\<critical user key> is too.
        return len(parts) == 1 or parts[1] in CRITICAL_USER_KEYS
    if hive_name == HKCR:
        return relative in CRITICAL_CLASSES_KEYS
    return True   # HKEY_CURRENT_CONFIG and anything unknown


# =============================================================================
# .REG FILE WRITER - produces the same format regedit / reg.exe use (Version 5.00, UTF-16 LE)
# =============================================================================

def escape_reg_string(text: str) -> str:
    """Escape backslashes and double quotes the way .reg files require."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _needs_hex_encoding(text: str) -> bool:
    """Return True if a string contains control characters that would break a one-line .reg value."""
    return any(ord(character) < 32 for character in text)


def value_data_to_bytes(value: RegValue) -> bytes:
    """
    Convert a value's data to the raw bytes Windows stores for it.

    Args:
        value (RegValue): The value to convert.

    Returns:
        bytes: Raw registry data (strings as UTF-16LE with terminating NULs, DWORD/QWORD little-endian).
    """
    data = value.data
    if value.value_type in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) and isinstance(data, str):
        return (data + "\0").encode("utf-16-le", errors="surrogatepass")
    if value.value_type == winreg.REG_MULTI_SZ and isinstance(data, (list, tuple)):
        joined = "".join(f"{item}\0" for item in data) + "\0"   # every string NUL-terminated, plus a final NUL
        return joined.encode("utf-16-le", errors="surrogatepass")
    if isinstance(data, int):
        size = 8 if value.value_type == winreg.REG_QWORD else 4
        return (data & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
    if isinstance(data, str):
        return data.encode("utf-16-le", errors="surrogatepass")
    if data is None:
        return b""
    return bytes(data)


def format_hex_line(prefix: str, raw: bytes) -> str:
    """
    Format raw bytes as a wrapped hex value line like regedit does (80 columns, "\\" continuations).

    Args:
        prefix (str): Everything before the data, e.g. '"Name"=hex(2):'.
        raw (bytes): The data bytes.

    Returns:
        str: One or more lines joined with CRLF (no trailing newline).
    """
    tokens = [f"{byte:02x}" for byte in raw]
    lines: list[str] = []
    current = prefix
    bytes_on_line = 0   # never wrap before the first byte of a line, so a very long name cannot leave "hex:\" alone
    for index, token in enumerate(tokens):
        piece = token + ("," if index < len(tokens) - 1 else "")
        if bytes_on_line > 0 and len(current) + len(piece) + 1 > REG_LINE_WIDTH:   # +1 for the trailing "\"
            lines.append(current + "\\")
            current = "  "
            bytes_on_line = 0
        current += piece
        bytes_on_line += 1
    lines.append(current)
    return "\r\n".join(lines)


def format_reg_value_line(value: RegValue) -> str:
    """
    Turn a RegValue into the text of its .reg line(s).

    Args:
        value (RegValue): The value to format.

    Returns:
        str: The value line, e.g. '"Name"="text"' or '@=dword:00000001' (may span several CRLF-joined lines).
    """
    name_part = "@" if value.name == "" else f'"{escape_reg_string(value.name)}"'
    if value.value_type == winreg.REG_SZ and isinstance(value.data, str) and not _needs_hex_encoding(value.data):
        return f'{name_part}="{escape_reg_string(value.data)}"'
    if value.value_type == winreg.REG_DWORD and isinstance(value.data, int):
        return f"{name_part}=dword:{value.data & 0xFFFFFFFF:08x}"
    hex_prefix = "hex" if value.value_type == winreg.REG_BINARY else f"hex({value.value_type:x})"
    return format_hex_line(f"{name_part}={hex_prefix}:", value_data_to_bytes(value))


def reg_event_fingerprint(kind: str, key_path: str, name: str = "", value_type: int = 0, data: Any = None) -> int:
    """
    A 64-bit fingerprint of one .reg entry (a key, a value, or a deletion).

    The SAME function fingerprints an entry when the writer writes it and again when the entry is read back from the
    file, so comparing the two sequences proves the file holds exactly what was meant to be written (content, not just
    counts) while needing only 8 bytes of memory per entry. Key paths are compared without regard to letter case, like
    the registry itself; value names are compared exactly.

    Args:
        kind (str): "key", "value", "delete_value" or "delete_key".
        key_path (str): Full key path.
        name (str): Value name (value and delete_value entries).
        value_type (int): Registry value type (value entries).
        data (Any): Value data as winreg represents it (value entries).

    Returns:
        int: The fingerprint (a signed 64-bit number).
    """
    if isinstance(data, list):
        data = tuple(data)               # lists cannot be hashed; a tuple with the same items can
    return hash((kind, key_path.lower(), name, value_type, data))


class RegFileWriter:
    """
    Streams a .reg file to disk safely: it writes to "<name>.partial" first and only renames it to the final
    name after the data has been flushed to disk, so a half-written file can never be mistaken for a backup.
    """

    def __init__(self, destination_path: str, track_content: bool = False) -> None:
        """
        Args:
            destination_path (str): Final path of the .reg file.
            track_content (bool): True to remember a fingerprint of every entry written (8 bytes each), so the file can
                be verified entry by entry after it is written (see _verify_streamed_undo_file). Off by default:
                writers whose contents are verified another way (or not at all, like the full backup) skip the cost.
        """
        self.destination_path = destination_path
        self._temp_path = destination_path + ".partial"
        self._file: Any = None
        self._current_key: str | None = None    # key whose header was written last (lower-case), for grouping
        self.keys_written = 0
        self.values_written = 0
        self.deletions_written = 0
        self.event_fingerprints: array | None = array("q") if track_content else None   # None = not tracking

    def __enter__(self) -> "RegFileWriter":
        """Create the destination folder, open the temporary file and write the header."""
        os.makedirs(os.path.dirname(os.path.abspath(self.destination_path)), exist_ok=True)
        self._file = open(self._temp_path, "wb")
        self._file.write(b"\xff\xfe")   # UTF-16 LE byte-order mark
        self._emit(f"{REG_HEADER_V5}\r\n")
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, exc_traceback: Any) -> None:
        """Finish the file: on success flush + rename, on error delete the partial file. Never swallows errors."""
        try:
            if exc_type is None:
                self._file.flush()
                os.fsync(self._file.fileno())   # make sure the data is really on disk before we rely on it
            self._file.close()
            if exc_type is None:
                os.replace(self._temp_path, self.destination_path)
            elif os.path.exists(self._temp_path):
                os.remove(self._temp_path)
        finally:
            self._file = None

    def _emit(self, text: str) -> None:
        """Encode text as UTF-16 LE and append it to the file."""
        self._file.write(text.encode("utf-16-le", errors="surrogatepass"))

    def _track(self, fingerprint: int) -> None:
        """Remember the fingerprint of the entry that was just written (only when tracking is on)."""
        if self.event_fingerprints is not None:
            self.event_fingerprints.append(fingerprint)

    def write_key_header(self, full_key_path: str) -> None:
        """Start a key section ("[HKEY_...\\Path]") unless that key's section is already open."""
        marker = full_key_path.lower()
        if marker == self._current_key:
            return
        self._emit(f"\r\n[{full_key_path}]\r\n")
        self._current_key = marker
        self.keys_written += 1
        self._track(reg_event_fingerprint("key", full_key_path))

    def write_value(self, full_key_path: str, value: RegValue) -> None:
        """Write one value line under the given key (writing the key header first if needed)."""
        self.write_key_header(full_key_path)
        self._emit(format_reg_value_line(value) + "\r\n")
        self.values_written += 1
        self._track(reg_event_fingerprint("value", full_key_path, value.name, value.value_type, value.data))

    def write_value_deletion(self, full_key_path: str, value_name: str) -> None:
        """Write a '"name"=-' line, which makes an import DELETE that value (used to undo value creation)."""
        self.write_key_header(full_key_path)
        name_part = "@" if value_name == "" else f'"{escape_reg_string(value_name)}"'
        self._emit(f"{name_part}=-\r\n")
        self.deletions_written += 1
        self._track(reg_event_fingerprint("delete_value", full_key_path, value_name))

    def write_key_deletion(self, full_key_path: str) -> None:
        """Write a '[-KEY]' line, which makes an import DELETE that key (used to undo key creation)."""
        self._emit(f"\r\n[-{full_key_path}]\r\n")
        self._current_key = None
        self.deletions_written += 1
        self._track(reg_event_fingerprint("delete_key", full_key_path))

    def write_snapshot_tree(self, snapshot: RegKeySnapshot) -> None:
        """Write a whole captured key tree (parents before children) so importing it recreates everything."""
        self.write_key_header(snapshot.full_path)
        for value in snapshot.values:
            self.write_value(snapshot.full_path, value)
        for child in snapshot.children:
            self.write_snapshot_tree(child)


# =============================================================================
# .REG FILE PARSER - reads Version 5.00 (UTF-16) and REGEDIT4 (ANSI) scripts
# =============================================================================

@dataclass
class RegFileEvent:
    """One meaningful line of a .reg file, in file order."""

    kind: str                       # "key", "delete_key", "value", "delete_value" or "warning"
    key_path: str = ""              # full key path for key/value events (and for a warning about an unparsable value line)
    value: RegValue | None = None   # for "value" events
    value_name: str = ""            # for "delete_value" events
    message: str = ""               # for "warning" events
    line_number: int = 0


def fingerprint_of_event(event: RegFileEvent) -> int:
    """
    Fingerprint an entry read back from a .reg file the same way RegFileWriter fingerprinted it when writing it.

    Args:
        event (RegFileEvent): A "key", "value", "delete_value" or "delete_key" event (not a warning).

    Returns:
        int: The fingerprint; equal to the writer's if the entry was read back exactly as written.
    """
    if event.kind == "value" and event.value is not None:
        return reg_event_fingerprint("value", event.key_path, event.value.name, event.value.value_type, event.value.data)
    if event.kind == "delete_value":
        return reg_event_fingerprint("delete_value", event.key_path, event.value_name)
    return reg_event_fingerprint(event.kind, event.key_path)


def describe_reg_event(event: RegFileEvent) -> str:
    """Short readable description of one .reg entry for error messages."""
    if event.kind == "value" and event.value is not None:
        return f"value {event.value.name or '(Default)'} of {short_hive_path(event.key_path)}"
    if event.kind == "delete_value":
        return f"deletion of value {event.value_name or '(Default)'} in {short_hive_path(event.key_path)}"
    if event.kind == "delete_key":
        return f"deletion of key {short_hive_path(event.key_path)}"
    return f"key {short_hive_path(event.key_path)}"


def detect_reg_encoding(path: str) -> str:
    """
    Guess a .reg file's text encoding from its first bytes.

    Args:
        path (str): Path of the file.

    Returns:
        str: A Python codec name.
    """
    with open(path, "rb") as file:
        head = file.read(4)
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"                       # the codec reads and strips the byte-order mark itself
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if len(head) >= 2 and head[1:2] == b"\x00":
        return "utf-16-le"                    # ASCII text stored as UTF-16 without a BOM
    return "mbcs" if sys.platform == "win32" else "cp1252"   # REGEDIT4 files use the ANSI code page


def _read_quoted_string(text: str, start: int) -> tuple[str, int]:
    """Read a double-quoted, backslash-escaped string starting at text[start] == '"'; return (value, index after it)."""
    characters: list[str] = []
    index = start + 1
    while index < len(text):
        character = text[index]
        if character == "\\" and index + 1 < len(text) and text[index + 1] in ('\\', '"'):
            characters.append(text[index + 1])   # \\ -> \   and   \" -> "
            index += 2
            continue
        if character == '"':
            return "".join(characters), index + 1
        characters.append(character)
        index += 1
    raise ValueError("unterminated quoted string")


def _decode_utf16_bytes(raw: bytes) -> str:
    """Decode registry string bytes (UTF-16LE); an odd trailing byte is ignored."""
    if len(raw) % 2:
        raw = raw[:-1]
    return raw.decode("utf-16-le", errors="surrogatepass")


def _split_multi_sz(text: str) -> list[str]:
    """
    Split the decoded text of a REG_MULTI_SZ value into its strings, exactly the way Python's winreg module does.

    Every string ends with a NUL and the whole list ends with one more NUL, so "a\0b\0\0" is ["a", "b"], an
    "empty" list stored as two NULs is [""] (ONE empty string, not no strings) and "a\0\0\0" is ["a", ""]. Only the
    single list terminator is dropped. The earlier version stripped EVERY trailing empty string, which turned [""]
    into [] and ["a", ""] into ["a"]: a value read back from an undo file then differed from the value read from the
    registry, and the undo safety check rejected perfectly good backups.

    Args:
        text (str): The decoded UTF-16 text of the value (NULs included).

    Returns:
        list[str]: The strings, identical to what winreg returns for the same raw data.
    """
    if text.endswith("\0"):
        text = text[:-1]                 # the list terminator
    if not text:
        return []
    parts = text.split("\0")
    if text.endswith("\0"):
        parts.pop()                      # the piece after the last NUL is not a string, it only exists because of the split
    return parts


def _convert_hex_value(name: str, type_id: int, raw: bytes) -> RegValue:
    """
    Turn the raw bytes of a hex(N): value into a RegValue exactly as Python's winreg module would have returned it.

    "Exactly as winreg" matters: the undo checks compare a value read back from a file with the value read from the
    registry, so any difference in representation (an empty binary value is None in winreg, a multi-string keeps its
    empty strings) would show up as a false "missing or different".
    """
    if type_id in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
        return RegValue(name, type_id, _decode_utf16_bytes(raw).split("\0", 1)[0])
    if type_id == winreg.REG_MULTI_SZ:
        return RegValue(name, type_id, _split_multi_sz(_decode_utf16_bytes(raw)))
    if type_id == winreg.REG_DWORD and len(raw) == 4:
        return RegValue(name, type_id, int.from_bytes(raw, "little"))
    if type_id == winreg.REG_QWORD and len(raw) == 8:
        return RegValue(name, type_id, int.from_bytes(raw, "little"))
    return RegValue(name, type_id, bytes(raw) if raw else None)   # winreg returns None (not b"") for empty binary data


def parse_reg_value_line(line: str) -> tuple[str, RegValue | None]:
    """
    Parse one (already joined) value line of a .reg file.

    Args:
        line (str): A line such as '"Name"="text"', '@=dword:00000001', '"x"=hex(2):41,00' or '"x"=-'.

    Returns:
        tuple[str, RegValue | None]: (value name, parsed value) - the value is None for a deletion ('=-').

    Raises:
        ValueError: If the line is malformed.
    """
    if line.startswith("@"):
        name = ""
        remainder = line[1:]
    elif line.startswith('"'):
        name, end_index = _read_quoted_string(line, 0)
        remainder = line[end_index:]
    else:
        raise ValueError("line does not start with a value name")
    remainder = remainder.lstrip()
    if not remainder.startswith("="):
        raise ValueError("missing '=' after the value name")
    data = remainder[1:].strip()
    if data == "-":
        return name, None
    if data.startswith('"'):
        text, _ = _read_quoted_string(data, 0)
        return name, RegValue(name, winreg.REG_SZ, text)
    lowered = data.lower()
    if lowered.startswith("dword:"):
        return name, RegValue(name, winreg.REG_DWORD, int(data[6:].strip(), 16))
    if lowered.startswith("hex"):
        colon_index = data.find(":")
        if colon_index < 0:
            raise ValueError("hex value without ':'")
        type_spec = lowered[3:colon_index].strip()
        if type_spec == "":
            type_id = winreg.REG_BINARY
        elif type_spec.startswith("(") and type_spec.endswith(")"):
            type_id = int(type_spec[1:-1], 16)
        else:
            raise ValueError(f"bad hex type {type_spec!r}")
        tokens = [token.strip() for token in data[colon_index + 1:].split(",")]
        byte_values: list[int] = []
        for token in tokens:
            if not token:
                continue
            if len(token) > 2:
                raise ValueError(f"bad hex byte {token!r}")
            byte_values.append(int(token, 16))
        return name, _convert_hex_value(name, type_id, bytes(byte_values))
    raise ValueError("unsupported value data format")


def _iter_logical_lines(stream: Any) -> Iterator[tuple[int, str]]:
    """
    Yield (first line number, text) for each .reg line, joining "\\" continuation lines and skipping comments.

    Continuation pieces are collected in a list and joined once: a large binary value spans thousands of lines, and
    repeated string concatenation would make parsing it quadratically slow (seconds for a 1 MB value).
    """
    pieces: list[str] = []
    first_line = 0
    for number, raw_line in enumerate(stream, start=1):
        text = raw_line.rstrip("\r\n")
        if pieces:
            text = text.lstrip()                 # continuation lines are indented
        else:
            text = text.strip()
            first_line = number
            if text.startswith(";"):
                continue                         # a comment is never a continuation, even if it ends with a backslash
        if text.endswith("\\"):                  # only hex values continue on the next line
            pieces.append(text[:-1])
            continue
        pieces.append(text)
        joined = "".join(pieces)
        pieces = []
        if joined:
            yield first_line, joined
    if pieces:
        yield first_line, "".join(pieces)


class _CountingReader(io.RawIOBase):
    """Read-only wrapper around a binary file that counts the bytes read (drives the progress bar for big files)."""

    def __init__(self, raw_file: Any, counter: list[int]) -> None:
        """
        Args:
            raw_file: An open binary file.
            counter (list[int]): One-item list that receives the running total of bytes read.
        """
        super().__init__()
        self._raw_file = raw_file
        self._counter = counter

    def readable(self) -> bool:
        """This wrapper can always be read from."""
        return True

    def readinto(self, buffer: Any) -> int:
        """Read into buffer (as io.RawIOBase requires) and add the byte count to the shared counter."""
        count = self._raw_file.readinto(buffer) or 0
        self._counter[0] += count
        return count

    def close(self) -> None:
        """Close the wrapped file as well."""
        try:
            self._raw_file.close()
        finally:
            super().close()


def iter_reg_file_events(path: str, byte_counter: list[int] | None = None) -> Iterator[RegFileEvent]:
    """
    Stream the meaningful lines of a .reg file (works for very large files - nothing is held in memory).

    Args:
        path (str): Path of the .reg file.
        byte_counter (list[int] | None): Optional one-item list that is updated with the number of bytes read so far.

    Yields:
        RegFileEvent: Key sections, value assignments, deletions and warnings for lines that could not be parsed.

    Raises:
        RegParseError: If the file does not start with a valid .reg header.
        OSError: If the file cannot be read.
    """
    encoding = detect_reg_encoding(path)
    counter = byte_counter if byte_counter is not None else [0]
    current_key: str | None = None
    header_seen = False
    with open(path, "rb") as raw_file:
        stream = io.TextIOWrapper(io.BufferedReader(_CountingReader(raw_file, counter)),
                                  encoding=encoding, errors="replace", newline=None)
        for line_number, line in _iter_logical_lines(stream):
            if not header_seen:
                if line not in (REG_HEADER_V5, REG_HEADER_V4):
                    raise RegParseError("This is not a registry script: the first line must be "
                                        f"'{REG_HEADER_V5}' or '{REG_HEADER_V4}'.")
                header_seen = True
                continue
            if line.startswith("[") and line.endswith("]"):
                inner = line[1:-1]
                is_delete = inner.startswith("-")
                key_path = inner[1:] if is_delete else inner
                try:
                    split_full_key_path(key_path)
                except ValueError:
                    current_key = None
                    yield RegFileEvent("warning", message=f"Unknown registry hive in: {line}", line_number=line_number)
                    continue
                if is_delete:
                    current_key = None
                    yield RegFileEvent("delete_key", key_path=key_path, line_number=line_number)
                else:
                    current_key = key_path
                    yield RegFileEvent("key", key_path=key_path, line_number=line_number)
                continue
            if line.startswith("@") or line.startswith('"'):
                if current_key is None:
                    yield RegFileEvent("warning", message=f"Value outside of a key: {line[:60]}", line_number=line_number)
                    continue
                try:
                    name, value = parse_reg_value_line(line)
                except ValueError as error:
                    # The key is attached so that an unparsable line in an UNDO file can be traced back to the finding
                    # it belongs to (which is what makes "Continue anyway" possible for that finding).
                    yield RegFileEvent("warning", key_path=current_key,
                                       message=f"Could not parse ({error}): {line[:60]}", line_number=line_number)
                    continue
                if value is None:
                    yield RegFileEvent("delete_value", key_path=current_key, value_name=name, line_number=line_number)
                else:
                    yield RegFileEvent("value", key_path=current_key, value=value, line_number=line_number)
                continue
            yield RegFileEvent("warning", message=f"Unrecognised line: {line[:60]}", line_number=line_number)
    if not header_seen:
        raise RegParseError("The file is empty.")


# =============================================================================
# SAFE PATH VERIFICATION
# =============================================================================
# The single most important rule of a registry cleaner: only call something "broken" when it is PROVEN
# missing. Everything uncertain becomes PathStatus.UNKNOWN and is skipped.

class PathStatus(Enum):
    """Result of checking a file/folder path."""

    EXISTS = "exists"
    MISSING = "missing"    # proven missing on a drive that is mounted right now
    UNKNOWN = "unknown"    # cannot be verified safely -> never treated as broken


_protected_prefix_cache: list[str] | None = None


def expand_env_vars(text: str) -> str:
    """Expand %VARIABLES% in text (unknown variables are left as they are)."""
    try:
        return winreg.ExpandEnvironmentStrings(text)
    except OSError:
        return text


def normalize_path_for_compare(path: str) -> str:
    """Normalise a Windows path (case, slashes, ".." parts) so two paths can be compared safely."""
    return ntpath.normcase(ntpath.normpath(path))


def get_protected_prefixes() -> list[str]:
    """Return the expanded, normalised list of Windows-owned folders that must never be flagged (cached)."""
    global _protected_prefix_cache
    if _protected_prefix_cache is None:
        prefixes: list[str] = []
        for template in PROTECTED_PATH_TEMPLATES:
            expanded = expand_env_vars(template)
            if "%" not in expanded:        # skip templates whose variable does not exist (e.g. x86 folders on 32-bit)
                prefixes.append(normalize_path_for_compare(expanded))
        _protected_prefix_cache = prefixes
    return _protected_prefix_cache


def is_protected_path(path: str) -> bool:
    """
    Check whether a path lies inside a Windows-owned folder (Windows itself, WindowsApps, Defender, ...).

    Args:
        path (str): Absolute path.

    Returns:
        bool: True if the path is inside (or equal to) a protected folder.
    """
    normalized = normalize_path_for_compare(path)
    return any(normalized == prefix or normalized.startswith(prefix + "\\") for prefix in get_protected_prefixes())


def get_drive_type(drive_root: str) -> int:
    """
    Ask Windows what kind of drive a root like "C:\\" is (3 = fixed disk, 1 = not mounted, 4 = network, ...).

    Args:
        drive_root (str): Drive root such as "C:\\".

    Returns:
        int: A GetDriveTypeW code, or 0 if it cannot be determined.
    """
    try:
        return int(ctypes.windll.kernel32.GetDriveTypeW(drive_root))  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return 0


def probe_path(path: str) -> PathStatus:
    """
    Look for a path on disk. Only a definite "not found" answer counts as MISSING; access-denied and any other
    error is UNKNOWN, so protected or unreadable locations can never be mistaken for missing ones.

    Args:
        path (str): Absolute, normalised path.

    Returns:
        PathStatus: EXISTS, MISSING or UNKNOWN.
    """
    try:
        os.stat(path)
    except FileNotFoundError:
        return PathStatus.MISSING
    except OSError:
        return PathStatus.UNKNOWN
    return PathStatus.EXISTS


def check_path_status(raw_path: str) -> PathStatus:
    """
    Verify a file/folder path taken from the registry.

    The path must be an absolute local path on a currently mounted FIXED drive, fully resolvable, not too long,
    free of illegal characters and outside all protected Windows folders - otherwise the answer is UNKNOWN.

    Args:
        raw_path (str): Path as stored in the registry (may be quoted and contain %VARIABLES%).

    Returns:
        PathStatus: EXISTS, MISSING (proven) or UNKNOWN.
    """
    text = raw_path.strip().strip('"').strip()
    if not text:
        return PathStatus.UNKNOWN
    expanded = expand_env_vars(text).strip().strip('"').strip()
    if "%" in expanded or len(expanded) > MAX_SAFE_PATH_LENGTH:
        return PathStatus.UNKNOWN
    drive, remainder = ntpath.splitdrive(expanded)
    if not re.fullmatch(r"[A-Za-z]:", drive) or not remainder.startswith(("\\", "/")):
        return PathStatus.UNKNOWN   # relative paths, UNC shares, \\?\ device paths ...
    if any(character in remainder for character in '<>|*?":'):
        return PathStatus.UNKNOWN   # illegal characters (also blocks NTFS alternate data streams)
    normalized = ntpath.normpath(expanded)
    if is_protected_path(normalized):
        return PathStatus.UNKNOWN
    if get_drive_type(drive.upper() + "\\") != DRIVE_FIXED:
        return PathStatus.UNKNOWN   # drive not mounted right now (external/network/optical) -> cannot judge
    return probe_path(normalized)


@dataclass
class CommandCheck:
    """Outcome of checking the program a command line would start."""

    status: PathStatus
    display_path: str = ""                       # the path to show the user
    checked_paths: tuple[str, ...] = ()          # every path variant that was checked (re-checked before deleting)


def _command_path_candidates(expanded_command: str) -> list[str]:
    """
    List the file paths Windows could mean by a command line.

    A quoted command has exactly one candidate. An unquoted command like `C:\\Program Files\\App\\app.exe /x`
    is ambiguous (Windows tries "C:\\Program", then "C:\\Program Files\\App\\app.exe", ...), so every
    space-separated prefix is a candidate.
    """
    if expanded_command.startswith('"'):
        end_index = expanded_command.find('"', 1)
        return [expanded_command[1:end_index]] if end_index > 1 else []
    usable_tokens: list[str] = []
    for position, token in enumerate(expanded_command.split(" ")[:12]):
        # Arguments start at the first switch ("/S", "-x"), placeholder ("%1", "%V") or quote: they are never part
        # of the program path, and must not make the check "unknown" (%1 appears in almost every shell command).
        if position > 0 and (token.startswith(("/", "-")) or "%" in token or '"' in token):
            break
        usable_tokens.append(token)
    candidates: list[str] = []
    for count in range(1, len(usable_tokens) + 1):
        candidate = " ".join(usable_tokens[:count]).strip()
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    return candidates


def resolve_command_status(command: str) -> CommandCheck:
    """
    Decide whether the program a command line starts (Run entry, uninstaller, menu verb ...) exists.

    Only absolute paths on local fixed drives can come out as MISSING, and only if *every* possible reading of the
    command is proven missing. Bare command names (`rundll32.exe`), UNC/network paths and relative paths are UNKNOWN
    without touching the file system or the network.

    Args:
        command (str): Command line as stored in the registry (may contain %VARIABLES% and arguments).

    Returns:
        CommandCheck: The status plus the paths that were examined.
    """
    text = command.strip()
    while text[:1] in ("!", "*"):          # RunOnce prefixes: "!" = delete after running, "*" = run in safe mode
        text = text[1:].lstrip()
    if not text:
        return CommandCheck(PathStatus.UNKNOWN)
    expanded = expand_env_vars(text).strip()
    candidates = _command_path_candidates(expanded)   # an unresolved %VARIABLE% inside a candidate makes it UNKNOWN below
    if not candidates:
        return CommandCheck(PathStatus.UNKNOWN, display_path=text)
    if not re.match(r"^[A-Za-z]:[\\/]", candidates[0]):
        # Bare command names (resolved through PATH), UNC shares and relative paths are never judged. Looking them up
        # would touch every PATH folder or contact a remote server, and a stale network location can freeze the caller
        # for many seconds - the scanner must NEVER cause that kind of stall itself.
        return CommandCheck(PathStatus.UNKNOWN, display_path=candidates[0])
    variants: list[str] = []
    for candidate in candidates:
        variants.append(candidate)
        if not ntpath.splitext(candidate)[1]:
            variants.append(candidate + ".exe")   # CreateProcess appends .exe when there is no extension
    statuses = [check_path_status(variant) for variant in variants]
    if PathStatus.EXISTS in statuses:
        overall = PathStatus.EXISTS
    elif PathStatus.UNKNOWN in statuses:
        overall = PathStatus.UNKNOWN
    else:
        overall = PathStatus.MISSING
    executable_like = [item for item in candidates if ntpath.splitext(item)[1].lower() in (".exe", ".com", ".bat", ".cmd", ".scr", ".dll")]
    display = executable_like[-1] if executable_like else candidates[0]
    return CommandCheck(overall, display_path=display, checked_paths=tuple(variants))


def extract_icon_path(icon_reference: str) -> str:
    """Strip quotes and the trailing ",index" from a DisplayIcon style reference ("C:\\App\\a.exe,0" -> "C:\\App\\a.exe")."""
    text = icon_reference.strip().strip('"')
    path, separator, index = text.rpartition(",")
    return path.strip().strip('"') if separator and re.fullmatch(r"\s*-?\d+\s*", index) else text


# =============================================================================
# SCAN CATEGORIES AND RESULT MODEL
# =============================================================================

CATEGORY_UNINSTALL = "uninstall"
CATEGORY_SHARED_DLLS = "shared_dlls"
CATEGORY_APP_PATHS = "app_paths"
CATEGORY_STARTUP = "startup"
CATEGORY_MUI_CACHE = "mui_cache"
CATEGORY_FONTS = "fonts"
CATEGORY_FILE_ASSOC = "file_associations"
CATEGORY_CONTEXT_MENU = "context_menu"
CATEGORY_NET_HISTORY = "network_history"


@dataclass(frozen=True)
class ScanCategory:
    """One checkbox on the Clean tab: what it is called and exactly what it looks for."""

    key: str
    title: str
    tooltip: str


SCAN_CATEGORIES: tuple[ScanCategory, ...] = (
    ScanCategory(CATEGORY_UNINSTALL, "Leftover uninstall entries",
                 "Entries in 'Installed apps' whose uninstaller, install folder AND icon are all gone.\n"
                 "Windows Installer (MSI) products, updates and system components are never touched."),
    ScanCategory(CATEGORY_SHARED_DLLS, "Stale shared-DLL counts",
                 "Older setup programs keep a reference count (SharedDLLs) for every shared file they install.\n"
                 "This lists counts for files that no longer exist: leftover bookkeeping, not missing files.\n"
                 "Removing one is harmless; a setup program simply records it again if it ever installs that file."),
    ScanCategory(CATEGORY_APP_PATHS, "Broken application paths",
                 "'App Paths' entries (used by the Run dialog) whose program no longer exists."),
    ScanCategory(CATEGORY_STARTUP, "Broken startup entries",
                 "Run / RunOnce entries that start a program which no longer exists.\n"
                 "Startup items you switched off in Task Manager or Settings are left alone."),
    ScanCategory(CATEGORY_MUI_CACHE, "Stale program-name cache",
                 "MUI cache entries (cached display names) for programs that no longer exist. Windows rebuilds them if needed."),
    ScanCategory(CATEGORY_FONTS, "Missing font files",
                 "Font entries that point to a font file outside the Windows folder which no longer exists."),
    ScanCategory(CATEGORY_FILE_ASSOC, "Orphaned file associations",
                 "File extensions pointing to a program type that no longer exists, and program types whose\n"
                 "'open' commands all point to missing programs. Critical system types and your chosen defaults are never touched."),
    ScanCategory(CATEGORY_CONTEXT_MENU, "Dead right-click menu entries",
                 "Right-click menu items (for files, folders and drives) whose program or shell-extension DLL no longer exists."),
    ScanCategory(CATEGORY_NET_HISTORY, "Stale network history ⚠",
                 "Remembered network locations (\\\\server\\share) in Explorer's address-bar history, the Map Network Drive list\n"
                 "and the network mount-point cache. If such a server is unreachable, Explorer can freeze for many seconds\n"
                 "while it tries to contact it.\n"
                 "This is history you may have created on purpose, so the findings start UNTICKED: review them and tick\n"
                 "what you want removed. Mapped drives, saved credentials and shortcuts are never touched, and nothing\n"
                 "is contacted over the network."),
)
SCAN_CATEGORY_TITLES = {category.key: category.title for category in SCAN_CATEGORIES}

# (hive name, key path lower-case, value name lower-case or None) - see BrokenEntry.identity
EntryIdentity = tuple[str, str, str | None]


@dataclass
class BrokenEntry:
    """One finding: a registry key (or a single value) that points at something that no longer exists."""

    category: str
    hive_name: str
    key_path: str
    value_name: str | None      # None -> the finding is the whole key (deleted as a tree); otherwise one value
    reason: str
    detail: str = ""
    recheck_missing_paths: tuple[str, ...] = ()   # paths that must STILL be missing right before deletion
    recheck_missing_progid: str = ""              # a ProgID that must STILL not exist right before deletion
    review_first: bool = False                    # True -> may be deliberate user history: listed, but starts UNTICKED
    group: str = ""                               # sort/grouping label inside a category (e.g. the server name)

    @property
    def full_key_path(self) -> str:
        """The key in .reg style, e.g. HKEY_LOCAL_MACHINE\\SOFTWARE\\Foo."""
        return f"{self.hive_name}\\{self.key_path}"

    @property
    def identity(self) -> EntryIdentity:
        """
        A hashable, case-insensitive fingerprint of WHAT this finding is (hive + key + value), independent of the object.

        The registry ignores letter case, and a re-scan builds brand-new BrokenEntry objects for the same registry
        location. Bookkeeping that has to survive a re-scan (how often an entry failed the undo check) is therefore
        keyed by this fingerprint instead of by the object itself.
        """
        return (self.hive_name.upper(), self.key_path.lower(), None if self.value_name is None else self.value_name.lower())

    @property
    def display_location(self) -> str:
        """Short, readable location for the results list."""
        short_hive = {HKLM: "HKLM", HKCU: "HKCU"}.get(self.hive_name, self.hive_name)
        suffix = f"  [{self.value_name or '(Default)'}]" if self.value_name is not None else ""
        return f"{short_hive}\\{self.key_path}{suffix}"


def extract_unc_host(path: str) -> str:
    """
    Return the server name of a UNC network path.

    Args:
        path (str): Text such as \\\\server\\share\\folder or the long form \\\\?\\UNC\\server\\share.

    Returns:
        str: The host part ("server"), or "" if the text is not a UNC network path.
    """
    text = path.strip().strip('"')
    if text.lower().startswith("\\\\?\\unc\\"):
        text = "\\\\" + text[8:]                 # the long form \\?\UNC\server\share means \\server\share
    if not text.startswith("\\\\"):
        return ""
    host = text[2:].split("\\", 1)[0].strip()
    return "" if host in ("", ".", "?") else host


def is_local_host(host: str) -> bool:
    """
    Check whether a UNC host name refers to this very PC (which can never be "unreachable").

    Args:
        host (str): Host part of a UNC path.

    Returns:
        bool: True for localhost, the loopback addresses and this PC's own name.
    """
    lowered = host.strip("[]").lower()
    if lowered in LOCAL_HOST_NAMES:
        return True
    computer_name = os.environ.get("COMPUTERNAME", "").lower()
    return bool(computer_name) and (lowered == computer_name or lowered.startswith(computer_name + "."))


def remote_host_of_value(value: RegValue) -> str:
    """
    Return the REMOTE server named by a string value that holds a UNC path.

    Args:
        value (RegValue): Any registry value.

    Returns:
        str: The server name, or "" if the value is not a UNC path or points at this PC itself.
    """
    if value.value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or not isinstance(value.data, str):
        return ""
    host = extract_unc_host(value.data)
    return "" if not host or is_local_host(host) else host


def parse_mount_point_name(key_name: str) -> str:
    """
    Turn the name of a MountPoints2 network subkey back into a UNC path.

    Explorer stores a network share it has seen as a subkey called "##server#share" (a registry key name cannot
    contain a backslash, so "#" stands in for it).

    Args:
        key_name (str): Subkey name, e.g. "##nas#media".

    Returns:
        str: The UNC path (e.g. \\\\nas\\media), or "" if the name is not a network mount point.
    """
    if not key_name.startswith("##"):
        return ""
    parts = [part for part in key_name[2:].split("#") if part]
    return "\\\\" + "\\".join(parts) if parts else ""


def progid_exists(progid: str) -> bool:
    """Check (directly in the registry) whether a ProgID exists in any of the four class stores."""
    relative_paths = ((HKLM, r"SOFTWARE\Classes"), (HKCU, r"Software\Classes"),
                      CLASSES_WOW_HKLM, CLASSES_WOW_HKCU)
    return any(registry_key_exists(hive, f"{root}\\{progid}") for hive, root in relative_paths)


# =============================================================================
# THE SCANNER
# =============================================================================

class RegistryScanner:
    """
    Read-only scanner: walks the chosen categories and returns BrokenEntry findings.
    It never writes anything - cleaning is a separate, guarded step.
    """

    _CLSID_PATTERN = re.compile(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")

    def __init__(self, reporter: ProgressReporter) -> None:
        """
        Args:
            reporter (ProgressReporter): Receives progress/status and provides the cancel flag.
        """
        self.reporter = reporter
        self._items_seen = 0

    def scan(self, category_keys: list[str]) -> list[BrokenEntry]:
        """
        Scan the selected categories.

        Args:
            category_keys (list[str]): Category keys (see SCAN_CATEGORIES) to scan.

        Returns:
            list[BrokenEntry]: All findings, sorted by category and location.

        Raises:
            OperationCancelled: If the user pressed Cancel.
        """
        handlers: dict[str, Callable[[], list[BrokenEntry]]] = {
            CATEGORY_UNINSTALL: self.scan_uninstall,
            CATEGORY_SHARED_DLLS: self.scan_shared_dlls,
            CATEGORY_APP_PATHS: self.scan_app_paths,
            CATEGORY_STARTUP: self.scan_startup,
            CATEGORY_MUI_CACHE: self.scan_mui_cache,
            CATEGORY_FONTS: self.scan_fonts,
            CATEGORY_FILE_ASSOC: self.scan_file_associations,
            CATEGORY_CONTEXT_MENU: self.scan_context_menus,
            CATEGORY_NET_HISTORY: self.scan_network_history,
        }
        selected = [key for key in handlers if key in category_keys]
        findings: list[BrokenEntry] = []
        for position, key in enumerate(selected):
            self.reporter.raise_if_cancelled()
            self.reporter.report(int(position * 100 / max(1, len(selected))), f"Scanning: {SCAN_CATEGORY_TITLES[key]}...", force=True)
            try:
                category_findings = handlers[key]()
            except OperationCancelled:
                raise
            except Exception:   # one broken category must not abort the whole scan
                log_exception(f"Scan of category '{key}' failed")
                self.reporter.status(f"Skipped '{SCAN_CATEGORY_TITLES[key]}' because of an error (see the log).")
                continue
            raw_count = len(category_findings)
            category_findings = keep_only_deletable(category_findings)   # never list what the allow-list would refuse
            if len(category_findings) != raw_count:
                self.reporter.status(f"{raw_count - len(category_findings)} finding(s) in '{SCAN_CATEGORY_TITLES[key]}' were left out "
                                     "because they are outside the safe cleaning locations (see the log).")
            log(f"[SCAN] {SCAN_CATEGORY_TITLES[key]}: {len(category_findings)} broken entr{'y' if len(category_findings) == 1 else 'ies'} found")
            findings.extend(category_findings)
        self.reporter.report(100, f"Scan finished: {len(findings)} broken entries found.")
        category_order = {category.key: position for position, category in enumerate(SCAN_CATEGORIES)}
        findings.sort(key=lambda entry: (category_order.get(entry.category, 99), entry.group.lower(),
                                         entry.full_key_path.lower(), (entry.value_name or "").lower()))
        return findings

    def _tick(self) -> None:
        """Check for a Cancel request every 64 items (cheap enough to call in every loop)."""
        self._items_seen += 1
        if self._items_seen % 64 == 0:
            self.reporter.raise_if_cancelled()

    # ------------------------------------------------------------------ uninstall entries
    def scan_uninstall(self) -> list[BrokenEntry]:
        """Find Uninstall entries whose uninstaller, install folder and icon are all provably gone."""
        findings: list[BrokenEntry] = []
        for hive_name, root in UNINSTALL_ROOTS:
            for entry_name in list_subkey_names(hive_name, root):
                self._tick()
                key_path = f"{root}\\{entry_name}"
                values = {value.name.lower(): value for value in read_registry_values(hive_name, key_path)}
                finding = self._evaluate_uninstall_entry(hive_name, key_path, values)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _evaluate_uninstall_entry(self, hive_name: str, key_path: str, values: dict[str, RegValue]) -> BrokenEntry | None:
        """Apply the strict rules that decide whether one Uninstall entry is broken (None = leave it alone)."""
        def text(name: str) -> str:
            """Return a stripped text value of this Uninstall entry ("" if it is missing or not text)."""
            value = values.get(name)
            return value.data.strip() if value is not None and isinstance(value.data, str) else ""

        def number(name: str) -> int:
            """Return a numeric value of this Uninstall entry (0 if it is missing or not a number)."""
            value = values.get(name)
            return value.data if value is not None and isinstance(value.data, int) else 0

        if number("systemcomponent") == 1 or number("windowsinstaller") == 1:
            return None                     # hidden system components and MSI products are managed by Windows
        if "parentkeyname" in values or "parentdisplayname" in values:
            return None                     # updates/patches use their parent's uninstaller
        uninstall_string = text("uninstallstring")
        if not uninstall_string or not text("displayname"):
            return None                     # nothing to verify, or an entry that is not shown to the user anyway
        if "msiexec" in uninstall_string.lower():
            return None
        uninstall_check = resolve_command_status(uninstall_string)
        if uninstall_check.status != PathStatus.MISSING:
            return None
        rechecks = list(uninstall_check.checked_paths)
        quiet_string = text("quietuninstallstring")
        if quiet_string:
            quiet_check = resolve_command_status(quiet_string)
            if quiet_check.status != PathStatus.MISSING:
                return None
            rechecks.extend(quiet_check.checked_paths)
        install_location = text("installlocation")
        if install_location:                # if the install folder is still there the program is probably still there
            if check_path_status(install_location) != PathStatus.MISSING:
                return None
            rechecks.append(install_location)
        display_icon = text("displayicon")
        if display_icon:
            icon_path = extract_icon_path(display_icon)
            if check_path_status(icon_path) != PathStatus.MISSING:
                return None
            rechecks.append(icon_path)
        return BrokenEntry(
            CATEGORY_UNINSTALL, hive_name, key_path, None,
            f"Uninstaller not found: {uninstall_check.display_path}",
            detail=f"Program: {text('displayname')}\nUninstall command: {uninstall_string}",
            recheck_missing_paths=tuple(rechecks))

    # ------------------------------------------------------------------ shared DLLs
    def scan_shared_dlls(self) -> list[BrokenEntry]:
        """Find SharedDLLs reference counts for files that no longer exist."""
        findings: list[BrokenEntry] = []
        for hive_name, root in SHARED_DLL_ROOTS:
            for value in read_registry_values(hive_name, root):
                self._tick()
                if value.name and check_path_status(value.name) == PathStatus.MISSING:
                    findings.append(BrokenEntry(
                        CATEGORY_SHARED_DLLS, hive_name, root, value.name, f"Shared file not found: {value.name}",
                        detail=f"Reference count: {value.data}", recheck_missing_paths=(value.name,)))
        return findings

    # ------------------------------------------------------------------ app paths
    def scan_app_paths(self) -> list[BrokenEntry]:
        """Find App Paths entries whose program no longer exists."""
        findings: list[BrokenEntry] = []
        for hive_name, root in APP_PATHS_ROOTS:
            for entry_name in list_subkey_names(hive_name, root):
                self._tick()
                key_path = f"{root}\\{entry_name}"
                values = {value.name.lower(): value for value in read_registry_values(hive_name, key_path)}
                default = values.get("")
                if default is None or not isinstance(default.data, str) or not default.data.strip():
                    continue
                if "delegateexecute" in values:
                    continue
                check = resolve_command_status(default.data)
                if check.status == PathStatus.MISSING:
                    findings.append(BrokenEntry(
                        CATEGORY_APP_PATHS, hive_name, key_path, None, f"Program not found: {check.display_path}",
                        detail=f"Registered program: {default.data}", recheck_missing_paths=check.checked_paths))
        return findings

    # ------------------------------------------------------------------ startup (Run / RunOnce)
    def _load_disabled_startup_names(self) -> set[str]:
        """Collect the names of startup items the user (or Windows) switched off in StartupApproved."""
        disabled: set[str] = set()
        for hive_name, path in STARTUP_APPROVED_ROOTS:
            for value in read_registry_values(hive_name, path):
                data = value.data
                if isinstance(data, (bytes, bytearray)) and len(data) >= 1 and data[0] not in STARTUP_APPROVED_ENABLED_BYTES:
                    disabled.add(value.name.lower())     # anything except the known "enabled" markers counts as disabled
        return disabled

    def scan_startup(self) -> list[BrokenEntry]:
        """Find Run/RunOnce entries whose program no longer exists (skipping ones the user switched off)."""
        disabled = self._load_disabled_startup_names()
        findings: list[BrokenEntry] = []
        for hive_name, root in RUN_ROOTS:
            for value in read_registry_values(hive_name, root):
                self._tick()
                if value.value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or not isinstance(value.data, str):
                    continue
                if not value.data.strip() or value.name.lower() in disabled:
                    continue
                check = resolve_command_status(value.data)
                if check.status == PathStatus.MISSING:
                    findings.append(BrokenEntry(
                        CATEGORY_STARTUP, hive_name, root, value.name, f"Program not found: {check.display_path}",
                        detail=f"Startup command: {value.data}", recheck_missing_paths=check.checked_paths))
        return findings

    # ------------------------------------------------------------------ MUI cache
    def scan_mui_cache(self) -> list[BrokenEntry]:
        """Find MUI-cache display names for programs that no longer exist."""
        hive_name, path = MUI_CACHE_ROOT
        findings: list[BrokenEntry] = []
        for value in read_registry_values(hive_name, path):
            self._tick()
            lowered = value.name.lower()
            suffix = next((item for item in (".friendlyappname", ".applicationcompany") if lowered.endswith(item)), None)
            if suffix is None:
                continue                    # e.g. the "LangID" value - not a cache entry
            program_path = value.name[: -len(suffix)]
            if check_path_status(program_path) == PathStatus.MISSING:
                findings.append(BrokenEntry(
                    CATEGORY_MUI_CACHE, hive_name, path, value.name, f"Program not found: {program_path}",
                    detail=f"Cached text: {value.data}", recheck_missing_paths=(program_path,)))
        return findings

    # ------------------------------------------------------------------ fonts
    def scan_fonts(self) -> list[BrokenEntry]:
        """Find font entries pointing at a full path outside the Windows folder where the file is gone."""
        findings: list[BrokenEntry] = []
        for hive_name, root in FONT_ROOTS:
            for value in read_registry_values(hive_name, root):
                self._tick()
                if not isinstance(value.data, str):
                    continue
                font_path = value.data.strip().strip('"')
                # Plain file names are resolved inside %WINDIR%\Fonts (protected), so only full paths are examined.
                if not re.match(r"^(?:[A-Za-z]:|%)", font_path):
                    continue
                if check_path_status(font_path) == PathStatus.MISSING:
                    findings.append(BrokenEntry(
                        CATEGORY_FONTS, hive_name, root, value.name, f"Font file not found: {font_path}",
                        recheck_missing_paths=(font_path,)))
        return findings

    # ------------------------------------------------------------------ file associations
    def _collect_user_choice_progids(self) -> set[str]:
        """Collect ProgIDs that are the user's chosen default app for some extension (never flagged)."""
        chosen: set[str] = set()
        hive_name, root = FILE_EXTS_HKCU
        for extension in list_subkey_names(hive_name, root):
            value = read_registry_value(hive_name, f"{root}\\{extension}\\UserChoice", "ProgId")
            if value is not None and isinstance(value.data, str) and value.data:
                chosen.add(value.data.lower())
        return chosen

    def scan_file_associations(self) -> list[BrokenEntry]:
        """Find dead extension keys and dead program types (ProgIDs / Applications entries)."""
        known: set[str] = set()
        for hive_name, root in (CLASSES_HKLM, CLASSES_HKCU, CLASSES_WOW_HKLM, CLASSES_WOW_HKCU):
            known.update(name.lower() for name in list_subkey_names(hive_name, root))
        user_choices = self._collect_user_choice_progids()

        def progid_is_known(progid: str) -> bool:
            """True if the ProgID exists: plain names are looked up in the collected set, names containing a backslash in the registry."""
            return progid.lower() in known if "\\" not in progid else progid_exists(progid)

        findings: list[BrokenEntry] = []
        for hive_name, root in CLASSES_ROOTS:
            for name in list_subkey_names(hive_name, root):
                self._tick()
                key_path = f"{root}\\{name}"
                if name.startswith("."):
                    finding = self._evaluate_extension_key(hive_name, key_path, name, progid_is_known)
                elif name.lower() == "applications":
                    finding = None
                    for app_name in list_subkey_names(hive_name, key_path):
                        app_finding = self._evaluate_progid_key(hive_name, f"{key_path}\\{app_name}", app_name, user_choices)
                        if app_finding is not None:
                            findings.append(app_finding)
                else:
                    finding = self._evaluate_progid_key(hive_name, key_path, name, user_choices)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _evaluate_extension_key(self, hive_name: str, key_path: str, extension: str,
                                progid_is_known: Callable[[str], bool]) -> BrokenEntry | None:
        """An extension key is dead only if its ProgID does not exist AND it holds nothing else of value."""
        if extension.lower() in PROTECTED_EXTENSIONS:
            return None
        values = read_registry_values(hive_name, key_path)
        default = next((value for value in values if value.name == ""), None)
        progid = default.data.strip() if default is not None and isinstance(default.data, str) else ""
        if not progid or progid_is_known(progid):
            return None
        harmless = {"", "content type", "perceivedtype"}
        if any(value.name.lower() not in harmless for value in values) or list_subkey_names(hive_name, key_path):
            return None                     # it holds other associations (OpenWithProgids, ShellNew, ...) -> leave alone
        return BrokenEntry(
            CATEGORY_FILE_ASSOC, hive_name, key_path, None, f"Points to a program type that no longer exists: {progid}",
            detail=f"Extension {extension} -> {progid}", recheck_missing_progid=progid)

    def _evaluate_progid_key(self, hive_name: str, key_path: str, name: str, user_choices: set[str]) -> BrokenEntry | None:
        """A program type is orphaned only if it has 'open' style commands and ALL of them point to missing programs."""
        lowered = name.lower()
        if lowered in PROTECTED_CLASS_KEYS or lowered in user_choices:
            return None
        children = {child.lower() for child in list_subkey_names(hive_name, key_path)}
        if "shell" not in children or "clsid" in children:
            return None                     # nothing runnable, or a COM class (out of scope)
        shell_path = f"{key_path}\\shell"
        checks: list[CommandCheck] = []
        for verb in list_subkey_names(hive_name, shell_path):
            verb_path = f"{shell_path}\\{verb}"
            verb_values = {value.name.lower() for value in read_registry_values(hive_name, verb_path)}
            if verb_values & {"delegateexecute", "explorercommandhandler", "subcommands"}:
                return None
            command_values = read_registry_values(hive_name, f"{verb_path}\\command")
            if not command_values:
                continue
            if any(value.name.lower() == "delegateexecute" for value in command_values):
                return None
            default = next((value for value in command_values if value.name == ""), None)
            if default is None or not isinstance(default.data, str) or not default.data.strip():
                return None
            checks.append(resolve_command_status(default.data))
        if not checks or any(check.status != PathStatus.MISSING for check in checks):
            return None
        rechecks = tuple(path for check in checks for path in check.checked_paths)
        return BrokenEntry(
            CATEGORY_FILE_ASSOC, hive_name, key_path, None, f"Its program no longer exists: {checks[0].display_path}",
            detail=f"Program type: {name}", recheck_missing_paths=rechecks)

    # ------------------------------------------------------------------ context menus
    def _handler_clsid(self, hive_name: str, handler_path: str, handler_name: str) -> str:
        """Find the CLSID a shell-extension handler key refers to (its default value, or its own name)."""
        default = read_registry_value(hive_name, handler_path, "")
        if default is not None and isinstance(default.data, str) and self._CLSID_PATTERN.match(default.data.strip()):
            return default.data.strip()
        return handler_name if self._CLSID_PATTERN.match(handler_name) else ""

    def _collect_com_server_checks(self, clsid: str) -> list[CommandCheck]:
        """Check every place a COM class can be registered; an unclear registration counts as UNKNOWN (blocks flagging)."""
        checks: list[CommandCheck] = []
        stores = ((HKLM, r"SOFTWARE\Classes"), (HKCU, r"Software\Classes"), CLASSES_WOW_HKLM, CLASSES_WOW_HKCU)
        for hive_name, root in stores:
            class_path = f"{root}\\CLSID\\{clsid}"
            if not registry_key_exists(hive_name, class_path):
                continue
            found_server = False
            for server_key in ("InprocServer32", "LocalServer32"):
                server = read_registry_value(hive_name, f"{class_path}\\{server_key}", "")
                if server is not None and isinstance(server.data, str) and server.data.strip():
                    checks.append(resolve_command_status(server.data))
                    found_server = True
            if not found_server:
                checks.append(CommandCheck(PathStatus.UNKNOWN))
        packaged_hive, packaged_root = PACKAGED_COM_INDEX
        if registry_key_exists(packaged_hive, f"{packaged_root}\\{clsid}"):
            checks.append(CommandCheck(PathStatus.UNKNOWN))   # provided by an app package -> not our business
        return checks

    def scan_context_menus(self) -> list[BrokenEntry]:
        """Find right-click menu handlers and menu commands whose program/DLL is provably gone."""
        findings: list[BrokenEntry] = []
        for hive_name, classes_root in CLASSES_ROOTS:
            for target in CONTEXT_MENU_TARGET_KEYS:
                findings.extend(self._scan_handler_keys(hive_name, f"{classes_root}\\{target}\\shellex\\ContextMenuHandlers"))
                findings.extend(self._scan_verb_keys(hive_name, f"{classes_root}\\{target}\\shell"))
        return findings

    def _scan_handler_keys(self, hive_name: str, handlers_root: str) -> list[BrokenEntry]:
        """Shell-extension handlers: flagged only if the COM server DLL of the referenced CLSID is provably missing."""
        findings: list[BrokenEntry] = []
        for handler_name in list_subkey_names(hive_name, handlers_root):
            self._tick()
            handler_path = f"{handlers_root}\\{handler_name}"
            clsid = self._handler_clsid(hive_name, handler_path, handler_name)
            if not clsid:
                continue
            checks = self._collect_com_server_checks(clsid)
            if not checks or any(check.status != PathStatus.MISSING for check in checks):
                continue                    # not registered anywhere (unclear) or at least one server still exists
            rechecks = tuple(path for check in checks for path in check.checked_paths)
            findings.append(BrokenEntry(
                CATEGORY_CONTEXT_MENU, hive_name, handler_path, None,
                f"Shell extension file not found: {checks[0].display_path}",
                detail=f"Handler {handler_name} -> {clsid}", recheck_missing_paths=rechecks))
        return findings

    def _scan_verb_keys(self, hive_name: str, shell_root: str) -> list[BrokenEntry]:
        """Static menu commands (shell\\<verb>\\command): flagged only if the program is provably missing."""
        findings: list[BrokenEntry] = []
        for verb in list_subkey_names(hive_name, shell_root):
            self._tick()
            if verb.lower() in PROTECTED_VERB_NAMES:
                continue
            verb_path = f"{shell_root}\\{verb}"
            verb_values = {value.name.lower() for value in read_registry_values(hive_name, verb_path)}
            if verb_values & {"delegateexecute", "explorercommandhandler", "subcommands"}:
                continue
            command_values = read_registry_values(hive_name, f"{verb_path}\\command")
            if not command_values or any(value.name.lower() == "delegateexecute" for value in command_values):
                continue
            default = next((value for value in command_values if value.name == ""), None)
            if default is None or not isinstance(default.data, str) or not default.data.strip():
                continue
            check = resolve_command_status(default.data)
            if check.status == PathStatus.MISSING:
                findings.append(BrokenEntry(
                    CATEGORY_CONTEXT_MENU, hive_name, verb_path, None, f"Program not found: {check.display_path}",
                    detail=f"Menu command: {default.data}", recheck_missing_paths=check.checked_paths))
        return findings

    # ------------------------------------------------------------------ stale network history
    def scan_network_history(self) -> list[BrokenEntry]:
        """
        Find remembered network locations in Explorer's history.

        This is a STATIC check: it only reads the registry and never contacts a server. Three places under
        HKEY_CURRENT_USER are examined: the address-bar history (TypedPaths), the "Map network drive" list and the
        network mount-point cache (MountPoints2). If a remembered server is unreachable, Explorer can freeze for many
        seconds while it tries to contact it. Because this is history the user may have created on purpose, every
        finding is marked review_first, so it starts unticked. Mapped drives (HKCU\\Network), saved credentials and
        shortcuts are never looked at, and entries that point at this PC itself are ignored.

        Returns:
            list[BrokenEntry]: One finding per remembered address (TypedPaths), one for the whole "Map network drive"
            list, and one per cached network share (MountPoints2).
        """
        findings: list[BrokenEntry] = []

        typed_hive, typed_path = NET_HISTORY_TYPED_PATHS
        for value in read_registry_values(typed_hive, typed_path):
            self._tick()
            if not re.fullmatch(r"url\d+", value.name, re.IGNORECASE):
                continue                    # only the numbered address-bar entries, nothing else stored in that key
            host = remote_host_of_value(value)
            if host:
                findings.append(BrokenEntry(
                    CATEGORY_NET_HISTORY, typed_hive, typed_path, value.name,
                    f"Remembered network address: {str(value.data).strip()}",
                    detail=f"Explorer address-bar history ({value.name}). Server: {host}",
                    review_first=True, group=host))

        mru_hive, mru_path = NET_HISTORY_MAP_DRIVE_MRU
        locations: list[str] = []
        host_counts: dict[str, int] = {}
        for value in read_registry_values(mru_hive, mru_path):
            host = "" if value.name.lower() == "mrulist" else remote_host_of_value(value)
            if host:
                locations.append(str(value.data).strip())
                host_counts[host] = host_counts.get(host, 0) + 1
        if locations:
            # The whole key is deleted (like Windows itself does when the list is cleared): it holds nothing but this
            # history, and removing it avoids leaving the MRUList index pointing at entries that no longer exist.
            summary = ", ".join("\\\\" + host + f" ({count})" for host, count in sorted(host_counts.items(), key=lambda item: item[0].lower()))
            findings.append(BrokenEntry(
                CATEGORY_NET_HISTORY, mru_hive, mru_path, None,
                f"Remembered 'Map network drive' locations: {summary}",
                detail="Locations in this list:\n" + "\n".join(f"  {location}" for location in locations),
                review_first=True, group=min(host_counts, key=str.lower)))

        mount_hive, mount_path = NET_HISTORY_MOUNT_POINTS
        for name in list_subkey_names(mount_hive, mount_path):
            self._tick()
            location = parse_mount_point_name(name)
            host = extract_unc_host(location)
            if host and not is_local_host(host):
                findings.append(BrokenEntry(
                    CATEGORY_NET_HISTORY, mount_hive, f"{mount_path}\\{name}", None,
                    f"Cached network share information: {location}",
                    detail=f"Explorer's cache for the share {location} (label, icon). Windows rebuilds it the next time you visit the share.",
                    review_first=True, group=host))
        return findings


# =============================================================================
# DELETE GUARD - the last line of defence against a bug in the scanner
# =============================================================================
# Even if the scanner had a bug, nothing outside these exact locations can ever be deleted by the cleaner.

_CLASSES_ROOT_PATTERN = r"(?:LOCAL_MACHINE\\SOFTWARE|CURRENT_USER\\Software)\\Classes"
_EXPLORER_HKCU_PATTERN = r"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
KEY_DELETE_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    CATEGORY_UNINSTALL: (re.compile(
        r"^HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\SOFTWARE\\(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$", re.I),),
    CATEGORY_APP_PATHS: (re.compile(
        r"^HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\SOFTWARE\\(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\App Paths\\[^\\]+$", re.I),),
    CATEGORY_FILE_ASSOC: (re.compile(rf"^HKEY_{_CLASSES_ROOT_PATTERN}\\(?:Applications\\)?[^\\]+$", re.I),),
    CATEGORY_CONTEXT_MENU: (re.compile(
        rf"^HKEY_{_CLASSES_ROOT_PATTERN}\\(?:\*|AllFilesystemObjects|Directory|Directory\\Background|Folder|Drive)"
        r"\\(?:shellex\\ContextMenuHandlers|shell)\\[^\\]+$", re.I),),
    # Exactly two places: the whole "Map Network Drive MRU" key, and "##..." (network) subkeys of MountPoints2 -
    # never MountPoints2 itself and never its drive-letter / volume subkeys.
    CATEGORY_NET_HISTORY: (
        re.compile(rf"^{_EXPLORER_HKCU_PATTERN}\\Map Network Drive MRU$", re.I),
        re.compile(rf"^{_EXPLORER_HKCU_PATTERN}\\MountPoints2\\##[^\\]+$", re.I),
    ),
}
VALUE_DELETE_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    CATEGORY_SHARED_DLLS: (re.compile(
        r"^HKEY_LOCAL_MACHINE\\SOFTWARE\\(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\SharedDLLs$", re.I),),
    CATEGORY_STARTUP: (re.compile(
        r"^HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\SOFTWARE\\(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce)$", re.I),),
    CATEGORY_MUI_CACHE: (re.compile(
        r"^HKEY_CURRENT_USER\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache$", re.I),),
    CATEGORY_FONTS: (re.compile(
        r"^HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts$", re.I),),
    CATEGORY_NET_HISTORY: (re.compile(rf"^{_EXPLORER_HKCU_PATTERN}\\TypedPaths$", re.I),),
}
# Some categories may only remove values with a particular kind of name (TypedPaths holds nothing but "url1".."urlN").
VALUE_NAME_PATTERNS: dict[str, re.Pattern[str]] = {
    CATEGORY_NET_HISTORY: re.compile(r"^url\d+$", re.I),
}


def is_delete_allowed(entry: BrokenEntry) -> tuple[bool, str]:
    """
    Check a finding against the strict allow-list before it may be deleted.

    Args:
        entry (BrokenEntry): The finding to be deleted.

    Returns:
        tuple[bool, str]: (allowed, reason). The reason explains a refusal.
    """
    patterns = (VALUE_DELETE_PATTERNS if entry.value_name is not None else KEY_DELETE_PATTERNS).get(entry.category, ())
    if not any(pattern.match(entry.full_key_path) for pattern in patterns):
        return False, "location is outside the allowed cleaning locations"
    if entry.value_name is not None:
        if not entry.value_name:
            return False, "the (Default) value is never deleted by the cleaner"
        name_pattern = VALUE_NAME_PATTERNS.get(entry.category)
        if name_pattern is not None and not name_pattern.match(entry.value_name):
            return False, "not one of the values this category is allowed to remove"
        return True, ""
    last_part = entry.key_path.rsplit("\\", 1)[-1].lower()
    if entry.category == CATEGORY_FILE_ASSOC:
        if last_part in PROTECTED_CLASS_KEYS or last_part in PROTECTED_EXTENSIONS:
            return False, "protected system file type"
    if entry.category == CATEGORY_CONTEXT_MENU and last_part in PROTECTED_VERB_NAMES:
        return False, "protected menu entry"
    return True, ""


def keep_only_deletable(findings: list[BrokenEntry]) -> list[BrokenEntry]:
    """
    Safety net for the scanner: keep only the findings that the delete allow-list would accept.

    clean_entries() refuses anything outside the allow-list, so listing such a finding would only mislead the user
    (it would show up ticked and then be "skipped"). It also means a scanner and the allow-list disagree, which is a
    bug worth knowing about, so every dropped finding is written to the log.

    Args:
        findings (list[BrokenEntry]): Raw findings of one scan category.

    Returns:
        list[BrokenEntry]: The findings that pass is_delete_allowed().
    """
    kept: list[BrokenEntry] = []
    for entry in findings:
        allowed, why = is_delete_allowed(entry)
        if allowed:
            kept.append(entry)
        else:
            log(f"[ERROR] Scanner/allow-list mismatch, finding dropped: {entry.category} {entry.full_key_path} "
                f"[{entry.value_name}] - {why}")
    return kept


def _still_remembered_network_location(entry: BrokenEntry) -> bool:
    """Check that a network-history finding still holds a remembered REMOTE location (it may have changed since the scan)."""
    if entry.value_name is not None:
        value = read_registry_value(entry.hive_name, entry.key_path, entry.value_name)
        return value is not None and remote_host_of_value(value) != ""
    last_part = entry.key_path.rsplit("\\", 1)[-1]
    if last_part.startswith("##"):
        host = extract_unc_host(parse_mount_point_name(last_part))
        return bool(host) and not is_local_host(host)
    return any(value.name.lower() != "mrulist" and remote_host_of_value(value) != ""
               for value in read_registry_values(entry.hive_name, entry.key_path))


def revalidate_entry(entry: BrokenEntry) -> tuple[bool, str]:
    """
    Re-check a finding right before deleting it (drives can be plugged in, apps installed, between scan and clean).

    Args:
        entry (BrokenEntry): The finding to re-check.

    Returns:
        tuple[bool, str]: (still broken, reason if not).
    """
    if entry.value_name is None:
        if not registry_key_exists(entry.hive_name, entry.key_path):
            return False, "already removed"
    elif read_registry_value(entry.hive_name, entry.key_path, entry.value_name) is None:
        return False, "already removed"
    for path in entry.recheck_missing_paths:
        if check_path_status(path) != PathStatus.MISSING:
            return False, f"'{path}' is no longer confirmed missing"
    if entry.recheck_missing_progid and progid_exists(entry.recheck_missing_progid):
        return False, f"program type '{entry.recheck_missing_progid}' exists now"
    if entry.category == CATEGORY_NET_HISTORY and not _still_remembered_network_location(entry):
        return False, "it no longer holds a remembered network location"
    return True, ""


# =============================================================================
# UNDO PLAN - records what is about to change, writes the undo .reg and PROVES it is readable
# =============================================================================

@dataclass
class UndoExpectations:
    """What a written undo file must contain; used to verify it by reading it back."""

    values: dict[tuple[str, str], RegValue] = field(default_factory=dict)   # (key lower, name lower) -> value
    keys: set[str] = field(default_factory=set)
    value_deletions: set[tuple[str, str]] = field(default_factory=set)
    key_deletions: set[str] = field(default_factory=set)


def find_undo_problems(path: str, expectations: UndoExpectations) -> list[UndoProblem]:
    """
    Read a written .reg file back and list everything that differs from what it was supposed to contain.

    Each problem records the key (and value) it belongs to, not just a sentence: that is how a failed check can be
    traced back to the exact findings that caused it.

    Args:
        path (str): The .reg file to verify.
        expectations (UndoExpectations): What must be present.

    Returns:
        list[UndoProblem]: Problems found (empty list = the file is exactly as intended).
    """
    found_values: dict[tuple[str, str], RegValue] = {}
    found_keys: set[str] = set()
    found_value_deletions: set[tuple[str, str]] = set()
    found_key_deletions: set[str] = set()
    problems: list[UndoProblem] = []
    try:
        for event in iter_reg_file_events(path):
            key_lower = event.key_path.lower()
            if event.kind == "key":
                found_keys.add(key_lower)
            elif event.kind == "value" and event.value is not None:
                found_values[(key_lower, event.value.name.lower())] = event.value
            elif event.kind == "delete_value":
                found_value_deletions.add((key_lower, event.value_name.lower()))
            elif event.kind == "delete_key":
                found_key_deletions.add(key_lower)
            elif event.kind == "warning":
                problems.append(UndoProblem(f"unparsable line: {event.message}", key_lower))
    except (RegParseError, OSError) as error:
        return [UndoProblem(f"the file cannot be read back: {error}")]   # no key: the file as a whole is unusable
    for key, expected in expectations.values.items():
        if found_values.get(key) != expected:
            problems.append(UndoProblem(f"value {key[1] or '(Default)'} of {key[0]} is missing or different", key[0], key[1]))
    # The sets are sorted so that the same failure always produces the same message (sets have no stable order).
    problems.extend(UndoProblem(f"key {key} is missing", key) for key in sorted(expectations.keys - found_keys))
    problems.extend(UndoProblem(f"value deletion {key} is missing", key[0], key[1])
                    for key in sorted(expectations.value_deletions - found_value_deletions))
    problems.extend(UndoProblem(f"key deletion {key} is missing", key)
                    for key in sorted(expectations.key_deletions - found_key_deletions))
    return problems


def verify_reg_file_against(path: str, expectations: UndoExpectations) -> list[str]:
    """
    Text-only version of find_undo_problems(), kept for callers that just need the sentences.

    Args:
        path (str): The .reg file to verify.
        expectations (UndoExpectations): What must be present.

    Returns:
        list[str]: Problems found (empty list = the file is exactly as intended).
    """
    return [problem.message for problem in find_undo_problems(path, expectations)]


class UndoPlan:
    """
    Collects everything an operation is about to change and turns it into a verified undo .reg file.

    Importing that file (Import tab) puts the registry back the way it was.
    """

    def __init__(self) -> None:
        """Start with an empty plan."""
        self._actions: list[Callable[[RegFileWriter], None]] = []
        self.expectations = UndoExpectations()

    @property
    def is_empty(self) -> bool:
        """True if nothing has been recorded yet."""
        return not self._actions

    def add_value_restore(self, hive_name: str, subkey: str, value: RegValue) -> None:
        """Record a value that exists now (undo = put this exact value back)."""
        full_path = f"{hive_name}\\{subkey}"
        self.expectations.keys.add(full_path.lower())
        self.expectations.values[(full_path.lower(), value.name.lower())] = value
        self._actions.append(lambda writer: writer.write_value(full_path, value))

    def add_value_removal(self, hive_name: str, subkey: str, value_name: str) -> None:
        """Record a value that does not exist yet but is about to be created (undo = delete it again)."""
        full_path = f"{hive_name}\\{subkey}"
        self.expectations.value_deletions.add((full_path.lower(), value_name.lower()))
        self._actions.append(lambda writer: writer.write_value_deletion(full_path, value_name))

    def add_key_tree_restore(self, snapshot: RegKeySnapshot) -> None:
        """Record a whole key tree that is about to be deleted (undo = recreate it with all its values)."""
        def register(node: RegKeySnapshot) -> None:
            """Record one key snapshot (and, recursively, its subkeys) as expected content of the undo file."""
            self.expectations.keys.add(node.full_path.lower())
            for value in node.values:
                self.expectations.values[(node.full_path.lower(), value.name.lower())] = value
            for child in node.children:
                register(child)

        register(snapshot)
        self._actions.append(lambda writer: writer.write_snapshot_tree(snapshot))

    def add_key_creation(self, hive_name: str, subkey: str) -> None:
        """
        Record that writing to this key path may create keys (undo = delete the topmost newly created key).

        Does nothing if the whole path exists already.
        """
        topmost = find_topmost_missing_ancestor(hive_name, subkey)
        if topmost is None:
            return
        full_path = f"{hive_name}\\{topmost}"
        if is_critical_key_path(full_path):
            raise RegistryOperationError(f"Refusing to plan the deletion of a critical key: {full_path}")
        self.expectations.key_deletions.add(full_path.lower())
        self._actions.append(lambda writer: writer.write_key_deletion(full_path))

    def write_and_verify(self, destination_path: str,
                         accept_problem: Callable[[UndoProblem], bool] | None = None) -> list[UndoProblem]:
        """
        Write the undo file and verify it by reading it back.

        By default ANY difference aborts the operation. The only way around that is the optional accept_problem
        callback, which the Clean tab uses for "Continue anyway (risky!)": it must say True for EVERY problem, so a
        single problem nobody explicitly accepted still stops everything.

        Args:
            destination_path (str): Where to save the undo .reg file.
            accept_problem (Callable | None): Called with each problem found; True means "the user accepted this one".
                None (the default) accepts nothing.

        Returns:
            list[UndoProblem]: The problems that were accepted (empty if the file verified perfectly). The undo file
                is kept in that case, so a later restore still has everything that could be captured.

        Raises:
            UndoVerificationError: If the file does not verify and not every problem was accepted. The unverified file
                is deleted first, and the caller MUST abort without changing anything.
            RegistryOperationError: If the file cannot be written at all (same rule for the caller).
        """
        try:
            with RegFileWriter(destination_path) as writer:
                for action in self._actions:
                    action(writer)
        except OSError as error:
            raise RegistryOperationError(f"The undo backup could not be written ({error}). Nothing was changed.") from error
        accepted: list[UndoProblem] = []
        rejected: list[UndoProblem] = []
        for problem in find_undo_problems(destination_path, self.expectations):
            is_accepted = accept_problem is not None and accept_problem(problem)
            (accepted if is_accepted else rejected).append(problem)
        if rejected:
            try:
                os.remove(destination_path)
            except OSError:
                pass
            self._log_problems("[WARNING] Undo check problem", rejected)   # the box only quotes the first few; the log has all
            texts = [problem.message for problem in rejected]
            shown = "; ".join(texts[:3]) + (f"; and {len(texts) - 3} more" if len(texts) > 3 else "")
            raise UndoVerificationError(f"The undo backup failed its safety check ({shown}). Nothing was changed.", rejected)
        if accepted:
            log(f"[WARNING] Undo file KEPT although it did not fully verify - {len(accepted)} problem(s) were accepted "
                f"by the user: {destination_path}")
            self._log_problems("[WARNING] Accepted undo problem", accepted)
        else:
            log(f"[UNDO] Verified undo file written: {destination_path}")
        return accepted

    @staticmethod
    def _log_problems(prefix: str, problems: list[UndoProblem]) -> None:
        """
        Write undo-check problems to the log, one line each (capped, so a systematic failure cannot flood the log).

        Args:
            prefix (str): Text that starts every line, e.g. "[WARNING] Undo check problem" (its tag sets the log level).
            problems (list[UndoProblem]): The problems to log.
        """
        for problem in problems[:MAX_LOGGED_UNDO_PROBLEMS]:
            log(f"{prefix}: {problem.message}")
        if len(problems) > MAX_LOGGED_UNDO_PROBLEMS:
            log(f"{prefix}: ... and {len(problems) - MAX_LOGGED_UNDO_PROBLEMS} more (not listed)")


def make_timestamp() -> str:
    """Return a file-name-safe timestamp such as 2026-09-19_14-05-33."""
    return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def get_undo_folder(backup_root: str) -> str:
    """
    Return (and create) the folder where undo files are stored.

    Raises:
        RegistryOperationError: If the folder cannot be created (nothing has been changed at that point).
    """
    folder = os.path.join(backup_root, UNDO_SUBFOLDER_NAME)
    try:
        os.makedirs(folder, exist_ok=True)
    except OSError as error:
        raise RegistryOperationError(
            f"The undo backup folder cannot be used ({error}). Choose another backup folder. Nothing was changed.") from error
    return folder


def build_undo_path(backup_root: str, operation_label: str) -> str:
    """
    Build a unique undo file path such as "<backup>\\Undo\\2026-09-19_14-05-33 Clean.reg".

    Args:
        backup_root (str): The backup folder chosen by the user.
        operation_label (str): Short label for the operation (Clean, Restore, Import ...).

    Returns:
        str: Full path (the file does not exist yet).
    """
    safe_label = re.sub(r"[^A-Za-z0-9._ -]", "_", operation_label)[:60]
    base = os.path.join(get_undo_folder(backup_root), f"{make_timestamp()} {safe_label}")
    candidate, counter = f"{base}.reg", 1
    while os.path.exists(candidate):
        counter += 1
        candidate = f"{base} ({counter}).reg"
    return candidate


# =============================================================================
# CLEAN ENGINE
# =============================================================================

@dataclass
class CleanReport:
    """What a clean run did."""

    deleted: list[BrokenEntry] = field(default_factory=list)
    skipped: list[tuple[BrokenEntry, str]] = field(default_factory=list)   # (entry, why it was left alone)
    failed: list[tuple[BrokenEntry, str]] = field(default_factory=list)    # (entry, error text)
    undo_file: str | None = None
    accepted_undo_problems: list[str] = field(default_factory=list)        # read-back problems the user chose to live with


class EntryProblemIndex:
    """
    Answers "which findings does this undo-file problem belong to?" quickly.

    A Clean run can involve tens of thousands of findings, so the lookup goes through dictionaries (key path -> findings)
    plus a walk up the key's parents - a problem deep inside a deleted key tree belongs to the finding for that tree -
    instead of scanning the whole list once per problem.
    """

    def __init__(self, entries: list[BrokenEntry]) -> None:
        """
        Args:
            entries (list[BrokenEntry]): The findings whose undo data was written (the ones that passed all checks).
        """
        self._entries = entries
        self._whole_keys: dict[str, list[BrokenEntry]] = {}      # lower-case key path -> findings that delete that whole key tree
        self._values_by_key: dict[str, list[BrokenEntry]] = {}   # lower-case key path -> findings that delete single values of it
        for entry in entries:
            target = self._whole_keys if entry.value_name is None else self._values_by_key
            target.setdefault(entry.full_key_path.lower(), []).append(entry)

    def owners_of(self, problem: UndoProblem) -> list[BrokenEntry]:
        """
        Find the findings one undo-file problem belongs to.

        Args:
            problem (UndoProblem): A problem reported by the read-back check.

        Returns:
            list[BrokenEntry]: The responsible findings. Empty if the problem concerns the file as a whole
                               (unreadable, malformed) and therefore cannot be pinned on any finding.
        """
        if not problem.key_path:
            return []
        owners: list[BrokenEntry] = []
        key_path = problem.key_path
        while True:   # the key itself first, then every parent: a finding that deletes a whole tree owns all its subkeys
            owners.extend(self._whole_keys.get(key_path, ()))
            if "\\" not in key_path:
                break
            key_path = key_path.rsplit("\\", 1)[0]
        for entry in self._values_by_key.get(problem.key_path, ()):
            # A problem about the key itself (no value name) concerns every single-value finding inside that key.
            if problem.value_name is None or (entry.value_name is not None and problem.value_name == entry.value_name.lower()):
                owners.append(entry)
        return owners

    def affected_entries(self, problems: list[UndoProblem]) -> list[BrokenEntry]:
        """
        Collect every finding that at least one of the problems belongs to.

        Args:
            problems (list[UndoProblem]): Problems reported by the read-back check.

        Returns:
            list[BrokenEntry]: Each affected finding once, in the order they were given to the constructor.
        """
        affected_ids = {id(owner) for problem in problems for owner in self.owners_of(problem)}
        return [entry for entry in self._entries if id(entry) in affected_ids]


def clean_entries(entries: list[BrokenEntry], backup_root: str, reporter: ProgressReporter,
                  accept_unverified_undo_for: frozenset[EntryIdentity] = frozenset()) -> CleanReport:
    """
    Delete the chosen broken entries - safely.

    Order of events: allow-list check and re-validation of every entry -> snapshot of what will be deleted ->
    undo file written and verified (abort here if that fails) -> deletion.

    Args:
        entries (list[BrokenEntry]): The findings the user confirmed.
        backup_root (str): Folder that holds the "Undo" subfolder.
        reporter (ProgressReporter): Progress/cancel channel.
        accept_unverified_undo_for (frozenset[EntryIdentity]): Findings for which the user chose "Continue anyway (risky!)"
            after repeated failures. If the read-back check finds problems ONLY in those findings, the unverified undo
            file is kept and the deletion goes ahead; a problem in any other finding still aborts everything.
            The default (empty) is the strict behaviour: any problem aborts.

    Returns:
        CleanReport: What was deleted, skipped and what failed.

    Raises:
        UndoVerificationError: If the undo backup does not verify (nothing has been changed then). Its
            failed_entries names the findings responsible, so the window can untick them.
        RegistryOperationError: If the undo backup cannot be written at all (nothing has been changed then).
        OperationCancelled: If the user cancelled before deletion started.
    """
    report = CleanReport()
    plan = UndoPlan()
    approved: list[BrokenEntry] = []
    for position, entry in enumerate(entries):
        reporter.raise_if_cancelled()
        reporter.report(int(position * 30 / max(1, len(entries))), "Re-checking the selected entries...")
        allowed, reason = is_delete_allowed(entry)
        if not allowed:
            log(f"[WARNING] Guard refused {entry.display_location}: {reason}")
            report.skipped.append((entry, reason))
            continue
        still_broken, reason = revalidate_entry(entry)
        if not still_broken:
            report.skipped.append((entry, reason))
            continue
        try:
            if entry.value_name is None:
                plan.add_key_tree_restore(snapshot_key_tree(entry.hive_name, entry.key_path))
            else:
                value = read_registry_value(entry.hive_name, entry.key_path, entry.value_name)
                if value is None:
                    report.skipped.append((entry, "already removed"))
                    continue
                plan.add_value_restore(entry.hive_name, entry.key_path, value)
        except (RegistryOperationError, OSError) as error:
            report.skipped.append((entry, f"could not be backed up ({error})"))
            continue
        approved.append(entry)
    if not approved:
        return report
    reporter.raise_if_cancelled()
    reporter.report(35, "Writing the undo backup...", force=True)
    undo_path = build_undo_path(backup_root, "Clean")
    problem_index = EntryProblemIndex(approved)

    def is_accepted(problem: UndoProblem) -> bool:
        """A read-back problem may be ignored only if EVERY finding it belongs to was explicitly accepted by the user."""
        owners = problem_index.owners_of(problem)
        return bool(owners) and all(owner.identity in accept_unverified_undo_for for owner in owners)

    try:
        accepted_problems = plan.write_and_verify(undo_path, is_accepted)    # raises -> nothing has been deleted yet
    except UndoVerificationError as error:
        # Pin the failure on the findings responsible: the window unticks exactly those and counts the attempt.
        error.failed_entries = problem_index.affected_entries(error.problems)
        raise
    report.undo_file = undo_path
    report.accepted_undo_problems = [problem.message for problem in accepted_problems]
    reporter.set_critical(True)            # from here on the operation must not be interrupted
    try:
        for position, entry in enumerate(approved):
            reporter.report(40 + int(position * 60 / max(1, len(approved))),
                            f"Deleting {position + 1} of {len(approved)}: {entry.display_location}")
            try:
                if entry.value_name is None:
                    delete_registry_tree(entry.hive_name, entry.key_path)
                else:
                    delete_registry_value(entry.hive_name, entry.key_path, entry.value_name)
                report.deleted.append(entry)
            except (OSError, RegistryOperationError) as error:
                log(f"[ERROR] Could not delete {entry.display_location}: {error}")
                report.failed.append((entry, str(error)))
    finally:
        reporter.set_critical(False)
    reporter.report(100, f"Done: {len(report.deleted)} deleted, {len(report.skipped)} skipped, {len(report.failed)} failed.")
    return report


class UndoFailureTracker:
    """
    Remembers how often each finding made the undo backup fail its safety check (this session only).

    Plain bookkeeping with no Qt in it: the window records a failure, asks whether "Continue anyway (risky!)" may be
    offered for a finding, and forgets a finding once it has been deleted. Findings are tracked by their identity
    (hive + key + value, ignoring letter case), so the count survives a re-scan that builds new BrokenEntry objects.
    """

    def __init__(self, threshold: int = UNDO_FAILURES_BEFORE_OVERRIDE) -> None:
        """
        Args:
            threshold (int): Failures of the same finding after which the risky choice may be offered.
        """
        self._threshold = threshold
        self._failures: dict[EntryIdentity, int] = {}

    def record_failure(self, entry: BrokenEntry) -> int:
        """
        Count one more failed undo check for a finding.

        Args:
            entry (BrokenEntry): The finding that made the check fail.

        Returns:
            int: How many times it has failed now (including this one).
        """
        count = self._failures.get(entry.identity, 0) + 1
        self._failures[entry.identity] = count
        return count

    def failure_count(self, entry: BrokenEntry) -> int:
        """Return how often this finding has failed the undo check so far (0 if never)."""
        return self._failures.get(entry.identity, 0)

    def has_failed(self, entry: BrokenEntry) -> bool:
        """Return True if this finding has failed the undo check at least once (it then starts unticked)."""
        return self.failure_count(entry) > 0

    def is_override_eligible(self, entry: BrokenEntry) -> bool:
        """Return True once this finding has failed often enough for "Continue anyway (risky!)" to be offered."""
        return self.failure_count(entry) >= self._threshold

    def forget(self, entry: BrokenEntry) -> None:
        """Drop a finding's history (it was deleted, so its earlier failures no longer matter)."""
        self._failures.pop(entry.identity, None)


# =============================================================================
# VALUE DISPLAY HELPERS (shared by the Restore and Import previews)
# =============================================================================

def short_value_text(value: RegValue | None, limit: int = 70) -> str:
    """
    Describe a registry value in one short line for previews.

    Args:
        value (RegValue | None): The value (None means "not set").
        limit (int): Maximum length of the returned text.

    Returns:
        str: Human-readable text such as 'exefile', '0x00000001 (1)' or '01 02 03 ... (300 bytes)'.
    """
    if value is None:
        return "(not set)"
    data = value.data
    if value.value_type in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) and isinstance(data, str):
        text = data.replace("\r", "\\r").replace("\n", "\\n") or "(empty)"
    elif value.value_type == winreg.REG_MULTI_SZ and isinstance(data, (list, tuple)):
        text = " | ".join(str(item) for item in data) or "(empty list)"
    elif value.value_type == winreg.REG_DWORD and isinstance(data, int):
        text = f"0x{data:08x} ({data})"
    elif value.value_type == winreg.REG_QWORD and isinstance(data, int):
        text = f"0x{data:016x}"
    elif isinstance(data, (bytes, bytearray)):
        preview = " ".join(f"{byte:02x}" for byte in data[:12])
        text = f"{preview}{' ...' if len(data) > 12 else ''} ({len(data)} bytes)" if data else "(empty binary)"
    else:
        text = str(data)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def short_hive_path(full_path: str) -> str:
    """Shorten HKEY_LOCAL_MACHINE / HKEY_CURRENT_USER to HKLM / HKCU for compact display."""
    for long_name, short_name in ((HKLM, "HKLM"), (HKCU, "HKCU"), (HKCR, "HKCR")):
        if full_path.upper().startswith(long_name):
            return short_name + full_path[len(long_name):]
    return full_path


def probe_directory(path: str) -> PathStatus:
    """
    Check that a path is an existing FOLDER. A file at that location counts as MISSING (it is not a usable folder);
    access-denied and other errors are UNKNOWN so that protected locations are never "repaired".
    """
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return PathStatus.MISSING
    except OSError:
        return PathStatus.UNKNOWN
    return PathStatus.EXISTS if stat.S_ISDIR(info.st_mode) else PathStatus.MISSING


# =============================================================================
# RESTORE DEFAULTS - curated repairs only, never a blanket reset
# =============================================================================
# Each repair is shown as "old value -> new value", backed up in an undo file first, and only proposed when the
# registry currently DIFFERS from the known-good default (a healthy PC produces an empty list).

AREA_POLICY_LOCKS = "policy_locks"
AREA_ASSOCIATIONS = "critical_associations"
AREA_SHELL_FOLDERS = "shell_folders"


@dataclass(frozen=True)
class RestoreArea:
    """One checkbox on the Restore tab."""

    key: str
    title: str
    tooltip: str


RESTORE_AREAS: tuple[RestoreArea, ...] = (
    RestoreArea(AREA_POLICY_LOCKS, "Policy locks",
                "Removes policy values that disable Task Manager, Registry Editor, Command Prompt and Control Panel\n"
                "(often left behind by malware or old tweak tools).\n"
                "On work/school PCs Group Policy may switch them back on - a warning is shown there."),
    RestoreArea(AREA_ASSOCIATIONS, "Critical file associations",
                "Only .exe, .lnk, .bat, .cmd, .reg, folders and drives.\n"
                "Your other default apps (.txt, pictures, music, videos ...) are never touched."),
    RestoreArea(AREA_SHELL_FOLDERS, "Shell folder paths",
                "Repairs Desktop / Documents / Downloads / ... locations that are missing or invalid.\n"
                "Folder locations that work (even custom ones) and view settings such as hidden files are never changed."),
)
RESTORE_AREA_TITLES = {area.key: area.title for area in RESTORE_AREAS}

ACTION_SET = "set"
ACTION_DELETE_VALUE = "delete_value"
ACTION_DELETE_KEY = "delete_key"


@dataclass
class RepairItem:
    """One proposed repair, ready to be previewed, backed up and applied."""

    area: str
    title: str
    action: str                  # ACTION_SET, ACTION_DELETE_VALUE or ACTION_DELETE_KEY
    hive_name: str
    key_path: str
    value_name: str              # "" = the (Default) value; unused for ACTION_DELETE_KEY
    old_value: RegValue | None   # what is stored now (None = not set)
    new_value: RegValue | None   # what will be stored (None = the value/key is removed)
    old_text: str
    new_text: str
    note: str = ""
    caution: bool = False        # True -> could be a deliberate personalisation, so it starts unchecked

    @property
    def location(self) -> str:
        """Short readable location for the preview list."""
        value_label = self.value_name or "(Default)"
        suffix = "" if self.action == ACTION_DELETE_KEY else f"  [{value_label}]"
        full_path = self.hive_name + "\\" + self.key_path     # built outside the f-string: Python 3.11 forbids backslashes there
        return f"{short_hive_path(full_path)}{suffix}"


# ---------------------------------------------------------------- policy locks
@dataclass(frozen=True)
class PolicyLockSpec:
    """A policy value that locks a Windows tool, and where it can live."""

    title: str
    value_name: str
    locations: tuple[RegLocation, ...]


_POLICIES_SYSTEM = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
_POLICIES_EXPLORER = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
_POLICIES_WINDOWS_SYSTEM = r"Software\Policies\Microsoft\Windows\System"
POLICY_LOCKS: tuple[PolicyLockSpec, ...] = (
    PolicyLockSpec("Task Manager lock", "DisableTaskMgr", ((HKCU, _POLICIES_SYSTEM), (HKLM, _POLICIES_SYSTEM))),
    PolicyLockSpec("Registry Editor lock", "DisableRegistryTools", ((HKCU, _POLICIES_SYSTEM), (HKLM, _POLICIES_SYSTEM))),
    PolicyLockSpec("Command Prompt lock", "DisableCMD", ((HKCU, _POLICIES_WINDOWS_SYSTEM), (HKLM, _POLICIES_WINDOWS_SYSTEM))),
    PolicyLockSpec("Control Panel lock", "NoControlPanel", ((HKCU, _POLICIES_EXPLORER), (HKLM, _POLICIES_EXPLORER))),
)


def analyze_policy_locks() -> list[RepairItem]:
    """
    Find active policy locks (a non-zero DWORD). Their default state is "value not present", so the repair deletes the value.

    Returns:
        list[RepairItem]: One item per active lock and location.
    """
    items: list[RepairItem] = []
    for spec in POLICY_LOCKS:
        for hive_name, key_path in spec.locations:
            key_path = key_path if hive_name == HKCU else key_path.replace("Software\\", "SOFTWARE\\", 1)
            current = read_registry_value(hive_name, key_path, spec.value_name)
            if current is None or not isinstance(current.data, int) or current.data == 0:
                continue                    # not set, or explicitly "0" (= not locked): nothing to repair
            scope = "this user" if hive_name == HKCU else "all users"
            items.append(RepairItem(
                AREA_POLICY_LOCKS, f"{spec.title} ({scope})", ACTION_DELETE_VALUE, hive_name, key_path, spec.value_name,
                current, None, short_value_text(current), "(not set)",
                note="Removing the value is the same as setting the policy to 'Not configured': the tool works normally again."))
    return items


# ---------------------------------------------------------------- critical file associations
def _exact_matcher(expected: str) -> Callable[[str], bool]:
    """Build a matcher that compares a stored string with the expected one (ignoring case and repeated spaces)."""
    normalized_expected = " ".join(expected.split()).lower()
    return lambda stored: " ".join(stored.split()).lower() == normalized_expected


_REGEDIT_OPEN_COMMAND = re.compile(
    r'^"?(?:[a-z]:\\windows\\|%systemroot%\\|%windir%\\)?regedit(?:\.exe)?"?\s+"%1"$', re.IGNORECASE)


def _matches_regedit_open_command(stored: str) -> bool:
    """Accept any spelling of 'start Windows regedit with the file' (with or without path/.exe/quotes)."""
    return bool(_REGEDIT_OPEN_COMMAND.match(" ".join(stored.split())))


@dataclass(frozen=True)
class AssociationSpec:
    """One critical value under HKEY_CLASSES_ROOT that must hold a known default."""

    title: str
    class_key: str                          # relative to the Classes key, e.g. ".exe" or "exefile\\shell\\open\\command"
    value_name: str                         # "" = (Default)
    canonical: str                          # what gets written when repairing
    matcher: Callable[[str], bool]          # True if a stored value is acceptable
    caution: bool = False                   # could be a deliberate customisation (e.g. a file-manager replacement)
    absent_is_default: bool = False         # True if the correct state is "value not present"


ASSOCIATION_SPECS: tuple[AssociationSpec, ...] = (
    AssociationSpec(".exe files use the 'exefile' type", ".exe", "", "exefile", _exact_matcher("exefile")),
    AssociationSpec("Programs (.exe): open command", r"exefile\shell\open\command", "", '"%1" %*', _exact_matcher('"%1" %*')),
    AssociationSpec(".bat files use the 'batfile' type", ".bat", "", "batfile", _exact_matcher("batfile")),
    AssociationSpec("Batch files (.bat): open command", r"batfile\shell\open\command", "", '"%1" %*', _exact_matcher('"%1" %*')),
    AssociationSpec(".cmd files use the 'cmdfile' type", ".cmd", "", "cmdfile", _exact_matcher("cmdfile")),
    AssociationSpec("Command scripts (.cmd): open command", r"cmdfile\shell\open\command", "", '"%1" %*', _exact_matcher('"%1" %*')),
    AssociationSpec(".reg files use the 'regfile' type", ".reg", "", "regfile", _exact_matcher("regfile")),
    AssociationSpec("Registry files (.reg): open command", r"regfile\shell\open\command", "", 'regedit.exe "%1"',
                    _matches_regedit_open_command),
    AssociationSpec(".lnk files use the 'lnkfile' type", ".lnk", "", "lnkfile", _exact_matcher("lnkfile")),
    AssociationSpec("Folders: double-click action", r"Directory\shell", "", "none", _exact_matcher("none"), caution=True),
    AssociationSpec("Drives: double-click action", r"Drive\shell", "", "none", _exact_matcher("none"), caution=True),
    AssociationSpec("Folders: no default action override", r"Folder\shell", "", "", lambda stored: not stored.strip(),
                    caution=True, absent_is_default=True),
)
# Windows never creates this key for .exe; when it exists, an app was force-associated with all programs.
USER_CHOICE_REMOVALS: tuple[tuple[str, str], ...] = (
    (".exe", r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.exe\UserChoice"),
)
_CLASSES_PATH = {HKCU: r"Software\Classes", HKLM: r"SOFTWARE\Classes"}


def _string_data(value: RegValue | None) -> str | None:
    """Return a value's text if it is a string value, otherwise None."""
    return value.data if value is not None and isinstance(value.data, str) else None


def analyze_critical_associations() -> list[RepairItem]:
    """
    Compare the critical associations (.exe .lnk .bat .cmd .reg, folders, drives) with their known defaults.

    A wrong per-user override (HKCU) is removed, a wrong or missing machine-wide value (HKLM) is set back.

    Returns:
        list[RepairItem]: The proposed repairs (empty if everything is already correct).
    """
    items: list[RepairItem] = []
    for spec in ASSOCIATION_SPECS:
        # 1) A per-user override wins over the machine value, so a wrong one is the classic hijack.
        user_path = f"{_CLASSES_PATH[HKCU]}\\{spec.class_key}"
        user_value = read_registry_value(HKCU, user_path, spec.value_name)
        user_text = _string_data(user_value)
        if user_value is not None and (user_text is None or not spec.matcher(user_text)):
            items.append(RepairItem(
                AREA_ASSOCIATIONS, spec.title, ACTION_DELETE_VALUE, HKCU, user_path, spec.value_name, user_value, None,
                short_value_text(user_value), "(override removed)",
                note="A per-user override replaces the Windows default for this account. Removing it lets the Windows default apply.", caution=spec.caution))
        # 2) The machine-wide value.
        machine_path = f"{_CLASSES_PATH[HKLM]}\\{spec.class_key}"
        machine_value = read_registry_value(HKLM, machine_path, spec.value_name)
        machine_text = _string_data(machine_value)
        machine_ok = machine_text is not None and spec.matcher(machine_text)
        if spec.absent_is_default:
            if machine_value is not None and not machine_ok:
                items.append(RepairItem(
                    AREA_ASSOCIATIONS, spec.title, ACTION_DELETE_VALUE, HKLM, machine_path, spec.value_name, machine_value,
                    None, short_value_text(machine_value), "(not set)", caution=spec.caution,
                    note="The Windows default is that this value is not set."))
        elif not machine_ok:
            new_value = RegValue(spec.value_name, winreg.REG_SZ, spec.canonical)
            items.append(RepairItem(
                AREA_ASSOCIATIONS, spec.title, ACTION_SET, HKLM, machine_path, spec.value_name, machine_value, new_value,
                short_value_text(machine_value), short_value_text(new_value), caution=spec.caution))
    for extension, user_choice_path in USER_CHOICE_REMOVALS:
        if registry_key_exists(HKCU, user_choice_path):
            progid = _string_data(read_registry_value(HKCU, user_choice_path, "ProgId"))
            items.append(RepairItem(
                AREA_ASSOCIATIONS, f"{extension}: remove the forced 'Open with' choice", ACTION_DELETE_KEY, HKCU,
                user_choice_path, "", None, None, f"UserChoice: {progid or 'unknown'}",
                "(key removed)",
                note="Windows never creates this key for .exe; it is the usual cause of 'every program opens in Notepad'."))
    return items


# ---------------------------------------------------------------- shell folder paths
USER_SHELL_FOLDERS_KEY: RegLocation = (HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
# (registry value name, friendly name, default path) - the Windows 10/11 defaults, see the source list at the top.
SHELL_FOLDER_DEFAULTS: tuple[tuple[str, str, str], ...] = (
    ("Desktop", "Desktop", r"%USERPROFILE%\Desktop"),
    ("Personal", "Documents", r"%USERPROFILE%\Documents"),
    ("{374DE290-123F-4565-9164-39C4925E467B}", "Downloads", r"%USERPROFILE%\Downloads"),
    ("My Pictures", "Pictures", r"%USERPROFILE%\Pictures"),
    ("My Music", "Music", r"%USERPROFILE%\Music"),
    ("My Video", "Videos", r"%USERPROFILE%\Videos"),
    ("Favorites", "Favorites", r"%USERPROFILE%\Favorites"),
    ("AppData", "AppData (Roaming)", r"%USERPROFILE%\AppData\Roaming"),
    ("Local AppData", "AppData (Local)", r"%USERPROFILE%\AppData\Local"),
    ("Cache", "Internet cache", r"%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache"),
    ("Cookies", "Cookies", r"%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCookies"),
    ("History", "History", r"%USERPROFILE%\AppData\Local\Microsoft\Windows\History"),
    ("NetHood", "Network Shortcuts", r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Network Shortcuts"),
    ("PrintHood", "Printer Shortcuts", r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Printer Shortcuts"),
    ("Recent", "Recent items", r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent"),
    ("SendTo", "Send To", r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\SendTo"),
    ("Start Menu", "Start Menu", r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu"),
    ("Programs", "Start Menu Programs", r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"),
    ("Startup", "Startup", r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
    ("Templates", "Templates", r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Templates"),
)


def evaluate_shell_folder_value(value: RegValue | None) -> tuple[str, bool] | None:
    """
    Decide whether a shell-folder entry is missing or invalid.

    Only clear-cut problems are reported. Anything that cannot be verified (unresolved variables, network
    locations, unreadable folders) is left alone.

    Args:
        value (RegValue | None): The stored entry (None = missing).

    Returns:
        tuple[str, bool] | None: (reason, caution) if it needs repair - caution=True when the folder is only
        "missing" because its drive is not connected right now - or None if it is fine or cannot be judged.
    """
    if value is None:
        return "the entry is missing", False
    if value.value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or not isinstance(value.data, str):
        return "the entry has an invalid type", False
    text = value.data.strip()
    if not text:
        return "the path is empty", False
    expanded = expand_env_vars(text)
    if "%" in expanded or expanded.startswith("\\\\"):
        return None                         # unresolved variable or network share: cannot be verified safely
    drive, remainder = ntpath.splitdrive(expanded)
    if not re.fullmatch(r"[A-Za-z]:", drive) or not remainder.startswith(("\\", "/")):
        return "the path is not a full local path", False
    if any(character in remainder for character in '<>|*?":'):
        return "the path contains illegal characters", False
    drive_type = get_drive_type(drive.upper() + "\\")
    if drive_type == 1:
        return "its drive is not available right now", True
    if drive_type in (0, 4, 5):
        return None                         # unknown / mapped network / optical drive: never probed (could freeze on a dead share)
    return ("the folder does not exist", False) if probe_directory(ntpath.normpath(expanded)) == PathStatus.MISSING else None


def analyze_shell_folders() -> list[RepairItem]:
    """
    Find per-user shell folder entries (Desktop, Documents, Downloads ...) that are missing or point nowhere.

    Returns:
        list[RepairItem]: Proposed repairs that reset just those entries to the Windows default.
    """
    hive_name, key_path = USER_SHELL_FOLDERS_KEY
    stored = {value.name.lower(): value for value in read_registry_values(hive_name, key_path)}
    items: list[RepairItem] = []
    for value_name, friendly_name, default_path in SHELL_FOLDER_DEFAULTS:
        current = stored.get(value_name.lower())
        verdict = evaluate_shell_folder_value(current)
        if verdict is None:
            continue
        reason, caution = verdict
        new_value = RegValue(value_name, winreg.REG_EXPAND_SZ, default_path)
        items.append(RepairItem(
            AREA_SHELL_FOLDERS, f"{friendly_name} folder location", ACTION_SET, hive_name, key_path, value_name, current,
            new_value, short_value_text(current), default_path, note=f"Reason: {reason}.", caution=caution))
    return items


def analyze_restore_areas(area_keys: list[str], reporter: ProgressReporter) -> list[RepairItem]:
    """
    Run the analysis for the chosen restore areas.

    Args:
        area_keys (list[str]): Area keys (see RESTORE_AREAS).
        reporter (ProgressReporter): Progress/cancel channel.

    Returns:
        list[RepairItem]: All proposed repairs.
    """
    analyzers: dict[str, Callable[[], list[RepairItem]]] = {
        AREA_POLICY_LOCKS: analyze_policy_locks,
        AREA_ASSOCIATIONS: analyze_critical_associations,
        AREA_SHELL_FOLDERS: analyze_shell_folders,
    }
    selected = [key for key in analyzers if key in area_keys]
    items: list[RepairItem] = []
    for position, key in enumerate(selected):
        reporter.raise_if_cancelled()
        reporter.report(int(position * 100 / max(1, len(selected))), f"Checking: {RESTORE_AREA_TITLES[key]}...", force=True)
        items.extend(analyzers[key]())
    reporter.report(100, f"Check finished: {len(items)} repair(s) proposed.")
    return items


def _build_allowed_repair_targets() -> frozenset[tuple[str, str, str, str]]:
    """Compute every (action, hive, key path, value name) the restore feature may ever touch, from the tables above."""
    targets: set[tuple[str, str, str, str]] = set()
    for lock_spec in POLICY_LOCKS:
        for hive_name, key_path in lock_spec.locations:
            key_path = key_path if hive_name == HKCU else key_path.replace("Software\\", "SOFTWARE\\", 1)
            targets.add((ACTION_DELETE_VALUE, hive_name, key_path.lower(), lock_spec.value_name.lower()))
    for association_spec in ASSOCIATION_SPECS:
        for hive_name in (HKCU, HKLM):
            class_path = _CLASSES_PATH[hive_name] + "\\" + association_spec.class_key   # no backslash inside an f-string (Python 3.11)
            targets.add((ACTION_DELETE_VALUE, hive_name, class_path.lower(), association_spec.value_name.lower()))
            targets.add((ACTION_SET, hive_name, class_path.lower(), association_spec.value_name.lower()))
    for _, key_path in USER_CHOICE_REMOVALS:
        targets.add((ACTION_DELETE_KEY, HKCU, key_path.lower(), ""))
    hive_name, key_path = USER_SHELL_FOLDERS_KEY
    for value_name, _, _ in SHELL_FOLDER_DEFAULTS:
        targets.add((ACTION_SET, hive_name, key_path.lower(), value_name.lower()))
    return frozenset(targets)


ALLOWED_REPAIR_TARGETS = _build_allowed_repair_targets()


def is_repair_allowed(item: RepairItem) -> bool:
    """Return True only if the repair touches one of the exact registry targets this feature is designed to repair."""
    return (item.action, item.hive_name, item.key_path.lower(), item.value_name.lower()) in ALLOWED_REPAIR_TARGETS


@dataclass
class RestoreReport:
    """What a restore run did."""

    applied: list[RepairItem] = field(default_factory=list)
    skipped: list[tuple[RepairItem, str]] = field(default_factory=list)
    failed: list[tuple[RepairItem, str]] = field(default_factory=list)
    undo_file: str | None = None


def _current_state_matches(item: RepairItem) -> bool:
    """Check that the registry still looks exactly like it did when the repair was previewed."""
    if item.action == ACTION_DELETE_KEY:
        return registry_key_exists(item.hive_name, item.key_path)
    return read_registry_value(item.hive_name, item.key_path, item.value_name) == item.old_value


def apply_repairs(items: list[RepairItem], backup_root: str, reporter: ProgressReporter) -> RestoreReport:
    """
    Apply the confirmed repairs - safely.

    Order of events: allow-list check + "unchanged since the preview" check -> undo file with exactly what will
    change (written and verified; abort here if that fails) -> apply.

    Args:
        items (list[RepairItem]): The repairs the user confirmed.
        backup_root (str): Folder that holds the "Undo" subfolder.
        reporter (ProgressReporter): Progress/cancel channel.

    Returns:
        RestoreReport: What was applied, skipped and what failed.

    Raises:
        RegistryOperationError: If the undo backup cannot be written/verified (nothing has been changed then).
    """
    report = RestoreReport()
    plan = UndoPlan()
    approved: list[RepairItem] = []
    for position, item in enumerate(items):
        reporter.raise_if_cancelled()
        reporter.report(int(position * 30 / max(1, len(items))), "Preparing the undo backup...")
        if not is_repair_allowed(item):
            log(f"[WARNING] Guard refused repair: {item.title} @ {item.location}")
            report.skipped.append((item, "not one of the repairs this tool is designed to make"))
            continue
        if not _current_state_matches(item):
            report.skipped.append((item, "changed since the preview - analyze again"))
            continue
        try:
            if item.action == ACTION_DELETE_KEY:
                plan.add_key_tree_restore(snapshot_key_tree(item.hive_name, item.key_path))
            elif item.action == ACTION_DELETE_VALUE and item.old_value is not None:
                plan.add_value_restore(item.hive_name, item.key_path, item.old_value)
            elif item.action == ACTION_SET:
                if find_topmost_missing_ancestor(item.hive_name, item.key_path) is not None:
                    plan.add_key_creation(item.hive_name, item.key_path)   # undoing = deleting the new key path
                elif item.old_value is not None:
                    plan.add_value_restore(item.hive_name, item.key_path, item.old_value)
                else:
                    plan.add_value_removal(item.hive_name, item.key_path, item.value_name)
            else:
                report.skipped.append((item, "nothing to change"))
                continue
        except (RegistryOperationError, OSError) as error:
            report.skipped.append((item, f"could not be backed up ({error})"))
            continue
        approved.append(item)
    if not approved:
        return report
    reporter.raise_if_cancelled()
    reporter.report(35, "Writing the undo backup...", force=True)
    undo_path = build_undo_path(backup_root, "Restore defaults")
    plan.write_and_verify(undo_path)         # raises -> nothing has been changed yet
    report.undo_file = undo_path
    reporter.set_critical(True)
    try:
        for position, item in enumerate(approved):
            reporter.report(40 + int(position * 60 / max(1, len(approved))),
                            f"Repairing {position + 1} of {len(approved)}: {item.title}")
            try:
                if item.action == ACTION_DELETE_KEY:
                    delete_registry_tree(item.hive_name, item.key_path)
                elif item.action == ACTION_DELETE_VALUE:
                    delete_registry_value(item.hive_name, item.key_path, item.value_name)
                elif item.new_value is not None:
                    set_registry_value(item.hive_name, item.key_path, item.new_value)
                report.applied.append(item)
            except (OSError, RegistryOperationError) as error:
                log(f"[ERROR] Repair failed ({item.title}): {error}")
                report.failed.append((item, str(error)))
    finally:
        reporter.set_critical(False)
    reporter.report(100, f"Done: {len(report.applied)} repaired, {len(report.skipped)} skipped, {len(report.failed)} failed.")
    return report


# =============================================================================
# FULL REGISTRY BACKUP (.reg files)
# =============================================================================
# The "whole registry" is HKEY_LOCAL_MACHINE plus HKEY_USERS. HKCU, HKCR and HKCC are views of parts of those two,
# so exporting them again would only duplicate data. Volatile or security-sensitive hives are skipped on purpose.

BACKUP_SKIPPED_HKLM_KEYS = {
    "HARDWARE": "volatile - rebuilt by Windows at every start",
    "SAM": "protected account database - not readable/importable as a .reg file",
    "SECURITY": "protected security data - not readable/importable as a .reg file",
}
LINK_KEY_PATHS_LOWER = frozenset({r"system\currentcontrolset"})   # symbolic links; exporting them would duplicate a whole tree


@dataclass
class BackupTarget:
    """One .reg file of the full backup."""

    hive_name: str
    subkey: str
    file_name: str

    @property
    def key_name(self) -> str:
        """Key name in the form reg.exe expects."""
        return f"{self.hive_name}\\{self.subkey}"


@dataclass
class BackupFileResult:
    """How one target of the full backup went."""

    target: BackupTarget
    status: str          # "ok", "ok_fallback", "failed"
    size_bytes: int = 0
    note: str = ""


@dataclass
class BackupReport:
    """Summary of a finished full backup."""

    folder: str
    results: list[BackupFileResult] = field(default_factory=list)
    skipped_notes: list[str] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        """Total size of all written files."""
        return sum(result.size_bytes for result in self.results)

    @property
    def failed_count(self) -> int:
        """Number of targets that could not be exported at all."""
        return sum(1 for result in self.results if result.status == "failed")


def sanitize_file_component(text: str) -> str:
    """Make text safe to use inside a file name."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", text)


def build_backup_targets() -> tuple[list[BackupTarget], list[str]]:
    """
    Work out which registry areas the full backup covers.

    Returns:
        tuple[list[BackupTarget], list[str]]: (targets, notes about deliberately skipped areas).
    """
    targets: list[BackupTarget] = []
    notes: list[str] = []
    for name in list_subkey_names(HKLM, ""):
        if name.upper() in BACKUP_SKIPPED_HKLM_KEYS:
            notes.append(f"HKEY_LOCAL_MACHINE\\{name} skipped: {BACKUP_SKIPPED_HKLM_KEYS[name.upper()]}.")
            continue
        targets.append(BackupTarget(HKLM, name, f"HKLM_{sanitize_file_component(name)}.reg"))
    for name in list_subkey_names(HKU, ""):
        targets.append(BackupTarget(HKU, name, f"HKU_{sanitize_file_component(name)}.reg"))
    return targets, notes


def get_reg_exe_path() -> str:
    """Absolute path of Windows' own reg.exe (an absolute path avoids picking up a look-alike from PATH)."""
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "reg.exe")


def run_reg_export(key_name: str, output_path: str, reporter: ProgressReporter) -> tuple[int, str]:
    """
    Run "reg export <key> <file> /y" and wait for it, staying responsive to Cancel.

    Args:
        key_name (str): Full key name, e.g. HKEY_LOCAL_MACHINE\\SOFTWARE.
        output_path (str): Destination .reg file.
        reporter (ProgressReporter): Used to notice a Cancel request.

    Returns:
        tuple[int, str]: (exit code, message text). Exit code 0 means success.

    Raises:
        OperationCancelled: If the user cancelled (the process is terminated).
    """
    command = [get_reg_exe_path(), "export", key_name, output_path, "/y"]   # syntax: Microsoft Learn "reg export"
    log(f"[BACKUP] Running: {' '.join(command)}")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace",
                               creationflags=CREATE_NO_WINDOW_FLAG)
    while True:
        try:
            stdout_text, stderr_text = process.communicate(timeout=SUBPROCESS_POLL_SECONDS)
            break
        except subprocess.TimeoutExpired:
            if reporter.is_cancelled():
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                raise OperationCancelled() from None
    return process.returncode, (stderr_text or stdout_text or "").strip()


def export_key_tree_streaming(writer: RegFileWriter, hive_name: str, subkey: str, reporter: ProgressReporter,
                              skipped_keys: list[str]) -> None:
    """
    Export a key tree into an open RegFileWriter, one key at a time (constant memory, tolerant of protected keys).

    This is the fallback when reg.exe cannot export something, and also how undo data for imported "[-KEY]"
    deletions is captured. Keys that cannot be read are skipped and listed in skipped_keys.

    Args:
        writer (RegFileWriter): Open writer receiving the data.
        hive_name (str): Long hive name.
        subkey (str): Path below the hive ("" = the whole hive).
        reporter (ProgressReporter): Used to notice a Cancel request.
        skipped_keys (list[str]): Receives the full paths of keys that could not be read.
    """
    pending = [subkey]
    counter = 0
    while pending:
        current = pending.pop()
        counter += 1
        if counter % 200 == 0:
            reporter.raise_if_cancelled()
        if current.lower() in LINK_KEY_PATHS_LOWER:
            continue                                   # symbolic link: its target is exported under its real name
        full_path = f"{hive_name}\\{current}" if current else hive_name
        try:
            with open_registry_key(hive_name, current):
                pass
        except FileNotFoundError:
            continue
        except OSError:
            skipped_keys.append(full_path)
            continue
        writer.write_key_header(full_path)
        for value in read_registry_values(hive_name, current):
            writer.write_value(full_path, value)
        children = list_subkey_names(hive_name, current)
        pending.extend((f"{current}\\{child}" if current else child) for child in reversed(children))


def _looks_like_reg_file(path: str) -> bool:
    """Cheap sanity check of a finished export: it exists, is not empty and starts with a .reg header."""
    try:
        if os.path.getsize(path) < 40:
            return False
        with open(path, "rb") as file:
            head = file.read(120)
    except OSError:
        return False
    return head.startswith(b"\xff\xfe") and "Windows Registry Editor".encode("utf-16-le") in head


def ensure_free_space(folder: str) -> None:
    """
    Make sure there is enough free disk space for a full backup.

    Raises:
        RegistryOperationError: If less than MIN_FREE_SPACE_BYTES is free.
    """
    free_bytes = shutil.disk_usage(folder).free
    if free_bytes < MIN_FREE_SPACE_BYTES:
        raise RegistryOperationError(
            f"Not enough free space for a full registry backup: {free_bytes / 1024 ** 3:.1f} GB free, "
            f"at least {MIN_FREE_SPACE_BYTES / 1024 ** 3:.0f} GB needed. Choose another backup folder.")


def write_backup_info(report: BackupReport) -> None:
    """Write backup-info.txt next to the .reg files so it is clear later what the backup contains."""
    lines = [
        f"{APP_NAME} {APP_VERSION} - full registry backup",
        f"Created: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Windows: {platform.platform()}",
        f"Windows architecture: {os.environ.get('PROCESSOR_ARCHITEW6432') or os.environ.get('PROCESSOR_ARCHITECTURE') or platform.machine()}",
        f"Python: {platform.python_version()} ({'64' if sys.maxsize > 2 ** 32 else '32'}-bit)",
        "Registry view: 64-bit (every key is read through KEY_WOW64_64KEY; 32-bit programs' data is under WOW6432Node)",
        f"Account: {describe_current_user()}",
        "",
        "Files (plain-text .reg files; restore with the Import tab or by double-clicking a file):",
    ]
    for result in report.results:
        size_mb = result.size_bytes / 1024 ** 2
        lines.append(f"  {result.target.file_name:<48} {result.status:<12} {size_mb:9.1f} MB  {result.note}".rstrip())
    lines.append("")
    lines.append("Not included (on purpose):")
    lines.extend(f"  {note}" for note in report.skipped_notes)
    lines.append("  HKEY_CURRENT_USER, HKEY_CLASSES_ROOT and HKEY_CURRENT_CONFIG are views of the data above.")
    lines.append("")
    lines.append("Note: .reg files do not store key permissions, and importing never removes keys that were added later.")
    with open(os.path.join(report.folder, BACKUP_INFO_FILE_NAME), "w", encoding="utf-8") as info_file:
        info_file.write("\n".join(lines) + "\n")


def run_full_backup(backup_root: str, reporter: ProgressReporter) -> BackupReport:
    """
    Back up the whole registry (HKLM + HKU) as .reg files into a new time-stamped folder.

    reg.exe does the export; if it fails for an area, a built-in exporter that skips unreadable keys is used instead.
    If the user cancels, everything written so far is removed so no half-finished backup is left behind.

    Args:
        backup_root (str): The folder chosen by the user.
        reporter (ProgressReporter): Progress/cancel channel.

    Returns:
        BackupReport: What was written.

    Raises:
        RegistryOperationError: If there is not enough space or nothing could be exported.
        OperationCancelled: If the user cancelled.
    """
    folder = os.path.join(backup_root, f"{FULL_BACKUP_FOLDER_PREFIX} {make_timestamp()}")
    try:
        os.makedirs(backup_root, exist_ok=True)
        ensure_free_space(backup_root)
        os.makedirs(folder)
    except OSError as error:
        raise RegistryOperationError(f"The backup folder cannot be used ({error}). Choose another backup folder.") from error
    report = BackupReport(folder=folder)
    try:
        targets, report.skipped_notes = build_backup_targets()
        for position, target in enumerate(targets):
            reporter.raise_if_cancelled()
            reporter.report(int(position * 100 / max(1, len(targets))), f"Exporting {target.key_name} ...", force=True)
            output_path = os.path.join(folder, target.file_name)
            exit_code, message = run_reg_export(target.key_name, output_path, reporter)
            if exit_code == 0 and _looks_like_reg_file(output_path):
                report.results.append(BackupFileResult(target, "ok", os.path.getsize(output_path)))
                continue
            log(f"[WARNING] reg.exe could not export {target.key_name} (code {exit_code}): {message}")
            reporter.status(f"reg.exe could not export {target.key_name}; using the built-in exporter...")
            report.results.append(_export_with_fallback(target, output_path, reporter, message))
        if not any(result.status != "failed" for result in report.results):
            raise RegistryOperationError("No registry data could be exported. Run the program as administrator and try again.")
        write_backup_info(report)
    except (OperationCancelled, RegistryOperationError):
        shutil.rmtree(folder, ignore_errors=True)   # never leave a half-finished backup that could be mistaken for a good one
        raise
    reporter.report(100, f"Backup finished: {report.total_bytes / 1024 ** 2:.0f} MB in {folder}")
    return report


def _export_with_fallback(target: BackupTarget, output_path: str, reporter: ProgressReporter, reg_message: str) -> BackupFileResult:
    """Export one target with the built-in exporter after reg.exe failed; returns how that went."""
    skipped_keys: list[str] = []
    try:
        with RegFileWriter(output_path) as writer:
            export_key_tree_streaming(writer, target.hive_name, target.subkey, reporter, skipped_keys)
    except OperationCancelled:
        raise
    except (OSError, RegistryOperationError) as error:
        log(f"[ERROR] Fallback export of {target.key_name} failed: {error}")
        return BackupFileResult(target, "failed", 0, f"export failed: {error}")
    note = f"built-in exporter used ({reg_message[:60]})"
    if skipped_keys:
        note += f"; {len(skipped_keys)} protected key(s) skipped"
        log(f"[WARNING] Protected keys skipped in {target.key_name}: {skipped_keys[:5]}")
    return BackupFileResult(target, "ok_fallback", os.path.getsize(output_path), note)


# =============================================================================
# .REG IMPORT - preview, undo backup, merge
# =============================================================================

@dataclass
class ImportAnalysis:
    """What a .reg file would do if it were imported."""

    file_path: str
    file_size: int = 0
    format_name: str = ""
    keys_in_file: int = 0
    values_in_file: int = 0
    value_deletions: int = 0
    key_deletions: int = 0
    new_keys: int = 0
    new_values: int = 0
    changed_values: int = 0
    unchanged_values: int = 0
    detailed: bool = True                         # False for huge files where only totals are counted
    hives: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)
    blocked_reasons: list[str] = field(default_factory=list)
    preview_lines: list[str] = field(default_factory=list)
    preview_truncated: bool = False
    restart_impacts: dict[str, RestartImpact] = field(default_factory=dict)   # kinds of change that may need a restart
    error: str = ""

    @property
    def is_blocked(self) -> bool:
        """True if this file must not be imported (unreadable, invalid, or it deletes critical keys)."""
        return bool(self.error or self.blocked_reasons)

    @property
    def has_delete_lines(self) -> bool:
        """True if the file contains explicit delete instructions."""
        return self.value_deletions > 0 or self.key_deletions > 0


class ImportProcessor:
    """
    Walks the events of one .reg file, comparing them with the live registry to fill an ImportAnalysis and - when an
    undo writer is given - recording exactly what the import would overwrite, create or delete.
    """

    def __init__(self, analysis: ImportAnalysis, reporter: ProgressReporter, undo_writer: RegFileWriter | None) -> None:
        """
        Args:
            analysis (ImportAnalysis): Receives the counters and preview lines.
            reporter (ProgressReporter): Progress/cancel channel.
            undo_writer (RegFileWriter | None): If given, undo data is written to it while processing.
        """
        self.analysis = analysis
        self.reporter = reporter
        self.undo_writer = undo_writer
        self.compare = undo_writer is not None or analysis.detailed
        self._current_exists = False
        self._current_values: dict[str, RegValue] = {}
        self._created_roots: set[str] = set()
        self.skipped_keys: list[str] = []

    def _add_preview(self, line: str) -> None:
        """Append a preview line unless the cap has been reached."""
        if len(self.analysis.preview_lines) < MAX_PREVIEW_ROWS:
            self.analysis.preview_lines.append(line)
        else:
            self.analysis.preview_truncated = True

    def _note_restart_impact(self, key_path: str) -> None:
        """Remember (once per kind) that this key belongs to an area that may need a restart to take full effect."""
        match = _IMPORT_RESTART_REGEX.match(key_path)
        if match is None or match.lastgroup is None:
            return
        label, score, reason, _ = IMPORT_RESTART_RULES[int(match.lastgroup[4:])]
        if score > 0:
            self.analysis.restart_impacts.setdefault(label, RestartImpact(label, score, reason))

    def handle(self, event: RegFileEvent) -> None:
        """Process one event of the file."""
        if event.kind == "warning":
            if len(self.analysis.warnings) < 10:
                self.analysis.warnings.append(f"line {event.line_number}: {event.message}")
        elif event.kind == "key":
            self._handle_key(event)
        elif event.kind == "delete_key":
            self._handle_delete_key(event)
        elif event.kind == "value" and event.value is not None:
            self._handle_value(event, event.value)
        elif event.kind == "delete_value":
            self._handle_delete_value(event)

    def _handle_key(self, event: RegFileEvent) -> None:
        """A "[KEY]" line: remember whether the key exists and what it holds."""
        analysis = self.analysis
        analysis.keys_in_file += 1
        hive_name, subkey = split_full_key_path(event.key_path)
        analysis.hives.add(hive_name)
        self._note_restart_impact(event.key_path)
        if not self.compare:
            return
        self._current_exists = registry_key_exists(hive_name, subkey) if subkey else True
        self._current_values = ({value.name.lower(): value for value in read_registry_values(hive_name, subkey)}
                                if self._current_exists and subkey else {})
        if not self._current_exists:
            analysis.new_keys += 1
            self._add_preview(f"+ NEW KEY      {short_hive_path(event.key_path)}")
            if self.undo_writer is not None:
                topmost = find_topmost_missing_ancestor(hive_name, subkey)
                if topmost is not None:
                    root_path = f"{hive_name}\\{topmost}"
                    if root_path.lower() not in self._created_roots:
                        self._created_roots.add(root_path.lower())
                        self.undo_writer.write_key_deletion(root_path)   # undo = delete the topmost key this import creates

    def _handle_value(self, event: RegFileEvent, value: RegValue) -> None:
        """A value assignment: classify it (new / changed / unchanged) and record the old data for the undo file."""
        analysis = self.analysis
        analysis.values_in_file += 1
        if not self.compare:
            return
        old = self._current_values.get(value.name.lower()) if self._current_exists else None
        label = value.name or "(Default)"
        if not self._current_exists:
            analysis.new_values += 1                     # covered by the "[-created key]" undo line
            return
        if old is None:
            analysis.new_values += 1
            self._add_preview(f"+ NEW VALUE    {short_hive_path(event.key_path)} [{label}] = {short_value_text(value, 50)}")
            if self.undo_writer is not None:
                self.undo_writer.write_value_deletion(event.key_path, value.name)
        elif old == value:
            analysis.unchanged_values += 1
            if self.undo_writer is not None:
                self.undo_writer.write_value(event.key_path, old)
        else:
            analysis.changed_values += 1
            self._add_preview(f"~ CHANGE       {short_hive_path(event.key_path)} [{label}]: "
                              f"{short_value_text(old, 40)}  ->  {short_value_text(value, 40)}")
            if self.undo_writer is not None:
                self.undo_writer.write_value(event.key_path, old)

    def _handle_delete_value(self, event: RegFileEvent) -> None:
        """A '"name"=-' line: the value will be deleted; keep its old data for the undo file."""
        analysis = self.analysis
        analysis.value_deletions += 1
        if not self.compare or not self._current_exists:
            return
        old = self._current_values.get(event.value_name.lower())
        if old is not None:
            self._add_preview(f"- DELETE VALUE {short_hive_path(event.key_path)} [{event.value_name or '(Default)'}]")
            if self.undo_writer is not None:
                self.undo_writer.write_value(event.key_path, old)

    def _handle_delete_key(self, event: RegFileEvent) -> None:
        """A '[-KEY]' line: block critical keys, otherwise keep a full copy of the key for the undo file."""
        analysis = self.analysis
        analysis.key_deletions += 1
        hive_name, subkey = split_full_key_path(event.key_path)
        analysis.hives.add(hive_name)
        self._note_restart_impact(event.key_path)
        self._current_exists = False
        self._current_values = {}
        if is_critical_key_path(event.key_path):
            analysis.blocked_reasons.append(f"Deletes a protected system key: {event.key_path}")
            return
        if not self.compare or not registry_key_exists(hive_name, subkey):
            return
        self._add_preview(f"- DELETE KEY   {short_hive_path(event.key_path)}   (with everything below it)")
        if self.undo_writer is not None:
            export_key_tree_streaming(self.undo_writer, hive_name, subkey, self.reporter, self.skipped_keys)


def process_reg_file(path: str, reporter: ProgressReporter, undo_writer: RegFileWriter | None = None) -> ImportAnalysis:
    """
    Analyze a .reg file (and optionally record undo data while doing so). Works for files of any size.

    Args:
        path (str): The .reg file.
        reporter (ProgressReporter): Progress/cancel channel.
        undo_writer (RegFileWriter | None): If given, the undo data is written to it.

    Returns:
        ImportAnalysis: Counters, warnings, blocked reasons and preview lines. Problems with the file itself are
        reported in .error instead of being raised.

    Raises:
        OperationCancelled: If the user cancelled.
    """
    analysis = ImportAnalysis(file_path=path)
    try:
        analysis.file_size = os.path.getsize(path)
        encoding = detect_reg_encoding(path)
    except OSError as error:
        analysis.error = f"The file cannot be read: {error}"
        return analysis
    analysis.format_name = {"utf-16": "Unicode (UTF-16)", "utf-16-le": "Unicode (UTF-16)"}.get(encoding, "Text")
    if encoding == "utf-8-sig":
        analysis.warnings.append("The file is UTF-8 encoded; Windows expects UTF-16, so special characters may import incorrectly.")
    analysis.detailed = analysis.file_size <= LARGE_REG_FILE_BYTES
    if not analysis.detailed and undo_writer is None:
        analysis.warnings.append("Large file: only totals are shown; a full comparison is made when you merge (an undo backup is written first).")
    processor = ImportProcessor(analysis, reporter, undo_writer)
    byte_counter = [0]
    try:
        for index, event in enumerate(iter_reg_file_events(path, byte_counter)):
            if index % 500 == 0:
                reporter.raise_if_cancelled()
                reporter.report(int(byte_counter[0] * 100 / max(1, analysis.file_size)))
            processor.handle(event)
    except RegParseError as error:
        analysis.error = str(error)
    except OSError as error:
        analysis.error = f"The file cannot be read: {error}"
    if processor.skipped_keys:
        analysis.warnings.append(f"{len(processor.skipped_keys)} unreadable key(s) could not be included in the undo backup.")
    return analysis


def run_reg_import(path: str) -> tuple[int, str]:
    """
    Merge a .reg file with Windows' own "reg import" (syntax: Microsoft Learn "reg import").

    Args:
        path (str): The .reg file.

    Returns:
        tuple[int, str]: (exit code, message text). Exit code 0 means success.
    """
    command = [get_reg_exe_path(), "import", path]
    log(f"[IMPORT] Running: {' '.join(command)}")
    completed = subprocess.run(command, capture_output=True, text=True, errors="replace", creationflags=CREATE_NO_WINDOW_FLAG)
    return completed.returncode, (completed.stderr or completed.stdout or "").strip()


@dataclass
class ImportResult:
    """Outcome of merging one .reg file."""

    path: str
    succeeded: bool
    message: str
    undo_file: str | None = None
    restart_impacts: list[RestartImpact] = field(default_factory=list)   # what the merge touched that may need a restart


def apply_reg_import(path: str, backup_root: str, reporter: ProgressReporter) -> ImportResult:
    """
    Merge one .reg file - safely: analysis (blocking critical deletes) -> undo file of exactly what will change
    (checked by reading it back; abort here if it fails) -> "reg import".

    Args:
        path (str): The .reg file.
        backup_root (str): Folder that holds the "Undo" subfolder.
        reporter (ProgressReporter): Progress/cancel channel.

    Returns:
        ImportResult: Whether Windows accepted the import, plus where the undo file is.

    Raises:
        RegistryOperationError: If the file is blocked or the undo backup cannot be written (nothing was changed).
        OperationCancelled: If the user cancelled before the import started.
    """
    undo_path = build_undo_path(backup_root, f"Import {sanitize_file_component(os.path.splitext(os.path.basename(path))[0])}")
    try:
        with RegFileWriter(undo_path, track_content=True) as writer:
            analysis = process_reg_file(path, reporter, writer)
            if analysis.is_blocked:
                raise RegistryOperationError("; ".join(analysis.blocked_reasons) or analysis.error)
    except OSError as error:
        raise RegistryOperationError(f"The undo backup could not be written ({error}). Nothing was changed.") from error
    except (RegistryOperationError, OperationCancelled):
        if os.path.exists(undo_path):
            os.remove(undo_path)                 # a blocked/cancelled import leaves no undo file behind
        raise
    problems = _verify_streamed_undo_file(undo_path, writer)
    if problems:
        for problem in problems:
            log(f"[WARNING] Import undo check problem: {problem}")
        os.remove(undo_path)
        raise RegistryOperationError("The undo backup failed its safety check (" + "; ".join(problems) + "). Nothing was changed.")
    reporter.raise_if_cancelled()
    reporter.set_critical(True)
    try:
        reporter.report(90, f"Importing {os.path.basename(path)} ...", force=True)
        try:
            exit_code, message = run_reg_import(path)
        except OSError as error:
            raise RegistryOperationError(f"reg.exe could not be started ({error}). Nothing was changed.") from error
    finally:
        reporter.set_critical(False)
    if exit_code == 0:
        return ImportResult(path, True, "Merged successfully.", undo_path, list(analysis.restart_impacts.values()))
    return ImportResult(path, False, message or f"reg.exe reported an error (code {exit_code}); some entries may have been applied.", undo_path)


def _verify_streamed_undo_file(undo_path: str, writer: RegFileWriter) -> list[str]:
    """
    Read a streamed undo file back and check that it holds exactly what the writer meant to write - entry by entry.

    Import writes its undo data as a stream because a .reg file can be huge, so (unlike the Clean and Restore checks)
    it cannot keep every expected value in memory. Instead the writer remembered a 64-bit fingerprint of each entry it
    wrote, and this function fingerprints what it reads back and compares the two sequences. A wrong value, a missing
    or extra entry, or a changed order all show up: the same "content, not just counts" standard as Clean and Restore.
    (Comparing only the number of keys/values/deletions, as this check used to, would pass a file with the right
    number of entries and the wrong data in one of them.)

    Args:
        undo_path (str): The undo file that was just written.
        writer (RegFileWriter): The writer that wrote it (must have been created with track_content=True).

    Returns:
        list[str]: Problems found (empty list = the file is exactly what was written).
    """
    expected = writer.event_fingerprints
    if expected is None:
        return ["internal error: the undo writer did not record what it wrote"]   # fail closed: never accept what cannot be checked
    problems: list[str] = []
    mismatches = 0
    position = 0                                       # entries read back so far
    try:
        for event in iter_reg_file_events(undo_path):
            if event.kind == "warning":
                return [f"unparsable line: {event.message}"]
            if position < len(expected) and expected[position] != fingerprint_of_event(event):
                mismatches += 1
                if mismatches <= 3:
                    problems.append(f"entry {position + 1} ({describe_reg_event(event)}) reads back differently from what was written")
            position += 1
    except (RegParseError, OSError) as error:
        return [f"the file cannot be read back: {error}"]
    if position != len(expected):
        problems.insert(0, f"expected {len(expected)} entries (keys, values and deletions) but found {position}")
    elif mismatches > 3:
        problems.append(f"and {mismatches - 3} more entries differ")
    return problems


# =============================================================================
# RESTART ADVICE - does a change need a restart?  (heuristic scores: see the RESTART_* constants)
# =============================================================================
# After a change the tool says whether a restart is advised instead of always (or never) asking for one:
#   * every kind of change has a score (0 = nothing to restart ... 7 = only read while Windows starts),
#   * the scores of the DISTINCT kinds that were changed are added up,
#   * below RESTART_RECOMMENDED_AT -> "No restart is needed", from there "recommended", from RESTART_STRONG_AT "strongly",
#   * if Windows already has a restart pending (from other software), a restart is at least "recommended".
# Routine cleaning of broken entries scores 0-1 per kind, so it stays below the threshold and never nags.

class RestartLevel(Enum):
    """How strongly a restart of Windows is advised."""

    NONE = "none"
    RECOMMENDED = "recommended"
    STRONG = "strong"


@dataclass(frozen=True)
class RestartImpact:
    """One kind of change that was made and how much it needs a restart."""

    label: str      # what changed; the same label is only counted once, however many entries of that kind were touched
    score: int      # one of the RESTART_SCORE_* values
    reason: str     # shown to the user when this contributes to a restart advice


@dataclass(frozen=True)
class RestartAdvice:
    """The result of assessing a finished operation."""

    level: RestartLevel
    score: int                      # total impact score (0 if only a pending restart made it "recommended")
    reasons: tuple[str, ...]        # why, most important first

    @property
    def needs_restart(self) -> bool:
        """True if the user should be offered "Restart Now / Restart Later"."""
        return self.level is not RestartLevel.NONE


# Clean categories -> (score, reason). Almost everything here is only bookkeeping that no running program reads.
CLEAN_RESTART_IMPACT: dict[str, tuple[int, str]] = {
    CATEGORY_UNINSTALL: (RESTART_SCORE_NONE, ""),
    CATEGORY_SHARED_DLLS: (RESTART_SCORE_NONE, ""),
    CATEGORY_APP_PATHS: (RESTART_SCORE_NONE, ""),
    CATEGORY_STARTUP: (RESTART_SCORE_NONE, ""),      # only decides what starts at the NEXT sign-in
    CATEGORY_MUI_CACHE: (RESTART_SCORE_NONE, ""),
    CATEGORY_FONTS: (RESTART_SCORE_NONE, ""),
    CATEGORY_NET_HISTORY: (RESTART_SCORE_NONE, ""),
    CATEGORY_FILE_ASSOC: (RESTART_SCORE_PROGRAMS, "Explorer may keep showing old file-type icons and menus until it is restarted."),
    CATEGORY_CONTEXT_MENU: (RESTART_SCORE_PROGRAMS, "Explorer may keep showing old right-click items until it is restarted."),
}

# Restore areas -> (score, reason).
RESTORE_RESTART_IMPACT: dict[str, tuple[int, str]] = {
    AREA_POLICY_LOCKS: (RESTART_SCORE_PROGRAMS, "Restored tools work the next time they are opened."),
    AREA_ASSOCIATIONS: (RESTART_SCORE_SHELL, "Explorer caches file associations: restart (or sign out and back in) so every program sees the repaired ones."),
    AREA_SHELL_FOLDERS: (RESTART_SCORE_SHELL, "Folder locations (Desktop, Documents, ...) are read when you sign in: restart, or sign out and back in."),
}
SHELL_READ_POLICY_VALUES = frozenset({"nocontrolpanel"})     # policy values Explorer reads at sign-in (lower-case)
CONTROL_PANEL_POLICY_IMPACT = RestartImpact("Control Panel lock", RESTART_SCORE_SHELL,
                                            "Explorer reads the Control Panel lock at sign-in: restart, or sign out and back in.")

# Import: (label, score, reason, regex on the full key path). The FIRST rule that matches a key wins, so the specific
# rules come before the broad ones. Keys that match no rule (for example HKEY_CURRENT_USER\SOFTWARE\SomeApp) score 0.
_SOFTWARE_HIVES = r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\SOFTWARE"
IMPORT_RESTART_RULES: tuple[tuple[str, int, str, str], ...] = (
    ("System settings", RESTART_SCORE_BOOT,
     "System settings (HKEY_LOCAL_MACHINE\\SYSTEM: services, drivers, start-up) are only read while Windows starts.",
     r"HKEY_LOCAL_MACHINE\\SYSTEM(?:\\|$)"),
    ("Shell folder locations", RESTART_SCORE_SHELL,
     "Folder locations (Desktop, Documents, ...) are read when you sign in.",
     _SOFTWARE_HIVES + r"\\Microsoft\\Windows\\CurrentVersion\\Explorer\\(?:User )?Shell Folders(?:\\|$)"),
    ("Sign-in settings", RESTART_SCORE_SHELL,
     "Sign-in (Winlogon) settings are read when you sign in.",
     _SOFTWARE_HIVES + r"\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon(?:\\|$)"),
    ("Policies", RESTART_SCORE_SHELL,
     "Policies are applied by Windows and Explorer when you sign in.",
     _SOFTWARE_HIVES + r"\\(?:Policies|Microsoft\\Windows\\CurrentVersion\\Policies)(?:\\|$)"),
    ("File types and shell classes", RESTART_SCORE_PROGRAMS,
     "Explorer may keep showing old file-type icons and menus until it is restarted.",
     r"HKEY_CLASSES_ROOT(?:\\|$)|" + _SOFTWARE_HIVES + r"\\Classes(?:\\|$)"),
    ("Machine-wide program settings", RESTART_SCORE_PROGRAMS,
     "Programs that are already running keep their old settings until they are restarted.",
     r"HKEY_LOCAL_MACHINE\\SOFTWARE(?:\\|$)"),
)
# One combined pattern (one match per key instead of one per rule): the name of the group that matched is "rule<index>".
_IMPORT_RESTART_REGEX = re.compile("|".join(f"(?P<rule{index}>{rule[3]})" for index, rule in enumerate(IMPORT_RESTART_RULES)),
                                   re.IGNORECASE)

# Standard "a restart is already pending" indicators: (hive, key path, value name or "" if the KEY existing is the signal, message)
PENDING_RESTART_CHECKS: tuple[tuple[str, str, str, str], ...] = (
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending", "",
     "Windows has updates or features waiting for a restart."),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired", "",
     "Windows Update is waiting for a restart."),
    (HKLM, r"SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations",
     "Some software has files waiting to be replaced at the next restart."),
)
RESTART_HEADLINES: dict[RestartLevel, str] = {
    RestartLevel.NONE: "✅ No restart is needed.",
    RestartLevel.RECOMMENDED: "⚠ A restart is recommended so Windows fully applies these changes.",
    RestartLevel.STRONG: "🔴 A restart is strongly recommended: some changes are not fully applied until Windows restarts.",
}


def detect_pending_restart_reasons() -> list[str]:
    """
    Check the standard registry indicators that Windows is already waiting for a restart (read-only).

    An unreadable indicator is simply ignored: the advice must never fail because of a missing key.

    Returns:
        list[str]: One sentence per indicator that is set (empty = no restart is pending).
    """
    reasons: list[str] = []
    for hive_name, key_path, value_name, message in PENDING_RESTART_CHECKS:
        try:
            if value_name:
                value = read_registry_value(hive_name, key_path, value_name)
                items = [] if value is None else (value.data if isinstance(value.data, list) else [value.data])
                pending = any(bool(item) for item in items)          # an empty list means nothing is waiting
            else:
                pending = registry_key_exists(hive_name, key_path)
        except OSError as error:
            log(f"[WARNING] Could not check the pending-restart indicator {key_path}: {error}")
            continue
        if pending:
            reasons.append(message)
    return reasons


def assess_restart_need(impacts: list[RestartImpact], pending_reasons: list[str]) -> RestartAdvice:
    """
    Turn the kinds of change that were made into a restart advice.

    Args:
        impacts (list[RestartImpact]): Everything that was changed (the same label counts once, with its highest score).
        pending_reasons (list[str]): Reasons Windows ALREADY has a restart pending (from detect_pending_restart_reasons).

    Returns:
        RestartAdvice: The level, the total score and the reasons worth telling the user.
    """
    distinct: dict[str, RestartImpact] = {}
    for impact in impacts:
        known = distinct.get(impact.label)
        if known is None or impact.score > known.score:
            distinct[impact.label] = impact
    total = sum(impact.score for impact in distinct.values())
    if total >= RESTART_STRONG_AT:
        level = RestartLevel.STRONG
    elif total >= RESTART_RECOMMENDED_AT or pending_reasons:
        level = RestartLevel.RECOMMENDED     # a restart that was already pending is enough for "recommended", never more
    else:
        level = RestartLevel.NONE
    ordered = sorted((impact for impact in distinct.values() if impact.score > 0), key=lambda impact: -impact.score)
    reasons = [impact.reason for impact in ordered] + pending_reasons
    return RestartAdvice(level, total, tuple(reasons) if level is not RestartLevel.NONE else ())


def assess_clean_restart(report: CleanReport) -> RestartAdvice | None:
    """Restart advice for a finished Clean run; None if nothing was deleted (nothing changed, so nothing to say)."""
    if not report.deleted:
        return None
    impacts: list[RestartImpact] = []
    for category in {entry.category for entry in report.deleted}:
        score, reason = CLEAN_RESTART_IMPACT.get(category, (RESTART_SCORE_NONE, ""))
        impacts.append(RestartImpact(SCAN_CATEGORY_TITLES.get(category, category), score, reason))
    return assess_restart_need(impacts, detect_pending_restart_reasons())


def assess_restore_restart(report: RestoreReport) -> RestartAdvice | None:
    """Restart advice for a finished Restore run; None if nothing was applied."""
    if not report.applied:
        return None
    impacts: list[RestartImpact] = []
    for item in report.applied:
        if item.area == AREA_POLICY_LOCKS and item.value_name.lower() in SHELL_READ_POLICY_VALUES:
            impacts.append(CONTROL_PANEL_POLICY_IMPACT)
            continue
        score, reason = RESTORE_RESTART_IMPACT.get(item.area, (RESTART_SCORE_NONE, ""))
        impacts.append(RestartImpact(RESTORE_AREA_TITLES.get(item.area, item.area), score, reason))
    return assess_restart_need(impacts, detect_pending_restart_reasons())


def assess_import_restart(results: list[ImportResult]) -> RestartAdvice | None:
    """Restart advice for finished merges; None if no file was merged."""
    merged = [result for result in results if result.succeeded]
    if not merged:
        return None
    impacts = [impact for result in merged for impact in result.restart_impacts]
    return assess_restart_need(impacts, detect_pending_restart_reasons())


def format_restart_advice(advice: RestartAdvice) -> str:
    """Build the restart paragraph of a completion box: the headline, then why (only when a restart is advised)."""
    lines = [RESTART_HEADLINES[advice.level]]
    lines.extend(f"  - {reason}" for reason in advice.reasons)
    return "\n".join(lines)


def get_shutdown_exe_path() -> str:
    """Absolute path of Windows' own shutdown.exe (an absolute path avoids picking up a look-alike from PATH)."""
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "shutdown.exe")


def schedule_windows_restart(delay_seconds: int = RESTART_DELAY_SECONDS) -> tuple[bool, str]:
    """
    Ask Windows to restart after a short countdown.

    The countdown (instead of restarting at once) gives the user time to change their mind: "shutdown /a" cancels it.
    /f is NOT used, so a program with unsaved work can still stop the restart instead of being killed.

    Args:
        delay_seconds (int): Countdown before the restart.

    Returns:
        tuple[bool, str]: (success, message for the user).
    """
    command = [get_shutdown_exe_path(), "/r", "/t", str(delay_seconds), "/c", RESTART_COMMENT]
    log(f"[RESTART] Running: {' '.join(command)}")
    try:
        completed = subprocess.run(command, capture_output=True, text=True, errors="replace", creationflags=CREATE_NO_WINDOW_FLAG)
    except OSError as error:
        return False, f"shutdown.exe could not be started ({error})."
    if completed.returncode == 0:
        return True, f"Windows will restart in {delay_seconds} seconds. To cancel, run 'shutdown /a' in a Command Prompt."
    return False, (completed.stderr or completed.stdout or f"shutdown.exe reported error code {completed.returncode}.").strip()


# =============================================================================
# SETTINGS (only the backup folder is remembered)
# =============================================================================

def get_settings_path() -> str:
    """Path of the small JSON settings file (next to the program)."""
    return os.path.join(get_app_dir(), SETTINGS_FILE_NAME)


def load_settings() -> dict[str, Any]:
    """
    Load saved settings.

    Returns:
        dict[str, Any]: The settings, or an empty dict if there are none or the file is unreadable.
    """
    try:
        with open(get_settings_path(), "r", encoding="utf-8") as settings_file:
            data = json.load(settings_file)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as error:
        log(f"[WARNING] Could not read the settings file, using defaults: {error}")
        return {}


def save_settings(settings: dict[str, Any]) -> None:
    """Save settings; a failure is logged but never interrupts the app."""
    try:
        with open(get_settings_path(), "w", encoding="utf-8") as settings_file:
            json.dump(settings, settings_file, indent=2)
    except OSError as error:
        log(f"[WARNING] Could not save settings: {error}")


def get_default_backup_root() -> str:
    """Default backup folder: 'Registry Backups' next to the program."""
    return os.path.join(get_app_dir(), DEFAULT_BACKUP_FOLDER_NAME)


def is_on_local_fixed_drive(path: str) -> bool:
    """Return True if the path is on a currently mounted FIXED drive (safe to touch without risking a network freeze)."""
    drive, _ = ntpath.splitdrive(path)
    return bool(re.fullmatch(r"[A-Za-z]:", drive)) and get_drive_type(drive.upper() + "\\") == DRIVE_FIXED


def resolve_backup_root(settings: dict[str, Any]) -> str:
    """
    Return the saved backup folder, or the default one if nothing usable was saved.

    Saved folders on network/removable/offline drives are returned WITHOUT being probed: probing a dead network
    share here would freeze the window at start-up. Problems with such a folder are reported when a backup runs.
    """
    saved = settings.get("backup_dir")
    if isinstance(saved, str) and saved.strip():
        if not is_on_local_fixed_drive(saved):
            return saved
        if os.path.isdir(saved) or os.path.isdir(os.path.dirname(saved) or "."):
            return saved
    return get_default_backup_root()


def export_error_log(errors: list[str]) -> str | None:
    """
    Append errors to "error-log 📃.txt" next to the program (same format as the other Rane tools).

    Returns:
        str | None: The log file path, or None if it could not be written.
    """
    log_path = os.path.join(get_app_dir(), ERROR_LOG_FILE_NAME)
    try:
        with open(log_path, "a", encoding="utf-8") as log_file:
            log_file.write("\n" + "=" * 50 + "\n")
            log_file.write(f"📅 Date & Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            log_file.write("⚠️ Errors encountered:\n")
            for error in errors:
                log_file.write(f"- {error}\n")
            log_file.write("=" * 50 + "\n")
        return log_path
    except OSError as error:
        log(f"[ERROR] Could not write the error log: {error}")
        return None


# =============================================================================
# BACKGROUND WORKER (keeps the window responsive during long operations)
# =============================================================================

class TaskWorker(QThread):
    """Runs one engine task in a background thread and reports back to the window through signals."""

    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    critical_changed = pyqtSignal(bool)     # True while a stage runs that must not be interrupted
    task_succeeded = pyqtSignal(object)
    task_failed = pyqtSignal(str)
    undo_check_failed = pyqtSignal(object)  # an UndoVerificationError: the undo file did not verify (nothing was changed)
    task_cancelled = pyqtSignal()

    def __init__(self, task: Callable[[ProgressReporter], Any], description: str) -> None:
        """
        Args:
            task (Callable): Function that receives a ProgressReporter and returns the result object.
            description (str): Short text for the log ("Scan", "Full backup", ...).
        """
        super().__init__()
        self._task = task
        self.description = description
        self._cancel_event = threading.Event()

    def cancel(self) -> None:
        """Ask the running task to stop at its next safe point."""
        self._cancel_event.set()

    def run(self) -> None:
        """Thread body: run the task and translate its outcome into exactly one signal."""
        log(f"[WORKER] Starting: {self.description}")
        reporter = ProgressReporter(self.progress_updated.emit, self.status_updated.emit,
                                    self._cancel_event.is_set, self.critical_changed.emit)
        try:
            result = self._task(reporter)
        except OperationCancelled:
            log(f"[WORKER] Cancelled: {self.description}")
            self.task_cancelled.emit()
        except UndoVerificationError as error:   # must come BEFORE its parent class below, or it would never be seen
            log(f"[ERROR] {self.description} stopped safely: {error}")
            self.undo_check_failed.emit(error)
        except RegistryOperationError as error:
            log(f"[ERROR] {self.description} stopped safely: {error}")
            self.task_failed.emit(str(error))
        except Exception as error:   # last-resort net: the UI must always get an answer
            log_exception(f"{self.description} failed unexpectedly")
            self.task_failed.emit(f"Unexpected error: {error}")
        else:
            log(f"[WORKER] Finished: {self.description}")
            self.task_succeeded.emit(result)


# =============================================================================
# USER INTERFACE HELPERS
# =============================================================================

def make_button(text: str, object_name: str = "", tooltip: str = "") -> QPushButton:
    """
    Create a push button with an optional style name and tooltip.

    Args:
        text (str): Button caption.
        object_name (str): Name used by the stylesheet ("primaryButton", "dangerButton"); empty = normal button.
        tooltip (str): Hover text.

    Returns:
        QPushButton: The new button.
    """
    button = QPushButton(text)
    if object_name:
        button.setObjectName(object_name)
    if tooltip:
        button.setToolTip(tooltip)
    return button


def format_size(byte_count: int) -> str:
    """Format a byte count for humans (e.g. 1.5 MB)."""
    size = float(byte_count)
    for unit in ("bytes", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} bytes" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{byte_count} bytes"


def plural(count: int, singular: str, plural_form: str) -> str:
    """Return '1 entry' / '3 entries' style text."""
    return f"{count} {singular if count == 1 else plural_form}"


def summarize_reasons(pairs: list[tuple[str, str]], limit: int = 5) -> str:
    """
    Turn (item, reason) pairs into a short bullet text for a message box.

    Args:
        pairs (list[tuple[str, str]]): Item description and why it was skipped/failed.
        limit (int): Maximum number of lines to show.

    Returns:
        str: Multi-line text (empty if there are no pairs).
    """
    lines = [f"  - {item}: {reason}" for item, reason in pairs[:limit]]
    if len(pairs) > limit:
        lines.append(f"  ... and {len(pairs) - limit} more (see the log)")
    return "\n".join(lines)


def format_import_analysis(analysis: ImportAnalysis) -> str:
    """
    Build the readable preview text for one analyzed .reg file.

    Args:
        analysis (ImportAnalysis): The analysis result.

    Returns:
        str: Multi-line text for the preview box.
    """
    lines = [f"File:     {os.path.basename(analysis.file_path)}  ({format_size(analysis.file_size)})"]
    if analysis.error:
        lines.append(f"PROBLEM:  {analysis.error}")
        return "\n".join(lines)
    lines.append(f"Format:   {analysis.format_name}")
    lines.append(f"Contains: {analysis.keys_in_file} key section(s), {analysis.values_in_file} value(s), "
                 f"{analysis.value_deletions} value deletion(s), {analysis.key_deletions} key deletion(s)")
    if analysis.detailed:
        lines.append(f"Effect:   {analysis.new_keys} new key(s), {analysis.new_values} new value(s), "
                     f"{analysis.changed_values} changed value(s), {analysis.unchanged_values} unchanged")
    lines.append(f"Touches:  {', '.join(sorted(analysis.hives)) or 'nothing'}")
    lines.extend(f"BLOCKED:  {reason}" for reason in analysis.blocked_reasons)
    if analysis.has_delete_lines:
        lines.append("WARNING:  this file contains explicit delete instructions.")
    lines.extend(f"Note:     {warning}" for warning in analysis.warnings)
    if analysis.preview_lines:
        lines.append("")
        lines.append("What merging would do:")
        lines.extend(analysis.preview_lines)
        if analysis.preview_truncated:
            lines.append(f"... and more (showing the first {MAX_PREVIEW_ROWS})")
    elif analysis.detailed and not analysis.is_blocked:
        lines.append("")
        lines.append("Nothing would change: every value in this file is already in the registry.")
    return "\n".join(lines)


def format_undo_check_failure(error_text: str, failed: list[tuple[BrokenEntry, int]], offer_override: bool) -> str:
    """
    Build the text of the error box shown when the undo backup of a Clean run failed its safety check.

    Args:
        error_text (str): The engine's own message ("The undo backup failed its safety check (...). Nothing was changed.").
        failed (list[tuple[BrokenEntry, int]]): The entries that caused it, each with how often it has failed so far.
            They have just been unticked in the results list.
        offer_override (bool): True if the box also carries the "Continue anyway (risky!)" button.

    Returns:
        str: Multi-line text for the message box.
    """
    lines = [error_text]
    if failed:
        lines += ["", f"Unticked because of this ({plural(len(failed), 'entry', 'entries')}):"]
        lines.extend(f"  - {entry.display_location}  (failed {plural(attempts, 'time', 'times')})"
                     for entry, attempts in failed[:UI_UNDO_FAILED_LIST_LIMIT])
        if len(failed) > UI_UNDO_FAILED_LIST_LIMIT:
            lines.append(f"  ... and {len(failed) - UI_UNDO_FAILED_LIST_LIMIT} more (see the log)")
    lines += ["", "Details were saved to the log (Open Error Log)."]
    if offer_override:
        lines += ["", (f"Every entry listed has now failed the check {UNDO_FAILURES_BEFORE_OVERRIDE} or more times. "
                        f"'{UI_CONTINUE_ANYWAY_TEXT}' deletes them anyway: their undo file is still saved, but it could not "
                        "be fully verified, so restoring them later may not bring back every value exactly. "
                        "Press OK to leave them alone.")]
    return "\n".join(lines)


def format_accepted_undo_note(messages: list[str]) -> str:
    """
    Explain, in the "Clean finished" box, which undo-file problems the user chose to live with.

    Args:
        messages (list[str]): The read-back problems that were accepted (empty for a normal, fully verified run).

    Returns:
        str: Text starting with a blank line, or "" if there is nothing to explain.
    """
    if not messages:
        return ""
    lines = ["", "", f"The undo file could not be fully verified (you chose '{UI_CONTINUE_ANYWAY_TEXT}'):"]
    lines.extend(f"  - {text}" for text in messages[:UI_UNDO_FAILED_LIST_LIMIT])
    if len(messages) > UI_UNDO_FAILED_LIST_LIMIT:
        lines.append(f"  ... and {len(messages) - UI_UNDO_FAILED_LIST_LIMIT} more (see the log)")
    lines.append("Restoring from it may not bring back every value exactly.")
    return "\n".join(lines)


# =============================================================================
# MAIN WINDOW
# =============================================================================

class RegistryCleanerWindow(QMainWindow):
    """
    Main window with four tabs (Clean, Backup, Restore Defaults, Import .reg) that share one progress bar.

    The window only handles display and input; all registry work happens in the engine functions above, run
    in a background TaskWorker so the window never freezes.
    """

    def __init__(self, is_admin: bool) -> None:
        """
        Args:
            is_admin (bool): Whether the process is elevated (write buttons are disabled if not).
        """
        super().__init__()
        log("[INIT] Initializing RegistryCleanerWindow...")
        self.is_admin = is_admin
        self.settings: dict[str, Any] = load_settings()
        self.backup_root: str = resolve_backup_root(self.settings)
        self.worker: TaskWorker | None = None
        self.busy = False
        self.critical_stage = False
        self.found_entries: list[BrokenEntry] = []
        self.repair_items: list[RepairItem] = []
        self.import_paths: list[str] = []
        self.import_analyses: dict[str, ImportAnalysis] = {}
        self.managed_reasons: list[str] | None = None
        self._selection_refresh_pending = False
        self.review_first_categories: set[str] = set()     # result groups that start unticked (need individual review)
        # Findings whose undo backup failed the safety check (this session only). It must exist BEFORE init_ui(),
        # because building the result tree consults it to decide which rows start unticked.
        self.undo_failures = UndoFailureTracker()
        self.init_ui()
        log("[INIT] RegistryCleanerWindow initialization complete")

    # ------------------------------------------------------------------ construction
    def init_ui(self) -> None:
        """Build all widgets, then size the window to fit them, lock that size and centre it on the screen."""
        log("[UI] Initializing user interface components...")
        self.setWindowTitle(APP_WINDOW_TITLE)
        icon_path = resource_path(ICON_FILE_NAME)
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            log(f"[WARNING] Icon file not found (optional): {icon_path}")
        self.setAcceptDrops(True)   # .reg files can be dropped anywhere on the window

        central_widget = QWidget()
        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(UI_WINDOW_MARGIN, UI_WINDOW_MARGIN, UI_WINDOW_MARGIN, UI_WINDOW_MARGIN)
        root_layout.setSpacing(UI_LAYOUT_SPACING)
        root_layout.addLayout(self.build_header())
        self.tabs = QTabWidget()
        self.clean_page = self.build_clean_tab()
        self.backup_page = self.build_backup_tab()
        self.restore_page = self.build_restore_tab()
        self.import_page = self.build_import_tab()
        self.tabs.addTab(self.clean_page, "Clean 🧹")
        self.tabs.addTab(self.backup_page, "Backup 💾")
        self.tabs.addTab(self.restore_page, "Restore Defaults 🛠️")
        self.tabs.addTab(self.import_page, "Import .reg 📥")
        root_layout.addWidget(self.tabs)
        root_layout.addLayout(self.build_footer())
        self.setCentralWidget(central_widget)

        self.refresh_button_states()
        self.update_log_button_states()
        # Apply the stylesheet and fonts to every widget NOW: size hints measured before that are slightly too small,
        # which would make the locked window a few pixels shorter than its content wants.
        for widget in self.findChildren(QWidget):
            widget.ensurePolished()
        self.ensurePolished()
        self.adjustSize()                       # let the layouts decide how big everything needs to be ...
        self.setFixedSize(self.sizeHint())      # ... then lock that size (no resizing)
        self.center_window()
        log("[UI] User interface initialization complete")

    def center_window(self) -> None:
        """Move the window to the middle of the usable screen area (the area without the taskbar)."""
        screen = QApplication.primaryScreen()
        if screen is None:
            return
        area = screen.availableGeometry()
        self.move(area.x() + (area.width() - self.width()) // 2, area.y() + (area.height() - self.height()) // 2)

    def build_header(self) -> QHBoxLayout:
        """Build the top line: who the app runs as, and a restart button when it is not elevated."""
        layout = QHBoxLayout()
        layout.setSpacing(UI_LAYOUT_SPACING)
        if self.is_admin:
            self.admin_label = QLabel(f"Running as {describe_current_user()} (administrator) ✅")
            self.admin_label.setObjectName("mutedLabel")
        else:
            self.admin_label = QLabel("⚠ Limited mode: not running as administrator. You can analyze and preview, "
                                      "but changes are disabled.")
            self.admin_label.setObjectName("warningLabel")
        self.admin_label.setToolTip("Entries under HKEY_CURRENT_USER belong to this Windows account.")
        layout.addWidget(self.admin_label, 1)
        self.restart_admin_button = make_button("Restart as Administrator 🛡️", tooltip="Asks Windows (UAC) to reopen this program with administrator rights.")
        self.restart_admin_button.clicked.connect(self.on_restart_as_admin_clicked)
        self.restart_admin_button.setVisible(not self.is_admin)
        layout.addWidget(self.restart_admin_button)
        return layout

    def _new_tab_layout(self, page: QWidget) -> QVBoxLayout:
        """Create the standard layout (margins + spacing) for a tab page."""
        layout = QVBoxLayout(page)
        layout.setContentsMargins(UI_WINDOW_MARGIN, UI_WINDOW_MARGIN, UI_WINDOW_MARGIN, UI_WINDOW_MARGIN)
        layout.setSpacing(UI_LAYOUT_SPACING)
        return layout

    def _configure_tree(self, tree: QTreeWidget, headers: list[str], fixed_chars: dict[int, int]) -> None:
        """
        Apply the shared look of the result trees: minimum size, elided text and column widths.

        Args:
            tree (QTreeWidget): The tree to configure.
            headers (list[str]): Column titles.
            fixed_chars (dict[int, int]): Columns with a fixed width, as {column: width in average characters}.
                All other columns share the remaining space.
        """
        char_width = tree.fontMetrics().averageCharWidth()          # the real font decides how wide a "character" is
        fixed_widths = {column: chars * char_width for column, chars in fixed_chars.items()}
        flexible_columns = len(headers) - len(fixed_widths)
        needed_width = (sum(fixed_widths.values()) + flexible_columns * UI_STRETCH_COLUMN_MIN_CHARS * char_width
                        + UI_SCROLLBAR_ALLOWANCE)
        tree.setHeaderLabels(headers)
        tree.setMinimumSize(max(UI_RESULTS_MIN_WIDTH, needed_width), UI_RESULTS_MIN_HEIGHT)
        tree.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        tree.setUniformRowHeights(True)
        tree.setAlternatingRowColors(True)
        header = tree.header()
        if header is not None:
            header.setStretchLastSection(False)
            for column in range(len(headers)):
                header.setSectionResizeMode(column, QHeaderView.ResizeMode.Fixed if column in fixed_widths
                                            else QHeaderView.ResizeMode.Stretch)
        for column, width in fixed_widths.items():
            tree.setColumnWidth(column, width)

    def build_clean_tab(self) -> QWidget:
        """Build the Clean tab: category checkboxes, Analyze, the results list and the Clean button."""
        page = QWidget()
        layout = self._new_tab_layout(page)
        description = QLabel("Finds registry entries that point to files or folders that no longer exist. Nothing is "
                             "deleted until you review the list and confirm - an undo backup is saved first. Remembered network locations that "
                             "can stall Explorer are listed too, but unticked: they may be history you made on purpose.")
        description.setWordWrap(True)
        description.setObjectName("mutedLabel")
        layout.addWidget(description)

        group = QGroupBox("What to scan")
        grid = QGridLayout(group)
        grid.setSpacing(UI_LAYOUT_SPACING)
        self.category_checkboxes: dict[str, QCheckBox] = {}
        rows_per_column = (len(SCAN_CATEGORIES) + UI_CATEGORY_COLUMNS - 1) // UI_CATEGORY_COLUMNS
        for index, category in enumerate(SCAN_CATEGORIES):
            checkbox = QCheckBox(category.title)
            checkbox.setChecked(True)
            checkbox.setToolTip(category.tooltip)
            self.category_checkboxes[category.key] = checkbox
            grid.addWidget(checkbox, index % rows_per_column, index // rows_per_column)
        layout.addWidget(group)

        button_row = QHBoxLayout()
        self.select_all_categories_button = make_button("Select All ✔️", tooltip="Tick every category.")
        self.select_all_categories_button.clicked.connect(self.on_select_all_categories)
        self.analyze_button = make_button("Analyze 🔍", "primaryButton", "Scans the ticked categories. Nothing is changed.")
        self.analyze_button.clicked.connect(self.on_analyze_clicked)
        button_row.addWidget(self.select_all_categories_button)
        button_row.addStretch(1)
        button_row.addWidget(self.analyze_button)
        layout.addLayout(button_row)

        self.clean_tree = QTreeWidget()
        self._configure_tree(self.clean_tree, ["Entry", "Problem"], {1: UI_COLUMN_PROBLEM_CHARS})
        self.clean_tree.itemChanged.connect(self.on_clean_item_changed)
        layout.addWidget(self.clean_tree)

        bottom_row = QHBoxLayout()
        self.clean_summary_label = QLabel("Press Analyze to look for broken entries.")
        self.check_all_clean_button = make_button("Check All", tooltip=("Ticks every found entry except the ⚠ ones, which need your individual "
                                                                        f"review, and the {UI_UNDO_FAILED_MARKER} ones, whose undo backup failed the safety check."))
        self.check_all_clean_button.clicked.connect(lambda: self.set_all_clean_checks(Qt.CheckState.Checked))
        self.uncheck_all_clean_button = make_button("Uncheck All", tooltip="Untick every found entry.")
        self.uncheck_all_clean_button.clicked.connect(lambda: self.set_all_clean_checks(Qt.CheckState.Unchecked))
        self.clean_button = make_button("Clean Selected 🧹", "dangerButton", "Deletes the ticked entries after saving an undo backup.")
        self.clean_button.clicked.connect(self.on_clean_clicked)
        bottom_row.addWidget(self.clean_summary_label, 1)
        bottom_row.addWidget(self.check_all_clean_button)
        bottom_row.addWidget(self.uncheck_all_clean_button)
        bottom_row.addWidget(self.clean_button)
        layout.addLayout(bottom_row)
        return page

    def build_backup_tab(self) -> QWidget:
        """Build the Backup tab: folder chooser and the one-click full backup button."""
        page = QWidget()
        layout = self._new_tab_layout(page)
        description = QLabel(
            "Saves the whole registry (HKEY_LOCAL_MACHINE and HKEY_USERS - the other roots are views of those) as "
            "plain-text .reg files in a new time-stamped folder. Expect several hundred MB and a few minutes.\n"
            "Skipped on purpose: volatile and protected hives (HARDWARE, SAM, SECURITY).")
        description.setWordWrap(True)
        description.setObjectName("mutedLabel")
        layout.addWidget(description)

        group = QGroupBox("Backup folder")
        row = QHBoxLayout(group)
        self.backup_folder_edit = QLineEdit(self.backup_root)
        self.backup_folder_edit.setReadOnly(True)
        self.browse_backup_button = make_button("Browse Backup Folder 📁", tooltip="Choose where backups and undo files are saved.")
        self.browse_backup_button.clicked.connect(self.on_browse_backup_folder)
        self.open_backup_button = make_button("Open Backup Folder 📂")
        self.open_backup_button.clicked.connect(self.on_open_backup_folder)
        row.addWidget(self.backup_folder_edit, 1)
        row.addWidget(self.browse_backup_button)
        row.addWidget(self.open_backup_button)
        layout.addWidget(group)

        self.backup_button = make_button("Backup Whole Registry 💾", "primaryButton", "Exports the registry into a new folder inside the backup folder.")
        self.backup_button.clicked.connect(self.on_backup_clicked)
        layout.addWidget(self.backup_button)

        note = QLabel("Undo files created by Clean, Restore Defaults and Import are saved in the 'Undo' subfolder of the "
                      "backup folder. Note: .reg files do not store key permissions, and importing one never removes keys "
                      "that were added after the backup.")
        note.setWordWrap(True)
        note.setObjectName("mutedLabel")
        layout.addWidget(note)
        layout.addStretch(1)
        return page

    def build_restore_tab(self) -> QWidget:
        """Build the Restore Defaults tab: area checkboxes, Analyze, the old -> new preview and the Apply button."""
        page = QWidget()
        layout = self._new_tab_layout(page)
        description = QLabel("Compares a curated set of critical Windows settings with their defaults and proposes repairs "
                             "only where something differs. Each repair is shown as old -> new value, backed up in an undo "
                             "file first, and needs administrator rights and your confirmation.")
        description.setWordWrap(True)
        description.setObjectName("mutedLabel")
        layout.addWidget(description)

        group = QGroupBox("What to check")
        area_row = QHBoxLayout(group)
        self.area_checkboxes: dict[str, QCheckBox] = {}
        for area in RESTORE_AREAS:
            checkbox = QCheckBox(area.title)
            checkbox.setChecked(True)
            checkbox.setToolTip(area.tooltip)
            self.area_checkboxes[area.key] = checkbox
            area_row.addWidget(checkbox)
        layout.addWidget(group)

        button_row = QHBoxLayout()
        self.restore_analyze_button = make_button("Analyze 🔍", "primaryButton", "Compares the registry with the defaults. Nothing is changed.")
        self.restore_analyze_button.clicked.connect(self.on_restore_analyze_clicked)
        button_row.addStretch(1)
        button_row.addWidget(self.restore_analyze_button)
        layout.addLayout(button_row)

        self.restore_tree = QTreeWidget()
        self._configure_tree(self.restore_tree, ["Repair", "Location", "Current value", "Restored value"],
                             {0: UI_COLUMN_REPAIR_CHARS, 2: UI_COLUMN_CURRENT_CHARS, 3: UI_COLUMN_RESTORED_CHARS})
        self.restore_tree.itemChanged.connect(self.on_restore_item_changed)
        layout.addWidget(self.restore_tree)

        bottom_row = QHBoxLayout()
        self.restore_summary_label = QLabel("Press Analyze to compare with the Windows defaults.")
        self.restore_apply_button = make_button("Apply Selected Repairs 🛠️", "dangerButton", "Applies the ticked repairs after saving an undo backup.")
        self.restore_apply_button.clicked.connect(self.on_restore_apply_clicked)
        bottom_row.addWidget(self.restore_summary_label, 1)
        bottom_row.addWidget(self.restore_apply_button)
        layout.addLayout(bottom_row)
        return page

    def build_import_tab(self) -> QWidget:
        """Build the Import tab: file list (drag & drop works too), Preview and Merge."""
        page = QWidget()
        layout = self._new_tab_layout(page)
        description = QLabel("Merge .reg files into the registry. Merging adds keys, overwrites values with the same name and "
                             "removes nothing unless the file itself says so. Drop files here or use Add. Preview first: an "
                             "undo file of exactly what changes is written before anything is merged.")
        description.setWordWrap(True)
        description.setObjectName("mutedLabel")
        layout.addWidget(description)

        self.import_list = QListWidget()
        self.import_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.import_list.setMinimumHeight(UI_FILE_LIST_MIN_HEIGHT)
        self.import_list.itemSelectionChanged.connect(self.show_import_details)
        layout.addWidget(self.import_list, 1)     # the preview box below gets the extra height, so it is given more weight

        button_row = QHBoxLayout()
        self.import_add_button = make_button("Add .reg Files 📄")
        self.import_add_button.clicked.connect(self.on_import_add_clicked)
        self.import_remove_button = make_button("Remove Selected")
        self.import_remove_button.clicked.connect(self.on_import_remove_clicked)
        self.import_clear_button = make_button("Clear List")
        self.import_clear_button.clicked.connect(self.on_import_clear_clicked)
        self.import_preview_button = make_button("Preview 🔍", "primaryButton", "Shows what merging would do. Nothing is changed.")
        self.import_preview_button.clicked.connect(self.on_import_preview_clicked)
        self.import_merge_button = make_button("Merge into Registry 📥", "dangerButton", "Merges the previewed files after saving undo files.")
        self.import_merge_button.clicked.connect(self.on_import_merge_clicked)
        for widget in (self.import_add_button, self.import_remove_button, self.import_clear_button):
            button_row.addWidget(widget)
        button_row.addStretch(1)
        button_row.addWidget(self.import_preview_button)
        button_row.addWidget(self.import_merge_button)
        layout.addLayout(button_row)

        self.import_details = QPlainTextEdit()
        self.import_details.setReadOnly(True)
        self.import_details.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.import_details.setMinimumSize(UI_RESULTS_MIN_WIDTH, UI_PREVIEW_MIN_HEIGHT)
        self.import_details.setPlaceholderText("Select a file and press Preview to see what merging it would do.")
        layout.addWidget(self.import_details, 3)
        return page

    def build_footer(self) -> QVBoxLayout:
        """Build the bottom area shared by all tabs: progress bar, status line, Cancel and the log buttons."""
        layout = QVBoxLayout()
        layout.setSpacing(UI_LAYOUT_SPACING)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        row = QHBoxLayout()
        self.status_label = QLabel("Ready ✌️")
        self.status_label.setMinimumWidth(UI_STATUS_MIN_WIDTH)
        self.cancel_button = make_button("Cancel ⛔", tooltip="Stops the running task at the next safe point.")
        self.cancel_button.clicked.connect(self.on_cancel_clicked)
        self.open_logs_button = make_button("Open Logs 📂", tooltip="Opens the folder with the detailed log of every run.")
        self.open_logs_button.clicked.connect(self.on_open_logs)
        self.open_error_log_button = make_button("Open Error Log 📃", tooltip="Opens error-log 📃.txt next to the program.")
        self.open_error_log_button.clicked.connect(self.on_open_error_log)
        self.open_undo_button = make_button("Open Undo Files ↩️", tooltip="Opens the folder with the undo .reg files. Import one to undo a change.")
        self.open_undo_button.clicked.connect(self.on_open_undo_folder)
        row.addWidget(self.status_label, 1)
        for widget in (self.cancel_button, self.open_undo_button, self.open_logs_button, self.open_error_log_button):
            row.addWidget(widget)
        layout.addLayout(row)
        return layout

    # ------------------------------------------------------------------ shared state helpers
    def set_status(self, text: str) -> None:
        """Show a status line, shortened in the middle if it is too long (the full text is in the tooltip)."""
        self.status_label.setToolTip(text)
        width = max(UI_STATUS_MIN_WIDTH, self.status_label.width())
        self.status_label.setText(self.status_label.fontMetrics().elidedText(text, Qt.TextElideMode.ElideMiddle, width))

    def count_checked(self, tree: QTreeWidget) -> int:
        """Count the ticked child rows of a result tree."""
        total = 0
        for top_index in range(tree.topLevelItemCount()):
            parent = tree.topLevelItem(top_index)
            if parent is None:
                continue
            total += sum(1 for child_index in range(parent.childCount())
                         if (child := parent.child(child_index)) is not None and child.checkState(0) == Qt.CheckState.Checked)
        return total

    def refresh_button_states(self) -> None:
        """Enable/disable every button from one place, based on: busy, administrator rights and what is selected."""
        idle = not self.busy
        can_write = idle and self.is_admin
        admin_hint = "" if self.is_admin else "Administrator rights are required - use 'Restart as Administrator'."

        self.analyze_button.setEnabled(idle)
        self.select_all_categories_button.setEnabled(idle)
        has_clean_results = bool(self.found_entries)
        self.check_all_clean_button.setEnabled(idle and has_clean_results)
        self.uncheck_all_clean_button.setEnabled(idle and has_clean_results)
        self.clean_button.setEnabled(can_write and self.count_checked(self.clean_tree) > 0)
        self.clean_button.setToolTip(admin_hint or "Deletes the ticked entries after saving an undo backup.")

        self.browse_backup_button.setEnabled(idle)
        self.open_backup_button.setEnabled(idle)
        self.backup_button.setEnabled(can_write)
        self.backup_button.setToolTip(admin_hint or "Exports the registry into a new folder inside the backup folder.")

        self.restore_analyze_button.setEnabled(idle)
        self.restore_apply_button.setEnabled(can_write and self.count_checked(self.restore_tree) > 0)
        self.restore_apply_button.setToolTip(admin_hint or "Applies the ticked repairs after saving an undo backup.")

        has_files = bool(self.import_paths)
        mergeable = [path for path in self.import_paths if path in self.import_analyses and not self.import_analyses[path].is_blocked]
        self.import_add_button.setEnabled(idle)
        self.import_remove_button.setEnabled(idle and has_files)
        self.import_clear_button.setEnabled(idle and has_files)
        self.import_preview_button.setEnabled(idle and has_files)
        self.import_merge_button.setEnabled(can_write and bool(mergeable))
        self.import_merge_button.setToolTip(admin_hint or "Merges the previewed files after saving undo files.")

        self.cancel_button.setEnabled(self.busy and not self.critical_stage)
        self.open_undo_button.setEnabled(idle)

    def update_log_button_states(self) -> None:
        """Grey out the log buttons while there is nothing to open (same behaviour as the other Rane tools)."""
        self.open_logs_button.setEnabled(os.path.isdir(LOG_DIR) and len(os.listdir(LOG_DIR)) > 0)
        self.open_error_log_button.setEnabled(os.path.exists(os.path.join(get_app_dir(), ERROR_LOG_FILE_NAME)))

    # ------------------------------------------------------------------ dialogs
    def show_info(self, title: str, text: str) -> None:
        """Show an information box."""
        QMessageBox.information(self, title, text)

    def show_warning(self, title: str, text: str) -> None:
        """Show a warning box."""
        QMessageBox.warning(self, title, text)

    def show_finished_box(self, title: str, text: str, advice: RestartAdvice | None, warning: bool = False) -> None:
        """
        Show the "... finished" box; when a restart is advised it also offers "Restart Now" / "Restart Later".

        Args:
            title (str): Box title.
            text (str): What the operation did.
            advice (RestartAdvice | None): None = nothing changed (no restart paragraph at all).
            warning (bool): True to use the warning look when no restart is offered (the operation had problems).
        """
        if advice is None:
            (self.show_warning if warning else self.show_info)(title, text)
            return
        full_text = f"{text}\n\n{format_restart_advice(advice)}"
        if not advice.needs_restart:
            (self.show_warning if warning else self.show_info)(title, full_text)
            return
        full_text += (f"\n\n'Restart Now' starts a {RESTART_DELAY_SECONDS}-second countdown, so save your work in other programs first. "
                      "You can cancel the countdown with 'shutdown /a' in a Command Prompt.")
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning if warning or advice.level is RestartLevel.STRONG else QMessageBox.Icon.Information)
        box.setWindowTitle(title)
        box.setText(full_text)
        now_button = make_button("Restart Now", tooltip=f"Restarts Windows after a {RESTART_DELAY_SECONDS}-second countdown.")
        box.addButton(now_button, QMessageBox.ButtonRole.AcceptRole)
        later_button = box.addButton("Restart Later", QMessageBox.ButtonRole.RejectRole)
        if later_button is not None:
            box.setDefaultButton(later_button)   # Enter must never restart the computer ...
            box.setEscapeButton(later_button)    # ... and neither must Esc or the window's close button
        box.exec()
        chose_restart = box.clickedButton() is now_button
        box.deleteLater()
        if chose_restart:
            self.restart_windows_now()

    def restart_windows_now(self) -> None:
        """Start the restart countdown and tell the user how to cancel it (or why it could not be started)."""
        started, message = schedule_windows_restart()
        self.set_status(message)
        if not started:
            self.show_error("The restart could not be started", message)

    def show_error(self, title: str, text: str) -> None:
        """Show an error box."""
        QMessageBox.critical(self, title, text)

    def ask_yes_no(self, title: str, text: str) -> bool:
        """Ask a yes/no question; 'No' is the default so that pressing Enter never confirms a risky action."""
        answer = QMessageBox.question(self, title, text,
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                      QMessageBox.StandardButton.No)
        return answer == QMessageBox.StandardButton.Yes

    def require_admin(self) -> bool:
        """Return True if the app is elevated; otherwise explain how to get administrator rights and return False."""
        if self.is_admin:
            return True
        self.show_warning("Administrator rights needed",
                          "This action changes the registry, which needs administrator rights.\n\n"
                          "Use 'Restart as Administrator' at the top of the window.")
        return False

    def on_restart_as_admin_clicked(self) -> None:
        """Reopen the program elevated and close this instance if Windows accepted the request."""
        if relaunch_as_admin():
            QApplication.quit()
        else:
            self.show_info("Not restarted", "The restart as administrator was cancelled or failed. "
                                            "The program keeps running in limited mode.")

    # ------------------------------------------------------------------ background task plumbing
    def start_task(self, task: Callable[[ProgressReporter], Any], description: str, on_success: Callable[[Any], None],
                   on_undo_failure: Callable[[UndoVerificationError], None] | None = None) -> None:
        """
        Run an engine task in a background thread and route its outcome back to this window.

        Args:
            task (Callable): Function taking a ProgressReporter and returning the result object.
            description (str): Short name for the log.
            on_success (Callable): Called (in the UI thread) with the task's result.
            on_undo_failure (Callable | None): Called (in the UI thread) instead of the generic error box when the task
                stopped because its undo backup failed the safety check. None = show the generic error box, exactly
                like for any other error (that is what Restore and Import do).
        """
        if self.busy:
            return
        worker = TaskWorker(task, description)
        worker.progress_updated.connect(self.progress_bar.setValue)
        worker.status_updated.connect(self.set_status)
        worker.critical_changed.connect(self.on_critical_changed)
        worker.task_succeeded.connect(lambda result: self.on_task_succeeded(on_success, result))
        worker.task_failed.connect(self.on_task_failed)
        worker.undo_check_failed.connect(lambda error: self.on_task_undo_check_failed(on_undo_failure, error))
        worker.task_cancelled.connect(self.on_task_cancelled)
        self.worker = worker
        self.busy = True
        self.critical_stage = False
        self.progress_bar.setValue(0)
        self.refresh_button_states()
        worker.start()

    def finish_task(self) -> None:
        """Common clean-up after a task ended (success, failure or cancel): unlock the window."""
        worker = self.worker
        self.busy = False
        self.critical_stage = False
        if worker is not None:
            worker.wait(2000)   # the thread is already leaving run(); this only lets it finish tearing down
        self.worker = None
        self.refresh_button_states()
        self.update_log_button_states()

    def on_task_succeeded(self, callback: Callable[[Any], None], result: Any) -> None:
        """A task finished normally: unlock the window, then let the tab that started it show the result."""
        self.finish_task()
        try:
            callback(result)
        except Exception as error:   # a bug while showing results must never leave the window locked or crash it
            log_exception("Showing a finished task's result failed")
            self.show_error("Something went wrong", f"The task finished, but showing its result failed:\n{error}")

    def on_task_failed(self, message: str) -> None:
        """A task stopped with an error: unlock the window, log it and tell the user what happened."""
        self.finish_task()
        self.set_status("Stopped - see the message.")
        export_error_log([message])
        self.update_log_button_states()
        self.show_error("The operation stopped", f"{message}\n\nDetails were saved to the log (Open Error Log).")

    def on_task_undo_check_failed(self, handler: Callable[[UndoVerificationError], None] | None,
                                  error: UndoVerificationError) -> None:
        """
        A task stopped because its undo backup failed the safety check (nothing was changed).

        Args:
            handler (Callable | None): The tab's own reaction (Clean has one); None = treat it like any other error.
            error (UndoVerificationError): The failure, including the individual problems.
        """
        if handler is None:
            self.on_task_failed(str(error))       # same box and same log entry as before this feature existed
            return
        self.finish_task()                        # unlock first: the handler may show a dialog or even start a new task
        try:
            handler(error)
        except Exception as handler_error:        # a bug while reacting must never leave the window locked or crash it
            log_exception("Handling a failed undo safety check failed")
            self.show_error("Something went wrong", f"{error}\n\nShowing the details failed:\n{handler_error}")

    def on_task_cancelled(self) -> None:
        """A task was cancelled by the user."""
        self.finish_task()
        self.progress_bar.setValue(0)
        self.set_status("Cancelled.")

    def on_cancel_clicked(self) -> None:
        """Ask the running task to stop at its next safe point."""
        if self.worker is not None:
            self.worker.cancel()
            self.set_status("Cancelling...")
            self.cancel_button.setEnabled(False)

    def on_critical_changed(self, is_critical: bool) -> None:
        """A task entered/left a stage that must not be interrupted (Cancel and closing are blocked meanwhile)."""
        self.critical_stage = is_critical
        self.refresh_button_states()

    # ------------------------------------------------------------------ CLEAN tab
    def on_select_all_categories(self) -> None:
        """Tick every scan category."""
        for checkbox in self.category_checkboxes.values():
            checkbox.setChecked(True)

    def on_analyze_clicked(self) -> None:
        """Start scanning the ticked categories."""
        categories = [key for key, checkbox in self.category_checkboxes.items() if checkbox.isChecked()]
        if not categories:
            self.show_info("Nothing to scan", "Tick at least one category first.")
            return
        self.found_entries = []
        self.populate_clean_tree()
        self.update_clean_summary()
        self.start_task(lambda reporter: RegistryScanner(reporter).scan(categories), "Scan", self.on_scan_finished)

    def on_scan_finished(self, entries: list[BrokenEntry]) -> None:
        """Show the scan results in the tree."""
        self.found_entries = entries
        self.populate_clean_tree()
        self.update_clean_summary()
        self.refresh_button_states()
        if entries:
            self.set_status(f"Scan finished: {plural(len(entries), 'entry', 'entries')} found. Review the list, then press Clean.")
        else:
            self.set_status("Scan finished: nothing found ✅")

    def populate_clean_tree(self) -> None:
        """
        Fill the results tree from self.found_entries, grouped by category.

        Everything starts ticked except entries that need a deliberate decision: possible user history (⚠) and
        entries whose undo backup already failed the safety check earlier in this session (⛔).
        """
        tree = self.clean_tree
        tree.blockSignals(True)
        tree.setUpdatesEnabled(False)
        tree.clear()
        parents: dict[str, QTreeWidgetItem] = {}
        self.review_first_categories = set()
        for index, entry in enumerate(self.found_entries):
            parent = parents.get(entry.category)
            if parent is None:
                parent = QTreeWidgetItem(tree, [SCAN_CATEGORY_TITLES.get(entry.category, entry.category), ""])
                parent.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsAutoTristate)
                parent.setData(0, Qt.ItemDataRole.UserRole, entry.category)   # lets 'Check All' recognise review-first groups
                parents[entry.category] = parent
            if entry.review_first:
                self.review_first_categories.add(entry.category)
            child = QTreeWidgetItem(parent, [self.build_clean_row_label(entry), entry.reason])
            child.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsUserCheckable)
            # Entries that may be deliberate user history, or that already failed the undo check, start UNTICKED.
            needs_decision = entry.review_first or self.undo_failures.has_failed(entry)
            child.setCheckState(0, Qt.CheckState.Unchecked if needs_decision else Qt.CheckState.Checked)
            child.setData(0, Qt.ItemDataRole.UserRole, index)
            child.setToolTip(0, self.build_clean_row_tooltip(entry))
            child.setToolTip(1, entry.reason)
        for category_key, parent in parents.items():
            parent.setText(0, f"{SCAN_CATEGORY_TITLES.get(category_key, category_key)} ({parent.childCount()})")
            parent.setExpanded(True)          # the group's own check state is derived from its rows (partly ticked, ...)
        tree.setUpdatesEnabled(True)
        tree.blockSignals(False)

    def build_clean_row_label(self, entry: BrokenEntry) -> str:
        """
        Text of a result row's first column: the location, prefixed by the markers that apply to it.

        Args:
            entry (BrokenEntry): The finding shown in the row.

        Returns:
            str: The location, e.g. "⛔ ⚠ HKCU\\Software\\..." (⛔ = its undo backup failed the safety check, ⚠ = review first).
        """
        markers = ""
        if self.undo_failures.has_failed(entry):
            markers += f"{UI_UNDO_FAILED_MARKER} "
        if entry.review_first:
            markers += "⚠ "
        return f"{markers}{entry.display_location}"

    def build_clean_row_tooltip(self, entry: BrokenEntry) -> str:
        """
        Tooltip of a result row: the full key, the details and one note for every marker that applies.

        Args:
            entry (BrokenEntry): The finding shown in the row.

        Returns:
            str: Multi-line tooltip text.
        """
        review_note = "\n⚠ This may be history you created on purpose, so it is not ticked by default." if entry.review_first else ""
        failure_note = ""
        failures = self.undo_failures.failure_count(entry)
        if failures:
            failure_note = (f"\n{UI_UNDO_FAILED_MARKER} Its undo backup failed the safety check {plural(failures, 'time', 'times')}, "
                            "so it was unticked. Tick it yourself to try again.")
        return f"{entry.full_key_path}\n{entry.detail}{review_note}{failure_note}".strip()

    def iter_clean_rows(self) -> Iterator[tuple[QTreeWidgetItem, BrokenEntry]]:
        """Yield (row, finding) for every result row of the Clean tab, group by group."""
        for top_index in range(self.clean_tree.topLevelItemCount()):
            group = self.clean_tree.topLevelItem(top_index)
            if group is None:
                continue
            for child_index in range(group.childCount()):
                row = group.child(child_index)
                if row is not None:
                    yield row, self.found_entries[int(row.data(0, Qt.ItemDataRole.UserRole))]

    def mark_failed_rows(self, failed: list[BrokenEntry]) -> None:
        """
        Untick and mark the result rows of entries that just failed the undo safety check.

        Only those rows change. Rebuilding the whole tree would also reset every other tick the user set and the scroll
        position, which is the last thing anyone wants after a failed attempt.

        Args:
            failed (list[BrokenEntry]): The entries whose failure was just recorded in self.undo_failures.
        """
        failed_identities = {entry.identity for entry in failed}
        self.clean_tree.blockSignals(True)     # one refresh at the end instead of one per changed row
        for row, entry in self.iter_clean_rows():
            if entry.identity in failed_identities:
                row.setCheckState(0, Qt.CheckState.Unchecked)
                row.setText(0, self.build_clean_row_label(entry))          # now carries the ⛔ marker
                row.setToolTip(0, self.build_clean_row_tooltip(entry))     # ... and explains it
        self.clean_tree.blockSignals(False)
        self.flush_selection_refresh()

    def untick_failed_rows(self, group: QTreeWidgetItem) -> None:
        """
        Untick the rows of one result group whose undo backup failed the safety check.

        Ticking a whole group (Check All) would otherwise silently re-select them: the next Clean would run into the same
        failure again and use up one of the attempts without the user having decided to retry.

        Args:
            group (QTreeWidgetItem): A top-level group row of the results tree.
        """
        for child_index in range(group.childCount()):
            row = group.child(child_index)
            if row is not None and self.undo_failures.has_failed(self.found_entries[int(row.data(0, Qt.ItemDataRole.UserRole))]):
                row.setCheckState(0, Qt.CheckState.Unchecked)

    def collect_checked_clean_entries(self) -> list[BrokenEntry]:
        """Return the findings whose row is ticked."""
        selected: list[BrokenEntry] = []
        for top_index in range(self.clean_tree.topLevelItemCount()):
            parent = self.clean_tree.topLevelItem(top_index)
            if parent is None:
                continue
            for child_index in range(parent.childCount()):
                child = parent.child(child_index)
                if child is not None and child.checkState(0) == Qt.CheckState.Checked:
                    selected.append(self.found_entries[int(child.data(0, Qt.ItemDataRole.UserRole))])
        return selected

    def update_clean_summary(self) -> None:
        """Refresh the 'N of M selected' line under the results."""
        total = len(self.found_entries)
        if total:
            self.clean_summary_label.setText(f"{self.count_checked(self.clean_tree)} of {total} entries selected")
        else:
            self.clean_summary_label.setText("No broken entries listed.")

    def on_clean_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        """A checkbox in the results changed: schedule ONE refresh of the summary and buttons."""
        self.schedule_selection_refresh()

    def schedule_selection_refresh(self) -> None:
        """
        Coalesce many checkbox changes into a single refresh.

        Ticking a category box changes every child row and emits one signal per row. Refreshing the summary for each
        of them would re-count the whole list every time (quadratic) and freeze the window with thousands of rows.
        """
        if not self._selection_refresh_pending:
            self._selection_refresh_pending = True
            QTimer.singleShot(0, self.flush_selection_refresh)

    def flush_selection_refresh(self) -> None:
        """Update both summaries and all button states once, after a burst of checkbox changes."""
        self._selection_refresh_pending = False
        self.update_clean_summary()
        self.update_restore_summary()
        self.refresh_button_states()

    def set_all_clean_checks(self, state: Qt.CheckState) -> None:
        """
        Tick or untick result groups (one refresh at the end, not one per row).

        Ticking skips the groups whose entries need individual review (the ⚠ ones) and leaves the rows whose undo
        backup failed the safety check (the ⛔ ones) unticked: those are only ticked by the user deliberately, row by
        row or with the group's own checkbox.
        """
        self.clean_tree.blockSignals(True)
        for top_index in range(self.clean_tree.topLevelItemCount()):
            parent = self.clean_tree.topLevelItem(top_index)
            if parent is None:
                continue
            if state == Qt.CheckState.Checked and parent.data(0, Qt.ItemDataRole.UserRole) in self.review_first_categories:
                continue
            parent.setCheckState(0, state)
            if state == Qt.CheckState.Checked:
                self.untick_failed_rows(parent)
        self.clean_tree.blockSignals(False)
        self.flush_selection_refresh()

    def on_clean_clicked(self) -> None:
        """Ask for confirmation, then clean the ticked entries (undo backup first)."""
        if not self.require_admin():
            return
        selected = self.collect_checked_clean_entries()
        if not selected:
            return
        counts: dict[str, int] = {}
        for entry in selected:
            counts[entry.category] = counts.get(entry.category, 0) + 1
        breakdown = "\n".join(f"  {SCAN_CATEGORY_TITLES.get(key, key)}: {count}" for key, count in counts.items())
        undo_folder = os.path.join(self.backup_root, UNDO_SUBFOLDER_NAME)
        network_count = sum(1 for entry in selected if entry.category == CATEGORY_NET_HISTORY)
        network_note = ""
        if network_count:
            network_note = (f"\n\nIncludes {plural(network_count, 'remembered network location', 'remembered network locations')} that you "
                            "ticked yourself. This is Explorer history: no files, shares, mapped drives or saved credentials are touched.")
        question = (f"Delete {plural(len(selected), 'registry entry', 'registry entries')}?\n\n{breakdown}{network_note}\n\n"
                    f"Before anything is deleted, an undo backup of exactly these entries is saved to:\n{undo_folder}\n\n"
                    "If anything looks wrong afterwards, import that file from the Import tab.")
        if not self.ask_yes_no("Confirm cleaning", question):
            return
        self.start_clean(selected)

    def start_clean(self, entries: list[BrokenEntry], accepted_identities: frozenset[EntryIdentity] = frozenset()) -> None:
        """
        Run the clean engine on these entries in the background.

        Shared by the normal "Clean Selected" path and the "Continue anyway (risky!)" path, so both go through exactly
        the same engine (allow-list, re-validation, undo file). The only difference is which failed undo checks the
        engine is allowed to accept.

        Args:
            entries (list[BrokenEntry]): The findings to delete.
            accepted_identities (frozenset[EntryIdentity]): Entries whose unverifiable undo backup the user accepted
                (empty = strict, any problem aborts).
        """
        backup_root = self.backup_root
        self.start_task(lambda reporter: clean_entries(entries, backup_root, reporter, accepted_identities),
                        "Clean", self.on_clean_finished,
                        on_undo_failure=lambda error: self.on_clean_undo_check_failed(entries, error))

    def on_clean_undo_check_failed(self, attempted: list[BrokenEntry], error: UndoVerificationError) -> None:
        """
        A Clean run stopped because the undo backup failed its safety check (nothing was deleted).

        1. The entries that caused it are unticked and marked, so the next Clean does not run into the same wall.
        2. Each of them is counted. Once every one of them has failed UNDO_FAILURES_BEFORE_OVERRIDE times, the error
           box gets a second button, "Continue anyway (risky!)", next to OK.
        3. Choosing it repeats the same clean, this time accepting the unverified undo file for exactly those entries.

        Args:
            attempted (list[BrokenEntry]): Everything the failed run tried to delete (repeated if the user continues).
            error (UndoVerificationError): The failure, including which entries are responsible.
        """
        self.set_status("Stopped - see the message.")
        export_error_log([str(error)])
        self.update_log_button_states()
        failed = error.failed_entries
        for entry in failed:
            attempts = self.undo_failures.record_failure(entry)
            log(f"[WARNING] Undo safety check failed for {entry.display_location} "
                f"(attempt {attempts}, the risky choice is offered from attempt {UNDO_FAILURES_BEFORE_OVERRIDE})")
        self.mark_failed_rows(failed)
        # Offer the risky choice only when EVERY entry that failed this time has failed often enough: the repeated run
        # accepts problems for those entries only, so one with fewer failures would simply stop it again.
        offer_override = bool(failed) and all(self.undo_failures.is_override_eligible(entry) for entry in failed)
        if not self.show_undo_check_error(error, failed, offer_override):
            return
        log(f"[WARNING] User chose '{UI_CONTINUE_ANYWAY_TEXT}' for {plural(len(failed), 'entry', 'entries')} "
            "whose undo backup could not be verified")
        self.start_clean(attempted, frozenset(entry.identity for entry in failed))

    def show_undo_check_error(self, error: UndoVerificationError, failed: list[BrokenEntry], offer_override: bool) -> bool:
        """
        Show the "The operation stopped" box for a failed undo safety check, with a second button when that is allowed.

        Args:
            error (UndoVerificationError): The failure.
            failed (list[BrokenEntry]): The entries responsible (already unticked and counted).
            offer_override (bool): True to add the "Continue anyway (risky!)" button next to OK.

        Returns:
            bool: True only if the user pressed "Continue anyway (risky!)" - a button that exists only when offered.
        """
        counted = [(entry, self.undo_failures.failure_count(entry)) for entry in failed]
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Critical)
        box.setWindowTitle("The operation stopped")
        box.setText(format_undo_check_failure(str(error), counted, offer_override))
        box.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)   # lets the user copy a key path
        ok_button = box.addButton(QMessageBox.StandardButton.Ok)
        if ok_button is not None:
            box.setDefaultButton(ok_button)      # Enter must never pick the risky choice ...
            box.setEscapeButton(ok_button)       # ... and neither must Esc or the window's close button
        continue_button: QPushButton | None = None
        if offer_override:
            # Built with make_button (not box.addButton(text, role)): the "dangerButton" style name must be set BEFORE the
            # widget is first polished, otherwise the stylesheet never picks it up and the risky choice looks harmless.
            continue_button = make_button(UI_CONTINUE_ANYWAY_TEXT, "dangerButton",
                                          "Deletes the entries although their undo backup could not be fully verified. "
                                          "The undo file is still saved.")
            box.addButton(continue_button, QMessageBox.ButtonRole.DestructiveRole)
        box.exec()
        chose_continue = continue_button is not None and box.clickedButton() is continue_button
        box.deleteLater()   # the box is parented to the window: without this every failure would leave a hidden box behind
        return chose_continue

    def on_clean_finished(self, report: CleanReport) -> None:
        """Show what the clean run did and remove the deleted entries from the list."""
        deleted_ids = {id(entry) for entry in report.deleted}
        for entry in report.deleted:
            self.undo_failures.forget(entry)     # gone from the registry: its failure history no longer matters
        self.found_entries = [entry for entry in self.found_entries if id(entry) not in deleted_ids]
        self.populate_clean_tree()
        self.update_clean_summary()
        self.refresh_button_states()
        lines = [f"Deleted: {len(report.deleted)}", f"Skipped: {len(report.skipped)}", f"Failed: {len(report.failed)}"]
        details = ""
        if report.skipped:
            details += "\n\nSkipped (left untouched):\n" + summarize_reasons([(e.display_location, why) for e, why in report.skipped])
        if report.failed:
            details += "\n\nCould not be deleted:\n" + summarize_reasons([(e.display_location, why) for e, why in report.failed])
            export_error_log([f"Could not delete {e.display_location}: {why}" for e, why in report.failed])
            self.update_log_button_states()
        details += format_accepted_undo_note(report.accepted_undo_problems)   # only present after "Continue anyway"
        undo_text = f"\n\nUndo file:\n{report.undo_file}" if report.undo_file else ""
        summary = "\n".join(lines)
        self.set_status(f"Clean finished: {len(report.deleted)} deleted, {len(report.skipped)} skipped, {len(report.failed)} failed.")
        self.show_finished_box("Clean finished", f"{summary}{details}{undo_text}", assess_clean_restart(report))

    # ------------------------------------------------------------------ BACKUP tab
    def on_browse_backup_folder(self) -> None:
        """Let the user pick the backup folder and remember it."""
        start_dir = self.backup_root if is_on_local_fixed_drive(self.backup_root) and os.path.isdir(self.backup_root) else ""
        folder = QFileDialog.getExistingDirectory(self, "Choose the backup folder", start_dir)
        if not folder:
            log("[FOLDER] Backup folder selection cancelled by user")
            return
        self.backup_root = os.path.normpath(folder)
        self.backup_folder_edit.setText(self.backup_root)
        self.settings["backup_dir"] = self.backup_root
        save_settings(self.settings)
        log(f"[FOLDER] Backup folder set to: {self.backup_root}")

    def open_in_explorer(self, path: str) -> None:
        """Open a file or folder in Windows Explorer / the default app, with friendly errors."""
        try:
            os.startfile(path)  # type: ignore[attr-defined]   # Windows-only API
        except FileNotFoundError:
            self.show_info("Nothing to open yet", f"This location does not exist yet:\n{path}")
        except (OSError, AttributeError) as error:
            self.show_warning("Could not open it", f"{path}\n\n{error}")

    def on_open_backup_folder(self) -> None:
        """Open the backup folder."""
        self.open_in_explorer(self.backup_root)

    def on_open_undo_folder(self) -> None:
        """Open the folder that holds the undo files."""
        self.open_in_explorer(os.path.join(self.backup_root, UNDO_SUBFOLDER_NAME))

    def on_open_logs(self) -> None:
        """Open the folder with this program's log files."""
        self.open_in_explorer(LOG_DIR)

    def on_open_error_log(self) -> None:
        """Open error-log 📃.txt."""
        self.open_in_explorer(os.path.join(get_app_dir(), ERROR_LOG_FILE_NAME))

    def on_backup_clicked(self) -> None:
        """Start the full registry backup."""
        if not self.require_admin():
            return
        backup_root = self.backup_root
        self.start_task(lambda reporter: run_full_backup(backup_root, reporter), "Full registry backup", self.on_backup_finished)

    def on_backup_finished(self, report: BackupReport) -> None:
        """Tell the user where the backup is and whether anything could not be exported."""
        problems = [result for result in report.results if result.status != "ok"]
        lines = [f"Files: {len(report.results)}  ({format_size(report.total_bytes)})", f"Folder:\n{report.folder}"]
        if problems:
            notes = "\n".join(f"  - {result.target.key_name}: {result.note}" for result in problems[:6])
            lines.append("Some areas needed the built-in exporter or could not be exported:\n" + notes)
        message = "\n\n".join(lines)
        self.set_status(f"Backup finished: {format_size(report.total_bytes)} in {len(report.results)} file(s).")
        if report.failed_count:
            self.show_warning("Backup finished with problems", message)
        else:
            self.show_info("Backup finished", message)

    # ------------------------------------------------------------------ RESTORE DEFAULTS tab
    def on_restore_analyze_clicked(self) -> None:
        """Start comparing the chosen areas with the Windows defaults."""
        areas = [key for key, checkbox in self.area_checkboxes.items() if checkbox.isChecked()]
        if not areas:
            self.show_info("Nothing to check", "Tick at least one area first.")
            return
        self.repair_items = []
        self.populate_restore_tree()
        self.update_restore_summary()
        self.start_task(lambda reporter: analyze_restore_areas(areas, reporter), "Restore analysis", self.on_restore_analysis_finished)

    def on_restore_analysis_finished(self, items: list[RepairItem]) -> None:
        """Show the proposed repairs (or a success message if everything already matches the defaults)."""
        self.repair_items = items
        self.populate_restore_tree()
        self.update_restore_summary()
        self.refresh_button_states()
        if items:
            self.set_status(f"{plural(len(items), 'repair', 'repairs')} proposed. Review the old -> new values, then apply.")
        else:
            self.set_status("Everything checked already matches the Windows defaults ✅")

    def populate_restore_tree(self) -> None:
        """Fill the restore tree from self.repair_items, grouped by area. Cautionary items start unticked."""
        tree = self.restore_tree
        tree.blockSignals(True)
        tree.setUpdatesEnabled(False)
        tree.clear()
        parents: dict[str, QTreeWidgetItem] = {}
        for index, item in enumerate(self.repair_items):
            parent = parents.get(item.area)
            if parent is None:
                parent = QTreeWidgetItem(tree, [RESTORE_AREA_TITLES.get(item.area, item.area), "", "", ""])
                parent.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsAutoTristate)
                parents[item.area] = parent
            title = f"⚠ {item.title}" if item.caution else item.title
            child = QTreeWidgetItem(parent, [title, item.location, item.old_text, item.new_text])
            child.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsUserCheckable)
            child.setCheckState(0, Qt.CheckState.Unchecked if item.caution else Qt.CheckState.Checked)
            child.setData(0, Qt.ItemDataRole.UserRole, index)
            caution_note = ("\n⚠ This could be a deliberate customisation (for example a file-manager replacement), "
                            "so it is not ticked by default." if item.caution else "")
            child.setToolTip(0, f"{item.note}{caution_note}".strip())
            child.setToolTip(1, f"{item.hive_name}\\{item.key_path}")
            child.setToolTip(2, item.old_text)      # full text of the (possibly shortened) values
            child.setToolTip(3, item.new_text)
        for area_key, parent in parents.items():
            parent.setText(0, f"{RESTORE_AREA_TITLES.get(area_key, area_key)} ({parent.childCount()})")
            parent.setExpanded(True)
        tree.setUpdatesEnabled(True)
        tree.blockSignals(False)

    def collect_checked_repairs(self) -> list[RepairItem]:
        """Return the repairs whose row is ticked."""
        selected: list[RepairItem] = []
        for top_index in range(self.restore_tree.topLevelItemCount()):
            parent = self.restore_tree.topLevelItem(top_index)
            if parent is None:
                continue
            for child_index in range(parent.childCount()):
                child = parent.child(child_index)
                if child is not None and child.checkState(0) == Qt.CheckState.Checked:
                    selected.append(self.repair_items[int(child.data(0, Qt.ItemDataRole.UserRole))])
        return selected

    def update_restore_summary(self) -> None:
        """Refresh the summary line under the restore results."""
        total = len(self.repair_items)
        if total:
            self.restore_summary_label.setText(f"{self.count_checked(self.restore_tree)} of {total} repairs selected")
        else:
            self.restore_summary_label.setText("No repairs listed.")

    def on_restore_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        """A checkbox in the restore list changed: schedule ONE refresh (see schedule_selection_refresh)."""
        self.schedule_selection_refresh()

    def get_managed_reasons(self) -> list[str]:
        """Return (and cache) the reasons this PC looks organisation-managed; empty if it does not."""
        if self.managed_reasons is None:
            self.managed_reasons = detect_managed_environment()
            log(f"[ADMIN] Managed-environment check: {self.managed_reasons or 'not managed'}")
        return self.managed_reasons

    def on_restore_apply_clicked(self) -> None:
        """Warn about managed PCs where relevant, ask for confirmation, then apply the ticked repairs."""
        if not self.require_admin():
            return
        selected = self.collect_checked_repairs()
        if not selected:
            return
        if any(item.area == AREA_POLICY_LOCKS for item in selected):
            reasons = self.get_managed_reasons()
            if reasons:
                reason_text = "\n".join(f"  - {reason}" for reason in reasons)
                warning = ("This PC appears to be managed by an organisation:\n\n" + reason_text +
                           "\n\nGroup Policy or device management may switch these locks back on at any time, and "
                           "removing them may go against your organisation's rules.\n\nRemove them anyway?")
                if not self.ask_yes_no("Managed PC detected", warning):
                    return
        lines = "\n".join(f"  {item.title}: {item.old_text}  ->  {item.new_text}" for item in selected[:12])
        more = f"\n  ... and {len(selected) - 12} more" if len(selected) > 12 else ""
        undo_folder = os.path.join(self.backup_root, UNDO_SUBFOLDER_NAME)
        question = (f"Apply {plural(len(selected), 'repair', 'repairs')}?\n\n{lines}{more}\n\n"
                    f"An undo backup of exactly what changes is saved first to:\n{undo_folder}")
        if not self.ask_yes_no("Confirm restore", question):
            return
        backup_root = self.backup_root
        self.start_task(lambda reporter: apply_repairs(selected, backup_root, reporter), "Restore defaults", self.on_restore_finished)

    def on_restore_finished(self, report: RestoreReport) -> None:
        """Show what the restore run did and refresh the list of proposed repairs."""
        applied_ids = {id(item) for item in report.applied}
        self.repair_items = [item for item in self.repair_items if id(item) not in applied_ids]
        self.populate_restore_tree()
        self.update_restore_summary()
        self.refresh_button_states()
        details = ""
        if report.skipped:
            details += "\n\nSkipped:\n" + summarize_reasons([(item.title, why) for item, why in report.skipped])
        if report.failed:
            details += "\n\nCould not be applied:\n" + summarize_reasons([(item.title, why) for item, why in report.failed])
            export_error_log([f"Restore failed for {item.title}: {why}" for item, why in report.failed])
            self.update_log_button_states()
        undo_text = f"\n\nUndo file:\n{report.undo_file}" if report.undo_file else ""
        self.set_status(f"Restore finished: {len(report.applied)} applied, {len(report.skipped)} skipped, {len(report.failed)} failed.")
        # The old "sign out and back in" hint for shell folders is now part of the restart advice (its reason says so).
        self.show_finished_box("Restore finished", f"Applied: {len(report.applied)}\nSkipped: {len(report.skipped)}\n"
                                                   f"Failed: {len(report.failed)}{details}{undo_text}", assess_restore_restart(report))

    # ------------------------------------------------------------------ IMPORT tab
    def add_import_files(self, paths: list[str]) -> None:
        """Add .reg files to the import list (duplicates and non-.reg files are ignored)."""
        known = {os.path.normcase(path) for path in self.import_paths}
        for path in paths:
            normalized = os.path.normpath(path)
            if not normalized.lower().endswith(".reg") or os.path.normcase(normalized) in known:
                continue
            self.import_paths.append(normalized)
            known.add(os.path.normcase(normalized))
        self.import_analyses = {}      # the list changed, so earlier previews no longer apply
        self.refresh_import_list()
        self.refresh_button_states()

    def refresh_import_list(self) -> None:
        """Rebuild the file list with a status text for each file."""
        self.import_list.blockSignals(True)
        self.import_list.clear()
        for path in self.import_paths:
            analysis = self.import_analyses.get(path)
            if analysis is None:
                status = "not analyzed yet"
            elif analysis.error:
                status = "⚠ problem with this file"
            elif analysis.blocked_reasons:
                status = "⛔ blocked (deletes protected keys)"
            elif analysis.detailed:
                status = f"ready: {analysis.new_values} new, {analysis.changed_values} changed value(s)"
            else:
                status = "ready (large file)"
            item = QListWidgetItem(f"{os.path.basename(path)}   -   {status}")
            item.setData(Qt.ItemDataRole.UserRole, path)
            item.setToolTip(path)
            self.import_list.addItem(item)
        self.import_list.blockSignals(False)
        self.show_import_details()

    def show_import_details(self) -> None:
        """Show the preview text for the selected file(s), or for all files if none is selected."""
        selected_paths = [str(item.data(Qt.ItemDataRole.UserRole)) for item in self.import_list.selectedItems()]
        paths = selected_paths or self.import_paths
        blocks = [format_import_analysis(self.import_analyses[path]) for path in paths if path in self.import_analyses]
        self.import_details.setPlainText(("\n\n" + "-" * 60 + "\n\n").join(blocks))

    def on_import_add_clicked(self) -> None:
        """Choose .reg files with a file dialog."""
        files, _ = QFileDialog.getOpenFileNames(self, "Select .reg files", "", "Registry files (*.reg);;All files (*)")
        if files:
            self.add_import_files(files)

    def on_import_remove_clicked(self) -> None:
        """Remove the selected files from the list."""
        remove = {str(item.data(Qt.ItemDataRole.UserRole)) for item in self.import_list.selectedItems()}
        self.import_paths = [path for path in self.import_paths if path not in remove]
        self.import_analyses = {path: analysis for path, analysis in self.import_analyses.items() if path not in remove}
        self.refresh_import_list()
        self.refresh_button_states()

    def on_import_clear_clicked(self) -> None:
        """Empty the file list."""
        self.import_paths = []
        self.import_analyses = {}
        self.refresh_import_list()
        self.refresh_button_states()

    def on_import_preview_clicked(self) -> None:
        """Analyze every listed file (read-only) and show what merging would do."""
        paths = list(self.import_paths)

        def task(reporter: ProgressReporter) -> dict[str, ImportAnalysis]:
            """Analyze every listed .reg file (runs in the background thread)."""
            results: dict[str, ImportAnalysis] = {}
            for path in paths:
                reporter.raise_if_cancelled()
                reporter.status(f"Analyzing {os.path.basename(path)} ...")
                results[path] = process_reg_file(path, reporter)
            return results

        self.start_task(task, "Import preview", self.on_import_preview_finished)

    def on_import_preview_finished(self, results: dict[str, ImportAnalysis]) -> None:
        """Store the analyses and show them."""
        self.import_analyses = results
        self.refresh_import_list()
        self.refresh_button_states()
        importable = sum(1 for analysis in results.values() if not analysis.is_blocked)
        self.set_status(f"Preview finished: {importable} of {len(results)} file(s) can be merged.")

    def on_import_merge_clicked(self) -> None:
        """Confirm (with extra warnings for delete instructions), then merge the previewed files."""
        if not self.require_admin():
            return
        files = [path for path in self.import_paths if path in self.import_analyses and not self.import_analyses[path].is_blocked]
        if not files:
            self.show_info("Nothing to merge", "Press Preview first; only files that passed the preview can be merged.")
            return
        lines = []
        for path in files:
            analysis = self.import_analyses[path]
            lines.append(f"  {os.path.basename(path)}: {analysis.new_values} new, {analysis.changed_values} changed value(s), "
                         f"{analysis.value_deletions + analysis.key_deletions} deletion(s)")
        warning = ""
        if any(self.import_analyses[path].has_delete_lines for path in files):
            warning = "\n\n⚠ At least one file contains explicit delete instructions. Only continue if you trust it."
        undo_folder = os.path.join(self.backup_root, UNDO_SUBFOLDER_NAME)
        question = (f"Merge {plural(len(files), 'file', 'files')} into the registry?\n\n" + "\n".join(lines) + warning +
                    f"\n\nFor each file an undo file of exactly what changes is saved first to:\n{undo_folder}")
        if not self.ask_yes_no("Confirm merge", question):
            return
        backup_root = self.backup_root

        def task(reporter: ProgressReporter) -> list[ImportResult]:
            """Merge every listed .reg file into the registry (runs in the background thread)."""
            results: list[ImportResult] = []
            for path in files:
                try:
                    reporter.raise_if_cancelled()
                    results.append(apply_reg_import(path, backup_root, reporter))
                except OperationCancelled:
                    results.append(ImportResult(path, False, "Cancelled before it was merged.", None))
                    break
                except RegistryOperationError as error:
                    results.append(ImportResult(path, False, str(error), None))   # this file stopped safely; try the next
            return results

        self.start_task(task, "Import merge", self.on_import_finished)

    def on_import_finished(self, results: list[ImportResult]) -> None:
        """Show which files were merged and where their undo files are."""
        self.import_analyses = {}      # the registry changed, so old previews are out of date
        self.refresh_import_list()
        self.refresh_button_states()
        succeeded = [result for result in results if result.succeeded]
        lines = []
        for result in results:
            mark = "✅" if result.succeeded else "❌"
            lines.append(f"{mark} {os.path.basename(result.path)}: {result.message}")
            if result.undo_file:
                lines.append(f"     undo file: {result.undo_file}")
        failed = [result for result in results if not result.succeeded]
        if failed:
            export_error_log([f"Import of {os.path.basename(r.path)} failed: {r.message}" for r in failed])
            self.update_log_button_states()
        self.set_status(f"Merge finished: {len(succeeded)} of {len(results)} file(s) merged.")
        text = "\n".join(lines)
        advice = assess_import_restart(results)
        if failed:
            self.show_finished_box("Merge finished with problems", text, advice, warning=True)
        else:
            self.show_finished_box("Merge finished", text, advice)

    # ------------------------------------------------------------------ drag & drop and closing
    def dragEnterEvent(self, event: QDragEnterEvent | None) -> None:
        """Accept a drag only if it carries local .reg files (and no task is running)."""
        if event is None:
            return
        mime = event.mimeData()
        if not self.busy and mime is not None and mime.hasUrls() and any(
                url.toLocalFile().lower().endswith(".reg") for url in mime.urls()):
            event.acceptProposedAction()
            return
        event.ignore()

    def dragMoveEvent(self, event: QDragMoveEvent | None) -> None:
        """Keep accepting the drag while it moves over the window."""
        if event is None:
            return
        mime = event.mimeData()
        if not self.busy and mime is not None and mime.hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent | None) -> None:
        """Add dropped .reg files to the import list and switch to the Import tab."""
        if event is None:
            return
        mime = event.mimeData()
        if self.busy or mime is None or not mime.hasUrls():
            event.ignore()
            return
        dropped = [url.toLocalFile() for url in mime.urls() if url.toLocalFile().lower().endswith(".reg")]
        if not dropped:
            event.ignore()
            return
        log(f"[FILES] Files dropped onto the window: {dropped}")
        self.add_import_files(dropped)
        self.tabs.setCurrentWidget(self.import_page)
        self.set_status(f"{plural(len(dropped), 'file', 'files')} added via drag & drop 🖱️ - press Preview.")
        event.acceptProposedAction()

    def closeEvent(self, event: QCloseEvent | None) -> None:
        """Never close in the middle of applying registry changes; otherwise stop any running task first."""
        if event is None:
            return
        worker = self.worker
        if worker is not None and worker.isRunning():
            if self.critical_stage:
                self.show_info("Please wait", "Registry changes are being applied right now. Closing now could leave them "
                                              "half-done - the window can be closed as soon as this step has finished.")
                event.ignore()
                return
            worker.cancel()
            worker.wait(10000)
        event.accept()
        log("[APP] Application closed")


# =============================================================================
# PROGRAM ENTRY POINT
# =============================================================================

def main() -> int:
    """
    Start the application: check the environment, offer to elevate, then show the window.

    Returns:
        int: Process exit code.
    """
    log(f"[APP] Starting {APP_NAME} {APP_VERSION}...")
    app = QApplication(sys.argv)
    app.setFont(QFont(UI_FONT_FAMILY, UI_FONT_POINT_SIZE))
    app.setStyleSheet(STYLESHEET)

    if os.name != "nt":
        QMessageBox.critical(None, APP_NAME, "This tool only works on Windows.")
        return 1
    if is_32bit_python_on_64bit_windows():
        QMessageBox.critical(
            None, APP_NAME,
            "This program is running in 32-bit Python on 64-bit Windows.\n\n"
            "Windows would hide some files from a 32-bit program, which could make working files look missing. "
            "Please install and use 64-bit Python.")
        return 1

    is_admin = is_running_as_admin()
    if not is_admin:
        answer = QMessageBox.question(
            None, APP_NAME,
            "Changing the registry needs administrator rights.\n\nRestart the program as administrator now?\n"
            "(Choose 'No' to continue in limited mode: analyzing and previewing only.)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.Yes)
        if answer == QMessageBox.StandardButton.Yes and relaunch_as_admin():
            return 0    # the elevated copy takes over

    window = RegistryCleanerWindow(is_admin)
    window.show()
    log("[APP] Application running, main window displayed")
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
