## 📌 What's New

**Initial release (2026-09-23):** Windows Registry Cleaner v1.0.0 is the first public version. It finds broken registry entries safely, backs up the whole registry, repairs a curated set of Windows defaults, and merges `.reg` files — all with the same safety model: **analyze first, undo file written and verified second, change only after that**.

### Highlights

- ✅ **Nine independent scan categories** — uninstall leftovers, shared-DLL counts, App Paths, startup entries, MUI cache, fonts, file associations, context menus, and stale network history
- ✅ **Verified undo files** — every change is preceded by an undo `.reg` file that is read back and compared entry by entry against what was meant to be written. If the check fails, **nothing changes**
- ✅ **Strict allow-list** — a hard-coded list of exactly which key patterns may be deleted per category; a bug in the scanner can't reach outside it
- ✅ **Curated restore defaults** — policy locks, critical file associations, shell folder paths. Never a blanket reset
- ✅ **Safe `.reg` merging** — preview, fingerprint-verified undo file, critical-key deletions blocked
- ✅ **Weighted restart advice** — told whether a restart actually helps (and how strongly), with a "Restart Now" countdown
- ✅ **Managed-PC warnings** — domain / Entra / Intune detection before policy-lock repairs
- ✅ **Non-blocking UI** — every operation runs in the background
- ✅ **Fully open source**

See [CHANGELOG.md](https://github.com/RaneKun/Windows-Registry-Cleaner/blob/main/CHANGELOG.md) for the complete feature list.

---

## ⚠️ Important Notes

### Antivirus Detection / VirusTotal Scan

Windows Registry Cleaner performs operations commonly associated with system-maintenance tools:

- Requests Administrator privileges (UAC)
- Reads and writes to `HKEY_LOCAL_MACHINE` and `HKEY_CURRENT_USER`
- Uses Windows tools such as `reg.exe`, `shutdown.exe`, `takeown` (indirectly, via the backup importer)
- Is distributed as a standalone PyInstaller-built executable

Because of this, some antivirus products may classify the executable as suspicious using heuristic or machine-learning based detection methods.

### VirusTotal Results

VirusTotal results will be added here for each release. As with all RaneKun tools, the majority of antivirus engines are expected to report the executable as clean, with a small number of heuristic detections related to the administrative system-maintenance functionality.

The project is completely open source. Anyone can inspect the source code, build the executable themselves, and compare it with the published release.

### Verify the Download (SHA-256)

You can independently verify that the downloaded executable matches the release published on GitHub.

Open PowerShell and run:

```powershell
Get-FileHash ".\Windows Registry Cleaner.exe" -Algorithm SHA256
```

Expected SHA-256 for v1.0.0:

```text
<TBD — will be added to the release notes once the build is published>
```

If the hash matches exactly, the file is identical to the one uploaded to this release.

### Transparency

For users who prefer to verify everything themselves:

- ✅ Full source code is available in this repository
- ✅ Build instructions are included
- ✅ The application can be compiled locally
- ✅ SHA-256 hash is provided above
- ✅ VirusTotal results are provided for transparency

If your antivirus flags the executable, please consider:

- Verifying the SHA-256 hash
- Reviewing the source code
- Building the application yourself from source
- Submitting the sample to your antivirus vendor as a potential false positive
- Opening a GitHub issue with the detection name and vendor information

---

## 📋 Requirements

- **Windows 10 or Windows 11**
- **64-bit Python 3.11+** (32-bit Python on 64-bit Windows is refused, because filesystem redirection would produce false "missing file" results)
- **Administrator rights** (required to write to `HKEY_LOCAL_MACHINE` and other protected keys)
- **~35 MB disk space** for the packaged executable

---

## 🙏 Credits

**Created by RaneKun**

Built with:

- Python 3.14
- PyQt6
- PyInstaller
- ❤️ and lots of coffee

---

## 📥 Download

### Standalone EXE

Download **Windows Registry Cleaner.exe** from the Assets section below.

> **Note:** Because this application performs administrative registry-editing operations, some antivirus products may classify it as suspicious. Please review the VirusTotal and SHA-256 verification information above if you want to independently verify the release.

### Source Code

Clone the repository or download the source archive:

https://github.com/RaneKun/Windows-Registry-Cleaner/archive/refs/heads/main.zip

### Changelog History

See:

https://github.com/RaneKun/Windows-Registry-Cleaner/blob/main/CHANGELOG.md

---

## 💬 Feedback

Found a bug or have a suggestion?

- 🐛 Report Issues  
  https://github.com/RaneKun/Windows-Registry-Cleaner/issues

- 💡 Request Features / Discussions  
  https://github.com/RaneKun/Windows-Registry-Cleaner/discussions

- ⭐ Star the repository if you find it useful

---

<p align="center">
  <sub>Made with ❤️ by RaneKun • Analyze. Review. Confirm. Undo if needed. 🧹✨</sub>
</p>