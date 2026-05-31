---
name: windows-usb-drive-repair
description: Safely diagnose and repair Windows USB drives that ask to be formatted, appear RAW, show hidden files after shortcut-virus infections, or remain dirty after unsafe removal. Use data-safe checks first, avoid formatting, preserve reports, and prefer minimal repairs.
---

# Windows USB Drive Repair

Use this skill when a Windows USB drive:

- asks to be formatted before use
- appears as `RAW`
- is detected by Windows but cannot be opened
- looks empty after a shortcut-virus infection
- has real files marked `Hidden` and `System`
- has folders replaced by `.lnk` shortcuts
- remains marked dirty after unsafe removal

## Safety Rules

1. Do not format the drive.
2. Do not run destructive repair first.
3. Export listings and diagnostics before changing attributes or metadata.
4. If the drive shows hardware-failure symptoms, stop writes and image the disk first.
5. Prefer the smallest repair that explains the symptom.

## Quick Triage

Run read-only checks first:

```powershell
Get-Disk
Get-Partition
Get-Volume
cmd /c chkdsk H:
cmd /c fsutil dirty query H:
```

Interpretation:

- `RAW` plus a healthy USB disk usually means metadata damage.
- `FAT32` or `exFAT` plus many hidden/system files usually means a hidden-file or shortcut-virus case.
- `Dirty` with a readable filesystem can usually be cleared with `chkdsk /f`, after confirming the target drive.
- Repeated disconnects, broad I/O errors, or unreadable later sectors means hardware/media failure; avoid repair writes.

## Hidden-File / Shortcut-Virus Workflow

Use the repository script:

```powershell
.\Start-Fix-Hidden-Files-And-Dirty.cmd
```

It will:

1. list USB/removable drives
2. ask for the drive letter twice
3. export a full before listing
4. record hidden/system items
5. record suspicious shortcuts, scripts, executables, and shortcut targets
6. restore user file visibility while skipping normal system folders
7. check the dirty flag
8. ask before running `chkdsk /f`
9. export after listings and `repair-summary.json`

The script does not format the drive and does not delete user files. It can optionally move suspicious root-level shortcut-virus files into the report quarantine folder.

## Format-Prompt / RAW Workflow

If Windows asks to format the drive or the filesystem is `RAW`, do not run the hidden-file script as the first fix. Use the format-prompt repair flow:

1. set the disk read-only if possible
2. back up the first sectors
3. create a full image if the data matters
4. inspect partition and filesystem metadata
5. use TestDisk or equivalent diagnostics on the image
6. only write minimal MBR/partition metadata after validating the real filesystem start

## Validation

After any repair, verify:

```powershell
Get-Volume -DriveLetter H
cmd /c fsutil dirty query H:
Get-ChildItem H:\ -Force
```

Also open or copy several important files. A directory listing alone is not enough.

## Reports To Keep

Keep the generated report folder. It should include:

- full listing before repair
- full listing after repair
- suspicious file scan
- shortcut target scan
- attribute-change CSV
- dirty flag before/after
- `chkdsk /f` output if it was run
- `repair-summary.json`
