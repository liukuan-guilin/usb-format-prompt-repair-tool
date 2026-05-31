[CmdletBinding()]
param(
    [string]$DriveLetter = "",
    [string]$OutputRoot,
    [switch]$ListOnly,
    [switch]$NoPause,
    [switch]$SkipChkdsk,
    [switch]$NoQuarantine
)

$ErrorActionPreference = "Stop"

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "==== $Text ====" -ForegroundColor Cyan
}

function Wait-ForExit {
    if (-not $NoPause) {
        Write-Host ""
        Read-Host "Press Enter to exit" | Out-Null
    }
}

function Format-Bytes {
    param([UInt64]$Bytes)
    $units = @("B", "KB", "MB", "GB", "TB")
    $value = [double]$Bytes
    $idx = 0
    while ($value -ge 1024 -and $idx -lt ($units.Count - 1)) {
        $value /= 1024
        $idx++
    }
    "{0:N2} {1}" -f $value, $units[$idx]
}

function Confirm-Yes {
    param(
        [string]$Prompt,
        [bool]$DefaultYes = $true
    )

    $suffix = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
    $answer = Read-Host "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $DefaultYes
    }

    return $answer -match "^(y|yes|1)$"
}

function Get-UsbVolumes {
    $result = @()
    $volumes = Get-Volume | Where-Object { $_.DriveLetter }
    foreach ($volume in $volumes) {
        try {
            $partition = Get-Partition -DriveLetter $volume.DriveLetter -ErrorAction Stop
            $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction Stop
            if ($disk.BusType -eq "USB" -or $volume.DriveType -eq "Removable" -or $disk.FriendlyName -match "USB|Flash|Removable|UFD") {
                $result += [pscustomobject]@{
                    DriveLetter       = $volume.DriveLetter
                    Label             = $volume.FileSystemLabel
                    FileSystem        = $volume.FileSystem
                    Size              = $volume.Size
                    Free              = $volume.SizeRemaining
                    OperationalStatus = ($volume.OperationalStatus -join ",")
                    HealthStatus      = $volume.HealthStatus
                    DiskNumber        = $disk.Number
                    DiskName          = $disk.FriendlyName
                    BusType           = $disk.BusType
                }
            }
        }
        catch {
        }
    }
    $result | Sort-Object DriveLetter
}

function Export-Listing {
    param(
        [string]$RootPath,
        [string]$Path
    )

    Get-ChildItem -LiteralPath $RootPath -Force -Recurse -ErrorAction SilentlyContinue |
        Select-Object FullName, Attributes, Length, LastWriteTime |
        Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

function Test-ExcludedPath {
    param(
        [string]$FullName,
        [string[]]$ExcludedRoots
    )

    foreach ($root in $ExcludedRoots) {
        if ($FullName.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or
            $FullName.StartsWith($root + "\", [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Get-SuspiciousFiles {
    param([string]$RootPath)

    $extensions = @(".lnk", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".cmd", ".bat", ".pif", ".scr", ".com", ".exe")
    Get-ChildItem -LiteralPath $RootPath -Force -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -ieq "autorun.inf" -or
            $extensions -contains $_.Extension.ToLowerInvariant()
        }
}

function Get-ShortcutDetails {
    param([object[]]$Files)

    $lnks = @($Files | Where-Object { $_.Extension -ieq ".lnk" })
    if ($lnks.Count -eq 0) {
        return @()
    }

    $shell = New-Object -ComObject WScript.Shell
    foreach ($lnk in $lnks) {
        try {
            $shortcut = $shell.CreateShortcut($lnk.FullName)
            [pscustomobject]@{
                FullName          = $lnk.FullName
                TargetPath        = $shortcut.TargetPath
                Arguments         = $shortcut.Arguments
                WorkingDirectory  = $shortcut.WorkingDirectory
                IconLocation      = $shortcut.IconLocation
                LastWriteTime     = $lnk.LastWriteTime
            }
        }
        catch {
            [pscustomobject]@{
                FullName          = $lnk.FullName
                TargetPath        = "<read failed>"
                Arguments         = $_.Exception.Message
                WorkingDirectory  = ""
                IconLocation      = ""
                LastWriteTime     = $lnk.LastWriteTime
            }
        }
    }
}

function Restore-UserFileAttributes {
    param(
        [string]$RootPath,
        [string]$CsvPath
    )

    $excludedRoots = @(
        (Join-Path $RootPath "System Volume Information"),
        (Join-Path $RootPath "System_Volume_Information"),
        (Join-Path $RootPath "LOST.DIR")
    )

    $changed = New-Object System.Collections.Generic.List[object]
    $items = Get-ChildItem -LiteralPath $RootPath -Force -Recurse -ErrorAction SilentlyContinue
    foreach ($item in $items) {
        if (Test-ExcludedPath -FullName $item.FullName -ExcludedRoots $excludedRoots) {
            continue
        }

        $old = $item.Attributes
        $new = $old -band (-bnot [IO.FileAttributes]::Hidden) -band (-bnot [IO.FileAttributes]::System) -band (-bnot [IO.FileAttributes]::ReadOnly)
        if ($new -eq $old) {
            continue
        }

        try {
            $item.Attributes = $new
            $changed.Add([pscustomobject]@{
                FullName      = $item.FullName
                Type          = if ($item.PSIsContainer) { "Directory" } else { "File" }
                OldAttributes = $old.ToString()
                NewAttributes = $new.ToString()
                Status        = "Changed"
            })
        }
        catch {
            $changed.Add([pscustomobject]@{
                FullName      = $item.FullName
                Type          = if ($item.PSIsContainer) { "Directory" } else { "File" }
                OldAttributes = $old.ToString()
                NewAttributes = ""
                Status        = "Failed: $($_.Exception.Message)"
            })
        }
    }

    $changed | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
    return $changed
}

function Move-SuspiciousRootFiles {
    param(
        [object[]]$SuspiciousFiles,
        [string]$RootPath,
        [string]$QuarantinePath
    )

    $rootPrefix = $RootPath.TrimEnd("\") + "\"
    $rootSuspicious = @($SuspiciousFiles | Where-Object {
        $_.DirectoryName.TrimEnd("\").Equals($RootPath.TrimEnd("\"), [StringComparison]::OrdinalIgnoreCase)
    })

    if ($rootSuspicious.Count -eq 0) {
        return @()
    }

    New-Item -ItemType Directory -Force -Path $QuarantinePath | Out-Null
    $moved = New-Object System.Collections.Generic.List[object]
    foreach ($item in $rootSuspicious) {
        $relative = $item.FullName.Substring($rootPrefix.Length)
        $dest = Join-Path $QuarantinePath $relative
        $idx = 1
        while (Test-Path -LiteralPath $dest) {
            $dest = Join-Path $QuarantinePath ("{0}_{1}{2}" -f $item.BaseName, $idx, $item.Extension)
            $idx++
        }
        try {
            Move-Item -LiteralPath $item.FullName -Destination $dest -Force
            $moved.Add([pscustomobject]@{
                OriginalPath = $item.FullName
                QuarantinePath = $dest
                Status = "Moved"
            })
        }
        catch {
            $moved.Add([pscustomobject]@{
                OriginalPath = $item.FullName
                QuarantinePath = $dest
                Status = "Failed: $($_.Exception.Message)"
            })
        }
    }
    return $moved
}

function Get-DirtyStatus {
    param([string]$DriveLetter)

    $output = cmd /c "fsutil dirty query $DriveLetter`: 2>&1"
    [pscustomobject]@{
        Raw = ($output -join "`n")
        IsDirty = (($output -join "`n") -match "is Dirty")
    }
}

function Get-DefenderStatusSafe {
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        [pscustomobject]@{
            Available = $true
            AMServiceEnabled = $status.AMServiceEnabled
            AntivirusEnabled = $status.AntivirusEnabled
            RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
            AntivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated
        }
    }
    catch {
        [pscustomobject]@{
            Available = $false
            Error = $_.Exception.Message
        }
    }
}

if (-not $OutputRoot) {
    $OutputRoot = Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) "repair-output"
}

Write-Section "USB hidden file / shortcut virus recovery"
Write-Host "Use this for drives that look empty, show folders as shortcuts, or have many hidden/system files." -ForegroundColor Yellow
Write-Host "The tool writes reports first, restores user file visibility, and can clear the filesystem dirty flag with chkdsk /f." -ForegroundColor Yellow
Write-Host "It does not format the drive and does not delete user files." -ForegroundColor Yellow

$usbVolumes = Get-UsbVolumes
if (-not $usbVolumes) {
    Write-Host "No USB/removable volumes were detected." -ForegroundColor Red
    Wait-ForExit
    exit 1
}

Write-Section "Detected USB/removable volumes"
$usbVolumes |
    Select-Object DriveLetter, Label, FileSystem,
        @{ Name = "Size"; Expression = { Format-Bytes $_.Size } },
        @{ Name = "Free"; Expression = { Format-Bytes $_.Free } },
        OperationalStatus, HealthStatus, DiskNumber, DiskName, BusType |
    Format-Table -AutoSize

if ($ListOnly) {
    Wait-ForExit
    exit 0
}

if ([string]::IsNullOrWhiteSpace($DriveLetter)) {
    $DriveLetter = Read-Host "Enter the drive letter to process"
}

$DriveLetter = $DriveLetter.Trim().TrimEnd(":").ToUpperInvariant()
if ($DriveLetter.Length -ne 1) {
    throw "Invalid drive letter."
}

$target = $usbVolumes | Where-Object { $_.DriveLetter -eq $DriveLetter } | Select-Object -First 1
if (-not $target) {
    throw "The selected drive is not in the detected USB/removable list."
}

$confirmLetter = Read-Host ("Type the drive letter {0} again to confirm" -f $DriveLetter)
if ($confirmLetter.Trim().TrimEnd(":").ToUpperInvariant() -ne $DriveLetter) {
    throw "Second confirmation failed."
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputDir = Join-Path $OutputRoot ("hidden-files-{0}-{1}" -f $DriveLetter, $timestamp)
New-Item -ItemType Directory -Force $outputDir | Out-Null

Start-Transcript -Path (Join-Path $outputDir "recover.log") -Force | Out-Null
try {
    $rootPath = "{0}:\" -f $DriveLetter

    Write-Section "Target volume"
    $target | Select-Object DriveLetter, Label, FileSystem,
        @{ Name = "Size"; Expression = { Format-Bytes $_.Size } },
        @{ Name = "Free"; Expression = { Format-Bytes $_.Free } },
        OperationalStatus, HealthStatus, DiskNumber, DiskName, BusType |
        Format-List

    Write-Section "Before scan"
    Export-Listing -RootPath $rootPath -Path (Join-Path $outputDir "full-listing-before.csv")

    $hiddenOrSystem = @(Get-ChildItem -LiteralPath $rootPath -Force -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Attributes.ToString().Contains("Hidden") -or
            $_.Attributes.ToString().Contains("System")
        })

    $hiddenOrSystem |
        Select-Object FullName, Attributes, Length, LastWriteTime |
        Export-Csv -LiteralPath (Join-Path $outputDir "hidden-or-system-before.csv") -NoTypeInformation -Encoding UTF8

    $suspicious = @(Get-SuspiciousFiles -RootPath $rootPath)
    $suspicious |
        Select-Object FullName, Attributes, Length, LastWriteTime |
        Export-Csv -LiteralPath (Join-Path $outputDir "suspicious-files-before.csv") -NoTypeInformation -Encoding UTF8

    Get-ShortcutDetails -Files $suspicious |
        Export-Csv -LiteralPath (Join-Path $outputDir "shortcut-targets-before.csv") -NoTypeInformation -Encoding UTF8

    Write-Host ("Hidden/system items found: {0}" -f $hiddenOrSystem.Count) -ForegroundColor Yellow
    Write-Host ("Suspicious files found: {0}" -f $suspicious.Count) -ForegroundColor Yellow

    Write-Section "Defender status"
    $defenderStatus = Get-DefenderStatusSafe
    $defenderStatus | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $outputDir "defender-status.json") -Encoding UTF8
    if ($defenderStatus.Available -and $defenderStatus.AntivirusEnabled) {
        Write-Host "Windows Defender appears enabled. This script does not start a scan automatically; scan the USB drive after recovery." -ForegroundColor Green
    }
    else {
        Write-Host "Windows Defender is unavailable or disabled. Use another antivirus scan before using this USB drive on other machines." -ForegroundColor Yellow
    }

    Write-Section "Restore user file attributes"
    $changed = Restore-UserFileAttributes -RootPath $rootPath -CsvPath (Join-Path $outputDir "attributes-restored.csv")
    Write-Host ("Changed attributes on {0} item(s)." -f $changed.Count) -ForegroundColor Green

    if (-not $NoQuarantine -and $suspicious.Count -gt 0 -and (Confirm-Yes -Prompt "Move suspicious root-level shortcut/script files into report quarantine?" -DefaultYes $false)) {
        $moved = Move-SuspiciousRootFiles -SuspiciousFiles $suspicious -RootPath $rootPath -QuarantinePath (Join-Path $outputDir "quarantine")
        $moved | Export-Csv -LiteralPath (Join-Path $outputDir "quarantine-moves.csv") -NoTypeInformation -Encoding UTF8
        Write-Host ("Quarantine move records: {0}" -f @($moved).Count) -ForegroundColor Green
    }

    Write-Section "Filesystem dirty status"
    $dirtyBeforeFix = Get-DirtyStatus -DriveLetter $DriveLetter
    $dirtyBeforeFix.Raw | Set-Content -LiteralPath (Join-Path $outputDir "dirty-before.txt") -Encoding UTF8
    Write-Host $dirtyBeforeFix.Raw

    $chkdskRan = $false
    if (-not $SkipChkdsk -and $dirtyBeforeFix.IsDirty) {
        if (Confirm-Yes -Prompt "The volume is dirty. Run chkdsk /f now? This can take a long time." -DefaultYes $true) {
            Write-Host "Running chkdsk /f. Do not unplug the drive." -ForegroundColor Yellow
            cmd /c "chkdsk $DriveLetter`: /f" | Tee-Object -FilePath (Join-Path $outputDir "chkdsk-f.txt")
            $chkdskRan = $true
        }
    }

    $dirtyAfterFix = Get-DirtyStatus -DriveLetter $DriveLetter
    $dirtyAfterFix.Raw | Set-Content -LiteralPath (Join-Path $outputDir "dirty-after.txt") -Encoding UTF8

    Write-Section "After scan"
    Export-Listing -RootPath $rootPath -Path (Join-Path $outputDir "full-listing-after.csv")

    $remainingHiddenOrSystem = @(Get-ChildItem -LiteralPath $rootPath -Force -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Attributes.ToString().Contains("Hidden") -or
            $_.Attributes.ToString().Contains("System")
        })
    $remainingHiddenOrSystem |
        Select-Object FullName, Attributes, Length, LastWriteTime |
        Export-Csv -LiteralPath (Join-Path $outputDir "hidden-or-system-after.csv") -NoTypeInformation -Encoding UTF8

    $summary = [ordered]@{
        repaired_at = (Get-Date).ToString("s")
        drive = "$DriveLetter`:"
        output_dir = $outputDir
        hidden_or_system_before = $hiddenOrSystem.Count
        changed_attribute_count = $changed.Count
        suspicious_file_count = $suspicious.Count
        defender_available = [bool]$defenderStatus.Available
        defender_antivirus_enabled = [bool]($defenderStatus.PSObject.Properties.Name -contains "AntivirusEnabled" -and $defenderStatus.AntivirusEnabled)
        dirty_before = [bool]$dirtyBeforeFix.IsDirty
        chkdsk_ran = [bool]$chkdskRan
        dirty_after = [bool]$dirtyAfterFix.IsDirty
        remaining_hidden_or_system_count = $remainingHiddenOrSystem.Count
    }
    $summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $outputDir "repair-summary.json") -Encoding UTF8

    Write-Section "Completed"
    Write-Host ("Reports saved to: {0}" -f $outputDir) -ForegroundColor Green
    Write-Host ("Dirty after repair: {0}" -f $dirtyAfterFix.IsDirty) -ForegroundColor Green
    Write-Host "If specific files are still missing, stop writing to the USB drive and use deeper file recovery on a copy/image." -ForegroundColor Yellow
}
finally {
    Stop-Transcript | Out-Null
    Wait-ForExit
}
