cls
$startTime = Get-Date

Add-Type -AssemblyName System.IO.Compression.FileSystem
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Logo {
    $color = "Magenta"

    Write-Host ""
    Write-Host ""
    Write-Host "       :::        ::::::::::       ::::::::       :::::::::::   :::::::::::        ::::::::       :::    :::       ::::::::::       ::::::::       :::    :::" -ForegroundColo $color -NoNewline
    Write-Host ""
    Write-Host "     :+:        :+:             :+:    :+:          :+:           :+:           :+:    :+:      :+:    :+:       :+:             :+:    :+:      :+:   :+:" -ForegroundColo $color -NoNewline
    Write-Host ""
    Write-Host "    +:+        +:+             +:+                 +:+           +:+           +:+             +:+    +:+       +:+             +:+             +:+  +:+:" -ForegroundColo $color -NoNewline
    Write-Host ""
    Write-Host "   +#+        +#++:++#        :#:                 +#+           +#+           +#+             +#++:++#++       +#++:++#        +#+             +#++:++" -ForegroundColo $color -NoNewline 
    Write-Host ""
    Write-Host "  +#+        +#+             +#+   +#+#          +#+           +#+           +#+             +#+    +#+       +#+             +#+             +#+  +#+" -ForegroundColo $color -NoNewline 
    Write-Host ""
    Write-Host " #+#        #+#             #+#    #+#          #+#           #+#           #+#    #+#      #+#    #+#       #+#             #+#    #+#      #+#   #+#" -ForegroundColo $color -NoNewline 
    Write-Host ""
    Write-Host "########## ##########       ########       ###########       ###            ########       ###    ###       ##########       ########       ###    ###" -ForegroundColo $color -NoNewline
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
}

Write-Logo

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Права администратора не обнаружены" -ForegroundColor Yellow
    exit 1
}

$obsProcess = Get-Process -Name "obs64", "obs32", "obs", "ayugram", "telegram", "nvcontainer", "gamebar", "steam", "discord", "lively", "chrome", "opera", "msedge" -ErrorAction SilentlyContinue
if ($obsProcess) { $obsProcess | Stop-Process -Force }


$data = Get-Date -Format "dd.MM.yyyy HH:mm"

$utilsPath = "C:\ss"
if (-not (Test-Path $utilsPath)) { New-Item -ItemType Directory -Path $utilsPath -Force | Out-Null }
Set-Location $utilsPath

Start-Process powershell -ArgumentList "-Command", "Invoke-Expression (Invoke-RestMethod 'https://github.com/Ryodzaki/scripts/raw/refs/heads/main/services.ps1')"
Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/doomsday finder.exe" -OutFile "6.exe"
Start-Process powershell -ArgumentList '-NoExit', '-Command', './6.exe; Remove-Item -Path "6.exe" -Force'


#InjGen
Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/jmd.exe" -OutFile "1.exe"
Invoke-Expression ".\1.exe"
Write-Host ""
#END

#DoomsdayCheck
Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/dd check.exe" -OutFile "2.exe"
Invoke-Expression ".\2.exe"
if (Test-Path "2.exe") { Remove-Item -Path "2.exe" -Force }
Write-Host ""
#END

Write-Host "Java args:"
Get-CimInstance Win32_Process | Where-Object {$_.Name -like '*java*'} | ForEach-Object { $splitText = (([string]($_.CommandLine) -split '-Djava.library.path=')[1] -split '"')[0]; Write-Host $splitText }
Write-Host ""



#Connection info
Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/NETSTAT.EXE" -OutFile "netstat.exe"
$connections = @(netstat.exe -an | Where-Object { $_ -match "TCP.*2556.*ESTABLISHED" } | ForEach-Object { ($_ -split '\s+')[3] | Select-Object -First 1 })
Write-Host "Connections: `n" ($connections -join "`n") -ForegroundColor Yellow
Write-Host ""
if (Test-Path "netstat.exe") { Remove-Item -Path "netstat.exe" -Force }
#END


#Get DNS Data
Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/ipconfig.EXE" -OutFile "ipconfig.exe"
$dnsData = @(ipconfig.exe /all | Select-String "DNS" | ForEach-Object { if ($_.ToString() -match "^([^:]+?)\s*:\s*(.*)$" -and $matches[2].Trim()) { $matches[2].Trim() } } | Where-Object { $_ })
Write-Host "DNS Data: `n" ($dnsData -join "`n") -ForegroundColor Yellow
Write-Host ""
if (Test-Path "ipconfig.exe") { Remove-Item -Path "ipconfig.exe" -Force }
#END


#Check USN
$usn_deletes = @(try { Get-WinEvent -FilterXml "<QueryList><Query Id='0' Path='Microsoft-Windows-Ntfs/Operational'><Select Path='Microsoft-Windows-Ntfs/Operational'>*[System[EventID=501]] and *[EventData[Data[@Name='ProcessName'] and (Data='fsutil.exe')]]</Select></Query></QueryList>" -ErrorAction Stop | ForEach-Object { $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") } } catch { @() })
if($usn_deletes) {
    Write-Host "USN Deleted: `n" ($usn_deletes -join "`n") -ForegroundColor Yellow
}
Write-Host ""

#Check .dlls
$javawDlls = @(Get-Process javaw -ErrorAction SilentlyContinue | ForEach-Object { $_.Modules } | Where-Object { $_.ModuleName -like "*.dll" -and -not $_.FileVersionInfo.FileDescription -and $_.FileName -notmatch "\\(natives|Temp)\\" } | Where-Object { (Get-AuthenticodeSignature $_.FileName).Status -ne 'Valid' } | Select-Object -ExpandProperty FileName)
if ($javawDlls) { 
    Write-Host "Suspicious dlls detected: `n" ($javawDlls -join "`n") -ForegroundColor Yellow
}
Write-Host ""

#VM Check
Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/vma.exe" -OutFile "3.exe"
Write-Host "VM check:"
Invoke-Expression ".\3.exe"
Write-Host ""
#END


#Mods check
Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/ehp.exe" -OutFile "8.exe"
Write-Host "Mods check:"
Invoke-Expression ".\8.exe javaw.exe /mods/ /addons"
Write-Host ""
#END


#BAM
$bamData = @()
Write-Host "Bam data:"
function Get-Signature {
    param ([string[]]$FilePath)

    $Existence = Test-Path -PathType "Leaf" -Path $FilePath
    $Authenticode = (Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue).Status

    if ($Existence) {
        if ($Authenticode -eq "Valid") { return "Valid Signature" }
        elseif ($Authenticode -eq "NotSigned") { return "Invalid Signature (NotSigned)" }
        else { return "Invalid Signature" }
    } else {
        return "File Was Not Found"
    }
}


$Users = foreach($ii in ("bam", "bam\State")) {
    Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ii)\UserSettings\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName
}




$rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")



$Bam = Foreach ($Sid in $Users) {
    foreach($rp in $rpath) {
        $BamItems = Get-Item -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property  -ErrorAction SilentlyContinue

        ForEach ($Item in $BamItems) {
            $Key = Get-ItemProperty -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Item -ErrorAction SilentlyContinue

            If($key.length -eq 24) {
                $Hex = [System.BitConverter]::ToString($key[7..0]) -replace "-",""
                $TimeUTC = Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))) -Format "dd.MM.yy HH:mm"

                if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}') {
                    $path = Join-Path -Path "C:" -ChildPath ($item).Remove(1,23)
                    $sig = Get-Signature -FilePath $path
                    $app = Split-path -leaf ($item).TrimStart()
                } else {
                    $path = ""
                    $sig = "N/A"
                    $app = $item
                }

                [PSCustomObject]@{
                    'Time' = $TimeUTC
                    'Signature' = $sig
                    'Path' = $path
                    'SortDate' = [DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))
                }
            }
        }
    }
}

$FilteredBam = $Bam | Where-Object {
    $_.Signature -eq "Invalid Signature (NotSigned)" -or
    $_.Signature -eq "File Was Not Found"
} | Sort-Object SortDate -Descending

if ($FilteredBam) {
    foreach($i in $FilteredBam) {
        if($i.Signature.Contains("File Was Not Found")) {
            Write-Host ("File Was Not Found | " + $i.Time + " | " + $i.Path + " ") -ForegroundColor Yellow 
        }
        if($i.Signature.Contains("Invalid Signature")) {
            Write-Host ("Invalid Signature | " + $i.Time + " | " + $i.Path + " ") -ForegroundColor Red
        }
    }
}
Write-Host ""
#END

#Search baritone folders
$baritoneDirs = @()

Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/ntfspasrser.exe" -OutFile "1.exe"
Write-Host "Check for baritone folders:"

$driveLetters = @(Get-Volume | Where-Object {$_.DriveLetter} | ForEach-Object {$_.DriveLetter})
$commandLine = @()

foreach($i in $driveLetters) {
    $commandLine += ./1.exe search $i -f cache --dir-only 
}

if($commandLine) {
    foreach($i in $commandLine -split "\n") {
        if($i.Contains("Path") -and $i.Contains("funtime")) { 
            $baritoneDirs += ($i -split " : ")[1].trim()
        }
    }
}

    
if($baritoneDirs) { 
    Write-Host ($baritoneDirs -join "`n") -ForegroundColor Yellow 
}
Write-Host ""
#END



#Check deleted files
Write-Host "Search for deleted files:"

$driveLetters = @(Get-Volume | Where-Object {$_.DriveLetter} | ForEach-Object {$_.DriveLetter})

$commandLine = @()

foreach($i in $driveLetters) {
    $commandLine += ./1.exe read $i -f '*funtime*' --dir-only
}

$needNext = 0
$lastTime = ''

if($commandLine) {
    foreach($i in $commandLine -split '\n') {
        if($needNext -eq 1) {
            Write-Host 'Deleted baritone in ' $lastTime ' : ' ($i -split ' : ')[1].trim() -ForegroundColor Magenta
            $needNext = 0
        }

        if($i.Contains('FILE_DELETE')) { 
            $needNext = 1
        }
        if($i.Contains('Timestamp')) {
            $lastTime = ($i -split ' : ')[1].trim()
        }
    }
}


$commandLine = @()

foreach($i in $driveLetters) {
    $commandLine += ./1.exe read $i -f '*.exe'
}

$needNext = 0
$lastTime = ''

if($commandLine) {
    foreach($i in $commandLine -split '\n') {
        if($needNext -eq 1) {
            Write-Host 'Deleted .exe in ' $lastTime ' : ' ($i -split ' : ')[1].trim() -ForegroundColor Yellow
            $needNext = 0
        }

        if($i.Contains('FILE_DELETE')) { 
            $needNext = 1
        }
        if($i.Contains('Timestamp')) {
            $lastTime = ($i -split ' : ')[1].trim()
        }
    }
}


$commandLine = @()

foreach($i in $driveLetters) {
    $commandLine += ./1.exe read $i -f '*.jar'
}

$needNext = 0
$lastTime = ''

if($commandLine) {
    foreach($i in $commandLine -split '\n') {
        if($needNext -eq 1) {
            Write-Host 'Deleted .jar in ' $lastTime ' : ' ($i -split ' : ')[1].trim() -ForegroundColor Red
            $needNext = 0
        }

        if($i.Contains('FILE_DELETE')) { 
            $needNext = 1
        }
        if($i.Contains('Timestamp')) {
            $lastTime = ($i -split ' : ')[1].trim()
        }
    }
}

if (Test-Path '1.exe') { Remove-Item -Path '1.exe' -Force }
Write-Host ""
#END



$endTime = Get-Date
$duration = $endTime - $startTime


$filePath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $filePath) { Clear-Content -Path $filePath -Force }
wevtutil clear-log "Microsoft-Windows-PowerShell/Operational"


Write-Host "Done! $($duration.TotalMinutes.ToString("F2")) min"















