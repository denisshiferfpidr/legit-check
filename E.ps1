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

Write-Host "Java args:"
Get-CimInstance Win32_Process | Where-Object {$_.Name -like '*java*'} | ForEach-Object { $splitText = ((string -split '-Djava.library.path=')[1] -split '"')[0]; Write-Host $splitText }
Write-Host ""

#Check deleted files
Invoke-WebRequest 'https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/2.exe' -OutFile '3.exe'

$driveLetters = @(Get-Volume | Where-Object {$_.DriveLetter} | ForEach-Object {$_.DriveLetter})
$commandLine = @()

foreach($i in $driveLetters) {
    $commandLine += ./3.exe read $i -f '*.exe'
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
    $commandLine += ./3.exe read $i -f '*.jar'
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


$commandLine = @()

foreach($i in $driveLetters) {
    $commandLine += ./3.exe read $i -f '*funtime*' --dir-only
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
if (Test-Path '3.exe') { Remove-Item -Path '3.exe' -Force }
#END


Start-Process powershell -ArgumentList "-Command", "Invoke-Expression (Invoke-RestMethod 'https://github.com/Ryodzaki/scripts/raw/refs/heads/main/services.ps1')"

#$obsProcess = Get-Process -Name "obs64", "obs32", "obs", "ayugram", "telegram", "nvcontainer", "gamebar", "steam", "discord", "lively", "chrome", "opera", "msedge"
#if ($obsProcess) { $obsProcess | Stop-Process -Force }

$data = Get-Date -Format "dd.MM.yyyy HH:mm"


#InjGen
Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/1.exe" -OutFile "1.exe"
Invoke-Expression ".\1.exe"
if (Test-Path "1.exe") { Remove-Item -Path "1.exe" -Force }
#END

#Connection info
$connections = @(netstat -an | Where-Object { $_ -match "TCP.*2556.*ESTABLISHED" } | ForEach-Object { ($_ -split '\s+')[3] | Select-Object -First 1 })
Write-Host "Connections: `n" $connections -join "`n" -ForegroundColor Yellow
#END


#Get DNS Data
$dnsData = @(ipconfig /all | Select-String "DNS" | ForEach-Object { if ($_.ToString() -match "^([^:]+?)\s*:\s*(.*)$" -and $matches[2].Trim()) { $matches[2].Trim() } } | Where-Object { $_ })
Write-Host "DNS Data: `n" $dnsData -join "`n" -ForegroundColor Yellow
#END



#Check USN
$usn_deletes = @(try { Get-WinEvent -FilterXml "<QueryList><Query Id='0' Path='Microsoft-Windows-Ntfs/Operational'><Select Path='Microsoft-Windows-Ntfs/Operational'>*[System[EventID=501]] and *[EventData[Data[@Name='ProcessName'] and (Data='fsutil.exe')]]</Select></Query></QueryList>" -ErrorAction Stop | ForEach-Object { $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") } } catch { @() })
Write-Host "USN Deleted: `n" $dnsData -join "`n" -ForegroundColor Yellow
#END


#Check .dlls
$javawDlls = @(Get-Process javaw -ErrorAction SilentlyContinue | ForEach-Object { $_.Modules } | Where-Object { $_.ModuleName -like "*.dll" -and -not $_.FileVersionInfo.FileDescription -and $_.FileName -notmatch "\\(natives|Temp)\\" } | Where-Object { (Get-AuthenticodeSignature $_.FileName).Status -ne 'Valid' } | Select-Object -ExpandProperty FileName)
if ($javawDlls) { 
    Write-Host "Suspicious dlls detected: `n" $javawDlls -join "`n" -ForegroundColor Yellow
}




Write-Host "Stage 3"



#Search baritoen folders
$baritoneDirs = @()

Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/2.exe" -OutFile "1.exe"

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

    #Zone.ID
$dooms = @()
$zoneidExes = @()


$commandLine = @()


foreach($i in $driveLetters) {
    $commandLine += ./1.exe search $i -f "*.exe" --file-only
}

if($commandLine) {
    foreach($i in $commandLine -split "\n") {
        if($i.Contains("Path")) { 
            $cleanPath = ($i -split " : ")[1].trim()
            if(Test-Path -LiteralPath $cleanPath) {
                $content = (Get-Content -LiteralPath $cleanPath -Stream Zone.Identifier -ErrorAction SilentlyContinue) -split "`n"
              
                if($content) { 
                    foreach($i in $content) {
                        if($i.Contains("HostUrl=")) {
                            $res = $cleanPath + "`n" + $i.Replace("HostUrl=", "").Trim()
                            $zoneidExes += $res
                        }
                    }
                }
            }
        }
    }
}

$commandLine = @()
Write-Host "Stage 3.1"

foreach($i in $driveLetters) {
    $commandLine += ./1.exe search $i -f "*.jar" --file-only
}

if($commandLine) {
    foreach($i in $commandLine -split "\n") {
        if($i.Contains("Path")) { 
            $cleanPath = ($i -split " : ")[1].trim()
            if(Test-Path -LiteralPath $cleanPath) {
                $content = (Get-Content -LiteralPath $cleanPath -Stream Zone.Identifier -ErrorAction SilentlyContinue) -split "`n"
              
                if($content) { 
                    foreach($i in $content) {
                        if($i.Contains("HostUrl=") -and $i.Contains("doomsdayclient.com")) {
                            $res = $cleanPath + "`n" + $i.Replace("HostUrl=", "").Trim()
                            $dooms += $res
                        }
                    }
                }
            }
        }
    }
}

if (Test-Path "1.exe") { Remove-Item -Path "1.exe" -Force }

if($baritoneDirs) { 
    Write-Host "Baritone Dirs Detected: " ($baritoneDirs -join "`n") -ForegroundColor Yellow 
}
if($zoneidExes) { 
    Write-Host "Suspicious exes: " ($zoneidExes -join "`n") -ForegroundColor Yellow 
}
if($dooms) { 
    Write-Host "Doomsday Clients: " ($dooms -join "`n") -ForegroundColor Yellow 
}
#END







Write-Host "Stage 4"


#VM Check
Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/3.exe" -OutFile "1.exe"
Invoke-Expression ".\1.exe"
if (Test-Path "1.exe") { Remove-Item -Path "1.exe" -Force }
#END




#BAM
$bamData = @()
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
#END



$endTime = Get-Date
$duration = $endTime - $startTime


$filePath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $filePath) { Clear-Content -Path $filePath -Force }
wevtutil clear-log "Microsoft-Windows-PowerShell/Operational"


Write-Host "Done! $($duration.TotalMinutes.ToString("F2")) min"



