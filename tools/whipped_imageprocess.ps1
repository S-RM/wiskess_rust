<#
.SYNOPSIS
   This script will pull data from an AWS or Azure store, process it with wiskess and upload the output to a store
.DESCRIPTION
   Requirements: run setup.ps1 using PowerShell as Administrator
   
   Azure Usage:
   * Generate a SAS key from the storage where the data is stored in azure
   * Generate a SAS key to where you need the Wiskess output to be uploaded to in azure
   * Copy the file path of all the data you need processed, this needs to be the same as the path in Azure
   * Set a start and end time, which is likely the incident timeframe
   
   AWS Usage:
   * Add to your session or terminal the AWS credentials for the account where the data is stored in S3
   * Get the s3:// link to where the data source is stored
   * Create a bucket or folder in AWS S3, where you need the Wiskess output to be uploaded to in azure. Get that s3:// link too.
   * Copy the file path of all the data you need processed, this needs to be from the folder or bucket that you got the s3:// link.
   * Set a start and end time, which is likely the incident timeframe

.PARAMETER config
    Required. The config used to pass to wiskess
.PARAMETER image_path
    Required. The paths to the disk image
.PARAMETER wiskess_folder
    Required. The path to where Wiskess output is stored locally
.PARAMETER start_date
    Required. The start time from when we want to look for interesting information. Normally aligned with the incident timeframe. Caution: specifying a high number of days will cause performance issues.
.PARAMETER end_date
    Required. The end time to when we want to look for interesting information. Normally aligned with the incident timeframe. Caution: specifying a high number of days will cause performance issues.
.PARAMETER ioc_file
    Optional. The paths to a file containing a list of indicators of compromise. Each indicator is on a separate line.
.NOTES
    Author: Gavin Hull
    Date:   2025-07-04
#>

#Requires -Version 7.0
#Requires -RunAsAdministrator

param (
    [Parameter(Mandatory)] [string] $config,
    [Parameter(Mandatory)] [string] $ioc_file,
    [Parameter(Mandatory)] [string] $start_date,
    [Parameter(Mandatory)] [string] $end_date,
    [Parameter(Mandatory)] [string] $image_path,
    [Parameter(Mandatory)] [string] $wiskess_folder,
    [Parameter()] [string] $tool_path = $PSScriptRoot
)

function Get-FreeDrives ($start, $end) {
    $mounted_drives = (Get-PSDrive -PSProvider FileSystem).Name
    $start..$end | Where-Object {$_ -cnotin $mounted_drives}
}

function Start-Wiskess ($dataSource, $wiskess_folder, $start_date, $end_date, $ioc_file) {
    $binary = "$tool_path\wiskess_rust.exe"
    $cmdline = "--silent wiskess " +
        "--config $config " +
        "--data-source $dataSource " +
        "--out-path $wiskess_folder " +
        "--ioc-file $ioc_file " +
        "--start-date $start_date " +
        "--end-date $end_date"

    Write-Host "[+] Running command: $binary $cmdline"
    Start-Process $binary $cmdline -NoNewWindow -Wait
}


function Start-ImageProcess ($image, $wiskess_folder, $start_date, $end_date, $ioc_file, $osf_mount) {   
    $free_drives = Get-FreeDrives 'D' 'M'
    if ($image -Match "-flat\.vmdk$" -and (Test-Path $($image -replace "-flat\.vmdk$",".vmdk"))) {
        # Make sure to use the vmdk that has the image descriptor, i.e. not '-flat.vmdk'
        $image = $image -replace "-flat\.vmdk$",".vmdk"
    } elseif ($image -Match "-flat\.vmdk$") {
        $osf_mount = $True
    }
    if ($image -Match "\.(?:vhdx|ova|vdi)$") {
        # OSFMount doesn't support these image types, so either convert or use AIM
        $osf_mount = $False
    }
    if ($image -Match "^\\\\\?\\") {
        $image = $image -replace "^\\\\\?\\",""
    }


    Write-Host "[+] Processing image: $image"

    if (!$osf_mount) {
        # Mount it with AIM if not supported by OSF Mount 
        if ($(Test-Path -PathType Leaf -Path "C:\ProgramData\chocolatey\bin\aim_cli.exe") -eq $True) {
            Start-Process -FilePath "C:\ProgramData\chocolatey\bin\aim_cli.exe" -ArgumentList '--mount','--readonly',"--filename=$image",'--fakesig','--background' -NoNewWindow -PassThru
            Start-Sleep -Seconds 5
            $dismount = 00000
        } elseif ($image -Match "\.(?:vhdx|vhd)$") {
            Mount-VHD -ReadOnly -Passthru -Path $image
        } else {
            Write-Warning "Unable to mount file, please install Arsenal-Image-Mounter under path $tool_path\Arsenal-Image-Mounter"
            Start-Sleep -Seconds 5
        }
    } else {
        # $osf_mount = & 'C:\Program Files\OSFMount\OSFMount.com' -a -t file -m '#:' -o wc -f "$image" -v all
        $osf_mount = & 'C:\Program Files\OSFMount\OSFMount.com' -a -t file -f "$image" -v all
        if ($osf_mount -match 'Created device\s') {
            $drive_mount_start = $(($osf_mount -match 'Created device\s') -replace 'Created device\s*\d+:\s*(\w):.*','$1')
        }
        Write-Host "[ ] Mounted image to drive: $drive_mount_start"
        if ($drive_mount_start -ne "") {
            $free_drives = $drive_mount_start
        }
    }

    $done = $false
    $free_drives | ForEach-Object { 
        $drive_mount = "$($_):"
        if (!$done) {
            if ($(Get-PSDrive -Name $($drive_mount -replace ":$","") -ErrorAction SilentlyContinue) -and $(Test-Path -PathType Container "$($drive_mount)\Windows") ) {
                Start-Wiskess $drive_mount $wiskess_folder $start_date $end_date $ioc_file
                $done = $true
            } else {
                Write-Warning "Data source $drive_mount had no Windows folder!"
                if ($(Get-PSDrive -Name $($drive_mount -replace ":$","") -ErrorAction SilentlyContinue)) {
                    $get_win_dir = Get-ChildItem -Depth 1 -Directory $drive_mount | Where-Object { $_.Name -match "Windows" }
                }
                if ($get_win_dir) {
                    Write-Host "[ ] Found Windows folder at dept 1"
                    Start-Wiskess $get_win_dir.Parent $wiskess_folder $start_date $end_date $ioc_file
                    $done = $true
                }
            }
        }
    }
    
    if (!$osf_mount) {
        if ($(Test-Path -PathType Leaf -Path "C:\ProgramData\chocolatey\bin\aim_cli.exe") -eq $True) {
            Start-Process -FilePath  "C:\ProgramData\chocolatey\bin\aim_cli.exe" -ArgumentList "--dismount=$dismount","--force" -NoNewWindow -PassThru
        } elseif ($image -Match "\.(?:vhdx|vhd)$") {
            Dismount-VHD -Path $image
        }
    } else {
        if ($drive_mount_start -ne "") {
            $drive_mount_start.Split() | ForEach-Object {
                & 'C:\Program Files\OSFMount\OSFMount.com' -D -m "$($_):"
            }
        } else {        
            $free_drives | ForEach-Object { 
                $drive_mount = "$($_):"
            }
        }
    }
    return $done
}

$wiskessed = $False
$wiskessed = Start-ImageProcess -image $image_path -wiskess_folder "$wiskess_folder" -start_date $start_date -end_date $end_date -ioc_file $ioc_file -osf_mount $False
if (!$wiskessed) {
    $wiskessed = Start-ImageProcess -image $image_path -wiskess_folder "$wiskess_folder" -start_date $start_date -end_date $end_date -ioc_file $ioc_file -osf_mount $True
} else {
    Write-Output "OK debug"
}
if (!$wiskessed) {
    Write-Error "[!] Wiskess tried to mount the image, $image_path, but was unable to mount and find a Windows folder using Arsenal Image Mounter or OSFMount."
    Write-Output "[ ] Please try to mount this manually and process with wiskess_rust.exe wiskess."
}
