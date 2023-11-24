<#
.DESCRIPTION
Setup the wiskess packages.

This downloads the required tools.
.NOTES
    Author: Gavin Hull
    Date:   2023-06-14
#>

param (
    [string] $gitKey
)

# Admin only mode
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))  
{  
  $arguments = "& '" +$myinvocation.mycommand.definition + "'"
  Start-Process powershell -Verb runAs -ArgumentList $arguments
  Break
}

# Globals
$toolPath = $PSScriptRoot

Function checkPython
{
  $p = &{py -V} 2>&1
  $version = if($p -is [System.Management.Automation.ErrorRecord])
  {
      # grab the version string from the error message
      $p.Exception.Message
  }
  else
  {
      # otherwise return as is
      $p
  }
  return $version
}

function  gitInstall($gitRepo, $outDir) {
  if ($(Test-Path -PathType Container -Path "$outDir\.git") -eq $False) {
    write-host "Installing $outDir" -ForegroundColor Magenta
    git clone "$gitRepo" "$toolPath\$outDir" --recursive
    Set-Location "$toolPath\$outDir"
  } else {
    write-host "Updating $outDir" -ForegroundColor Magenta
    Set-Location "$toolPath\$outDir"
    git pull
  }
  if ($(Test-Path -PathType Leaf -Path "$toolPath\$outDir\requirements.txt") -eq $True) {
    py -m pip install -r "$toolPath\$outDir\requirements.txt"
  }
  if ($(Test-Path -PathType Leaf -Path "$toolPath\$outDir\setup.py") -eq $True) {
    py "$toolPath\$outDir\setup.py" install
  }
  if ($(Test-Path -PathType Leaf -Path "$toolPath\$outDir\Cargo.toml") -eq $True) {
    & "$env:USERPROFILE\.cargo\bin\cargo.exe" build --release
  }
  Set-Location "$toolPath"
}

function gitRelease($gitRepo, $gitKeyToken) {
  Write-Host "Getting release of $gitRepo"
  & py $toolPath\setup_get_git.py $gitKeyToken $gitRepo
}

function Install-Rust {
  choco uninstall rust
  # Download and install the Rust installer
  Invoke-WebRequest -Uri "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe" -OutFile "$toolPath\rustup-init.exe"
  Start-Process -FilePath "$toolPath\rustup-init.exe" -ArgumentList "-y" -NoNewWindow -Wait
  & "$env:USERPROFILE\.cargo\bin\rustup.exe" uninstall toolchain stable-x86_64-pc-windows-msvc
  & "$env:USERPROFILE\.cargo\bin\rustup.exe" toolchain install stable-x86_64-pc-windows-gnu
  & "$env:USERPROFILE\.cargo\bin\rustup.exe" default stable-x86_64-pc-windows-gnu
  # Start-Sleep -Seconds 60
}

function Install-Azcopy {
  Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile "$toolPath\AzCopy.zip" -UseBasicParsing
  7z e "$toolPath\AzCopy.zip" -o"$toolPath\azcopy\" azcopy.exe -r -aoa
  Remove-Item "$toolPath\AzCopy.zip"
}

function Start-MainSetup {
  # install chocolatey, git, 7zip, ripgrep, python2/3, EZ-Tools, chainsaw, hayabusa, osfmount, fd
  Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

  choco install -y git 7zip ripgrep python2 fd osfmount awscli
  $chkPython = checkPython
  if ($chkPython.ToLower().Contains("python 3")) {
    write-host "Python already installed" -ForegroundColor White -BackgroundColor DarkGreen
  } else {
    write-host "[!] Missing Dependency. Please install Python 3." -ForegroundColor White -BackgroundColor DarkRed
    choco install -y python3
  }
  
  # Rust is needed for compiling hayabusa and chainsaw - not anymore, as will download latest release instead
  # Install-Rust

  # Download azcopy to tools folder
  Install-Azcopy

  RefreshEnv.cmd

  $gitRepos = @{
    # Format: "URL gitRepo" = "Output Director outDir"
    "https://github.com/EricZimmerman/Get-ZimmermanTools.git" = "Get-ZimmermanTools"
    # "https://github.com/Neo23x0/Loki2.git" = "loki2"
  }
  $gitReleases = @{    
    # "https://github.com/SigmaHQ/sigma" = "sigma"
    "https://github.com/countercept/chainsaw" = "chainsaw"
    "https://github.com/Yamato-Security/hayabusa" = "hayabusa"
    "https://github.com/omerbenamram/evtx.git" = "evtx"
    "https://github.com/Neo23x0/loki.git" = "loki"
    "https://github.com/omerbenamram/mft" = "mft"
  }
  # Install all listed git repos
  $gitRepos.Keys.Clone() | ForEach-Object {
    gitInstall -gitRepo $_ -outDir $gitRepos.$_
  }
  # Install all listed git releases
  $gitReleases.Keys.Clone() | ForEach-Object {
    gitRelease -gitRepo $_ -gitKey $gitKey
  }
  
  # Hayabusa post process, move exe to sibling of rules
  # if ($(Test-Path -PathType Leaf "$toolPath\hayabusa\target\release\hayabusa.exe") -eq $True) {
  #   Copy-Item "$toolPath\hayabusa\target\release\hayabusa.exe" "$toolPath\hayabusa\hayabusa.exe"
  # } else {
  #   Copy-Item "$toolPath\hayabusa.exe" "$toolPath\hayabusa\hayabusa.exe"
  # }

  # EZ Tools
  & "$toolPath\Get-ZimmermanTools\Get-ZimmermanTools.ps1" -NetVersion 4 -Dest "$toolPath\Get-ZimmermanTools\"

  # Chainsaw download shimcache patterns
  Invoke-WebRequest -Uri "https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/analysis/shimcache_patterns.txt" -OutFile "$toolPath\shimcache_patterns.txt"

  # installPython-CIM -- needs python2
  py -3 -m pip install PyQt6
  py -2 -m pip install python-cim

  # polars install
  py -m pip install polars
  py -m pip install chardet
  py -m pip install datetime
  py -m pip install filetype
  py -m pip install requests

  # Reprting - Out-HTMLView and New-HTMLTable
  Install-Module -Force PSWriteHTML -SkipPublisherCheck
}

if (!$gitKey) {
  $gitKey = Read-Host -Prompt "[?] What's your git token? Please follow these guidelines if unaware: https://github.blog/2022-10-18-introducing-fine-grained-personal-access-tokens-for-github/"
}

Start-MainSetup
write-host "[+] Setup finished. Check output and run again, if needing to update."