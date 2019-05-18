@echo off 
rem Simple batch script to install commonly used applications, tools, utilities on a windows machine.
rem Assumes that chocolatey is already installed, else use the following Powershell command to install it.
rem Set-ExecutionPolicy Bypass -Scope Process -Force; 
rem   `iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"

rem Upgrade chocolatey
rem #choco upgrade chocolatey

rem Install Oracle Virtualbox 
choco install virtualbox --yes

rem Install web browsers and Internet connectivity tools
choco install firefox --yes
choco install googlechrome --yes
choco install nordvpn --yes

rem Install Windows management and admin tools
choco install rsat --yes
choco install sysinternals --yes

rem Install Utilities
choco install 7zip --yes
choco install bind-toolsonly --yes
choco install cygwin --yes
choco install putty --yes

rem Install password manager
choco install keepass --yes

rem Install Dropbox
choco install dropbox --yes

rem Install useful applications
choco install vim --yes
choco install vlc --yes
choco install pdfxchangeeditor --yes

rem Install Network traffic capture and analysis tools
choco install microsoft-message-analyzer --yes
choco install winpcap --yes
choco install wireshark --yes

rem Install web traffic analysis tools
choco install fiddler --yes
choco install burp-suite-free-edition --yes

rem Install memory analysis tools
choco install vilatility --yes

rem Install development tools
choco install python --yes
choco install arduino --yes
choco install git --yes
choco install github --yes

rem Install communications tools and utilities
choco install slack --yes
choco install signal --yes

rem Upgrade all other installed applications
rem #choco upgrade all

rem List all installed applications
choco list --local-only
