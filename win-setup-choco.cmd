@echo off 
rem Simple batch script to install commonly used applications, tools, utilities on a windows machine.
rem Assumes that chocolatey is already installed, else use the following Powershell command to install it.
rem Set-ExecutionPolicy Bypass -Scope Process -Force; 
rem   `iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

rem Upgrade chocolatey
choco upgrade chocolatey

rem Install Oracle Virtualbox 
choco install virtualbox --yes

rem Install web browser and Internet connectivity tools
choco install firefox --yes
choco install nordvpn --yes

rem Install Network traffic capture tools
choco install wireshark --yes

rem Install Utilities
choco install 7zip --yes
choco install sysinternals --yes
choco install putty --yes

rem Install password manager
choco install keepass --yes

rem Install Dropbox
choco install dropbox --yes

rem Install useful applications
choco install neovim --yes
choco install vlc --yes

rem Install Arduino development environment
choco install arduino --yes

rem Install Git tools
choco install git --yes
choco install github --yes

rem Upgrade all other installed applications
choco upgrade all

rem List all installed applications
choco list --local-only
