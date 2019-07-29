@echo off

rem must be run with elevated privileges

rem disable windows 10 telemetry
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection /v AllowTelemetry /t REG_DWORD /d 0
sc config diagtrack start= disabled
sc stop diagtrack

rem set windows firewall to defaults
netsh advfirewall reset
