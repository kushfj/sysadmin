@echo off
rem Simple batch script to tweak Windows 10 host to 
rem must be run with elevated privileges
rem TODO: add checking for elevated privileges and attempt elevation via UAC

rem disable windows 10 telemetry
echo "[+] disabling windows10 telemetry"
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection /v AllowTelemetry /t REG_DWORD /d 0 /f
sc stop "DiagTrack"
sc config "DiagTrack" start=disabled

rem disable active probing for internet connection
echo "[+] disabling active internet connection probing"
reg add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet\" /v "EnableActiveProbing" /t REG_DWORD /d 0 /f

rem disable multi-cast dns and link local multi-cast name resolution (LLMNR)
echo "[+] disabling multicast DNS and LLMNR"
reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d 0 /f

rem disbale netbios over TCP/IP on all interfaces
echo "[+] disabling NetBIOS over TCP on all interfaces"
for /f %%i in ('reg query HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\') do reg add "%%i" /v "NetbiosOptions" /t REG_DWORD /d 2 /f

rem disable multicast internet group manangement protocol (IGMP)
echo "[+] disabling internet group management protocol"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IGMPLevel" /t REG_DWORD /d 0 /f 

rem disable IPv6
echo "[+] disabling IPv6"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d 0xff /f

rem disable universal plug and play/pray (UPnP)
echo "[+] disabling UPnP"
reg add "HKLM\Software\Microsoft\DirectplayNATHelp\DPNHUPnP" /v "UPnPMode" /t REG_DWORD /d 2 /f

rem disable redundant services
for %%j in (
  "diagnosticshub.standardcollector.service" 
  "dmwappushservice"
  "HomeGroupListener"
  "HomeGroupProvider"
  "lfsvc"
  "MapsBroker"
  "NetTcpPortSharing"
  "RemoteAccess"
  "RemoteRegistry"
  "SharedAccess"
  "TrkWks"
  "WbioSrvc"
  "WMPNetworkSvc"
  "XblAuthManager"
  "XblGameSave"
  "XboxNetApiSvc"
  "ndu"
) do (
echo "[+] disabling %%j"
sc stop "%%j" 
sc config "%%j" start=disabled
)

rem stop and disable simple service discovery protocol (SSDP)
echo "[+] disabling simple service discovery protocol"
sc stop "SSDPSRV" 
sc config "SSDPSRV" start=disabled

rem stop and disable 
sc stop "WinHttpAutoProxySvc"
sc config "WinHttpAutoProxySvc" start=disabled

rem set windows firewall to defaults
echo "[+] resetting windows firewall"
netsh advfirewall reset
