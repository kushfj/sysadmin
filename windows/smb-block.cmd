@echo off
echo [*] start blocking SMB and NetBIOS script
setlocal enabledelayedexpansion

rem windows batch script to create firewall rules to block SMB and NetBIOS to
rem Internet sites from local host. The following traffic is blocked
rem
rem SMB		445/tcp (server message block)
rem NBSS	139/tcp (netbios session service)
rem NBNR	137/udp (netbios name resolution)
rem NBDS	138/udp (netbios datagram service)
rem 
rem - https://support.microsoft.com/en-us/topic/preventing-smb-traffic-from-lateral-connections-and-entering-or-leaving-the-network-c0541db7-2244-0dce-18fd-14a3ddeb282a
rem - https://serverfault.com/questions/653814/windows-firewall-netsh-block-all-ips-from-a-text-file
rem - https://serverfault.com/questions/304781/cidr-ranges-for-everything-except-rfc1918


rem initialise local variables
set remips=
set /a count=0


rem loop through file of internet addresses
echo [+] getting ip addresses
rem for /f "skip=1" %%f in (internet.txt) do (
for /f %%f in (internet.txt) do (
	set remips=!remips!,%%f
	set /a count+=1
)
echo [+] read %count% IPs


rem rem remove the leading comma
set remips=%remips:~1%


rem create block SMB/NetBIOS session service firewall rule
echo [+] blocking SMB/NBSS
echo [-] debug: netsh advfirewall firewall add rule name="Block SMB/NBSS to Internet" dir=out action=block enable=yes Profile=any Localip=any Remoteip=%remips% Protocol=tcp Interfacetype=any remoteport=445,139
netsh advfirewall firewall add rule name="Block SMB/NBSS to Internet" dir=out action=block enable=yes Profile=any Localip=any Remoteip=%remips% Protocol=tcp Interfacetype=any remoteport=445,139
echo.
rem create block NetBIOS name resolution and datagram services firewall rule
echo [+] blocking NBDS/NBNR
echo [-] debug: netsh advfirewall firewall add rule name="Block NBDS/NBNR to Internet" dir=out action=block enable=yes Profile=any Localip=any Remoteip=%remips% Protocol=udp Interfacetype=any remoteport=137,138
netsh advfirewall firewall add rule name="Block NBDS/NBNR to Internet" dir=out action=block enable=yes Profile=any Localip=any Remoteip=%remips% Protocol=udp Interfacetype=any remoteport=137,138
echo.

endlocal
echo [*] done
pause
