@echo off
echo [*] start blocking SMB and NetBIOS script
set starttime=%time%
echo [+] start time

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


setlocal enabledelayedexpansion


rem initialise local variables
set /a count=0


rem loop through file of internet addresses
echo [+] getting ip addresses
for /f %%f in (internet.txt) do (
	set /a count+=1
	echo [+] blocking SMB/NetBIOS access to %%f
	start /b netsh advfirewall firewall add rule name="Block SMB/NBSS to Internet - %%f" dir=out action=block enable=yes Profile=any Localip=any Remoteip=%%f Protocol=tcp Interfacetype=any remoteport=445,139
	start /b netsh advfirewall firewall add rule name="Block NBDS/NBNR to Internet - %%f" dir=out action=block enable=yes Profile=any Localip=any Remoteip=%%f Protocol=udp Interfacetype=any remoteport=137,138
)
echo [+] read %count% IPs


endlocal
echo [*] done
set endtime=%time%
echo [-] start: %starttime%
echo [-] end: %endtime%
pause

rem cleanup all outgoing rules
rem netsh advfirewall firewall delete rule name=all dir=out
