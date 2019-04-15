@echo off

rem # get system date, time, and timezone
rem # https://superuser.com/questions/1302362/how-to-display-current-windows-os-date-time-and-timezone-in-cli
rem # echo %date% %time% & tzutil /g
rem # for /f "tokens=*" %i in ('tzutil /g') do echo %date% %time% %i
echo Date:	%date% 
echo Time:	%time%
echo TZ:	tzutil /g


rem # get operating system version
rem # https://www.windows-commandline.com/find-windows-os-version-from-command/
rem # ver
rem # systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
systeminfo


rem # get autostart services
rem # https://pario.no/2011/06/19/list-installed-windows-updates-using-wmic/
wmic service where startmode="auto" get displayname,name,state,startmode
wmic startup


rem # get scheduled task details


rem # get local users and groups


rem # get network details, interfaces, IPs, MAC addresses, routing table, ARP cache, DNS cache
ipconfig /all
netstat -an
netstat -nr
arp -a
ipconfig /displaydns


rem # get list of drivers 
driverquery


rem # get list of open file handles
rem # sysinternals - handle.exe


rem # get running processes
rem # wmic process get
wmic process get processid,parentprocessid,executablepath


rem # get user login history, usernames, source, and login duration


rem # get list of installed applications
rem # wmic product get name,vendor,version
wmic product get
wmic qfe get