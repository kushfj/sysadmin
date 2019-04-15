# Based on the following references:
#  * ACSC Windows 10 Hardening Guide - https://www.cyber.gov.au/sites/default/files/2019-03/hardening_win10_1709.pdf
#  * BlackViper Scripts - https://github.com/madbomb122/BlackViperScript/

# Reset local security policy to default
# secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose

# Reset group policy objects
# RD /S /Q "%WinDir%\System32\GroupPolicyUsers"
# RD /S /Q "%WinDir%\System32\GroupPolicy"
# gpupdate /force

#
# Define functions
#

Function CheckOSVersion
{
  $WinOSVersion = [Environment]::OSVersion.Version.Major
  If ($WinOSVersion -ne 10)
  {
    Write-Host '[!] Microsoft Windows 10 required'
    Read-Host -Prompt '[+] press Enter key to exit...'
    Exit
  }
}

Function CheckPrivilege
{
  $Principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()

  if(-Not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
  {
    Write-Host '[!] Elevated privileges required'
    Read-Host -Prompt '[+] Press Enter key to exit...'
    Exit
  }
}

# https://blogs.technet.microsoft.com/kfalde/2014/11/01/kb2871997-and-wdigest-part-1/
# https://support.microsoft.com/en-gb/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a
Function RemoveWDigestLogon
{
  try
  {
    Remove-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction Stop
    Write-Host '[+] WDigest UseLogonCredential disabled'
  }
  catch
  {
    Write-Verbose '[!] Unable to disable WDigest UseLogonCredential.'
  }
}

Function SetRegistryValue($RegKey, $RegName, $RegValue)
{
  # Check if the key exists
  If ((TestPath -Path $RegKey) -eq False)
  {
    # Create the key
    New-Item -ItemType Directory -Path $RegKey | Out-Null
  }

  # Set the registry key
  Set-ItemProperty -Path $RegKey -Name $RegName -Value $RegValue -Type "Dword"
}

Function SetUAC
{
  try
  {
    SetRegistryValue("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 3)
    SetRegistryValue("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "PromptOnSecureDesktop", 1)
    Write-Host '[+] UAC changes enabled successfully.'
  }
  catch
  {
    Write-Verbose '[!] Unable to enable UAC changes.'
  }
}


#
# main() - Main entry point
#

# Check the operating system version
CheckOSVersion

# Check is user has elevated privileges
CheckPrivilege

# Credentials - Disable credential digests (LSASS hardening)
RemoveWDigestLogon

# User Account Control - Enable request for credentials to authorise sensitive actions
SetUAC

# Exploit Protection - Enable Microsoft Windows Defender Exploit Guide's Exploit Protection
# Windows Updates - Enable Automatic Update installation
# Password - Enable strict high complexity password

# Account - Enable account lockout
# Anonymous Access - Disable anonymous connections
# Logging - Enable audit loggings
# Autorun - Disable automatic run and play 

# Disable DNS multi-cast
# Disable SMBv1
# Disable NetBIOS
# Firewall - Block all inbound connections and enable firewall event logging


