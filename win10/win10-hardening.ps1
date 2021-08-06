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

# https://github.com/ChrisTitusTech/win10script/blob/master/win10debloat.ps1
# https://raw.githubusercontent.com/Sycnex/Windows10Debloater/master/Windows10DebloaterGUI.ps1
Function Debloat
{
  try
  {
    # Define list of bloatware applications
    $Bloatware = @(
      # Unnecessary Windows 10 AppX Apps
      "Microsoft.3DBuilder"
      "Microsoft.AppConnector"
      "Microsoft.BingFinance"
      "Microsoft.BingNews"
      "Microsoft.BingSports"
      "Microsoft.BingTranslator"
      "Microsoft.BingWeather"
      "Microsoft.GetHelp"
      "Microsoft.Getstarted"
      "Microsoft.Messaging"
      "Microsoft.Microsoft3DViewer"
      "Microsoft.MicrosoftOfficeHub"
      "Microsoft.MicrosoftSolitaireCollection"
      "Microsoft.NetworkSpeedTest"
      "Microsoft.News"
      "Microsoft.Office.Lens"
      "Microsoft.Office.OneNote"
      "Microsoft.Office.Sway"
      "Microsoft.Office.Todo.List"  
      "Microsoft.OneConnect"
      "Microsoft.PPIProjection"
      "Microsoft.People"
      "Microsoft.Print3D"
      "Microsoft.RemoteDesktop"  
      "Microsoft.SkypeApp"
      "Microsoft.StorePurchaseApp"
      "Microsoft.Wallet"
      "Microsoft.Whiteboard"
      "Microsoft.WindowsAlarms"
      "Microsoft.WindowsFeedbackHub"
      "Microsoft.WindowsMaps"
      "Microsoft.WindowsSoundRecorder"
      "Microsoft.Xbox.TCUI"
      "Microsoft.XboxApp"
      "Microsoft.XboxGameOverlay"
      "Microsoft.XboxGamingOverlay"
      "Microsoft.XboxIdentityProvider"
      "Microsoft.XboxSpeechToTextOverlay"
      "Microsoft.ZuneMusic"
      "Microsoft.ZuneVideo"
      "microsoft.windowscommunicationsapps"


      # Sponsored Windows 10 AppX Apps
      "*ACGMediaPlayer*"
      "*ActiproSoftwareLLC*"
      "*AdobePhotoshopExpress*"
      "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
      "*BubbleWitch3Saga*"
      "*CandyCrush*"
      "*Dolby*"
      "*Duolingo-LearnLanguagesforFree*"
      "*EclipseManager*"
      "*Facebook*"
      "*Flipboard*"
      "*HiddenCity*"
      "*HiddenCityMysteryofShadows*"
      "*Hulu*"
      "*LinkedInforWindows*"
      "*Minecraft*"
      "*Netflix*"
      "*OneCalendar*"
      "*PandoraMediaInc*"
      "*Royal Revolt*"
      "*Speed Test*"
      "*Spotify*"
      "*Sway*"
      "*Twitter*"
      "*Viber*"
      "*Wunderlist*"
                     
      # Optional: Typically not removed but you can if you need to for some reason
      "*CanonicalGroupLimited.UbuntuonWindows*"
      "*MIDIBerry*"
      "*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
      "*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
      "*Microsoft.BingWeather*"
      "*Microsoft.DesktopAppInstaller*"
      "*Microsoft.HEIFImageExtension*"
      #"*Microsoft.MSPaint*"
      "*Microsoft.MicrosoftStickyNotes*"
      "*Microsoft.MixedReality.Portal*"
      "*Microsoft.ScreenSketch*"
      "*Microsoft.StorePurchaseApp*"
      "*Microsoft.VP9VideoExtensions*"
      "*Microsoft.WebMediaExtensions*"
      "*Microsoft.WebpImageExtension*"
      #"*Microsoft.Windows.Photos*"
      #"*Microsoft.WindowsCalculator*"
      #"*Microsoft.WindowsCamera*"
      #"*Microsoft.WindowsStore*"
      "*Microsoft.Xbox.TCUI*"
      "*Microsoft.XboxApp*"
      "*Microsoft.XboxGameOverlay*"
      "*Microsoft.XboxGamingOverlay*"
      "*Microsoft.XboxIdentityProvider*"
      "*Microsoft.XboxSpeechToTextOverlay*"
      "*Nvidia*"
      "*Slack*"
      "*WindSynthBerry*"
      "*\.NET*"
    )

    foreach ($Bloat in $Bloatware) 
    {
      Write-Host "Attempting to remove - $Bloat."
      Get-AppxPackage -Name $Bloat| Remove-AppxPackage
      Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
    }
  }
  catch
  {
    Write-Verbose '[!] Failed to uninstall all bloatware.'
  }
}

# Disable unnecessary services and settings to enhance privacy
Function CleanUp
{
  # Disable Windows Telemetry
  Write-Host '[-] Disabling windows telemetry.' 
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
  Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

  # Disable CloudStore for storing registry and filesystem data
  If (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore" ) 
  {
    #Stop-Process Explorer.exe -Force
    Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore" -Recurse -Force
    #Start-Process Explorer.exe -Wait
  }

  # Disable Tailored Experiences
  If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) 
  {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
  }
  Write-Host "Disabling Tailored Experiences..."
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
  
  # Stop and disable diagnostic tracking
  Write-Host '[-] Stopping and disabling diagnostic tracking service.' 
  Stop-Service "DiagTrack" -WarningAction SilentlyContinue
  Set-Service "DiagTrack" -StartupType Disabled

  # Disable location tracking
  Write-Host '[-] Disabling location tracking.' 
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
  # Disable Windows Feedback Experience program
  If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")
  {
    Write-Host '[-] Disabling windows feedback experience program.'
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Enabled -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
  }

  # Disable error reporting
  Write-Host '[-] Disabling error reporting.'
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

  # Disable Windows application suggestions
  Write-Host '[-] Disabling windows application suggestions.'
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0

  # Disable activity history
  Write-Host '[-] Disabling windows user activity history.'
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

  # Stopping and disabling Home Groups services
  # !!! Not applicable to 1803 and newer or Server !!!
#  If (Get-Service "HomeGroupListener" -ErrorAction SilentlyContinue)
#  {
#    Write-Host '[-] Stopping and disabling windows home group listener.'
#    Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
#    Set-Service "HomeGroupListener" -StartupType Disabled
#  }
#  If (Get-Service "HomeGroupProvider" -ErrorAction SilentlyContinue)
#  {
#    Write-Host '[-] Stopping and disabling windows home group provider.'
#    Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
#    Set-Service "HomeGroupProvider" -StartupType Disabled
#  }

  # Disabling windows remote assistance
  Write-Host '[-] Disabling windows remote assistance' 
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

  # Stopping and disabling Windows Search indexing service
  Write-Host '[-] Stopping and disabling windows indexing service' 
  Stop-Service "WSearch" -WarningAction SilentlyContinue
  Set-Service "WSearch" -StartupType Disabled

  # Disable Shared Experiences - Not applicable to Server
  Write-Host '[-] Disabling Shared Experiences.'
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableMmx" -Type DWord -Value 0

  # Disabling Cortana
  Write-Host '[-] Disabling cortana' 
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
  If (Test-Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")
  {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
  }

  # Stop and remove OneDrive
  Write-Host '[-] Removing OneDrive' 
  If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")
  {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1  }
  Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
  $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
  If (!(Test-Path $onedrive)) 
  {
    $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
  }
  Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
  Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
  Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
}

# Disable SMB version 1
Function DisableSMBv1
{
  Write-Host '[-] Disabling SMB version 1 (SMBv1)'
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

# Disable windows file and print sharing
# If you ar eusing psexec then this should not be run, just enable SMBv2
Function DisableSMBShare
{
  Write-Host 'Disabling SMB Server.'
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
  Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
}

# Disable SuperFetch service
Function DisableSuperFetch
{
  Stop-Service "SysMain" -WarningAction SilentlyContinue
  Set-Service "SysMain" -StartupType Disabled
}

# Disable unnecessary scheduled tasks
Function DisableScheduledTasks
{
  Write-Host '[-] Disabling unnecessary scheduled tasks.'
  #Get-ScheduledTask XblGameSaveTaskLogon | Disable-ScheduledTask
  Get-ScheduledTask XblGameSaveTask | Disable-ScheduledTask
  Get-ScheduledTask Consolidator | Disable-ScheduledTask
  Get-ScheduledTask UsbCeip | Disable-ScheduledTask
  Get-ScheduledTask DmClient | Disable-ScheduledTask
  Get-ScheduledTask DmClientOnScenarioDownload | Disable-ScheduledTask
}

# Disable sharing of mapped drives
Function DisableMapShare
{
  Write-Host '[-] Disabling sharing mapped drives between users.'
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue
}

# Disable SMB server to prevent sharing of files and printers
# If you ar eusing psexec then this should not be run
Function DisableAdminShare
{
  Write-Host '[-] Disabling implicit administrative shares.'
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0
}

# Disable link-local multicast name resolution (LLMNR) protocol
Function DisableLLMNR 
{
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) 
  {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
  }
  Write-Host '[-] Disabling LLMNR.'
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
}

# Disable Autoplay
Function DisableAutoplay 
{
  Write-Host '[-] Disabling Autoplay.'
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
}

# Disable Autorun for all drives
Function DisableAutorun 
{
  Write-Host '[-] Disabling Autorun for all drives.'
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) 
  {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
}

# Restrict Windows Update Delivery Optimisation to LAN P2P only
Function RestrictP2P
{
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) 
  {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
  }
  Write-Host '[-] Restrict P2P updates to local network only.'
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
}

# Disable performance impacting look and feel
Function SetLookFeel
{
  Write-Host '[-] Setting look and feel'
  Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 200
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 2
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 1
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" NoTileApplicationNotification -Value 1 


  # Set small icons for control panel
  Write-Host 'Setting Control Panel view to small icons.'
  If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) 
  {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
  }
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1

  # Disable search applications in Store {
  Write-Host 'Disabling search for app in store for unknown extensions.'
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) 
  {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
  }
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1

  # Set default Windows Explorer view to 'This PC'
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
  # Show all system tray icons
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0

  # Disbale sticky keys
  Write-Host 'Disabling Sticky keys prompt.'
  Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
}

# Enable password complexity and maximum age requirements
Function EnablePasswordPolicy 
{
  Write-Host '[-] Enabling password complexity and maximum age requirements.'
  $tmpfile = New-TemporaryFile
  secedit /export /cfg $tmpfile /quiet
  (Get-Content $tmpfile).Replace("PasswordComplexity = 0", "PasswordComplexity = 1").Replace("MaximumPasswordAge = -1", "MaximumPasswordAge = 42") | Out-File $tmpfile
  secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
  Remove-Item -Path $tmpfile
}




#
# main() - Main entry point
#

# Check the operating system version
CheckOSVersion

# Check is user has elevated privileges
CheckPrivilege

# Remove bloatware and other telemetry services, set performance 
Debloat
CleanUp
SetLookFeel

DisableSuperFetch
DisableScheduledTasks
#RestrictP2P

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
DisableLLMNR

# Disable SMBv1, sharing if mapped drives, implicit admin shares, and SMB server to share files and printer
DisableSMBv1
DisableMapShare
DisableAdminShare
DisableSMBShare

# Disable NetBIOS
# Firewall - Block all inbound connections and enable firewall event logging

# Download and install Sysmon

