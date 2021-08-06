# https://www.makeuseof.com/tag/easily-remove-bloatware-windows-10/
Get-AppxPackage -name "Microsoft.3DBuilder" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.BingFinance" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.BingFoodAndDrink" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.BingHealthAndFitness" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.BingNews" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.BingSports" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.BingTravel" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.BingWeather" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.BioEnrollment" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.Getstarted" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.Music.Preview" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.Office.OneNote" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.People" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.Windows.Photos" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.WindowsCalculator" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.WindowsCamera" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.WindowsMaps" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.WindowsPhone" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.WindowsStore" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.XboxApp" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.XboxGameCallableUI" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.XboxIdentityProvider" | Remove-AppxPackage
Get-AppxPackage -name "Microsoft.ZuneMusic" | Remove-AppxPackage


# https://www.askvg.com/guide-how-to-remove-all-built-in-apps-in-windows-10/
get-appxpackage *3d* | remove-appxpackage
get-appxpackage *3dbuilder* | remove-appxpackage
get-appxpackage *alarms* | remove-appxpackage
get-appxpackage *appconnector* | remove-appxpackage
get-appxpackage *appinstaller* | remove-appxpackage
get-appxpackage *bing* | remove-appxpackage
get-appxpackage *bingfinance* | remove-appxpackage
get-appxpackage *bingnews* | remove-appxpackage
get-appxpackage *bingsports* | remove-appxpackage
get-appxpackage *bingweather* | remove-appxpackage
get-appxpackage *camera* | remove-appxpackage
get-appxpackage *commsphone* | remove-appxpackage
get-appxpackage *communicationsapps* | remove-appxpackage
get-appxpackage *connectivitystore* | remove-appxpackage
get-appxpackage *feedback* | remove-appxpackage
get-appxpackage *getstarted* | remove-appxpackage
get-appxpackage *holographic* | remove-appxpackage
get-appxpackage *maps* | remove-appxpackage
get-appxpackage *people* | remove-appxpackage
get-appxpackage *phone* | remove-appxpackage
get-appxpackage *solitaire* | remove-appxpackage
get-appxpackage *soundrecorder* | remove-appxpackage
get-appxpackage *sticky* | remove-appxpackage
get-appxpackage *sway* | remove-appxpackage
get-appxpackage *wallet* | remove-appxpackage
get-appxpackage *windowsphone* | remove-appxpackage
get-appxpackage *xbox* | remove-appxpackage