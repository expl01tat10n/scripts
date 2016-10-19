#Qualys Parser

# Import Qualys CSV Export File
$Report = Import-CSV .\Qualys_Scan.csv
$date = Get-Date
$target = "Target Name"
$stype = "Authenticated Scan Report"
# Comment the above line and uncomment the below line depending on type of test run - or just edit in place
# $stype = "Unauthenticated Scan Report"

# Extract vulnerability titles, dump to temp file, import tmp file, and output html list
$tmplist = $Report | Select-Object -property Title | % {$_.Title} | Sort -Unique | Out-String > $target' '_tmp.txt
$vulnlist = (Get-Content -Path .\$target' '_tmp.txt) -join "<br>"