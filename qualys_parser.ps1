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

# CVE REGEX Extraction - Somewhat broken
# $regex = '^(CVE-(1999|2\d{3})-(0\d{2}[1-9]|[1-9]\d{3,}))$'
# $cvelist = $Report | Select-String -Pattern $regex | Sort -Unique | Out-String > $target' '_cvetmp.txt
# $cvelist = (Get-Content -Path .\$target' '_cvetmp.txt) -join "<br>"

$out = $target + '_report.html'

# Generate stats based on data
$critical = @($Report | Where-Object{$_.Severity -eq "5"}).Count
$high = @($Report | Where-Object{$_.Severity -eq "4"}).Count
$medium = @($Report | Where-Object{$_.Severity -eq "3"}).Count
$low = @($Report | Where-Object{$_.Severity -eq "2"}).Count
$info = @($Report | Where-Object{$_.Severity -eq "1"}).Count
$TotalStats = @($Report | Where-Object{$_.Severity -eq "5" -or $_.Severity -eq "4" -or $_.Severity -eq "3" -or $_.Severity -eq "2" -or $_.Severity -eq "1"}).Count