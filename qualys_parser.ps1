<#
.SYNOPSIS

Author: expl01tation
License: https://creativecommons.org/licenses/by/4.0/
Required Dependencies: PowerShell 3.0
Version: 1.0

.DESCRIPTION

Parses the supplied CSV file and generates HTML output into a file that can be emailed to a specified recipient automatically, using only native PowerShell commands.  

.NOTES

This script was created to perform a quick parse of the Qualys CSV format into a digestable output and automate the delivery of the generated report to the desired recipient.  

This script was written in PowerShell 3

Change {$_.Severity} to reflect what you want exported - as of now only Critical, High, and Medium findings are exported
Regex for finding CVE's may need some work: ^(CVE-(1999|2\d{3})-(0\d{2}[1-9]|[1-9]\d{3,}))$

Remove Garbage lines prior to processing using the below as an example:
$a = get-content test.csv
$a[7..($a.length -2)] > temp.csv
$Report = Import-CSV temp.csv

.LINK

Twitter: https://www.twitter.com/expl01tat10n
GitHub Repo: https://github.com/expl01tat10n
GitHub Page: https://expl01tat10n.github.io

#>

# Import Qualys CSV Export File - Use the above if the CSV file is corrupted
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