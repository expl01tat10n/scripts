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
 
# Create DataTable & Structure
$table = New-Object system.Data.DataTable "Vulnerability Breakout"
$col1 = New-Object system.Data.DataColumn Critical,([string])
$col2 = New-Object system.Data.DataColumn High,([string])
$col3 = New-Object system.Data.DataColumn Medium,([string])
$col4 = New-Object system.Data.DataColumn Low,([string])
$col5 = New-Object system.Data.DataColumn Informational,([string])

# Add columns to DataTable
$table.columns.add($col1)
$table.columns.add($col2)
$table.columns.add($col3)
$table.columns.add($col4)
$table.columns.add($col5)

# Add content to the DataTable
$row = $table.NewRow()
$row.Critical = "$critical"
$row.High = "$high"
$row.Medium = "$medium"
$row.Low = "$low"
$row.Informational = "$info"
$table.Rows.Add($row)

# Create HTML Version of the DataTable
$vhtml = 
"<table><tr><td><b>Critical</b></td><td><b>High</b></td><td><b>Medium</b></td><td><b>Low</b></td><td><b>Informational</b></td></tr>"
foreach ($row in $table.Rows)
{

    $vhtml += "<tr align=center><td>" + $row[0] + "</td><td>" + $row[1] + "</td><td>" + $row[2] + "</td><td>" + $row[3] + "</td><td>" + $row[4] + "</td></tr>"
}
$varhtml += "</table>"
$Header = @"
<style>
BODY {font-family:"Calibri";font-size:12px}
TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #eeeeee;}
TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;}
.odd { background-color:#ffffff }
.even { background-color:#aaaaaa; }
</style>
<title>
$target $stype
</title>
"@
$Pre = @"
<H2>$target $stype</H2>
<H3>Synthesis</H3>
$target has $TotalStats vulnerabilities.<br>
$vhtml
<br>Legend: 5 = Critical, 4 = High, 3 = Medium, 2 = Low, 1 = Informational<br><br>
Summary of Unique vulnerabilities<br>
$vulnlist
<br><br>
Discovered Vulnerabilities by CVE<br>
$cvelist
<br><br>Please contact <a href="mailto:email@address.com">email@address or Name</a> for any questions on this report or to provide comments/suggestions for improvement.
"@
$Post = @"
<i>Generated $date</i>
"@

# Possible fields to extract are {"IP","DNS","NetBIOS","OS","IP Status","QID","Title","Type","Severity","Port","Protocol", "FQDN","SSL","CVE ID","Vendor Reference","Bugtraq ID","Threat","Impact","Solution", "Exploitability","Associated Malware","Results","PCI Vuln","Instance"}
$Generate = $Report | Select-Object -property IP, DNS, OS, Title, Severity, 'Vendor Reference', Threat, Impact, Solution, Results | Where {$_.Severity -gt "0"} | Sort-Object -property @{e={$_.IP}; Ascending = $false}, Severity | ConvertTo-HTML -Head $Header -PreContent $Pre -PostContent $Post | Out-File $out

# Old Code
# $Generate = $Report | Select IP, DNS, OS, Title, Severity, 'Vendor Reference', Threat, Impact, Solution, Results | Where {$_.Severity -gt "0"} | Sort-Object Severity -Descending | ConvertTo-HTML -Head $Header -PreContent $Pre -PostContent $Post | Out-File $out

# Mail Magic Happens Here
$from = "email@address.com"
$to = "email@address.com"
# $cc = "email@address.com"
# $bcc = "email@address.com"
$Subject = $target Vulnerability Scan Report
$body = Get-Content .\$target' '_report.html
$msg = New-Object Net.Mail.MailMessage
$msg.Priority = [System..Net.Mail.MailPriority]::High
$msg.From = $from
$msg.To.Add($to)
# $msg.CC.Add($cc)
# $msg.BCC.Add($bcc)
$msg.IsBodyHTML = $True
$msg.Subject = $Subject
# Once HTML is enabled this will turn into msg.Body = $body - otherwise msg.Body = "Body Contents"
$msg.Body = $body
$smtp = New-Object Net.Mail.SmtpClient("mail")
$smtp.Send($msg)