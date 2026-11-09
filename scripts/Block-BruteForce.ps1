param([switch]$DryRun)

$Threshold = 5
$WindowMin = 10
$Exclude   = @('administrator','krbtgt','guest','unknown')
$LogFile   = 'C:\Scripts\block-log.txt'
$Culture   = [System.Globalization.CultureInfo]::InvariantCulture
$Styles    = [System.Globalization.DateTimeStyles]::RoundtripKind

$Since = (Get-Date).AddMinutes(-$WindowMin)

$events = Get-WinEvent -FilterHashtable @{
    LogName='Security'; Id=4625,4771,4776; StartTime=$Since
} -ErrorAction SilentlyContinue
if (-not $events) { exit 0 }

# Last block time per user
$blocks = @{}
if (Test-Path $LogFile) {
    foreach ($line in (Get-Content $LogFile)) {
        if ($line -match '^(\S+)\s+DISABLED\s+(\S+)') {
            $blocks[$matches[2].ToLower()] = [datetime]::Parse($matches[1], $Culture, $Styles)
        }
    }
}

$rows = foreach ($e in $events) {
    $xml = [xml]$e.ToXml(); $d = @{}
    foreach ($n in $xml.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }

    if ($e.Id -eq 4776 -and $d['Status'] -eq '0x0') { continue }

    $u = $d['TargetUserName']
    if (-not $u -or $u -eq '-') { $u = $d['UserName'] }
    if (-not $u -or $u -eq '-') { continue }
    $u = $u -replace '@.*$',''
    $u = $u -replace '^.*\\',''

    [pscustomobject]@{ User = $u.ToLower(); Id = $e.Id; Time = $e.TimeCreated }
}
if (-not $rows) { exit 0 }

foreach ($g in ($rows | Group-Object User)) {
    if ($Exclude -contains $g.Name) { continue }

    # Usernames come from attacker-controlled input: allow only safe characters
    if ($g.Name -notmatch '^[a-z0-9._-]{1,20}$') { continue }

    $items = $g.Group
    if ($blocks.ContainsKey($g.Name)) {
        $last = $blocks[$g.Name]
        $items = $items | Where-Object { $_.Time -gt $last }
    }
    if (-not $items) { continue }

    $count = [int](($items | Group-Object Id | Measure-Object -Property Count -Maximum).Maximum)
    if ($count -lt $Threshold) { continue }

    $acc = Get-ADUser -Identity $g.Name -ErrorAction SilentlyContinue
    if (-not $acc -or -not $acc.Enabled) { continue }

    if ($DryRun) {
        Write-Host "DRY RUN: would disable $($g.Name) ($count failed attempts)"
        continue
    }

    Disable-ADAccount -Identity $acc
    Add-Content -Path $LogFile -Value "$((Get-Date).ToString('o')) DISABLED $($g.Name) after $count failed attempts in $WindowMin min"
}
