$WebhookUrl = "http://YOUR-N8N-HOST:5678/webhook/ad-security-events"
$StateFile  = "C:\Scripts\last4625.txt"
$EventIds   = 4625, 4771, 4776
$Culture    = [System.Globalization.CultureInfo]::InvariantCulture
$Styles     = [System.Globalization.DateTimeStyles]::RoundtripKind

if (Test-Path $StateFile) {
    $raw = (Get-Content $StateFile -Raw).Trim()
    $since = [datetime]::Parse($raw, $Culture, $Styles)
} else {
    $since = (Get-Date).AddMinutes(-5)
}

$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = $EventIds
    StartTime = $since
} -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -gt $since } |
    Sort-Object TimeCreated

if (-not $events) { exit 0 }

foreach ($e in $events) {
    $xml = [xml]$e.ToXml()
    $d = @{}
    foreach ($n in $xml.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
     
   # skip successful NTLM validations (4776 with Status 0x0)
     if ($e.Id -eq 4776 -and $d['Status'] -eq '0x0') {
        Set-Content -Path $StateFile -Value $e.TimeCreated.ToString("o")
        continue
    }
    $user = $d['TargetUserName']
    if (-not $user -or $user -eq '-') { $user = $d['UserName'] }
    if (-not $user -or $user -eq '-') { $user = 'unknown' }
    $user = $user -replace '@.*$', ''
    $user = $user -replace '^.*\\', ''

    $domain = $d['TargetDomainName']
    if (-not $domain -or $domain -eq '-') { $domain = 'hsw' }

    $ip = $d['IpAddress']
    if (-not $ip -or $ip -eq '-') { $ip = $d['Workstation'] }
    if ($ip) { $ip = $ip -replace '^::ffff:', '' }
    if (-not $ip -or $ip -eq '-') { $ip = 'unknown' }

    $status = $d['Status']
    if (-not $status) { $status = $d['SubStatus'] }
    if (-not $status) { $status = 'unknown' }

    $ksa = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId(
        $e.TimeCreated.ToUniversalTime(), "Arab Standard Time")
    $time = $ksa.ToString("yyyy-MM-dd HH:mm:ss") + " (KSA)"

    $payload = @{
        event_id         = $e.Id
        user             = $user
        username         = $user
        TargetUserName   = $user
        domain           = $domain
        TargetDomainName = $domain
        source_ip        = $ip
        IpAddress        = $ip
        status           = $status
        time             = $time
        computer         = $e.MachineName
    } | ConvertTo-Json -Compress

    try {
        Invoke-RestMethod -Uri $WebhookUrl -Method Post `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($payload)) `
            -ContentType 'application/json; charset=utf-8' `
            -TimeoutSec 15 -ErrorAction Stop | Out-Null
        Set-Content -Path $StateFile -Value $e.TimeCreated.ToString("o")
    }
    catch {
        Write-Warning "Send failed: $($_.Exception.Message)"
        exit 1
    }
}
