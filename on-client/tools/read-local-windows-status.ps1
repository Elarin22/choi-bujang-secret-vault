$ErrorActionPreference = 'Stop'
$windowEnd = [DateTimeOffset]::Now
$windowStart = $windowEnd.AddHours(-24)

function Get-ReasonCode($errorRecord, [string]$kind) {
  $name = $errorRecord.Exception.GetType().Name
  if ($name -eq 'UnauthorizedAccessException' -or $name -eq 'SecurityException') { return "${kind}_READ_DENIED" }
  if ($name -eq 'CimException' -or $errorRecord.FullyQualifiedErrorId -like '*CimException*') { return "${kind}_CIM_UNAVAILABLE" }
  if ($errorRecord.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') { return 'NO_MATCHING_EVENTS' }
  return "${kind}_QUERY_FAILED"
}

function Get-EventCounts([string]$logName) {
  $checkedAt = [DateTimeOffset]::Now.ToString('o')
  $counts = @{ errors = 0; warnings = 0 }
  try {
    Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = @(2, 3); StartTime = $windowStart.LocalDateTime; EndTime = $windowEnd.LocalDateTime } -ErrorAction Stop |
      ForEach-Object {
        if ($_.Level -eq 2) { $counts.errors++ }
        elseif ($_.Level -eq 3) { $counts.warnings++ }
      }
    return [ordered]@{ status = 'ok'; checkedAt = $checkedAt; errors = $counts.errors; warnings = $counts.warnings }
  } catch {
    $reason = Get-ReasonCode $_ 'EVENT_LOG'
    if ($reason -eq 'NO_MATCHING_EVENTS') {
      return [ordered]@{ status = 'ok'; checkedAt = $checkedAt; errors = 0; warnings = 0 }
    }
    return [ordered]@{ status = 'unknown'; checkedAt = $checkedAt; reasonCode = $reason }
  }
}

$networkCheckedAt = [DateTimeOffset]::Now.ToString('o')
try {
  $interfaces = @(
    foreach ($adapter in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
      if ($adapter.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
      $properties = $adapter.GetIPProperties()
      $addresses = @(
        foreach ($entry in $properties.UnicastAddresses) {
          [ordered]@{
            family = $entry.Address.AddressFamily.ToString()
            address = $entry.Address.ToString()
            prefixLength = [int]$entry.PrefixLength
          }
        }
      )
      $gateways = @($properties.GatewayAddresses | ForEach-Object { $_.Address.ToString() } | Where-Object { $_ -and $_ -notin @('0.0.0.0', '::') })
      $dnsServers = @($properties.DnsAddresses | ForEach-Object { $_.ToString() })
      [ordered]@{
        name = $adapter.Name
        type = $adapter.NetworkInterfaceType.ToString()
        ipv4 = @($addresses | Where-Object { $_.family -eq 'InterNetwork' } | ForEach-Object { "$($_.address)/$($_.prefixLength)" })
        ipv6 = @($addresses | Where-Object { $_.family -eq 'InterNetworkV6' } | ForEach-Object { "$($_.address)/$($_.prefixLength)" })
        gateways = $gateways
        dnsServers = $dnsServers
      }
    }
  )
  $network = [ordered]@{ status = 'ok'; checkedAt = $networkCheckedAt; interfaces = $interfaces }
} catch {
  $network = [ordered]@{ status = 'unknown'; checkedAt = $networkCheckedAt; reasonCode = (Get-ReasonCode $_ 'NETWORK') }
}

$firewallCheckedAt = [DateTimeOffset]::Now.ToString('o')
try {
  $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
    [ordered]@{ name = [string]$_.Name; enabled = [bool]$_.Enabled }
  })
  if (@($profiles | Where-Object { $_.name -in @('Domain', 'Private', 'Public') }).Count -ne 3) { throw 'FIREWALL_PROFILE_SET_INCOMPLETE' }
  $firewall = [ordered]@{ status = 'ok'; checkedAt = $firewallCheckedAt; profiles = $profiles }
} catch {
  $firewall = [ordered]@{ status = 'unknown'; checkedAt = $firewallCheckedAt; reasonCode = (Get-ReasonCode $_ 'FIREWALL') }
}

$result = [ordered]@{
  network = $network
  firewall = $firewall
  events = [ordered]@{
    windowHours = 24
    windowStart = $windowStart.ToString('o')
    windowEnd = $windowEnd.ToString('o')
    system = (Get-EventCounts 'System')
    application = (Get-EventCounts 'Application')
  }
}
$json = ConvertTo-Json -InputObject $result -Depth 8 -Compress
[Console]::Out.WriteLine([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json)))
