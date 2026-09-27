param(
    [string]$LanAlias = 'Ethernet',
    [string]$InternetAlias = 'Wi-Fi',
    [string]$Prefix = '172.20.10.0/24',
    [switch]$ShortName
)
# Temporary elevated reproduction. Does not change IPs, DNS, firewall or services.
# Only its own uniquely named NAT object is removed. Forwarding is restored.
$ErrorActionPreference = 'Stop'
$logPath = Join-Path $PSScriptRoot 'Probe-Nat.log'
$snapshotPath = Join-Path $PSScriptRoot 'Probe-Nat-state.json'
function Write-Probe([string]$Message) {
    ('[{0:o}] {1}' -f (Get-Date), $Message) | Add-Content -LiteralPath $logPath
}
$probeName = 'WifiShare-' + [guid]::NewGuid().ToString('N')
if ($ShortName) { $probeName = 'WS-' + [guid]::NewGuid().ToString('N').Substring(0,8) }
$original = @()
$stage = 'Preflight'
$failure = $false
$restored = $true
try {
    Write-Probe 'BEGIN'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this diagnostic as Administrator.'
    }
    if (Test-Path -LiteralPath $snapshotPath) { throw 'A previous diagnostic recovery snapshot exists; restore it before another run.' }
    if (@(Get-NetNat).Count -gt 0) { throw 'An existing NAT is present; diagnostic stopped without changes.' }
    foreach ($alias in @($LanAlias, $InternetAlias)) {
        foreach ($store in @('ActiveStore','PersistentStore')) {
            $ifaces = @(Get-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -PolicyStore $store)
            foreach ($iface in $ifaces) {
                $original += [pscustomobject]@{
                    Index = $iface.InterfaceIndex
                    Alias = $alias
                    Store = $store
                    Forwarding = $iface.Forwarding.ToString()
                }
            }
        }
    }
    @{ NatName = $probeName; Interfaces = $original } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $snapshotPath
    foreach ($alias in @($LanAlias, $InternetAlias)) {
        $stage = "Set-NetIPInterface '$alias' IPv4 Forwarding Enabled (default policy store)"
        Write-Probe $stage
        Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -Forwarding Enabled
        Write-Probe 'PASS'
    }
    $stage = "New-NetNat '$probeName' '$Prefix'"
    Write-Probe $stage
    New-NetNat -Name $probeName -InternalIPInterfaceAddressPrefix $Prefix | Out-Null
    Write-Probe ((Get-NetNat -Name $probeName | Format-List Name,Active,InternalIPInterfaceAddressPrefix | Out-String).Trim())
    Write-Probe 'PASS'
} catch {
    $failure = $true
    Write-Probe ("FAIL stage={0}; {1}; ID={2}; HRESULT={3}; Command={4}" -f $stage, $_.Exception.Message, $_.FullyQualifiedErrorId, $_.Exception.HResult, $_.InvocationInfo.Line)
} finally {
    if ($original.Count -gt 0 -and (Test-Path -LiteralPath $snapshotPath)) {
        try {
            Get-NetNat | Where-Object Name -eq $probeName | Remove-NetNat -Confirm:$false
        } catch { $restored = $false; Write-Probe ('NAT cleanup failed: ' + $_.Exception.Message) }
        foreach ($item in $original) {
            try {
                Set-NetIPInterface -InterfaceIndex $item.Index -AddressFamily IPv4 -PolicyStore $item.Store -Forwarding $item.Forwarding
            } catch { $restored = $false; Write-Probe ('Forwarding cleanup failed: ' + $_.Exception.Message) }
        }
        if ($restored) { Remove-Item -LiteralPath $snapshotPath; Write-Probe 'RESTORED' }
    }
    Write-Probe "DONE failure=$failure restored=$restored"
}
