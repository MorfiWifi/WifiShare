# WifiShare

Share Wi-Fi with **one Ethernet client**, using Windows WinNAT, DHCP and optional
SMB/HTTP file sharing. All application code is in Program.cs.

## Correct addresses

| Setting | Laptop Ethernet | Client Ethernet |
|---|---|---|
| IPv4 | 172.20.10.1 | **172.20.10.185** |
| Mask | 255.255.255.0 | 255.255.255.0 |
| Gateway | None; internet exits through Wi-Fi | 172.20.10.1 |
| DNS | Existing Wi-Fi DNS | Upstream DNS selected at Start |

The .185 address belongs to the client. The laptop must have a different address.
Startup allows editing both addresses within the same /24 and rejects overlapping
upstream subnets. MAC spoofing is no longer part of startup.

The DHCP pool contains exactly the selected client address. Connect only the intended
client to this cable. The selected DNS suffix defaults to mydomain.net; this does not
create a domain or make private DNS servers reachable.

## Run

Requires Windows with working WinNAT (Get-NetNat / New-NetNat), Administrator rights,
and .NET 10 to build. No NuGet packages. The app checks prerequisites and does not
automatically install Windows features.

In Administrator PowerShell:

```powershell
cd D:\KscProjects\WifiShare
dotnet run -c Release
```

Choose **1 — Start**, confirm the physical adapters and the addresses above. DNS
defaults come from Wi-Fi. Choose DHCP for an automatic client, or decline it if the
client already has a static address. Keep the app open for DHCP and HTTP.

Menu: **1** Start, **2** Stop/Restore, **3** Settings, **4** Status, **5** Exit.

- --start runs setup prompts, then keeps the menu and background servers alive.
- --stop restores the session saved beside this executable.
- --setup-share applies the SMB login to an existing share without restarting networking.
- --status runs read-only diagnostics without requiring elevation; some Windows queries
  may still require Administrator privileges.
- --help prints usage.

Publish the standalone executable:

```powershell
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true -o publish
```

Run publish/WifiShare.exe as Administrator. Do not run multiple copies.
**Stop an active old build before upgrading**: Debug, Release and publish folders have
separate saved session files.

## Client setup

Set the client's Ethernet IPv4 **and DNS to automatic**, then reconnect the cable or
run `ipconfig /renew` on the client. Expect 172.20.10.185 with gateway 172.20.10.1.
Look for DHCP OFFER and ACK in the laptop log.

For static configuration, use the client column above and the DNS printed by Start.

- File Explorer address bar: `\\172.20.10.1\Shared`.
- Browser: http://172.20.10.1:8080/ when HTTP is running.

### Shared-folder login

Default username: **admin**. Default password: **123456**.
When Windows asks, use **LAPTOP-NAME\admin**, where LAPTOP-NAME is the server's
computer name printed by the app. This selects the laptop account instead of an
account on the client. You can also run this on the client and type the password:

```cmd
net use \\172.20.10.1\Shared /user:LAPTOP-NAME\admin *
```

Startup creates a standard local account, grants it read/write folder and share
access, and removes the share's old Everyone grant. Administrators retain full
share access. Existing unrelated accounts are never adopted or password-reset;
choose another username in Settings if the default is already in use.

Settings allows a different username/password. Passwords are not written to the
recovery JSON or application log; the requested default is in source. Windows
password policy is respected, so a rejected password needs to be changed in Settings.
The account is retained when sharing stops and reused by later starts. Credential
settings last for the current process; a new process uses the default password again.

For an already-running share, use an Administrator terminal:

```powershell
dotnet run -c Release -- --setup-share
```

If Windows cached a different login, disconnect the existing share mapping first
and reconnect with the laptop-qualified username. These credentials apply to SMB;
the optional HTTP file browser remains unauthenticated.

## Why sharing changed

The previous flow assigned the client's .185 address to the laptop, overwrote the ICS
LAN configuration, added an off-subnet gateway and ran another DHCP server. Its
unicast-only listener could miss DHCP broadcasts, and its Private-only firewall rule
did not cover an unidentified Public Ethernet network.

This version uses [Windows configurable NAT](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/setup-nat-network)
for the actual subnet and one DHCP server. The listener receives broadcasts, filters
input by Ethernet interface index, and selects that interface for replies.
The app's DHCP, file, discovery, ping and HTTP rules are scoped to Ethernet.

**Disable ICS / Mobile hotspot first.** Startup refuses existing ICS, Windows NAT or
DHCP port conflicts before changing addresses; it does not delete other applications'
networks or change undocumented ICS registry settings. Corrected ICS COM declarations
remain for diagnostics and legacy session cleanup.

Startup saves address/DNS/forwarding settings before changes and rolls back failed setup.
Failed restoration keeps the recovery file for retry. Old APIPA snapshots are restored
to DHCP instead of being recreated as static addresses. Shared folders remain on disk.
File-sharing service and folder-permission changes are not rolled back by Stop.

## Troubleshooting

Version 1.1.1 fixes `New-NetNat` rejecting the previous 42-character generated name
with Windows error 122 (displayed as “One or more parameter values ... invalid”).
Sessions now use short unique NAT names, verified against the Windows provider on
the target laptop. Startup also identifies the exact failed command and error ID.

1. Link down / cable unplugged: check the cable, client power and adapter.
2. Client has 169.254.x.x: no DHCP lease. Check automatic IPv4/DNS, OFFER/ACK logs and
   whether another DHCP server holds UDP 67. Leave the app open.
3. Client has .185: try `ping 172.20.10.1` and the HTTP link. Check masks, duplicate
   addresses and endpoint firewalls if both fail.
4. Gateway works but internet fails: check NAT in Status, laptop Wi-Fi internet and
   VPN/default routes. Try `ping 1.1.1.1` and a website; ICMP can be blocked separately.
5. Addresses work but names fail: use `nslookup example.com` and check the chosen DNS.
   The laptop does not run a DNS proxy in this mode.
6. Only File Explorer's Network list is empty: discovery is separate from routing.
   Use the direct share path and enable discovery on the client's trusted LAN.
   “Unidentified network” alone does not prove connectivity is broken.

## Verification

```powershell
dotnet build -c Release
dotnet run --project tests/WifiShare.Tests.csproj -c Release
```

Tests cover addressing, subnet overlap, adapter selection, restoration decisions,
interface filtering, malformed requests and real loopback UDP OFFER/ACK/NAK exchanges.
They do not change OS networking. End-to-end forwarding and Ethernet broadcast delivery
still require an elevated run and checks on the physical client.

After applying the default SMB login, this opt-in check validates the password and
creates, reads and deletes one temporary file through the loopback SMB share using
an independent logon session:

```powershell
dotnet run --project tests/WifiShare.Tests.csproj -c Release -- --smb-integration
```

An optional Windows integration check exercises the production NAT creation,
active-subnet verification and cleanup. Run it only from an Administrator terminal:

```powershell
dotnet run --project tests/WifiShare.Tests.csproj -c Release -- --nat-integration
```

This temporarily enables forwarding and creates its own NAT, then restores both.
It refuses an existing NAT or ICS session and leaves IP/DNS/firewall settings alone.
The standalone `diagnostics/Probe-Nat.ps1` can reproduce the old long-name failure;
its `-ShortName` switch tests the short-name form. Both runs keep a recovery snapshot
until cleanup succeeds.

## License

MIT — see [LICENSE](LICENSE).
