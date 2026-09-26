# WifiShare

Turn a Windows laptop into a network bridge / share host — **one single-file C# (.NET 10) console app** (`Program.cs`).

Laptop Wi-Fi (internet) → shared over an Ethernet cable → client PC, with an exact
network identity, **plug-and-play DHCP**, and file sharing.

## What it does

1. **Internet Connection Sharing (ICS)** — detects the active Wi-Fi adapter and the
   Ethernet adapter (prefers Realtek PCIe GbE), enables ICS via the HNetCfg COM API.
2. **Exact network identity** on the Ethernet side — static `172.20.10.185/24`,
   gateway `169.254.254.254`, DNS `172.16.61.20` (+ `172.16.61.10`), connection
   DNS suffix `mydomain.net`, optional MAC spoof (`88:11:1E:34:F6:41`) via registry.
3. **Plug-and-play DHCP server (built in, no extra software)** — the client gets
   `172.20.10.100–200` + mask + gateway + DNS + domain automatically the moment
   the cable is plugged in. This is what makes preconfigured clients work: the
   stock ICS allocator only serves `192.168.137.x` with itself as DNS and no
   domain name, so it can never satisfy a client that expects your ranges/names.
   Our server also NAKs out-of-pool requests, healing stray `192.168.137.x`
   leases in seconds.
4. **File sharing** — File/Printer Sharing + Network Discovery firewall rules,
   SMB share `\\172.20.10.185\Shared`, optional HTTP file browser on port 8080.

## Quick start (Windows 10/11, Administrator terminal)

```powershell
dotnet run
# or publish a single self-contained exe:
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true -o publish
```

Menu: **1** Start · **2** Stop/Restore · **3** Settings · **4** Status · **5** Exit.
Scripting flags: `--start`, `--stop`, `--status`, `--help`.

## Client setup

**Plug-and-play (recommended):** leave the client on automatic/DHCP — done.
**Fallback static IP:** `172.20.10.186`, mask `255.255.255.0`, gateway `172.20.10.185`,
DNS `172.16.61.20`. Then open `\\172.20.10.185\Shared`.

## Repo layout

| File | Purpose |
|---|---|
| `Program.cs` | The entire application (single file). The comment header is the full manual: build/run, permissions, MAC/driver-spoofing limits, client setup. |
| `WifiShare.csproj` | Thin build wrapper so `dotnet run` / `dotnet publish` work. |

Zero NuGet packages — only .NET + Windows built-ins (`netsh`, PowerShell, registry, COM).

## Honest limitations

- Adapter **Description / Manufacturer / Driver version** and link speed come from
  the signed driver and cannot be changed from user mode.
- MAC override works on most Realtek drivers, not all (burned-in address wins).
- The app must keep running while DHCP/file sharing is needed; **Stop** restores
  the adapter to DHCP/original settings and removes the share + firewall rules.
- Full details live in the `Program.cs` header comment.

## License

MIT — see [LICENSE](LICENSE).
