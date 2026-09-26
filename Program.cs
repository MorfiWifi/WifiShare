// ============================================================================
// WifiShare — turn a Windows laptop into a network bridge / share host.
// ----------------------------------------------------------------------------
// SINGLE-FILE C# (.NET 10) console application. Everything lives in THIS file.
//
// WHAT IT DOES
//   1. Shares the laptop's Wi-Fi internet with a client PC over Ethernet
//      cable using Windows Internet Connection Sharing (ICS).
//   2. Applies an exact network identity on the Ethernet adapter facing the
//      client (static IP 172.20.10.185/24, gateway, DNS, DNS suffix,
//      optional MAC spoof via the registry).
//   3. Runs a built-in plug-and-play DHCP server on the Ethernet side, so the
//      client "just works" when the cable is plugged in: it automatically
//      receives 172.20.10.100-200, mask /24, gateway 172.20.10.185,
//      DNS 172.16.61.20 (+ .10) and the domain suffix mydomain.net — matching
//      preconfigured clients that only accept those names/ranges.
//   4. Enables File/Printer Sharing + Network Discovery, creates an SMB
//      share, and optionally runs a lightweight HTTP file server so the
//      client can browse/download files easily.
//
// HOW TO COMPILE / RUN (pick one)
//   Option A — with the tiny companion project file (recommended):
//       dotnet run                       (from an ELEVATED terminal)
//   Option B — .NET 10 file-based apps (no .csproj needed, SDK 10+):
//       dotnet run Program.cs
//   Option C — publish a single self-contained .exe (run on Windows x64):
//       dotnet publish -c Release -r win-x64 --self-contained true ^
//           /p:PublishSingleFile=true -o publish
//       (then run publish\WifiShare.exe as Administrator)
//
// REQUIRED PERMISSIONS
//   * Windows 10 / 11.
//   * MUST run as Administrator (the program detects this and offers to
//     relaunch elevated). Changing IPs, ICS, firewall rules, shares and the
//     network-adapter registry key all require elevation.
//
// LIMITATIONS (read before you blame the program)
//   * MAC spoofing: Windows lets you *suggest* a MAC by writing the
//     "NetworkAddress" value under the adapter's registry key and restarting
//     the adapter. Most Realtek drivers honour it, some do not (they keep
//     the burned-in address). If it does not stick, update the driver or use
//     the vendor utility. The program reports what the OS actually shows.
//   * Adapter Description / Manufacturer / Driver Version (e.g. "Realtek
//     PCIe GbE Family Controller", "1.0.0.14"): these strings come from the
//     signed driver INF and CANNOT be changed from user mode. Any tool that
//     claims otherwise is lying or installs an unsigned filter driver (which
//     breaks driver-signature enforcement). The program verifies/displays
//     them but does not fake them.
//   * Link speed: shows the real negotiated speed; it cannot be spoofed.
//   * "Unencrypted": Ethernet has no encryption flag to set — wired traffic
//     is unencrypted at L2 by nature, so there is nothing to configure.
//   * ICS ships its own DHCP allocator for 192.168.137.0/24. Our DHCP server
//     binds EXCLUSIVELY to 172.20.10.185:67, so the two do not fight; if the
//     ICS allocator is holding UDP 67, ours reports it and the client falls
//     back to the static IP below. Our server also NAKs out-of-pool REQUESTs,
//     which heals a stray 192.168.137.x lease within seconds.
//   * Default gateway 169.254.254.254 is off-subnet for 172.20.10.0/24.
//     Windows accepts it with a warning on most builds; if netsh refuses,
//     the program applies the IP without a gateway and tells you.
//
// HOW THE CLIENT SHOULD CONNECT
//   Option 1 — PLUG-AND-PLAY (recommended): leave the client on automatic
//     (DHCP). Our server assigns 172.20.10.100-200 + mask + gateway
//     172.20.10.185 + DNS 172.16.61.20 (+ .10) + domain mydomain.net.
//   Option 2 — static IP on the client (fallback, or when preconfiguration
//     demands a fixed address):
//       Client IP:      172.20.10.186        (any free .2-.254 except .185)
//       Subnet mask:    255.255.255.0
//       Default gw:     172.20.10.185        (this laptop)
//       DNS:            172.16.61.20  (alt. 172.16.61.10)
//   Then on the client open:  \\172.20.10.185\Shared
//   Or in a browser:          http://172.20.10.185:8080/   (if HTTP on)
// ============================================================================

// Explicit usings: harmless if ImplicitUsings is also enabled, and required
// for .NET 10 file-based runs where ImplicitUsings may be off.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

// ============================================================================
// BOOTSTRAP — top-level statements. Must stay ABOVE all type declarations.
// Asks for elevation on Windows, then hands control to the menu app.
// ============================================================================
try
{
    int code = WifiShareApp.Run(args);
    return code;
}
catch (Exception ex)
{
    try
    {
        Log.Error("Fatal unhandled error: " + ex.Message);
        Log.Info(ex.ToString());
    }
    catch { /* logging must never crash the process */ }
    return 1;
}

// ============================================================================
// Defaults — every spec value from the task lives here in one place.
// ============================================================================
internal static class Defaults
{
    public const string HostIp = "172.20.10.185";
    public const string Mask = "255.255.255.0";
    public const int PrefixLength = 24;
    public const string Gateway = "169.254.254.254";   // off-subnet: see README
    public const string DnsPrimary = "172.16.61.20";
    public const string DnsSecondary = "172.16.61.10";
    public const string DnsSuffix = "mydomain.net";
    public const string TargetMac = "88:11:1E:34:F6:41";
    // Plug-and-play DHCP pool served to the client (must sit inside 172.20.10.0/24
    // and must NOT contain the host IP .185). Lease time in hours.
    public const string PoolStart = "172.20.10.100";
    public const string PoolEnd = "172.20.10.200";
    public const int LeaseHours = 24;
    public const string SharePath = @"C:\SharedWithClient";
    public const string ShareName = "Shared";
    public const int HttpPort = 8080;
    public const string ExpectedAdapterHint = "Realtek PCIe GbE Family Controller";
}

// Runtime-tweakable settings (menu option 3 edits these).
internal static class Settings
{
    public static string SharePath = Defaults.SharePath;
    public static string ShareName = Defaults.ShareName;
    public static string DnsSuffix = Defaults.DnsSuffix;
    public static int HttpPort = Defaults.HttpPort;
    public static bool StartHttpServer = true;
    public static bool SpoofMac = true;
    // Plug-and-play DHCP (option 5 in subst: offered on Start, see DhcpServer).
    public static bool StartDhcp = true;
    public static string PoolStart = Defaults.PoolStart;
    public static string PoolEnd = Defaults.PoolEnd;
    public static int LeaseHours = Defaults.LeaseHours;
}

// ============================================================================
// ShareState — snapshot of the ORIGINAL settings, persisted to JSON so we
// can restore them later (even if the program was closed and reopened).
// ============================================================================
internal sealed class ShareState
{
    public string PublicAdapterName { get; set; } = "";
    public string? PublicAdapterId { get; set; }
    public string PrivateAdapterName { get; set; } = "";
    public string? PrivateAdapterId { get; set; }
    public bool HadStaticIp { get; set; }
    public string? OrigIp { get; set; }
    public string? OrigMask { get; set; }
    public string? OrigGateway { get; set; }
    public List<string> OrigDns { get; set; } = new();
    public string OrigSuffix { get; set; } = "";
    // null = no NetworkAddress override existed; otherwise the old value.
    public string? OrigMacOverride { get; set; } = null;
    public bool OrigMacOverrideExisted { get; set; }
    public string SharePath { get; set; } = "";
    public string ShareName { get; set; } = "";
    public string DnsSuffix { get; set; } = "";
    public int HttpPort { get; set; }
    public bool IcsEnabledByUs { get; set; }
    public bool MacSpoofedByUs { get; set; }
    public bool DhcpStartedByUs { get; set; }
    public DateTimeOffset StartedUtc { get; set; }
}

internal static class StateStore
{
    // JSON file next to the exe/log so Start and Stop always find it.
    public static string Path =>
        System.IO.Path.Combine(AppContext.BaseDirectory, "wifishare-state.json");

    public static void Save(ShareState s)
    {
        var json = JsonSerializer.Serialize(s, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(Path, json, Encoding.UTF8);
    }

    public static ShareState? Load()
    {
        try
        {
            if (!File.Exists(Path)) return null;
            var json = File.ReadAllText(Path, Encoding.UTF8);
            return JsonSerializer.Deserialize<ShareState>(json);
        }
        catch { return null; }
    }

    public static void Clear()
    {
        try { if (File.Exists(Path)) File.Delete(Path); } catch { }
    }

    public static bool Exists => File.Exists(Path);
}

// ============================================================================
// Log — every action goes to the console (colored) AND to WifiShare.log.
// ============================================================================
internal static class Log
{
    private static readonly object _lock = new();
    public static string FilePath =>
        System.IO.Path.Combine(AppContext.BaseDirectory, "WifiShare.log");

    private static void Write(string level, string msg, ConsoleColor color)
    {
        string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {msg}";
        lock (_lock)
        {
            var old = Console.ForegroundColor;
            try
            {
                Console.ForegroundColor = color;
                Console.WriteLine(line);
            }
            finally { Console.ForegroundColor = old; }
            try { File.AppendAllText(FilePath, line + Environment.NewLine, Encoding.UTF8); }
            catch { /* logging must never crash */ }
        }
    }

    public static void Info(string m) => Write("INFO", m, ConsoleColor.Gray);
    public static void Ok(string m) => Write("OK", m, ConsoleColor.Green);
    public static void Warn(string m) => Write("WARN", m, ConsoleColor.Yellow);
    public static void Error(string m) => Write("ERROR", m, ConsoleColor.Red);
    public static void Step(string m) => Write("STEP", m, ConsoleColor.Cyan);
}

// ============================================================================
// Ui — banner, menus, prompts, tiny progress helpers.
// ============================================================================
internal static class Ui
{
    public static void Banner()
    {
        Console.Clear();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@" __        ___  __ _   ___ _                    ");
        Console.WriteLine(@" \ \      / (_)/ _(_) / __| |__   __ _ _ __ ___  ");
        Console.WriteLine(@"  \ \ /\ / /| | |_| | \__ \ '_ \ / _` | '__/ _ \ ");
        Console.WriteLine(@"   \ V  V / | |  _| | |___| | | | (_| | | |  __/ ");
        Console.WriteLine(@"    \_/\_/  |_|_| |_| |___/|_| |_|\__,_|_|  \___| ");
        Console.ResetColor();
        Console.WriteLine("  Share laptop Wi-Fi over Ethernet  |  ICS + static identity + file share");
        Console.WriteLine($"  Log file: {Log.FilePath}");
        Console.WriteLine(new string('=', 70));
    }

    public static void Section(string title)
    {
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine();
        Console.WriteLine($"--- {title} ---");
        Console.ResetColor();
    }

    public static void Pause()
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine();
        Console.WriteLine("Press ENTER to continue...");
        Console.ResetColor();
        try { Console.ReadLine(); } catch { }
    }

    // Prompt with a default shown in [brackets]; ENTER keeps the default.
    public static string Prompt(string label, string defaultValue)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{label} [{defaultValue}]: ");
        Console.ResetColor();
        string? input = null;
        try { input = Console.ReadLine(); } catch { }
        if (string.IsNullOrWhiteSpace(input)) return defaultValue;
        return input.Trim();
    }

    public static bool PromptYesNo(string label, bool defaultYes)
    {
        string hint = defaultYes ? "Y/n" : "y/N";
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"{label} ({hint}): ");
        Console.ResetColor();
        string? input = null;
        try { input = Console.ReadLine(); } catch { }
        if (string.IsNullOrWhiteSpace(input)) return defaultYes;
        input = input.Trim().ToLowerInvariant();
        return input is "y" or "yes";
    }

    // Simple "please wait" dots while we sleep between long operations.
    public static void Wait(int seconds, string message)
    {
        Console.Write(message);
        for (int i = 0; i < seconds; i++)
        {
            Thread.Sleep(1000);
            Console.Write(".");
        }
        Console.WriteLine();
    }
}

// ============================================================================
// Sys — thin wrapper around external tools (netsh, powershell, net, sc,
// icacls). Using the OS tools keeps us dependency-free (no NuGet) and is
// the most reliable way to drive Windows networking from .NET.
// ============================================================================
internal sealed record CommandResult(int ExitCode, string StdOut, string StdErr)
{
    public bool Success => ExitCode == 0;
}

internal static class Sys
{
    // Run any process, capture stdout/stderr, never throw.
    public static CommandResult Run(string fileName, string arguments, int timeoutMs = 90_000)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            using var p = Process.Start(psi);
            if (p is null) return new CommandResult(-1, "", "could not start process");
            Task<string> outTask = p.StandardOutput.ReadToEndAsync();
            Task<string> errTask = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(); } catch { }
                return new CommandResult(-1, "", "timed out");
            }
            return new CommandResult(p.ExitCode, outTask.Result.Trim(), errTask.Result.Trim());
        }
        catch (Exception ex)
        {
            return new CommandResult(-1, "", ex.Message);
        }
    }

    public static CommandResult Netsh(string args) => Run("netsh", args);

    // Quote a PowerShell single-quoted string safely (' -> '').
    public static string PwshQuote(string s) => "'" + s.Replace("'", "''") + "'";

    // Run PowerShell via -EncodedCommand (Base64 UTF-16) so we never fight
    // with nested quoting of interface names like "Wi-Fi".
    public static CommandResult PowerShell(string script, int timeoutMs = 90_000)
    {
        if (!OperatingSystem.IsWindows())
            return new CommandResult(-1, "", "PowerShell is only available on Windows.");
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return Run("powershell",
            "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + b64,
            timeoutMs);
    }

    public static bool IsWindows() => OperatingSystem.IsWindows();

    public static bool IsAdmin()
    {
        if (!IsWindows()) return false;
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    // Relaunch ourselves elevated ("runas" verb). Returns true if relaunch ok.
    public static bool RelaunchAsAdmin(string args)
    {
        try
        {
            string? exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe)) return false;
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                Verb = "runas",          // triggers the UAC prompt
                UseShellExecute = true,  // required for "runas"
            };
            Process.Start(psi);
            return true;
        }
        catch (Exception ex)
        {
            Log.Error("Elevation failed: " + ex.Message);
            return false;
        }
    }
}

// ============================================================================
// Adapters — discovery + status via System.Net.NetworkInformation (built in).
// ============================================================================
internal sealed record AdapterSnapshot(
    string Name,                    // connection name, e.g. "Wi-Fi", "Ethernet"
    string Description,             // driver description, e.g. "Realtek PCIe GbE..."
    NetworkInterfaceType Type,
    OperationalStatus Status,
    string Id,                      // NetCfgInstanceId GUID string
    string Mac,
    long SpeedBps,
    List<string> IPv4,
    List<string> Masks,
    List<string> Gateways,
    List<string> Dns,
    bool DhcpEnabled);

internal static class Adapters
{
    public static List<AdapterSnapshot> ListAll()
    {
        var list = new List<AdapterSnapshot>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            List<string> ips = new(), masks = new(), gws = new(), dns = new();
            bool dhcp = false;
            try
            {
                var props = nic.GetIPProperties();
                foreach (var u in props.UnicastAddresses)
                {
                    if (u.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                        continue;
                    if (IPAddress.IsLoopback(u.Address)) continue;
                    ips.Add(u.Address.ToString());
                    masks.Add(u.IPv4Mask?.ToString() ?? "");
                }
                foreach (var g in props.GatewayAddresses)
                {
                    if (g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        gws.Add(g.Address.ToString());
                }
                foreach (var d in props.DnsAddresses)
                {
                    if (d.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        dns.Add(d.ToString());
                }
                dhcp = props.DhcpServerAddresses.Count > 0;
            }
            catch { /* one bad adapter must not hide the others */ }

            string mac = "";
            try
            {
                var bytes = nic.GetPhysicalAddress()?.GetAddressBytes();
                if (bytes is { Length: 6 })
                    mac = string.Join(":", bytes.Select(b => b.ToString("X2")));
            }
            catch { }

            long speed = 0;
            try { speed = nic.Speed; } catch { }

            list.Add(new AdapterSnapshot(
                nic.Name, nic.Description, nic.NetworkInterfaceType,
                nic.OperationalStatus, nic.Id, mac, speed,
                ips, masks, gws, dns, dhcp));
        }
        return list;
    }

    private static bool IsApipa(string ip) => ip.StartsWith("169.254.", StringComparison.Ordinal);

    // Score Wi-Fi candidates: Up + default gateway + usable (non-APIPA) IPv4.
    public static AdapterSnapshot? DetectWifi(List<AdapterSnapshot> all)
    {
        AdapterSnapshot? best = null;
        int bestScore = -1;
        foreach (var a in all.Where(a => a.Type == NetworkInterfaceType.Wireless80211))
        {
            int score = 0;
            if (a.Status == OperationalStatus.Up) score += 2;
            if (a.Gateways.Any(g => g != "0.0.0.0")) score += 2;
            if (a.IPv4.Any(ip => !IsApipa(ip))) score += 1;
            if (score > bestScore) { bestScore = score; best = a; }
        }
        return bestScore > 0 ? best : null;
    }

    // Score Ethernet candidates: prefer Realtek GbE hint, Up, named Ethernet.
    public static AdapterSnapshot? DetectEthernet(List<AdapterSnapshot> all)
    {
        AdapterSnapshot? best = null;
        int bestScore = -1;
        foreach (var a in all.Where(a => a.Type == NetworkInterfaceType.Ethernet))
        {
            int score = 0;
            if (a.Description.Contains("Realtek", StringComparison.OrdinalIgnoreCase)) score += 2;
            if (a.Description.Contains("GbE", StringComparison.OrdinalIgnoreCase) ||
                a.Description.Contains("PCIe", StringComparison.OrdinalIgnoreCase)) score += 1;
            if (a.Status == OperationalStatus.Up) score += 2;
            if (a.Name.Contains("Ethernet", StringComparison.OrdinalIgnoreCase)) score += 1;
            if (score > bestScore) { bestScore = score; best = a; }
        }
        return bestScore >= 0 ? best : null;
    }

    public static string FormatSpeed(long bps)
    {
        if (bps <= 0) return "unknown";
        if (bps >= 1_000_000_000) return $"{bps / 1_000_000_000.0:0.#} Gbps";
        if (bps >= 1_000_000) return $"{bps / 1_000_000.0:0.#} Mbps";
        return $"{bps / 1_000.0:0.#} Kbps";
    }

    public static void PrintTable(List<AdapterSnapshot> all)
    {
        Console.WriteLine($"{"Name",-14} {"Type",-10} {"Status",-9} {"MAC",-19} {"Speed",-11} IPs");
        Console.WriteLine(new string('-', 100));
        foreach (var a in all)
        {
            string ips = a.IPv4.Count > 0 ? string.Join(",", a.IPv4) : "(none)";
            Console.WriteLine($"{Trunc(a.Name, 14),-14} {Trunc(a.Type.ToString(), 10),-10} " +
                              $"{a.Status,-9} {a.Mac,-19} {FormatSpeed(a.SpeedBps),-11} {ips}");
            Console.WriteLine($"    Desc: {a.Description}");
            if (a.Gateways.Count > 0) Console.WriteLine($"    GW:   {string.Join(",", a.Gateways)}");
            if (a.Dns.Count > 0) Console.WriteLine($"    DNS:  {string.Join(",", a.Dns)}");
        }
    }

    private static string Trunc(string s, int n) =>
        s.Length <= n ? s : s[..(n - 1)] + "…";
}

// ============================================================================
// IpConfig — static IP / DNS / suffix / MAC via netsh + PowerShell + registry.
// No WMI, no NuGet: everything here uses tools/APIs built into Windows.
// ============================================================================
internal static class IpConfig
{
    private static string Q(string iface) => $"\"{iface}\"";

    public static bool SetStaticIp(string iface, string ip, string mask, string? gateway)
    {
        // NOTE: an off-subnet gateway (like 169.254.254.254 for 172.20.10.0/24)
        // makes netsh print a warning but usually still applies the address.
        string gwPart = string.IsNullOrEmpty(gateway) ? "none" : $"{gateway} 1";
        var r = Sys.Netsh($"interface ip set address name={Q(iface)} static {ip} {mask} {gwPart}");
        Log.Info($"netsh set address -> exit {r.ExitCode}: {FirstLine(r.StdOut)} {FirstLine(r.StdErr)}".Trim());
        if (r.Success) return true;

        // Fallback: apply IP+mask without a gateway so sharing still works.
        Log.Warn("Gateway rejected; retrying without a gateway (IP+mask only).");
        var r2 = Sys.Netsh($"interface ip set address name={Q(iface)} static {ip} {mask} none");
        Log.Info($"netsh set address (no gw) -> exit {r2.ExitCode}");
        return r2.Success;
    }

    public static bool SetDhcp(string iface)
    {
        var a = Sys.Netsh($"interface ip set address name={Q(iface)} source=dhcp");
        var d = Sys.Netsh($"interface ip set dnsservers name={Q(iface)} source=dhcp");
        Log.Info($"netsh dhcp address -> {a.ExitCode}, dhcp dns -> {d.ExitCode}");
        return a.Success && d.Success;
    }

    public static bool SetDns(string iface, string primary, string? secondary)
    {
        // Clear stale entries first (ignored when the adapter uses DHCP).
        Sys.Netsh($"interface ip delete dnsservers name={Q(iface)} addr=all");
        var r1 = Sys.Netsh($"interface ip set dnsservers name={Q(iface)} static {primary} primary");
        Log.Info($"netsh set dns primary -> exit {r1.ExitCode}");
        bool ok = r1.Success;
        if (!string.IsNullOrWhiteSpace(secondary))
        {
            var r2 = Sys.Netsh($"interface ip add dnsservers name={Q(iface)} {secondary} index=2");
            Log.Info($"netsh add dns secondary -> exit {r2.ExitCode}");
            ok = ok && r2.Success;
        }
        return ok;
    }

    public static void FlushDns()
    {
        var r = Sys.Run("ipconfig", "/flushdns", 30_000);
        Log.Info($"ipconfig /flushdns -> exit {r.ExitCode}");
    }

    // Best-effort: mark the Ethernet network as Private so discovery/sharing
    // rules and the "Unidentified network" prompt behave.
    public static void SetPrivateProfile(string iface)
    {
        var r = Sys.PowerShell(
            $"Set-NetConnectionProfile -InterfaceAlias {Sys.PwshQuote(iface)} " +
            "-NetworkCategory Private -ErrorAction Stop");
        if (r.Success) Log.Ok("Network profile set to Private.");
        else Log.Warn("Could not set Private profile: " + FirstLine(r.StdErr));
    }

    // ---- DNS suffix (connection-specific, per adapter) --------------------
    private const string TcpipIfaces =
        @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

    public static string GetConnectionSuffix(string? adapterId)
    {
        if (!Sys.IsWindows() || string.IsNullOrEmpty(adapterId)) return "";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($"{TcpipIfaces}\\{adapterId}", false);
            return (key?.GetValue("Domain") as string) ?? "";
        }
        catch { return ""; }
    }

    public static bool SetConnectionSuffix(string iface, string? adapterId, string suffix)
    {
        bool ok = false;
        // Layer 1: registry value the TCP/IP stack actually reads.
        if (!string.IsNullOrEmpty(adapterId))
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($"{TcpipIfaces}\\{adapterId}", true);
                if (key != null)
                {
                    if (string.IsNullOrEmpty(suffix)) key.DeleteValue("Domain", false);
                    else key.SetValue("Domain", suffix, RegistryValueKind.String);
                    ok = true;
                    Log.Info($"Registry Domain suffix {(string.IsNullOrEmpty(suffix) ? "cleared" : $"set to '{suffix}'")}.");
                }
            }
            catch (Exception ex) { Log.Warn("Registry suffix write failed: " + ex.Message); }
        }
        // Layer 2: documented PowerShell cmdlet (updates the live profile).
        var r = Sys.PowerShell(
            string.IsNullOrEmpty(suffix)
                ? $"Set-DnsClient -InterfaceAlias {Sys.PwshQuote(iface)} -ConnectionSpecificSuffix '' -ErrorAction Stop"
                : $"Set-DnsClient -InterfaceAlias {Sys.PwshQuote(iface)} -ConnectionSpecificSuffix {Sys.PwshQuote(suffix)} -UseSuffixWhenRegistering $true -ErrorAction Stop");
        if (r.Success) { ok = true; Log.Info("Set-DnsClient suffix applied."); }
        else Log.Warn("Set-DnsClient failed: " + FirstLine(r.StdErr));
        return ok;
    }

    // ---- MAC spoof via "NetworkAddress" registry value --------------------
    private const string NetClassKey =
        @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";

    public static string? FindAdapterRegKey(string? adapterId, string description)
    {
        if (!Sys.IsWindows()) return null;
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(NetClassKey, false);
            if (root is null) return null;
            string normId = (adapterId ?? "").Trim('{', '}').ToLowerInvariant();
            string? descFallback = null;
            foreach (var sub in root.GetSubKeyNames())
            {
                if (sub.Length != 4) continue; // real adapters live in 0000, 0001, ...
                using var k = root.OpenSubKey(sub, false);
                if (k is null) continue;
                string cfgId = ((k.GetValue("NetCfgInstanceId") as string) ?? "").Trim('{', '}').ToLowerInvariant();
                if (!string.IsNullOrEmpty(normId) && cfgId == normId)
                    return $"{NetClassKey}\\{sub}";
                string desc = (k.GetValue("DriverDesc") as string) ?? "";
                if (!string.IsNullOrEmpty(description) &&
                    desc.Equals(description, StringComparison.OrdinalIgnoreCase))
                    descFallback = $"{NetClassKey}\\{sub}";
            }
            return descFallback;
        }
        catch (Exception ex)
        {
            Log.Warn("Adapter registry lookup failed: " + ex.Message);
            return null;
        }
    }

    // Returns (existed, oldValue). oldValue null when nothing was set.
    public static (bool existed, string? oldValue) GetMacOverride(string regKey)
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(regKey, false);
            var v = k?.GetValue("NetworkAddress") as string;
            return (v is not null, v);
        }
        catch { return (false, null); }
    }

    public static bool ValidateMac(string mac, out string plain)
    {
        plain = new string(mac.Where(c => Uri.IsHexDigit(c)).ToArray()).ToUpperInvariant();
        if (plain.Length != 12) return false;
        // Reject multicast addresses (LSB of first octet set): drivers refuse.
        int first = Convert.ToInt32(plain[..2], 16);
        return (first & 1) == 0;
    }

    public static bool SetMacOverride(string regKey, string mac)
    {
        if (!ValidateMac(mac, out string plain))
        {
            Log.Error($"Refusing to write invalid/multicast MAC '{mac}'.");
            return false;
        }
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(regKey, true);
            if (k is null) { Log.Error("Cannot open adapter registry key for writing."); return false; }
            k.SetValue("NetworkAddress", plain, RegistryValueKind.String);
            Log.Ok($"Registry NetworkAddress set to {plain} (shown as {mac}). Restarting adapter...");
            return true;
        }
        catch (Exception ex)
        {
            Log.Error("MAC registry write failed: " + ex.Message);
            return false;
        }
    }

    public static void ClearMacOverride(string regKey, bool existed, string? oldValue)
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(regKey, true);
            if (k is null) return;
            if (existed && oldValue is not null) k.SetValue("NetworkAddress", oldValue, RegistryValueKind.String);
            else k.DeleteValue("NetworkAddress", false);
            Log.Ok("MAC override restored to original.");
        }
        catch (Exception ex) { Log.Warn("MAC restore failed: " + ex.Message); }
    }

    // Restart so IP/MAC/registry changes take effect; waits for link-up.
    public static void RestartAdapter(string iface)
    {
        Log.Step($"Restarting adapter '{iface}'...");
        var r = Sys.PowerShell(
            $"$a = Get-NetAdapter -Name {Sys.PwshQuote(iface)} -ErrorAction Stop; " +
            "Restart-NetAdapter -InputObject $a -Confirm:$false -ErrorAction Stop");
        if (!r.Success)
        {
            Log.Warn("Restart-NetAdapter failed, trying disable/enable: " + FirstLine(r.StdErr));
            Sys.Netsh($"interface set interface {Q(iface)} admin=disable");
            Thread.Sleep(3000);
            Sys.Netsh($"interface set interface {Q(iface)} admin=enable");
        }
        // Poll for the link to come back (up to ~25 s).
        for (int i = 0; i < 25; i++)
        {
            Thread.Sleep(1000);
            var nic = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => n.Name.Equals(iface, StringComparison.OrdinalIgnoreCase));
            if (nic?.OperationalStatus == OperationalStatus.Up)
            {
                Log.Ok($"Adapter '{iface}' is back up.");
                return;
            }
        }
        Log.Warn($"Adapter '{iface}' did not report Up within 25 s (it may still recover).");
    }

    private static string FirstLine(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        int i = s.IndexOf('\n');
        return (i < 0 ? s : s[..i]).Trim();
    }
}

// ============================================================================
// Ics — Internet Connection Sharing via the documented HNetCfg COM API
// (the same engine behind the "Allow other network users to connect"
// checkbox). No NuGet: plain ComImport interfaces, early-bound in IDL order.
// ============================================================================
internal enum SharingConnectionType : int { Public = 0, Private = 1 }
internal enum SharingConnectionEnumFlags : int { Default = 0, Public = 1, Private = 2, All = 3 }

[ComImport, Guid("5C63C1AD-3956-4FF8-8486-40034758315B")]
internal class NetSharingManager { }

[ComImport, Guid("B92F52E6-90A5-4E69-8421-525ABF359F8D")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetSharingManager
{
    bool SharingInstalled { get; }
    [return: MarshalAs(UnmanagedType.Interface)]
    object get_EnumPublicConnections(SharingConnectionEnumFlags flags);
    [return: MarshalAs(UnmanagedType.Interface)]
    object get_EnumPrivateConnections(SharingConnectionEnumFlags flags);
    INetSharingEveryConnectionCollection get_EnumEveryConnection();
    // Slot kept with generic 'object' so we do not need the (undocumented
    // here) INetConnectionProps GUID; vtable order is what matters.
    [return: MarshalAs(UnmanagedType.Interface)]
    object get_NetConnectionProps([MarshalAs(UnmanagedType.Interface)] INetConnection connection);
    INetSharingConfiguration get_INetSharingConfigurationForINetConnection(
        [MarshalAs(UnmanagedType.Interface)] INetConnection connection);
}

[ComImport, Guid("C08956B8-1CD3-11D1-B1C5-00805FC1270E")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetSharingEveryConnectionCollection
{
    int Count { get; }
    [DispId(-4)] IEnumerator GetEnumerator(); // _NewEnum: standard tlbimp pattern
}

[ComImport, Guid("C08956B6-1CD3-11D1-B1C5-00805FC1270E")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetConnection
{
    void Connect();
    void Disconnect();
    [return: MarshalAs(UnmanagedType.Interface)] object Properties();
    string DeviceName { get; }
    int Status { get; }
    int Type { get; }
    uint Characteristics { get; }
    Guid Id { get; }
    string Name { get; }
}

[ComImport, Guid("C08956B7-1CD3-11D1-B1C5-00805FC1270E")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetSharingConfiguration
{
    bool SharingEnabled { get; }
    SharingConnectionType SharingConnectionType { get; }
    void DisableSharing();
    void EnableSharing(SharingConnectionType type);
}

internal sealed record IcsEntry(string Name, string Device, bool Enabled, string Kind);

internal static class Ics
{
    private static string NormId(string? id) =>
        (id ?? "").Trim().Trim('{', '}').ToLowerInvariant();

    private static bool IsMatch(string? name, string? device, Guid id, string wantName, string? wantId)
    {
        if (!string.IsNullOrEmpty(name) &&
            name.Equals(wantName, StringComparison.OrdinalIgnoreCase)) return true;
        if (!string.IsNullOrEmpty(wantId) && NormId(id.ToString()) == NormId(wantId)) return true;
        return false;
    }

    // Read one connection defensively: a single failing property must not
    // abort the whole enumeration.
    private static (string? name, string? device, Guid id) Describe(INetConnection c)
    {
        string? n = null, d = null;
        Guid g = Guid.Empty;
        try { n = c.Name; } catch { }
        try { d = c.DeviceName; } catch { }
        try { g = c.Id; } catch { }
        return (n, d, g);
    }

    public static bool TryEnable(string publicName, string? publicId,
                                 string privateName, string? privateId,
                                 out string message)
    {
        message = "";
        if (!Sys.IsWindows()) { message = "ICS requires Windows."; return false; }

        INetSharingManager? mgr = null;
        var rcws = new List<object>(); // every RCW we touch, released in finally
        try
        {
            mgr = (INetSharingManager)new NetSharingManager();
            rcws.Add(mgr);

            if (!mgr.SharingInstalled)
            {
                message = "ICS is not installed on this Windows edition.";
                return false;
            }

            var every = mgr.get_EnumEveryConnection();
            rcws.Add(every);

            INetConnection? pub = null, prv = null;
            Log.Info("Enumerating network connections visible to ICS:");
            foreach (object? o in every)
            {
                if (o is not INetConnection c) continue;
                rcws.Add(c);
                var (n, d, g) = Describe(c);
                Log.Info($"  Name='{n ?? "?"}'  Device='{d ?? "?"}'  Id={g}");
                if (pub is null && IsMatch(n, d, g, publicName, publicId)) pub = c;
                if (prv is null && IsMatch(n, d, g, privateName, privateId)) prv = c;
            }

            if (pub is null) { message = $"Public (Wi-Fi) connection '{publicName}' not found by ICS."; return false; }
            if (prv is null) { message = $"Private (Ethernet) connection '{privateName}' not found by ICS."; return false; }
            if (ReferenceEquals(pub, prv)) { message = "Public and private resolved to the SAME connection."; return false; }

            // Clear any existing sharing first (handles "already shared" and
            // the one-shared-connection-at-a-time Windows limit).
            foreach (object? o in every)
            {
                if (o is not INetConnection c) continue;
                try
                {
                    var cfg = mgr.get_INetSharingConfigurationForINetConnection(c);
                    rcws.Add(cfg);
                    if (cfg.SharingEnabled)
                    {
                        var (n, _, _) = Describe(c);
                        Log.Step($"Disabling old sharing on '{n}'...");
                        cfg.DisableSharing();
                        Thread.Sleep(800);
                    }
                }
                catch (Exception ex) { Log.Warn("DisableSharing note: " + ex.Message); }
            }

            Log.Step($"Enabling ICS: public='{publicName}' private='{privateName}'...");
            var pubCfg = mgr.get_INetSharingConfigurationForINetConnection(pub);
            rcws.Add(pubCfg);
            pubCfg.EnableSharing(SharingConnectionType.Public);
            Thread.Sleep(1500);

            var prvCfg = mgr.get_INetSharingConfigurationForINetConnection(prv);
            rcws.Add(prvCfg);
            prvCfg.EnableSharing(SharingConnectionType.Private);
            Thread.Sleep(1500);

            // Verify both ends actually report sharing.
            bool pubOk = SafeEnabled(mgr, pub, rcws), prvOk = SafeEnabled(mgr, prv, rcws);
            if (pubOk && prvOk)
            {
                message = "ICS enabled.";
                return true;
            }
            message = $"ICS partially applied (public={pubOk}, private={prvOk}).";
            return pubOk || prvOk;
        }
        catch (COMException ex)
        {
            message = $"ICS COM error 0x{ex.ErrorCode:X8}: {ex.Message}. " +
                      "Fallback: open ncpa.cpl > Wi-Fi adapter > Properties > Sharing tab > " +
                      "check 'Allow other network users...' and pick the Ethernet adapter.";
            return false;
        }
        catch (Exception ex)
        {
            message = "ICS failed: " + ex.Message;
            return false;
        }
        finally
        {
            foreach (var r in rcws)
                try { Marshal.ReleaseComObject(r); } catch { }
        }
    }

    private static bool SafeEnabled(INetSharingManager mgr, INetConnection c, List<object> rcws)
    {
        try
        {
            var cfg = mgr.get_INetSharingConfigurationForINetConnection(c);
            rcws.Add(cfg);
            return cfg.SharingEnabled;
        }
        catch { return false; }
    }

    public static bool TryDisable(out string message)
    {
        message = "";
        if (!Sys.IsWindows()) { message = "ICS requires Windows."; return false; }
        INetSharingManager? mgr = null;
        var rcws = new List<object>();
        try
        {
            mgr = (INetSharingManager)new NetSharingManager();
            rcws.Add(mgr);
            if (!mgr.SharingInstalled) { message = "ICS not installed; nothing to disable."; return true; }
            var every = mgr.get_EnumEveryConnection();
            rcws.Add(every);
            int count = 0;
            foreach (object? o in every)
            {
                if (o is not INetConnection c) continue;
                rcws.Add(c);
                try
                {
                    var cfg = mgr.get_INetSharingConfigurationForINetConnection(c);
                    rcws.Add(cfg);
                    if (cfg.SharingEnabled)
                    {
                        var (n, _, _) = Describe(c);
                        Log.Step($"Disabling sharing on '{n}'...");
                        cfg.DisableSharing();
                        count++;
                        Thread.Sleep(500);
                    }
                }
                catch (Exception ex) { Log.Warn("DisableSharing note: " + ex.Message); }
            }
            message = count == 0 ? "No shared connections found." : $"Disabled sharing on {count} connection(s).";
            return true;
        }
        catch (Exception ex)
        {
            message = "Disable ICS failed: " + ex.Message;
            return false;
        }
        finally
        {
            foreach (var r in rcws)
                try { Marshal.ReleaseComObject(r); } catch { }
        }
    }

    public static List<IcsEntry> GetStatus()
    {
        var result = new List<IcsEntry>();
        if (!Sys.IsWindows()) return result;
        INetSharingManager? mgr = null;
        var rcws = new List<object>();
        try
        {
            mgr = (INetSharingManager)new NetSharingManager();
            rcws.Add(mgr);
            if (!mgr.SharingInstalled) return result;
            var every = mgr.get_EnumEveryConnection();
            rcws.Add(every);
            foreach (object? o in every)
            {
                if (o is not INetConnection c) continue;
                rcws.Add(c);
                var (n, d, _) = Describe(c);
                bool en = false;
                string kind = "-";
                try
                {
                    var cfg = mgr.get_INetSharingConfigurationForINetConnection(c);
                    rcws.Add(cfg);
                    en = cfg.SharingEnabled;
                    if (en) kind = cfg.SharingConnectionType == SharingConnectionType.Public ? "PUBLIC" : "PRIVATE";
                }
                catch { }
                result.Add(new IcsEntry(n ?? "?", d ?? "?", en, kind));
            }
        }
        catch { /* status must never throw */ }
        finally
        {
            foreach (var r in rcws)
                try { Marshal.ReleaseComObject(r); } catch { }
        }
        return result;
    }
}

// ============================================================================
// Sharing — firewall rules, helper services, SMB share, HTTP firewall port.
// ============================================================================
internal static class Sharing
{
    public static void EnsureFirewallAndServices()
    {
        Log.Step("Enabling File and Printer Sharing + Network Discovery firewall rules...");
        var r1 = Sys.Netsh(@"advfirewall firewall set rule group=""File and Printer Sharing"" new enable=Yes");
        Log.Info($"File/Printer Sharing rule -> exit {r1.ExitCode}");
        var r2 = Sys.Netsh(@"advfirewall firewall set rule group=""Network Discovery"" new enable=Yes");
        Log.Info($"Network Discovery rule -> exit {r2.ExitCode}");
        if (!r1.Success || !r2.Success)
            Log.Warn("One or more firewall groups could not be enabled (see above).");

        // Helper services file sharing depends on. 'sc config/start' works
        // on every Windows edition without extra APIs.
        foreach (var svc in new[] { "LanmanServer", "SSDPSRV", "FDResPub" })
        {
            var c = Sys.Run("sc", $"config {svc} start= auto", 30_000);
            var s = Sys.Run("sc", $"start {svc}", 30_000);
            bool running = s.Success || s.StdOut.Contains("START_PENDING") ||
                           s.StdOut.Contains("RUNNING") || s.StdOut.Contains("1056");
            Log.Info($"Service {svc}: config={c.ExitCode} start={(running ? "running" : "FAILED: " + s.StdOut)}");
            if (!running) Log.Warn($"Service {svc} is not running; file sharing may fail.");
        }
    }

    // Create (or recreate) an SMB share with full access for Everyone.
    // Uses the Everyone SID (*S-1-1-0) for icacls so it works on any locale.
    public static bool EnsureShare(string folder, string shareName)
    {
        try
        {
            Directory.CreateDirectory(folder);
            Log.Ok($"Folder ready: {folder}");
        }
        catch (Exception ex)
        {
            Log.Error("Cannot create folder: " + ex.Message);
            return false;
        }

        var acl = Sys.Run("icacls", $"\"{folder}\" /grant *S-1-1-0:(OI)(CI)F /T /Q", 60_000);
        Log.Info($"icacls -> exit {acl.ExitCode}");
        if (!acl.Success) Log.Warn("icacls failed; share may be read-only for guests.");

        Sys.Run("net", $"share {shareName} /delete /y", 30_000); // ignore errors
        var r = Sys.Run("net",
            $"share {shareName}=\"{folder}\" /GRANT:Everyone,FULL /REMARK:\"WifiShare file drop\"", 60_000);
        if (r.Success)
        {
            Log.Ok($"SMB share created: \\\\{Environment.MachineName}\\{shareName}");
            return true;
        }
        Log.Error($"net share failed (exit {r.ExitCode}): {r.StdOut} {r.StdErr}");
        Log.Info("Fallback: right-click the folder > Properties > Sharing > Advanced Sharing.");
        return false;
    }

    public static void RemoveShare(string shareName)
    {
        var r = Sys.Run("net", $"share {shareName} /delete /y", 30_000);
        Log.Info($"net share delete -> exit {r.ExitCode} (0 = removed, 2 = did not exist)");
    }

    public static string GetShareTable()
    {
        var r = Sys.Run("net", "share", 30_000);
        return r.Success ? r.StdOut : "(could not query shares)";
    }

    public static void OpenHttpPort(int port, bool open)
    {
        string rule = $"WifiShare HTTP {port}";
        if (open)
        {
            var r = Sys.Netsh($"advfirewall firewall add rule name=\"{rule}\" dir=in action=allow " +
                              $"protocol=TCP localport={port} profile=private");
            Log.Info($"HTTP firewall rule -> exit {r.ExitCode}");
        }
        else
        {
            Sys.Netsh($"advfirewall firewall delete rule name=\"{rule}\" protocol=TCP localport={port}");
        }
    }

    // DHCP listens on UDP 67 (server) and answers to UDP 68 (client).
    // Inbound 67 must be open on the Private profile; outbound answers to a
    // broadcast address are allowed by default, but we open 68 too so a
    // locked-down firewall cannot break renewals.
    public static void OpenDhcpPort(bool open)
    {
        const string rule = "WifiShare DHCP";
        if (open)
        {
            var r = Sys.Netsh($"advfirewall firewall add rule name=\"{rule}\" dir=in action=allow " +
                              "protocol=UDP localport=67 profile=private");
            Log.Info($"DHCP firewall rule -> exit {r.ExitCode}");
        }
        else
        {
            Sys.Netsh($"advfirewall firewall delete rule name=\"{rule}\" protocol=UDP localport=67");
        }
    }
}

// ============================================================================
// DHCP — minimal plug-and-play server (RFC 2131 subset) so the client "just
// works" when the cable is plugged in.
//
// WHY OUR OWN DHCP SERVER? The built-in ICS allocator only serves the
// hardcoded 192.168.137.0/24 range (its scope lives in the undocumented
// SharedAccess\Parameters registry keys and behaves differently per Windows
// build), offers ITSELF as DNS, and never sends a domain name. A client with
// preconfiguration (expects 172.20.10.x, DNS 172.16.61.20, domain
// mydomain.net) would reject all of that. Our server offers exactly:
//   pool 172.20.10.100-200, mask /24, router 172.20.10.185,
//   DNS 172.16.61.20 (+ .10), domain mydomain.net, 24 h leases.
// It also NAKs out-of-pool REQUESTs, which heals a stray 192.168.137.x lease
// (from the ICS allocator, if it ever answers) within seconds.
//
// CONFLICT NOTE: only one program can own UDP port 67 per interface. We bind
// EXCLUSIVELY to 172.20.10.185:67 so we never steal DHCP on the Wi-Fi side.
// If the bind fails, the ICS allocator is holding the port: the program logs
// remediation steps and continues (client falls back to static IP).
// No NuGet, no P/Invoke: one UDP Socket + manual packet codec below.
// ============================================================================

// Fixed configuration for one DHCP scope (validated in the constructor).
internal sealed class DhcpScope
{
    public IPAddress ServerIp { get; }
    public IPAddress Mask { get; }
    public IPAddress Router { get; }
    public List<IPAddress> Dns { get; }
    public string Domain { get; }
    public IPAddress PoolStart { get; }
    public IPAddress PoolEnd { get; }
    public int LeaseSeconds { get; }
    public IPAddress Broadcast { get; }

    public DhcpScope(IPAddress serverIp, IPAddress mask, IPAddress router,
                     List<IPAddress> dns, string domain,
                     IPAddress poolStart, IPAddress poolEnd, int leaseSeconds)
    {
        if (dns is null || dns.Count == 0) throw new ArgumentException("At least one DNS server is required.");
        if (leaseSeconds < 60) throw new ArgumentException("Lease time must be >= 60 seconds.");
        ServerIp = serverIp; Mask = mask; Router = router;
        Dns = dns; Domain = domain ?? "";
        PoolStart = poolStart; PoolEnd = poolEnd; LeaseSeconds = leaseSeconds;

        uint m = DhcpPacket.ToUInt(mask);
        uint net = DhcpPacket.ToUInt(serverIp) & m;
        Broadcast = DhcpPacket.ToIp(net | ~m);
        // Pool must be a sane range inside our own subnet.
        if (DhcpPacket.ToUInt(poolStart) > DhcpPacket.ToUInt(poolEnd))
            throw new ArgumentException("DHCP pool start must be <= pool end.");
        foreach (var p in new[] { poolStart, poolEnd })
            if ((DhcpPacket.ToUInt(p) & m) != net)
                throw new ArgumentException($"Pool address {p} is outside {serverIp}/{PrefixOf(mask)}.");
    }

    private static int PrefixOf(IPAddress mask)
    {
        // Count the 1-bits: 255.255.255.0 -> 24.
        uint m = DhcpPacket.ToUInt(mask);
        int n = 0;
        while (m != 0) { n += (int)(m & 1); m >>= 1; }
        return n;
    }
}

// One granted lease, persisted to dhcp-leases.json so restarts are stable.
internal sealed class DhcpLeaseRecord
{
    public string Mac { get; set; } = "";
    public string Ip { get; set; } = "";
    public DateTime ExpiryUtc { get; set; }
    public string HostName { get; set; } = "";
}

// Raw DHCP packet codec: 236-byte header + magic cookie + TLV options.
internal static class DhcpPacket
{
    // DHCP message types (option 53).
    public const byte Discover = 1, Offer = 2, Request = 3, Decline = 4;
    public const byte Ack = 5, Nak = 6, Release = 7, Inform = 8;

    public sealed class Message
    {
        public byte Op;                 // 1 = BOOTREQUEST (client -> server)
        public uint Xid;                // transaction id, echoed in replies
        public ushort Flags;            // bit 15: client wants broadcast reply
        public IPAddress CIAddr = IPAddress.Any;  // client IP (renewals)
        public byte[] ChAddr = Array.Empty<byte>(); // client MAC (hlen bytes)
        public Dictionary<byte, byte[]> Options = new();
        public byte MsgType;            // option 53, 0 when absent
    }

    // Big-endian IP <-> uint helpers (pool arithmetic needs integers).
    public static uint ToUInt(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        if (b.Length != 4) throw new ArgumentException("IPv4 only.");
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    public static IPAddress ToIp(uint v) =>
        new(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });

    private static uint ReadU32(byte[] b, int o) =>
        ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3];

    private static void WriteU32(List<byte> out_, uint v)
    {
        out_.Add((byte)(v >> 24)); out_.Add((byte)(v >> 16));
        out_.Add((byte)(v >> 8)); out_.Add((byte)v);
    }

    // Parse + validate. Returns null for anything that is not a well-formed
    // client DHCP packet (wrong size, bad magic cookie, not BOOTREQUEST...).
    public static Message? Parse(byte[] buf, int len)
    {
        if (buf is null || len < 240 || buf.Length < len) return null;
        if (buf[0] != 1 || buf[1] != 1 || buf[2] != 6) return null; // op/htype/hlen
        if (buf[236] != 99 || buf[237] != 130 || buf[238] != 83 || buf[239] != 99) return null;
        var m = new Message
        {
            Op = buf[0],
            Xid = ReadU32(buf, 4),
            Flags = (ushort)((buf[10] << 8) | buf[11]),
            CIAddr = new IPAddress(new[] { buf[12], buf[13], buf[14], buf[15] }),
            ChAddr = buf.Skip(28).Take(6).ToArray(),
        };
        int i = 240;
        while (i < len)
        {
            byte code = buf[i++];
            if (code == 0) continue;   // pad
            if (code == 255) break;    // end
            if (i >= len) return null; // truncated length byte
            byte optLen = buf[i++];
            if (i + optLen > len) return null; // truncated value
            m.Options[code] = buf.Skip(i).Take(optLen).ToArray();
            i += optLen;
        }
        if (m.Options.TryGetValue(53, out var t) && t.Length == 1) m.MsgType = t[0];
        return m;
    }

    private static void AddOpt(List<byte> out_, byte code, byte[] value)
    {
        out_.Add(code); out_.Add((byte)value.Length);
        out_.AddRange(value);
    }

    // Build OFFER / ACK / NAK. Echoes xid + broadcast flag + chaddr so the
    // (still address-less) client recognises its own transaction.
    public static byte[] Build(byte msgType, Message req, IPAddress yiaddr,
                               DhcpScope scope, string? nakText = null)
    {
        var p = new List<byte>(300);
        p.Add(2); p.Add(1); p.Add(6); p.Add(0);            // op=reply, eth, maclen, hops
        WriteU32(p, req.Xid);                             // xid
        p.Add(0); p.Add(0);                               // secs
        p.Add((byte)(req.Flags >> 8)); p.Add((byte)req.Flags); // flags echo
        p.AddRange(req.CIAddr.GetAddressBytes());          // ciaddr echo
        p.AddRange(yiaddr.GetAddressBytes());              // yiaddr (0.0.0.0 for NAK/INFORM)
        p.AddRange(scope.ServerIp.GetAddressBytes());      // siaddr = us
        p.AddRange(new byte[4]);                           // giaddr = 0
        var ch = new byte[16];                             // chaddr padded to 16
        Array.Copy(req.ChAddr, ch, Math.Min(req.ChAddr.Length, 16));
        p.AddRange(ch);
        p.AddRange(new byte[64]);                          // sname (unused)
        p.AddRange(new byte[128]);                         // file (unused)
        p.Add(99); p.Add(130); p.Add(83); p.Add(99);       // magic cookie

        var sid = scope.ServerIp.GetAddressBytes();
        AddOpt(p, 53, new[] { msgType });
        AddOpt(p, 54, sid);
        if (msgType == Offer || msgType == Ack)
        {
            var tmp = new List<byte>();
            WriteU32(tmp, (uint)scope.LeaseSeconds); AddOpt(p, 51, tmp.ToArray());
            AddOpt(p, 1, scope.Mask.GetAddressBytes());
            AddOpt(p, 3, scope.Router.GetAddressBytes());
            var dns = new List<byte>();
            foreach (var d in scope.Dns) dns.AddRange(d.GetAddressBytes());
            AddOpt(p, 6, dns.ToArray());
            if (!string.IsNullOrEmpty(scope.Domain))
                AddOpt(p, 15, Encoding.ASCII.GetBytes(scope.Domain));
            AddOpt(p, 28, scope.Broadcast.GetAddressBytes());
            tmp.Clear(); WriteU32(tmp, (uint)(scope.LeaseSeconds / 2)); AddOpt(p, 58, tmp.ToArray());
            tmp.Clear(); WriteU32(tmp, (uint)(scope.LeaseSeconds * 7 / 8)); AddOpt(p, 59, tmp.ToArray());
        }
        else if (msgType == Nak && !string.IsNullOrEmpty(nakText))
        {
            AddOpt(p, 56, Encoding.ASCII.GetBytes(nakText)); // human-readable reason
        }
        p.Add(255);                                        // end
        while (p.Count < 300) p.Add(0);                    // BOOTP minimum size
        return p.ToArray();
    }
}

// The server itself: one UDP socket, one background loop, in-memory leases
// with JSON persistence. Handles DISCOVER/OFFER, REQUEST/ACK/NAK,
// DECLINE, RELEASE and INFORM for a single-cable client setup.
internal sealed class DhcpServer : IDisposable
{
    private readonly DhcpScope _scope;
    private readonly int _listenPort;      // 67 in production
    private readonly int _peerPort;        // 68 in production
    private readonly bool _broadcastReplies; // false = unicast to sender (tests)
    private readonly string _leaseFile;
    private Socket? _sock;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private readonly Dictionary<string, DhcpLeaseRecord> _leases = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (string ip, DateTime until)> _offers = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _declined = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private bool _disposed;

    public bool Running { get; private set; }
    public string PoolSummary => $"{_scope.PoolStart} - {_scope.PoolEnd}";
    public string LeaseSummary => $"{_scope.LeaseSeconds / 3600} h lease, router {_scope.Router}, " +
                                  $"dns {string.Join(",", _scope.Dns)}, domain '{_scope.Domain}'";

    public DhcpServer(DhcpScope scope, string? leaseFile = null,
                      int listenPort = 67, int peerPort = 68, bool broadcastReplies = true)
    {
        _scope = scope;
        _leaseFile = leaseFile ?? Path.Combine(AppContext.BaseDirectory, "dhcp-leases.json");
        _listenPort = listenPort; _peerPort = peerPort; _broadcastReplies = broadcastReplies;
    }

    public bool Start(out string message)
    {
        message = "";
        try
        {
            LoadLeases();
            Stop(); // idempotent
            var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            // Exclusive bind: fail loudly on conflict instead of fighting another server.
            sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse, true);
            sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
            sock.ReceiveTimeout = 1000; // lets the loop notice cancellation promptly
            // Bind ONLY our Ethernet IP: never answer DHCP on the Wi-Fi side.
            sock.Bind(new IPEndPoint(_scope.ServerIp, _listenPort));
            _sock = sock;
            _cts = new CancellationTokenSource();
            _loop = Task.Run(() => RecvLoop(_cts.Token));
            Running = true;
            message = $"serving {PoolSummary} on {_scope.ServerIp}:{_listenPort}";
            return true;
        }
        catch (SocketException ex)
        {
            message = $"UDP {_scope.ServerIp}:{_listenPort} is busy (error {ex.ErrorCode}). " +
                      (_listenPort == 67
                        ? "Another DHCP server (usually the ICS built-in allocator) holds port 67. " +
                          "Remedy: Stop sharing, disable/re-enable ICS, reboot, then Start again. " +
                          "The client can still use the static IP from the instructions."
                        : ex.Message);
            return false;
        }
        catch (Exception ex) { message = ex.Message; return false; }
    }

    public void Stop()
    {
        Running = false;
        try { _cts?.Cancel(); } catch { }
        try { _sock?.Close(); } catch { }
        _sock = null;
        try { _loop?.Wait(2000); } catch { }
        _cts?.Dispose(); _cts = null;
    }

    public List<DhcpLeaseRecord> GetLeases()
    {
        lock (_gate)
        {
            PruneLocked();
            return _leases.Values
                .OrderBy(l => DhcpPacket.ToUInt(IPAddress.Parse(l.Ip)))
                .Select(l => new DhcpLeaseRecord { Mac = l.Mac, Ip = l.Ip, ExpiryUtc = l.ExpiryUtc, HostName = l.HostName })
                .ToList();
        }
    }

    // ---- receive loop -------------------------------------------------------
    private void RecvLoop(CancellationToken ct)
    {
        var buf = new byte[1500];
        while (!ct.IsCancellationRequested)
        {
            EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
            int n;
            try { n = _sock!.ReceiveFrom(buf, ref remote); }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut) { continue; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { if (ct.IsCancellationRequested) break; continue; }
            catch { break; }
            try { Handle(buf, n, remote); }
            catch (Exception ex) { Log.Warn("DHCP handler error: " + ex.Message); }
        }
    }

    private void Handle(byte[] buf, int n, EndPoint remote)
    {
        var msg = DhcpPacket.Parse(buf, n);
        if (msg is null || msg.MsgType == 0) return; // not a client DHCP message
        string mac = MacKey(msg);
        string host = HostNameOf(msg);
        switch (msg.MsgType)
        {
            case DhcpPacket.Discover: OnDiscover(msg, mac, host, remote); break;
            case DhcpPacket.Request: OnRequest(msg, mac, host, remote); break;
            case DhcpPacket.Decline: OnDecline(msg, mac); break;
            case DhcpPacket.Release: OnRelease(msg, mac); break;
            case DhcpPacket.Inform: OnInform(msg, mac, remote); break;
        }
    }

    // Lease key = MAC (+ DHCP client-id option 61 when the client sends one).
    private static string MacKey(DhcpPacket.Message msg)
    {
        string mac = BitConverter.ToString(msg.ChAddr).Replace("-", "");
        if (msg.Options.TryGetValue(61, out var cid) && cid.Length > 0)
            mac += "|" + BitConverter.ToString(cid).Replace("-", "");
        return mac;
    }

    private static string HostNameOf(DhcpPacket.Message msg)
    {
        if (!msg.Options.TryGetValue(12, out var raw) || raw.Length == 0) return "";
        var s = Encoding.ASCII.GetString(raw);
        return new string(s.Where(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.').ToArray());
    }

    private static string? OptIp(DhcpPacket.Message msg, byte code)
    {
        if (msg.Options.TryGetValue(code, out var v) && v.Length == 4)
            return new IPAddress(v).ToString();
        return null;
    }

    // ---- DISCOVER ------------------------------------------------------------
    private void OnDiscover(DhcpPacket.Message msg, string mac, string host, EndPoint remote)
    {
        string? want = OptIp(msg, 50); // client may request a specific IP
        string? ip;
        lock (_gate)
        {
            PruneLocked();
            ip = FindForMacLocked(mac)                                   // stable IP: same client, same IP
                 ?? (want is not null && IsOfferableLocked(want, mac) ? want : null)
                 ?? AllocateNewLocked(mac);
            if (ip is not null) _offers[mac] = (ip, DateTime.UtcNow.AddSeconds(60));
        }
        if (ip is null) { Log.Warn($"DHCP pool exhausted for {mac} ({host})."); return; }
        Send(DhcpPacket.Offer, msg, IPAddress.Parse(ip), remote);
        Log.Info($"DHCP OFFER {ip} -> {mac} ({host})");
    }

    // ---- REQUEST --------------------------------------------------------------
    private void OnRequest(DhcpPacket.Message msg, string mac, string host, EndPoint remote)
    {
        string? serverId = OptIp(msg, 54);
        string? want = OptIp(msg, 50);
        bool fromOurs = serverId is null || serverId == _scope.ServerIp.ToString();
        if (!fromOurs) return; // SELECTING against another server: stay silent.

        lock (_gate)
        {
            PruneLocked();
            // Case A: SELECTING — client accepted our OFFER (server-id present).
            if (serverId is not null)
            {
                if (_offers.TryGetValue(mac, out var pend) &&
                    (want is null || want == pend.ip) && IsOfferableLocked(pend.ip, mac))
                { GrantLocked(mac, host, pend.ip); Send(DhcpPacket.Ack, msg, IPAddress.Parse(pend.ip), remote); return; }
                if (want is not null && IsOfferableLocked(want, mac))
                { GrantLocked(mac, host, want); Send(DhcpPacket.Ack, msg, IPAddress.Parse(want), remote); return; }
                Send(DhcpPacket.Nak, msg, IPAddress.Any, remote, "address unavailable");
                Log.Warn($"DHCP NAK -> {mac} ({host}): requested {want ?? pend.ip} unavailable");
                return;
            }
            // Case B: INIT-REBOOT — client reboots with a previous address.
            if (want is not null)
            {
                if (!InSubnet(want))
                {
                    // Wrong network (e.g. a stale 192.168.137.x lease from the ICS
                    // allocator): NAK so the client restarts discovery at once.
                    Send(DhcpPacket.Nak, msg, IPAddress.Any, remote, "wrong network");
                    Log.Info($"DHCP NAK -> {mac}: {want} is outside our subnet (re-discover)");
                    return;
                }
                if (FindForMacLocked(mac) == want || IsOfferableLocked(want, mac))
                { GrantLocked(mac, host, want); Send(DhcpPacket.Ack, msg, IPAddress.Parse(want), remote); return; }
                return; // taken by someone else: stay silent per RFC 2131.
            }
            // Case C: RENEW/REBIND — ciaddr set, client keeps using its address.
            string ci = msg.CIAddr.ToString();
            if (FindForMacLocked(mac) == ci)
            { GrantLocked(mac, host, ci); Send(DhcpPacket.Ack, msg, IPAddress.Parse(ci), remote); return; }
            // Unknown or expired binding: NAK to force a fast fresh DISCOVER.
            Send(DhcpPacket.Nak, msg, IPAddress.Any, remote, "lease expired");
            Log.Info($"DHCP NAK -> {mac}: no binding for {ci} (re-discover)");
        }
    }

    // ---- DECLINE / RELEASE / INFORM --------------------------------------------
    private void OnDecline(DhcpPacket.Message msg, string mac)
    {
        string? bad = OptIp(msg, 50);
        if (bad is null) return;
        lock (_gate)
        {
            foreach (var kv in _leases.Where(kv => kv.Value.Ip == bad).ToList()) _leases.Remove(kv.Key);
            foreach (var kv in _offers.Where(kv => kv.Value.ip == bad).ToList()) _offers.Remove(kv.Key);
            _declined[bad] = DateTime.UtcNow.AddMinutes(10); // quarantine, then reusable
            PersistLocked();
        }
        Log.Warn($"DHCP DECLINE from {mac}: {bad} quarantined 10 min (possible IP conflict)");
    }

    private void OnRelease(DhcpPacket.Message msg, string mac)
    {
        lock (_gate)
        {
            string ci = msg.CIAddr.ToString();
            if (_leases.TryGetValue(mac, out var l) && l.Ip == ci)
            {
                _leases.Remove(mac);
                PersistLocked();
                Log.Info($"DHCP RELEASE {ci} <- {mac}");
            }
        }
    }

    private void OnInform(DhcpPacket.Message msg, string mac, EndPoint remote)
    {
        // Client has an IP, only wants options: ACK with config, no lease.
        Send(DhcpPacket.Ack, msg, IPAddress.Any, remote);
        Log.Info($"DHCP INFORM -> {mac}: options sent");
    }

    // ---- lease bookkeeping (caller must hold _gate) ------------------------------
    private void PruneLocked()
    {
        foreach (var kv in _leases.Where(kv => kv.Value.ExpiryUtc <= DateTime.UtcNow).ToList())
            _leases.Remove(kv.Key);
        foreach (var kv in _offers.Where(kv => kv.Value.until <= DateTime.UtcNow).ToList())
            _offers.Remove(kv.Key);
        foreach (var kv in _declined.Where(kv => kv.Value <= DateTime.UtcNow).ToList())
            _declined.Remove(kv.Key);
    }

    private string? FindForMacLocked(string mac) =>
        _leases.TryGetValue(mac, out var l) && l.ExpiryUtc > DateTime.UtcNow ? l.Ip : null;

    private bool InSubnet(string ip)
    {
        uint m = DhcpPacket.ToUInt(_scope.Mask);
        return (DhcpPacket.ToUInt(IPAddress.Parse(ip)) & m) == (DhcpPacket.ToUInt(_scope.ServerIp) & m);
    }

    private bool IsOfferableLocked(string ip, string forMac)
    {
        if (!InSubnet(ip)) return false;
        uint v = DhcpPacket.ToUInt(IPAddress.Parse(ip));
        uint net = DhcpPacket.ToUInt(_scope.ServerIp) & DhcpPacket.ToUInt(_scope.Mask);
        uint bcast = DhcpPacket.ToUInt(_scope.Broadcast);
        if (v == net || v == bcast) return false;                 // network/broadcast
        if (ip == _scope.ServerIp.ToString()) return false;       // ourselves
        if (ip == _scope.Router.ToString() && ip != _scope.ServerIp.ToString()) return false;
        if (_declined.ContainsKey(ip)) return false;              // quarantined
        if (_leases.TryGetValue(forMac, out var own) && own.Ip == ip) return true;
        if (_leases.Values.Any(l => l.Ip == ip)) return false;    // held by another client
        // A pending offer to ANOTHER client blocks; our own pending offer
        // must never block us (SELECTING/INIT-REBOOT would NAK itself).
        if (_offers.Any(kv => kv.Value.ip == ip &&
            !kv.Key.Equals(forMac, StringComparison.OrdinalIgnoreCase))) return false;
        return true;
    }

    private string? AllocateNewLocked(string forMac)
    {
        uint from = DhcpPacket.ToUInt(_scope.PoolStart);
        uint to = DhcpPacket.ToUInt(_scope.PoolEnd);
        for (uint v = from; v <= to; v++)
        {
            string ip = DhcpPacket.ToIp(v).ToString();
            if (!IsOfferableLocked(ip, forMac)) continue;
            if (IsAliveOnWire(ip)) { Log.Warn($"DHCP: {ip} answers ping, skipping (in use)"); continue; }
            return ip;
        }
        return null;
    }

    // Address-conflict detection: never offer an IP that already answers.
    // A failed ping (firewalled host, no permission) counts as "free".
    private static bool IsAliveOnWire(string ip)
    {
        try
        {
            using var ping = new Ping();
            var r = ping.Send(IPAddress.Parse(ip), 350);
            return r?.Status == IPStatus.Success;
        }
        catch { return false; }
    }

    private void GrantLocked(string mac, string host, string ip)
    {
        _leases[mac] = new DhcpLeaseRecord
        {
            Mac = mac, Ip = ip, HostName = host,
            ExpiryUtc = DateTime.UtcNow.AddSeconds(_scope.LeaseSeconds),
        };
        _offers.Remove(mac);
        PersistLocked();
        Log.Ok($"DHCP ACK {ip} -> {mac} ({host}), lease {_scope.LeaseSeconds / 3600} h");
    }

    private void Send(byte msgType, DhcpPacket.Message req, IPAddress yiaddr,
                      EndPoint remote, string? nakText = null)
    {
        try
        {
            byte[] pkt = DhcpPacket.Build(msgType, req, yiaddr, _scope, nakText);
            // Production: broadcast so the address-less client hears us.
            // Tests run with broadcastReplies=false: unicast back to the sender.
            EndPoint dest = _broadcastReplies
                ? new IPEndPoint(IPAddress.Broadcast, _peerPort)
                : remote;
            _sock?.SendTo(pkt, dest);
        }
        catch (Exception ex) { Log.Warn("DHCP send failed: " + ex.Message); }
    }

    // ---- persistence -------------------------------------------------------------
    private void PersistLocked()
    {
        try
        {
            var json = JsonSerializer.Serialize(_leases.Values.ToList(),
                new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_leaseFile, json, Encoding.UTF8);
        }
        catch { /* leases are best-effort persistence, never fatal */ }
    }

    private void LoadLeases()
    {
        try
        {
            if (!File.Exists(_leaseFile)) return;
            var list = JsonSerializer.Deserialize<List<DhcpLeaseRecord>>(
                File.ReadAllText(_leaseFile, Encoding.UTF8));
            if (list is null) return;
            lock (_gate)
            {
                foreach (var l in list)
                    if (!string.IsNullOrEmpty(l.Mac) && !string.IsNullOrEmpty(l.Ip))
                        _leases[l.Mac] = l;
                PruneLocked();
            }
            Log.Info($"DHCP: loaded {list.Count} saved lease(s).");
        }
        catch { /* corrupt file: start fresh */ }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }
}

// ============================================================================
// HttpFileServer — tiny read-only file browser for the client, built only on
// HttpListener (in-box, no NuGet). Directory listing + file download.
// ============================================================================
internal sealed class HttpFileServer : IDisposable
{
    private readonly string _root;
    private readonly int _port;
    private HttpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _disposed;

    public bool Running { get; private set; }
    public string Url => $"http://{Defaults.HostIp}:{_port}/";

    public HttpFileServer(string root, int port)
    {
        _root = System.IO.Path.GetFullPath(root);
        _port = port;
    }

    public bool Start(out string message)
    {
        message = "";
        try
        {
            Directory.CreateDirectory(_root);
            Stop(); // idempotent
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://*:{_port}/");
            _listener.Start();
            _cts = new CancellationTokenSource();
            _loop = Task.Run(() => LoopAsync(_cts.Token));
            Running = true;
            message = $"listening on port {_port}";
            return true;
        }
        catch (HttpListenerException ex)
        {
            message = $"cannot listen on port {_port}: {ex.Message} " +
                      $"(error {ex.ErrorCode}; another app may use the port, or run: " +
                      $"netsh http add urlacl url=http://*:{_port}/ user=Everyone)";
            return false;
        }
        catch (Exception ex)
        {
            message = ex.Message;
            return false;
        }
    }

    public void Stop()
    {
        Running = false;
        try { _cts?.Cancel(); } catch { }
        try
        {
            if (_listener?.IsListening == true) _listener.Stop();
            _listener?.Close();
        }
        catch { }
        _listener = null;
        _cts?.Dispose();
        _cts = null;
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener?.IsListening == true)
        {
            HttpListenerContext ctx;
            try { ctx = await _listener.GetContextAsync().ConfigureAwait(false); }
            catch { break; } // listener stopped
            _ = Task.Run(() => Handle(ctx), ct);
        }
    }

    private void Handle(HttpListenerContext ctx)
    {
        try
        {
            // Map URL -> file, jailed inside _root (blocks "/../" escapes).
            string rel = Uri.UnescapeDataString(ctx.Request.Url?.AbsolutePath.TrimStart('/') ?? "");
            string full = System.IO.Path.GetFullPath(System.IO.Path.Combine(_root, rel.Replace('/', System.IO.Path.DirectorySeparatorChar)));
            if (!full.Equals(_root, StringComparison.OrdinalIgnoreCase) &&
                !full.StartsWith(_root + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                Send(ctx, 403, "text/plain; charset=utf-8", "Forbidden"u8.ToArray());
                return;
            }

            if (Directory.Exists(full))
            {
                // Redirect /sub -> /sub/ so relative links work.
                if (!ctx.Request.Url!.AbsolutePath.EndsWith('/'))
                {
                    ctx.Response.Redirect(ctx.Request.Url.AbsolutePath + "/");
                    ctx.Response.Close();
                    return;
                }
                Send(ctx, 200, "text/html; charset=utf-8", Encoding.UTF8.GetBytes(ListingPage(rel, full)));
            }
            else if (File.Exists(full))
            {
                ctx.Response.ContentType = MimeOf(full);
                ctx.Response.ContentLength64 = new FileInfo(full).Length;
                ctx.Response.StatusCode = 200;
                using var fs = File.OpenRead(full);
                fs.CopyTo(ctx.Response.OutputStream);
                ctx.Response.Close();
            }
            else
            {
                Send(ctx, 404, "text/plain; charset=utf-8", "Not found"u8.ToArray());
            }
        }
        catch { try { ctx.Response.Abort(); } catch { } }
    }

    private string ListingPage(string rel, string dir)
    {
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html><head><meta charset='utf-8'><title>WifiShare</title></head><body>");
        sb.Append("<h2>WifiShare file drop</h2><ul>");
        if (!string.IsNullOrEmpty(rel)) sb.Append("<li><a href='../'>.. (up)</a></li>");
        foreach (var d in Directory.GetDirectories(dir).OrderBy(x => x))
        {
            string n = System.IO.Path.GetFileName(d);
            sb.Append($"<li>[dir] <a href='{WebUtility.UrlEncode(n)}/'>{WebUtility.HtmlEncode(n)}/</a></li>");
        }
        foreach (var f in Directory.GetFiles(dir).OrderBy(x => x))
        {
            var fi = new FileInfo(f);
            sb.Append($"<li><a href='{WebUtility.UrlEncode(fi.Name)}'>{WebUtility.HtmlEncode(fi.Name)}</a> ({fi.Length} bytes)</li>");
        }
        sb.Append("</ul></body></html>");
        return sb.ToString();
    }

    private static void Send(HttpListenerContext ctx, int code, string type, byte[] body)
    {
        ctx.Response.StatusCode = code;
        ctx.Response.ContentType = type;
        ctx.Response.ContentLength64 = body.Length;
        ctx.Response.OutputStream.Write(body, 0, body.Length);
        ctx.Response.Close();
    }

    private static string MimeOf(string path) =>
        System.IO.Path.GetExtension(path).ToLowerInvariant() switch
        {
            ".html" or ".htm" => "text/html; charset=utf-8",
            ".txt" or ".log" => "text/plain; charset=utf-8",
            ".json" => "application/json",
            ".xml" => "text/xml",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".png" => "image/png",
            ".gif" => "image/gif",
            ".pdf" => "application/pdf",
            ".zip" => "application/zip",
            _ => "application/octet-stream",
        };

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }
}

// ============================================================================
// ClientHelp — what to do on the CLIENT pc, printed after Start + in README.
// ============================================================================
internal static class ClientHelp
{
    public static string SuggestClientIp(string hostIp)
    {
        try
        {
            var parts = hostIp.Split('.').Select(int.Parse).ToArray();
            int last = parts[3] < 254 ? parts[3] + 1 : parts[3] - 1;
            if (last is 0 or 255) last = 100;
            return $"{parts[0]}.{parts[1]}.{parts[2]}.{last}";
        }
        catch { return "172.20.10.186"; }
    }

    public static void Print(string hostIp, string shareName, int httpPort, bool httpOn,
                             string dns1, string dns2,
                             bool dhcpOn, string poolStart, string poolEnd, string domain)
    {
        string clientIp = SuggestClientIp(hostIp);
        Ui.Section("CLIENT SETUP (do this on the client PC)");
        Console.WriteLine("1. Plug the Ethernet cable laptop <-> client.");
        if (dhcpOn)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("2. PLUG-AND-PLAY: leave the client on automatic (DHCP). It will receive:");
            Console.WriteLine($"     IP address:      {poolStart} - {poolEnd} (automatic)");
            Console.WriteLine($"     Subnet mask:     255.255.255.0");
            Console.WriteLine($"     Default gateway: {hostIp}");
            Console.WriteLine($"     DNS:             {dns1}  (alt. {dns2})");
            Console.WriteLine($"     DNS suffix:      {domain}");
            Console.ResetColor();
            Console.WriteLine("   No manual TCP/IP setup needed. If DHCP ever fails, fall back to:");
        }
        else
        {
            Console.WriteLine("2. DHCP is OFF, so set a STATIC IP on the client (Control Panel > Network):");
        }
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"     IP address:      {clientIp}");
        Console.WriteLine($"     Subnet mask:     255.255.255.0");
        Console.WriteLine($"     Default gateway: {hostIp}");
        Console.WriteLine($"     DNS:             {dns1}  (alt. {dns2})");
        Console.ResetColor();
        Console.WriteLine("3. Open the shared files with one of:");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"     \\\\{hostIp}\\{shareName}      (File Explorer address bar)");
        if (httpOn) Console.WriteLine($"     http://{hostIp}:{httpPort}/   (any browser)");
        Console.ResetColor();
        Console.WriteLine("4. Internet on the client flows through this laptop (ICS/NAT).");
    }
}

// ============================================================================
// WifiShareApp — interactive menu + Start/Stop/Settings/Status orchestration.
// ============================================================================
internal static class WifiShareApp
{
    private static HttpFileServer? _http;
    private static DhcpServer? _dhcp;
    private static volatile bool _sharingActive;

    public static int Run(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        var argSet = new HashSet<string>(args.Select(a => a.ToLowerInvariant()));

        if (argSet.Contains("--help") || argSet.Contains("-h") || argSet.Contains("/?"))
        {
            PrintHelp();
            return 0;
        }

        if (!Sys.IsWindows())
        {
            Log.Warn("This tool manages Windows networking (netsh / ICS / registry).");
            Log.Warn($"You are on {RuntimeInformation.OSDescription}; sharing actions are disabled.");
            Ui.Banner();
            var all = Adapters.ListAll(); // cross-platform part still works
            Ui.Section("Local adapters (read-only view)");
            Adapters.PrintTable(all);
            return 2;
        }

        // Must be admin: offer to relaunch elevated, preserving CLI args.
        if (!Sys.IsAdmin())
        {
            Ui.Banner();
            Log.Warn("Administrator rights are required (IP, ICS, firewall, shares, registry).");
            string joined = string.Join(" ", args.Select(a => a.Contains(' ') ? $"\"{a}\"" : a));
            if (Ui.PromptYesNo("Relaunch as Administrator now?", true))
            {
                if (Sys.RelaunchAsAdmin(joined)) return 0;
                Log.Error("Could not relaunch elevated. Right-click > 'Run as administrator'.");
                return 1;
            }
            Log.Error("Continuing without admin will fail. Exiting.");
            return 1;
        }

        // Ctrl+C: try to leave the machine clean instead of abandoning ICS+IP.
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            Log.Warn("Ctrl+C pressed — restoring network settings before exit...");
            try { StopSharing(quiet: true); } catch { }
            Environment.Exit(130);
        };

        // Non-interactive flags (scripting friendly).
        if (argSet.Contains("--status")) { Ui.Banner(); ShowStatus(); return 0; }
        if (argSet.Contains("--start")) { Ui.Banner(); StartSharing(); return _sharingActive ? 0 : 1; }
        if (argSet.Contains("--stop")) { Ui.Banner(); StopSharing(); return 0; }

        // If a previous session is still active, resume that knowledge.
        var saved = StateStore.Load();
        if (saved is not null)
        {
            Settings.SharePath = saved.SharePath;
            Settings.ShareName = saved.ShareName;
            Settings.DnsSuffix = saved.DnsSuffix;
            Settings.HttpPort = saved.HttpPort;
            _sharingActive = true;
        }

        MenuLoop();
        return 0;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("WifiShare — share laptop Wi-Fi over Ethernet (Windows, admin required).");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  WifiShare                 interactive menu");
        Console.WriteLine("  WifiShare --start         start sharing with current/default settings");
        Console.WriteLine("  WifiShare --stop          stop sharing and restore original settings");
        Console.WriteLine("  WifiShare --status        show adapters, IPs and sharing state");
        Console.WriteLine("  WifiShare --help          this text");
    }

    // ---------------- interactive menu ----------------
    private static void MenuLoop()
    {
        while (true)
        {
            Ui.Banner();
            Console.WriteLine($"Status: {(_sharingActive ? "SHARING ACTIVE" : "idle")}");
            Console.WriteLine();
            Console.WriteLine("  1. Start Sharing (ICS + static IP + DHCP + share folder)");
            Console.WriteLine("  2. Stop / Restore original network settings");
            Console.WriteLine("  3. Change settings (folder, share name, DNS suffix, HTTP port)");
            Console.WriteLine("  4. Show current status (adapters, IPs, sharing state)");
            Console.WriteLine("  5. Exit");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Select [1-5]: ");
            Console.ResetColor();
            string? choice = null;
            try { choice = Console.ReadLine()?.Trim(); } catch { }

            switch (choice)
            {
                case "1": StartSharing(); Ui.Pause(); break;
                case "2": StopSharing(); Ui.Pause(); break;
                case "3": ChangeSettings(); Ui.Pause(); break;
                case "4": ShowStatus(); Ui.Pause(); break;
                case "5":
                    if (_sharingActive)
                    {
                        Ui.Section("Sharing is still active");
                        if (Ui.PromptYesNo("Stop sharing and restore settings before exit?", true))
                            StopSharing();
                        else
                            Log.Warn("Leaving sharing active. Run option 2 later to restore.");
                    }
                    Log.Info("Bye.");
                    return;
                default:
                    Log.Warn("Please type 1-5.");
                    Thread.Sleep(700);
                    break;
            }
        }
    }

    // ---------------- option 1: START ----------------
    private static void StartSharing()
    {
        if (_sharingActive)
        {
            Log.Warn("Sharing is already active. Use option 2 (Stop) first.");
            return;
        }

        Ui.Section("Step 1/7 — Detecting adapters");
        var all = Adapters.ListAll();
        Adapters.PrintTable(all);
        var wifi = Adapters.DetectWifi(all);
        var eth = Adapters.DetectEthernet(all);

        if (wifi is null)
        {
            Log.Error("No active Wi-Fi adapter with internet access found. Connect Wi-Fi first.");
            return;
        }
        if (eth is null)
        {
            Log.Error("No Ethernet adapter found. Plug the cable / enable the adapter first.");
            return;
        }
        Log.Ok($"Wi-Fi (internet/public):  '{wifi.Name}' ({wifi.Description})");
        Log.Ok($"Ethernet (client/private): '{eth.Name}' ({eth.Description})");
        if (Ui.PromptYesNo("Use these adapters?", true) == false)
        {
            string w = Ui.Prompt("Public Wi-Fi connection name", wifi.Name);
            string e = Ui.Prompt("Private Ethernet connection name", eth.Name);
            wifi = all.FirstOrDefault(a => a.Name.Equals(w, StringComparison.OrdinalIgnoreCase)) ?? wifi;
            eth = all.FirstOrDefault(a => a.Name.Equals(e, StringComparison.OrdinalIgnoreCase)) ?? eth;
        }

        // Confirm the exact identity to apply (spec values are the defaults).
        Ui.Section("Step 2/7 — Confirm Ethernet identity");
        string ip = Ui.Prompt("IPv4 address", Defaults.HostIp);
        string mask = Ui.Prompt("Subnet mask", Defaults.Mask);
        string gw = Ui.Prompt("Default gateway (empty = none)", Defaults.Gateway);
        string dns1 = Ui.Prompt("Primary DNS", Defaults.DnsPrimary);
        string dns2 = Ui.Prompt("Secondary DNS (empty = none)", Defaults.DnsSecondary);
        Settings.DnsSuffix = Ui.Prompt("Primary DNS suffix (connection-specific)", Settings.DnsSuffix);
        bool spoofMac = Settings.SpoofMac &&
                        Ui.PromptYesNo($"Spoof MAC to {Defaults.TargetMac}?", true);
        if (string.IsNullOrWhiteSpace(gw)) gw = "";

        // Plug-and-play for the client: our DHCP server hands out this pool
        // (IP + mask + gateway + DNS + domain) the moment the cable is in.
        Settings.StartDhcp = Ui.PromptYesNo("Run plug-and-play DHCP server for the client?", Settings.StartDhcp);
        if (Settings.StartDhcp)
        {
            Settings.PoolStart = Ui.Prompt("DHCP pool start", Settings.PoolStart);
            Settings.PoolEnd = Ui.Prompt("DHCP pool end", Settings.PoolEnd);
            string lh = Ui.Prompt("DHCP lease time (hours)", Settings.LeaseHours.ToString());
            if (int.TryParse(lh, out int h) && h >= 1 && h <= 720) Settings.LeaseHours = h;
            else Log.Warn("Invalid lease time, keeping previous.");
        }

        // Snapshot originals BEFORE changing anything.
        var state = new ShareState
        {
            PublicAdapterName = wifi.Name,
            PublicAdapterId = wifi.Id,
            PrivateAdapterName = eth.Name,
            PrivateAdapterId = eth.Id,
            HadStaticIp = eth.IPv4.Count > 0,
            OrigIp = eth.IPv4.FirstOrDefault(),
            OrigMask = eth.Masks.FirstOrDefault(),
            OrigGateway = eth.Gateways.FirstOrDefault(),
            OrigDns = new List<string>(eth.Dns),
            OrigSuffix = IpConfig.GetConnectionSuffix(eth.Id),
            SharePath = Settings.SharePath,
            ShareName = Settings.ShareName,
            DnsSuffix = Settings.DnsSuffix,
            HttpPort = Settings.HttpPort,
            StartedUtc = DateTimeOffset.UtcNow,
        };
        Log.Info($"Original Ethernet snapshot: IP={state.OrigIp ?? "DHCP/none"} " +
                 $"GW={state.OrigGateway ?? "-"} DNS=[{string.Join(",", state.OrigDns)}] " +
                 $"suffix='{state.OrigSuffix}'");

        Ui.Section("Step 3/7 — Enabling Internet Connection Sharing");
        // IMPORTANT ORDER: ICS first (it resets the private NIC to
        // 192.168.137.1), then we override with the custom static identity.
        if (!Ics.TryEnable(wifi.Name, wifi.Id, eth.Name, eth.Id, out string icsMsg))
        {
            Log.Error("ICS failed: " + icsMsg);
            Log.Warn("Fix the cause above and retry; nothing else was changed.");
            return;
        }
        Log.Ok(icsMsg);
        state.IcsEnabledByUs = true;
        Ui.Wait(2, "Waiting for ICS to settle");

        Ui.Section("Step 4/7 — Applying static identity on Ethernet");
        if (!IpConfig.SetStaticIp(eth.Name, ip, mask, gw))
        {
            Log.Error("Static IP failed. Disabling ICS again to leave things clean...");
            Ics.TryDisable(out _);
            return;
        }
        Log.Ok($"IP set: {ip} / {mask}  gateway {(string.IsNullOrEmpty(gw) ? "(none)" : gw)}");
        if (!IpConfig.SetDns(eth.Name, dns1, string.IsNullOrWhiteSpace(dns2) ? null : dns2))
            Log.Warn("DNS setup reported a problem; continuing anyway.");
        else
            Log.Ok($"DNS set: {dns1}" + (string.IsNullOrWhiteSpace(dns2) ? "" : $", {dns2}"));
        if (IpConfig.SetConnectionSuffix(eth.Name, eth.Id, Settings.DnsSuffix))
            Log.Ok($"DNS suffix set: '{Settings.DnsSuffix}'");
        IpConfig.SetPrivateProfile(eth.Name);

        if (spoofMac)
        {
            string? regKey = IpConfig.FindAdapterRegKey(eth.Id, eth.Description);
            if (regKey is null)
            {
                Log.Warn("Adapter registry key not found; skipping MAC spoof.");
            }
            else
            {
                var (existed, oldVal) = IpConfig.GetMacOverride(regKey);
                state.OrigMacOverrideExisted = existed;
                state.OrigMacOverride = oldVal;
                if (IpConfig.SetMacOverride(regKey, Defaults.TargetMac))
                {
                    state.MacSpoofedByUs = true;
                    IpConfig.RestartAdapter(eth.Name);
                    // Re-apply IP after the restart (some drivers reset it).
                    IpConfig.SetStaticIp(eth.Name, ip, mask, gw);
                    IpConfig.SetDns(eth.Name, dns1, string.IsNullOrWhiteSpace(dns2) ? null : dns2);
                }
            }
        }
        IpConfig.FlushDns();
        StateStore.Save(state); // persist early: later steps may still fail

        Ui.Section("Step 5/7 — Plug-and-play DHCP server");
        bool dhcpOn = false;
        if (Settings.StartDhcp &&
            Ui.PromptYesNo($"Serve DHCP pool {Settings.PoolStart} - {Settings.PoolEnd} to the client?", true))
        {
            Sharing.OpenDhcpPort(open: true);
            try
            {
                var dnsServers = new List<IPAddress> { IPAddress.Parse(dns1) };
                if (!string.IsNullOrWhiteSpace(dns2)) dnsServers.Add(IPAddress.Parse(dns2));
                var scope = new DhcpScope(
                    IPAddress.Parse(ip), IPAddress.Parse(mask), IPAddress.Parse(ip),
                    dnsServers, Settings.DnsSuffix,
                    IPAddress.Parse(Settings.PoolStart), IPAddress.Parse(Settings.PoolEnd),
                    Settings.LeaseHours * 3600);
                _dhcp?.Dispose();
                _dhcp = new DhcpServer(scope);
                if (_dhcp.Start(out string dm))
                {
                    dhcpOn = true;
                    state.DhcpStartedByUs = true;
                    StateStore.Save(state);
                    Log.Ok("DHCP server: " + dm);
                    Log.Info("Client plug-and-play: just plug the cable, no manual TCP/IP setup needed.");
                }
                else
                {
                    Log.Error("DHCP server failed: " + dm);
                    Log.Warn("Continuing without DHCP; the client must use the static IP below.");
                    _dhcp?.Dispose();
                    _dhcp = null;
                }
            }
            catch (Exception ex)
            {
                Log.Error("DHCP setup failed: " + ex.Message);
                Log.Warn("Continuing without DHCP; the client must use the static IP below.");
            }
        }

        Ui.Section("Step 6/7 — File sharing (SMB) + optional HTTP server");
        Sharing.EnsureFirewallAndServices();
        bool shareOk = Sharing.EnsureShare(Settings.SharePath, Settings.ShareName);
        if (!shareOk) Log.Warn("Continuing without SMB share; HTTP server may still help.");

        _http?.Dispose();
        _http = null;
        bool httpOn = false;
        if (Settings.StartHttpServer &&
            Ui.PromptYesNo($"Start HTTP file server on port {Settings.HttpPort}?", true))
        {
            Sharing.OpenHttpPort(Settings.HttpPort, open: true);
            _http = new HttpFileServer(Settings.SharePath, Settings.HttpPort);
            if (_http.Start(out string hm))
            {
                httpOn = true;
                Log.Ok("HTTP server: " + hm);
            }
            else
            {
                Log.Error("HTTP server failed: " + hm);
                _http.Dispose();
                _http = null;
            }
        }

        _sharingActive = true;
        Ui.Section("Step 7/7 — Done");
        Log.Ok($"Host Ethernet is now {ip}  (client gateway/DNS target).");
        Log.Info("Driver-bound fields are read-only on Windows: " +
                 $"Description='{eth.Description}', speed={Adapters.FormatSpeed(eth.SpeedBps)} " +
                 "(see README limitations). Ethernet is unencrypted at L2 by nature.");
        ClientHelp.Print(ip, Settings.ShareName, Settings.HttpPort, httpOn, dns1, dns2,
                         dhcpOn, Settings.PoolStart, Settings.PoolEnd, Settings.DnsSuffix);
    }

    // ---------------- option 2: STOP / RESTORE ----------------
    private static void StopSharing(bool quiet = false)
    {
        var state = StateStore.Load();
        string ethName = state?.PrivateAdapterName ??
                         Adapters.DetectEthernet(Adapters.ListAll())?.Name ?? "";

        if (state is null && !_sharingActive)
        {
            Log.Warn("No saved session found. Attempting best-effort cleanup anyway...");
        }

        Ui.Section("Stopping share & restoring originals");

        try { _http?.Dispose(); } catch { }
        _http = null;
        if (state is not null) Sharing.OpenHttpPort(state.HttpPort, open: false);

        // Stop our DHCP server first: the client keeps its last lease until it
        // expires, so plug-and-play degrades gracefully instead of breaking.
        try { _dhcp?.Dispose(); } catch { }
        _dhcp = null;
        Sharing.OpenDhcpPort(open: false);

        if (!string.IsNullOrEmpty(state?.ShareName)) Sharing.RemoveShare(state.ShareName);
        Log.Info($"Shared folder kept on disk: {state?.SharePath ?? Settings.SharePath}");

        if (state?.IcsEnabledByUs == true || state is null)
        {
            if (Ics.TryDisable(out string m)) Log.Ok(m);
            else Log.Warn(m);
        }

        if (!string.IsNullOrEmpty(ethName))
        {
            // MAC first (needs an adapter restart), then IP/DNS/suffix.
            if (state?.MacSpoofedByUs == true)
            {
                var fresh = Adapters.ListAll().FirstOrDefault(a =>
                    a.Name.Equals(ethName, StringComparison.OrdinalIgnoreCase));
                string? key = IpConfig.FindAdapterRegKey(
                    state.PrivateAdapterId ?? fresh?.Id, fresh?.Description ?? "");
                if (key is not null)
                {
                    IpConfig.ClearMacOverride(key, state.OrigMacOverrideExisted, state.OrigMacOverride);
                    IpConfig.RestartAdapter(ethName);
                }
            }

            if (state is not null && state.HadStaticIp && !string.IsNullOrEmpty(state.OrigIp))
            {
                IpConfig.SetStaticIp(ethName, state.OrigIp,
                    string.IsNullOrEmpty(state.OrigMask) ? "255.255.255.0" : state.OrigMask,
                    state.OrigGateway);
                if (state.OrigDns.Count > 0)
                    IpConfig.SetDns(ethName, state.OrigDns[0],
                        state.OrigDns.Count > 1 ? state.OrigDns[1] : null);
                else
                    Sys.Netsh($"interface ip set dnsservers name=\"{ethName}\" source=dhcp");
            }
            else
            {
                IpConfig.SetDhcp(ethName);
            }

            if (state is not null)
                IpConfig.SetConnectionSuffix(ethName, state.PrivateAdapterId, state.OrigSuffix ?? "");
            IpConfig.FlushDns();
        }

        StateStore.Clear();
        _sharingActive = false;
        Log.Ok("Restore complete: ICS off, Ethernet back to original/DHCP, share removed.");
        if (!quiet) Ui.Pause();
    }

    // ---------------- option 3: SETTINGS ----------------
    private static void ChangeSettings()
    {
        Ui.Section("Settings (applied on next Start; folder applies live if active)");
        Settings.SharePath = Ui.Prompt("Shared folder path", Settings.SharePath);
        Settings.ShareName = Ui.Prompt("SMB share name", Settings.ShareName);
        Settings.DnsSuffix = Ui.Prompt("Primary DNS suffix", Settings.DnsSuffix);
        string port = Ui.Prompt("HTTP port", Settings.HttpPort.ToString());
        if (int.TryParse(port, out int p) && p is > 0 and < 65536) Settings.HttpPort = p;
        else Log.Warn("Invalid port, keeping previous.");
        Settings.StartHttpServer = Ui.PromptYesNo("Offer HTTP file server on Start?", Settings.StartHttpServer);
        Settings.SpoofMac = Ui.PromptYesNo("Offer MAC spoof on Start?", Settings.SpoofMac);
        Settings.StartDhcp = Ui.PromptYesNo("Offer plug-and-play DHCP server on Start?", Settings.StartDhcp);
        Settings.PoolStart = Ui.Prompt("DHCP pool start", Settings.PoolStart);
        Settings.PoolEnd = Ui.Prompt("DHCP pool end", Settings.PoolEnd);
        string lh = Ui.Prompt("DHCP lease time (hours)", Settings.LeaseHours.ToString());
        if (int.TryParse(lh, out int h) && h >= 1 && h <= 720) Settings.LeaseHours = h;
        else Log.Warn("Invalid lease time, keeping previous.");
        Log.Ok("Settings updated.");

        // Live-apply the folder if we are currently sharing.
        var state = StateStore.Load();
        if (_sharingActive && state is not null)
        {
            Log.Step("Sharing is active — re-pointing the share to the new folder...");
            Sharing.RemoveShare(state.ShareName);
            if (Sharing.EnsureShare(Settings.SharePath, Settings.ShareName))
            {
                state.SharePath = Settings.SharePath;
                state.ShareName = Settings.ShareName;
                StateStore.Save(state);
                try { _http?.Dispose(); } catch { }
                _http = new HttpFileServer(Settings.SharePath, state.HttpPort);
                if (_http.Start(out string hm)) Log.Ok("HTTP server restarted: " + hm);
                else { Log.Warn("HTTP restart failed: " + hm); _http = null; }
            }
        }
    }

    // ---------------- option 4: STATUS ----------------
    private static void ShowStatus()
    {
        Ui.Section("Adapters & IPs");
        var all = Adapters.ListAll();
        Adapters.PrintTable(all);

        Ui.Section("Internet Connection Sharing");
        var entries = Ics.GetStatus();
        if (entries.Count == 0)
            Log.Info("(ICS unavailable or no connections enumerated.)");
        foreach (var e in entries)
        {
            string flag = e.Enabled ? $"SHARED [{e.Kind}]" : "not shared";
            Console.WriteLine($"  {e.Name}  ({e.Device})  ->  {flag}");
        }

        Ui.Section("SMB shares");
        Console.WriteLine(Sharing.GetShareTable());

        Ui.Section("DHCP server (plug-and-play)");
        if (_dhcp?.Running == true)
        {
            Console.WriteLine($"  Running: pool {_dhcp.PoolSummary}  ({_dhcp.LeaseSummary})");
            var leases = _dhcp.GetLeases();
            if (leases.Count == 0) Console.WriteLine("  No active leases yet (plug the client in).");
            foreach (var l in leases)
                Console.WriteLine($"  lease {l.Ip,-15} {l.Mac,-22} {l.HostName,-20} until {l.ExpiryUtc:u}");
        }
        else Console.WriteLine("  Stopped.");

        Ui.Section("HTTP file server");
        Console.WriteLine(_http?.Running == true
            ? $"  Running: {_http.Url}  (share: {Settings.SharePath})"
            : "  Stopped.");

        Ui.Section("Saved session");
        var s = StateStore.Load();
        if (s is null) Console.WriteLine("  (none)");
        else
        {
            Console.WriteLine($"  Started (UTC): {s.StartedUtc:u}");
            Console.WriteLine($"  Public:  {s.PublicAdapterName}");
            Console.WriteLine($"  Private: {s.PrivateAdapterName}  ICS={s.IcsEnabledByUs} MACspoof={s.MacSpoofedByUs}");
            Console.WriteLine($"  Orig IP: {s.OrigIp ?? "DHCP/none"}  Orig DNS: [{string.Join(",", s.OrigDns)}]  Orig suffix: '{s.OrigSuffix}'");
            Console.WriteLine($"  Share:   \\\\{Environment.MachineName}\\{s.ShareName}  <-  {s.SharePath}");
        }

        Ui.Section("Identity notes");
        Console.WriteLine("  Description / Manufacturer / Driver version: read-only (driver INF).");
        Console.WriteLine("  Link speed: real negotiated speed (cannot be spoofed).");
        Console.WriteLine("  Encryption flag: N/A — Ethernet is unencrypted at L2 by nature.");
    }
}
