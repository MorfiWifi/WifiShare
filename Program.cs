// ============================================================================
// WifiShare — share Wi-Fi with one Ethernet client on a dedicated IPv4 subnet.
//
// Default CLIENT: 172.20.10.185/24. LAPTOP/gateway: 172.20.10.1/24.
// The laptop Ethernet has NO default gateway. Internet exits through Wi-Fi.
// WinNAT translates 172.20.10.0/24; do not run ICS or Mobile hotspot alongside it.
// The built-in DHCP server offers .185, upstream Wi-Fi DNS and the chosen suffix.
// It receives broadcasts on UDP 67, filters by the selected interface, and sends
// replies on that interface. Firewall rules are scoped to the Ethernet adapter.
//
// Windows with WinNAT support and .NET 10; run as Administrator:
//   dotnet run -c Release
//   dotnet run -c Release -- --status      (read-only, no elevation required)
//   dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true -o publish
//
// Keep the app open for DHCP/HTTP. Stop restores the saved address/DNS/forwarding.
// Failed setup rolls back; failed cleanup keeps the recovery file for retry.
// Existing ICS or Windows NAT configurations are never silently replaced.
// Client file access: \\172.20.10.1\Shared or http://172.20.10.1:8080/
// See README.md for client setup and checks. All application code is in this file.
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
    public const string HostIp = "172.20.10.1";
    public const string ClientIp = "172.20.10.185";
    public const string Mask = "255.255.255.0";
    public const int PrefixLength = 24;
    public const string Gateway = ""; // The host's default route belongs to Wi-Fi.
    public const string DnsPrimary = "172.16.61.20";
    public const string DnsSecondary = "172.16.61.10";
    public const string DnsSuffix = "mydomain.net";
    public const string TargetMac = "88:11:1E:34:F6:41";
    // Plug-and-play DHCP pool served to the client (must sit inside 172.20.10.0/24
    // and must NOT contain the host IP .185). Lease time in hours.
    public const string PoolStart = ClientIp;
    public const string PoolEnd = ClientIp;
    public const int LeaseHours = 24;
    public const string SharePath = @"D:\SharedWithClient";
    public const string ShareName = "Shared";
    public const string ShareUserName = "admin";
    public const string SharePassword = "123456";
    public const int HttpPort = 8080;
    public const string ExpectedAdapterHint = "Realtek PCIe GbE Family Controller";
}

// Runtime-tweakable settings (menu option 3 edits these).
internal static class Settings
{
    public static string SharePath = Defaults.SharePath;
    public static string ShareName = Defaults.ShareName;
    public static string ShareUserName = Defaults.ShareUserName;
    public static string SharePassword = Defaults.SharePassword;
    public static string DnsSuffix = Defaults.DnsSuffix;
    public static int HttpPort = Defaults.HttpPort;
    public static bool StartHttpServer = true;
    public static bool SpoofMac = false;
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
    public bool? OrigDnsAutomatic { get; set; }
    public string HostIp { get; set; } = "";
    public string HostMask { get; set; } = "";
    public string? NatName { get; set; }
    public bool OrigPublicForwarding { get; set; }
    public bool OrigPrivateForwarding { get; set; }
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
    public bool? ShareCreatedByUs { get; set; }
    public string ShareUserName { get; set; } = Defaults.ShareUserName;
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
        File.WriteAllText(Path + ".tmp", json, Encoding.UTF8);
        File.Move(Path + ".tmp", Path, overwrite: true);
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
        if (!Console.IsOutputRedirected) Console.Clear();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@" __        ___  __ _   ___ _                    ");
        Console.WriteLine(@" \ \      / (_)/ _(_) / __| |__   __ _ _ __ ___  ");
        Console.WriteLine(@"  \ \ /\ / /| | |_| | \__ \ '_ \ / _` | '__/ _ \ ");
        Console.WriteLine(@"   \ V  V / | |  _| | |___| | | | (_| | | |  __/ ");
        Console.WriteLine(@"    \_/\_/  |_|_| |_| |___/|_| |_|\__,_|_|  \___| ");
        Console.ResetColor();
        Console.WriteLine("  Share laptop Wi-Fi over Ethernet  |  Dedicated client subnet + NAT + DHCP");
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

    public static string PromptPassword(string current)
    {
        Console.Write("SMB password (Enter keeps current): ");
        if (Console.IsInputRedirected)
        {
            string? input = Console.ReadLine();
            return string.IsNullOrEmpty(input) ? current : input;
        }
        var password = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (password.Length > 0) { password.Length--; Console.Write("\b \b"); }
            }
            else if (!char.IsControl(key.KeyChar)) { password.Append(key.KeyChar); Console.Write('*'); }
        }
        Console.WriteLine();
        return password.Length == 0 ? current : password.ToString();
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
        script = "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; try { " +
                 script + "; exit 0 } catch { " +
                 "[Console]::Error.WriteLine(('{0} [ErrorId: {1}]' -f $_.Exception.Message, $_.FullyQualifiedErrorId)); exit 1 }";
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return Run("powershell",
            "-NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass -EncodedCommand " + b64,
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
                dhcp = props.GetIPv4Properties()?.IsDhcpEnabled ?? false;
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
            if (a.Status != OperationalStatus.Up || !a.IPv4.Any(ip => !IsApipa(ip)) ||
                !a.Gateways.Any(g => g != "0.0.0.0")) continue;
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
            if (IsVirtual(a)) continue;
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

    private static bool IsVirtual(AdapterSnapshot a) =>
        new[] { "virtual", "VMware", "Hyper-V", "TAP-", "TUN", "VPN", "Filter", "Miniport", "Kernel Debug" }
            .Any(s => a.Description.Contains(s, StringComparison.OrdinalIgnoreCase) ||
                      a.Name.Contains(s, StringComparison.OrdinalIgnoreCase));

    public static bool ShouldRestoreStatic(AdapterSnapshot a) =>
        !a.DhcpEnabled && a.IPv4.Any(ip => !IsApipa(ip));

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
        string gwPart = string.IsNullOrEmpty(gateway) ? "none" : $"{gateway} 1";
        var r = Sys.Netsh($"interface ip set address name={Q(iface)} static {ip} {mask} {gwPart}");
        Log.Info($"netsh set address -> exit {r.ExitCode}: {FirstLine(r.StdOut)} {FirstLine(r.StdErr)}".Trim());
        return r.Success; // Restoration must not silently drop a saved gateway.
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

    public static bool IsDnsAutomatic(string adapterId)
    {
        using var key = Registry.LocalMachine.OpenSubKey($"{TcpipIfaces}\\{adapterId}");
        if (key is null) throw new InvalidOperationException("Cannot read original Ethernet DNS configuration.");
        return string.IsNullOrWhiteSpace(key.GetValue("NameServer") as string);
    }

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

// GUIDs and vtable order must match the Windows SDK NetCon.h declarations.
[ComImport, Guid("C08956B7-1CD3-11D1-B1C5-00805FC1270E")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetSharingManager
{
    bool SharingInstalled { [return: MarshalAs(UnmanagedType.VariantBool)] get; }
    [return: MarshalAs(UnmanagedType.Interface)]
    object get_EnumPublicConnections(SharingConnectionEnumFlags flags);
    [return: MarshalAs(UnmanagedType.Interface)]
    object get_EnumPrivateConnections(SharingConnectionEnumFlags flags);
    INetSharingConfiguration get_INetSharingConfigurationForINetConnection(
        [MarshalAs(UnmanagedType.Interface)] INetConnection connection);
    INetSharingEveryConnectionCollection get_EnumEveryConnection();
    INetConnectionProps get_NetConnectionProps(
        [MarshalAs(UnmanagedType.Interface)] INetConnection connection);
}

[ComImport, Guid("33C4643C-7811-46FA-A89A-768597BD7223")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetSharingEveryConnectionCollection
{
    [DispId(-4)] IEnumerator GetEnumerator(); // _NewEnum: standard tlbimp pattern
    int Count { get; }
}

[ComImport, Guid("C08956A1-1CD3-11D1-B1C5-00805FC1270E")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface INetConnection
{
    // Opaque connection handle: properties are obtained through the manager.
    // No INetConnection methods are invoked by this application.
}

[ComImport, Guid("F4277C95-CE5B-463D-8167-5662D9BCAA72")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetConnectionProps
{
    string Guid { [return: MarshalAs(UnmanagedType.BStr)] get; }
    string Name { [return: MarshalAs(UnmanagedType.BStr)] get; }
    string DeviceName { [return: MarshalAs(UnmanagedType.BStr)] get; }
    int Status { get; }
    int MediaType { get; }
    uint Characteristics { get; }
}

[ComImport, Guid("C08956B6-1CD3-11D1-B1C5-00805FC1270E")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetSharingConfiguration
{
    bool SharingEnabled { [return: MarshalAs(UnmanagedType.VariantBool)] get; }
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
    private static (string? name, string? device, Guid id) Describe(INetSharingManager mgr, INetConnection c)
    {
        string? n = null, d = null;
        Guid g = Guid.Empty;
        INetConnectionProps? props = null;
        try
        {
            props = mgr.get_NetConnectionProps(c);
            try { n = props.Name; } catch { }
            try { d = props.DeviceName; } catch { }
            try { Guid.TryParse(props.Guid, out g); } catch { }
        }
        catch { /* a connection may disappear during enumeration */ }
        finally
        {
            if (props is not null)
                try { Marshal.ReleaseComObject(props); } catch { }
        }
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
                var (n, d, g) = Describe(mgr, c);
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
                        var (n, _, _) = Describe(mgr, c);
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
            bool pubOk = SafeEnabled(mgr, pub, SharingConnectionType.Public, rcws);
            bool prvOk = SafeEnabled(mgr, prv, SharingConnectionType.Private, rcws);
            if (pubOk && prvOk)
            {
                message = "ICS enabled.";
                return true;
            }
            message = $"ICS partially applied (public={pubOk}, private={prvOk}).";
            return false;
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
            message = ex.Message;
            return false;
        }
        finally
        {
            foreach (var r in rcws)
                try { Marshal.ReleaseComObject(r); } catch { }
        }
    }

    private static bool SafeEnabled(INetSharingManager mgr, INetConnection c,
                                    SharingConnectionType expected, List<object> rcws)
    {
        try
        {
            var cfg = mgr.get_INetSharingConfigurationForINetConnection(c);
            rcws.Add(cfg);
            return cfg.SharingEnabled && cfg.SharingConnectionType == expected;
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
            int failures = 0;
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
                        var (n, _, _) = Describe(mgr, c);
                        Log.Step($"Disabling sharing on '{n}'...");
                        cfg.DisableSharing();
                        count++;
                        Thread.Sleep(500);
                    }
                }
                catch (Exception ex) { failures++; Log.Warn("DisableSharing note: " + ex.Message); }
            }
            message = $"Disabled sharing on {count} connection(s); {failures} failure(s).";
            return failures == 0;
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

    public static List<IcsEntry> GetStatus() => GetStatus(out _);

    public static List<IcsEntry> GetStatus(out string? error)
    {
        error = null;
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
                var (n, d, _) = Describe(mgr, c);
                bool en = false;
                string kind = "-";
                try
                {
                    var cfg = mgr.get_INetSharingConfigurationForINetConnection(c);
                    rcws.Add(cfg);
                    en = cfg.SharingEnabled;
                    if (en) kind = cfg.SharingConnectionType == SharingConnectionType.Public ? "PUBLIC" : "PRIVATE";
                }
                catch (Exception ex) { error = ex.Message; }
                result.Add(new IcsEntry(n ?? "?", d ?? "?", en, kind));
            }
        }
        catch (Exception ex) { error = ex.Message; }
        finally
        {
            foreach (var r in rcws)
                try { Marshal.ReleaseComObject(r); } catch { }
        }
        return result;
    }
}

// ============================================================================
// LanPlan — one dedicated Ethernet client, with separate host/client addresses.
// WinNAT covers exactly this subnet; no off-subnet gateway is put on the host.
internal sealed class LanPlan
{
    public string HostIp { get; }
    public string ClientIp { get; }
    public string Prefix { get; }
    public const string Mask = "255.255.255.0";

    public LanPlan(string hostIp, string clientIp)
    {
        uint host = DhcpPacket.ToUInt(IPAddress.Parse(hostIp));
        uint client = DhcpPacket.ToUInt(IPAddress.Parse(clientIp));
        if (host == client) throw new ArgumentException("Laptop and client must have different IP addresses.");
        if ((host & 0xffffff00) != (client & 0xffffff00))
            throw new ArgumentException("Laptop and client must be in the same /24 subnet.");
        foreach (uint ip in new[] { host, client })
            if ((ip & 255) is 0 or 255 || (ip >> 24) is 0 or 127 or >= 224 ||
                (ip >> 16) == 0xa9fe)
                throw new ArgumentException("Use usable unicast addresses, not network, broadcast or link-local addresses.");
        HostIp = IPAddress.Parse(hostIp).ToString();
        ClientIp = IPAddress.Parse(clientIp).ToString();
        Prefix = DhcpPacket.ToIp(host & 0xffffff00) + "/24";
    }

    public bool Overlaps(AdapterSnapshot adapter)
    {
        uint target = DhcpPacket.ToUInt(IPAddress.Parse(HostIp)) & 0xffffff00;
        for (int i = 0; i < adapter.IPv4.Count; i++)
        {
            if (i >= adapter.Masks.Count || !IPAddress.TryParse(adapter.Masks[i], out var mask)) continue;
            uint other = DhcpPacket.ToUInt(IPAddress.Parse(adapter.IPv4[i]));
            uint commonMask = DhcpPacket.ToUInt(mask) & 0xffffff00;
            if ((target & commonMask) == (other & commonMask)) return true;
        }
        return false;
    }
}

internal static class LanNat
{
    // Windows on the target host rejects the old 42-character name with error
    // 122. This short ASCII form was verified with the actual WinNAT provider.
    public static string CreateName() => "WS-" + Guid.NewGuid().ToString("N")[..8];

    public static void Require(CommandResult result, string operation)
    {
        if (!result.Success)
            throw new InvalidOperationException(operation + ": " + result.StdErr + " " + result.StdOut);
    }

    public static void Preflight(AdapterSnapshot wifi, AdapterSnapshot ethernet, bool dhcp)
    {
        var sharing = Ics.GetStatus(out string? error);
        if (error is not null) throw new InvalidOperationException("Cannot inspect ICS: " + error);
        if (sharing.Any(e => e.Enabled))
            throw new InvalidOperationException("ICS is already enabled. Stop the existing sharing session or disable " +
                "the Wi-Fi Sharing checkbox / Mobile hotspot first. ICS and this custom-subnet NAT must not run together.");
        Require(Sys.PowerShell(
            "Get-Command New-NetNat -ErrorAction Stop | Out-Null; " +
            "if (@(Get-NetNat -ErrorAction Stop).Count -ne 0) { throw 'An existing Windows NAT is configured. " +
            "WifiShare will not replace another app or VM network.' }; " +
            "$route = Find-NetRoute -RemoteIPAddress '1.1.1.1' | Select-Object -First 1; " +
            $"$wifi = Get-NetAdapter -Name {Sys.PwshQuote(wifi.Name)}; " +
            "if ($route.InterfaceIndex -ne $wifi.ifIndex) { throw 'The default internet route does not use the selected Wi-Fi. Check VPN/default routes first.' }"),
            "Custom subnet routing is unavailable (requires Windows WinNAT)");
        if (dhcp)
        {
            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            probe.ExclusiveAddressUse = true;
            try { probe.Bind(new IPEndPoint(IPAddress.Any, 67)); }
            catch (SocketException ex)
            {
                throw new InvalidOperationException("Cannot listen for DHCP broadcasts on UDP 67. " +
                    "Stop the conflicting DHCP server / Mobile hotspot, or choose static client configuration. " + ex.Message);
            }
        }
    }

    public static bool GetForwarding(string name)
    {
        var r = Sys.PowerShell($"(Get-NetIPInterface -InterfaceAlias {Sys.PwshQuote(name)} " +
                               "-AddressFamily IPv4).Forwarding.ToString()");
        Require(r, "Read forwarding for " + name);
        return r.StdOut.Trim().Equals("Enabled", StringComparison.OrdinalIgnoreCase);
    }

    public static void Create(ShareState state, LanPlan plan)
    {
        Log.Step($"Enable IPv4 forwarding on '{state.PrivateAdapterName}'");
        Require(Sys.PowerShell(
            $"Set-NetIPInterface -InterfaceAlias {Sys.PwshQuote(state.PrivateAdapterName)} -AddressFamily IPv4 -Forwarding Enabled"),
            "Set-NetIPInterface (Ethernet forwarding)");
        Log.Step($"Enable IPv4 forwarding on '{state.PublicAdapterName}'");
        Require(Sys.PowerShell(
            $"Set-NetIPInterface -InterfaceAlias {Sys.PwshQuote(state.PublicAdapterName)} -AddressFamily IPv4 -Forwarding Enabled"),
            "Set-NetIPInterface (Wi-Fi forwarding)");
        Log.Step($"Create NAT '{state.NatName}' for {plan.Prefix}");
        Require(Sys.PowerShell(
            $"New-NetNat -Name {Sys.PwshQuote(state.NatName!)} -InternalIPInterfaceAddressPrefix {Sys.PwshQuote(plan.Prefix)} | Out-Null"),
            $"New-NetNat (name='{state.NatName}', prefix='{plan.Prefix}')");
        Require(Sys.PowerShell(
            $"$nat = Get-NetNat -Name {Sys.PwshQuote(state.NatName!)}; " +
            $"if (-not $nat.Active -or $nat.InternalIPInterfaceAddressPrefix -ne {Sys.PwshQuote(plan.Prefix)}) {{ throw 'NAT did not become active with the requested subnet.' }}"),
            "Verify NAT state");
    }

    public static bool Restore(ShareState state)
    {
        var r = Sys.PowerShell(
            $"Get-NetNat | Where-Object Name -eq {Sys.PwshQuote(state.NatName!)} | Remove-NetNat -Confirm:$false; " +
            $"Set-NetIPInterface -InterfaceAlias {Sys.PwshQuote(state.PrivateAdapterName)} -AddressFamily IPv4 -Forwarding {(state.OrigPrivateForwarding ? "Enabled" : "Disabled")}; " +
            $"Set-NetIPInterface -InterfaceAlias {Sys.PwshQuote(state.PublicAdapterName)} -AddressFamily IPv4 -Forwarding {(state.OrigPublicForwarding ? "Enabled" : "Disabled")}");
        if (!r.Success) Log.Error("Restore NAT/forwarding: " + r.StdErr);
        return r.Success;
    }
}

// ============================================================================
// Sharing — firewall rules, helper services, SMB share, HTTP firewall port.
// ============================================================================
internal static class Sharing
{
    public static void EnsureFirewallAndServices()
    {
        Log.Step("Starting file sharing and Network Discovery services...");
        // ConfigureLanRules installs interface-scoped rules; do not enable
        // global built-in groups on unrelated Wi-Fi or VPN networks.

        // Helper services file sharing depends on. 'sc config/start' works
        // on every Windows edition without extra APIs.
        foreach (var svc in new[] { "LanmanServer", "SSDPSRV", "fdPHost", "FDResPub" })
        {
            var c = Sys.Run("sc", $"config {svc} start= auto", 30_000);
            var s = Sys.Run("sc", $"start {svc}", 30_000);
            bool running = s.Success || s.StdOut.Contains("START_PENDING") ||
                           s.StdOut.Contains("RUNNING") || s.StdOut.Contains("1056");
            Log.Info($"Service {svc}: config={c.ExitCode} start={(running ? "running" : "FAILED: " + s.StdOut)}");
            if (!running) Log.Warn($"Service {svc} is not running; file sharing may fail.");
        }
    }

    public static void ValidateShareCredentials(string userName, string password)
    {
        if (string.IsNullOrWhiteSpace(userName) || userName.Length > 20 ||
            userName.EndsWith('.') || userName.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '_' and not '-' and not '.'))
            throw new ArgumentException("Share username must be 1-20 letters, digits, dots, underscores or hyphens, and must not end in a dot.");
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("The SMB account needs a non-empty password.");
    }

    // Only a SID recorded by this app may have its password reset on later runs.
    // Never adopt an unrelated local account just because its name matches.
    internal static string BuildShareScript(string folder, string shareName, string userName, string password)
    {
        ValidateShareCredentials(userName, password);
        return $$"""
            $folder = {{Sys.PwshQuote(Path.GetFullPath(folder))}}
            $shareName = {{Sys.PwshQuote(shareName)}}
            $userName = {{Sys.PwshQuote(userName)}}
            $existing = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
            if ($existing -and [IO.Path]::GetFullPath($existing.Path).TrimEnd('\') -ne $folder.TrimEnd('\')) {
                throw 'The share name already points to a different folder. Choose a different share name.'
            }
            $registryPath = 'HKLM:\SOFTWARE\WifiShare\ShareAccounts'
            $knownSid = Get-ItemPropertyValue -LiteralPath $registryPath -Name $userName -ErrorAction SilentlyContinue
            $user = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
            if ($user -and $user.SID.Value -ne $knownSid) {
                throw "Local account '$userName' already exists and is not managed by WifiShare. Choose another share username in Settings."
            }
            $secret = ConvertTo-SecureString {{Sys.PwshQuote(password)}} -AsPlainText -Force
            try {
                if ($user) {
                    $isAdmin = Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -eq $user.SID.Value }
                    if ($isAdmin) { throw 'The managed share account has administrator privileges. Choose a different standard account name.' }
                    Set-LocalUser -SID $user.SID -Password $secret -PasswordNeverExpires $true
                    Enable-LocalUser -SID $user.SID
                } else {
                    $user = New-LocalUser -Name $userName -Password $secret -PasswordNeverExpires -AccountNeverExpires -Description 'WifiShare SMB access account'
                    try {
                        New-Item -Path $registryPath -Force | Out-Null
                        New-ItemProperty -LiteralPath $registryPath -Name $userName -Value $user.SID.Value -PropertyType String -Force | Out-Null
                    } catch {
                        Remove-LocalUser -SID $user.SID
                        throw
                    }
                }
            } finally { $secret.Dispose() }
            $members = @(Get-LocalGroupMember -SID 'S-1-5-32-545')
            if (-not ($members | Where-Object { $_.SID.Value -eq $user.SID.Value })) {
                Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
            }
            $account = "$env:COMPUTERNAME\$userName"
            $admins = ([Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value
            $everyone = ([Security.Principal.SecurityIdentifier]'S-1-1-0').Translate([Security.Principal.NTAccount]).Value
            [IO.Directory]::CreateDirectory($folder) | Out-Null
            & icacls.exe $folder /grant ("*" + $user.SID.Value + ':(OI)(CI)M') /T /Q
            if ($LASTEXITCODE -ne 0) { throw "NTFS access grant failed (icacls exit $LASTEXITCODE)." }
            if ($existing) {
                Grant-SmbShareAccess -Name $shareName -AccountName $account -AccessRight Change -Force | Out-Null
                Grant-SmbShareAccess -Name $shareName -AccountName $admins -AccessRight Full -Force | Out-Null
                Revoke-SmbShareAccess -Name $shareName -AccountName $everyone -Force | Out-Null
            } else {
                New-SmbShare -Name $shareName -Path $folder -ChangeAccess $account -FullAccess $admins -FolderEnumerationMode AccessBased | Out-Null
            }
            """;
    }

    public static bool EnsureShare(string folder, string shareName)
    {
        try
        {
            var result = Sys.PowerShell(BuildShareScript(folder, shareName, Settings.ShareUserName, Settings.SharePassword));
            if (!result.Success)
            {
                Log.Error("SMB account/share setup failed: " + result.StdErr);
                return false;
            }
            Log.Ok($"SMB share ready: \\\\{Environment.MachineName}\\{shareName}; user {Environment.MachineName}\\{Settings.ShareUserName}");
            return true;
        }
        catch (Exception ex) { Log.Error("SMB setup failed: " + ex.Message); return false; }
    }

    public static void PrintShareLogin(string hostIp, string shareName)
    {
        Console.WriteLine($"SMB username: {Environment.MachineName}\\{Settings.ShareUserName}");
        Console.WriteLine($"SMB password: {Settings.SharePassword}");
        Console.WriteLine($"Client command: net use \\\\{hostIp}\\{shareName} /user:{Environment.MachineName}\\{Settings.ShareUserName} *");
        Console.WriteLine("Enter the password at the prompt. If Windows cached another login, disconnect that share and reconnect.");
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

    public static bool ConfigureLanRules(string adapterName, bool open)
    {
        string script = "Get-NetFirewallRule -Name 'WifiShare-Smb','WifiShare-DiscoveryUdp','WifiShare-DiscoveryTcp','WifiShare-Ping' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; ";
        if (open)
        {
            string scope = $" -InterfaceAlias {Sys.PwshQuote(adapterName)} -Profile Any -Direction Inbound -Action Allow -RemoteAddress LocalSubnet ";
            script += "New-NetFirewallRule -Name 'WifiShare-Smb' -DisplayName 'WifiShare LAN files' -Protocol TCP -LocalPort 445" + scope + "| Out-Null; " +
                      "New-NetFirewallRule -Name 'WifiShare-DiscoveryUdp' -DisplayName 'WifiShare LAN discovery UDP' -Protocol UDP -LocalPort 3702" + scope + "| Out-Null; " +
                      "New-NetFirewallRule -Name 'WifiShare-DiscoveryTcp' -DisplayName 'WifiShare LAN discovery TCP' -Protocol TCP -LocalPort 5357,5358" + scope + "| Out-Null; " +
                      "New-NetFirewallRule -Name 'WifiShare-Ping' -DisplayName 'WifiShare LAN ping' -Protocol ICMPv4 -IcmpType 8" + scope + "| Out-Null";
        }
        var result = Sys.PowerShell(script);
        if (!result.Success) Log.Warn("LAN firewall rules: " + result.StdErr);
        return result.Success;
    }

    public static void OpenHttpPort(int port, bool open, string? adapterName = null)
    {
        string rule = $"WifiShare HTTP {port}";
        if (open)
        {
            if (adapterName is not null)
            {
                var scoped = Sys.PowerShell(
                    $"Get-NetFirewallRule -Name 'WifiShare-Http-{port}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; " +
                    $"New-NetFirewallRule -Name 'WifiShare-Http-{port}' -DisplayName {Sys.PwshQuote(rule)} " +
                    $"-Direction Inbound -Action Allow -Protocol TCP -LocalPort {port} -InterfaceAlias {Sys.PwshQuote(adapterName)} -RemoteAddress LocalSubnet -Profile Any | Out-Null");
                if (!scoped.Success) Log.Warn("HTTP firewall: " + scoped.StdErr);
                return;
            }
            var r = Sys.Netsh($"advfirewall firewall add rule name=\"{rule}\" dir=in action=allow " +
                              $"protocol=TCP localport={port} profile=private");
            Log.Info($"HTTP firewall rule -> exit {r.ExitCode}");
        }
        else
        {
            Sys.PowerShell($"Get-NetFirewallRule -Name 'WifiShare-Http-{port}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule");
            Sys.Netsh($"advfirewall firewall delete rule name=\"{rule}\" protocol=TCP localport={port}");
        }
    }

    // DHCP listens on UDP 67 (server) and answers to UDP 68 (client).
    // Inbound 67 must be open on the Private profile; outbound answers to a
    // broadcast address are allowed by default, but we open 68 too so a
    // locked-down firewall cannot break renewals.
    public static bool OpenDhcpPort(bool open, string? adapterName = null)
    {
        string script = "Get-NetFirewallRule -Name 'WifiShare-Dhcp-In','WifiShare-Dhcp-Out' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; ";
        if (open)
        {
            if (string.IsNullOrWhiteSpace(adapterName)) return false;
            string nic = Sys.PwshQuote(adapterName);
            script += $"New-NetFirewallRule -Name 'WifiShare-Dhcp-In' -DisplayName 'WifiShare DHCP receive' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 67 -RemotePort 68 -InterfaceAlias {nic} -Profile Any | Out-Null; " +
                      $"New-NetFirewallRule -Name 'WifiShare-Dhcp-Out' -DisplayName 'WifiShare DHCP reply' -Direction Outbound -Action Allow -Protocol UDP -LocalPort 67 -RemotePort 68 -InterfaceAlias {nic} -Profile Any | Out-Null";
        }
        var r = Sys.PowerShell(script);
        if (!r.Success) Log.Error("DHCP firewall: " + r.StdErr);
        if (!open) Sys.Netsh("advfirewall firewall delete rule name=\"WifiShare DHCP\" protocol=UDP localport=67"); // legacy rule
        return r.Success;
    }
}

// ============================================================================
// DHCP — single-client address assignment for the WinNAT subnet.
// A wildcard bind receives initial broadcasts; IP_PKTINFO restricts input to
// the selected adapter and IP_UNICAST_IF selects the outgoing Windows interface.
// ICS must be off. An exclusive UDP 67 bind detects competing DHCP servers.
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

        if (dns.Count > 63 || Encoding.ASCII.GetByteCount(Domain) > 253)
            throw new ArgumentException("DHCP DNS list or domain is too long.");
        foreach (var address in dns.Append(router)) DhcpPacket.ToUInt(address);
        uint m = DhcpPacket.ToUInt(mask);
        uint inverse = ~m;
        if (m == 0 || (inverse & (inverse + 1)) != 0)
            throw new ArgumentException("DHCP subnet mask must be contiguous and nonzero.");
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
        if (ReadU32(buf, 24) != 0) return null; // dedicated LAN only; no DHCP relays
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
    private int _interfaceIndex;
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
            _sock = sock; // ensure failed setup is disposed as well
            // Exclusive bind: fail loudly on conflict instead of fighting another server.
            sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse, true);
            sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
            sock.ReceiveTimeout = 1000; // lets the loop notice cancellation promptly
            var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n =>
                n.GetIPProperties().UnicastAddresses.Any(a => a.Address.Equals(_scope.ServerIp)))
                ?? throw new InvalidOperationException("The DHCP server address is not assigned to a local adapter.");
            _interfaceIndex = nic.GetIPProperties().GetIPv4Properties()!.Index;
            sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
            if (OperatingSystem.IsWindows())
                sock.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)31, // Windows IP_UNICAST_IF
                    IPAddress.HostToNetworkOrder(_interfaceIndex));
            // Address-less clients send to 255.255.255.255. A unicast-only bind
            // misses those requests. Packet information restricts input to LAN.
            sock.Bind(new IPEndPoint(IPAddress.Any, _listenPort));
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            Running = true;
            _loop = Task.Run(() => RecvLoop(sock, token));
            message = $"serving {PoolSummary} on {_scope.ServerIp}:{_listenPort}";
            return true;
        }
        catch (SocketException ex)
        {
            Stop();
            message = $"DHCP socket failed ({ex.SocketErrorCode}): {ex.Message}. " +
                      "Check for another DHCP server or Mobile hotspot holding UDP 67.";
            return false;
        }
        catch (Exception ex) { Stop(); message = ex.Message; return false; }
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
    private void RecvLoop(Socket socket, CancellationToken ct)
    {
        var buf = new byte[1500];
        while (!ct.IsCancellationRequested)
        {
            EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
            int n;
            try
            {
                SocketFlags flags = SocketFlags.None;
                n = socket.ReceiveMessageFrom(buf, 0, buf.Length, ref flags, ref remote, out var info);
                if (!AcceptInterface(info.Interface, _interfaceIndex)) continue;
                if (_listenPort == 67 && ((IPEndPoint)remote).Port != 68) continue;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut) { continue; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { if (ct.IsCancellationRequested) break; continue; }
            catch { break; }
            try { Handle(buf, n, remote); }
            catch (Exception ex) { Log.Warn("DHCP handler error: " + ex.Message); }
        }
        Running = false;
    }

    internal static bool AcceptInterface(int received, int selected) => selected > 0 && received == selected;

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
        if (v < DhcpPacket.ToUInt(_scope.PoolStart) || v > DhcpPacket.ToUInt(_scope.PoolEnd)) return false;
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
                    if (!string.IsNullOrEmpty(l.Mac) && IPAddress.TryParse(l.Ip, out var ip) &&
                        ip.AddressFamily == AddressFamily.InterNetwork && IsOfferableLocked(l.Ip, l.Mac))
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
    private readonly string _hostIp;
    private HttpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _disposed;

    public bool Running { get; private set; }
    public string Url => $"http://{_hostIp}:{_port}/";

    public HttpFileServer(string root, int port, string? hostIp = null)
    {
        _root = System.IO.Path.GetFullPath(root);
        _port = port;
        _hostIp = hostIp ?? Defaults.HostIp;
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
        string clientIp = poolStart;
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
        Console.WriteLine("4. On the client, run ipconfig /all and check the address, gateway and DNS above.");
        Console.WriteLine("   For DHCP, set IPv4 AND DNS to automatic, then run ipconfig /renew on the client.");
        Console.WriteLine("   A 169.254.x.x address means the client did not obtain a DHCP lease.");
        Console.WriteLine($"5. Test: ping {hostIp}, then ping 1.1.1.1, then nslookup example.com.");
        Console.WriteLine("   ICMP can be blocked; also try the HTTP link and a website in a browser.");
        Console.WriteLine("   File Explorer Network discovery is separate: use the direct share address above.");
        Console.WriteLine("Keep this app open while DHCP or HTTP service is needed.");
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
            Log.Warn("This tool manages Windows networking (WinNAT / DHCP / netsh).");
            Log.Warn($"You are on {RuntimeInformation.OSDescription}; sharing actions are disabled.");
            Ui.Banner();
            var all = Adapters.ListAll(); // cross-platform part still works
            Ui.Section("Local adapters (read-only view)");
            Adapters.PrintTable(all);
            return 2;
        }

        // Read-only diagnostics are useful even before elevation is available.
        if (argSet.Contains("--status")) { Ui.Banner(); ShowStatus(); return 0; }

        // Must be admin: offer to relaunch elevated, preserving CLI args.
        if (!Sys.IsAdmin())
        {
            Ui.Banner();
            Log.Warn("Administrator rights are required (IP, NAT, firewall and shares).");
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

        // Update credentials on a running share without stopping NAT/DHCP.
        if (argSet.Contains("--setup-share"))
        {
            var session = StateStore.Load();
            if (session is not null)
            {
                Settings.SharePath = session.SharePath;
                Settings.ShareName = session.ShareName;
                Settings.ShareUserName = session.ShareUserName;
            }
            if (!Sharing.EnsureShare(Settings.SharePath, Settings.ShareName)) return 1;
            Sharing.PrintShareLogin(session?.HostIp is { Length: > 0 } address ? address : Defaults.HostIp, Settings.ShareName);
            return 0;
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
        if (argSet.Contains("--start"))
        {
            Ui.Banner(); StartSharing();
            if (!_sharingActive) return 1;
            MenuLoop(); // keep the DHCP/HTTP workers alive until the user exits
            return 0;
        }
        if (argSet.Contains("--stop")) { Ui.Banner(); StopSharing(); return 0; }

        // If a previous session is still active, resume that knowledge.
        var saved = StateStore.Load();
        if (saved is not null)
        {
            Settings.SharePath = saved.SharePath;
            Settings.ShareName = saved.ShareName;
            Settings.ShareUserName = saved.ShareUserName;
            Settings.DnsSuffix = saved.DnsSuffix;
            Settings.HttpPort = saved.HttpPort;
            _sharingActive = false;
            Log.Warn("Saved network session found. DHCP/HTTP workers are stopped; use Stop/Restore before a new Start.");
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
        Console.WriteLine("  WifiShare --start         configure sharing, then keep the menu/services running");
        Console.WriteLine("  WifiShare --stop          stop sharing and restore original settings");
        Console.WriteLine("  WifiShare --setup-share   create/update SMB login without restarting networking");
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
            Console.WriteLine("  1. Start Sharing (custom-subnet NAT + client DHCP + share folder)");
            Console.WriteLine("  2. Stop / Restore original network settings");
            Console.WriteLine("  3. Change settings (folder, share name, client DNS suffix, HTTP port)");
            Console.WriteLine("  4. Show current status (adapters, IPs, sharing state)");
            Console.WriteLine("  5. Exit");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Select [1-5]: ");
            Console.ResetColor();
            string? choice = null;
            try { choice = Console.ReadLine()?.Trim(); } catch { }
            if (choice is null)
            {
                if (_sharingActive) StopSharing(quiet: true);
                return;
            }

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
        if (_sharingActive || StateStore.Exists)
        {
            Log.Warn("A saved sharing session exists. Use option 2 (Stop/Restore) before starting again.");
            return;
        }
        ShareState? state = null;
        try
        {
            Ui.Section("Step 1/5 — Select the internet and client adapters");
            var all = Adapters.ListAll();
            Adapters.PrintTable(all);
            var wifi = Adapters.DetectWifi(all)
                ?? throw new InvalidOperationException("Connect Wi-Fi first; it needs an IPv4 address and a default gateway.");
            var eth = Adapters.DetectEthernet(all)
                ?? throw new InvalidOperationException("No physical Ethernet adapter found. Check the cable and adapter.");
            Log.Info($"Internet: '{wifi.Name}'; client cable: '{eth.Name}'.");
            if (!Ui.PromptYesNo("Use these adapters?", true))
            {
                string w = Ui.Prompt("Internet Wi-Fi adapter name", wifi.Name);
                string e = Ui.Prompt("Client Ethernet adapter name", eth.Name);
                wifi = all.FirstOrDefault(a => a.Name.Equals(w, StringComparison.OrdinalIgnoreCase))
                    ?? throw new ArgumentException("Wi-Fi adapter name not found.");
                eth = all.FirstOrDefault(a => a.Name.Equals(e, StringComparison.OrdinalIgnoreCase))
                    ?? throw new ArgumentException("Ethernet adapter name not found.");
            }
            if (wifi.Id == eth.Id || wifi.Type != NetworkInterfaceType.Wireless80211 ||
                eth.Type != NetworkInterfaceType.Ethernet)
                throw new ArgumentException("Select distinct Wi-Fi and Ethernet adapters.");
            if (wifi.Status != OperationalStatus.Up || eth.Status != OperationalStatus.Up)
                throw new InvalidOperationException("Both adapters must be connected. Check that the client is powered on and the Ethernet cable is plugged in.");
            if (eth.IPv4.Count(ip => !ip.StartsWith("169.254.")) > 1)
                throw new InvalidOperationException("The Ethernet adapter has multiple IPv4 addresses. Use a dedicated client adapter.");

            Ui.Section("Step 2/5 — Client address and laptop gateway");
            string clientIp = Ui.Prompt("CLIENT IPv4 address (the PC at the other end of the cable)", Defaults.ClientIp);
            string hostIp = Ui.Prompt("LAPTOP Ethernet IPv4 / client's gateway (must be different)", Defaults.HostIp);
            var plan = new LanPlan(hostIp, clientIp);
            var overlap = all.FirstOrDefault(a => a.Id != eth.Id && plan.Overlaps(a));
            if (overlap is not null)
                throw new InvalidOperationException($"The LAN subnet overlaps '{overlap.Name}'. Use a different subnet or disconnect the conflicting network.");
            string dns1 = Ui.Prompt("Client primary DNS (from Wi-Fi)", wifi.Dns.FirstOrDefault() ?? Defaults.DnsPrimary);
            string dns2 = Ui.Prompt("Client secondary DNS (type none to omit)", wifi.Dns.Skip(1).FirstOrDefault() ?? "none");
            if (dns2.Equals("none", StringComparison.OrdinalIgnoreCase)) dns2 = "";
            var dnsServers = new List<IPAddress> { IPAddress.Parse(dns1) };
            if (dns2.Length > 0) dnsServers.Add(IPAddress.Parse(dns2));
            if (dnsServers.Any(d => d.AddressFamily != AddressFamily.InterNetwork ||
                IPAddress.IsLoopback(d) || d.Equals(IPAddress.Any) || d.ToString() == hostIp))
                throw new ArgumentException("Use reachable upstream IPv4 DNS servers; the laptop does not run a DNS proxy in this mode.");
            Settings.DnsSuffix = Ui.Prompt("Client DNS suffix (type none to omit)", Settings.DnsSuffix);
            if (Settings.DnsSuffix.Equals("none", StringComparison.OrdinalIgnoreCase)) Settings.DnsSuffix = "";
            Settings.StartDhcp = Ui.PromptYesNo($"Offer {clientIp} automatically to the single Ethernet client via DHCP?", true);
            var scope = new DhcpScope(IPAddress.Parse(hostIp), IPAddress.Parse(LanPlan.Mask), IPAddress.Parse(hostIp),
                dnsServers, Settings.DnsSuffix, IPAddress.Parse(clientIp), IPAddress.Parse(clientIp), Settings.LeaseHours * 3600);
            LanNat.Preflight(wifi, eth, Settings.StartDhcp);
            LanNat.Require(Sys.PowerShell(
                $"if (Get-SmbShare -Name {Sys.PwshQuote(Settings.ShareName)} -ErrorAction SilentlyContinue) {{ throw 'The selected SMB share name already exists. Choose a different share name in Settings.' }}"),
                "Check shared folder name");

            // Persist recovery information before changing addresses or routing.
            int originalIpIndex = eth.IPv4.FindIndex(ip => !ip.StartsWith("169.254."));
            state = new ShareState
            {
                PublicAdapterName = wifi.Name, PublicAdapterId = wifi.Id,
                PrivateAdapterName = eth.Name, PrivateAdapterId = eth.Id,
                HadStaticIp = Adapters.ShouldRestoreStatic(eth),
                OrigIp = originalIpIndex >= 0 ? eth.IPv4[originalIpIndex] : null,
                OrigMask = originalIpIndex >= 0 ? eth.Masks[originalIpIndex] : null,
                OrigGateway = eth.Gateways.FirstOrDefault(), OrigDns = new List<string>(eth.Dns),
                OrigDnsAutomatic = IpConfig.IsDnsAutomatic(eth.Id),
                OrigSuffix = IpConfig.GetConnectionSuffix(eth.Id),
                OrigPublicForwarding = LanNat.GetForwarding(wifi.Name),
                OrigPrivateForwarding = LanNat.GetForwarding(eth.Name),
                SharePath = Settings.SharePath, ShareName = Settings.ShareName, ShareCreatedByUs = false,
                ShareUserName = Settings.ShareUserName,
                DnsSuffix = Settings.DnsSuffix, HttpPort = Settings.HttpPort,
                HostIp = hostIp, HostMask = LanPlan.Mask,
                NatName = LanNat.CreateName(),
                StartedUtc = DateTimeOffset.UtcNow,
            };
            StateStore.Save(state);

            Ui.Section("Step 3/5 — Configure the laptop and subnet routing");
            // The laptop uses Wi-Fi's default route. Its Ethernet has no gateway.
            if (!IpConfig.SetStaticIp(eth.Name, hostIp, LanPlan.Mask, null))
                throw new InvalidOperationException("Could not assign the laptop's Ethernet address.");
            LanNat.Require(Sys.Netsh($"interface ip set dnsservers name=\"{eth.Name}\" source=dhcp"), "Clear stale Ethernet DNS");
            bool addressReady = false;
            for (int attempt = 0; attempt < 15; attempt++)
            {
                var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Id == eth.Id);
                addressReady = nic?.GetIPProperties().UnicastAddresses.Any(a =>
                    a.Address.ToString() == hostIp && a.DuplicateAddressDetectionState == DuplicateAddressDetectionState.Preferred) == true;
                if (addressReady) break;
                Thread.Sleep(1000);
            }
            if (!addressReady) throw new InvalidOperationException("The laptop's LAN address did not become ready. Check for a duplicate IP on the cable.");
            if (Adapters.ListAll().First(a => a.Id == eth.Id).Gateways.Count != 0)
                throw new InvalidOperationException("A stale Ethernet default gateway remains. The client-facing adapter must have no default gateway.");
            LanNat.Create(state, plan);
            IpConfig.SetPrivateProfile(eth.Name);
            Log.Ok($"NAT active for {plan.Prefix}; laptop gateway {hostIp}; client {clientIp}.");

            Ui.Section("Step 4/5 — Client address assignment");
            if (Settings.StartDhcp)
            {
                if (!Sharing.OpenDhcpPort(true, eth.Name)) throw new InvalidOperationException("Could not open the Ethernet DHCP firewall rules.");
                _dhcp = new DhcpServer(scope);
                if (!_dhcp.Start(out string message)) throw new InvalidOperationException(message);
                state.DhcpStartedByUs = true;
                StateStore.Save(state);
                Log.Ok(message);
                Log.Info("Waiting for the client: DHCP OFFER and ACK messages will appear here.");
            }
            else Log.Info($"Static client setup required: {clientIp}/24, gateway {hostIp}, DNS {dns1}.");

            Ui.Section("Step 5/5 — Shared files");
            Sharing.EnsureFirewallAndServices();
            Sharing.ConfigureLanRules(eth.Name, true);
            state.ShareCreatedByUs = true;
            StateStore.Save(state);
            bool smbOn = Sharing.EnsureShare(Settings.SharePath, Settings.ShareName);
            if (!smbOn)
                Log.Warn("SMB setup failed; network routing remains available.");
            _http?.Dispose();
            _http = null;
            bool httpOn = false;
            if (Settings.StartHttpServer && Ui.PromptYesNo($"Start HTTP file server on port {Settings.HttpPort}?", true))
            {
                Sharing.OpenHttpPort(Settings.HttpPort, true, eth.Name);
                _http = new HttpFileServer(Settings.SharePath, Settings.HttpPort, hostIp);
                httpOn = _http.Start(out string message);
                if (httpOn) Log.Ok(message);
                else { Log.Warn(message); _http.Dispose(); _http = null; }
            }
            _sharingActive = true;
            StateStore.Save(state);
            Log.Ok("Host configuration ready. Client connectivity still needs the checks below.");
            ClientHelp.Print(hostIp, Settings.ShareName, Settings.HttpPort, httpOn, dns1, dns2,
                Settings.StartDhcp, clientIp, clientIp, Settings.DnsSuffix);
            if (smbOn) Sharing.PrintShareLogin(hostIp, Settings.ShareName);
        }
        catch (Exception ex)
        {
            Log.Error("Start failed: " + ex.Message);
            if (state is not null && StateStore.Exists)
            {
                Log.Warn("Restoring the saved network settings after the failed start...");
                StopSharing(quiet: true);
            }
        }
    }
    // ---------------- option 2: STOP / RESTORE ----------------
    private static void StopSharing(bool quiet = false)
    {
        var state = StateStore.Load();
        _http?.Dispose(); _http = null;
        _dhcp?.Dispose(); _dhcp = null;
        _sharingActive = false;
        if (state is null)
        {
            Log.Warn("No saved session. No system network configuration was changed.");
            return;
        }
        Ui.Section("Stopping share & restoring originals");
        bool ok = Sharing.OpenDhcpPort(false);
        ok &= Sharing.ConfigureLanRules(state.PrivateAdapterName, false);
        Sharing.OpenHttpPort(state.HttpPort, false);
        if (state.NatName is not null)
        {
            if (!LanNat.Restore(state))
            {
                Log.Error("Recovery information kept. Retry Stop/Restore as Administrator.");
                return;
            }
        }
        else if (state.IcsEnabledByUs)
        {
            if (Ics.TryDisable(out string message)) Log.Ok(message);
            else { Log.Error(message); ok = false; }
        }
        if (state.MacSpoofedByUs)
        {
            string? key = IpConfig.FindAdapterRegKey(state.PrivateAdapterId, "");
            if (key is not null)
            {
                IpConfig.ClearMacOverride(key, state.OrigMacOverrideExisted, state.OrigMacOverride);
                IpConfig.RestartAdapter(state.PrivateAdapterName);
            }
            else ok = false;
        }
        // Older builds accidentally saved APIPA as static. Restore those to DHCP,
        // never recreate the invalid link-local IP + off-subnet gateway pairing.
        bool restoreStatic = state.HadStaticIp && !string.IsNullOrEmpty(state.OrigIp) &&
                             !state.OrigIp.StartsWith("169.254.", StringComparison.Ordinal);
        if (restoreStatic)
            ok &= IpConfig.SetStaticIp(state.PrivateAdapterName, state.OrigIp!,
                string.IsNullOrEmpty(state.OrigMask) ? LanPlan.Mask : state.OrigMask, state.OrigGateway);
        else
            ok &= IpConfig.SetDhcp(state.PrivateAdapterName);
        bool automaticDns = state.OrigDnsAutomatic ?? (!restoreStatic || state.OrigDns.Count == 0);
        if (!automaticDns && state.OrigDns.Count > 0)
            ok &= IpConfig.SetDns(state.PrivateAdapterName, state.OrigDns[0],
                state.OrigDns.Count > 1 ? state.OrigDns[1] : null);
        else
            ok &= Sys.Netsh($"interface ip set dnsservers name=\"{state.PrivateAdapterName}\" source=dhcp").Success;
        if (state.NatName is null) // New NAT sessions don't change host suffix or MAC.
            ok &= IpConfig.SetConnectionSuffix(state.PrivateAdapterName, state.PrivateAdapterId, state.OrigSuffix);
        if (state.ShareCreatedByUs != false && !string.IsNullOrEmpty(state.ShareName)) Sharing.RemoveShare(state.ShareName);
        Log.Info($"Shared folder kept: {state.SharePath}");
        if (ok)
        {
            StateStore.Clear();
            Log.Ok("Routing stopped; original Ethernet address/DNS restored.");
        }
        else Log.Error("Restore was incomplete. Saved recovery information kept; retry Stop/Restore.");
        if (!quiet) Ui.Pause();
    }
    // ---------------- option 3: SETTINGS ----------------
    private static void ChangeSettings()
    {
        Ui.Section("Settings (applied on next Start; folder applies live if active)");
        Settings.SharePath = Ui.Prompt("Shared folder path", Settings.SharePath);
        Settings.ShareName = Ui.Prompt("SMB share name", Settings.ShareName);
        string userName = Ui.Prompt("SMB username", Settings.ShareUserName);
        string password = Ui.PromptPassword(Settings.SharePassword);
        try
        {
            Sharing.ValidateShareCredentials(userName, password);
            Settings.ShareUserName = userName;
            Settings.SharePassword = password;
        }
        catch (ArgumentException ex) { Log.Warn(ex.Message + " Keeping the previous SMB credentials."); }
        Settings.DnsSuffix = Ui.Prompt("Primary DNS suffix", Settings.DnsSuffix);
        string port = Ui.Prompt("HTTP port", Settings.HttpPort.ToString());
        if (int.TryParse(port, out int p) && p is > 0 and < 65536) Settings.HttpPort = p;
        else Log.Warn("Invalid port, keeping previous.");
        Settings.StartHttpServer = Ui.PromptYesNo("Offer HTTP file server on Start?", Settings.StartHttpServer);
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
                state.ShareUserName = Settings.ShareUserName;
                StateStore.Save(state);
                Sharing.PrintShareLogin(state.HostIp, state.ShareName);
                try { _http?.Dispose(); } catch { }
                _http = new HttpFileServer(Settings.SharePath, state.HttpPort, state.HostIp);
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
        var entries = Ics.GetStatus(out string? icsError);
        if (icsError is not null) Log.Warn("ICS status: " + icsError);
        if (entries.Count == 0)
            Log.Info("(ICS unavailable or no connections enumerated.)");
        foreach (var e in entries)
        {
            string flag = e.Enabled ? $"SHARED [{e.Kind}]" : "not shared";
            Console.WriteLine($"  {e.Name}  ({e.Device})  ->  {flag}");
        }

        Ui.Section("SMB shares");
        Console.WriteLine(Sharing.GetShareTable());

        Ui.Section("LAN routing and DHCP diagnostics");
        var diagnostic = Sys.PowerShell(
            "Get-NetNat | Format-Table Name,InternalIPInterfaceAddressPrefix,Active; " +
            "Get-Service SharedAccess,Dhcp | Format-Table Name,Status; " +
            "Get-NetConnectionProfile | Format-Table InterfaceAlias,NetworkCategory,IPv4Connectivity; " +
            "Get-NetUDPEndpoint -LocalPort 67 -ErrorAction SilentlyContinue | Format-Table LocalAddress,LocalPort,OwningProcess");
        Console.WriteLine(diagnostic.StdOut);
        if (!diagnostic.Success) Log.Warn(diagnostic.StdErr);

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
            Console.WriteLine($"  Private: {s.PrivateAdapterName}  NAT={s.NatName ?? "legacy ICS"}  Host={s.HostIp}");
            Console.WriteLine($"  Orig IP: {s.OrigIp ?? "DHCP/none"}  Orig DNS: [{string.Join(",", s.OrigDns)}]  Orig suffix: '{s.OrigSuffix}'");
            Console.WriteLine($"  Share:   \\\\{Environment.MachineName}\\{s.ShareName}  <-  {s.SharePath}");
        }

        Ui.Section("Identity notes");
        Console.WriteLine("  Description / Manufacturer / Driver version: read-only (driver INF).");
        Console.WriteLine("  Link speed: real negotiated speed (cannot be spoofed).");
        Console.WriteLine("  Encryption flag: N/A — Ethernet is unencrypted at L2 by nature.");
    }
}
