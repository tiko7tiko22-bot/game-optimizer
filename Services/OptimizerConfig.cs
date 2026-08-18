using System.Text.Json;
using System.Text.Json.Serialization;

namespace GameOptimizer.Services;

public class OptimizerConfig
{
    public string NicName { get; set; } = "Ethernet 2";

    /// <summary>Host pinged to measure latency and jitter.</summary>
    public string PingHost { get; set; } = "1.1.1.1";
    public long GameAffinityMask { get; set; } = 0xFFFF;
    public long FirefoxAffinityMask { get; set; } = 0x3000;
    public long BgAffinityMask { get; set; } = 0xC000;
    public int AlertGpuTempC { get; set; } = 80;
    public int AlertVramPct { get; set; } = 90;
    public int AlertGpuUtilPct { get; set; } = 95;
    public int AlertCpuZonePct { get; set; } = 90;
    public int AlertSustainedTicks { get; set; } = 4;

    public List<string> GamePaths { get; set; } =
    [
        @"C:\Program Files (x86)\Steam\steamapps\common",
        @"C:\Program Files\Steam\steamapps\common",
        @"C:\Program Files (x86)\GOG Galaxy\Games",
        @"C:\Program Files\GOG Galaxy\Games",
        @"C:\Program Files (x86)\Hearthstone",
        @"C:\Program Files (x86)\Overwatch",
        @"C:\Program Files (x86)\Overwatch\_retail_",
        @"C:\Program Files (x86)\World of Warcraft",
        @"C:\Program Files (x86)\Diablo IV",
        @"C:\Program Files\Epic Games",
    ];

    public List<string> ExtraThrottledProcs { get; set; } = [];

    /// <summary>
    /// Optional per-game affinity/priority overrides. A game with no matching
    /// profile uses <see cref="GameAffinityMask"/> and High priority.
    /// </summary>
    public List<GameProfile> GameProfiles { get; set; } = [];

    /// <summary>
    /// Background apps to fully suspend while a game runs (resumed when the game
    /// ends or pinning is turned off). Defaults to common cloud-sync clients -
    /// the main cause of mid-game disk stutter - plus on-demand launcher UIs
    /// like the PowerToys Command Palette that are never needed mid-game.
    /// </summary>
    public List<SuspendApp> SuspendDuringGame { get; set; } =
    [
        new() { ProcessName = "onedrive",      Enabled = true },
        new() { ProcessName = "dropbox",       Enabled = true },
        new() { ProcessName = "googledrivefs", Enabled = true },
        new() { ProcessName = "Microsoft.CmdPal.UI", Enabled = true },
    ];

    /// <summary>
    /// Services stopped for the duration of a session and restarted on teardown
    /// (StartType is never changed - identical to the built-in SysMain handling).
    /// Defaults to the Windows Search indexer and telemetry, both common sources
    /// of mid-game disk/CPU spikes.
    /// </summary>
    public List<string> StopServicesDuringSession { get; set; } = ["WSearch", "DiagTrack"];

    /// <summary>
    /// Pin NVIDIA GPU clocks to maximum while a game runs (via nvidia-smi),
    /// reset when it exits. Prevents GPU P-state oscillation - a microstutter
    /// source - at the cost of higher idle clocks/heat during play.
    /// </summary>
    public bool LockGpuClocksDuringGame { get; set; } = true;

    public bool StartMinimized { get; set; } = false;
    public bool StartWithWindows { get; set; } = false;

    /// <summary>
    /// Turn CPU pinning on automatically when a game is detected and back off
    /// when the last auto-pinned game exits. Manual toggles always win: turning
    /// pinning off by hand while a game runs stops the automation for that game.
    /// </summary>
    public bool AutoPinOnGameDetect { get; set; } = true;

    /// <summary>Purge the Windows standby memory list each time a game is detected.</summary>
    public bool AutoFlushStandbyOnGameStart { get; set; } = true;

    /// <summary>Disable Windows Game DVR / Xbox background capture while CPU pinning is on.</summary>
    public bool DisableGameDvrWhenPinning { get; set; } = true;

    [JsonIgnore]
    public static string ConfigPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                     "GamingOptimizer", "config.json");

    public static OptimizerConfig Load()
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                var loaded = JsonSerializer.Deserialize<OptimizerConfig>(
                    File.ReadAllText(ConfigPath),
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (loaded is not null)
                {
                    loaded.Validate();
                    return loaded;
                }
            }
        }
        catch { }
        return CreateDefault();
    }

    /// <summary>
    /// Clamps all values to safe ranges. A corrupt affinity mask (zero, or
    /// referencing cores that do not exist) would pin a game to no cores at
    /// all - those fall back to the all-cores mask. Alert thresholds are
    /// clamped to the ranges enforced by the Settings UI.
    /// </summary>
    public void Validate()
    {
        long allCores = (1L << Environment.ProcessorCount) - 1;
        GameAffinityMask    = SanitizeMask(GameAffinityMask, allCores);
        FirefoxAffinityMask = SanitizeMask(FirefoxAffinityMask, allCores);
        BgAffinityMask      = SanitizeMask(BgAffinityMask, allCores);

        AlertGpuTempC       = Math.Clamp(AlertGpuTempC, 50, 110);
        AlertVramPct        = Math.Clamp(AlertVramPct, 50, 100);
        AlertGpuUtilPct     = Math.Clamp(AlertGpuUtilPct, 50, 100);
        AlertCpuZonePct     = Math.Clamp(AlertCpuZonePct, 50, 100);
        AlertSustainedTicks = Math.Clamp(AlertSustainedTicks, 1, 20);

        if (string.IsNullOrWhiteSpace(PingHost)) PingHost = "1.1.1.1";
        else PingHost = PingHost.Trim();

        // Normalize throttle/service lists - entries typed with ".exe" or stray
        // whitespace would otherwise never match a process or service name
        ExtraThrottledProcs = ExtraThrottledProcs
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => p.Trim()
                .Replace(".exe", "", StringComparison.OrdinalIgnoreCase)
                .ToLowerInvariant())
            .Distinct()
            .ToList();

        StopServicesDuringSession = StopServicesDuringSession
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // Normalize and prune per-game profiles
        GameProfiles = GameProfiles
            .Where(p => !string.IsNullOrWhiteSpace(p.ProcessName))
            .Select(p =>
            {
                p.ProcessName = p.ProcessName.Trim()
                    .Replace(".exe", "", StringComparison.OrdinalIgnoreCase)
                    .ToLowerInvariant();
                // 0 stays 0 ("use default"); a non-zero corrupt mask also
                // falls back to 0 rather than pinning the game to nothing.
                if (p.AffinityMask != 0 && (p.AffinityMask & ~allCores) != 0)
                    p.AffinityMask = 0;
                if (!Enum.TryParse<System.Diagnostics.ProcessPriorityClass>(
                        p.Priority, ignoreCase: true, out _))
                    p.Priority = "High";
                return p;
            })
            .ToList();

        // Normalize and prune the suspend-during-game list
        SuspendDuringGame = SuspendDuringGame
            .Where(a => !string.IsNullOrWhiteSpace(a.ProcessName))
            .Select(a =>
            {
                a.ProcessName = a.ProcessName.Trim()
                    .Replace(".exe", "", StringComparison.OrdinalIgnoreCase)
                    .ToLowerInvariant();
                return a;
            })
            .ToList();
    }

    // A mask is valid only if it is non-zero and references real cores.
    private static long SanitizeMask(long mask, long allCores) =>
        mask != 0 && (mask & ~allCores) == 0 ? mask : allCores;

    private static OptimizerConfig CreateDefault()
    {
        var cfg = new OptimizerConfig();
        var zones = AffinityCalculator.Calculate();
        cfg.GameAffinityMask    = zones.GameMask;
        cfg.FirefoxAffinityMask = zones.MediaMask;
        cfg.BgAffinityMask      = zones.BgMask;

        // Merge auto-detected game library paths with the hardcoded defaults
        var detected = GameLibraryScanner.ScanAll();
        if (detected.Count > 0)
            cfg.GamePaths = [.. cfg.GamePaths.Union(detected, StringComparer.OrdinalIgnoreCase)];

        return cfg;
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
            var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(ConfigPath, json);
        }
        catch { }
    }
}
