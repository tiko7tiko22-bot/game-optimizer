using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;

namespace GameOptimizer.Services;

public class ProcessManager : IDisposable
{
    private static readonly HashSet<string> NotAGame = new(StringComparer.OrdinalIgnoreCase)
    {
        "steam","steamwebhelper","steamservice","gameoverlayui",
        "gogalaxy","gogalaxy-notifications","gogcomm","gogservices",
        "battle.net","epicgameslauncher","epicwebhelper",
        "unitycrashandler64","unitycrashandler32","crashreportclient",
        "unrealcefsubprocess","easyanticheat","easyanticheat_setup",
        "bsoverlay","nvcapcli","nvidiaoverlaycontainer",
        "gamebarftstserver","gamebarpresencewriter",
        "stardocklauncher","unins000",
        "quicksfv","sfv","md5","hashcheck"
    };

    private static readonly string[] BuiltInBgProcs =
    [
        "onedrive","icloudckks","iclouddrive","icloudservices","icloudhome",
        "phoneexperiencehost","crossdeviceservice",
        "malwarebytes","mbamservice","hearthstonedecktracker",
        "backgroundtaskhost","windowspackagemanagerserver",
        "hwinfo64","nahimicsvc32","nahimicsvc64",
        "unigetui","appcontrol"
    ];

    private readonly OptimizerConfig _cfg;
    private readonly IntPtr _allCores;

    public ConcurrentDictionary<int, string> ActiveGames { get; } = new();
    private readonly ConcurrentDictionary<int, string> _appliedMediaZone = new();
    private readonly ConcurrentDictionary<int, string> _appliedBgProcs = new();

    // PIDs known not to be games (path unresolvable, or resolved outside every
    // game path). A process's image path never changes, so once classified the
    // per-scan path lookup is skipped entirely.
    private readonly ConcurrentDictionary<int, byte> _notGamePids = new();

    // Track every PID we've modified so ReleasePinning/RestoreAll only touches those
    private readonly ConcurrentDictionary<int, byte> _modifiedPids = new();

    // PIDs this instance has suspended; resumed when the game ends / pinning off
    private readonly ConcurrentDictionary<int, string> _suspendedPids = new();

    public IReadOnlyList<string> SuspendedProcessNames => [.. _suspendedPids.Values.Distinct()];

    // WMI event watchers for instant process start/stop detection
    private ManagementEventWatcher? _startWatcher;
    private ManagementEventWatcher? _stopWatcher;

    public bool PinningEnabled { get; set; } = false;

    public event Action<string>? LogEntry;

    public ProcessManager(OptimizerConfig cfg)
    {
        _cfg = cfg;
        long allBits = (1L << Environment.ProcessorCount) - 1;
        _allCores = (IntPtr)allBits;
    }

    public IntPtr FirefoxAffinity => (IntPtr)_cfg.FirefoxAffinityMask;
    public IntPtr BgAffinity => (IntPtr)_cfg.BgAffinityMask;

    public IReadOnlyList<string> GameProcessNames => [.. ActiveGames.Values.Distinct()];
    public IReadOnlyList<string> MediaProcessNames => [.. _appliedMediaZone.Values.Distinct()];
    public IReadOnlyList<string> BgProcessNames => [.. _appliedBgProcs.Values.Distinct()];

    private bool IsBgProc(string name)
    {
        foreach (var b in BuiltInBgProcs)
            if (b.Equals(name, StringComparison.OrdinalIgnoreCase)) return true;
        foreach (var b in _cfg.ExtraThrottledProcs)
            if (string.Equals(b, name, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    // Subscribe to WMI process start/stop events for instant detection.
    // Fires on a WMI thread - all handlers are thread-safe.
    public void StartWmiWatcher()
    {
        try
        {
            _startWatcher = new ManagementEventWatcher(
                new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            _startWatcher.EventArrived += OnProcessStarted;
            _startWatcher.Start();

            _stopWatcher = new ManagementEventWatcher(
                new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace"));
            _stopWatcher.EventArrived += OnProcessStopped;
            _stopWatcher.Start();
        }
        catch { } // Win32_ProcessStartTrace requires admin; silently degrade
    }

    private void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var name = e.NewEvent["ProcessName"]?.ToString()?.Replace(".exe", "", StringComparison.OrdinalIgnoreCase) ?? "";
            var pid  = Convert.ToInt32(e.NewEvent["ProcessID"]);

            // Check firefox/vlc immediately
            if (name.Equals("firefox", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("vlc", StringComparison.OrdinalIgnoreCase))
            {
                if (PinningEnabled)
                {
                    using var proc = SafeGetProcess(pid);
                    if (proc is not null && !_appliedMediaZone.ContainsKey(pid))
                    {
                        ApplyMediaZone(proc);
                        _appliedMediaZone[pid] = name;
                        LogEntry?.Invoke($"[MEDIA] Pinned {name} (PID {pid}) to media zone");
                    }
                }
                return;
            }

            // Check bg procs immediately
            if (IsBgProc(name))
            {
                if (PinningEnabled)
                {
                    using var proc = SafeGetProcess(pid);
                    if (proc is not null)
                    {
                        try
                        {
                            proc.PriorityClass = ProcessPriorityClass.Idle;
                            proc.ProcessorAffinity = BgAffinity;
                            ProcessControl.SetIoPriorityVeryLow(pid);
                            _modifiedPids[pid] = 0;
                            _appliedBgProcs[pid] = name;
                        }
                        catch { }
                    }
                }
                return;
            }

            // Defer game path check to the next Scan() tick (needs path resolution)
        }
        catch { }
    }

    private void OnProcessStopped(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
            if (ActiveGames.TryRemove(pid, out var name))
            {
                LogEntry?.Invoke($"[ENDED] {name} closed (PID {pid})");
            }
            _appliedMediaZone.TryRemove(pid, out _);
            _appliedBgProcs.TryRemove(pid, out _);
            _modifiedPids.TryRemove(pid, out _);
            _notGamePids.TryRemove(pid, out _);   // PID may be reused for a game
        }
        catch { }
    }

    // One process snapshot per tick drives everything below: game detection,
    // the firefox/vlc fallback, suspend candidates, exited-game detection, and
    // pruning of every tracking dictionary.
    public List<string> Scan()
    {
        var newGames = new List<string>();
        var procs = SafeGetProcesses();
        var alive = new HashSet<int>(procs.Length);
        List<(int Pid, string Name)>? suspendCandidates = null;

        HashSet<string>? suspendNames = null;
        if (PinningEnabled)
        {
            foreach (var app in _cfg.SuspendDuringGame)
            {
                if (!app.Enabled || string.IsNullOrWhiteSpace(app.ProcessName)) continue;
                (suspendNames ??= new(StringComparer.OrdinalIgnoreCase)).Add(app.ProcessName);
            }
        }

        try
        {
            foreach (var proc in procs)
            {
                int pid = proc.Id;
                alive.Add(pid);
                var name = proc.ProcessName;

                if (PinningEnabled)
                {
                    // Pin new firefox + vlc (fallback for when WMI start event is missed)
                    if ((name.Equals("firefox", StringComparison.OrdinalIgnoreCase) ||
                         name.Equals("vlc", StringComparison.OrdinalIgnoreCase)) &&
                        !_appliedMediaZone.ContainsKey(pid))
                    {
                        ApplyMediaZone(proc);
                        _appliedMediaZone[pid] = name;
                        LogEntry?.Invoke($"[MEDIA] Pinned {name} (PID {pid}) to media zone");
                    }

                    if (suspendNames is not null && suspendNames.Contains(name) &&
                        pid != Environment.ProcessId)
                        (suspendCandidates ??= []).Add((pid, name));
                }

                if (ActiveGames.ContainsKey(pid)) continue;
                if (_notGamePids.ContainsKey(pid)) continue;
                if (IsExcluded(name)) continue;

                var path = GetProcPath(proc);

                // A configured per-game profile also makes the process a real Game.
                // This is important for emulators such as GameLoop whose EXE path
                // is not inside a normal Steam/Epic game library.
                var hasGameProfile = _cfg.GameProfiles.Any(p =>
                    p.ProcessName.Equals(name, StringComparison.OrdinalIgnoreCase));

                if (hasGameProfile || IsGamePath(path))
                {
                    if (ApplyGame(proc))
                    {
                        ActiveGames[pid] = name;
                        _modifiedPids[pid] = 0;
                        newGames.Add(name);

                        LogEntry?.Invoke(
                            hasGameProfile
                                ? $"[GAME] Profile detected: {name} (PID {pid})"
                                : $"[GAME] Detected: {name} (PID {pid})");
                    }
                }
                else if (path is not null)
                {
                    _notGamePids[pid] = 0;
                }
            }

            // Re-apply affinity each scan to counter external tools
            if (PinningEnabled && !ActiveGames.IsEmpty)
            {
                foreach (var proc in procs)
                {
                    if (!ActiveGames.TryGetValue(proc.Id, out var gameName)) continue;
                    var (mask, _) = ResolveGameSettings(_cfg, gameName);
                    try
                    {
                        if (proc.ProcessorAffinity.ToInt64() != mask)
                            proc.ProcessorAffinity = (IntPtr)mask;
                    }
                    catch { }
                }
            }
        }
        finally
        {
            foreach (var proc in procs) proc.Dispose();
        }

        // Detect exited games (fallback for when WMI stop event is missed)
        foreach (var pid in ActiveGames.Keys.ToList())
        {
            if (!alive.Contains(pid) && ActiveGames.TryRemove(pid, out var exitedName))
                LogEntry?.Invoke($"[ENDED] {exitedName} closed (PID {pid})");
        }

        ReconcileSuspension(suspendCandidates);

        PruneDeadPids(_appliedMediaZone, alive);
        PruneDeadPids(_appliedBgProcs, alive);
        PruneDeadPids(_notGamePids, alive);
        PruneDeadPids(_suspendedPids, alive);

        return newGames;
    }

    /// <summary>
    /// Suspends or resumes the configured background apps depending on whether
    /// a game is active. Candidates come from the single per-scan process
    /// snapshot. Gated on <see cref="PinningEnabled"/> so the pinning-off
    /// state remains a guaranteed no-op.
    /// </summary>
    private void ReconcileSuspension(List<(int Pid, string Name)>? candidates)
    {
        if (PinningEnabled && !ActiveGames.IsEmpty)
        {
            if (candidates is null) return;
            foreach (var (pid, name) in candidates)
            {
                if (_suspendedPids.ContainsKey(pid)) continue;
                if (ProcessControl.Suspend(pid))
                {
                    _suspendedPids[pid] = name;
                    LogEntry?.Invoke($"[SUSPEND] Paused {name} (PID {pid}) - game running");
                }
            }
        }
        else if (!_suspendedPids.IsEmpty)
        {
            ResumeAllSuspended();
        }
    }

    /// <summary>
    /// Resumes every process this instance suspended. Safe to call at any time;
    /// invoked automatically when no game is active and on every teardown path.
    /// </summary>
    public void ResumeAllSuspended()
    {
        foreach (var pid in _suspendedPids.Keys.ToList())
        {
            if (_suspendedPids.TryRemove(pid, out var name))
            {
                ProcessControl.Resume(pid);
                LogEntry?.Invoke($"[SUSPEND] Resumed {name} (PID {pid})");
            }
        }
    }

    /// <summary>
    /// Pins all known background process names to the BG affinity zone at Idle priority.
    /// No-op when <see cref="PinningEnabled"/> is false - guaranteed to make zero process changes.
    /// Re-run periodically (~60s) to catch processes that started after the last scan.
    /// </summary>
    public void ThrottleBg()
    {
        if (!PinningEnabled) return;

        // One process snapshot instead of a GetProcessesByName sweep per name
        var bgNames = new HashSet<string>(BuiltInBgProcs, StringComparer.OrdinalIgnoreCase);
        foreach (var extra in _cfg.ExtraThrottledProcs)
            if (!string.IsNullOrWhiteSpace(extra)) bgNames.Add(extra);

        foreach (var proc in SafeGetProcesses())
        {
            using (proc)
            {
                if (!bgNames.Contains(proc.ProcessName)) continue;
                try
                {
                    proc.PriorityClass = ProcessPriorityClass.Idle;
                    proc.ProcessorAffinity = BgAffinity;
                    ProcessControl.SetIoPriorityVeryLow(proc.Id);
                    _modifiedPids[proc.Id] = 0;
                    _appliedBgProcs[proc.Id] = proc.ProcessName;
                }
                catch { }
            }
        }
    }

    // Remove tracking entries for PIDs no longer in the latest process snapshot
    private static void PruneDeadPids<T>(ConcurrentDictionary<int, T> dict, HashSet<int> alive)
    {
        foreach (var pid in dict.Keys)
            if (!alive.Contains(pid)) dict.TryRemove(pid, out _);
    }

    public void ReleasePinning()
    {
        ResumeAllSuspended();

        // Only reset PIDs we actually modified - no full process scan needed
        var pidsToReset = _modifiedPids.Keys.ToList();

        Parallel.ForEach(pidsToReset, pid =>
        {
            ProcessControl.SetIoPriorityNormal(pid);
            using var p = SafeGetProcess(pid);
            if (p is null) return;
            try
            {
                p.ProcessorAffinity = _allCores;
                if (p.PriorityClass == ProcessPriorityClass.BelowNormal ||
                    p.PriorityClass == ProcessPriorityClass.Idle ||
                    p.PriorityClass == ProcessPriorityClass.High)
                    p.PriorityClass = ProcessPriorityClass.Normal;
            }
            catch { }
        });

        LogEntry?.Invoke("[PIN] CPU pinning DISABLED - all processes running on all cores");
    }

    public void RestorePinning()
    {
        foreach (var pid in ActiveGames.Keys)
        {
            if (!ActiveGames.TryGetValue(pid, out var gameName)) continue;
            using var p = SafeGetProcess(pid);
            if (p is null) continue;
            var (mask, priority) = ResolveGameSettings(_cfg, gameName);
            try { p.ProcessorAffinity = (IntPtr)mask; p.PriorityClass = priority; } catch { }
        }
        foreach (var proc in SafeGetProcessesByName("firefox").Concat(SafeGetProcessesByName("vlc")))
        {
            using (proc)
            {
                try
                {
                    proc.ProcessorAffinity = FirefoxAffinity;
                    proc.PriorityClass = ProcessPriorityClass.Normal;
                    _appliedMediaZone[proc.Id] = proc.ProcessName;
                    _modifiedPids[proc.Id] = 0;
                }
                catch { }
            }
        }
        ThrottleBg();
        LogEntry?.Invoke("[PIN] CPU pinning ENABLED - affinities restored");
    }

    /// <summary>
    /// Wipes all internal tracking state without touching any live processes.
    /// Call this only after <see cref="RestoreAll"/>, which resumes suspended
    /// processes - clearing first would orphan a frozen process.
    /// Safe to call at any time; subsequent <see cref="Scan"/> calls work normally.
    /// </summary>
    public void ClearState()
    {
        ActiveGames.Clear();
        _appliedMediaZone.Clear();
        _appliedBgProcs.Clear();
        _modifiedPids.Clear();
        _notGamePids.Clear();
        _suspendedPids.Clear();
    }

    /// <summary>
    /// Undoes everything this instance changed: resumes suspended processes and
    /// restores every modified PID to all-cores affinity, Normal priority, and
    /// Normal I/O priority. Only touches PIDs this instance actually modified.
    /// Does NOT clear internal tracking state; call <see cref="ClearState"/> after.
    /// </summary>
    public void RestoreAll()
    {
        ResumeAllSuspended();

        var pidsToReset = _modifiedPids.Keys.ToList();

        Parallel.ForEach(pidsToReset, pid =>
        {
            if (pid == Environment.ProcessId) return;
            ProcessControl.SetIoPriorityNormal(pid);
            using var p = SafeGetProcess(pid);
            if (p is null) return;
            try
            {
                if (p.ProcessorAffinity.ToInt64() != _allCores.ToInt64())
                    p.ProcessorAffinity = _allCores;
                if (p.PriorityClass == ProcessPriorityClass.BelowNormal ||
                    p.PriorityClass == ProcessPriorityClass.Idle ||
                    p.PriorityClass == ProcessPriorityClass.High)
                    p.PriorityClass = ProcessPriorityClass.Normal;
            }
            catch { }
        });
    }

    /// <summary>
    /// Resolves the affinity mask and priority for a game, honoring any matching
    /// per-game profile in <paramref name="cfg"/>. Falls back to the global game
    /// affinity mask and High priority when no profile matches.
    /// </summary>
    public static (long affinityMask, ProcessPriorityClass priority) ResolveGameSettings(
        OptimizerConfig cfg, string procName)
    {
        var name = procName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);
        var profile = cfg.GameProfiles.FirstOrDefault(p =>
            p.ProcessName.Equals(name, StringComparison.OrdinalIgnoreCase));

        long mask = profile is { AffinityMask: not 0 }
            ? profile.AffinityMask
            : cfg.GameAffinityMask;
        var priority = profile is not null
            && Enum.TryParse<ProcessPriorityClass>(profile.Priority, ignoreCase: true, out var p)
            ? p : ProcessPriorityClass.High;
        return (mask, priority);
    }

    private bool ApplyGame(Process proc)
    {
        try
        {
            if (PinningEnabled)
            {
                var (mask, priority) = ResolveGameSettings(_cfg, proc.ProcessName);
                proc.PriorityClass = priority;
                proc.ProcessorAffinity = (IntPtr)mask;
            }
            return true;
        }
        catch { return false; }
    }

    private void ApplyMediaZone(Process proc)
    {
        try
        {
            // Only called when PinningEnabled is true
            proc.PriorityClass = ProcessPriorityClass.Normal;
            proc.ProcessorAffinity = FirefoxAffinity;
            _modifiedPids[proc.Id] = 0;
        }
        catch { }
    }

    private string? GetProcPath(Process proc)
    {
        string? path = null;
        try { path = proc.MainModule?.FileName; } catch { }
        if (path is null)
        {
            try
            {
                using var q = new ManagementObjectSearcher("root\\cimv2",
                    $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId={proc.Id}");
                using var results = q.Get();
                foreach (ManagementObject mo in results)
                {
                    path = mo["ExecutablePath"]?.ToString();
                    mo.Dispose();
                    break;
                }
            }
            catch { }
        }
        if (path is null)
        {
            // Give a brand-new process a few scans to expose its path before
            // writing off the PID for good
            try
            {
                var ageMs = (DateTime.Now - proc.StartTime).TotalMilliseconds;
                if (ageMs > 5000) _notGamePids[proc.Id] = 0;
            }
            catch { _notGamePids[proc.Id] = 0; }
        }
        return path;
    }

    private bool IsGamePath(string? path)
    {
        if (path is null) return false;
        return _cfg.GamePaths.Any(root =>
            path.StartsWith(root, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsExcluded(string name) =>
        NotAGame.Contains(name.Replace(".exe", "", StringComparison.OrdinalIgnoreCase));

    private static Process[] SafeGetProcesses()
    {
        try { return Process.GetProcesses(); } catch { return []; }
    }

    private static Process? SafeGetProcess(int pid)
    {
        try { return Process.GetProcessById(pid); } catch { return null; }
    }

    private static IEnumerable<Process> SafeGetProcessesByName(string name)
    {
        try { return Process.GetProcessesByName(name); } catch { return []; }
    }

    public void Dispose()
    {
        // Backstop: never leave a process frozen because the app shut down
        ResumeAllSuspended();
        _startWatcher?.Stop();
        _startWatcher?.Dispose();
        _stopWatcher?.Stop();
        _stopWatcher?.Dispose();
        GC.SuppressFinalize(this);
    }
}
