// comwatch — detector engine
// Part of the Cognis Neural Suite. Defensive triage only.
//
// Each detector inspects the flat list of RegEntry rows and emits Finding rows.
// Detectors are pure functions over the parsed export — no live registry, no
// network, no side effects — so the whole engine runs on any OS and in CI.
//
// Coverage (MITRE ATT&CK):
//   T1546.015  COM hijacking (HKCU CLSID override, user-writable/LOLBin handler,
//              TreatAs redirection, scriptlet/moniker COM, per-user shell verb)
//   T1218      System Binary Proxy Execution (LOLBin handlers)
//   T1547.001  Registry Run keys / Startup folder
//   T1546.012  Image File Execution Options (IFEO) Debugger
//   T1546.010  AppInit_DLLs
//   T1574.012  COR_PROFILER environment hijack
//   T1543.003  Windows Service (user-writable / LOLBin ImagePath)
//   T1112      Modify Registry (Winlogon Shell/Userinit tampering)
using System.Text.RegularExpressions;

namespace ComWatch;

public sealed class DetectorOptions
{
    /// <summary>Fingerprints to suppress (baseline / known-good allowlist).</summary>
    public HashSet<string> Baseline { get; init; } = new();
    /// <summary>Emit INFO baseline findings for benign HKLM COM servers.</summary>
    public bool IncludeInfo { get; init; } = false;
}

public static class Detectors
{
    static readonly string[] LolBins =
        { "rundll32", "regsvr32", "mshta", "powershell", "pwsh", "wscript",
          "cscript", "msbuild", "installutil", "regasm", "regsvcs", "certutil",
          "bitsadmin", "curl", "hh.exe", "forfiles", "wmic" };

    static readonly string[] UserWritable =
        { @"\appdata\", @"\local\temp\", @"\temp\", @"\users\public\",
          @"\programdata\", @"\downloads\", @"\windows\temp\", @"\tmp\",
          @"\roaming\", @"\perflogs\" };

    static readonly Regex ClsidRx = new(
        @"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}",
        RegexOptions.Compiled);

    static readonly Dictionary<string, string> TechniqueNames = new()
    {
        ["T1546.015"] = "Event Triggered Execution: Component Object Model Hijacking",
        ["T1218"] = "System Binary Proxy Execution",
        ["T1547.001"] = "Boot or Logon Autostart Execution: Registry Run Keys",
        ["T1546.012"] = "Event Triggered Execution: Image File Execution Options Injection",
        ["T1546.010"] = "Event Triggered Execution: AppInit DLLs",
        ["T1574.012"] = "Hijack Execution Flow: COR_PROFILER",
        ["T1543.003"] = "Create or Modify System Process: Windows Service",
        ["T1112"] = "Modify Registry",
    };

    public static List<Finding> Run(IReadOnlyList<RegEntry> entries, DetectorOptions? opts = null)
    {
        opts ??= new DetectorOptions();
        var findings = new List<Finding>();

        foreach (var e in entries)
        {
            string keyLower = e.Key.ToLowerInvariant();
            string valNameLower = (e.ValueName ?? "").ToLowerInvariant();
            string handler = e.ValueData;
            string handlerLower = handler.ToLowerInvariant();
            bool userWritable = UserWritable.Any(u => handlerLower.Contains(u));
            bool lol = LolBins.Any(b => handlerLower.Contains(b));
            string? clsid = ExtractClsid(e.Key);

            // --- COM server registrations (InprocServer32 / LocalServer32) ----
            bool isComServer = keyLower.Contains(@"\clsid\")
                && (keyLower.EndsWith("inprocserver32") || keyLower.EndsWith("localserver32")
                    || keyLower.EndsWith("inprochandler32")) && e.ValueName is null;
            if (isComServer)
            {
                if (e.Hive is "HKCU" or "HKCR")
                    Add(findings, opts, Severity.High, "com-hijack",
                        "COM server registered in a user-controlled hive",
                        $"CLSID handler registered under {e.Hive} takes precedence over the HKLM (system) registration and silently overrides that COM object.",
                        "T1546.015", e, clsid, handler, "com", "persistence", "hijack");
                if (userWritable)
                    Add(findings, opts, Severity.High, "com-handler-user-writable",
                        "COM handler in a user-writable directory",
                        "COM handler resolves into a user-writable directory (AppData/Temp/ProgramData/Public), a hallmark of dropper-backed hijacks.",
                        "T1546.015", e, clsid, handler, "com", "persistence");
                if (lol)
                    Add(findings, opts, Severity.High, "com-handler-lolbin",
                        "COM handler invokes a LOLBin",
                        "COM handler invokes a living-off-the-land binary (proxy execution of arbitrary code through a signed system binary).",
                        "T1218", e, clsid, handler, "com", "lolbin", "proxy-execution");
                if (e.Hive == "HKLM" && !userWritable && !lol)
                    Add(findings, opts, Severity.Info, "com-server",
                        "COM server registration (baseline)",
                        "COM server registration in HKLM. Benign baseline unless it resolves to an unexpected path.",
                        "T1546.015", e, clsid, handler, "com", "baseline");
                continue;
            }

            // --- CLSID TreatAs redirection ------------------------------------
            if (keyLower.Contains(@"\clsid\") && keyLower.EndsWith("treatas") && e.ValueName is null)
            {
                var sev = e.Hive is "HKCU" or "HKCR" ? Severity.High : Severity.Medium;
                Add(findings, opts, sev, "com-treatas", "CLSID TreatAs redirection",
                    $"CLSID is redirected via TreatAs to {handler}. Redirection in {e.Hive} can silently substitute a class for a system one.",
                    "T1546.015", e, clsid, handler, "com", "persistence", "hijack");
                continue;
            }

            // --- Scriptlet/moniker-backed COM (scrobj.dll surrogate) ----------
            if (keyLower.Contains(@"\clsid\") && valNameLower is "scriptleturl" or "moniker")
            {
                Add(findings, opts, Severity.High, "com-scriptlet", "Scriptlet/moniker-backed COM object",
                    "CLSID uses a ScriptletURL/Moniker (scrobj.dll surrogate) to execute remote or local script as a COM object.",
                    "T1218", e, clsid, handler, "com", "scriptlet", "proxy-execution");
                continue;
            }

            // --- Per-user shell verb command hijack ---------------------------
            // e.g. HKCU\Software\Classes\<progid>\shell\open\command
            if (keyLower.EndsWith(@"\shell\open\command") || keyLower.EndsWith(@"\shell\runas\command")
                || Regex.IsMatch(keyLower, @"\\shell\\[^\\]+\\command$"))
            {
                if (e.Hive is "HKCU" or "HKCR" && (userWritable || lol))
                    Add(findings, opts, Severity.High, "shell-verb-hijack", "User shell-verb command hijack",
                        "A file/protocol shell verb command in a user hive invokes a LOLBin or user-writable payload — hijacks the handler for that class.",
                        "T1546.015", e, clsid, handler, "com", "shell-verb", "persistence");
                continue;
            }

            // --- Autorun (Run / RunOnce) --------------------------------------
            if (keyLower.EndsWith(@"\currentversion\run") || keyLower.EndsWith(@"\currentversion\runonce")
                || keyLower.EndsWith(@"\currentversion\runservices") || keyLower.EndsWith(@"\currentversion\runservicesonce"))
            {
                // Autorun into a system-owned path (System32 / Program Files) that
                // is neither a LOLBin nor user-writable is a normal startup entry
                // (INFO baseline). Everything else is at least MEDIUM.
                bool systemPath = handlerLower.Contains(@"\windows\system32\")
                    || handlerLower.Contains(@"\windows\syswow64\")
                    || handlerLower.Contains(@"\program files\")
                    || handlerLower.Contains(@"\program files (x86)\");
                var sev = (lol || userWritable) ? Severity.High
                        : (systemPath ? Severity.Info : Severity.Medium);
                Add(findings, opts, sev, "autorun", "Registry Run key persistence",
                    "Autorun (Run/RunOnce) value" + (lol ? " invoking a LOLBin." : userWritable ? " pointing at a user-writable path." : "."),
                    "T1547.001", e, null, handler, "autostart", "persistence");
                continue;
            }

            // --- Image File Execution Options: Debugger -----------------------
            if (keyLower.Contains(@"\image file execution options\") && valNameLower == "debugger")
            {
                Add(findings, opts, Severity.High, "ifeo-debugger", "Image File Execution Options debugger",
                    "An IFEO 'Debugger' value hijacks execution of the target image — running the named debugger instead of (or before) the real program.",
                    "T1546.012", e, null, handler, "ifeo", "persistence", "hijack");
                continue;
            }
            if (keyLower.Contains(@"\silentprocessexit\") && valNameLower is "monitorprocess")
            {
                Add(findings, opts, Severity.High, "ifeo-silentexit", "SilentProcessExit MonitorProcess",
                    "A SilentProcessExit MonitorProcess value launches an attacker binary when the monitored process exits.",
                    "T1546.012", e, null, handler, "ifeo", "persistence");
                continue;
            }

            // --- AppInit_DLLs -------------------------------------------------
            if (keyLower.Contains(@"\windows nt\currentversion\windows") && valNameLower == "appinit_dlls" && handler.Trim().Length > 0)
            {
                Add(findings, opts, Severity.High, "appinit-dlls", "AppInit_DLLs injection",
                    "AppInit_DLLs is populated — every GUI process loading user32.dll will load the listed DLL(s). Classic broad DLL injection.",
                    "T1546.010", e, null, handler, "dll-injection", "persistence");
                continue;
            }

            // --- COR_PROFILER environment hijack ------------------------------
            if (valNameLower is "cor_profiler" or "cor_profiler_path" or "cor_enable_profiling")
            {
                var sev = valNameLower == "cor_profiler_path" && (userWritable || lol) ? Severity.High : Severity.Medium;
                Add(findings, opts, sev, "cor-profiler", "COR_PROFILER .NET profiler hijack",
                    "A COR_PROFILER environment value forces the CLR to load a profiler DLL into managed processes — a stealthy code-injection persistence.",
                    "T1574.012", e, null, handler, "dotnet", "dll-injection", "persistence");
                continue;
            }

            // --- Winlogon Shell / Userinit tampering --------------------------
            if (keyLower.EndsWith(@"\winlogon") && valNameLower is "shell" or "userinit")
            {
                // A pristine Winlogon Shell is exactly "explorer.exe"; Userinit is
                // "C:\Windows\system32\userinit.exe," (with the trailing comma).
                // Any extra command appended is a classic logon-persistence tail.
                string ht = handlerLower.Trim().TrimEnd(',').Trim();
                bool suspicious = lol || userWritable
                    || (valNameLower == "shell" && ht != "explorer.exe")
                    || (valNameLower == "userinit" && !ht.EndsWith("userinit.exe"));
                if (suspicious)
                    Add(findings, opts, Severity.High, "winlogon-tamper", "Winlogon Shell/Userinit tampering",
                        $"Winlogon '{e.ValueName}' deviates from the expected value — a logon-time persistence/hijack vector.",
                        "T1112", e, null, handler, "winlogon", "persistence");
                continue;
            }

            // --- Windows service ImagePath ------------------------------------
            if (keyLower.Contains(@"\services\") && valNameLower == "imagepath")
            {
                if (userWritable || lol)
                    Add(findings, opts, Severity.High, "service-imagepath", "Service binary in a suspicious location",
                        "A service ImagePath resolves to a user-writable directory or a LOLBin — a service-based persistence / privilege path.",
                        "T1543.003", e, null, handler, "service", "persistence");
                continue;
            }
        }

        // De-duplicate identical findings (same fingerprint), keep highest sev order stable.
        var seen = new HashSet<string>();
        var deduped = new List<Finding>();
        foreach (var f in findings.OrderByDescending(f => f.Severity))
            if (seen.Add(f.Fingerprint())) deduped.Add(f);
        return deduped;
    }

    static void Add(List<Finding> list, DetectorOptions opts, Severity sev, string ruleId,
        string title, string message, string technique, RegEntry e, string? clsid, string handler,
        params string[] tags)
    {
        if (sev == Severity.Info && !opts.IncludeInfo) return;
        var f = new Finding
        {
            Severity = sev,
            RuleId = ruleId,
            Title = title,
            Message = message,
            Technique = technique,
            TechniqueName = TechniqueNames.TryGetValue(technique, out var n) ? n : "",
            Hive = e.Hive,
            Clsid = clsid,
            Key = e.Key,
            ValueName = e.ValueName,
            Handler = handler,
            Line = e.Line,
            Tags = tags,
        };
        if (opts.Baseline.Contains(f.Fingerprint())) return; // suppressed baseline
        list.Add(f);
    }

    static string? ExtractClsid(string key)
    {
        var m = ClsidRx.Match(key);
        return m.Success ? m.Value : null;
    }
}
