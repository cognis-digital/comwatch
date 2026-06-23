// comwatch — COM-hijack & persistence detector (C# / .NET)
// Part of the Cognis Neural Suite. Single-purpose, JSON-out, CI-tested.
//
// Parses a Windows registry export (.reg) and flags persistence/hijack
// tradecraft without touching a live registry (so it runs anywhere, including
// on triage images / offline hives exported with `reg export`):
//
//   * COM hijacking  — a CLSID InprocServer32/LocalServer32 handler in the
//     HKCU hive (HKCU takes precedence over HKLM, so this silently overrides a
//     legitimate system COM object).            [MITRE ATT&CK T1546.015]
//   * Suspicious handler path — DLL/EXE in a user-writable dir (AppData, Temp,
//     Public, ProgramData, Downloads).
//   * LOLBin handler — rundll32/regsvr32/mshta/powershell/wscript/cscript.
//                                                [MITRE ATT&CK T1218]
//   * Autorun persistence — ...\CurrentVersion\Run / RunOnce values.
//                                                [MITRE ATT&CK T1547.001]
//
// Usage:
//   comwatch <export.reg>     analyze a .reg export
//   comwatch -                read .reg text from stdin
//   comwatch --selftest       analyze a bundled sample export (demo/CI)
//   --format json|sigma       output format (default json)
//
// JSON on stdout. Exit 2 if any HIGH finding, else 0. Defensive triage only.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

static class ComWatch
{
    record Finding(string severity, string id, string technique, string hive,
                   string? clsid, string key, string handler, string message);

    static readonly string[] LolBins =
        { "rundll32", "regsvr32", "mshta", "powershell", "pwsh", "wscript",
          "cscript", "msbuild", "installutil", "regasm", "regsvcs" };

    static readonly string[] UserWritable =
        { @"\appdata\", @"\local\temp\", @"\temp\", @"\users\public\",
          @"\programdata\", @"\downloads\", @"\windows\temp\" };

    static int Main(string[] args)
    {
        string fmt = "json";
        string? src = null;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--format" && i + 1 < args.Length) fmt = args[++i];
            else if (args[i] is "-h" or "--help")
            {
                Console.Error.WriteLine("usage: comwatch <export.reg> | - | --selftest [--format json|sigma]");
                return 0;
            }
            else src = args[i];
        }
        if (src is null)
        {
            Console.Error.WriteLine("comwatch: no input (.reg file, '-' for stdin, or --selftest)");
            return 1;
        }

        string text;
        try
        {
            text = src switch
            {
                "--selftest" => SampleReg(),
                "-"          => Console.In.ReadToEnd(),
                _            => File.ReadAllText(src),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"comwatch: cannot read input: {ex.Message}");
            return 1;
        }

        var findings = Analyze(text);

        if (fmt == "sigma")
        {
            Console.WriteLine(ToSigma(findings));
            return findings.Any(f => f.severity == "HIGH") ? 2 : 0;
        }

        var report = new Dictionary<string, object?>
        {
            ["tool"] = "comwatch",
            ["source"] = src == "--selftest" ? "<selftest>" : src,
            ["finding_count"] = findings.Count,
            ["high_count"] = findings.Count(f => f.severity == "HIGH"),
            ["findings"] = findings,
        };
        Console.WriteLine(JsonSerializer.Serialize(report,
            new JsonSerializerOptions { WriteIndented = true }));
        return findings.Any(f => f.severity == "HIGH") ? 2 : 0;
    }

    static readonly Regex KeyHeader = new(@"^\[(?<key>[^\]]+)\]\s*$", RegexOptions.Compiled);
    static readonly Regex Clsid = new(@"\{[0-9A-Fa-f\-]{36}\}", RegexOptions.Compiled);
    static readonly Regex DefaultVal = new("^@=\"(?<v>.*)\"\\s*$", RegexOptions.Compiled);
    static readonly Regex NamedVal = new("^\"(?<n>[^\"]+)\"=\"(?<v>.*)\"\\s*$", RegexOptions.Compiled);

    static List<Finding> Analyze(string text)
    {
        var findings = new List<Finding>();
        string curKey = "";
        string curHiveRaw = "";

        foreach (var rawLine in text.Replace("\r\n", "\n").Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith(";")) continue;

            var hm = KeyHeader.Match(line);
            if (hm.Success) { curKey = hm.Groups["key"].Value; curHiveRaw = curKey; continue; }
            if (curKey.Length == 0) continue;

            string hive = curHiveRaw.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase) ? "HKCU"
                        : curHiveRaw.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase) ? "HKLM"
                        : curHiveRaw.StartsWith("HKEY_USERS", StringComparison.OrdinalIgnoreCase) ? "HKU"
                        : "?";
            string keyLower = curKey.ToLowerInvariant();

            // value lines
            string? val = null;
            var dm = DefaultVal.Match(line);
            if (dm.Success) val = dm.Groups["v"].Value;
            else { var nm = NamedVal.Match(line); if (nm.Success) val = nm.Groups["v"].Value; }
            if (val is null) continue;
            string handler = val.Replace(@"\\", @"\");

            bool isComServer = keyLower.Contains(@"\clsid\")
                && (keyLower.EndsWith("inprocserver32") || keyLower.EndsWith("localserver32")
                    || keyLower.EndsWith("inprochandler32"));
            bool isAutorun = keyLower.EndsWith(@"\currentversion\run")
                || keyLower.EndsWith(@"\currentversion\runonce");

            if (isComServer)
            {
                string? clsid = Clsid.Match(curKey) is { Success: true } m ? m.Value : null;
                bool userWritable = UserWritable.Any(u => handler.ToLowerInvariant().Contains(u));
                bool lol = LolBins.Any(b => handler.ToLowerInvariant().Contains(b));

                if (hive == "HKCU")
                    findings.Add(new("HIGH", "com-hijack", "T1546.015", hive, clsid, curKey, handler,
                        "COM server registered in HKCU — overrides the HKLM (system) handler for this CLSID."));
                if (userWritable)
                    findings.Add(new("HIGH", "com-handler-user-writable", "T1546.015", hive, clsid, curKey, handler,
                        "COM handler resolves to a user-writable directory."));
                if (lol)
                    findings.Add(new("HIGH", "com-handler-lolbin", "T1218", hive, clsid, curKey, handler,
                        "COM handler invokes a living-off-the-land binary."));
                if (hive == "HKLM" && !userWritable && !lol)
                    findings.Add(new("INFO", "com-server", "T1546.015", hive, clsid, curKey, handler,
                        "COM server registration (HKLM, benign baseline)."));
            }
            else if (isAutorun)
            {
                bool lol = LolBins.Any(b => handler.ToLowerInvariant().Contains(b));
                bool userWritable = UserWritable.Any(u => handler.ToLowerInvariant().Contains(u));
                string sev = (lol || userWritable) ? "HIGH" : "MEDIUM";
                findings.Add(new(sev, "autorun", "T1547.001", hive, null, curKey, handler,
                    "Autorun (Run/RunOnce) persistence value" + (lol ? " invoking a LOLBin." : ".")));
            }
        }
        return findings;
    }

    static string ToSigma(List<Finding> findings)
    {
        var clsids = findings.Where(f => f.id == "com-hijack" && f.clsid != null)
                             .Select(f => f.clsid!).Distinct().ToList();
        var sb = new StringBuilder();
        sb.AppendLine("title: COM Hijack via HKCU CLSID InprocServer32 (comwatch)");
        sb.AppendLine("id: cognis-comwatch-com-hijack");
        sb.AppendLine("status: experimental");
        sb.AppendLine("description: Detects user-hive COM server registrations that override system CLSIDs.");
        sb.AppendLine("references:");
        sb.AppendLine("  - https://attack.mitre.org/techniques/T1546/015/");
        sb.AppendLine("logsource:");
        sb.AppendLine("  category: registry_set");
        sb.AppendLine("  product: windows");
        sb.AppendLine("detection:");
        sb.AppendLine("  selection:");
        sb.AppendLine("    TargetObject|contains: 'HKCU\\Software\\Classes\\CLSID\\'");
        sb.AppendLine("    TargetObject|endswith:");
        sb.AppendLine("      - '\\InprocServer32\\(Default)'");
        sb.AppendLine("      - '\\LocalServer32\\(Default)'");
        if (clsids.Count > 0)
        {
            sb.AppendLine("  observed_clsids:  # surfaced by comwatch in this export");
            foreach (var c in clsids) sb.AppendLine($"    - '{c}'");
        }
        sb.AppendLine("  condition: selection");
        sb.AppendLine("level: high");
        sb.AppendLine("tags:");
        sb.AppendLine("  - attack.persistence");
        sb.AppendLine("  - attack.t1546.015");
        return sb.ToString();
    }

    static string SampleReg() =>
        "Windows Registry Editor Version 5.00\n\n" +
        // benign HKLM COM server (baseline — should be INFO)
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{0002DF01-0000-0000-C000-000000000046}\\InprocServer32]\n" +
        "@=\"C:\\\\Windows\\\\System32\\\\ieframe.dll\"\n\n" +
        // malicious HKCU COM hijack pointing at AppData (should be HIGH x2)
        "[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{0002DF01-0000-0000-C000-000000000046}\\InprocServer32]\n" +
        "@=\"C:\\\\Users\\\\victim\\\\AppData\\\\Roaming\\\\evil.dll\"\n\n" +
        // autorun via LOLBin (should be HIGH)
        "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n" +
        "\"Updater\"=\"rundll32.exe C:\\\\Users\\\\victim\\\\AppData\\\\Local\\\\Temp\\\\x.dll,Start\"\n";
}
