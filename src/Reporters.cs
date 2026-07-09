// comwatch — output reporters
// Part of the Cognis Neural Suite. Defensive triage only.
//
// Renders a scan result in one of several formats:
//   json    structured report with findings[]                (default)
//   sarif   SARIF 2.1.0 — GitHub code scanning / IDE ingest
//   sigma   deployable Sigma detection rule for the hijacks found
//   cef     ArcSight Common Event Format lines (one per finding) for SIEM
//   table   human-readable console table
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace ComWatch;

public sealed record ScanResult(string Source, IReadOnlyList<Finding> Findings)
{
    public int High => Findings.Count(f => f.Severity >= Severity.High);
    public int Total => Findings.Count;

    /// <summary>Exit code contract: 2 if any HIGH+ finding, else 0.</summary>
    public int ExitCode => High > 0 ? 2 : 0;
}

public static class Reporters
{
    const string Tool = "comwatch";
    const string Version = "2.0.0";
    const string InfoUri = "https://github.com/cognis-digital/comwatch";

    static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string Render(ScanResult r, string format) => format.ToLowerInvariant() switch
    {
        "json" => Json(r),
        "sarif" => Sarif(r),
        "sigma" => Sigma(r),
        "cef" => Cef(r),
        "table" or "text" => Table(r),
        _ => throw new ArgumentException($"unknown format '{format}' (json|sarif|sigma|cef|table)"),
    };

    // ---------------------------------------------------------------- JSON ---
    static string Json(ScanResult r)
    {
        var report = new
        {
            tool = Tool,
            version = Version,
            source = r.Source,
            finding_count = r.Total,
            high_count = r.High,
            severity_breakdown = r.Findings.GroupBy(f => f.Severity.ToJsonString())
                                           .ToDictionary(g => g.Key, g => g.Count()),
            findings = r.Findings.Select(f => new
            {
                severity = f.Severity.ToJsonString(),
                id = f.RuleId,
                title = f.Title,
                technique = f.Technique,
                technique_name = f.TechniqueName,
                hive = f.Hive,
                clsid = f.Clsid,
                key = f.Key,
                value_name = f.ValueName,
                handler = f.Handler,
                line = f.Line,
                tags = f.Tags,
                fingerprint = f.Fingerprint(),
            }),
        };
        return JsonSerializer.Serialize(report, JsonOpts);
    }

    // --------------------------------------------------------------- SARIF ---
    // SARIF 2.1.0 static analysis interchange. Consumable by GitHub code
    // scanning, VS Code SARIF Viewer, and most SAST dashboards.
    static string Sarif(ScanResult r)
    {
        var ruleIds = r.Findings.Select(f => f.RuleId).Distinct().ToList();
        var rules = ruleIds.Select(id =>
        {
            var sample = r.Findings.First(f => f.RuleId == id);
            return new
            {
                id,
                name = ToPascal(id),
                shortDescription = new { text = sample.Title },
                fullDescription = new { text = sample.Message },
                helpUri = $"https://attack.mitre.org/techniques/{sample.Technique.Replace('.', '/')}/",
                defaultConfiguration = new { level = sample.Severity.ToSarifLevel() },
                properties = new { tags = sample.Tags, mitreTechnique = sample.Technique },
            };
        }).ToArray();

        var results = r.Findings.Select(f => new
        {
            ruleId = f.RuleId,
            level = f.Severity.ToSarifLevel(),
            message = new { text = f.Message },
            locations = new[]
            {
                new
                {
                    physicalLocation = new
                    {
                        artifactLocation = new { uri = ArtifactUri(r.Source) },
                        region = new { startLine = Math.Max(1, f.Line) },
                    },
                    logicalLocations = new[] { new { fullyQualifiedName = f.Key, kind = "member" } },
                },
            },
            partialFingerprints = new Dictionary<string, string> { ["comwatch/v1"] = f.Fingerprint() },
            properties = new { severity = f.Severity.ToJsonString(), hive = f.Hive, clsid = f.Clsid, handler = f.Handler },
        }).ToArray();

        var sarif = new
        {
            version = "2.1.0",
            _schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            runs = new[]
            {
                new
                {
                    tool = new
                    {
                        driver = new
                        {
                            name = Tool,
                            version = Version,
                            informationUri = InfoUri,
                            rules,
                        },
                    },
                    results,
                },
            },
        };
        // System.Text.Json can't emit "$schema" via anonymous property name, patch it.
        return JsonSerializer.Serialize(sarif, JsonOpts).Replace("\"_schema\"", "\"$schema\"");
    }

    // --------------------------------------------------------------- Sigma ---
    static string Sigma(ScanResult r)
    {
        var clsids = r.Findings.Where(f => f.RuleId is "com-hijack" or "com-treatas" && f.Clsid != null)
                               .Select(f => f.Clsid!).Distinct().ToList();
        var sb = new StringBuilder();
        sb.AppendLine("title: COM Hijack via User-Hive CLSID Registration (comwatch)");
        sb.AppendLine("id: cognis-comwatch-com-hijack");
        sb.AppendLine("status: experimental");
        sb.AppendLine("description: Detects user-hive COM server registrations / TreatAs redirections that override system CLSIDs.");
        sb.AppendLine("author: comwatch (Cognis Digital)");
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
        sb.AppendLine("      - '\\TreatAs\\(Default)'");
        if (clsids.Count > 0)
        {
            sb.AppendLine("  # CLSIDs surfaced by comwatch in this export:");
            foreach (var c in clsids) sb.AppendLine($"  #   {c}");
        }
        sb.AppendLine("  condition: selection");
        sb.AppendLine("falsepositives:");
        sb.AppendLine("  - Legitimate per-user COM registrations by installers");
        sb.AppendLine("level: high");
        sb.AppendLine("tags:");
        sb.AppendLine("  - attack.persistence");
        sb.AppendLine("  - attack.t1546.015");
        return sb.ToString();
    }

    // ----------------------------------------------------------------- CEF ---
    // ArcSight Common Event Format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
    static string Cef(ScanResult r)
    {
        var sb = new StringBuilder();
        foreach (var f in r.Findings)
        {
            sb.Append("CEF:0|Cognis Digital|comwatch|").Append(Version).Append('|')
              .Append(CefEsc(f.RuleId)).Append('|').Append(CefEsc(f.Title)).Append('|')
              .Append(f.Severity.ToCefSeverity()).Append('|');
            sb.Append("cs1Label=technique cs1=").Append(CefExt(f.Technique)).Append(' ');
            sb.Append("cs2Label=hive cs2=").Append(CefExt(f.Hive)).Append(' ');
            if (f.Clsid != null) sb.Append("cs3Label=clsid cs3=").Append(CefExt(f.Clsid)).Append(' ');
            sb.Append("filePath=").Append(CefExt(f.Handler)).Append(' ');
            sb.Append("cs4Label=key cs4=").Append(CefExt(f.Key)).Append(' ');
            sb.Append("msg=").Append(CefExt(f.Message));
            sb.AppendLine();
        }
        return sb.ToString().TrimEnd('\n');
    }

    // --------------------------------------------------------------- Table ---
    static string Table(ScanResult r)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"comwatch {Version} — source: {r.Source}");
        sb.AppendLine($"findings: {r.Total}  (HIGH+: {r.High})");
        sb.AppendLine(new string('-', 78));
        if (r.Total == 0)
        {
            sb.AppendLine("No findings.");
            return sb.ToString();
        }
        foreach (var f in r.Findings)
        {
            sb.AppendLine($"[{f.Severity.ToJsonString(),-8}] {f.RuleId}  ({f.Technique})");
            sb.AppendLine($"    {f.Title}");
            sb.AppendLine($"    key    : {f.Key}");
            if (f.ValueName != null) sb.AppendLine($"    value  : {f.ValueName}");
            sb.AppendLine($"    handler: {f.Handler}");
            sb.AppendLine();
        }
        return sb.ToString().TrimEnd('\n');
    }

    // ------------------------------------------------------------- helpers ---
    static string ToPascal(string id) =>
        string.Concat(id.Split('-', StringSplitOptions.RemoveEmptyEntries)
                        .Select(p => char.ToUpperInvariant(p[0]) + p[1..]));

    static string ArtifactUri(string source) =>
        source is "<selftest>" or "<stdin>" ? source : Path.GetFileName(source);

    static string CefEsc(string s) => s.Replace("\\", "\\\\").Replace("|", "\\|");
    static string CefExt(string s) => s.Replace("\\", "\\\\").Replace("=", "\\=")
                                        .Replace("\n", " ").Replace("\r", " ");
}
